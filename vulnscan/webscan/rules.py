"""The rule registry of the passive web scanner: every rule of spec §2 (1.1.0), frozen in WP0.

``RULES`` maps a rule id to its :class:`RuleMeta`: default severity and the allowed range, default confidence and the
allowed ones, CWE, OWASP WSTG / ASVS 4.0.3 / ASVS 5.0.0 mappings (an empty tuple means "—", no matching requirement),
title and advice in English and Arabic, remediation snippet ids (§2.13), family, the paranoid-only flag and the
coverage check id. The engine formats findings from here; ``vulnscan/i18n/cat_web2.py`` builds its catalogue with
:func:`i18n_catalog`; ``docs/web-checks.md`` is generated from it.

Titles and advice may be format strings: ``{cookie}``, ``{value}``, ``{versions}``, ``{days}`` … are filled from
``Issue.params``. A parameter listed in :data:`PLURAL_PARAMS` is a count rendered with the noun that agrees with it
(Arabic via ``vulnscan.i18n.plural``). ``Issue.params["variant"]`` selects an alternative title/advice from
``RuleMeta.variants``.

Stability (1.x): rule ids and their meanings never change; an id is never reused. ``title_1_0`` keeps the English
title format of 1.0.1 for the existing rules whose wording changed, so the engine can keep their fingerprints.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .types import CONFIDENCES

# the order of vulnscan.model.SEVERITIES (not imported: vulnscan.i18n imports this module through cat_web2, and
# vulnscan.model imports vulnscan.i18n, so importing model here would be circular; a test asserts they are equal)
SEVERITIES = ("critical", "high", "medium", "low", "info")

# ----------------------------------------------------------------------------------------------- vocabularies

FAMILIES: dict[str, tuple[str, str]] = {
    "A": ("Transport, redirects, HSTS", "النقل والتوجيه وHSTS"),
    "B": ("Content-Security-Policy", "سياسة أمان المحتوى (CSP)"),
    "C": ("Framing, MIME, referrer, permissions, isolation, caching and other headers",
          "التضمين ونوع المحتوى والإحالة والصلاحيات والعزل والتخزين المؤقت وترويسات أخرى"),
    "D": ("CORS", "مشاركة الموارد بين المصادر (CORS)"),
    "E": ("Cookies", "الكوكيز"),
    "F": ("Page content and client-side code", "محتوى الصفحة والشيفرة في المتصفح"),
    "G": ("Information disclosure", "كشف المعلومات"),
    "H": ("TLS and certificates", "TLS والشهادات"),
    "I": ("Components and technologies", "المكونات والتقنيات"),
    "J": ("Exposure, well-known files, deep probe", "الملفات المكشوفة والملفات المعروفة والفحص العميق"),
    "K": ("Scan meta", "معلومات الفحص"),
}

# §3.4 grade families (weights 20/20/20/15/15/10; "meta" never counts)
GRADE_FAMILIES: dict[str, tuple[str, str, int]] = {
    "transport": ("Transport & HSTS", "النقل وHSTS", 20),
    "tls": ("TLS", "TLS", 20),
    "policies": ("Browser policies", "سياسات المتصفح", 20),
    "cookies": ("Cookies & session", "الكوكيز والجلسة", 15),
    "content": ("Content & components", "المحتوى والمكونات", 15),
    "exposure": ("Exposure & disclosure", "الكشف والملفات المكشوفة", 10),
    "meta": ("Scan meta", "معلومات الفحص", 0),
}

# check modules (``webscan/<module>.py``; tls = ``webscan/tls/assess.py``; engine = scan meta)
MODULES = ("transport", "csp", "headers", "cors", "cookies", "content", "domxss", "disclosure", "tls", "libs", "tech",
           "exposure", "engine")

# remediation snippet ids of §2.13 (webscan/remediation.py, WP14)
FIX_IDS = ("S-HSTS", "S-REDIR", "S-CSP", "S-FRAME", "S-XCTO", "S-REF", "S-PP", "S-ISO", "S-COOKIE", "S-CORS",
           "S-BANNER", "S-DIRLIST", "S-DOTFILES", "S-ERR", "S-TLS", "S-MIXED", "S-SRI", "S-LIBS", "S-SECTXT", "S-CACHE",
           "S-DEPR", "S-BREACH", "S-HTML", "S-SECRET", "S-ADMIN", "S-TAKEOVER", "S-INCIDENT")

# §3.4 step 2 sum cap: control → (the "missing" rule, the weakness rules whose summed penalty is capped)
CONTROLS: dict[str, tuple[str, tuple[str, ...]]] = {
    "csp": ("WEB-content-security-policy",
            ("WEB040", "WEB041", "WEB042", "WEB043") + tuple(f"WEB{n}" for n in range(200, 220) if n != 206)),
    "framing": ("WEB-x-frame-options", ("WEB206", "WEB207", "WEB300", "WEB301", "WEB302")),
    "hsts": ("WEB-strict-transport-security", tuple(f"WEB{n}" for n in range(110, 118))),
    "xcto": ("WEB-x-content-type-options", ("WEB303",)),
    "referrer": ("WEB-referrer-policy", ("WEB304",)),
    "permissions": ("WEB-permissions-policy", ("WEB305", "WEB306", "WEB307")),
    "coop": ("WEB308", ("WEB308",)),
}

# count parameters: (English singular, English plural, Arabic five forms one/two/few/many/other with {n})
PLURAL_PARAMS: dict[str, tuple[str, str, tuple[str, str, str, str, str]]] = {
    "days": ("{n} day", "{n} days", ("يوم واحد", "يومين", "{n} أيام", "{n} يومًا", "{n} يوم")),
    "hops": ("{n} hop", "{n} hops", ("قفزة واحدة", "قفزتين", "{n} قفزات", "{n} قفزةً", "{n} قفزة")),
}

_PLACEHOLDER = re.compile(r"\{([a-z_][a-z0-9_]*)\}")


# ----------------------------------------------------------------------------------------------- RuleMeta

@dataclass(frozen=True)
class RuleMeta:
    id: str
    family: str                       # A … K (§2.1 … §2.11)
    module: str                       # owning check module
    grade_family: str                 # §3.4 family
    severity: str                     # default severity
    allowed_severities: tuple[str, ...]
    confidence: str                   # default confidence
    allowed_confidences: tuple[str, ...]
    cwe: str                          # primary CWE ("" only for scan-meta rules)
    wstg: tuple[str, ...]
    asvs4: tuple[str, ...]
    asvs5: tuple[str, ...]
    fix: tuple[str, ...]              # remediation snippet ids
    name_en: str                      # plain title (docs, coverage)
    name_ar: str
    title_en: str                     # finding title format string
    title_ar: str
    advice_en: str
    advice_ar: str                    # Finding.advice (Arabic); English via the i18n catalogue
    paranoid_only: bool = False       # evaluated only at --web-sensitivity paranoid
    check_id: str = ""                # coverage check id
    cwe_variants: tuple[str, ...] = ()
    controls: tuple[str, ...] = ()    # §3.4 sum-cap controls
    variants: dict = field(default_factory=dict)   # name → {title_en?, title_ar?, advice_en?, advice_ar?}
    existing: bool = False            # rule existed in 1.0.1
    title_1_0: str = ""               # 1.0.1 English title format when it differs (fingerprint continuity)

    # -- formatting ----------------------------------------------------------------------------------------
    @property
    def params(self) -> tuple[str, ...]:
        names: dict[str, None] = {}
        for text in (self.title_en, self.advice_en):
            for n in _PLACEHOLDER.findall(text):
                names.setdefault(n, None)
        for v in self.variants.values():
            for key in ("title_en", "advice_en"):
                for n in _PLACEHOLDER.findall(v.get(key, "")):
                    names.setdefault(n, None)
        return tuple(names)

    def allows(self, severity: str) -> bool:
        return severity in self.allowed_severities

    def title(self, lang: str = "en", **params) -> str:
        return self._text("title", lang, params)

    def advice(self, lang: str = "ar", **params) -> str:
        return self._text("advice", lang, params)

    def name(self, lang: str = "en") -> str:
        return self.name_ar if lang == "ar" else self.name_en

    def _text(self, what: str, lang: str, params: dict) -> str:
        lang = "ar" if lang == "ar" else "en"
        key = f"{what}_{lang}"
        template = getattr(self, key)
        var = self.variants.get(params.get("variant") or "")
        if var and var.get(key):
            template = var[key]
        names = _PLACEHOLDER.findall(template)
        if any(params.get(n) in (None, "") for n in names):
            return self.name(lang) if what == "title" else _PLACEHOLDER.sub("", template).strip()
        return _PLACEHOLDER.sub(lambda m: _render(m.group(1), params[m.group(1)], lang), template)


def _render(name: str, value, lang: str) -> str:
    plural = PLURAL_PARAMS.get(name)
    if plural is None:
        return str(value)
    try:
        n = int(value)
    except (TypeError, ValueError):
        return str(value)
    if lang == "ar":
        from ..i18n.plural import ar_count   # lazy: see the SEVERITIES note above
        return ar_count(n, plural[2])
    return (plural[0] if n == 1 else plural[1]).replace("{n}", str(n))


# ----------------------------------------------------------------------------------------------- builder

_FAMILY_GRADE = {"A": "transport", "B": "policies", "C": "policies", "D": "policies", "E": "cookies", "F": "content",
                 "G": "exposure", "H": "tls", "I": "content", "J": "exposure", "K": "meta"}
_ORDER: list[str] = []
_BUILT: dict[str, RuleMeta] = {}


def _split(s: str) -> tuple[str, ...]:
    return tuple(x for x in s.split() if x and x != "—")


def _r(rid: str, family: str, module: str, sev: str, conf: str, cwe: str, wstg: str, asvs4: str, asvs5: str, fix: str,
       name: tuple[str, str], advice: tuple[str, str], *, sevs: str = "", confs: str = "", title: tuple[str, str] | None = None,
       paranoid: bool = False, cwe_variants: str = "", variants: dict | None = None, existing: bool = False,
       title_1_0: str = "") -> None:
    if rid in _BUILT:
        raise ValueError(f"duplicate rule id {rid}")
    allowed = _split(sevs) or (sev,)
    if sev not in allowed:
        allowed = (sev,) + allowed
    allowed_c = _split(confs) or (conf,)
    if conf not in allowed_c:
        allowed_c = (conf,) + allowed_c
    controls = tuple(c for c, (missing, weak) in CONTROLS.items() if rid == missing or rid in weak)
    t_en, t_ar = title or name
    _BUILT[rid] = RuleMeta(
        id=rid, family=family, module=module, grade_family=_FAMILY_GRADE[family], severity=sev,
        allowed_severities=tuple(s for s in SEVERITIES if s in allowed), confidence=conf,
        allowed_confidences=tuple(c for c in CONFIDENCES if c in allowed_c), cwe=cwe, wstg=_split(wstg),
        asvs4=_split(asvs4), asvs5=_split(asvs5), fix=_split(fix), name_en=name[0], name_ar=name[1], title_en=t_en,
        title_ar=t_ar, advice_en=advice[0], advice_ar=advice[1], paranoid_only=paranoid, check_id=rid,
        cwe_variants=_split(cwe_variants), controls=controls, variants=variants or {}, existing=existing,
        title_1_0=title_1_0)
    _ORDER.append(rid)


# =============================================================================================== §2.1 Family A
_r("WEB000", "A", "transport", "high", "certain", "CWE-319", "WSTG-CRYP-03", "9.1.1", "12.2.1", "S-REDIR S-TLS",
   ("Site served over plain HTTP", "الموقع يُقدَّم عبر HTTP غير مشفّر"),
   ("Serve the site only over HTTPS and redirect every HTTP request to the same host on HTTPS with a 301/308 (for APIs, "
    "refuse plain HTTP instead of redirecting).",
    "قدّم الموقع عبر HTTPS فقط، وأعد توجيه كل طلب HTTP إلى نفس المضيف عبر HTTPS بتوجيه 301 أو 308 (أما واجهات API فارفض HTTP كليًا بدل التوجيه)."),
   sevs="high info", existing=True,
   variants={"api": {
       "advice_en": "Refuse plain HTTP for this API (close port 80 or answer 403/421) instead of redirecting it to HTTPS.",
       "advice_ar": "ارفض طلبات HTTP غير المشفّرة لواجهة API هذه (أغلق المنفذ 80 أو أجب بـ 403 أو 421) بدل توجيهها إلى HTTPS."}})
_r("WEB101", "A", "transport", "medium", "certain", "CWE-319", "WSTG-CONF-07", "9.1.1", "12.2.1", "S-REDIR",
   ("First HTTP redirect does not go to HTTPS", "أول توجيه من HTTP لا يذهب إلى HTTPS"),
   ("Make the first redirect from HTTP go straight to HTTPS on the same host; only then redirect to another host.",
    "اجعل أول توجيه من HTTP يذهب مباشرة إلى HTTPS على نفس المضيف، ثم وجّه بعد ذلك إلى أي مضيف آخر."))
_r("WEB102", "A", "transport", "low", "certain", "CWE-319", "WSTG-CONF-07", "14.4.5", "3.4.1", "S-REDIR",
   ("HTTP→HTTPS redirect changes host on the first hop", "التوجيه الأول إلى HTTPS يغيّر المضيف"),
   ("Redirect http://example.com to https://example.com first (and set HSTS there), then to https://www.example.com.",
    "وجّه http://example.com أولًا إلى https://example.com (واضبط HSTS هناك)، ثم إلى https://www.example.com."))
_r("WEB103", "A", "transport", "high", "certain", "CWE-319", "WSTG-CRYP-03", "9.1.1", "12.2.1", "S-REDIR",
   ("Redirect or refresh downgrades HTTPS to HTTP", "توجيه يخفّض الاتصال من HTTPS إلى HTTP"),
   ("Never redirect from HTTPS to HTTP; use https:// in every Location header, meta refresh and script redirect.",
    "لا توجّه أبدًا من HTTPS إلى HTTP؛ استخدم https:// في كل ترويسة Location وفي meta refresh وفي توجيهات السكربت."),
   confs="certain tentative")
_r("WEB104", "A", "transport", "info", "certain", "CWE-319", "WSTG-CONF-02", "—", "—", "S-REDIR",
   ("Redirect chain too long or looping", "سلسلة توجيه طويلة أو دائرية"),
   ("Reduce the chain to at most two hops (http→https, then canonical host).",
    "اختصر سلسلة التوجيه إلى قفزتين على الأكثر (من HTTP إلى HTTPS ثم إلى المضيف الأساسي)."),
   sevs="info low")
_r("WEB105", "A", "transport", "info", "certain", "CWE-319", "WSTG-CONF-07", "—", "—", "S-REDIR",
   ("Temporary redirect used for HTTP→HTTPS", "توجيه مؤقت من HTTP إلى HTTPS"),
   ("Use a permanent redirect (301 or 308) from HTTP to HTTPS.",
    "استخدم توجيهًا دائمًا (301 أو 308) من HTTP إلى HTTPS."))
_r("WEB106", "A", "transport", "low", "firm", "CWE-698", "WSTG-INFO-05", "—", "—", "S-ERR",
   ("Redirect response carries a full page", "استجابة التوجيه تحمل صفحة كاملة"),
   ("Stop rendering page content in redirect responses (send the redirect before any output, e.g. call exit after "
    "header(\"Location\")).",
    "لا تُرسل محتوى الصفحة مع استجابة التوجيه (أرسل التوجيه قبل أي مخرجات، مثل استدعاء exit بعد header(\"Location\") في PHP)."))
_r("WEB-strict-transport-security", "A", "transport", "medium", "firm", "CWE-319", "WSTG-CONF-07", "14.4.5", "3.4.1",
   "S-HSTS",
   ("Missing Strict-Transport-Security", "ترويسة HSTS مفقودة"),
   ("Send Strict-Transport-Security: max-age=63072000; includeSubDomains on every HTTPS response.",
    "أرسل الترويسة Strict-Transport-Security: max-age=63072000; includeSubDomains في كل استجابة HTTPS."),
   sevs="medium info", existing=True)
_r("WEB110", "A", "transport", "medium", "certain", "CWE-319", "WSTG-CONF-07", "14.4.5", "3.4.1", "S-HSTS",
   ("HSTS disabled by max-age=0", "HSTS معطَّل بالقيمة max-age=0"),
   ("Set max-age to at least 31536000 (one year); max-age=0 removes HSTS protection from browsers.",
    "اضبط max-age على 31536000 (سنة) على الأقل؛ القيمة 0 تزيل حماية HSTS من المتصفحات."))
_r("WEB111", "A", "transport", "medium", "certain", "CWE-319", "WSTG-CONF-07", "14.4.5", "3.4.1", "S-HSTS",
   ("HSTS max-age too short", "مدة HSTS قصيرة"),
   ("Raise max-age to 63072000 (two years) once HTTPS works everywhere.",
    "ارفع max-age إلى 63072000 (سنتين) بعد التأكد من عمل HTTPS في كل مكان."),
   sevs="medium low info",
   variants={"too_long": {
       "title_en": "HSTS max-age longer than ten years", "title_ar": "مدة HSTS أطول من عشر سنوات",
       "advice_en": "Use a max-age of one or two years (31536000–63072000); hstspreload warns about values above ten years.",
       "advice_ar": "استخدم max-age لمدة سنة أو سنتين (31536000–63072000)؛ إذ يحذّر hstspreload من القيم التي تتجاوز عشر سنوات."}})
_r("WEB112", "A", "transport", "medium", "certain", "CWE-319", "WSTG-CONF-07", "14.4.5", "3.4.1", "S-HSTS",
   ("HSTS header invalid (ignored by browsers)", "ترويسة HSTS غير صالحة فيتجاهلها المتصفح"),
   ("Use exactly: Strict-Transport-Security: max-age=63072000; includeSubDomains (one header, plain ASCII, no commas).",
    "استخدم الصيغة بالضبط: Strict-Transport-Security: max-age=63072000; includeSubDomains (ترويسة واحدة، أحرف ASCII عادية، بلا فواصل)."))
_r("WEB113", "A", "transport", "low", "certain", "CWE-319", "WSTG-CONF-07", "14.4.5", "3.4.1", "S-HSTS",
   ("Multiple HSTS headers", "أكثر من ترويسة HSTS"),
   ("Set HSTS in one place only (the proxy or the application, not both).",
    "اضبط HSTS في مكان واحد فقط (الوكيل العكسي أو التطبيق، وليس كليهما)."),
   sevs="low info")
_r("WEB114", "A", "transport", "info", "certain", "CWE-319", "WSTG-CONF-07", "14.4.5", "3.4.1", "S-HSTS",
   ("HSTS without includeSubDomains", "HSTS بلا includeSubDomains"),
   ("Add includeSubDomains after confirming every subdomain serves HTTPS.",
    "أضف includeSubDomains بعد التأكد من أن كل النطاقات الفرعية تعمل عبر HTTPS."),
   sevs="info low")
_r("WEB115", "A", "transport", "low", "certain", "CWE-319", "WSTG-CONF-07", "—", "3.7.4", "S-HSTS",
   ("HSTS preload: requested but not eligible / eligibility report", "طلب الإدراج المسبق لـ HSTS غير مستوفٍ"),
   ("Either remove \"preload\" or meet every preload requirement (listed in the evidence) before submitting at "
    "hstspreload.org.",
    "إما أن تحذف preload، أو تستوفي كل شروط الإدراج المسبق (المذكورة في الدليل) قبل التقديم في hstspreload.org."),
   sevs="low info", confs="certain firm")
_r("WEB116", "A", "transport", "info", "certain", "CWE-319", "WSTG-CONF-07", "—", "—", "S-HSTS",
   ("HSTS where browsers ignore it", "HSTS في موضع يتجاهله المتصفح"),
   ("Send HSTS as an HTTP response header on HTTPS responses only; it has no effect over HTTP or in a meta tag.",
    "أرسل HSTS كترويسة HTTP في استجابات HTTPS فقط؛ لا أثر لها عبر HTTP أو داخل وسم meta."))
_r("WEB117", "A", "transport", "low", "certain", "CWE-319", "WSTG-CONF-07", "14.4.5", "3.4.1", "S-HSTS",
   ("HTTPS hop without HSTS before redirecting", "قفزة HTTPS بلا HSTS قبل التوجيه"),
   ("Add the HSTS header to the HTTPS redirect response too.",
    "أضف ترويسة HSTS إلى استجابة التوجيه عبر HTTPS أيضًا."))
_r("WEB118", "A", "transport", "medium", "certain", "CWE-523", "WSTG-ATHN-01", "9.1.1", "12.2.1", "S-REDIR",
   ("Basic/Digest authentication over plain HTTP", "مصادقة Basic أو Digest عبر HTTP غير مشفّر"),
   ("Serve authenticated areas only over HTTPS; Basic sends the password base64-encoded in clear text.",
    "قدّم المناطق المحمية بالمصادقة عبر HTTPS فقط؛ فطريقة Basic ترسل كلمة المرور بترميز base64 مكشوفًا."),
   sevs="medium high")
_r("WEB119", "A", "transport", "info", "tentative", "CWE-200", "WSTG-CRYP-01", "—", "—", "S-BREACH",
   ("Compression on HTTPS pages that carry secrets (BREACH precondition)", "ضغط HTTP على صفحات حساسة (شرط BREACH)"),
   ("Keep compression but mask CSRF tokens per response (e.g. XOR with a random pad) or disable compression on pages "
    "that mix secrets with user input. Treat as informational.",
    "أبقِ الضغط مع إخفاء رموز CSRF في كل استجابة (مثل XOR بقيمة عشوائية)، أو عطّل الضغط في الصفحات التي تخلط الأسرار بمدخلات المستخدم. هذه ملاحظة معلوماتية."),
   sevs="info low")

# =============================================================================================== §2.2 Family B
_CSP = ("CWE-693", "WSTG-CONF-12", "14.4.3", "3.4.3", "S-CSP")
_r("WEB-content-security-policy", "B", "csp", "medium", "firm", *_CSP,
   ("Missing Content-Security-Policy", "ترويسة CSP مفقودة"),
   ("Add a Content-Security-Policy; a strict nonce-based policy is recommended (see the snippet).",
    "أضف ترويسة Content-Security-Policy، ويُنصح بسياسة صارمة قائمة على nonce (انظر المقتطف)."),
   sevs="medium low", existing=True)
_r("WEB040", "B", "csp", "medium", "certain", *_CSP,
   ("CSP allows inline scripts ('unsafe-inline')", "CSP يسمح بسكربتات inline"),
   ("Remove 'unsafe-inline' from script-src and use nonces or hashes (with 'strict-dynamic').",
    "أزل 'unsafe-inline' من script-src واستخدم nonce أو hash (مع 'strict-dynamic')."),
   existing=True, title_1_0="CSP allows 'unsafe-inline' scripts")
_r("WEB041", "B", "csp", "medium", "certain", *_CSP,
   ("CSP allows 'unsafe-eval'", "CSP يسمح بـ unsafe-eval"),
   ("Remove 'unsafe-eval'; replace eval/new Function/string timers in your code and libraries.",
    "أزل 'unsafe-eval' واستبدل eval و new Function والمؤقتات النصية في الشيفرة والمكتبات."),
   existing=True)
_r("WEB042", "B", "csp", "medium", "certain", *_CSP,
   ("CSP lets scripts load from any source", "CSP يسمح بتحميل السكربتات من أي مصدر"),
   ("Replace *, https:, http: and data: in script-src with nonces/hashes and 'strict-dynamic' (or an explicit host list).",
    "استبدل *، https:، http:، data: في script-src بـ nonce/hash و'strict-dynamic' (أو قائمة مضيفين محددة)."),
   existing=True, title_1_0="CSP script source uses wildcard *",
   variants={"non_script": {
       "title_en": "CSP does not restrict scripts", "title_ar": "سياسة CSP لا تقيّد السكربتات",
       "advice_en": "This policy restricts neither script-src nor default-src; add a script policy (nonces or hashes with "
                    "'strict-dynamic').",
       "advice_ar": "هذه السياسة لا تقيّد script-src ولا default-src؛ أضف سياسة للسكربتات (nonce أو hash مع 'strict-dynamic')."}})
_r("WEB043", "B", "csp", "low", "certain", *_CSP,
   ("CSP does not restrict plugins (object-src)", "CSP لا يقيّد الإضافات (object-src)"),
   ("Add object-src 'none'.", "أضف object-src 'none'."),
   sevs="low info", existing=True, title_1_0="CSP missing object-src 'none'")
_r("WEB200", "B", "csp", "medium", "certain", *_CSP,
   ("CSP only in report-only mode", "CSP في وضع التقرير فقط وغير مُطبَّقة"),
   ("Switch the report-only policy to enforcement (Content-Security-Policy) once the reports are clean.",
    "حوّل السياسة من وضع التقرير إلى التطبيق (Content-Security-Policy) بعد خلوّ التقارير من المخالفات."))
_r("WEB201", "B", "csp", "low", "certain", *_CSP,
   ("CSP syntax errors", "أخطاء صياغة في CSP"),
   ("Fix the listed CSP syntax errors; browsers silently ignore invalid parts.",
    "صحّح أخطاء الصياغة المذكورة في CSP؛ المتصفح يتجاهل الأجزاء غير الصالحة دون تنبيه."),
   sevs="low medium info")
_r("WEB202", "B", "csp", "low", "certain", *_CSP,
   ("Duplicate CSP directive ignored", "توجيه مكرر في CSP يُتجاهَل"),
   ("Merge the duplicated directive into one; only the first occurrence is used.",
    "ادمج التوجيه المكرر في توجيه واحد؛ فالمتصفح يستخدم أول ظهور فقط."))
_r("WEB203", "B", "csp", "medium", "certain", *_CSP,
   ("'strict-dynamic' without a nonce or hash", "'strict-dynamic' بلا nonce أو hash"),
   ("Add a per-response nonce (or hashes) to script-src next to 'strict-dynamic'.",
    "أضف nonce يتغيّر مع كل استجابة (أو hash) إلى script-src بجانب 'strict-dynamic'."))
_r("WEB204", "B", "csp", "medium", "certain", *_CSP,
   ("CSP base-uri missing or broad", "base-uri مفقود أو واسع في CSP"),
   ("Add base-uri 'none' (or 'self').", "أضف base-uri 'none' (أو 'self')."),
   sevs="medium info")
_r("WEB205", "B", "csp", "medium", "certain", *_CSP,
   ("CSP form-action missing or broad (form hijacking)", "form-action مفقود أو واسع (اختطاف النماذج)"),
   ("Add form-action 'self' (plus any legitimate external form targets).",
    "أضف form-action 'self' (مع أي وجهات خارجية مشروعة للنماذج)."),
   sevs="medium info")
_r("WEB206", "B", "csp", "medium", "certain", "CWE-1021", "WSTG-CLNT-09", "14.4.7", "3.4.6", "S-FRAME",
   ("CSP frame-ancestors allows any site", "frame-ancestors يسمح بالتضمين من أي موقع"),
   ("Use frame-ancestors 'none' (or 'self' / an explicit list of trusted origins).",
    "استخدم frame-ancestors 'none' (أو 'self' أو قائمة محددة بالمواقع الموثوقة)."))
_r("WEB207", "B", "csp", "medium", "certain", "CWE-693", "WSTG-CONF-12", "14.4.3", "3.4.3", "S-CSP S-FRAME",
   ("CSP directive ignored in a meta tag", "توجيه CSP لا يعمل داخل وسم meta"),
   ("Send frame-ancestors, report-uri and sandbox in the HTTP header; browsers ignore them in <meta>.",
    "أرسل frame-ancestors وreport-uri وsandbox في ترويسة HTTP؛ المتصفح يتجاهلها داخل <meta>."),
   sevs="medium low")
_r("WEB208", "B", "csp", "low", "certain", *_CSP,
   ("Meta CSP placed after scripts or styles", "وسم CSP يأتي بعد سكربتات أو أنماط"),
   ("Make the CSP meta tag the first element in <head>, or send CSP as a header.",
    "اجعل وسم CSP أول عنصر في <head>، أو أرسل CSP كترويسة HTTP."))
_r("WEB209", "B", "csp", "medium", "firm", *_CSP,
   ("CSP allowlists a host that can bypass it (JSONP/AngularJS)", "CSP يسمح بمضيف يمكن تجاوزها عبره"),
   ("Allowlisted hosts serve JSONP or AngularJS that defeat this policy; switch to a nonce-based policy with "
    "'strict-dynamic'.",
    "المضيفون المسموح بهم يقدّمون JSONP أو AngularJS تتيح تجاوز هذه السياسة؛ انتقل إلى سياسة nonce مع 'strict-dynamic'."),
   sevs="medium low")
_r("WEB210", "B", "csp", "medium", "certain", *_CSP,
   ("CSP allows 'unsafe-hashes'", "CSP يسمح بـ 'unsafe-hashes'"),
   ("Remove 'unsafe-hashes' and move inline event handlers into nonce'd scripts (addEventListener).",
    "أزل 'unsafe-hashes' وانقل معالجات الأحداث المضمّنة إلى سكربتات بـ nonce (addEventListener)."))
_r("WEB211", "B", "csp", "medium", "certain", "CWE-319", "WSTG-CONF-12", "14.4.3", "3.4.3", "S-CSP",
   ("CSP allows insecure http: sources on an HTTPS page", "CSP يسمح بمصادر http: غير آمنة"),
   ("Use only https: sources and add upgrade-insecure-requests.",
    "استخدم مصادر https: فقط وأضف upgrade-insecure-requests."),
   sevs="medium low")
_r("WEB212", "B", "csp", "medium", "certain", "CWE-330", "WSTG-CONF-12", "14.4.3", "3.4.3", "S-CSP",
   ("CSP nonce is static (reused across responses)", "قيمة nonce ثابتة لا تتغيّر"),
   ("Generate a new cryptographically random nonce (≥ 128 bits) for every response and do not cache nonce'd pages "
    "publicly.",
    "ولّد nonce عشوائيًا آمنًا جديدًا (128 بت على الأقل) لكل استجابة، ولا تخزّن الصفحات المحتوية على nonce في ذاكرة تخزين عامة."),
   confs="certain firm")
_r("WEB213", "B", "csp", "medium", "certain", "CWE-330", "WSTG-CONF-12", "14.4.3", "3.4.3", "S-CSP",
   ("CSP nonce too short", "قيمة nonce قصيرة"),
   ("Use at least 16 random bytes, base64-encoded, per response.",
    "استخدم 16 بايت عشوائية على الأقل بترميز base64 لكل استجابة."),
   sevs="medium info")
_r("WEB214", "B", "csp", "info", "certain", *_CSP,
   ("CSP allows inline styles", "CSP يسمح بأنماط inline"),
   ("Prefer nonces or hashes for styles; 'unsafe-inline' in style-src allows CSS injection.",
    "يُفضَّل استخدام nonce أو hash للأنماط؛ فالسماح بـ 'unsafe-inline' في style-src يتيح حقن CSS."))
_r("WEB215", "B", "csp", "info", "certain", "CWE-778", "WSTG-CONF-12", "—", "3.4.7", "S-CSP",
   ("CSP reporting not configured", "لا يوجد إعداد للإبلاغ عن مخالفات CSP"),
   ("Add report-to (with a Reporting-Endpoints header) and report-uri for older browsers.",
    "أضف report-to (مع ترويسة Reporting-Endpoints) وreport-uri للمتصفحات الأقدم."),
   sevs="info low")
_r("WEB216", "B", "csp", "info", "certain", "CWE-693", "WSTG-CONF-12", "—", "—", "S-CSP",
   ("Deprecated CSP directive", "توجيه CSP متقادم"),
   ("Remove deprecated directives; they have no effect in current browsers.",
    "احذف التوجيهات المتقادمة؛ فلا أثر لها في المتصفحات الحالية."))
_r("WEB217", "B", "csp", "info", "certain", "CWE-693", "WSTG-CONF-12", "—", "—", "S-CSP",
   ("Obsolete X-Content-Security-Policy / X-WebKit-CSP", "ترويسة CSP قديمة"),
   ("Replace the prefixed header with the standard Content-Security-Policy header.",
    "استبدل الترويسة القديمة بالترويسة القياسية Content-Security-Policy."),
   sevs="info low")
_r("WEB218", "B", "csp", "info", "certain", *_CSP,
   ("Allowlist-only CSP (no nonce/hash)", "سياسة CSP قائمة على المضيفين فقط"),
   ("Consider a strict CSP (nonce or hash + 'strict-dynamic'), which is more robust than host allowlists.",
    "يُنصح بسياسة CSP صارمة (nonce أو hash مع 'strict-dynamic')، فهي أمتن من قوائم المضيفين."))
_r("WEB219", "B", "csp", "info", "certain", "CWE-79", "WSTG-CLNT-01", "—", "—", "S-CSP",
   ("Trusted Types not required (paranoid only)", "Trusted Types غير مفعّل"),
   ("Add require-trusted-types-for 'script' to block DOM XSS sinks.",
    "أضف require-trusted-types-for 'script' لمنع نقاط DOM XSS الخطرة."),
   paranoid=True)

# =============================================================================================== §2.3 Family C
_FRAME = ("CWE-1021", "WSTG-CLNT-09", "14.4.7", "3.4.6", "S-FRAME")
_r("WEB-x-frame-options", "C", "headers", "medium", "firm", *_FRAME,
   ("No clickjacking protection", "لا حماية من Clickjacking"),
   ("Add Content-Security-Policy: frame-ancestors 'none' (or 'self'), and X-Frame-Options: DENY for old browsers.",
    "أضف Content-Security-Policy: frame-ancestors 'none' (أو 'self')، وX-Frame-Options: DENY للمتصفحات القديمة."),
   sevs="medium low", existing=True, title_1_0="Missing X-Frame-Options / frame-ancestors")
_r("WEB300", "C", "headers", "medium", "certain", *_FRAME,
   ("X-Frame-Options value is ineffective", "قيمة X-Frame-Options غير فعّالة"),
   ("Use X-Frame-Options: DENY or SAMEORIGIN; ALLOW-FROM is ignored — use CSP frame-ancestors for an allowlist.",
    "استخدم X-Frame-Options: DENY أو SAMEORIGIN؛ فالقيمة ALLOW-FROM مهملة، واستخدم frame-ancestors في CSP لقائمة السماح."),
   sevs="medium low")
_r("WEB301", "C", "headers", "low", "certain", *_FRAME,
   ("Conflicting or duplicated X-Frame-Options", "قيم X-Frame-Options متعارضة أو مكررة"),
   ("Set X-Frame-Options once, in one layer.", "اضبط X-Frame-Options مرة واحدة وفي طبقة واحدة فقط."),
   sevs="low info")
_r("WEB302", "C", "headers", "low", "certain", *_FRAME,
   ("X-Frame-Options in a meta tag (ignored)", "X-Frame-Options داخل وسم meta (مُهمَل)"),
   ("Send X-Frame-Options as an HTTP header; browsers ignore it in <meta>.",
    "أرسل X-Frame-Options كترويسة HTTP؛ فالمتصفح يتجاهلها داخل <meta>."))
_r("WEB-x-content-type-options", "C", "headers", "low", "firm", "CWE-693", "WSTG-CONF-14", "14.4.4", "3.4.4", "S-XCTO",
   ("Missing X-Content-Type-Options", "ترويسة X-Content-Type-Options مفقودة"),
   ("Send X-Content-Type-Options: nosniff on all responses.", "أرسل X-Content-Type-Options: nosniff في جميع الاستجابات."),
   existing=True)
_r("WEB303", "C", "headers", "low", "certain", "CWE-693", "WSTG-CONF-14", "14.4.4", "3.4.4", "S-XCTO",
   ("X-Content-Type-Options has an invalid value", "قيمة X-Content-Type-Options غير صالحة"),
   ("The only valid value is nosniff.", "القيمة الصالحة الوحيدة هي nosniff."))
_r("WEB-referrer-policy", "C", "headers", "info", "certain", "CWE-200", "WSTG-CONF-14", "14.4.6", "3.4.5", "S-REF",
   ("Missing Referrer-Policy", "ترويسة Referrer-Policy مفقودة"),
   ("Add Referrer-Policy: strict-origin-when-cross-origin (or no-referrer).",
    "أضف Referrer-Policy: strict-origin-when-cross-origin (أو no-referrer)."),
   existing=True)
_r("WEB304", "C", "headers", "medium", "certain", "CWE-200", "WSTG-CONF-14", "14.4.6", "3.4.5", "S-REF",
   ("Referrer-Policy leaks URLs to other sites", "سياسة Referrer تسرّب الروابط لمواقع أخرى"),
   ("Use strict-origin-when-cross-origin, same-origin or no-referrer.",
    "استخدم strict-origin-when-cross-origin أو same-origin أو no-referrer."),
   sevs="medium low")
_r("WEB-permissions-policy", "C", "headers", "info", "certain", "CWE-693", "WSTG-CONF-14", "—", "—", "S-PP",
   ("Missing Permissions-Policy", "ترويسة Permissions-Policy مفقودة"),
   ("Add a Permissions-Policy that disables features you do not use, e.g. camera=(), microphone=(), geolocation=().",
    "أضف Permissions-Policy تعطّل الميزات غير المستخدمة، مثل camera=() وmicrophone=() وgeolocation=()."),
   existing=True)
_r("WEB305", "C", "headers", "medium", "certain", "CWE-693", "WSTG-CONF-14", "—", "—", "S-PP",
   ("Permissions-Policy is invalid (whole header ignored)", "Permissions-Policy غير صالحة فتُتجاهَل كليًا"),
   ("Use structured-field syntax: camera=(), geolocation=(self), fullscreen=(self \"https://trusted.example\").",
    "استخدم صياغة الحقول المهيكلة: camera=() وgeolocation=(self) وfullscreen=(self \"https://trusted.example\")."),
   sevs="medium low info")
_r("WEB306", "C", "headers", "low", "certain", "CWE-693", "WSTG-CONF-14", "—", "—", "S-PP",
   ("Powerful feature allowed for every origin", "ميزة حساسة مسموحة لكل المواقع"),
   ("Restrict the feature to self or named origins.", "قيّد الميزة على self أو على مواقع محددة بالاسم."))
_r("WEB307", "C", "headers", "info", "certain", "CWE-693", "WSTG-CONF-14", "—", "—", "S-PP",
   ("Deprecated Feature-Policy header", "ترويسة Feature-Policy متقادمة"),
   ("Migrate Feature-Policy to Permissions-Policy.", "انقل إعدادات Feature-Policy إلى Permissions-Policy."),
   sevs="info low")
_r("WEB308", "C", "headers", "info", "certain", "CWE-1021", "WSTG-CONF-14", "—", "3.4.8", "S-ISO",
   ("Cross-Origin-Opener-Policy missing or invalid", "ترويسة COOP مفقودة أو غير صالحة"),
   ("Send Cross-Origin-Opener-Policy: same-origin (or same-origin-allow-popups if you rely on OAuth/payment popups).",
    "أرسل Cross-Origin-Opener-Policy: same-origin (أو same-origin-allow-popups إن كنت تعتمد على نوافذ OAuth أو الدفع المنبثقة)."),
   sevs="info low")
_r("WEB309", "C", "headers", "low", "certain", "CWE-693", "WSTG-CONF-14", "—", "—", "S-ISO",
   ("Cross-Origin-Embedder-Policy invalid", "ترويسة COEP غير صالحة"),
   ("Use require-corp or credentialless, sent once.", "استخدم require-corp أو credentialless، مرة واحدة فقط."),
   sevs="low info")
_r("WEB310", "C", "headers", "low", "certain", "CWE-693", "WSTG-CONF-14", "—", "3.5.8", "S-ISO",
   ("Cross-Origin-Resource-Policy invalid or missing on private data", "ترويسة CORP غير صالحة أو مفقودة لبيانات خاصة"),
   ("Send Cross-Origin-Resource-Policy: same-origin (or same-site) on private responses.",
    "أرسل Cross-Origin-Resource-Policy: same-origin (أو same-site) في الاستجابات الخاصة."),
   sevs="low info", confs="certain tentative")
_r("WEB311", "C", "headers", "info", "certain", "CWE-693", "WSTG-CONF-14", "—", "—", "S-DEPR",
   ("X-XSS-Protection enables the legacy XSS auditor", "X-XSS-Protection يفعّل المدقق القديم"),
   ("Set X-XSS-Protection: 0 (or remove it) and rely on CSP; the old auditor caused XS-Leaks.",
    "اضبط X-XSS-Protection: 0 (أو احذفها) واعتمد على CSP؛ فالمدقق القديم كان يسبب تسريبات XS-Leaks."))
_r("WEB312", "C", "headers", "info", "certain", "CWE-693", "WSTG-CONF-14", "—", "—", "S-DEPR",
   ("Deprecated security header", "ترويسة أمان متقادمة"),
   ("Remove deprecated headers (HPKP, Expect-CT); use Cache-Control instead of Pragma.",
    "احذف الترويسات المتقادمة (HPKP وExpect-CT)، واستخدم Cache-Control بدل Pragma."))
_r("WEB313", "C", "headers", "low", "certain", "CWE-345", "WSTG-CONF-14", "14.4.1", "3.2.1", "S-XCTO",
   ("Content-Type missing, multiple or wrong", "نوع المحتوى مفقود أو مكرر أو خاطئ"),
   ("Send exactly one correct Content-Type for every response.", "أرسل ترويسة Content-Type واحدة وصحيحة لكل استجابة."),
   confs="certain firm")
_r("WEB314", "C", "headers", "info", "certain", "CWE-436", "WSTG-CONF-14", "14.4.1", "3.2.1", "S-XCTO",
   ("HTML without a declared charset, or conflicting charsets", "صفحة HTML بلا ترميز محدد أو بترميزات متعارضة"),
   ("Declare UTF-8 in the Content-Type header (text/html; charset=utf-8).",
    "صرّح بترميز UTF-8 في ترويسة Content-Type (text/html; charset=utf-8)."))
_r("WEB315", "C", "headers", "medium", "firm", "CWE-525", "WSTG-ATHN-06", "8.2.1", "14.3.2", "S-CACHE",
   ("Sensitive response can be cached", "استجابة حساسة قابلة للتخزين المؤقت"),
   ("Send Cache-Control: no-store on responses with personal or session data; never mark them public.",
    "أرسل Cache-Control: no-store في الاستجابات التي تحوي بيانات شخصية أو بيانات جلسة، ولا تجعلها public أبدًا."),
   sevs="high medium low", confs="certain firm")
_r("WEB316", "C", "headers", "low", "certain", "CWE-942", "WSTG-CONF-14", "—", "—", "S-DEPR",
   ("X-Permitted-Cross-Domain-Policies allows all", "X-Permitted-Cross-Domain-Policies تسمح بالكل"),
   ("Set X-Permitted-Cross-Domain-Policies: none.", "اضبط X-Permitted-Cross-Domain-Policies: none."),
   sevs="low info")
_r("WEB317", "C", "headers", "low", "certain", "CWE-693", "WSTG-SESS-06", "8.2.3", "14.3.1", "S-CACHE",
   ("Clear-Site-Data misconfigured", "ترويسة Clear-Site-Data بإعداد خاطئ"),
   ("Quote every value (\"cache\", \"cookies\", \"storage\") and send it only on the logout response.",
    "ضع كل قيمة بين علامتي تنصيص (\"cache\" و\"cookies\" و\"storage\") وأرسلها في استجابة تسجيل الخروج فقط."))
_r("WEB318", "C", "headers", "info", "certain", "CWE-693", "WSTG-CONF-14", "14.4.1", "3.4.1", "S-HSTS S-CSP S-FRAME S-XCTO",
   ("Security headers dropped on error responses", "ترويسات الأمان تسقط من صفحات الخطأ"),
   ("Send the security headers on error responses too (nginx: add_header … always; Apache: Header always set).",
    "أرسل ترويسات الأمان في استجابات الخطأ أيضًا (nginx: add_header … always، وApache: Header always set)."))

# =============================================================================================== §2.4 Family D
_CORS = ("CWE-942", "WSTG-CLNT-07", "14.5.3", "3.4.2", "S-CORS")
_CORS_ADVICE = (
    "Return Access-Control-Allow-Origin only for an explicit allowlist of trusted https origins, never reflect the Origin "
    "header, never allow \"null\", and add Vary: Origin.",
    "أعد Access-Control-Allow-Origin لقائمة سماح محددة من أصول https موثوقة فقط، ولا تعكس ترويسة Origin أبدًا، ولا تسمح بالأصل null، وأضف Vary: Origin.")
for _rid, _sev, _sevs, _conf, _en, _ar in (
        ("WEB320", "high", "", "certain", "Any website can read authenticated responses (Origin reflected with credentials)",
         "أي موقع يستطيع قراءة الاستجابات الموثقة"),
        ("WEB321", "low", "low medium", "certain", "Origin reflected without credentials", "أصل الطلب يُعاد بلا اعتماديات"),
        ("WEB322", "medium", "medium high", "certain", "CORS trusts the \"null\" origin", "CORS يثق بالأصل null"),
        ("WEB323", "low", "", "certain", "ACAO * combined with credentials (invalid)", "ACAO * مع الاعتماديات (تركيبة غير صالحة)"),
        ("WEB324", "low", "", "certain", "Reflected ACAO without Vary: Origin", "إعادة الأصل بلا Vary: Origin"),
        ("WEB325", "low", "", "certain", "Invalid ACAO value", "قيمة ACAO غير صالحة"),
        ("WEB326", "low", "", "certain", "CORS trusts an http:// origin on an https site", "CORS يثق بأصل http على موقع https"),
        ("WEB327", "low", "", "tentative", "Public CORS on a response with session data", "CORS عام على استجابة تحوي بيانات جلسة")):
    _r(_rid, "D", "cors", _sev, _conf, *_CORS, (_en, _ar), _CORS_ADVICE, sevs=_sevs)

# =============================================================================================== §2.5 Family E
_r("WEB020", "E", "cookies", "high", "certain", "CWE-614", "WSTG-SESS-02", "3.4.1", "3.3.1", "S-COOKIE",
   ("Cookie without Secure flag", "كوكي بدون علامة Secure"),
   ("Add the Secure attribute (and preferably the __Host- prefix) to this cookie.",
    "أضف السمة Secure إلى هذه الكوكي (ويُفضَّل استخدام البادئة __Host-)."),
   sevs="high medium low info", confs="certain tentative",
   title=("Cookie without Secure flag: {cookie}", "كوكي بدون علامة Secure: {cookie}"), existing=True)
_r("WEB021", "E", "cookies", "medium", "firm", "CWE-1004", "WSTG-SESS-02", "3.4.2", "3.3.4", "S-COOKIE",
   ("Session cookie without HttpOnly", "كوكي جلسة بدون HttpOnly"),
   ("Add HttpOnly so page scripts cannot read the session cookie.",
    "أضف HttpOnly حتى لا تستطيع سكربتات الصفحة قراءة كوكي الجلسة."),
   sevs="medium info", confs="certain firm tentative",
   title=("Session cookie without HttpOnly: {cookie}", "كوكي جلسة بدون HttpOnly: {cookie}"), existing=True,
   title_1_0="Cookie without HttpOnly flag: {cookie}")
_r("WEB022", "E", "cookies", "low", "certain", "CWE-1275", "WSTG-SESS-02", "3.4.3", "3.3.2", "S-COOKIE",
   ("Cookie without SameSite", "كوكي بدون SameSite"),
   ("Set SameSite=Lax (or Strict) explicitly.", "اضبط SameSite=Lax (أو Strict) صراحةً."),
   sevs="low info", confs="certain tentative",
   title=("Cookie without SameSite: {cookie}", "كوكي بدون SameSite: {cookie}"), existing=True)


def _cookie(rid, sev, sevs, conf, cwe, asvs4, asvs5, name, advice, *, confs="", paranoid=False):
    _r(rid, "E", "cookies", sev, conf, cwe, "WSTG-SESS-02", asvs4, asvs5, "S-COOKIE", name, advice, sevs=sevs,
       confs=confs, paranoid=paranoid, title=(name[0] + ": {cookie}", name[1] + ": {cookie}"))


_cookie("WEB400", "medium", "", "certain", "CWE-1275", "3.4.3", "3.3.2",
        ("SameSite=None without Secure (cookie rejected)", "SameSite=None بلا Secure (يرفضها المتصفح)"),
        ("Add Secure, or use Lax/Strict.", "أضف Secure أو استخدم Lax أو Strict."))
_cookie("WEB401", "medium", "", "certain", "CWE-614", "3.4.4", "3.3.1",
        ("Cookie prefix rules broken (cookie rejected)", "قواعد بادئة الكوكي مخالفة (يرفضها المتصفح)"),
        ("Meet the prefix rules (__Host-: Secure; Path=/; no Domain).",
         "استوفِ قواعد البادئة (__Host- تتطلب Secure وPath=/ وبلا Domain)."))
_cookie("WEB402", "low", "", "certain", "CWE-1275", "3.4.3", "3.3.2",
        ("Invalid SameSite value", "قيمة SameSite غير صالحة"),
        ("Use Strict, Lax or None.", "استخدم Strict أو Lax أو None."))
_cookie("WEB403", "medium", "", "certain", "CWE-614", "—", "3.3.1",
        ("Partitioned without Secure (cookie rejected)", "Partitioned بلا Secure"),
        ("Add Secure (and prefer __Host-).", "أضف Secure (ويُفضّل __Host-)."))
_cookie("WEB404", "low", "", "certain", "CWE-565", "3.4.5", "3.3.3",
        ("Cookie scoped too broadly or to a foreign domain", "نطاق الكوكي واسع أو لا يطابق المضيف"),
        ("Omit Domain (host-only) or set it to the narrowest needed host.",
         "احذف السمة Domain (لتصبح خاصة بالمضيف) أو اجعلها أضيق نطاق ممكن."),
        confs="certain tentative")
_cookie("WEB405", "low", "low info", "certain", "CWE-613", "—", "—",
        ("Long-lived session cookie", "كوكي جلسة طويلة العمر"),
        ("Keep session cookies short-lived; use a separate remember-me token if needed.",
         "اجعل كوكي الجلسة قصيرة العمر، واستخدم رمز \"تذكّرني\" منفصلًا عند الحاجة."),
        confs="certain tentative")
_cookie("WEB406", "low", "", "certain", "CWE-436", "—", "—",
        ("Same cookie set more than once in one response", "الكوكي نفسها تُضبط أكثر من مرة"),
        ("Set each cookie once.", "اضبط كل كوكي مرة واحدة."))
_cookie("WEB407", "low", "low info", "certain", "CWE-1275", "3.4.3", "3.3.2",
        ("Session cookie sent on cross-site requests (SameSite=None)", "كوكي الجلسة تُرسل في الطلبات عبر المواقع"),
        ("Use Lax or Strict unless cross-site embedding is required.",
         "استخدم Lax أو Strict ما لم يكن التضمين عبر المواقع ضروريًا."),
        confs="certain tentative")
_cookie("WEB408", "low", "", "certain", "CWE-436", "—", "3.3.5",
        ("Cookie too large (ignored by browsers)", "كوكي كبيرة جدًا (يتجاهلها المتصفح)"),
        ("Keep name and value under 4096 bytes.", "اجعل الاسم والقيمة معًا أقل من 4096 بايت."))
_cookie("WEB409", "info", "", "certain", "CWE-614", "3.4.4", "3.3.3",
        ("Session cookie without the __Host- prefix", "كوكي جلسة بلا البادئة __Host-"),
        ("Rename to __Host-<name> (Secure; Path=/; no Domain).", "أعد تسميتها إلى __Host-<الاسم> مع Secure وPath=/ وبلا Domain."),
        confs="certain tentative", paranoid=True)
_cookie("WEB410", "low", "", "certain", "CWE-614", "—", "—",
        ("Secure attribute on a cookie set over HTTP (ignored)", "سمة Secure على كوكي عبر HTTP (مُهمَلة)"),
        ("Serve the site over HTTPS.", "قدّم الموقع عبر HTTPS."))
_cookie("WEB411", "low", "", "certain", "CWE-200", "—", "—",
        ("Load-balancer cookie reveals an internal address", "كوكي موازن الحمل يكشف عنوانًا داخليًا"),
        ("Enable cookie encryption on the BIG-IP persistence profile.", "فعّل تشفير كوكي الاستمرارية في ملف إعداد BIG-IP."))
_cookie("WEB412", "medium", "medium low", "firm", "CWE-315", "3.5.3", "14.3.3",
        ("Sensitive data in a cookie value", "بيانات حساسة في قيمة الكوكي"),
        ("Do not store secrets or personal data in cookies; use opaque session ids.",
         "لا تخزّن أسرارًا أو بيانات شخصية في الكوكيز، واستخدم معرّفات جلسة عشوائية."))
_cookie("WEB413", "high", "high low", "certain", "CWE-319", "3.4.1", "3.3.1",
        ("Session cookie issued over plain HTTP", "كوكي جلسة تُصدَر عبر HTTP غير مشفّر"),
        ("Issue session cookies only on HTTPS responses; make the HTTP listener redirect without setting cookies.",
         "أصدر كوكيز الجلسة في استجابات HTTPS فقط، واجعل مستمع HTTP يعيد التوجيه دون ضبط أي كوكي."),
        confs="certain tentative")
_cookie("WEB414", "low", "", "certain", "CWE-1004", "3.4.2", "3.3.4",
        ("Session token exposed in page content (HttpOnly bypassed)", "رمز الجلسة مكشوف داخل محتوى الصفحة"),
        ("Never render the session token into HTML or JavaScript; keep it only in an HttpOnly cookie.",
         "لا تضع رمز الجلسة داخل HTML أو JavaScript أبدًا، واحفظه في كوكي HttpOnly فقط."))

# =============================================================================================== §2.6 Family F
_r("WEB050", "F", "content", "medium", "certain", "CWE-319", "WSTG-CRYP-03", "9.1.1", "12.2.1", "S-MIXED",
   ("Mixed content on an HTTPS page", "محتوى مختلط في صفحة HTTPS"),
   ("Load every subresource over https:// (and add CSP upgrade-insecure-requests as a safety net).",
    "حمّل كل الموارد الفرعية عبر https:// (وأضف upgrade-insecure-requests في CSP كشبكة أمان)."),
   sevs="medium low info", existing=True, title_1_0="Mixed content: insecure resource on HTTPS page")
_r("WEB051", "F", "content", "high", "certain", "CWE-319", "WSTG-ATHN-01", "9.1.1", "12.2.1", "S-MIXED",
   ("Form submits over plain HTTP", "نموذج يُرسل عبر HTTP"),
   ("Make the form action https://.", "اجعل وجهة النموذج (action) عبر https://."),
   sevs="high medium", existing=True)
_r("WEB052", "F", "content", "high", "certain", "CWE-523", "WSTG-ATHN-01", "9.1.1", "12.2.1", "S-REDIR",
   ("Password field on a non-HTTPS page", "حقل كلمة مرور في صفحة غير HTTPS"),
   ("Serve login pages only over HTTPS.", "قدّم صفحات تسجيل الدخول عبر HTTPS فقط."),
   existing=True, title_1_0="Password field on non-HTTPS page")
_r("WEB053", "F", "content", "low", "certain", "CWE-353", "WSTG-CONF-14", "14.2.3", "3.6.1", "S-SRI",
   ("External script or stylesheet without Subresource Integrity", "سكربت أو ملف أنماط خارجي بلا SRI"),
   ("Add integrity=\"sha384-…\" and crossorigin=\"anonymous\" to third-party scripts and stylesheets (or self-host them).",
    "أضف integrity=\"sha384-…\" وcrossorigin=\"anonymous\" للسكربتات وملفات الأنماط من أطراف ثالثة (أو استضفها على خادمك)."),
   sevs="low info", existing=True, title_1_0="External script without Subresource Integrity")
_r("WEB500", "F", "content", "low", "certain", "CWE-353", "—", "14.2.3", "3.6.1", "S-SRI",
   ("SRI without crossorigin: the browser blocks the file", "SRI بلا crossorigin: المتصفح يحجب الملف"),
   ("Add crossorigin=\"anonymous\" (the file is currently blocked).", "أضف crossorigin=\"anonymous\" (الملف محجوب حاليًا)."))
_r("WEB501", "F", "content", "low", "certain", "CWE-353", "—", "14.2.3", "3.6.1", "S-SRI",
   ("SRI value malformed or weak", "قيمة SRI تالفة أو ضعيفة"),
   ("Use sha384- or sha512- hashes.", "استخدم تجزئة sha384- أو sha512-."))
_r("WEB502", "F", "content", "medium", "certain", "CWE-319", "WSTG-CRYP-03", "9.1.1", "12.2.1", "S-MIXED",
   ("SRI-protected resource loaded over HTTP", "مورد محمي بـ SRI يُحمَّل عبر HTTP"),
   ("Load it over https.", "حمّله عبر https."))
_r("WEB503", "F", "content", "medium", "firm", "CWE-353", "—", "14.2.3", "3.6.1", "S-SRI",
   ("SRI hash does not match the served file", "تجزئة SRI لا تطابق الملف المقدَّم"),
   ("Update the hash after verifying the file; investigate an unexpected change.",
    "حدّث قيمة التجزئة بعد التحقق من الملف، وتحقّق من سبب أي تغيير غير متوقع."))
_r("WEB504", "F", "content", "low", "certain", "CWE-319", "WSTG-ATHN-01", "9.1.1", "12.2.1", "S-REDIR",
   ("HTTP page posts a form to HTTPS (MITM can change it)", "صفحة HTTP ترسل نموذجًا إلى HTTPS"),
   ("Serve the page itself over HTTPS.", "قدّم الصفحة نفسها عبر HTTPS."))
_r("WEB505", "F", "content", "low", "certain", "CWE-1022", "WSTG-CLNT-14", "—", "—", "S-HTML",
   ("Link gives the opened site control of this page (reverse tabnabbing)", "رابط يمنح الموقع المفتوح تحكمًا بهذه الصفحة"),
   ("Remove rel=\"opener\" (use noopener).", "احذف rel=\"opener\" (واستخدم noopener)."))
_r("WEB506", "F", "content", "high", "certain", "CWE-829", "—", "10.3.2", "15.2.4", "S-SRI",
   ("Script from a known malicious or compromised CDN", "سكربت من شبكة توزيع معروفة بأنها خبيثة أو مخترقة"),
   ("Remove it immediately and self-host a trusted copy.", "أزله فورًا واستضف نسخة موثوقة على خادمك."),
   confs="certain firm")
_r("WEB507", "F", "content", "high", "firm", "CWE-506", "—", "—", "—", "S-INCIDENT",
   ("Signs of compromise (cryptominer, injected loader, defacement)", "مؤشرات اختراق (معدِّن عملات، محمّل مزروع، تشويه)"),
   ("Treat as a security incident: take a clean backup, rotate credentials, find the entry point.",
    "تعامل معه كحادث أمني: استعد نسخة نظيفة، وغيّر بيانات الاعتماد، وابحث عن نقطة الاختراق."))
_r("WEB508", "F", "content", "info", "certain", "CWE-521", "WSTG-ATHN-05", "—", "6.2.7", "S-HTML",
   ("Password field blocks password managers or paste", "حقل كلمة المرور يمنع مدير كلمات المرور أو اللصق"),
   ("Allow paste and password managers (use autocomplete=\"current-password\"/\"new-password\").",
    "اسمح باللصق وبمديري كلمات المرور (استخدم autocomplete=\"current-password\" أو \"new-password\")."))
_r("WEB509", "F", "content", "high", "certain", "CWE-598", "WSTG-ATHN-01", "8.3.1", "14.2.1", "S-HTML",
   ("Login form sends the password in the URL (GET)", "نموذج الدخول يرسل كلمة المرور في الرابط (GET)"),
   ("Use method=\"post\".", "استخدم method=\"post\"."),
   sevs="high low", confs="certain tentative")
_r("WEB510", "F", "content", "medium", "certain", "CWE-598", "WSTG-SESS-04", "3.1.1", "14.2.1", "S-COOKIE",
   ("Session id in URLs", "معرّف الجلسة في الروابط"),
   ("Keep session ids in cookies only.", "احتفظ بمعرّف الجلسة في الكوكيز فقط."))
_r("WEB511", "F", "content", "low", "tentative", "CWE-598", "WSTG-SESS-04", "8.3.1", "14.2.1", "S-HTML",
   ("Sensitive data in URLs", "بيانات حساسة في الروابط"),
   ("Send sensitive values in the request body or headers, not the URL.",
    "أرسل القيم الحساسة في جسم الطلب أو الترويسات لا في الرابط."))
_r("WEB512", "F", "content", "info", "tentative", "CWE-601", "WSTG-CLNT-04", "5.1.5", "3.7.2", "S-HTML",
   ("Redirect-style parameter with an absolute URL (possible open redirect, not tested)",
    "معامل توجيه بعنوان كامل (احتمال توجيه مفتوح، لم يُختبَر)"),
   ("Allow only relative paths or an allowlist of destinations.", "اسمح فقط بمسارات نسبية أو بقائمة وجهات معتمدة."))
_r("WEB513", "F", "content", "info", "certain", "CWE-434", "WSTG-BUSL-08", "12.5.2", "5.3.1", "S-HTML",
   ("File upload form (attack-surface inventory)", "نموذج رفع ملفات (حصر لسطح الهجوم)"),
   ("Validate type and size server-side and serve uploads from a separate origin with Content-Disposition: attachment.",
    "تحقّق من النوع والحجم في الخادم وقدّم الملفات المرفوعة من نطاق منفصل مع Content-Disposition: attachment."))
_r("WEB514", "F", "content", "info", "firm", "CWE-436", "—", "—", "—", "S-HTML",
   ("Quirks mode with relative stylesheet (path-relative style import precondition)", "وضع quirks مع ملف أنماط نسبي"),
   ("Add <!doctype html> and use root-relative or absolute stylesheet URLs.",
    "أضف <!doctype html> واستخدم روابط أنماط مطلقة أو تبدأ من الجذر."))
_r("WEB515", "F", "content", "info", "certain", "CWE-693", "WSTG-CONF-12", "—", "—", "S-CSP",
   ("Inline event handlers or javascript: URLs block a strict CSP", "معالجات أحداث مضمّنة تعيق CSP صارمة"),
   ("Move inline event handlers and javascript: URLs into script files (addEventListener) to prepare for a strict CSP.",
    "انقل معالجات الأحداث المضمّنة وروابط javascript: إلى ملفات سكربت (addEventListener) تمهيدًا لسياسة CSP صارمة."),
   paranoid=True)
_r("WEB516", "F", "content", "info", "tentative", "CWE-352", "WSTG-SESS-05", "4.2.2", "3.5.1", "S-COOKIE",
   ("State-changing form without an anti-CSRF token (paranoid only)", "نموذج بلا رمز مضاد لـ CSRF"),
   ("Use anti-CSRF tokens and SameSite cookies.", "استخدم رموزًا مضادة لـ CSRF وكوكيز SameSite."),
   paranoid=True)
_r("WEB517", "F", "content", "high", "firm", "CWE-829", "WSTG-CONF-10", "14.2.3", "15.2.4", "S-SRI",
   ("Page loads code from a host or bucket that does not exist (hijackable)",
    "الصفحة تحمّل شيفرة من مضيف أو حاوية تخزين غير موجودة (قابلة للاستيلاء)"),
   ("Remove the reference or host the file yourself; check whether the domain has expired.",
    "أزل المرجع أو استضف الملف على خادمك، وتحقّق مما إذا كان النطاق قد انتهى تسجيله."),
   sevs="high medium low info", confs="firm tentative")
_r("WEB518", "F", "content", "low", "firm", "CWE-201", "WSTG-ATHN-01", "—", "14.2.1", "S-HTML",
   ("Password form submits to another site", "نموذج كلمة المرور يُرسَل إلى موقع آخر"),
   ("Post credentials only to your own origin; investigate the form if you did not add it.",
    "أرسل بيانات الدخول إلى نطاقك فقط، وافحص النموذج إن لم تكن أنت من أضافه."),
   sevs="low medium")
_r("WEB519", "F", "content", "low", "certain", "CWE-829", "WSTG-CONF-14", "14.2.3", "15.2.4", "S-SRI",
   ("Third-party script from a mutable (unpinned) package-CDN URL", "سكربت خارجي من رابط CDN غير مثبّت الإصدار"),
   ("Pin an exact version (pkg@1.2.3) and add an integrity hash, or self-host the file.",
    "ثبّت إصدارًا محددًا (pkg@1.2.3) وأضف قيمة integrity، أو استضف الملف على خادمك."))
_DOM_ADVICE = (
    "Treat URL fragments, query strings and messages as untrusted: use textContent / safe DOM APIs and validate redirect "
    "targets and message origins.",
    "اعتبر أجزاء الرابط والاستعلام والرسائل بيانات غير موثوقة: استخدم textContent وواجهات DOM الآمنة، وتحقّق من وجهات التوجيه ومصدر الرسائل.")
_r("WEB520", "F", "domxss", "medium", "firm", "CWE-79", "WSTG-CLNT-01", "5.3.3", "3.2.2", "S-HTML",
   ("DOM-based XSS flow in page script", "تدفق DOM XSS في سكربت الصفحة"), _DOM_ADVICE, confs="firm tentative")
_r("WEB521", "F", "domxss", "low", "firm", "CWE-601", "WSTG-CLNT-04", "5.1.5", "3.7.2", "S-HTML",
   ("DOM-based open redirect in page script", "توجيه مفتوح عبر DOM في سكربت الصفحة"), _DOM_ADVICE, confs="firm tentative")
_r("WEB522", "F", "domxss", "low", "tentative", "CWE-346", "WSTG-CLNT-11", "—", "3.5.5", "S-HTML",
   ("postMessage handler without origin check", "معالج postMessage بلا تحقق من المصدر"), _DOM_ADVICE,
   confs="firm tentative")

# =============================================================================================== §2.7 Family G
_r("WEB010", "G", "disclosure", "low", "certain", "CWE-497", "WSTG-INFO-02", "14.3.3", "13.4.6", "S-BANNER",
   ("Server header reveals version", "ترويسة Server تكشف الإصدار"),
   ("Hide version numbers from the Server header.", "أخفِ أرقام الإصدارات من ترويسة Server."),
   sevs="low info", title=("Server header reveals version: {value}", "ترويسة Server تكشف الإصدار: {value}"),
   existing=True)
_r("WEB011", "G", "disclosure", "low", "certain", "CWE-497", "WSTG-INFO-08", "14.3.3", "13.4.6", "S-BANNER",
   ("X-Powered-By reveals the stack", "ترويسة X-Powered-By تكشف التقنية"),
   ("Remove the X-Powered-By header.", "احذف ترويسة X-Powered-By."),
   sevs="low info", title=("X-Powered-By reveals the stack: {value}", "ترويسة X-Powered-By تكشف التقنية: {value}"),
   existing=True, title_1_0="X-Powered-By reveals stack: {value}")
_r("WEB055", "G", "disclosure", "medium", "certain", "CWE-548", "WSTG-CONF-04", "4.3.2", "13.4.3", "S-DIRLIST",
   ("Directory listing enabled", "عرض فهرس المجلدات مفعّل"),
   ("Disable automatic directory listing on the web server.", "عطّل العرض التلقائي لفهرس المجلدات في خادم الويب."),
   existing=True)
_r("WEB056", "G", "disclosure", "medium", "firm", "CWE-209", "WSTG-ERRH-02", "7.4.1", "16.5.1", "S-ERR",
   ("Stack trace or detailed error in response", "أثر استثناء أو خطأ تفصيلي في الاستجابة"),
   ("Show a generic error page in production and log the details on the server.",
    "اعرض صفحة خطأ عامة في بيئة الإنتاج وسجّل التفاصيل في الخادم."),
   confs="firm tentative", existing=True, title_1_0="Stack trace / debug output in response")
_r("WEB600", "G", "disclosure", "low", "certain", "CWE-497", "WSTG-INFO-02", "14.3.3", "13.4.6", "S-BANNER",
   ("Header reveals backend software or version", "ترويسة تكشف برمجيات الخلفية أو إصدارها"),
   ("Remove these headers at the proxy.", "احذف هذه الترويسات عند الوكيل العكسي."),
   sevs="low info", title=("Header reveals backend software or version: {header}", "ترويسة تكشف برمجيات الخلفية أو إصدارها: {header}"))
_r("WEB601", "G", "disclosure", "medium", "certain", "CWE-489", "WSTG-ERRH-02", "14.3.2", "13.4.2", "S-ERR",
   ("Debug or profiler header exposed", "ترويسة تصحيح أو تحليل أداء مكشوفة"),
   ("Disable debug toolbars and profilers in production.", "عطّل أشرطة التصحيح وأدوات تحليل الأداء في بيئة الإنتاج."),
   title=("Debug or profiler header exposed: {header}", "ترويسة تصحيح أو تحليل أداء مكشوفة: {header}"))
_r("WEB602", "G", "disclosure", "low", "certain", "CWE-540", "WSTG-INFO-05", "14.3.2", "13.4.7", "S-DOTFILES",
   ("Source map exposed", "خريطة المصدر (source map) مكشوفة"),
   ("Do not deploy .map files to production (or restrict them).", "لا تنشر ملفات .map في الإنتاج (أو قيّد الوصول إليها)."),
   sevs="low info")
_r("WEB603", "G", "disclosure", "low", "firm", "CWE-200", "WSTG-INFO-05", "—", "—", "S-BANNER",
   ("Internal IP address disclosed", "كشف عنوان IP داخلي"),
   ("Remove internal addresses from responses.", "أزل العناوين الداخلية من الاستجابات."),
   confs="firm tentative")
_r("WEB604", "G", "disclosure", "info", "certain", "CWE-200", "WSTG-INFO-02", "—", "—", "S-BANNER",
   ("ETag reveals inode numbers", "ترويسة ETag تكشف أرقام inode"),
   ("Set FileETag MTime Size.", "اضبط FileETag MTime Size."))
_r("WEB605", "G", "disclosure", "high", "certain", "CWE-489", "WSTG-ERRH-02", "14.3.2", "13.4.2", "S-ERR",
   ("Framework debug mode enabled", "وضع التصحيح للإطار مفعّل"),
   ("Turn off debug mode in production.", "أوقف وضع التصحيح في بيئة الإنتاج."),
   sevs="critical high")
_r("WEB606", "G", "disclosure", "medium", "firm", "CWE-209", "WSTG-ERRH-01", "7.4.1", "16.5.1", "S-ERR",
   ("Database error message disclosed", "كشف رسالة خطأ قاعدة البيانات"),
   ("Catch database errors and return a generic message.", "التقط أخطاء قاعدة البيانات وأعد رسالة عامة."))
_r("WEB607", "G", "disclosure", "low", "tentative", "CWE-209", "WSTG-ERRH-01", "7.4.1", "16.5.1", "S-ERR",
   ("Server file path disclosed in an error", "كشف مسار ملف في الخادم ضمن رسالة خطأ"),
   ("Hide internal paths in error output.", "أخفِ المسارات الداخلية من رسائل الخطأ."))
_r("WEB608", "G", "disclosure", "medium", "firm", "CWE-540", "WSTG-CONF-03", "12.5.1", "13.4.7", "S-DOTFILES",
   ("Server-side source code disclosed", "كشف شيفرة المصدر من جهة الخادم"),
   ("Make sure server-side files are executed, never served as text.", "تأكد من تنفيذ ملفات الخادم وعدم تقديمها كنص."))
_r("WEB609", "G", "disclosure", "critical", "firm", "CWE-798", "WSTG-INFO-05", "2.10.4", "13.3.1", "S-SECRET",
   ("Secret or private key in client-side code", "سرّ أو مفتاح خاص في الشيفرة المقدَّمة للمتصفح"),
   ("Revoke the secret now and move it server-side.", "أبطل السرّ فورًا وانقله إلى جهة الخادم."),
   sevs="critical high low", confs="certain firm tentative")
_r("WEB610", "G", "disclosure", "medium", "firm", "CWE-502", "—", "1.5.2", "1.5.2", "S-SECRET",
   ("Serialized object in a response or cookie", "كائن مُسلسَل في استجابة أو كوكي"),
   ("Do not send native serialized objects to clients; use signed JSON.",
    "لا ترسل كائنات مُسلسَلة أصلية إلى العميل؛ استخدم JSON موقّعًا."))
_r("WEB611", "G", "disclosure", "high", "firm", "CWE-642", "—", "—", "—", "S-ERR",
   ("ViewState without integrity protection", "ViewState بلا حماية سلامة"),
   ("Enable ViewState MAC/encryption (ASP.NET) or server-side state (JSF).",
    "فعّل MAC/التشفير لـ ViewState في ASP.NET أو حالة الخادم في JSF."),
   sevs="high medium", confs="firm tentative")
_r("WEB612", "G", "disclosure", "medium", "firm", "CWE-200", "WSTG-INFO-05", "—", "—", "S-SECRET",
   ("Password hash disclosed", "كشف تجزئة كلمة مرور"),
   ("Never return password hashes to clients.", "لا تُرجع تجزئات كلمات المرور إلى العميل أبدًا."))
_r("WEB613", "G", "disclosure", "medium", "firm", "CWE-359", "WSTG-INFO-05", "—", "14.2.6", "S-SECRET",
   ("Payment card number in a page", "رقم بطاقة دفع في الصفحة"),
   ("Remove or mask card numbers (show at most the last 4 digits).", "أزل أرقام البطاقات أو أخفها (اعرض آخر 4 أرقام فقط)."),
   sevs="medium info")
_r("WEB614", "G", "disclosure", "info", "tentative", "CWE-615", "WSTG-INFO-05", "—", "—", "S-HTML",
   ("Sensitive HTML comment (paranoid only)", "تعليق HTML حساس"),
   ("Strip comments from production HTML.", "احذف التعليقات من HTML في الإنتاج."),
   paranoid=True)
_r("WEB615", "G", "disclosure", "high", "tentative", "CWE-119", "WSTG-CRYP-01", "9.1.2", "12.1.2", "S-TLS",
   ("OpenSSL version vulnerable to Heartbleed (from banner)", "إصدار OpenSSL عرضة لـ Heartbleed (من الترويسة)"),
   ("Upgrade OpenSSL and reissue keys.", "حدّث OpenSSL وأعد إصدار المفاتيح."))
_r("WEB616", "G", "disclosure", "low", "certain", "CWE-497", "WSTG-INFO-02", "14.3.3", "13.4.6", "S-BANNER",
   ("Server version shown on error pages", "إصدار الخادم يظهر في صفحات الخطأ"),
   ("Use custom error pages without version strings.", "استخدم صفحات خطأ مخصصة بلا أرقام إصدارات."))
_r("WEB617", "G", "disclosure", "low", "certain", "CWE-1188", "WSTG-CONF-02", "14.2.2", "—", "S-DOTFILES",
   ("Default server page or parked domain", "صفحة الخادم الافتراضية أو نطاق مركون"),
   ("Replace the default page and remove sample content.", "استبدل الصفحة الافتراضية واحذف المحتوى التجريبي."),
   sevs="low info")
_r("WEB619", "G", "disclosure", "low", "certain", "CWE-200", "WSTG-INFO-05", "—", "14.2.8", "S-HTML",
   ("Image metadata reveals a GPS location", "بيانات صورة تكشف موقعًا جغرافيًا"),
   ("Strip EXIF metadata from published images.", "احذف بيانات EXIF من الصور المنشورة."))

# =============================================================================================== §2.8 Family H
_TLS_WSTG = "WSTG-CRYP-01"


def _tls(rid, sev, sevs, conf, cwe, asvs4, asvs5, name, advice, *, confs="", paranoid=False, title=None, existing=False,
         title_1_0=""):
    _r(rid, "H", "tls", sev, conf, cwe, _TLS_WSTG, asvs4, asvs5, "S-TLS", name, advice, sevs=sevs, confs=confs,
       paranoid=paranoid, title=title, existing=existing, title_1_0=title_1_0)


_tls("WEB030", "medium", "", "certain", "CWE-327", "9.1.3", "12.1.1",
     ("Server accepts TLS 1.0 / 1.1", "الخادم يقبل TLS 1.0 أو 1.1"),
     ("Allow only TLS 1.2 and 1.3.", "اسمح فقط بـ TLS 1.2 و1.3."),
     title=("Server accepts {versions}", "الخادم يقبل {versions}"), existing=True)
_tls("WEB070", "high", "", "certain", "CWE-298", "9.1.1", "12.2.2",
     ("TLS certificate expired", "شهادة TLS منتهية"),
     ("Renew the certificate now (automate renewal).", "جدّد الشهادة فورًا (واجعل التجديد آليًا)."), existing=True)
_tls("WEB071", "medium", "medium low", "certain", "CWE-298", "—", "12.2.2",
     ("TLS certificate expires soon", "شهادة TLS تقترب من الانتهاء"),
     ("Renew before expiry; automate with ACME.", "جدّد قبل الانتهاء، واجعل ذلك آليًا عبر ACME."),
     title=("TLS certificate expires in {days}", "شهادة TLS تقترب من الانتهاء (تنتهي خلال {days})"), existing=True,
     title_1_0="TLS certificate expires in {days} days")
_tls("WEB072", "high", "", "certain", "CWE-295", "9.1.1", "12.2.2",
     ("TLS certificate does not validate", "شهادة TLS لا تجتاز التحقق"),
     ("Use a publicly trusted certificate that matches the host.", "استخدم شهادة موثوقة عامة تطابق اسم المضيف."),
     existing=True)
_tls("WEB700", "high", "", "certain", "CWE-297", "9.1.1", "12.2.2",
     ("Certificate does not match the host name", "الشهادة لا تطابق اسم المضيف"),
     ("Include the host in the certificate's SAN.", "أضف اسم المضيف إلى حقل SAN في الشهادة."))
_tls("WEB701", "high", "", "certain", "CWE-295", "9.1.1", "12.2.2",
     ("Certificate not publicly trusted (self-signed or private CA)", "شهادة غير موثوقة عامة"),
     ("Use a certificate from a publicly trusted CA.", "استخدم شهادة من جهة إصدار موثوقة عامة."),
     confs="certain tentative")
_tls("WEB702", "medium", "", "firm", "CWE-295", "9.1.1", "12.2.2",
     ("Incomplete certificate chain", "سلسلة الشهادات ناقصة"),
     ("Serve the full chain (leaf + intermediates).", "قدّم السلسلة كاملة (الشهادة + الشهادات الوسيطة)."),
     confs="firm tentative")
_tls("WEB703", "info", "info low", "certain", "CWE-295", "—", "—",
     ("Chain sent in wrong order or with extra certificates", "سلسلة بترتيب خاطئ أو بشهادات زائدة"),
     ("Send leaf then intermediates in order, without the root.", "أرسل الشهادة ثم الوسيطة بالترتيب ومن دون شهادة الجذر."),
     confs="certain tentative")
_tls("WEB704", "critical", "critical high", "certain", "CWE-327", "9.1.3", "12.1.1",
     ("SSLv2 or SSLv3 accepted", "الخادم يقبل SSLv2 أو SSLv3"),  # nosec - protocol name
     ("Disable SSLv2/SSLv3 everywhere (also on other services sharing the key).",  # nosec - protocol name
      "عطّل SSLv2 وSSLv3 في كل مكان (وكذلك في الخدمات الأخرى التي تستخدم المفتاح نفسه)."),  # nosec - protocol name
     title=("Server accepts {versions}", "الخادم يقبل {versions}"))
_tls("WEB705", "high", "high low", "certain", "CWE-327", "9.1.3", "12.1.1",
     ("TLS 1.2 not supported / TLS 1.3 not supported", "لا دعم لـ TLS 1.2 أو 1.3"),
     ("Enable TLS 1.3 (and keep 1.2).", "فعّل TLS 1.3 (مع الإبقاء على 1.2)."),
     title=("{versions} not supported", "لا دعم لـ {versions}"))
_tls("WEB706", "high", "high medium low", "certain", "CWE-327", "9.1.2", "12.1.2",
     ("Weak cipher suites offered", "مجموعات تشفير ضعيفة مسموحة"),
     ("Offer only ECDHE + AEAD suites (Mozilla intermediate).", "اسمح فقط بمجموعات ECDHE مع AEAD (إعداد Mozilla المتوسط)."))
_tls("WEB707", "critical", "critical high info", "certain", "CWE-326", "9.1.2", "12.1.2",
     ("Weak certificate key", "مفتاح الشهادة ضعيف"),
     ("Reissue with RSA ≥ 2048 or ECDSA P-256, generated by a fixed library.",
      "أعد الإصدار بمفتاح RSA بطول 2048 أو أكثر أو ECDSA P-256، مولَّد بمكتبة سليمة."))
_tls("WEB708", "high", "high medium", "certain", "CWE-327", "9.1.2", "12.1.2",
     ("Weak certificate signature", "توقيع الشهادة ضعيف"),
     ("Reissue with SHA-256 or better.", "أعد الإصدار بتوقيع SHA-256 أو أقوى."))
_tls("WEB709", "low", "", "certain", "CWE-295", "—", "12.2.2",
     ("Certificate lifetime beyond CA/Browser Forum limits", "مدة صلاحية الشهادة تتجاوز الحد"),
     ("Use short-lived, automatically renewed certificates.", "استخدم شهادات قصيرة العمر تُجدَّد آليًا."))
_tls("WEB710", "high", "high medium", "certain", "CWE-326", "9.1.2", "12.1.2",
     ("Weak Diffie-Hellman parameters", "معاملات Diffie-Hellman ضعيفة"),
     ("Disable DHE or use ffdhe2048+ groups (RFC 7919).", "عطّل DHE أو استخدم مجموعات ffdhe2048 أو أقوى (RFC 7919)."))
_tls("WEB711", "high", "", "certain", "CWE-200", "9.1.2", "12.1.2",
     ("TLS compression enabled (CRIME)", "ضغط TLS مفعّل (CRIME)"),
     ("Disable TLS-level compression.", "عطّل الضغط على مستوى TLS."))
_tls("WEB712", "low", "", "certain", "CWE-757", "9.1.2", "12.1.2",
     ("Secure renegotiation not supported", "لا دعم لإعادة التفاوض الآمنة"),
     ("Update the TLS library.", "حدّث مكتبة TLS."))
_tls("WEB713", "medium", "medium low", "firm", "CWE-295", "—", "12.2.2",
     ("Certificate Transparency requirements not met", "متطلبات شفافية الشهادات غير مستوفاة"),
     ("Use a CA that embeds SCTs from distinct operators.", "استخدم جهة إصدار تضمّن SCTs من مشغّلين مختلفين."),
     confs="firm tentative")
_tls("WEB714", "high", "high medium info", "certain", "CWE-299", "—", "12.1.4",
     ("OCSP stapling problem", "مشكلة في تدبيس OCSP"),
     ("Enable stapling, or reissue without must-staple.", "فعّل تدبيس OCSP أو أعد إصدار الشهادة بلا must-staple."))
_tls("WEB715", "low", "", "certain", "CWE-1188", "—", "12.1.1",
     ("TLS configuration differs between servers", "إعداد TLS مختلف بين الخوادم"),
     ("Apply one TLS configuration to every node.", "طبّق إعداد TLS نفسه على جميع الخوادم."))
_tls("WEB716", "low", "", "certain", "CWE-757", "—", "—",
     ("Server negotiates a higher version than offered", "الخادم يفاوض إصدارًا أعلى مما طُلب"),
     ("Update the TLS stack.", "حدّث حزمة TLS."))
_tls("WEB717", "info", "", "certain", "CWE-297", "—", "—",
     ("Certificate names problem", "مشكلة في أسماء الشهادة"),
     ("List exact host names in SAN.", "اذكر أسماء المضيفين بدقة في SAN."))
_tls("WEB718", "info", "", "certain", "CWE-327", "9.1.2", "12.1.2",
     ("Not conformant with Mozilla TLS guidelines 6.0", "غير مطابق لإرشادات Mozilla لـ TLS"),
     ("Generate your config from the Mozilla SSL Configuration Generator (intermediate).",
      "ولّد الإعداد من مولّد إعدادات Mozilla (المستوى المتوسط)."))
_tls("WEB719", "info", "", "certain", "CWE-327", "—", "—",
     ("No post-quantum key exchange", "لا تبادل مفاتيح مقاوم للحوسبة الكمية"),
     ("Enable X25519MLKEM768 (OpenSSL ≥ 3.5).", "فعّل X25519MLKEM768 (يتطلب OpenSSL 3.5 أو أحدث)."),
     paranoid=True)
_tls("WEB720", "high", "", "certain", "CWE-298", "9.1.1", "12.2.2",
     ("Certificate not yet valid", "الشهادة لم تصبح صالحة بعد"),
     ("Check the server clock and the certificate dates.", "تحقّق من ساعة الخادم ومن تواريخ الشهادة."))

# =============================================================================================== §2.9 Family I
_r("WEB054", "I", "libs", "high", "certain", "CWE-1395", "WSTG-INFO-08", "14.2.1", "15.2.1", "S-LIBS",
   ("Vulnerable JavaScript library", "مكتبة JavaScript بها ثغرات معروفة"),
   ("Upgrade {library} to {fixed} or later.", "حدّث {library} إلى الإصدار {fixed} أو أحدث."),
   sevs="critical high medium low", confs="certain firm",
   title=("Vulnerable JavaScript library: {library} {version}", "مكتبة JavaScript بها ثغرات معروفة: {library} {version}"),
   existing=True, title_1_0="Outdated {library} {version} (known vulnerabilities)")
_r("WEB080", "I", "tech", "info", "firm", "CWE-1395", "WSTG-INFO-08 WSTG-INFO-09", "—", "—", "S-LIBS",
   ("Detected platform", "منصّة مكتشفة"),
   ("Keep {platform} and its plugins/themes on the latest patched release.",
    "تأكد أن {platform} وإضافاتها وقوالبها محدّثة لآخر إصدار مُصحَّح."),
   confs="certain firm tentative", title=("Detected platform: {platform}", "منصّة مكتشفة: {platform}"), existing=True)
_r("WEB081", "I", "tech", "medium", "firm", "CWE-1104", "WSTG-INFO-08", "14.2.1", "15.2.1", "S-LIBS",
   ("Outdated platform version", "إصدار المنصّة قديم"),
   ("Upgrade {platform} to a supported release ({branch} reached end of life on {date}).",
    "حدّث {platform} إلى إصدار مدعوم (انتهى دعم الفرع {branch} في {date})."),
   sevs="medium low", confs="firm tentative",
   title=("Outdated platform version: {platform} {version}", "إصدار المنصّة قديم: {platform} {version}"), existing=True,
   title_1_0="Outdated {platform} ({version})",
   variants={"patch": {
       "advice_en": "Upgrade {platform} to the latest patch release of its branch ({latest}).",
       "advice_ar": "حدّث {platform} إلى آخر إصدار تصحيحي في فرعه ({latest})."}})
_r("WEB800", "I", "tech", "high", "firm", "CWE-1395", "WSTG-INFO-02", "14.2.1", "15.2.1", "S-BANNER",
   ("Server software version with known vulnerabilities", "إصدار برمجية خادم به ثغرات معروفة"),
   ("Upgrade {product} to {fixed} (or confirm your distribution backported the fixes).",
    "حدّث {product} إلى {fixed} (أو تأكد أن التوزيعة نقلت التصحيحات إليه)."),
   sevs="critical high medium low", confs="firm tentative",
   title=("Server software version with known vulnerabilities: {product} {version}",
          "إصدار برمجية خادم به ثغرات معروفة: {product} {version}"),
   variants={"tentative": {
       "title_en": "Server software version may be affected by known vulnerabilities: {product} {version}",
       "title_ar": "إصدار برمجية الخادم قد يكون متأثرًا بثغرات معروفة: {product} {version}"}})
_r("WEB801", "I", "tech", "medium", "firm", "CWE-1104", "WSTG-INFO-02", "14.2.1", "15.2.1", "S-BANNER",
   ("End-of-life server software or runtime", "برمجية خادم أو بيئة تشغيل انتهى دعمها"),
   ("Move to a supported release.", "انتقل إلى إصدار ما زال مدعومًا."),
   title=("End-of-life server software or runtime: {product} {version}",
          "برمجية خادم أو بيئة تشغيل انتهى دعمها: {product} {version}"))
_r("WEB802", "I", "tech", "low", "certain", "CWE-1104", "—", "1.14.6", "3.7.1", "S-HTML",
   ("Obsolete client-side technology (Flash, Silverlight, Java applets)", "تقنية عميل متقادمة"),
   ("Remove plugin content; no current browser runs it.", "احذف محتوى الإضافات؛ لا يشغّله أي متصفح حالي."))
_r("WEB803", "I", "libs", "low", "firm", "CWE-1104", "WSTG-INFO-08", "14.2.1", "3.7.1", "S-LIBS",
   ("End-of-life front-end framework", "إطار واجهة أمامية انتهى دعمه"),
   ("Plan a migration to a supported major version.", "خطّط للانتقال إلى إصدار رئيسي مدعوم."),
   title=("End-of-life front-end framework: {library} {version}", "إطار واجهة أمامية انتهى دعمه: {library} {version}"))

# =============================================================================================== §2.10 Family J
_r("WEB060", "J", "exposure", "info", "certain", "CWE-1059", "WSTG-INFO-03", "—", "—", "S-SECTXT",
   ("No security.txt", "لا يوجد security.txt"),
   ("Publish /.well-known/security.txt with Contact and Expires (RFC 9116); its absence is not a vulnerability.",
    "انشر الملف /.well-known/security.txt مع الحقلين Contact وExpires (RFC 9116)؛ وغيابه ليس ثغرة."),
   existing=True)
_r("WEB900", "J", "exposure", "low", "certain", "CWE-1059", "WSTG-INFO-03", "—", "—", "S-SECTXT",
   ("security.txt invalid", "ملف security.txt غير صالح"),
   ("Fix the listed RFC 9116 problems (Contact and a future Expires are required).",
    "صحّح مشكلات RFC 9116 المذكورة (الحقل Contact وتاريخ Expires مستقبلي إلزاميان)."),
   sevs="low info")
_r("WEB061", "J", "exposure", "info", "firm", "CWE-200", "WSTG-INFO-03", "—", "—", "S-DOTFILES",
   ("robots.txt reveals sensitive paths", "robots.txt يكشف مسارات حساسة"),
   ("robots.txt is public; protect sensitive paths with authentication instead of hiding them.",
    "ملف robots.txt عام؛ احمِ المسارات الحساسة بالمصادقة بدل إخفائها فيه."),
   existing=True)
_r("WEB062", "J", "exposure", "high", "certain", "CWE-538", "WSTG-CONF-04", "12.5.1", "13.4.7 13.4.1 13.4.5",
   "S-DOTFILES",
   ("Exposed sensitive file", "ملف حساس مكشوف"),
   ("Remove the file from the web root or deny access to it, and revoke any secret it exposed.",
    "احذف الملف من جذر الموقع أو امنع الوصول إليه، وأبطل أي سرّ كشفه."),
   sevs="critical high medium low info", title=("Exposed sensitive file: {path}", "ملف حساس مكشوف: {path}"),
   cwe_variants="CWE-527 CWE-530 CWE-532 CWE-200 CWE-489", existing=True)
_r("WEB082", "J", "exposure", "high", "certain", "CWE-538", "WSTG-CONF-04", "12.5.1", "13.4.7", "S-DOTFILES",
   ("Platform sensitive file exposed", "ملف حساس للمنصّة مكشوف"),
   ("Block access to this file at the web server and remove it from the web root; rotate any secret it contained.",
    "امنع الوصول إلى هذا الملف من خادم الويب واحذفه من جذر الموقع، وغيّر أي سرّ كان فيه."),
   title=("{platform} sensitive file exposed: {path}", "ملف حساس لـ {platform} مكشوف: {path}"), existing=True,
   title_1_0="{platform}: sensitive file exposed {path}")
_r("WEB083", "J", "exposure", "info", "firm", "CWE-284", "WSTG-CONF-05", "—", "—", "S-ADMIN",
   ("Admin or login page reachable", "صفحة إدارة أو دخول متاحة"),
   ("Restrict the admin or login page (internal network, VPN, or strong authentication with rate limiting and MFA).",
    "قيّد الوصول إلى صفحة الإدارة أو الدخول (شبكة داخلية أو VPN أو مصادقة قوية مع تحديد عدد المحاولات والتحقق متعدد العوامل)."),
   title=("{platform} admin or login page reachable: {path}", "صفحة إدارة أو دخول لـ {platform} متاحة: {path}"),
   existing=True, title_1_0="{platform}: admin/login page reachable {path}")
_r("WEB901", "J", "exposure", "high", "firm", "CWE-284", "WSTG-CONF-10", "10.3.3", "—", "S-TAKEOVER",
   ("Possible subdomain takeover", "احتمال الاستيلاء على النطاق الفرعي"),
   ("Remove the dangling DNS record or reclaim the resource at the provider immediately.",
    "احذف سجل DNS المعلّق أو استعد المورد لدى المزوّد فورًا."))
_r("WEB903", "J", "exposure", "medium", "certain", "CWE-942", "WSTG-CLNT-07", "14.5.3", "3.4.2", "S-CORS",
   ("Permissive Flash/Silverlight cross-domain policy", "سياسة نطاقات Flash/Silverlight متساهلة"),
   ("Delete the policy file (no current browser needs it) or restrict it to your own domains.",
    "احذف ملف السياسة (لا يحتاجه أي متصفح حالي) أو قيّده بنطاقاتك فقط."),
   sevs="medium low")

# =============================================================================================== §2.11 Family K
_r("WEB990", "K", "engine", "info", "certain", "", "", "", "", "",
   ("Scan partly inconclusive (WAF, challenge or rate limit)", "الفحص غير حاسم جزئيًا (جدار حماية أو تحدٍّ أو تقييد معدل)"),
   ("The listed checks could not run because a WAF challenge or a rate limit answered instead of the site; as the site's "
    "owner, allow the scanner's requests (or scan from an allowed network) and run the scan again.",
    "تعذّر إجراء الفحوص المذكورة لأن جدار حماية أو تقييد معدل أجاب بدل الموقع؛ بصفتك مالك الموقع اسمح بطلبات الفاحص (أو افحص من شبكة مسموح بها) ثم أعد الفحص."))
_r("WEB991", "K", "engine", "info", "certain", "", "", "", "", "",
   ("Some checks could not be performed", "تعذّر إجراء بعض الفحوص"),
   ("These checks were not performed and are not counted as passed; review them manually or re-run the scan where they "
    "can run.",
    "لم تُجرَ هذه الفحوص ولا تُحسب ناجحة؛ راجعها يدويًا أو أعد الفحص في بيئة تسمح بإجرائها."))


# ----------------------------------------------------------------------------------------------- public API

RULE_IDS: tuple[str, ...] = tuple(_ORDER)
RULES: dict[str, RuleMeta] = {rid: _BUILT[rid] for rid in RULE_IDS}
META_RULES = frozenset(r for r in RULE_IDS if RULES[r].family == "K")


def rule(rule_id: str) -> RuleMeta:
    return RULES[rule_id]


def checks_for_module(module: str) -> tuple[str, ...]:
    """The coverage check ids a module owns (``CheckModule.CHECKS``)."""
    return tuple(dict.fromkeys(RULES[r].check_id for r in RULE_IDS if RULES[r].module == module))


def rules_for_family(family: str) -> tuple[str, ...]:
    return tuple(r for r in RULE_IDS if RULES[r].family == family)


def all_check_ids() -> tuple[str, ...]:
    return tuple(dict.fromkeys(RULES[r].check_id for r in RULE_IDS))


def validate_issue(issue) -> list[str]:
    """Problems with an ``Issue`` against the registry (empty list = valid). Used by the engine and module tests."""
    meta = RULES.get(issue.rule)
    if meta is None:
        return [f"unknown rule {issue.rule!r}"]
    errs = []
    if issue.severity is not None and issue.severity not in meta.allowed_severities:
        errs.append(f"{issue.rule}: severity {issue.severity!r} not in {meta.allowed_severities}")
    if issue.confidence not in meta.allowed_confidences:
        errs.append(f"{issue.rule}: confidence {issue.confidence!r} not in {meta.allowed_confidences}")
    variant = (issue.params or {}).get("variant")
    if variant and variant not in meta.variants:
        errs.append(f"{issue.rule}: unknown variant {variant!r}")
    needed = set(_PLACEHOLDER.findall(meta.title_en))
    var = meta.variants.get(variant or "", {})
    needed |= set(_PLACEHOLDER.findall(var.get("title_en", "")))
    missing = sorted(n for n in needed if (issue.params or {}).get(n) in (None, ""))
    if missing:
        errs.append(f"{issue.rule}: missing title parameters {missing}")
    return errs


def _template_regex(template: str) -> str | None:
    """A regular expression for an Arabic template with ``{name}`` groups (None when it has no placeholder)."""
    if not _PLACEHOLDER.search(template):
        return None
    out, pos = [], 0
    for m in _PLACEHOLDER.finditer(template):
        out.append(re.escape(template[pos:m.start()]))
        out.append(f"(?P<{m.group(1)}>.+?)")
        pos = m.end()
    out.append(re.escape(template[pos:]))
    return "".join(out)


def _en_replacement(template: str) -> str:
    return _PLACEHOLDER.sub(lambda m: f"\\g<{m.group(1)}>", template)


def _plural_patterns(ar: str, en: str) -> list[tuple[str, str]]:
    """Five patterns (one per Arabic plural form) for a template whose placeholders include one count parameter."""
    names = _PLACEHOLDER.findall(ar)
    counts = [n for n in names if n in PLURAL_PARAMS]
    if not counts:
        rx = _template_regex(ar)
        return [(rx, _en_replacement(en))] if rx else []
    count = counts[0]
    en_one, en_many, ar_forms = PLURAL_PARAMS[count]
    out = []
    for form, fixed in zip(ar_forms, (1, 2, None, None, None)):
        ar_t = ar.replace("{" + count + "}", form.replace("{n}", "{" + count + "}"))
        if fixed is None:
            en_t = en.replace("{" + count + "}", en_many.replace("{n}", "{" + count + "}"))
        else:
            ar_t = ar_t.replace("{" + count + "}", str(fixed))   # forms one/two carry no digits; keep the template
            en_t = en.replace("{" + count + "}", (en_one if fixed == 1 else en_many).replace("{n}", str(fixed)))
        rx = _template_regex(ar_t)
        if rx is None:
            out.append((re.escape(ar_t), en_t))
        else:
            out.append((rx, _en_replacement(en_t)))
    return out


def template_patterns(ar: str, en: str) -> list[tuple[str, str]]:
    """i18n PATTERNS entries for one Arabic/English template pair (``{name}`` groups; one count parameter of
    :data:`PLURAL_PARAMS` expands to its five Arabic forms). Empty when the template has no placeholder."""
    return _plural_patterns(ar, en)


def i18n_catalog() -> tuple[dict[str, str], list[tuple[str, str]]]:
    """``(CATALOG, PATTERNS)`` for ``vulnscan/i18n/cat_web2.py``: Arabic → English for every name, title and advice of
    the registry (variants included). Templates with parameters become regular expressions (see i18n/__init__)."""
    catalog: dict[str, str] = {}
    patterns: list[tuple[str, str]] = []
    seen_rx: set[str] = set()
    for rid in RULE_IDS:
        m = RULES[rid]
        pairs = [(m.name_ar, m.name_en), (m.title_ar, m.title_en), (m.advice_ar, m.advice_en)]
        for v in m.variants.values():
            if v.get("title_ar"):
                pairs.append((v["title_ar"], v["title_en"]))
            if v.get("advice_ar"):
                pairs.append((v["advice_ar"], v["advice_en"]))
        for ar, en in pairs:
            if _PLACEHOLDER.search(ar):
                for rx, repl in _plural_patterns(ar, en):
                    if rx not in seen_rx:
                        seen_rx.add(rx)
                        patterns.append((rx, repl))
            else:
                catalog.setdefault(ar, en)
    for code, (en, ar) in FAMILIES.items():
        catalog.setdefault(ar, en)
    for _key, (en, ar, _w) in GRADE_FAMILIES.items():
        catalog.setdefault(ar, en)
    return catalog, patterns


__all__ = ["RuleMeta", "RULES", "RULE_IDS", "META_RULES", "FAMILIES", "GRADE_FAMILIES", "MODULES", "FIX_IDS", "CONTROLS",
           "PLURAL_PARAMS", "rule", "checks_for_module", "rules_for_family", "all_check_ids", "validate_issue",
           "template_patterns", "i18n_catalog"]
