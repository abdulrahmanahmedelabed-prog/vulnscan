"""Texts of the web scanner (1.1.0 UX round): the shared bidi helper (vulnscan/i18n/bidi.py), Arabic count phrases
(vulnscan/i18n/plural.py), and the wording of the rule registry (webscan/rules.py) and the remediation library
(webscan/remediation.py): advice that matches the evidence, Arabic agreement and terminology, title parity.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess

import pytest

from vulnscan.i18n import bidi, plural
from vulnscan.webscan import remediation as REM
from vulnscan.webscan import rules as R

ARABIC = re.compile(r"[؀-ۿ]")

# ----------------------------------------------------------------------------------------------- 1. bidi

ONE_RUN = ["SameSite=Lax", "max-age=0", "Let's Encrypt", "__Host-", "default-src 'self'; object-src 'none'",
           "camera=()", "/.well-known/security.txt", "2026-11-12", 'method="post"',
           "Strict-Transport-Security: max-age=63072000; includeSubDomains"]
CONTEXTS = ["اضبط {} الآن.", "اضبط {}.", "استخدم {}", "{} أولًا", "القيمة ({}) صحيحة", "«{}»، ثم", "القيمة: {}؛ ثم",
            "{}"]


@pytest.mark.parametrize("run", ONE_RUN)
@pytest.mark.parametrize("context", CONTEXTS)
def test_each_code_fragment_is_exactly_one_ltr_run(run, context):
    text = context.format(run)
    assert [text[a:b] for a, b in bidi.ltr_runs(text)] == [run]


@pytest.mark.parametrize("text, runs", [
    ("اضبط SameSite=Lax (أو Strict) صراحةً.", ["SameSite=Lax", "Strict"]),
    ("استخدم frame-ancestors 'none' (أو 'self').", ["frame-ancestors 'none'", "'self'"]),
    ('مثل استدعاء exit بعد header("Location") في PHP).', ["exit", 'header("Location")', "PHP"]),
    ("أعد تسميتها إلى __Host-<الاسم> مع Secure وPath=/ وبلا Domain.", ["__Host-", "Secure", "Path=/", "Domain"]),
    ("انتهى دعم الفرع 5.9 في 2024-01-01 على 10.0.0.1:8443 بعد 128 يومًا", ["5.9", "2024-01-01", "10.0.0.1:8443"]),
    ("لا دعم لـ TLS 1.2 ولا TLS 1.3", ["TLS 1.2", "TLS 1.3"]),
    ("كاشِف F* · Observatory 0 (F)", ["F*", "Observatory 0 (F)"]),
    ("/admin → HTTP 200 صفحة", ["/admin → HTTP 200"]),
    ("الملف /admin → في الخادم", ["/admin"]),
    ("اضبط FileETag في Apache (في httpd.conf أو .htaccess) الآن", ["FileETag", "Apache", "httpd.conf", ".htaccess"]),
    ("- بند و* نجمة", []),
    ("نص عربي فقط، بلا أي كود.", []),
])
def test_ltr_runs_in_real_sentences(text, runs):
    assert [text[a:b] for a, b in bidi.ltr_runs(text)] == runs


def test_iso_isolate_and_html():
    assert bidi.iso("A+") == "\u2066A+\u2069"
    assert bidi.iso("") == ""
    assert bidi.isolate("اضبط SameSite=Lax الآن.") == "اضبط \u2066SameSite=Lax\u2069 الآن."
    assert bidi.isolate("plain English: SameSite=Lax") == "plain English: SameSite=Lax"     # no Arabic: unchanged
    assert bidi.html_runs('استخدم method="post".') == 'استخدم <bdi dir="ltr">method=&quot;post&quot;</bdi>.'
    assert bidi.html_runs("<b>x</b>") == "&lt;b&gt;x&lt;/b&gt;"


def test_pattern_source_is_ascii_without_bidi_controls():
    """The shared pattern is pasted into JavaScript and must not carry invisible directional characters."""
    assert bidi.LTR_RUN_PATTERN.isascii()
    src = open(bidi.__file__, encoding="utf-8").read()
    assert not re.search("[\u200e\u200f\u202a-\u202e\u2066-\u2069]", src)


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_javascript_twin_finds_the_same_runs():
    samples = [c.format(r) for r in ONE_RUN for c in CONTEXTS] + [
        "اضبط SameSite=Lax (أو Strict) صراحةً.", "كاشِف F* · Observatory 0 (F)", "انتهى في 2024-01-01 على 10.0.0.1:8443",
        "\u200f(HSTS) و(JSONP أو AngularJS)", "/admin → HTTP 200 صفحة", "- بند و* نجمة"]
    samples += [R.RULES[r].advice_ar for r in R.RULE_IDS] + [R.RULES[r].title_ar for r in R.RULE_IDS]
    script = bidi.JS_BIDI + "\nconst S = JSON.parse(require('fs').readFileSync(0, 'utf8'));\n" \
                            "process.stdout.write(JSON.stringify(S.map(ltrRuns)));\n"
    out = subprocess.run(["node", "-e", script], input=json.dumps(samples), capture_output=True, text=True,
                         encoding="utf-8", timeout=60, check=True).stdout
    js = json.loads(out)
    py = [[list(r) for r in bidi.ltr_runs(s)] for s in samples]
    diff = [(s, a, b) for s, a, b in zip(samples, py, js) if a != b]
    assert not diff, diff[:5]


def test_every_arabic_registry_text_keeps_brackets_and_quotes_balanced_in_its_runs():
    """No run may take the closing bracket of an Arabic parenthesis or leave one of its own outside."""
    bad = []
    for rid in R.RULE_IDS:
        m = R.RULES[rid]
        for t in (m.name_ar, m.title_ar, m.advice_ar, *(v.get(k, "") for v in m.variants.values()
                                                        for k in ("title_ar", "advice_ar"))):
            for a, b in bidi.ltr_runs(t):
                run = t[a:b]
                if run.count("(") != run.count(")") or ARABIC.search(run):
                    bad.append((rid, run))
    assert not bad, bad[:10]


# ----------------------------------------------------------------------------------------------- 2. plural

@pytest.mark.parametrize("n, pages, seconds, requests", [
    (1, "صفحة واحدة مفحوصة", "ثانية واحدة", "طلب واحد"),
    (2, "صفحتان مفحوصتان", "ثانيتين", "طلبان"),
    (3, "3 صفحات مفحوصة", "3 ثوانٍ", "3 طلبات"),
    (11, "11 صفحةً مفحوصة", "11 ثانيةً", "11 طلبًا"),
    (100, "100 صفحة مفحوصة", "100 ثانية", "100 طلب"),
    (0, "0 صفحة مفحوصة", "0 ثانية", "0 طلب"),
    (103, "103 صفحات مفحوصة", "103 ثوانٍ", "103 طلبات"),
])
def test_new_count_phrases(n, pages, seconds, requests):
    assert plural.ar_count(n, plural.PAGES_SCANNED) == pages
    assert plural.ar_count(n, plural.SECONDS) == seconds
    assert plural.ar_count(n, plural.REQUESTS) == requests


def test_fractional_and_string_counts():
    assert plural.ar_count(0.5, plural.SECONDS) == "0.5 ثانية"
    assert plural.ar_count(1.5, plural.SECONDS) == "1.5 ثانية"
    assert plural.ar_count(2.0, plural.SECONDS) == "ثانيتين"
    assert plural.ar_count("3", plural.SECONDS) == "3 ثوانٍ"
    assert plural.ar_category("abc") == "other"


def test_seconds_and_delay_render_through_ar_count():
    for name in ("seconds", "delay"):
        assert R.PLURAL_PARAMS[name][2] == plural.SECONDS
        assert R._render(name, 1, "ar") == "ثانية واحدة"
        assert R._render(name, 2, "ar") == "ثانيتين"
        assert R._render(name, 5, "ar") == "5 ثوانٍ"
        assert R._render(name, 1, "en") == "1 second"
        assert R._render(name, 1.5, "en") == "1.5 seconds"
        assert R._render(name, "n/a", "ar") == "n/a"


def test_count_templates_keep_a_plain_number_pattern():
    """A module that prints "Retry-After: {seconds}" (the header's bare number) still translates."""
    pats = R.template_patterns("انتظر (Retry-After: {seconds}) ثم أعاد", "waited (Retry-After: {seconds}) then retried")
    hits = [re.sub(rx, en, "انتظر (Retry-After: 5) ثم أعاد") for rx, en in pats if re.fullmatch(rx, "انتظر (Retry-After: 5) ثم أعاد")]
    assert hits and hits[0] == "waited (Retry-After: 5) then retried"
    hits = [re.sub(rx, en, "انتظر (Retry-After: 5 ثوانٍ) ثم أعاد") for rx, en in pats
            if re.fullmatch(rx, "انتظر (Retry-After: 5 ثوانٍ) ثم أعاد")]
    assert hits[0] == "waited (Retry-After: 5 seconds) then retried"


# ----------------------------------------------------------------------------------------------- 3-10. registry texts

def _texts(rid, lang="ar"):
    m = R.RULES[rid]
    key = "ar" if lang == "ar" else "en"
    out = [getattr(m, f"name_{key}"), getattr(m, f"title_{key}"), getattr(m, f"advice_{key}")]
    out += [v.get(f"{w}_{key}", "") for v in m.variants.values() for w in ("title", "advice")]
    return [t for t in out if t]


def test_hsts_advice_adds_include_subdomains_only_after_checking():
    for rid in ("WEB-strict-transport-security", "WEB112"):
        m = R.RULES[rid]
        assert "max-age=63072000" in m.advice_en and "only after confirming that every subdomain serves HTTPS" in m.advice_en
        assert "max-age=63072000" in m.advice_ar and "إلا بعد التأكد من أن كل النطاقات الفرعية تعمل عبر HTTPS" in m.advice_ar
    m = R.RULES["WEB115"]
    assert m.name_en == m.title_en == "HSTS preload requested but requirements not met"
    assert m.name_ar == "طلب الإدراج المسبق لـ HSTS غير مستوفٍ للشروط"
    assert "remove" in m.advice_en.lower() and "every subdomain of the registrable domain" in m.advice_en
    assert "removal takes months" in m.advice_en and "يستغرق أشهرًا" in m.advice_ar


CORS = ("WEB320", "WEB321", "WEB322", "WEB323", "WEB324", "WEB325", "WEB326", "WEB327")


def test_cors_advice_per_rule():
    base = R.RULES["WEB320"].advice_en
    assert "exact match against an allowlist" in base and "never reflect arbitrary origins" in base
    assert '"null"' in base and "Vary: Origin" in base
    assert "Access-Control-Allow-Credentials" in R.RULES["WEB323"].advice_en
    assert "allowlisted origin" in R.RULES["WEB323"].advice_en
    assert R.RULES["WEB324"].advice_en.startswith("Add Vary: Origin")
    assert "exactly one" in R.RULES["WEB325"].advice_en and "*, null or one origin" in R.RULES["WEB325"].advice_en
    assert "Access-Control-Allow-Origin: *" in R.RULES["WEB327"].advice_en
    assert len({R.RULES[r].advice_en for r in ("WEB320", "WEB323", "WEB324", "WEB325", "WEB327")}) == 5
    assert len({R.RULES[r].advice_ar for r in ("WEB320", "WEB323", "WEB324", "WEB325", "WEB327")}) == 5


def test_cors_glossary_credentials_are_not_dependencies():
    """«الاعتماديات» means software dependencies; CORS credentials are «بيانات الاعتماد»."""
    for rid in CORS:
        for t in _texts(rid):
            assert "اعتماديات" not in t, (rid, t)
    assert "بيانات الاعتماد" in R.RULES["WEB321"].name_ar
    assert "بيانات الاعتماد" in R.RULES["WEB323"].name_ar
    assert R.RULES["WEB320"].name_ar.endswith("(إعادة Origin مع السماح ببيانات الاعتماد)")


def test_tls_and_server_variants():
    m = R.RULES["WEB714"]
    assert set(m.variants) >= {"revoked", "expired", "must_staple", "no_staple"}
    assert m.advice("en", variant="revoked").startswith("The certificate is revoked: install a new certificate now")
    assert "OCSP" in m.advice("en", variant="expired") and "restart" in m.advice("en", variant="expired")
    assert m.advice("en", variant="must_staple") == m.advice("en") == "Enable stapling, or reissue without must-staple."
    m = R.RULES["WEB705"]
    assert m.advice("en", variant="no12no13") == "Enable TLS 1.2 and TLS 1.3 (see S-TLS)."
    assert m.title("ar", variant="no12no13") == "لا دعم لـ TLS 1.2 ولا TLS 1.3"
    assert m.title("ar", versions=["TLS 1.2", "TLS 1.3"]) == "لا دعم لـ TLS 1.2 ولا TLS 1.3"
    assert m.title("ar", versions="TLS 1.2, TLS 1.3") == "لا دعم لـ TLS 1.2 ولا TLS 1.3"
    assert m.title("en", versions=["TLS 1.2", "TLS 1.3"]) == "TLS 1.2 and TLS 1.3 not supported"
    assert m.title("ar", versions="TLS 1.3") == "لا دعم لـ TLS 1.3"
    assert R.RULES["WEB030"].title("ar", versions=["TLS 1.0", "TLS 1.1"]) == "الخادم يقبل TLS 1.0 وTLS 1.1"
    m = R.RULES["WEB800"]
    p = {"product": "PHP", "version": "8.1.2", "fixed": "8.1.31", "supported": "8.3", "variant": "eol"}
    assert m.advice("en", **p) == ("Upgrade PHP to a supported release (≥ 8.3); 8.1.31 only closes these CVEs and is "
                                   "itself unsupported.")
    assert m.advice("ar", **p) == "حدّث PHP إلى إصدار مدعوم (8.3 أو أحدث)؛ فالإصدار 8.1.31 يسدّ هذه الثغرات فقط، وهو نفسه غير مدعوم."
    assert m.title("en", **p) == "Server software version with known vulnerabilities: PHP 8.1.2"
    issue_ok = R.validate_issue(type("I", (), {"rule": "WEB800", "severity": "high", "confidence": "firm",
                                               "params": p})())
    assert issue_ok == []


def test_incident_and_disclosure_advice():
    en, ar = R.RULES["WEB507"].advice_en, R.RULES["WEB507"].advice_ar
    order = ["preserve a copy of the evidence", "find and close the entry point", "remove the injected code",
             "known-clean copy", "rotate credentials"]
    assert [en.index(x) for x in order] == sorted(en.index(x) for x in order)
    assert ar.index("احتفظ بنسخة من الأدلة") < ar.index("نقطة الاختراق وأغلقها") < ar.index("أزل الكود المحقون")
    inc = REM.SNIPPETS["S-INCIDENT"].summary_en
    assert inc.index("evidence") < inc.index("entry point") < inc.index("injected code")
    assert "CVE-2014-0160" in R.RULES["WEB615"].advice_en and "revoke the old certificate" in R.RULES["WEB615"].advice_en
    assert "CVE-2014-0160" in R.RULES["WEB615"].advice_ar and "أبطل الشهادة القديمة" in R.RULES["WEB615"].advice_ar
    for t in (R.RULES["WEB604"].advice_en, R.RULES["WEB604"].advice_ar):
        assert "FileETag" in t and "Apache" in t and "httpd.conf" in t and ".htaccess" in t


def test_cookie_texts():
    m = R.RULES["WEB410"]
    assert m.name_en == "Secure cookie set over HTTP (the browser drops it)"
    assert m.name_ar == "كوكي بسمة Secure تُضبط عبر HTTP (يرفضها المتصفح)"
    m = R.RULES["WEB401"]
    for t in (m.advice_en, m.advice_ar):
        assert "__Secure-" in t and "__Host-" in t


def test_title_parity():
    for rid in R.RULE_IDS:
        assert "paranoid" not in R.RULES[rid].name_en.lower(), rid
    assert R.RULES["WEB403"].name_ar.endswith("(يرفضها المتصفح)")
    assert R.RULES["WEB209"].name_ar.endswith("(JSONP أو AngularJS)")
    assert 'e.g. in PHP, call exit after header("Location")' in R.RULES["WEB106"].advice_en
    # every English "(cookie rejected)" / "(ignored)" title has its Arabic counterpart
    for rid in R.RULE_IDS:
        m = R.RULES[rid]
        if re.search(r"\((cookie rejected|the browser drops it)\)", m.name_en):
            assert "(يرفضها المتصفح)" in m.name_ar, rid


def test_arabic_agreement_and_terminology():
    csp_rules = ["WEB040", "WEB041", "WEB042", "WEB043"] + [f"WEB{n}" for n in range(200, 220)]
    for rid in csp_rules:
        for t in _texts(rid):
            # CSP is «سياسة CSP» (feminine); a bare "CSP" + masculine verb is the old wording
            assert not re.search(r"(?<!سياسة )CSP (يسمح|لا يقيّد|يقيّد)", t), (rid, t)
            if re.search(r"\bCSP\b", t) and not re.search(r"Content-Security-Policy|ترويسة CSP|CSP3", t):
                assert "سياسة CSP" in t or "لسياسة CSP" in t or "بسياسة CSP" in t, (rid, t)
    assert R.RULES["WEB209"].name_ar.startswith("سياسة CSP تسمح بمضيف يمكن تجاوزها عبره")
    assert R.RULES["WEB110"].name_ar.startswith("HSTS معطَّلة")
    assert R.RULES["WEB411"].name_ar == "كوكي موازن الحمل تكشف عنوانًا داخليًا"
    for rid in ("WEB020", "WEB021", "WEB022"):
        for t in _texts(rid):
            assert "بدون" not in t, (rid, t)
        assert "بلا" in R.RULES[rid].name_ar
    assert "16 بايتًا عشوائيًا" in R.RULES["WEB213"].advice_ar
    assert "128 بتًا" in R.RULES["WEB212"].advice_ar
    assert "4096 بايتًا" in R.RULES["WEB408"].advice_ar
    for rid in R.RULE_IDS:
        for t in _texts(rid):
            assert "الشيفرة" not in t and "شيفرة" not in t, (rid, t)
    for en, ar in REM.texts():
        assert "شيفرة" not in ar, ar


def test_no_hidden_directional_marks_in_registry_texts():
    for rid in R.RULE_IDS:
        for t in _texts(rid) + _texts(rid, "en"):
            assert not re.search("[\u200e\u200f\u202a-\u202e\u2066-\u2069]", t), (rid, t)


# ----------------------------------------------------------------------------------------------- 11-14. remediation

def _block(sid, platform, n=0):
    return [b for b in REM.SNIPPETS[sid].blocks if b.platform == platform][n]


def test_s_tls_nginx_curves_and_config_test():
    b = _block("S-TLS", "nginx")
    lines = b.code.splitlines()
    assert "ssl_ecdh_curve X25519:prime256v1:secp384r1;" in lines
    assert "# ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1:secp384r1;" in lines
    assert not any(l.startswith("ssl_ecdh_curve X25519MLKEM768") for l in lines)
    assert "nginx -t" in b.note_en and "nginx -t" in b.note_ar
    md = REM.to_markdown("S-TLS", "ar")
    assert "ssl_ecdh_curve X25519:prime256v1:secp384r1;" in md and "nginx -t" in md


def test_s_hsts_iis_native_element_and_cloudflare():
    native = _block("S-HSTS", "iis", 0)
    assert ('<hsts enabled="true" max-age="63072000" includeSubDomains="true" redirectHttpToHttps="true" />'
            in native.code)
    custom = _block("S-HSTS", "iis", 1)
    assert "customHeaders" in custom.code and "HTTPS" in custom.note_en and "HTTPS" in custom.note_ar
    cf = _block("S-HSTS", "cloudflare")
    assert "Max Age 12 months" in cf.note_en and "12 months" in cf.note_ar and "or more" not in cf.note_en


def test_s_csp_cloudflare_is_a_complete_worker():
    code = _block("S-CSP", "cloudflare").code
    assert code.lstrip("/ ").splitlines()[1].startswith("export default {")
    assert "async fetch(req" in code and "const res = await fetch(req);" in code
    assert "crypto.getRandomValues(new Uint8Array(16))" in code and 'r.headers.set("Content-Security-Policy"' in code
    assert code.count("{") == code.count("}") and code.count("(") == code.count(")")
    assert "'strict-dynamic'" in code and "env.NONCE_MARK" in code
    if shutil.which("node"):
        subprocess.run(["node", "--check", "--input-type=module"], input=code, text=True, check=True, timeout=60,
                       capture_output=True)


def test_s_err_and_s_cookie_blocks():
    assert _block("S-ERR", "express").code == "NODE_ENV=production"
    assert '<httpErrors errorMode="DetailedLocalOnly" />' in _block("S-ERR", "iis").code
    ng = _block("S-COOKIE", "nginx")
    lines = [l.split("#")[0].strip() for l in ng.code.splitlines()]
    assert "proxy_cookie_flags ~ secure samesite=lax;" in lines
    session = [l for l in lines if "httponly" in l]
    assert session and all(not l.startswith("proxy_cookie_flags ~") for l in session)
    assert lines.index(session[0]) < lines.index("proxy_cookie_flags ~ secure samesite=lax;")   # first match applies
    assert "CSRF" in ng.note_en and "HttpOnly" in ng.note_en and "CSRF" in ng.note_ar


@pytest.mark.parametrize("lang", ["en", "ar"])
def test_no_snippet_shows_two_blocks_under_one_heading(lang):
    for sid in REM.SNIPPETS:
        d = REM.render(sid, lang)
        names = [b["name"] for b in d["detected"] + d["other"]]
        assert len(names) == len(set(names)), (sid, names)


def test_platform_labels_and_brand_spelling():
    assert REM.PLATFORMS["aspnet"] == ("ASP.NET (.NET Framework)", "ASP.NET (.NET Framework)")
    ar = [ar for _en, ar in REM.texts()]
    assert not any("كاشف" in t for t in ar)
    assert any("كاشِف" in t for t in ar)


# ----------------------------------------------------------------------------------------------- 15. 1.0.1 wording

@pytest.mark.parametrize("rid, what", [("WEB040", "title"), ("WEB-x-frame-options", "title"), ("WEB052", "title"),
                                        ("WEB052", "advice")])
def test_registry_english_matches_the_1_0_1_catalogue(rid, what):
    from vulnscan.i18n import to_en
    m = R.RULES[rid]
    assert to_en(getattr(m, what)("ar")) == getattr(m, what)("en")
