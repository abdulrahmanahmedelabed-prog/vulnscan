"""WP14: remediation snippet library (§2.13), the web English catalogue (cat_web2), docs/web-checks.md, site/scanner.html
and NOTICE.

The central acceptance test runs Kashif's own header, CSP, HSTS, cookie and CORS checks on every header a snippet
recommends (the snippet's header lines and every header the nginx / Apache / IIS / Caddy blocks set) and asserts that
no finding above ``info`` comes back: Kashif's advice must pass Kashif.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import pathlib
import re
import secrets
import subprocess
import sys
from datetime import datetime, timezone
from html.parser import HTMLParser

import pytest

from vulnscan.webscan import htmlparse, remediation as R
from vulnscan.webscan.rules import FIX_IDS, RULE_IDS, RULES
from vulnscan.webscan.types import UA_INFO_URL, HeaderList, Page, Response, ScanContext, ScanOptions

ROOT = pathlib.Path(__file__).resolve().parents[2]
NOW = datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc)
ARABIC = re.compile(r"[؀-ۿ]")
SPEC_PLATFORMS = ("nginx", "apache", "iis", "caddy", "express", "django", "spring", "aspnetcore", "cloudflare")


# ----------------------------------------------------------------------------------------------- library shape

def test_every_fix_id_used_by_rules_exists():
    used = {sid for rid in RULE_IDS for sid in RULES[rid].fix}
    assert used <= set(R.SNIPPETS), sorted(used - set(R.SNIPPETS))
    assert set(FIX_IDS) == set(R.SNIPPETS)          # no orphan snippet, no snippet the registry does not know
    assert set(FIX_IDS) == used                     # and every snippet is used by at least one rule


@pytest.mark.parametrize("sid", sorted(R.SNIPPETS))
def test_snippet_has_bilingual_one_line_texts(sid):
    sn = R.SNIPPETS[sid]
    for en, ar in ((sn.title_en, sn.title_ar), (sn.summary_en, sn.summary_ar), (sn.caveat_en, sn.caveat_ar)):
        assert en.strip() and ar.strip(), sid
        assert "\n" not in en and "\n" not in ar, sid          # one line each
        assert not ARABIC.search(en), (sid, en)
        assert ARABIC.search(ar), (sid, ar)
    assert sn.blocks, sid
    for b in sn.blocks:
        assert b.platform in R.PLATFORMS, (sid, b.platform)
        assert b.lang in R.SNIPPET_LANGS, (sid, b.lang)
        assert b.code or b.note_en, (sid, b.platform)
        assert bool(b.note_en) == bool(b.note_ar), (sid, b.platform)
        if b.note_en:
            assert not ARABIC.search(b.note_en) and ARABIC.search(b.note_ar), (sid, b.platform)
        assert not ARABIC.search(b.code), (sid, b.platform)


@pytest.mark.parametrize("sid", ["S-HSTS", "S-REDIR", "S-CSP", "S-FRAME", "S-XCTO", "S-REF", "S-PP"])
def test_core_snippets_cover_every_spec_platform(sid):
    missing = set(SPEC_PLATFORMS) - set(R.SNIPPETS[sid].platforms)
    assert not missing, (sid, sorted(missing))


def test_code_fences_and_placeholders_are_well_formed():
    for sid, sn in R.SNIPPETS.items():
        for b in sn.blocks:
            tokens = set(re.findall(r"\{(host|domain|domain_re|names|expires)\}", b.code))
            assert tokens <= set(R.TOKENS), sid
            assert "example.com" not in b.code or sid == "S-SRI", (sid, b.platform)   # use the {host}/{domain} tokens
            md = R.to_markdown(sid)
            assert md.count("```") % 2 == 0, sid


# ----------------------------------------------------------------------------------------------- self-check

def _nonce() -> str:
    return base64.b64encode(secrets.token_bytes(18)).decode()


def _concrete(value: str, nonce: str) -> str:
    """A recommended value as a server would send it: placeholders replaced by real values."""
    value = R.fill(value, R.placeholders("www.example.com", NOW))
    return value.replace("{RANDOM}", nonce).replace("<random>", secrets.token_urlsafe(24))


_SCOPES = {"document": ("any", "document"), "sensitive": ("any", "document", "sensitive"),
           "logout": ("any", "document", "sensitive", "logout"), "api": ("any", "api")}


def _recommended(where: str, nonce: str, *, skip: str = "") -> list[tuple[str, str]]:
    """Every recommended header line of every snippet for one kind of response (``sensitive`` and ``logout`` responses
    also carry the document headers). S-MIXED's extra policy is layered on in its own test."""
    out = []
    for sn in R.SNIPPETS.values():
        if sn.id in ("S-MIXED", skip):
            continue
        out += [(h.name, _concrete(h.value, nonce)) for h in sn.headers if h.where in _SCOPES[where]]
    return out


def _page(where: str, nonce: str) -> tuple[str, str, str]:
    """(url, body, content type) of a typical response of that kind."""
    head = f"<!doctype html><html lang=en><head><meta charset=utf-8><title>T</title>" \
           f"<script nonce=\"{nonce}\">window.app = 1;</script></head><body>"
    if where == "api":
        return "https://api.example.com/v1/me", '{"ok": true}', "application/json"
    if where == "sensitive":
        return ("https://www.example.com/login", head + "<form method=post action=/login><input name=user>"
                "<input type=password name=password><button>Sign in</button></form></body></html>",
                "text/html; charset=utf-8")
    if where == "logout":
        return "https://www.example.com/logout", head + "<p>Signed out.</p></body></html>", "text/html; charset=utf-8"
    return "https://www.example.com/", head + "<h1>Home</h1><p>Welcome.</p></body></html>", "text/html; charset=utf-8"


def _check_kind(where: str, headers: list[tuple[str, str]], nonce: str):
    url, body, ctype = _page(where, nonce)
    return _run_checks(headers, url=url, body=body, content_type=ctype, nonce=nonce)


def _run_checks(headers: list[tuple[str, str]], *, url: str = "https://www.example.com/", body: str | None = None,
                content_type: str = "text/html; charset=utf-8", nonce: str = "") -> list[tuple[str, str, str]]:
    from vulnscan.webscan import cookies, cors, csp, headers as hdr, transport
    if body is None:
        body = (f"<!doctype html><html lang=en><head><meta charset=utf-8><title>Home</title>"
                f"<script nonce=\"{nonce}\">window.app = 1;</script></head><body><h1>Home</h1>"
                "<p>Welcome.</p></body></html>")
    items = [("Content-Type", content_type)] + [h for h in headers if h[0].lower() != "content-type"]
    r = Response(url=url, status=200, headers=HeaderList.of(*items), body=body.encode("utf-8"),
                 kind="document" if content_type.startswith("text/html") else "api")
    pages = [Page(r, htmlparse.parse_response(r), 0)] if content_type.startswith("text/html") else []
    ctx = ScanContext(options=ScanOptions(sensitivity="paranoid"), target=url, entry=r, pages=pages, now=NOW)
    ctx.csp = csp.parse_all(ctx)
    ctx.hsts = transport.hsts_facts(ctx)
    ctx.cookies = cookies.parse_and_classify(ctx)
    found = []
    for mod in (hdr, csp, transport, cookies, cors):
        for issue in mod.run(ctx):
            sev = issue.severity or RULES[issue.rule].severity
            found.append((issue.rule, sev, mod.__name__.rsplit(".", 1)[-1]))
    return found


def _above_info(found):
    return [f for f in found if f[1] != "info"]


@pytest.mark.parametrize("where", sorted(_SCOPES))
def test_all_recommended_headers_together_pass_kashif(where):
    nonce = _nonce()
    found = _check_kind(where, _recommended(where, nonce), nonce)
    assert not _above_info(found), (where, found)


def _overlay(base: list[tuple[str, str]], own: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """``own`` replaces the same headers of ``base``; a Content-Security-Policy is layered on instead (several
    policies all apply, which is how S-MIXED's directive is meant to be combined with S-CSP)."""
    names = {n.lower() for n, _ in own if n.lower() != "content-security-policy"}
    return [h for h in base if h[0].lower() not in names] + own


@pytest.mark.parametrize("sid", sorted(s for s in R.SNIPPETS if R.SNIPPETS[s].headers))
def test_each_snippet_header_passes_kashif(sid):
    """The snippet's own header lines on top of the other snippets' recommended set: nothing above info, and in
    particular none of the rules this snippet is the fix for. Without the snippet, its rules fire (it is the fix)."""
    nonce = _nonce()
    for where in sorted({"document" if h.where == "any" else h.where for h in R.SNIPPETS[sid].headers}):
        own = [(h.name, _concrete(h.value, nonce)) for h in R.SNIPPETS[sid].headers if h.where in _SCOPES[where]]
        found = _check_kind(where, _overlay(_recommended(where, nonce, skip=sid), own), nonce)
        assert not _above_info(found), (sid, where, found)


@pytest.mark.parametrize("sid,rule", [("S-HSTS", "WEB-strict-transport-security"), ("S-CSP", "WEB-content-security-policy"),
                                      ("S-FRAME", None), ("S-XCTO", "WEB-x-content-type-options"),
                                      ("S-REF", "WEB-referrer-policy"), ("S-PP", "WEB-permissions-policy"),
                                      ("S-CACHE", "WEB315")])
def test_without_the_snippet_its_rule_fires(sid, rule):
    nonce = _nonce()
    where = "sensitive" if sid == "S-CACHE" else "document"
    base = _recommended(where, nonce, skip=sid)
    if sid == "S-CACHE":     # S-COOKIE repeats S-CACHE's no-store for the response that sets the cookie
        base = [h for h in base if h[0].lower() != "cache-control"]
    found = _check_kind(where, base, nonce)
    if rule is None:     # S-FRAME: S-CSP's frame-ancestors still protects the page, so nothing fires
        assert not _above_info(found), found
    else:
        assert any(r == rule for r, _s, _m in found), (sid, found)


def test_upgrade_insecure_requests_layered_policy_passes_kashif():
    nonce = _nonce()
    extra = [(h.name, h.value) for h in R.SNIPPETS["S-MIXED"].headers]
    found = _check_kind("document", _recommended("document", nonce) + extra, nonce)
    assert not _above_info(found), found


_SETTERS = (
    re.compile(r'^\s*add_header\s+([A-Za-z0-9-]+)\s+(?:"([^"]*)"|\'([^\']*)\')(?:\s+always)?;', re.M),          # nginx
    re.compile(r'^\s*Header\s+always\s+set\s+([A-Za-z0-9-]+)\s+(?:"([^"]*)"|\'([^\']*)\')\s*$', re.M),            # Apache
    re.compile(r'<add\s+name="([A-Za-z0-9-]+)"\s+value="([^"]*)"()\s*/>'),                                        # IIS
    re.compile(r'^\s*header\s+([A-Za-z0-9-]+)\s+(?:"([^"]*)"|`([^`]*)`)\s*$', re.M),                              # Caddy
)


def _platform_header_values() -> list[tuple[str, str, str, str]]:
    out = []
    for sid, sn in R.SNIPPETS.items():
        for b in sn.blocks:
            for rx in _SETTERS:
                for m in rx.finditer(b.code):
                    name = m.group(1)
                    value = next(g for g in m.groups()[1:] if g is not None)
                    value = value.replace("&quot;", '"').replace("&lt;", "<").replace("&amp;", "&")
                    if "$" in value or "%{" in value:
                        continue           # server variables (CORS map / SetEnvIf), not literal values
                    out.append((sid, b.platform, name, value))
    return out


def test_platform_blocks_set_headers_found():
    found = {(sid, p) for sid, p, _n, _v in _platform_header_values()}
    for sid in ("S-HSTS", "S-CSP", "S-FRAME", "S-XCTO", "S-REF", "S-PP", "S-ISO", "S-DEPR"):
        assert {(sid, "nginx"), (sid, "apache"), (sid, "iis"), (sid, "caddy")} <= found, sid
    assert ("S-CACHE", "nginx") in found


@pytest.mark.parametrize("sid,platform,name,value", _platform_header_values(),
                         ids=lambda v: v if isinstance(v, str) and len(v) < 30 else "")
def test_every_platform_header_value_passes_kashif(sid, platform, name, value):
    nonce = _nonce()
    where = {"clear-site-data": "logout", "cache-control": "sensitive"}.get(name.lower(), "document")
    base = _recommended(where, nonce)
    if name.lower() == "content-security-policy":   # an alternative to S-CSP's policy, so it replaces it
        base = [h for h in base if h[0].lower() != "content-security-policy"]
    found = _check_kind(where, _overlay(base, [(name, value)]), nonce)
    assert not _above_info(found), (sid, platform, name, value, found)


# ----------------------------------------------------------------------------------------------- security.txt

@pytest.mark.parametrize("now,expected", [
    (datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc), "2027-05-13T00:00:00.000Z"),
    (datetime(2026, 8, 31, 23, 59, tzinfo=timezone.utc), "2027-02-28T00:00:00.000Z"),
    (datetime(2027, 8, 31, 0, 0, tzinfo=timezone.utc), "2028-02-29T00:00:00.000Z"),
    (datetime(2026, 6, 30, 0, 0, tzinfo=timezone.utc), "2026-12-30T00:00:00.000Z"),
])
def test_security_txt_expires_is_scan_date_plus_six_months(now, expected):
    assert R.security_txt_expires(now) == expected


def test_security_txt_snippet_is_valid_rfc9116():
    from vulnscan.webscan import sectxt
    body = R.render("S-SECTXT", host="https://www.example.org/", now=NOW)["detected"][0]["code"] + "\n"
    assert "Expires: 2027-05-13T00:00:00.000Z" in body
    assert "Canonical: https://www.example.org/.well-known/security.txt" in body
    assert "mailto:security@example.org" in body
    st = sectxt.validate(body, url="https://www.example.org/.well-known/security.txt",
                         content_type="text/plain; charset=utf-8", now=NOW)
    assert st.severity is None or st.severity == "info", [p.code for p in st.problems]
    # a date fixed in the snippet would age into its own WEB900 finding; the computed one never does
    later = datetime(2027, 4, 1, tzinfo=timezone.utc)
    st = sectxt.validate(R.render("S-SECTXT", host="www.example.org", now=later)["detected"][0]["code"] + "\n",
                         url="https://www.example.org/.well-known/security.txt",
                         content_type="text/plain; charset=utf-8", now=later)
    assert st.severity in (None, "info"), [p.code for p in st.problems]


# ----------------------------------------------------------------------------------------------- placeholders

def test_fill_replaces_only_known_tokens():
    vals = R.placeholders("https://shop.example.co.uk:8443/cart", NOW)
    assert vals["host"] == "shop.example.co.uk" and vals["domain"] == "example.co.uk"
    assert vals["names"] == "shop.example.co.uk"
    assert R.placeholders("www.example.org")["names"] == "example.org www.example.org"
    assert R.placeholders("a.b.github.io")["domain"] == "b.github.io"          # PSL private section
    text = "server_name {names}; `'nonce-${res.locals.cspNonce}'` {RANDOM} {nonce} {host} {{host}} {R:1}"
    out = R.fill(text, vals)
    assert "${res.locals.cspNonce}" in out and "{RANDOM}" in out and "{nonce}" in out and "{R:1}" in out
    assert "server_name shop.example.co.uk;" in out and "{shop.example.co.uk}" in out
    assert R.fill("{host}") == "example.com"


@pytest.mark.parametrize("host", ["x$(id).com", "a b.com", "evil.com\nadd_header X 1", "'; rm -rf /", "a\x1b[31m.com"])
def test_hostile_host_never_reaches_copy_paste_config(host):
    vals = R.placeholders(host, NOW)
    assert vals["host"] == "example.com" and vals["domain"] == "example.com"


def test_idn_and_ip_hosts():
    assert R.placeholders("https://bücher.example/")["host"] == "xn--bcher-kva.example"
    assert R.placeholders("http://127.0.0.1:8080/")["names"] == "127.0.0.1"
    assert R.placeholders("http://[2001:db8::1]/")["host"] == "[2001:db8::1]"


# ----------------------------------------------------------------------------------------------- platform ordering

def test_detect_platforms_from_headers_and_inventory():
    assert R.detect_platforms(headers={"Server": "nginx/1.25.3", "X-Powered-By": "Express"})[:2] == ("nginx", "express")
    assert R.detect_platforms(headers=[("Server", "Apache-Coyote/1.1")])[0] == "tomcat"       # not Apache httpd
    assert "apache" not in R.detect_platforms(headers=[("Server", "Apache-Coyote/1.1")])
    assert R.detect_platforms(headers=[("server", "Microsoft-IIS/10.0"), ("X-AspNet-Version", "4.0.30319")])[0] == "iis"
    assert R.detect_platforms(headers=HeaderList.of(("Server", "cloudflare"), ("CF-RAY", "8a-AMS"))) == ("cloudflare",)
    assert R.detect_platforms([{"id": "django", "name": "Django"}, "python"]) == ("django",)
    assert R.detect_platforms(["wordpress", "php", "apache-http-server"]) == ("php", "apache")
    assert R.detect_platforms(headers={"Server": "Kestrel"}) == ("aspnetcore",)
    assert R.detect_platforms() == ()


def test_tech_platform_ids_exist_in_tech_data():
    from vulnscan.webscan import data
    ids = {t["id"] for t in data.load_json("tech.json")["technologies"]}
    unknown = set(R.TECH_PLATFORMS) - ids
    assert not unknown, sorted(unknown)
    for plats in R.TECH_PLATFORMS.values():
        assert set(plats) <= set(R.PLATFORMS)
    for _h, _rx, plats in R.HEADER_PLATFORMS:
        assert set(plats) <= set(R.PLATFORMS)


def test_detected_platforms_are_shown_first_and_the_rest_collapsed():
    d = R.render("S-HSTS", "en", detected=("django", "nginx"))
    assert [b["platform"] for b in d["detected"]] == ["any", "django", "nginx"]
    rest = [b["platform"] for b in d["other"]]
    assert "django" not in rest and "nginx" not in rest
    assert rest == [p for p in R.PLATFORMS if p in set(rest)]            # default order for the collapsed ones
    plain = R.render("S-HSTS", "en")
    assert [b["platform"] for b in plain["detected"]] == ["any"]
    assert [b["platform"] for b in plain["other"]][:4] == ["nginx", "apache", "iis", "caddy"]
    # a detected platform without a block in this snippet changes nothing
    assert [b["platform"] for b in R.render("S-SRI", detected=("nginx",))["detected"]] == ["any", "any"]


def test_platforms_from_context(make_ctx, make_page):
    page = make_page("<html><body>hi</body></html>", url="https://shop.example.test/",
                     headers={"Server": "nginx", "X-Powered-By": "PHP/8.3.1"})
    ctx = make_ctx(target="https://shop.example.test/", entry=page)
    ctx.inventory["technologies"] = [{"id": "laravel", "name": "Laravel"}]
    plats = R.platforms_from_context(ctx)
    assert plats[:2] == ("nginx", "php") and "laravel" in plats
    d = R.render("S-ERR", "ar", host=ctx.target, detected=plats)
    assert [b["platform"] for b in d["detected"]] == [p for p in plats if p in R.SNIPPETS["S-ERR"].platforms]
    assert {b["platform"] for b in d["detected"]} == {"nginx", "php", "laravel"}
    assert d["caveat_label"] == "تنبيه" and ARABIC.search(d["caveat"])


def test_for_rules_and_markdown():
    out = R.for_rules(["WEB020", "WEB021", "WEB-strict-transport-security", "WEB999"], "en", host="example.org")
    assert [d["id"] for d in out] == ["S-COOKIE", "S-HSTS"]
    assert R.fix_ids_for(["WEB318"]) == ("S-HSTS", "S-CSP", "S-FRAME", "S-XCTO")
    md = R.to_markdown("S-CSP", "ar", host="www.example.org", detected=("express",))
    assert md.startswith("### S-CSP · ") and "**تنبيه:**" in md and "csp=\"https://www.example.org/csp-report\"" in md
    assert md.index("Express") < md.index("nginx") and "منصات أخرى" in md


def test_remediation_module_imports_no_check_module():
    src = (ROOT / "vulnscan" / "webscan" / "remediation.py").read_text(encoding="utf-8")
    checks = ("transport", "csp", "headers", "cors", "cookies", "content", "domxss", "disclosure", "libs", "tech",
              "exposure", "engine", "http", "classify", "tls")
    for m in checks:
        assert not re.search(rf"^\s*(from \.{m}\b|from \.\. ?import|import vulnscan\.webscan\.{m}\b)", src, re.M), m


# ----------------------------------------------------------------------------------------------- i18n (cat_web2)

def test_cat_web2_builds_without_failures():
    from vulnscan.i18n import cat_web2
    catalog, patterns = cat_web2.load()
    assert not cat_web2.FAILED, cat_web2.FAILED
    assert len(catalog) > 500 and len(patterns) > 300
    for rx, _en in patterns:
        re.compile(rx, re.S)


def test_importing_i18n_stays_lazy():
    """`import vulnscan.model` (every kashif command) must not import the web scanner; the first untranslated web
    string loads it and is translated in the same call."""
    code = ("import sys, vulnscan.model\n"
            "print('vulnscan.webscan.csp' in sys.modules)\n"
            "from vulnscan.i18n import to_en\n"
            "print(to_en('تعذّر إجراء بعض الفحوص'))\n"
            "print('vulnscan.webscan.csp' in sys.modules)\n")
    out = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
                         timeout=60, check=True).stdout.split("\n")
    assert out[:3] == ["False", "Some checks could not be performed", "True"], out


# texts whose Arabic equals a 1.0.1 string of cat_web with a slightly different English (cat_web is earlier, so 1.x
# reports keep the 1.0.1 wording); vulnscan.model.Finding carries its English title directly, so only to_en differs
LEGACY_1_0 = {"لا حماية من Clickjacking", "ترويسة X-Powered-By تكشف التقنية", "CSP يسمح بسكربتات inline",
              "حقل كلمة مرور في صفحة غير HTTPS", "قدّم صفحات تسجيل الدخول عبر HTTPS فقط."}


def test_every_rule_text_has_english_through_vulnscan_i18n():
    from vulnscan.i18n import cat_web, to_en, translated
    samples = {"cookie": "sid", "value": "Apache/2.4.1", "versions": "TLS 1.0", "library": "jquery", "version": "1.8.3",
               "fixed": "3.5.0", "platform": "WordPress", "branch": "5.9", "date": "2024-01-01", "latest": "6.4.5",
               "product": "nginx", "path": "/.env", "header": "X-AspNet-Version"}
    wrong = []
    for rid, m in RULES.items():
        for variant in (None, *m.variants):
            for days in (1, 2, 7, 11, 100):
                params = dict(samples, variant=variant, days=days, hops=days)
                for what in ("title", "advice"):
                    ar, en = getattr(m, what)("ar", **params), getattr(m, what)("en", **params)
                    assert translated(ar), (rid, what, ar)
                    if to_en(ar) != en and ar not in LEGACY_1_0:
                        wrong.append((rid, what, ar, to_en(ar), en))
        assert translated(m.name_ar), rid
    assert not wrong, wrong[:10]
    assert LEGACY_1_0 <= set(cat_web.CATALOG)


def test_remediation_texts_have_english_through_vulnscan_i18n():
    from vulnscan.i18n import to_en
    for en, ar in R.texts():
        if ARABIC.search(ar):
            assert to_en(ar) == en, ar


def test_web_module_texts_have_english():
    """Every fixed Arabic text of every webscan STR table, and the Arabic titles/advice of the data files."""
    from vulnscan.i18n import cat_web2, translated
    import importlib
    missing = []
    for name in cat_web2.SOURCES:
        try:
            mod = importlib.import_module(f"vulnscan.webscan.{name}")
        except ModuleNotFoundError:
            continue
        for pair in (getattr(mod, "STR", None) or {}).values():
            if isinstance(pair, tuple) and len(pair) == 2 and isinstance(pair[1], str) and ARABIC.search(pair[1]):
                text = re.sub(r"\{[a-z_]+\}", "X1", pair[1])
                if not translated(text):
                    missing.append((name, pair[1]))
    from vulnscan.webscan import data
    for fname in cat_web2.DATA_FILES:
        pairs: list[tuple[str, str]] = []
        cat_web2._walk_records(data.load_json(fname), pairs)
        assert pairs, fname
        missing += [(fname, ar) for ar, _en in pairs if not translated(ar)]
    assert not missing, missing[:10]


def test_arabic_counts_agree_with_the_number():
    """Snippet texts cite fixed values only; a counted noun after a number 11-99 would need plural.py's forms."""
    from vulnscan.i18n.plural import ar_count
    for sn in R.SNIPPETS.values():
        for text in (sn.caveat_ar, sn.summary_ar, sn.title_ar):
            assert not re.search(r"\b(1[1-9]|[2-9][0-9]) (ملف|نتيجة|يوم|شهر)\b", text), text
    assert ar_count(6, ("شهر واحد", "شهران", "{n} أشهر", "{n} شهرًا", "{n} شهر")) == "6 أشهر"


# ----------------------------------------------------------------------------------------------- docs page

def _gen_docs():
    spec = importlib.util.spec_from_file_location("kashif_gen_docs", ROOT / "tools" / "webdata" / "gen_docs.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_docs_page_is_current_and_lists_every_rule():
    gen = _gen_docs()
    text = gen.render()
    committed = (ROOT / "docs" / "web-checks.md").read_text(encoding="utf-8").replace("\r\n", "\n")
    assert committed == text, "docs/web-checks.md is out of date: run python tools/webdata/gen_docs.py"
    assert gen.render() == text                                      # deterministic
    for rid in RULE_IDS:
        m = RULES[rid]
        row = next((line for line in text.splitlines() if line.startswith(f"| `{rid}` |")), None)
        assert row, rid
        for value in (m.cwe or "—", *(m.wstg or ("—",)), *(m.asvs4 or ("—",)), *(m.asvs5 or ("—",)), *m.fix):
            assert value in row, (rid, value)
    for sid in R.SNIPPETS:
        assert f'<a id="{sid.lower()}"></a>' in text
    assert "github.com" not in text


# ----------------------------------------------------------------------------------------------- site/scanner.html

class _Doc(HTMLParser):
    VOID = {"meta", "link", "img", "br", "hr", "input", "source"}

    def __init__(self):
        super().__init__()
        self.stack, self.errors, self.links, self.scripts, self.langs = [], [], [], 0, []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "script":
            self.scripts += 1
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        if a.get("lang"):
            self.langs.append(a["lang"])
        if tag not in self.VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if self.stack and self.stack[-1] == tag:
            self.stack.pop()
        else:
            self.errors.append(tag)


def test_scanner_page_explains_the_scanner_in_both_languages():
    assert UA_INFO_URL.endswith("/scanner.html")
    html = (ROOT / "site" / "scanner.html").read_text(encoding="utf-8")
    doc = _Doc()
    doc.feed(html)
    assert not doc.stack and not doc.errors
    assert doc.scripts == 0                                       # static page, nothing to execute
    assert {"en", "ar"} <= set(doc.langs) and 'dir="rtl"' in html
    assert not any("github.com" in h for h in doc.links) and "github.com" not in html.replace(
        "abdulrahmanahmedelabed-prog.github.io", "")
    assert all(not re.match(r"https?://", h) for h in doc.links)  # on-site links only
    for fact in ("Kashif/1.", "scanner.html", "--authorized", "kashif-cors-check.invalid", "/kashif-404-",
                 "robots.txt", "Crawl-delay", "Retry-After", "security.html#report", "45", "150",
                 "Accept-Encoding: gzip, deflate", "telemetry"):
        assert fact in html, fact
    for fact in ("مالكه", "مخوَّل", "الإبلاغ", "سلبي"):
        assert fact in html, fact


def test_scanner_page_request_table_matches_the_scope_contract():
    """The limits on the page are the §0.1 numbers the fetcher enforces."""
    html = (ROOT / "site" / "scanner.html").read_text(encoding="utf-8")
    for n in ("≤ 10 hops", "≤ 5", "≤ 15 same-site", "≤ 10 third-party", "≤ 70 paths", "≤ 5 random paths per host"):
        assert n in html, n


# ----------------------------------------------------------------------------------------------- NOTICE

def test_notice_names_every_third_party_data_file():
    notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
    data_dir = ROOT / "vulnscan" / "data" / "web"
    third_party = re.compile(r"Apache|MIT|BSD|MPL", re.I)
    checked = 0
    for f in sorted(data_dir.iterdir()):
        meta = None
        if f.name.endswith(".meta.json"):
            blob = json.loads(f.read_text(encoding="utf-8"))
            meta = blob.get("meta", blob) if isinstance(blob, dict) else None      # {"meta": {...}, "file": ...}
            name = f.name.replace(".meta.json", "")
        elif f.suffix == ".json" and f.name != "MANIFEST.json":
            blob = json.loads(f.read_text(encoding="utf-8"))
            meta = blob.get("meta") if isinstance(blob, dict) else None
            name = f.name
        elif f.name.endswith(".json.gz"):
            import gzip
            blob = json.loads(gzip.decompress(f.read_bytes()))
            meta = blob.get("meta") if isinstance(blob, dict) else None
            name = f.name
        if not meta:
            continue
        lic = str(meta.get("license") or meta.get("licence") or "")
        if third_party.search(lic):
            checked += 1
            assert name in notice, (name, lic)
    assert checked >= 9                    # psl.dat (.meta.json) included



# ----------------------------------------------------------------------------------------------- adversarial review

def test_apache_cors_allowlist_regex_escapes_the_domain():
    """``app\\.{domain}`` with the dots of a multi-label domain left bare let ``https://app.site-co.uk`` (registrable by
    anyone) through the copy-paste allowlist of ``site.co.uk``."""
    d = R.render("S-CORS", host="https://shop.site.co.uk/")
    code = next(b["code"] for b in d["detected"] + d["other"] if b["platform"] == "apache")
    rx = re.search(r'SetEnvIf Origin "([^"]+)"', code).group(1)
    assert re.fullmatch(rx, "https://app.site.co.uk")
    for evil in ("https://app.site-co.uk", "https://appXsite.co.uk", "https://app.site.coXuk", "https://app.site.co.uk.evil.net"):
        assert not re.fullmatch(rx, evil), evil
    plain = R.render("S-CORS")
    assert 'SetEnvIf Origin "^(https://app\\.example\\.com)$"' in next(
        b["code"] for b in plain["other"] if b["platform"] == "apache")
    # every other block names the origin literally (nginx map strings are exact matches, not regexes)
    for b in d["detected"] + d["other"]:
        if b["platform"] != "apache" and b["code"]:
            assert "https://app.site.co.uk" in b["code"], b["platform"]


@pytest.mark.parametrize("host", ["http://[::1", "http://a]b/", "https://[", "http://user@", "\x00", "",
                                  "http://evil..com/", "http://" + "a" * 64 + ".com/", "a" * 300, b"example.org", 5,
                                  "http://-x.com", "http://x-.com", "http://%2e%2e/", "http://exa mple.com"])
def test_malformed_hosts_fall_back_without_raising(host):
    vals = R.placeholders(host, NOW)
    assert vals["host"] == "example.com" and vals["names"] == "example.com www.example.com"
    out = R.render("S-REDIR", "ar", host=host, now=NOW)
    assert "example.com" in "".join(b["code"] for b in out["other"])


def test_host_with_port_and_bare_ipv6():
    assert R.placeholders("example.org:8080")["host"] == "example.org"
    assert R.placeholders("www.example.org:443")["names"] == "example.org www.example.org"
    assert R.placeholders("2001:db8::1")["host"] == "[2001:db8::1]"
    assert R.placeholders("2001:db8::1")["domain_re"] == re.escape("[2001:db8::1]")


def test_fuzzed_hosts_only_ever_yield_host_name_characters():
    import random
    rnd = random.Random(1110)
    alphabet = "abc.-_:/[]@%?#{}$'\";\\ \n\t\x00\x1bé١" + "0123456789"
    for _ in range(400):
        host = "".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 40)))
        for sch in ("", "http://", "https://"):
            vals = R.placeholders(sch + host, NOW)
            for k in ("host", "domain", "names"):
                assert re.fullmatch(r"[a-z0-9._ \[\]:-]+", vals[k]), (host, k, vals[k])
            assert re.fullmatch(r"[a-z0-9_\\.\[\]:-]+", vals["domain_re"]), (host, vals["domain_re"])


def test_detect_platforms_tolerates_malformed_input():
    assert R.detect_platforms(headers=[("Server",), ("Server", None), (b"Server", b"nginx"), "junk", None]) == ()
    assert R.detect_platforms(headers="Server: nginx") == ()
    assert R.detect_platforms(technologies=[None, 5, {"id": None}, {}]) == ()
    assert R.detect_platforms(technologies="nginx") == ("nginx",)          # one id, not its characters
    assert R.detect_platforms(headers={"Server": "x" * 70000}) == ()
    assert R.detect_platforms(headers={"Server": "Tengine/2.3"}) == ("nginx",)


def test_weak_or_generic_detections_are_not_shown_as_detected():
    assert R.detect_platforms([{"id": "nginx", "confidence": 20}]) == ()          # below exposure.py's bar
    assert R.detect_platforms([{"id": "nginx", "confidence": 50}]) == ("nginx",)
    assert "spring" not in R.detect_platforms(["java", "confluence"])            # Java alone is not Spring
    assert R.detect_platforms(["codeigniter"]) == ("php",)


def test_arabic_menu_paths_read_in_the_right_direction():
    """A menu path written with "←" between Latin names is laid out left to right by the bidi algorithm (the arrow is
    neutral between two strong LTR runs), so it read backwards; Arabic notes use "→" inside the Latin path."""
    for en, ar in R.texts():
        assert "←" not in ar, ar
        if "→" in ar:
            for m in re.finditer(r"→", ar):
                before, after = ar[:m.start()].rstrip(), ar[m.end():].lstrip()
                assert before and after and not ARABIC.match(after[0]) and not ARABIC.search(before[-1]), ar


def test_english_lookup_of_hostile_text_is_bounded():
    """A page's own Arabic text can reach to_en through a finding parameter: "x: x: x: …" recursed once per separator
    through the generic "{kind}: {value}" template (minutes for 6 kB, then RecursionError)."""
    import time
    from vulnscan.i18n import cat_web2, to_en
    cat_web2.ensure_loaded()
    cases = ["ب: " * 2000, "ب: " * 120, "ظهر في " * 280 + ": x", "…و" * 995 + ".", "ب: x (y). " * 199,
             "ب (" * 666, "الترويسة " * 220, "ب" * 50000]
    t0 = time.monotonic()
    for text in cases:
        out = to_en(text)
        assert isinstance(out, str)
    assert time.monotonic() - t0 < 5
    assert to_en("ب: ب") == "ب: ب"                         # untranslatable parts: returned, no endless re-match
    assert to_en("تعذّر إجراء بعض الفحوص") == "Some checks could not be performed"


def test_composed_web_sentences_still_translate_through_the_bounded_lookup():
    from vulnscan.i18n import cat_web2, to_en
    cat_web2.ensure_loaded()
    rx, en = next((rx, en) for rx, en in cat_web2.PATTERNS if rx.startswith("(?P<kind>.+?):"))
    known = next(ar for ar, e in cat_web2.CATALOG.items() if len(ar) < 60 and ":" not in ar)
    assert to_en(f"{known}: {known}") == f"{cat_web2.CATALOG[known]}: {cat_web2.CATALOG[known]}", (rx, en)


def test_copy_paste_blocks_are_syntactically_valid():
    """Apache and Java .properties have no trailing comments (``FileETag MTime Size # …`` is a FileETag error, and a
    property value would swallow the comment); Apache containers cannot sit on one line; IIS XML parses; nginx
    statements end with ``;`` and braces balance."""
    import xml.etree.ElementTree as ET
    for sid, sn in R.SNIPPETS.items():
        for b in sn.blocks:
            code = R.fill(b.code)
            if b.lang in ("apache", "properties", "ini"):
                for line in code.splitlines():
                    st = line.strip()
                    assert st.startswith(("#", ";")) or not re.search(r"\s[#;]", st), (sid, b.platform, line)
            if b.lang == "apache":
                assert not re.search(r"^\s*<\w+[^>\n]*>\S", code, re.M), (sid, code)
                opens = sorted(re.findall(r"^\s*<(\w+)", code, re.M))
                assert opens == sorted(re.findall(r"^\s*</(\w+)>", code, re.M)), (sid, code)
            if b.lang == "xml":
                ET.fromstring("<r>" + code + "</r>")
            if b.lang in ("nginx", "caddy"):
                assert code.count("{") == code.count("}"), (sid, b.platform)
            if b.lang == "nginx":
                for line in code.splitlines():
                    st = re.sub(r"\s+#.*$", "", line).strip()
                    assert not st or st.startswith("#") or st.endswith((";", "{", "}")), (sid, line)
