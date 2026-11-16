"""Kashif 1.1.0 web-scanning documentation: README web section, docs/web-scanning.md, CHANGELOG, and the site
(site/build_docs.py publishing docs/web-scanning.md and docs/web-checks.md, index.html, scanner.html, sitemap.xml).

The documents state facts the code enforces (option combinations, budgets, platforms, coverage states, severities);
these tests read them from the code, so a change on one side without the other fails here. Offline and fast.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import re
import xml.dom.minidom

import pytest

from vulnscan.i18n.plural import REQUESTS, ar_count
from vulnscan.webscan import coverage, remediation, rules

ROOT = pathlib.Path(__file__).resolve().parents[1]
SITE = "https://abdulrahmanahmedelabed-prog.github.io/vulnscan/"
DOC = (ROOT / "docs" / "web-scanning.md").read_text(encoding="utf-8")
EN, _, AR = DOC.partition('<a id="arabic"></a>')
README = (ROOT / "README.md").read_text(encoding="utf-8")
README_EN, _, README_AR = README.partition('<a id="arabic"></a>')
CHANGELOG = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
INDEX = (ROOT / "site" / "index.html").read_text(encoding="utf-8")
SCANNER = (ROOT / "site" / "scanner.html").read_text(encoding="utf-8")
PAGES_AR = ("صفحة واحدة", "صفحتان", "{n} صفحات", "{n} صفحةً", "{n} صفحة")
PLATFORMS_AR = ("منصة واحدة", "منصتان", "{n} منصات", "{n} منصةً", "{n} منصة")
SECONDS_AR = ("ثانية واحدة", "ثانيتان", "{n} ثوانٍ", "{n} ثانيةً", "{n} ثانية")


def _section(text: str, heading: str) -> str:
    """The body of the Markdown section `heading` (up to the next heading of the same or a higher level)."""
    m = re.search(rf"(?m)^(#+) {re.escape(heading)}\s*$", text)
    assert m, heading
    level = len(m.group(1))
    nxt = re.search(rf"(?m)^#{{1,{level}}} ", text[m.end():])
    return text[m.end(): m.end() + nxt.start() if nxt else len(text)]


# ----------------------------------------------------------------------------------------------- docs/web-scanning.md

def test_both_halves_have_the_same_sections():
    en = re.findall(r"(?m)^##+ ", EN)
    ar = re.findall(r"(?m)^##+ ", AR)
    assert len(en) == len(ar) >= 10
    for heading in ("What a passive scan cannot find", "Using it in CI", "Policy files", "Comparing scans",
                    "Proxies", "Limits of one scan", "Upgrading from 1.0"):
        assert re.search(rf"(?m)^##+ {re.escape(heading)}$", EN), heading
    for heading in ("ما لا يكشفه الفحص السلبي", "الاستخدام في CI", "ملف السياسة", "مقارنة الفحوص",
                    "الوكيل (Proxy)", "حدود الفحص الواحد", "الترقية من 1.0"):
        assert re.search(rf"(?m)^##+ {re.escape(heading)}$", AR), heading


def test_what_a_passive_scan_cannot_find():
    en = _section(EN, "What a passive scan cannot find")
    for fact in ("Anonymous pages only", "injection", "XSS", "authentication", "access-control", "business-logic",
                 "revocation", "configuration hygiene, not the absence of vulnerabilities", "SAST",
                 "authorised active test"):
        assert fact in en, fact
    ar = _section(AR, "ما لا يكشفه الفحص السلبي")
    for fact in ("الصفحات العامة فقط", "للحقن", "XSS", "للمصادقة", "للتحكم في الوصول", "لمنطق العمل",
                 "إلغاء الشهادة", "سلامة الإعدادات، لا خلوّ الموقع من الثغرات", "SAST", "اختبار نشط مصرَّح به"):
        assert fact in ar, fact


def test_ci_section_states_the_command_exit_codes_and_sarif_upload():
    for half, heading in ((EN, "Using it in CI"), (AR, "الاستخدام في CI")):
        ci = _section(half, heading)
        assert "--fail-on high -f sarif" in ci
        for code in ("`0`", "`1`", "`2`"):
            assert code in ci, (heading, code)
        for fact in ("--fail-on-inconclusive", "WEB990", "--compare previous", "category: kashif-web",
                     '"unreachable"', "executionSuccessful", "web/<code>", "runs[0].properties.kashif.web"):
            assert fact in ci, (heading, fact)
    en = _section(EN, "Using it in CI")
    assert "URL, not a file location" in en and "upload-sarif" in en
    # the unreachable-report example is the shape cli._write_unreachable writes
    example = json.loads(re.search(r"```json\n(.*?)```", en, re.S).group(1))
    assert example["web"]["status"] == "unreachable" and example["findings"] == []
    assert set(example["web"]["error"]) == {"code", "en", "ar", "raw"}
    assert set(example) == {"target", "generated_at", "files_scanned", "notes", "notes_en", "summary", "findings", "web"}
    from vulnscan.report import WEB_SCHEMA
    assert example["web"]["schema"] == WEB_SCHEMA
    # no GitHub link is added: the CI job installs from the project site
    assert "github.com" not in en.replace("github/codeql-action/upload-sarif", "")


def test_unreachable_report_shape_matches_the_cli(tmp_path, monkeypatch):
    """The documented JSON shape is what the CLI writes for a site that cannot be reached (exit code 2)."""
    import argparse
    from vulnscan import cli
    out = tmp_path / "r.json"
    args = argparse.Namespace(all_formats=None, output=str(out), format="json")
    info = {"code": "refused", "en": "The site was not scanned: x", "ar": "لم يُفحص الموقع: x", "raw": "refused"}
    cli._write_unreachable(args, "https://staging.example.com", info, "en")
    doc = json.loads(out.read_text(encoding="utf-8"))
    example = json.loads(re.search(r"```json\n(.*?)```", EN, re.S).group(1))
    assert set(doc) == set(example) and set(doc["web"]) == set(example["web"])


@pytest.mark.parametrize("argv,why", [
    (["{dir}", "--compare", "x"], "web_only"),
    (["{dir}", "--fail-on-inconclusive"], "web_only"),
    (["{dir}", "--no-proxy"], "web_only"),
    (["https://example.invalid/", "--authorized", "--deep", "--web-profile", "standard"], "deep_conflict"),
    (["https://example.invalid/", "--authorized", "--crawl", "--web-profile", "minimal"], "crawl_minimal"),
    (["https://example.invalid/", "--authorized", "--compare", "a", "--compare-previous"], "compare_both"),
    (["https://example.invalid/", "--authorized", "--diff-base", "main"], "--diff-base"),
])
def test_documented_rejected_combinations_exit_2_before_sending(argv, why, tmp_path, capsys):
    from vulnscan.cli import _WEB_HELP, main
    with pytest.raises(SystemExit) as e:
        main([a.replace("{dir}", str(tmp_path)) for a in argv] + ["--lang", "en"])
    assert e.value.code == 2
    err = capsys.readouterr().err
    expected = why if why.startswith("--") else re.split(r"\{", _WEB_HELP["en"][why])[0]
    assert expected in err, err


def test_policy_section_names_the_file_and_the_gate():
    for half, heading in ((EN, "Policy files"), (AR, "ملف السياسة")):
        pol = _section(half, heading)
        assert "--policy kashif.yml" in pol and "--ignore-rule" in pol
        assert "rules.disable" in pol and "rules.severity" in pol
        yml = re.search(r"```yaml\n(.*?)```", pol, re.S).group(1)       # the example is in both languages
        assert "gate:" in yml and "fail_on:" in yml and "disable:" in yml and "severity:" in yml
    from vulnscan import policy
    assert policy._GATE_DEFAULTS["fail_on"] == "high"                   # "the default gate fails on high"


def test_policy_example_is_a_valid_policy(tmp_path):
    from vulnscan import policy
    yml = re.search(r"```yaml\n(.*?)```", _section(EN, "Policy files"), re.S).group(1)
    f = tmp_path / "kashif.yml"
    f.write_text(yml, encoding="utf-8")
    pol = policy.load_policy(str(f))
    assert pol.gate["fail_on"] == "medium"


def test_proxy_and_limits_are_documented():
    for half, heading, facts in (
            (EN, "Proxies", ("http://", "CONNECT", "`web.error.code`", "tentative", "--web-sensitivity paranoid",
                             "--no-proxy", "NO_PROXY", "not tested")),
            (AR, "الوكيل (Proxy)", ("http://", "CONNECT", "`web.error.code`", "محتملة", "--web-sensitivity paranoid",
                                     "--no-proxy", "NO_PROXY", "لم تُجرَ"))):
        sec = _section(half, heading)
        for fact in facts:
            assert fact in sec, (heading, fact)
    lim = _section(EN, "Limits of one scan")
    assert "600 s" in lim and "50 MB" in lim and "500 pages" in lim and "`minimal` cannot crawl" in lim
    lim_ar = _section(AR, "حدود الفحص الواحد")
    assert ar_count(600, SECONDS_AR) in lim_ar and "50 ميغابايت" in lim_ar and ar_count(500, PAGES_AR) in lim_ar
    from vulnscan.cli import _WEB_HELP
    assert "500" in _WEB_HELP["en"]["max_pages"]                        # the cap the CLI applies
    from vulnscan import web
    import inspect
    assert inspect.signature(web.options_for).parameters["time_budget"].default == 600.0
    from vulnscan.webscan import http as web_http
    assert "(50 MB)" in (web_http.__doc__ or "") and "(600 s)" in (web_http.__doc__ or "")


def test_compare_section_says_where_ids_come_from():
    en = _section(EN, "Comparing scans")
    for fact in ("Scan saved in the local history (id", "stderr", "Reports", "index.json", "--compare previous.json",
                 "`kashif history` is unrelated"):
        assert fact in en, fact
    ar = _section(AR, "مقارنة الفحوص")
    from vulnscan.cli import _WEB_HELP
    assert _WEB_HELP["ar"]["saved"].split("(")[0].strip() in ar               # the stderr line, as printed
    assert _WEB_HELP["en"]["saved"].split("(")[0].strip() in en
    for fact in ("stderr", "التقارير", "index.json", "--compare previous.json", "kashif history"):
        assert fact in ar, fact


def test_numbers_and_lists_match_the_code():
    # the standard row names the sitemap, fetched with --crawl only
    std = next(line for line in EN.splitlines() if line.startswith("| `standard` (default)"))
    assert "`/sitemap.xml` (with `--crawl`)" in std
    std_ar = next(line for line in AR.splitlines() if line.startswith("| `standard` (الافتراضي)"))
    assert "`/sitemap.xml` (مع `--crawl`)" in std_ar
    # all 18 remediation platforms
    names = [en for key, (en, _ar) in remediation.PLATFORMS.items() if key != "any"]
    assert len(names) == 18
    for half in (EN, AR):
        for name in names:
            assert name.split(" (")[0] in half, name
    assert "18 platforms" in EN and ar_count(18, PLATFORMS_AR) in AR
    # the exact JSON coverage state tokens
    tokens = sorted(coverage.PRECEDENCE)
    for half in (EN, AR):
        for tok in tokens:
            assert f"`{tok}`" in half, tok
    # request budgets with the right Arabic agreement
    from vulnscan.cli import WEB_BUDGET
    for n in WEB_BUDGET.values():
        assert ar_count(n, REQUESTS) in AR, n
        assert f"at most {n}" in EN


def test_crawl_is_same_origin_everywhere():
    phrase_en, phrase_ar = "same-origin (same scheme, host and port)", "الأصل نفسه (المخطط والمضيف والمنفذ"
    assert phrase_en in EN and phrase_ar in AR
    web_en = _section(README_EN, "Passive web scanning")
    assert "same-origin pages (same scheme, host and port)" in web_en
    assert "same-origin links (same scheme, host and port)" in web_en
    web_ar = _section(README_AR, "فحص المواقع السلبي")
    assert phrase_ar in web_ar and "صفحات الموقع نفسه" not in web_ar
    crawl_ar = _section(README_AR, "فحص تطبيقات الويب وصفحاتها (الزحف وبصمة المنصّات)")
    assert "**النطاق نفسه**" not in crawl_ar and "الأصل نفسه" in crawl_ar
    assert "same scheme, host and port" in SCANNER and "المخطط والمضيف والمنفذ" in SCANNER


def test_arabic_terminology():
    for name, text in (("docs/web-scanning.md", AR), ("README.md", README_AR), ("CHANGELOG.md", CHANGELOG),
                       ("site/index.html", INDEX), ("site/scanner.html", SCANNER)):
        assert "الشيفرة" not in text.replace("«الكود» بدل «الشيفرة»", ""), name
        assert "محميّ للصدفة" not in text, name
        assert "كاشف" not in text, name                          # always «كاشِف»
        assert "ملف الفحص" not in text and "ملفات الفحص" not in text, name   # the profile is «نمط الفحص»
    assert "مُحاط بعلامات اقتباس آمنة لسطر الأوامر" in AR
    assert "نمط الفحص" in AR and "أنماط الفحص" in CHANGELOG


def test_upgrade_notes_have_the_severity_table_and_the_breaking_changes():
    up = _section(EN, "Upgrading from 1.0")
    rows = {m.group(1): (m.group(2), m.group(3))
            for m in re.finditer(r"(?m)^  \| `(WEB[\w-]+)`[^|]*\| ([^|]+) \| ([^|]+) \|$", up)}
    assert len(rows) >= 8
    for rid, (_old, new) in rows.items():
        meta = rules.RULES[rid]
        if "CWE" in new:
            assert meta.cwe in new, rid
        else:
            assert meta.severity in new or (rid == "WEB054"), (rid, meta.severity, new)
    assert rows["WEB-strict-transport-security"] == ("high", "medium")
    for fact in ("Default profile `standard`", "Recalibrated severities", "CSV column", "`Confidence`",
                 "Proxy failure", "exit code 2", "--write-baseline"):
        assert fact in up, fact
    up_ar = _section(AR, "الترقية من 1.0")
    assert up_ar.count("\n  | `WEB") == up.count("\n  | `WEB")
    for fact in ("نمط الفحص الافتراضي", "إعادة معايرة الخطورة", "عمود CSV", "فشل الوكيل", "رمز الخروج 2"):
        assert fact in up_ar, fact


def test_options_document_fail_on_inconclusive_and_ignore_rule():
    opts = _section(EN, "Options")
    assert "`--fail-on-inconclusive`" in opts and "`--ignore-rule ID`" in opts and "rejected" in opts
    for opt in ("--compare", "--compare-previous", "--web-profile", "--web-sensitivity", "--third-party-lookups",
                "--ignore-robots", "--web-cookie-ignore", "--no-proxy", "--fail-on-inconclusive"):
        assert f"`{opt}`" in opts.split("These combinations are rejected")[1], opt
    opts_ar = _section(AR, "الخيارات")
    assert "`--fail-on-inconclusive`" in opts_ar and "`--ignore-rule ID`" in opts_ar and "تُرفض" in opts_ar
    assert "--fail-on-inconclusive" in CHANGELOG and "docs/web-scanning.md#upgrading-from-10" in CHANGELOG


# ----------------------------------------------------------------------------------------------- README

def test_readme_web_section():
    en = _section(README_EN, "Passive web scanning")
    for fact in ("**What a passive scan cannot find:**", "revocation", "configuration hygiene", "**In CI**",
                 "--fail-on high", "-f sarif", "category: kashif-web", "--fail-on-inconclusive", '"unreachable"',
                 "--compare previous.json", "--policy kashif.yml", "gate:", "fail_on:", "--ignore-rule",
                 "`web.error.code` starts with `proxy`", "`/sitemap.xml` (with `--crawl`)", "18\nplatforms", "600 s", "50 MB",
                 "`minimal` cannot crawl", "`kashif history` is unrelated"):
        assert fact in en, fact
    ar = _section(README_AR, "فحص المواقع السلبي")
    for fact in ("**ما لا يكشفه الفحص السلبي:**", "إلغاء الشهادة", "سلامة الإعدادات", "**في CI**",
                 "category: kashif-web", "--fail-on-inconclusive", '"unreachable"', "--compare previous.json",
                 "--policy kashif.yml", "gate:", "fail_on:", "--ignore-rule", "`web.error.code`", "`/sitemap.xml` (مع `--crawl`)",
                 ar_count(18, PLATFORMS_AR), ar_count(600, SECONDS_AR), "kashif history"):
        assert fact in ar, fact
    assert "injection, XSS, authentication, access control or business logic" in _section(README_EN, "Limitations")
    assert "منطق" in _section(README_AR, "حدود الأداة")


# ----------------------------------------------------------------------------------------------- site

def _load_build_docs():
    spec = importlib.util.spec_from_file_location("kashif_build_docs", ROOT / "site" / "build_docs.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    bd = _load_build_docs()
    out = tmp_path_factory.mktemp("site")
    assert bd.main(["--out", str(out), "--version", "1.1.0"]) == 0      # includes the anchor checks
    return {p.name: p.read_text(encoding="utf-8") for p in out.glob("*.html")}


def test_web_docs_are_published(built):
    assert {"web-scanning.html", "web-checks.html", "docs.html"} <= set(built)
    docs = built["docs.html"]
    assert 'href="web-checks.html"' in docs and 'href="web-scanning.html"' in docs   # no longer plain text
    assert 'href="web-scanning.html#using-it-in-ci"' in docs
    assert 'href="web-scanning.html#upgrading-from-10"' in built["changelog.html"]
    page = built["web-scanning.html"]
    assert 'href="web-checks.html"' in page and 'href="scanner.html"' in page
    assert '<div class="half sw" lang="en" dir="ltr">' in page and '<div class="half sw" lang="ar" dir="rtl">' in page
    assert f'<link rel="canonical" href="{SITE}web-scanning.html">' in page
    for name, html_ in built.items():          # the header button is the only GitHub link
        links = re.findall(r'href="(https?://[^"]*github\.com[^"]*)"', html_)
        assert links == ["https://github.com/abdulrahmanahmedelabed-prog/vulnscan"], (name, links)


def test_web_checks_page_has_one_anchor_per_rule(built):
    page = built["web-checks.html"]
    ids = re.findall(r'<tr id="([^"]+)">', page)
    assert sorted(ids) == sorted(rules.RULE_IDS)
    for rid in ("WEB110", "WEB-strict-transport-security", "WEB990"):
        assert f'<tr id="{rid}"><td><a href="#{rid}"><code>{rid}</code></a></td>' in page
    # "Used by:" under each snippet links back to the rule rows, never doubly wrapped
    assert '<a href="#WEB110"><code>WEB110</code></a>' in page and '<a href="#WEB110"><a' not in page


def test_bilingual_ltr_page_isolates_arabic(built):
    page = built["web-checks.html"]
    assert ' · <bdi lang="ar" dir="rtl">النقل والتوجيه وHSTS</bdi>' in page        # heading
    assert '<td dir="rtl" lang="ar">الموقع يُقدَّم عبر HTTP غير مشفّر</td>' in page  # Arabic column
    assert re.search(r'<p dir="rtl" lang="ar">كل قواعد الفحص السلبي للمواقع', page)
    # the table of contents keeps the English part of "English · العربية" headings
    toc = page.split('class="tochalf"', 1)[1].split("</ol>", 1)[0]
    assert "A. Transport, redirects, HSTS</bdi>" in toc and "النقل" not in toc


def test_options_in_code_do_not_break_after_their_dashes(built):
    page = built["web-scanning.html"]
    assert '<code><span class="nb">--fail-on-inconclusive</span></code>' in page
    assert ".prose .nb{white-space:nowrap}" in page
    # JetBrains Mono's contextual hyphens are drawn off by one cell in right-to-left text: turned off
    assert 'font-feature-settings:"calt" 0}' in page and "font-variant-ligatures:none" not in page   # lam-alef


def test_index_links_the_web_pages_and_states_the_limit():
    i18n_en = INDEX[INDEX.index('"f8.h"'):]
    for key in ("f8.more", "f8.href", "cov3.more", "cov3.href", "cov3.sends", "cov3.sends.href", "lim.5"):
        assert INDEX.count(f'"{key}":') == 2, key                         # English and Arabic
        assert f'data-i18n="{key}"' in INDEX or f"href:{key}" in INDEX, key
    assert 'href="web-checks.html?lang=en"' in INDEX and 'href="web-scanning.html?lang=en"' in INDEX
    assert 'href="scanner.html"' in INDEX and '"cov3.sends.href":"scanner.html#ar"' in INDEX
    assert '"web-scanning.html?lang=ar"' in INDEX and '"web-checks.html?lang=ar"' in INDEX
    assert "configuration hygiene, not the absence of vulnerabilities" in i18n_en
    assert "سلامة الإعدادات لا خلوّ الموقع من الثغرات" in INDEX
    assert "github.com" not in INDEX.split('"f8.more"')[1][:300]


def test_scanner_page_links_the_web_docs():
    assert 'href="web-checks.html"' in SCANNER and 'href="web-scanning.html"' in SCANNER
    assert 'href="web-checks.html?lang=ar"' in SCANNER and 'href="web-scanning.html?lang=ar"' in SCANNER
    assert '<code class="nb">--authorized</code>' in SCANNER and "code.nb{white-space:nowrap}" in SCANNER


def test_sitemap_lists_the_new_pages():
    text = (ROOT / "site" / "sitemap.xml").read_text(encoding="utf-8")
    xml.dom.minidom.parseString(text)
    locs = re.findall(r"<loc>([^<]+)</loc>", text)
    for page in ("web-scanning.html", "web-scanning.html?lang=ar", "web-checks.html", "scanner.html"):
        assert SITE + page in locs, page
    assert len(locs) == len(set(locs))
    for loc in locs:
        assert loc.startswith(SITE) and "github.com" not in loc


def test_docs_name_only_user_visible_tokens_and_no_stale_lookup_claims():
    """``error:proxy`` is an internal response flag (users see ``web.error.code``), and in 1.1 no check makes a
    third-party lookup, so no page may promise one (hstspreload.org, CT search, OCSP requests)."""
    for name, text in (("docs", EN + AR), ("README", README_EN + README_AR), ("CHANGELOG", CHANGELOG)):
        assert "error:proxy" not in text, name
        assert "hstspreload.org" not in text, name
    for p in ("scanner.html", "index.html"):
        assert "error:proxy" not in (ROOT / "site" / p).read_text(encoding="utf-8"), p


def test_deep_platform_paths_are_disclosed():
    """``--deep`` fetches the login/admin pages of a detected platform (tech.json ``deep_paths``): every page that
    describes the deep traffic must say so, the site owner's page included."""
    assert "/wp-login.php" in _section(EN, "What Kashif sends") and "/wp-login.php" in _section(AR, "ما يرسله كاشِف")
    scanner = (ROOT / "site" / "scanner.html").read_text(encoding="utf-8")
    assert scanner.count("/wp-login.php") >= 2
    assert "login and administration pages" in _section(README_EN, "Passive web scanning")
    assert "صفحات الدخول والإدارة" in _section(README_AR, "فحص المواقع السلبي")
