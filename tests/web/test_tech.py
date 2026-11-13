"""WP9: murmur3/favicons, technology detection, platform EOL, server CVEs and EOL, obsolete plugins (tech.py, mmh3.py),
the WP9 data files, and the C-LIB corpus cases for WEB080/081/800/801 (offline)."""

from __future__ import annotations

import base64
import hashlib
import importlib
import json
import pathlib
import sys
import time

import pytest

from vulnscan.webscan import data, htmlparse, mmh3, tech
from vulnscan.webscan.coverage import Coverage
from vulnscan.webscan.rules import RULES, validate_issue
from vulnscan.webscan.types import HeaderList, Page, Response

ROOT = pathlib.Path(__file__).resolve().parents[2]
FAVICONS = ROOT / "tests" / "data" / "web" / "favicons"
SITE = "https://site.example.test/"

# ----------------------------------------------------------------------------------------------- murmur3

@pytest.mark.parametrize("data_, seed, expected, signed", [
    (b"foo", 0, -156908512, True),                       # mmh3 package README
    (b"", 0, 0, True),
    (b"", 1, 0x514E28B7, False),
    (b"", 0xFFFFFFFF, 0x81F16F39, False),
    (b"Hello, world!", 0x9747B28C, 0x24884CBA, False),
    (b"The quick brown fox jumps over the lazy dog", 0x9747B28C, 0x2FA826CD, False),
    ("foo", 0, -156908512, True),                        # str is UTF-8 encoded like the reference package
])
def test_mmh3_reference_vectors(data_, seed, expected, signed):
    assert mmh3.hash32(data_, seed, signed=signed) == expected


# expected values computed once with the reference ``mmh3`` package (5.x): mmh3.hash(base64.encodebytes(icon))
ICONS = {
    "kashif-shield-16.ico": (-592208701, "74bb828894653b73"),
    "kashif-ring-32.png": (-1236153713, "337098c3adf639ba"),
    "kashif-mark.svg": (1136654198, "a06e6d06b5d528e1"),
}


@pytest.mark.parametrize("name", sorted(ICONS))
def test_favicon_hash_shodan_convention(name):
    body = (FAVICONS / name).read_bytes()
    expected, sha_prefix = ICONS[name]
    assert hashlib.sha256(body).hexdigest().startswith(sha_prefix), "fixture changed (line endings?)"
    assert mmh3.favicon_hash(body) == expected
    assert mmh3.favicon_hash(body) == mmh3.hash32(base64.encodebytes(body))


# ----------------------------------------------------------------------------------------------- helpers

class DataStub:
    """The real data module, with some files replaced or removed."""

    def __init__(self, **override):
        self.override = {k.replace("_", "-").replace("-json", ".json"): v for k, v in override.items()}

    def load_json(self, name):
        if name in self.override:
            if self.override[name] is None:
                raise FileNotFoundError(name)
            return self.override[name]
        return data.load_json(name)


def resp(url=SITE, status=200, headers=(), body=b"", kind="document", **kw) -> Response:
    if isinstance(body, str):
        body = body.encode("utf-8")
    return Response(url=url, status=status, headers=HeaderList.of(*headers), body=body, kind=kind, **kw)


def ctx_for(make_ctx, html="<p>hi</p>", headers=(), url=SITE, pages=(), sensitivity="default", **kw):
    r = resp(url, headers=(("Content-Type", "text/html; charset=utf-8"), *headers), body=html)
    page = Page(r, htmlparse.parse_response(r), 0)
    return make_ctx(target=url, entry=page, pages=list(pages), sensitivity=sensitivity, coverage=Coverage(), **kw)


def run(ctx):
    issues = tech.run(ctx)
    for i in issues:
        assert not validate_issue(i), (i.rule, validate_issue(i))
    return issues


def reported(ctx, issues):
    return [i for i in issues if ctx.options.reports(i.confidence)]


def techs(ctx):
    return {t["id"]: t for t in ctx.inventory.get("technologies", [])}


# ----------------------------------------------------------------------------------------------- the seven 1.0.1 platforms

LEGACY = {
    "moodle": ("<p>x</p>", (("Set-Cookie", "MoodleSession=abc; path=/; secure; HttpOnly"),)),
    "oracle-apex": ('<form action="wwv_flow.accept" method="post" name="wwv_flow" id="wwv_flow">'
                    '<input type="hidden" name="p_flow_id" value="100"></form>', ()),
    "wordpress": ('<link rel="stylesheet" href="/wp-content/themes/twentytwenty/style.css">', ()),
    "joomla": ("", ()),
    "drupal": ("", (("X-Generator", "Drupal 10 (https://www.drupal.org)"),)),
    "phpmyadmin": ('<link rel="stylesheet" href="./themes/pmahomme/jquery/jquery-ui.css">', (
        ("Set-Cookie", "phpMyAdmin=abc; path=/phpmyadmin/; secure; HttpOnly"),)),
    "laravel": ("<p>x</p>", (("Set-Cookie", "laravel_session=abc; path=/; secure; httponly; samesite=lax"),)),
}
HEADS = {"joomla": '<meta name="generator" content="Joomla! - Open Source Content Management">'}


@pytest.mark.parametrize("tid", sorted(LEGACY))
def test_all_seven_legacy_platforms_still_detected(tid, make_ctx):
    body, headers = LEGACY[tid]
    html = f"<!doctype html><html><head>{HEADS.get(tid, '')}</head><body>{body}</body></html>"
    ctx = ctx_for(make_ctx, html, headers)
    issues = reported(ctx, run(ctx))
    platforms = [i.params["id"] for i in issues if i.rule == "WEB080"]
    assert tid in platforms, (tid, techs(ctx))


def test_legacy_platforms_keep_deep_paths():
    obj = data.load_json("tech.json")
    by_id = {t["id"]: t for t in obj["technologies"]}
    for tid in ("moodle", "oracle-apex", "wordpress", "joomla", "drupal", "phpmyadmin"):
        assert by_id[tid].get("deep_paths"), tid
    paths = [p["path"] for t in obj["technologies"] for p in t.get("deep_paths", [])]
    assert len(paths) == len(set(paths))
    # moved to exposed-paths.json (WP11): a path lives in exactly one data file
    for p in ("/storage/logs/laravel.log", "/.env", "/telescope", "/wp-config.php.bak"):
        assert p not in paths
    assert "laravel" in by_id


def test_deep_paths_are_disjoint_from_exposed_paths_and_safe():
    paths = {p["path"] for t in data.load_json("tech.json")["technologies"] for p in t.get("deep_paths", [])}
    if data.available("exposed-paths.json"):
        exposed = {p["path"] for p in data.load_json("exposed-paths.json")["paths"]}
        assert not paths & exposed
    never = ("heapdump", "threaddump", "pprof", "/debug/", "install", "setup", "purge")
    assert not [p for p in paths if any(n in p.lower() for n in never)]
    assert len(paths) <= 30, "platform paths share the deep budget (≤ 70 with exposed-paths.json)"


def test_all_detected_platforms_are_reported(make_ctx):
    html = ('<!doctype html><html><head><meta name="generator" content="WordPress 6.6.2">'
            '<link rel="stylesheet" href="/wp-content/themes/x/style.css"></head><body></body></html>')
    ctx = ctx_for(make_ctx, html, (("Set-Cookie", "laravel_session=x; Path=/; Secure; HttpOnly"),))
    names = sorted(i.params["id"] for i in run(ctx) if i.rule == "WEB080")
    assert names == ["laravel", "wordpress"]


@pytest.mark.parametrize("html", [
    "<h1>Guide</h1><p>Our handbook explains the /administrator/ area of popular CMSs and option=com_content.</p>",
    "<h1>WordPress 5.2 tutorial</h1><p>How to migrate from WordPress 5.2 (wp-content, wp-includes) to a static site.</p>",
    "<p>Moodle 3.9 and Drupal 7 and phpMyAdmin 4.8 are covered in this course; see &lt;meta name=generator&gt;.</p>",
    "<pre>&lt;meta name=\"generator\" content=\"WordPress 4.9\"&gt;</pre>",
])
def test_prose_is_not_a_platform(html, make_ctx):
    ctx = ctx_for(make_ctx, f"<!doctype html><html><body>{html}</body></html>", sensitivity="paranoid")
    assert [i for i in run(ctx) if i.rule in ("WEB080", "WEB081")] == []


def test_confidence_threshold_and_paranoid(make_ctx):
    html = '<html><body><link rel="stylesheet" href="/sites/default/files/css/x.css"></body></html>'   # Drupal 40
    ctx = ctx_for(make_ctx, html)
    issues = run(ctx)
    d = [i for i in issues if i.rule == "WEB080"]
    assert d and d[0].confidence == "tentative" and not reported(ctx, d)
    assert techs(ctx)["drupal"]["confidence"] == 40


def test_implies_and_cpe(make_ctx):
    ctx = ctx_for(make_ctx, '<html><head><meta name="generator" content="WordPress 6.8.1"></head></html>')
    run(ctx)
    t = techs(ctx)
    assert t["php"]["implied_by"] == "wordpress"
    assert t["wordpress"]["cpe"] == "cpe:2.3:a:wordpress:wordpress:6.8.1:*:*:*:*:*:*:*"


def test_third_party_responses_do_not_describe_the_site(make_ctx):
    cdn = resp("https://cdnjs.cloudflare.com/ajax/libs/x/1/x.js", headers=(("Server", "cloudflare"), ("CF-RAY", "1")),
               kind="script", source="subresource")
    ctx = ctx_for(make_ctx, "<p>x</p>", subresources=[cdn])
    run(ctx)
    assert "cloudflare" not in techs(ctx)


def test_favicon_detection(make_ctx):
    icon = (FAVICONS / "kashif-shield-16.ico").read_bytes()
    favs = {"meta": data.load_json("favicons.json")["meta"],
            "hashes": [{"hash": mmh3.favicon_hash(icon), "tech": "jenkins", "name": "Jenkins"}]}
    fav = resp(SITE + "favicon.ico", headers=(("Content-Type", "image/x-icon"),), body=icon, kind="image",
               source="wellknown")
    ctx = ctx_for(make_ctx, "<p>x</p>", wellknown={"/favicon.ico": fav}, data=DataStub(favicons_json=favs))
    tech._DB_CACHE.clear()
    run(ctx)
    t = techs(ctx)
    assert t["jenkins"]["confidence"] == 60 and t["jenkins"]["evidence"][0]["source"] == "favicon"
    tech._DB_CACHE.clear()


def test_favicon_that_is_a_catch_all_page_is_ignored(make_ctx):
    page = resp(SITE + "favicon.ico", headers=(("Content-Type", "text/html"),), body="<!doctype html><p>home</p>",
                source="wellknown")
    ctx = ctx_for(make_ctx, "<p>x</p>", wellknown={"/favicon.ico": page})
    assert tech._favicons(ctx) == []


# ----------------------------------------------------------------------------------------------- WEB081

@pytest.mark.parametrize("generator, version, severity, variant", [
    ("Drupal 7 (http://drupal.org)", "7", "medium", None),
    ("Joomla! 3.9 - Open Source Content Management", None, None, None),        # no version in this form
    ("WordPress 4.9", "4.9", "low", "patch"),                                   # 4.9 is supported, 4.9.0 < latest
    ("WordPress 3.9.2", "3.9.2", "medium", None),                               # 3.7–4.0 EOL 2022-12-01
])
def test_web081_from_eol_snapshot(generator, version, severity, variant, make_ctx):
    ctx = ctx_for(make_ctx, f'<html><head><meta name="generator" content="{generator}"></head></html>')
    w = [i for i in run(ctx) if i.rule == "WEB081"]
    if severity is None:
        assert w == []
        return
    assert len(w) == 1 and w[0].severity == severity and w[0].params["version"] == version
    assert w[0].params.get("variant") == variant and w[0].confidence == "firm"
    title = RULES["WEB081"].title("en", **w[0].params)
    assert version in title


def test_web081_current_version_is_clean(make_ctx, fixed_now):
    wp = data.load_json("eol.json")["products"]["wordpress"]["cycles"][0]
    ctx = ctx_for(make_ctx, f'<html><head><meta name="generator" content="WordPress {wp["latest"]}"></head></html>')
    assert [i for i in run(ctx) if i.rule == "WEB081"] == []
    assert ctx.coverage.state("WEB081").state == "pass"


def test_web081_weak_version_is_tentative(make_ctx):
    html = ('<html><head><script src="/wp-includes/js/wp-emoji-release.min.js?ver=3.9.2"></script>'
            '<link rel="stylesheet" href="/wp-content/themes/x/style.css"></head></html>')
    ctx = ctx_for(make_ctx, html)
    w = [i for i in run(ctx) if i.rule == "WEB081"]
    assert w and w[0].confidence == "tentative"


# ----------------------------------------------------------------------------------------------- banners, WEB800/WEB801

def test_parse_banner_tokens_and_distro():
    toks = tech.parse_banner("Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips mod_fcgid/2.3.9 PHP/5.4.16")
    assert [(t[0], t[1]) for t in toks] == [("Apache", "2.4.6"), ("OpenSSL", "1.0.2k-fips"), ("mod_fcgid", "2.3.9"),
                                           ("PHP", "5.4.16")]
    assert tech._distro_of("7.4.3-4ubuntu2.19", []) == "Ubuntu"
    assert tech._distro_of("2.4.41", ["Ubuntu"]) == "Ubuntu"
    assert tech._distro_of("1.0.2k-fips", []) == "a FIPS vendor build"
    assert tech._distro_of("8.2.12", ["Win64"]) == ""
    assert tech._distro_of("2.4.62", ["Unix"]) == ""


@pytest.mark.parametrize("a, b, expected", [
    ("1.0.1e", "1.0.1g", -1), ("1.0.1", "1.0.1e", -1), ("9.0.0.M1", "9.0.0", -1), ("8.1", "8.1.0", 0),
    ("2.4.10", "2.4.9", 1), ("11.0.0-M21", "11.0.0-M3", 1),
])
def test_version_order(a, b, expected):
    assert tech._cmp(a, b) == expected


def _banner_ctx(make_ctx, *headers, sensitivity="default", status=200, body="<p>x</p>"):
    return ctx_for(make_ctx, body, headers, sensitivity=sensitivity)


def test_web800_firm_for_upstream_build(make_ctx):
    ctx = _banner_ctx(make_ctx, ("Server", "Apache/2.4.49"))
    w = [i for i in run(ctx) if i.rule == "WEB800"]
    assert len(w) == 1 and w[0].confidence == "firm"
    assert "CVE-2021-41773" in w[0].params["cves"] and w[0].severity in ("critical", "high")
    assert w[0].params["fixed"].startswith("2.4.")
    assert "may be affected" not in RULES["WEB800"].title("en", **w[0].params)


def test_web800_distro_backport_downgrade(make_ctx):
    ctx = _banner_ctx(make_ctx, ("Server", "Apache/2.4.41 (Ubuntu)"))
    issues = run(ctx)
    w = [i for i in issues if i.rule == "WEB800"]
    assert len(w) == 1 and w[0].confidence == "tentative" and w[0].severity != "critical"
    assert w[0].params["variant"] == "tentative"
    assert "may be affected" in RULES["WEB800"].title("en", **w[0].params)
    assert any("Ubuntu" in en and "Ubuntu" in ar for en, ar in w[0].notes)
    assert not reported(ctx, w)                              # tentative: only at paranoid
    assert [i for i in issues if i.rule == "WEB801"] == []   # the distribution supports its own build


@pytest.mark.parametrize("value", ["PHP/7.4.3-4ubuntu2.19", "PHP/8.2.20-1~deb12u1", "PHP/7.2.24 (Red Hat)"])
def test_web800_distro_suffixes(value, make_ctx):
    ctx = _banner_ctx(make_ctx, ("X-Powered-By", value))
    w = [i for i in run(ctx) if i.rule == "WEB800"]
    assert w and all(i.confidence == "tentative" for i in w)


def test_web800_incomplete_version(make_ctx):
    ctx = _banner_ctx(make_ctx, ("X-Powered-By", "PHP/8.1"), sensitivity="paranoid")
    w = [i for i in run(ctx) if i.rule == "WEB800"]
    assert len(w) == 1 and w[0].confidence == "tentative" and w[0].severity in ("high", "medium", "low")
    assert any("8.1" in en for en, _ar in w[0].notes)


def test_web800_one_per_product_version_per_site(make_ctx):
    p2 = resp(SITE + "a", headers=(("Server", "nginx/1.18.0"),))
    p3 = resp(SITE + "b", headers=(("Server", "nginx/1.18.0"),))
    ctx = ctx_for(make_ctx, "<p>x</p>", (("Server", "nginx/1.18.0"),),
                  pages=[Page(p2, htmlparse.parse_response(p2)), Page(p3, htmlparse.parse_response(p3))])
    issues = run(ctx)
    assert [i.rule for i in issues].count("WEB800") == 1 and [i.rule for i in issues].count("WEB801") == 1


def test_web801_eol_runtimes(make_ctx):
    ctx = _banner_ctx(make_ctx, ("Server", "Microsoft-IIS/7.5"), ("X-Powered-By", "PHP/5.6.40"))
    w = {i.params["product"]: i for i in run(ctx) if i.rule == "WEB801"}
    assert set(w) == {"Microsoft IIS", "PHP"}
    assert w["PHP"].params["branch"] == "5.6" and w["PHP"].params["date"] == "2018-12-31"
    assert w["Microsoft IIS"].params["date"] == "2020-01-14"


def test_web801_centos_banner(make_ctx):
    ctx = _banner_ctx(make_ctx, ("Server", "Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16"))
    w = {i.params["product"]: i for i in run(ctx) if i.rule == "WEB801"}
    assert w["CentOS Linux"].params["version"] == "7" and w["CentOS Linux"].confidence == "firm"
    assert "OpenSSL" not in w          # a FIPS vendor build: the vendor supports it
    assert "PHP" not in w              # a CentOS package (same banner): covered by the CentOS end-of-life finding


def test_web801_supported_versions_are_clean(make_ctx):
    eol = data.load_json("eol.json")["products"]
    php = next(c for c in eol["php"]["cycles"] if c["eol"] is False or c["eol"] > "2027")
    ctx = _banner_ctx(make_ctx, ("Server", f"nginx/{eol['nginx']['cycles'][0]['latest']}"),
                      ("X-Powered-By", f"PHP/{php['latest']}"))
    assert [i for i in run(ctx) if i.rule in ("WEB800", "WEB801")] == []
    assert ctx.coverage.state("WEB800").state == "pass" and ctx.coverage.state("WEB801").state == "pass"


def test_error_page_banners(make_ctx):
    body = ("<!doctype html><html><head><title>HTTP Status 404 – Not Found</title></head><body>"
            "<h1>HTTP Status 404 – Not Found</h1><hr class=\"line\" /><h3>Apache Tomcat/9.0.30</h3></body></html>")
    err = resp(SITE + "missing", status=404, headers=(("Content-Type", "text/html;charset=utf-8"),), body=body,
               kind="error_page", source="wellknown")
    ctx = ctx_for(make_ctx, "<p>x</p>", wellknown={"/robots.txt": err})
    w = [i for i in run(ctx) if i.rule == "WEB800"]
    assert w and w[0].params["product"] == "Apache Tomcat" and "CVE-2020-1938" in w[0].params["cves"]
    assert w[0].evidence.match["where"] == "body"


def test_banner_without_version_is_ignored(make_ctx):
    ctx = _banner_ctx(make_ctx, ("Server", "Apache"), ("X-Powered-By", "PHP"), sensitivity="paranoid")
    assert [i for i in run(ctx) if i.rule in ("WEB800", "WEB801")] == []


def test_cve_ranges_split_at_older_branch_fixes():
    """nginx "0.1.29-1.31.6, good 1.31.7+, 1.30.6+": 1.30.6 is fixed, 1.31.0 is not."""
    cve = next(c for c in data.load_json("server-cve.json")["products"]["nginx"] if c["id"] == "CVE-2026-15176")
    mk = lambda v: tech.Banner("nginx", "nginx", v, v, "", False, "Server", v, resp())   # noqa: E731
    assert tech.cve_matches([cve], mk("1.30.6")) == []
    assert tech.cve_matches([cve], mk("1.31.0")) and tech.cve_matches([cve], mk("1.28.0"))


# ----------------------------------------------------------------------------------------------- WEB802

@pytest.mark.parametrize("html, kind", [
    ('<object type="application/x-shockwave-flash" data="/intro.swf"></object>', "flash"),
    ('<embed src="banner.swf" width="300">', "flash"),
    ('<object classid="clsid:D27CDB6E-AE6D-11cf-96B8-444553540000"><param name="movie" value="a.swf"></object>', "flash"),
    ('<object data="data:application/x-silverlight-2," type="application/x-silverlight-2">'
     '<param name="source" value="ClientBin/App.xap"></object>', "silverlight"),
    ('<applet code="Clock.class" width="100" height="40"></applet>', "applet"),
])
def test_web802_plugins(html, kind, make_ctx):
    ctx = ctx_for(make_ctx, f"<!doctype html><html><body>{html}</body></html>")
    w = [i for i in run(ctx) if i.rule == "WEB802"]
    assert [i.params["technology"] for i in w] == [kind] and w[0].confidence == "certain"


@pytest.mark.parametrize("html", [
    '<object data="/manual.pdf" type="application/pdf"></object>',
    '<template><embed src="old.swf"></template>',
    "<p>We removed our old Flash .swf intro and the Java applet.</p>",
    '<video src="intro.mp4"></video>',
])
def test_web802_traps(html, make_ctx):
    ctx = ctx_for(make_ctx, f"<!doctype html><html><body>{html}</body></html>")
    assert [i for i in run(ctx) if i.rule == "WEB802"] == []


# ----------------------------------------------------------------------------------------------- coverage, data, i18n

def test_no_input_is_not_tested(make_ctx):
    ctx = make_ctx(target=SITE, coverage=Coverage())
    assert tech.run(ctx) == []
    assert all(ctx.coverage.state(c).state == "not_tested" for c in tech.CHECKS)


def test_missing_data_files(make_ctx):
    ctx = ctx_for(make_ctx, "<p>x</p>", (("Server", "nginx/1.18.0"),),
                  data=DataStub(server_cve_json=None, eol_json=None))
    tech.run(ctx)
    assert ctx.coverage.state("WEB800").state == "not_tested"
    assert ctx.coverage.state("WEB801").reasons[0][0] == "data_missing"


@pytest.mark.parametrize("name", ["tech.json", "favicons.json", "eol.json", "server-cve.json",
                                  "retire-jsrepository.json.gz"])
def test_wp9_data_files_validate(name):
    assert data.validate_file(data.BUNDLED_DIR / name) == []
    meta = data.meta(name)
    assert meta["date"] and meta["license"] and meta["source"]


def test_tech_json_patterns_compile_and_are_scoped():
    obj = data.load_json("tech.json")
    for t in obj["technologies"]:
        for s in t["signals"]:
            import re
            re.compile(s["pattern"])
            if s["source"] == "html":
                assert s["pattern"].startswith("<"), (t["id"], s["pattern"])
            if s["source"] in ("header", "meta"):
                assert s.get("name"), (t["id"], s)


def test_favicon_table_size():
    hashes = data.load_json("favicons.json")["hashes"]
    assert len(hashes) >= 500 and len({h["hash"] for h in hashes}) == len(hashes)


def test_notes_are_bilingual_and_catalogued():
    catalog, patterns = tech.i18n_catalog()
    assert catalog and patterns
    for key, (en, ar) in tech.STR.items():
        assert en and ar, key
        assert sorted(set(__import__("re").findall(r"\{(\w+)\}", en))) == \
            sorted(set(__import__("re").findall(r"\{(\w+)\}", ar))), key


def test_refresh_scripts_rebuild_offline(tmp_path):
    """The maintainer scripts turn upstream-format inputs into schema-valid files (tiny synthetic inputs)."""
    sys.path.insert(0, str(ROOT / "tools" / "webdata"))
    try:
        eol = importlib.import_module("eol")
        favicons = importlib.import_module("favicons")
        server_cve = importlib.import_module("server_cve")
        tech_tool = importlib.import_module("tech")
    finally:
        sys.path.pop(0)
    md = ("---\ntitle: PHP\nreleases:\n  - releaseCycle: \"8.4\"\n    eol: 2028-12-31\n    latest: \"8.4.1\"\n"
          "  - releaseCycle: \"5.6\"\n    eol: 2018-12-31 # comment\n    latest: \"5.6.40\"\n---\n")
    prod = eol.parse_product(md)
    assert prod["cycles"][1] == {"cycle": "5.6", "eol": "2018-12-31", "latest": "5.6.40"}
    yaml = ('      - type: dsl\n        name: "jenkins"\n        dsl:\n'
            '          - "status_code==200 && (\\"81586312\\" == mmh3(base64_py(body)))"\n') * 600
    assert favicons.parse(yaml) == [{"hash": 81586312, "tech": "jenkins", "name": "jenkins"}]
    xml = ('<item name="Bug" severity="major" cve="2021-23017" good="1.21.0+, 1.20.1+" vulnerable="0.6.18-1.20.0">'
           '</item>')
    assert server_cve.from_nginx(xml)[0]["ranges"] == [{"at_or_above": "0.6.18", "below": "1.20.1"}]
    m = tech_tool.parse_matchers('matchers:\n      - type: word\n        name: express\n        words:\n'
                                 '          - "X-Powered-By: Express"\n        part: header\n')
    assert tech_tool.nuclei_signals(m[0]) == [{"source": "header", "pattern": "Express", "confidence": 50,
                                               "name": "x-powered-by"}]
    prose = tech_tool.parse_matchers('matchers:\n      - type: word\n        name: x\n        words:\n'
                                     '          - "Project Management Software"\n')
    assert tech_tool.nuclei_signals(prose[0]) == []


# ----------------------------------------------------------------------------------------------- C-LIB corpus cases

BENCH = ROOT / "bench" / "web"
TECH_RULES = {"WEB080", "WEB081", "WEB800", "WEB801", "WEB802"}


def _corpus():
    if str(BENCH) not in sys.path:
        sys.path.insert(0, str(BENCH))
    return importlib.import_module("corpus")


@pytest.mark.parametrize("case_id", [c.id for c in _corpus().CASES if c.group == "C-LIB" and TECH_RULES & set(c.labels)])
def test_corpus_c_lib(case_id, make_ctx):
    c = next(x for x in _corpus().CASES if x.id == case_id)
    r = c.routes[c.path]
    body = (r.body.encode("utf-8") if isinstance(r.body, str) else r.body)
    body = body.replace(b"{NONCE}", b"n0nce").replace(b"{RAND}", b"0123456789abcdef")
    entry = Response(url=f"https://{c.host}{c.path}", status=r.status, headers=HeaderList.of(*r.headers), body=body,
                     kind="document")
    ctx = make_ctx(target=f"https://{c.host}/", entry=Page(entry, htmlparse.parse_response(entry), 0),
                   sensitivity=c.sensitivity, coverage=Coverage())
    issues = reported(ctx, run(ctx))
    fired = {i.rule for i in issues}
    for rule, must in c.labels.items():
        if rule in TECH_RULES:
            assert (rule in fired) is must, (case_id, rule, must, [(i.rule, i.confidence, i.params) for i in issues])
    for rule, n in c.expect.get("min_count", {}).items():
        assert sum(1 for i in issues if i.rule == rule) >= n


def test_json_roundtrip_of_inventory(make_ctx):
    ctx = _banner_ctx(make_ctx, ("Server", "nginx/1.18.0 (Ubuntu)"))
    run(ctx)
    json.dumps(ctx.inventory)


# ----------------------------------------------------------------------------------------------- review: false positives and hostile input

def test_excludes_do_not_crash_and_drop_the_weaker(make_ctx):
    obj = {"meta": data.load_json("tech.json")["meta"], "technologies": [
        {"id": "a-cms", "name": "A", "categories": ["cms"], "excludes": ["b-cms"],
         "signals": [{"source": "cookie", "pattern": "^a_sess$", "confidence": 90}]},
        {"id": "b-cms", "name": "B", "categories": ["cms"], "excludes": ["a-cms"],
         "signals": [{"source": "cookie", "pattern": "^b_sess$", "confidence": 40}]},
    ]}
    db = tech.build_db(obj)
    ctx = ctx_for(make_ctx, "<p>x</p>", (("Set-Cookie", "a_sess=1"), ("Set-Cookie", "b_sess=1")))
    assert sorted(tech.detect(ctx, db)) == ["a-cms"]


@pytest.mark.parametrize("header", [("Server", "nginx/1." + "9" * 5000), ("X-Powered-By", "PHP/8." + "1" * 5000),
                                    ("Server", "Apache/2.4.1 " + "(x) " * 15000), ("Server", "a" * 60000 + "/1.2")])
def test_hostile_banners_do_not_crash_or_hang(header, make_ctx):
    ctx = ctx_for(make_ctx, "<p>x</p>", (header,), sensitivity="paranoid")
    start = time.monotonic()
    run(ctx)
    assert time.monotonic() - start < 2.0


def test_huge_generator_version_is_not_a_version(make_ctx):
    ctx = ctx_for(make_ctx, '<html><head><meta name="generator" content="WordPress 4.' + "9" * 5000 + '"></head></html>')
    issues = run(ctx)
    assert [i.params["version"] for i in issues if i.rule == "WEB080"] == [""]
    assert [i for i in issues if i.rule == "WEB081"] == []


def test_many_banner_tokens_are_bounded(make_ctx):
    value = " ".join(f"PHP/7.{i}.1" for i in range(3000))
    ctx = ctx_for(make_ctx, "<p>x</p>", (("X-Powered-By", value),), sensitivity="paranoid")
    issues = run(ctx)
    assert len({i.params["version"] for i in issues if i.rule == "WEB800"}) <= tech.MAX_VERSIONS_PER_PRODUCT
    assert len(ctx.inventory["server_software"]) <= tech.MAX_VERSIONS_PER_PRODUCT


def test_major_only_banner_lists_no_cves(make_ctx):
    ctx = ctx_for(make_ctx, "<p>x</p>", (("Server", "Apache/2"),), sensitivity="paranoid")
    assert [i for i in run(ctx) if i.rule == "WEB800"] == []


@pytest.mark.parametrize("html", [
    '<form id="login_form" action="/login"><input name="user"></form>',                  # any login page
    '<link rel="stylesheet" href="/themes/bootstrap/css/bootstrap.min.css">',             # any Bootstrap theme
    '<script src="/static/frontend/js/vendor/app.js"></script>',                          # not Magento's layout
])
def test_generic_markup_is_not_a_platform(html, make_ctx):
    ctx = ctx_for(make_ctx, f"<!doctype html><html><head>{html}</head><body></body></html>")
    assert [i.params["id"] for i in reported(ctx, run(ctx)) if i.rule == "WEB080"] == []


def test_third_party_platform_paths_do_not_make_the_site_that_platform(make_ctx):
    html = '<script src="https://widgets.otherblog.example/wp-content/plugins/w/w.js"></script>'
    ctx = ctx_for(make_ctx, html)
    issues = run(ctx)
    assert [i for i in reported(ctx, issues) if i.rule == "WEB080"] == []
    assert techs(ctx)["wordpress"]["confidence"] == 30          # still in the inventory, at half weight
    # the same path on the site itself, or on its own CDN host, is the site's platform
    for src in ("/wp-content/plugins/w/w.js", "https://cdn.site.example.test/wp-content/plugins/w/w.js"):
        ctx = ctx_for(make_ctx, f'<script src="{src}"></script>')
        assert [i.params["id"] for i in reported(ctx, run(ctx)) if i.rule == "WEB080"] == ["wordpress"]


def test_host_specific_platform_signals_keep_full_weight(make_ctx):
    ctx = ctx_for(make_ctx, '<script src="https://cdn.shopify.com/s/files/1/x.js"></script>')
    run(ctx)
    assert techs(ctx)["shopify"]["confidence"] == 70


def test_confine_html():
    assert tech.confine_html(r"<link\b[^>]+rel=[\"']x") == r"<link\b[^<>]+rel=[\"']x"
    assert tech.confine_html(r"<style>[\s\S]*\.a > \.b") == r"<style>[^<]*\.a > \.b"
    assert tech.confine_html(r"<script[^<>]*>[^]{0,128}?src") == r"<script[^<>]*>[^<]{0,128}?src"
    assert tech.confine_html(r"<a .+x\S+") == r"<a [^<\n]+x[^\s<]+"
    assert tech.cap_segments("a<" + "b" * 10 + "<c", cap=4) == "a<bbbb<c"


@pytest.mark.parametrize("body", ["<link a" * 30_000, "<" * 200_000, "<script x" * 25_000, "<a href='?" * 20_000,
                                  "<link" + " href=x" * 30_000, "<style>" * 30_000 + "x"])
def test_hostile_markup_is_linear(body, make_ctx):
    ctx = ctx_for(make_ctx, "<html><body>" + body)
    start = time.monotonic()
    run(ctx)
    assert time.monotonic() - start < 3.0


def test_cve_more_note_agrees_in_arabic(make_ctx):
    from vulnscan.i18n.plural import ar_count
    ctx = _banner_ctx(make_ctx, ("Server", "Apache/2.4.1"))
    w = [i for i in run(ctx) if i.rule == "WEB800"]
    en, ar = next(n for n in w[0].notes if n[0].startswith("…and "))
    count = int(en.split()[1])
    assert count > 10 and ar == "…و" + ar_count(count, tech._MORE_CVES[2]) + "."


def test_php_of_a_distribution_web_server_is_a_distro_build(make_ctx):
    ctx = _banner_ctx(make_ctx, ("Server", "Apache/2.4.62 (Debian)"), ("X-Powered-By", "PHP/7.4.33"),
                      sensitivity="paranoid")
    issues = run(ctx)
    php = [i for i in issues if i.params.get("product") == "PHP"]
    assert all(i.rule == "WEB800" and i.confidence == "tentative" for i in php)
    # the same PHP behind a server that names no distribution stays firm
    ctx = _banner_ctx(make_ctx, ("Server", "Apache/2.4.62 (Unix)"), ("X-Powered-By", "PHP/7.4.33"))
    php = [i for i in run(ctx) if i.params.get("product") == "PHP"]
    assert any(i.rule == "WEB801" and i.confidence == "firm" for i in php)
