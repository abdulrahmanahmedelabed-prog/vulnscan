"""WP9: retire.js port (libs.py), WEB054 and WEB803; plus the C-LIB corpus cases for both rules (offline)."""

from __future__ import annotations

import hashlib
import importlib
import pathlib
import sys
import time

import pytest

from vulnscan.webscan import data, htmlparse, libs
from vulnscan.webscan.coverage import Coverage
from vulnscan.webscan.rules import validate_issue
from vulnscan.webscan.types import HeaderList, Page, Response

ROOT = pathlib.Path(__file__).resolve().parents[2]
LIBS_DIR = ROOT / "tests" / "data" / "web" / "libs"

# retire.js node/spec/repository.json (Apache-2.0), the repository retire's own unit tests run against
SPEC_REPO = {
    "jquery": {
        "vulnerabilities": [
            {"atOrAbove": "1.6.0-rc.1", "below": "1.6.0-rc.1.1", "info": ["http://some.url"]},
            {"below": "1.5.0", "info": ["http://some.url"]},
            {"atOrAbove": "1.8.0", "below": "1.9.0", "info": ["http://some.url"], "cwe": ["CWE-79"],
             "identifiers": {"CVE": ["CVE-2021-1234"], "githubID": "GHSA-1234"}},
        ],
        "extractors": {
            "uri": ["/([0-9.]+([a-z\\-0-9.]+)?)/jquery(\\.min)?\\.js"],
            "filename": ["jquery-([0-9.]+(-rc[0-9.a-zA-Z\\-]+?)?)(.min)?\\.js"],
            "filecontent": ["/*! jQuery v([0-9.]+(-rc[0-9.]+)?)"],
            "hashes": {"abcdelfkjsalkdj": "1.9.10"},
        },
    }
}


def spec_repo(extra_vulns=None, replace_vulns=None) -> libs.Repository:
    import copy
    raw = copy.deepcopy(SPEC_REPO)
    if replace_vulns is not None:
        raw["jquery"]["vulnerabilities"] = replace_vulns
    if extra_vulns:
        raw["jquery"]["vulnerabilities"].extend(extra_vulns)
    return libs.build_repository(raw)


def vulnerable(detections, repo) -> bool:
    return any(libs.check(d, repo) for d in detections)


# ----------------------------------------------------------------------------------------------- isAtOrAbove (retire's versions.spec.ts)

@pytest.mark.parametrize("uri, vulns, expected", [
    # should_not_be_vulnerable_release_when_beta_is
    ("https://ajax.googleapis.com/ajax/libs/jquery/10.0.0/jquery.min.js", [{"below": "10.0.0.beta.2"}], False),
    # should_be_vulnerable_release_when_all_starting_at_version_is
    ("https://ajax.googleapis.com/ajax/libs/jquery/10.0.0.beta.2/jquery.min.js",
     [{"atOrAbove": "10.0.0-*", "below": "10.0.1"}], True),
    ("https://ajax.googleapis.com/ajax/libs/jquery/10.0.0.beta.3/jquery.min.js", [{"below": "10.0.0.beta.2"}], False),
    ("https://ajax.googleapis.com/ajax/libs/jquery/1.9.0rc1/jquery.min.js", [{"below": "1.9.0b1"}], False),
    ("https://ajax.googleapis.com/ajax/libs/jquery/10.0.0.beta.2/jquery.min.js", [{"below": "10.0.0.beta.2"}], False),
    ("https://ajax.googleapis.com/ajax/libs/jquery/10.0.0.beta.1/jquery.min.js", [{"below": "10.0.0.beta.2"}], True),
    ("https://ajax.googleapis.com/ajax/libs/jquery/10.0.0.beta.1/jquery.min.js", [{"below": "10.0.0"}], True),
    ("https://ajax.googleapis.com/ajax/libs/jquery/10.0.0.rc.1/jquery.min.js", [{"below": "10.0.0"}], True),
    ("https://ajax.googleapis.com/ajax/libs/jquery/10.0.0.rc.1/jquery.min.js", [{"below": "10.0.0.beta.2"}], False),
    ("https://ajax.googleapis.com/ajax/libs/jquery/1.12.4-aem/jquery.min.js",
     [{"atOrAbove": "1.0.0", "below": "3.0.0", "excludes": ["1.12.4-aem"]}], False),
    ("https://ajax.googleapis.com/ajax/libs/jquery/1.12.4/jquery.min.js",
     [{"atOrAbove": "1.0.0", "below": "3.0.0", "excludes": ["1.12.4-aem"]}], True),
])
def test_versions_spec(uri, vulns, expected):
    repo = spec_repo(replace_vulns=vulns)
    assert vulnerable(libs.scan_uri(uri, repo), repo) is expected


def test_min_is_at_or_above_non_min_below():
    # should_see_min_as_at_or_above_non_min_below (filename form; the spec repo's uri needs a /x.y.z/ directory)
    repo = libs.build_repository({"jquery": {"vulnerabilities": [{"below": "3.5.0"}],
                                             "extractors": {"uri": ["/jquery-([0-9][0-9.a-z_\\-]+)\\.js"]}}})
    d = libs.scan_uri("https://ajax.googleapis.com/lib/jquery-3.5.0.min.js", repo)
    assert [x.version for x in d] == ["3.5.0"] and not vulnerable(d, repo)


@pytest.mark.parametrize("a, b, expected", [
    ("1.0.0", "1.0.0-beta", True), ("1.0.0-beta", "1.0.0", False), ("1.2", "1.2.0", True), ("1.2.0", "1.2", True),
    ("1.10.0", "1.9.9", True), ("1.9.9", "1.10.0", False), ("2.0.0-rc.1", "2.0.0-beta.2", True), ("0.9", "1", False),
])
def test_is_at_or_above(a, b, expected):
    assert libs.is_at_or_above(a, b) is expected


# ----------------------------------------------------------------------------------------------- extractors (retire's *scan.spec.ts)

@pytest.mark.parametrize("uri, expected", [
    ("https://ajax.googleapis.com/ajax/libs/jquery/1.8.1/jquery.min.js", True),
    ("https://ajax.googleapis.com/ajax/libs/jquery/1.6.1/jquery.min.js", False),
    ("https://ajax.googleapis.com/ajax/libs/jquery/1.9.0/jquery.min.js", False),
    ("https://ajax.googleapis.com/ajax/libs/jquery/1.9.1/jquery.min.js", False),
    ("https://ajax.googleapis.com/ajax/libs/jquery/1.4/jquery.min.js", True),
])
def test_uri_scan(uri, expected):
    repo = spec_repo()
    assert vulnerable(libs.scan_uri(uri, repo), repo) is expected


@pytest.mark.parametrize("name, expected", [
    ("jquery-1.8.1.js", True), ("jquery-1.6.1.js", False), ("jquery-1.9.0.js", False), ("jquery-1.9.1.js", False),
    ("jquery-1.4.js", True), ("jquery-1.6.0.js", False), ("jquery-1.6.0-rc.1.js", True), ("jquery-1.6.0-rc.1.1.js", False),
    ("/usr/file/jquery-1.8.1.js", True), ("\\usr\\file\\jquery-1.8.1.js", True),
])
def test_filename_scan(name, expected):
    repo = spec_repo()
    assert vulnerable(libs.scan_filename(name, repo), repo) is expected


@pytest.mark.parametrize("content, expected", [
    ("/*! jQuery v1.8.1 asdasd ", True), ("/*! jQuery v1.6.1 asdasd ", False), ("/*! jQuery v1.9.0 asdasd ", False),
    ("/*! jQuery v1.9.1 asdasd ", False), ("/*! jQuery v1.4 asdasd ", True), ("var a = 1; /*! jQuery v1.4 asdasd ", True),
])
def test_content_scan(content, expected):
    repo = spec_repo()
    assert vulnerable(libs.scan_content(content, repo), repo) is expected


@pytest.mark.parametrize("version, expected", [("1.8.1", True), ("1.6.1", False), ("1.9.0", False), ("1.9.1", False),
                                               ("1.4", True)])
def test_hash_scan(version, expected):
    body = b"data"
    repo = libs.build_repository({"jquery": {**SPEC_REPO["jquery"], "extractors": {
        "hashes": {hashlib.sha1(body).hexdigest(): version}}}})
    d = libs.scan_hash(body, repo)
    assert d and d[0].method == "hash" and d[0].version == version
    assert vulnerable(d, repo) is expected


def test_hash_ignores_line_endings():
    body = b"line one\nline two\n"
    repo = libs.build_repository({"x": {"vulnerabilities": [], "extractors": {"hashes": {
        hashlib.sha1(body).hexdigest(): "1.0.0"}}}})
    assert libs.scan_hash(body.replace(b"\n", b"\r\n"), repo)


@pytest.mark.parametrize("uri", [
    "https://example.com/assets/svelte-890f984e77ad.js", "https://example.com/7951fbedcefd/jquery.min.js",
    "https://example.com/npm/vue@7951fbedcefd",
])
def test_content_hashes_in_urls_are_not_versions(uri):
    repo = libs.load_repository()
    assert libs.scan_uri(uri, repo) == [] and libs.scan_filename(uri, repo) == []


@pytest.mark.parametrize("uri, component, version", [
    ("https://cdn.jsdelivr.net/npm/vue@2.6.10", "vue", "2.6.10"),
    ("https://cdnjs.cloudflare.com/ajax/libs/vue/2.6.10/vue.min.js", "vue", "2.6.10"),
    ("https://ajax.googleapis.com/ajax/libs/jquery/1.12.4/jquery.min.js", "jquery", "1.12.4"),
])
def test_real_versions_still_detected(uri, component, version):
    repo = libs.load_repository()
    got = {(d.component, d.version) for d in libs.scan_uri(uri, repo)}
    assert (component, version) in got


# ----------------------------------------------------------------------------------------------- JS → Python regex port

def test_variable_lookbehind_becomes_a_post_check():
    rx, checks = libs.compile_js_regex('="(§§version§§)(?<=[0-9]{1,2}\\.[0-9]{1,2}\\.[0-9]{1,2})"[\\s\\S]{1,30}__lodash_x')
    assert rx is not None and len(checks) == 1
    ex = libs._Extractor(rx, checks)
    assert [v for v, _t, _o in libs._matches(ex, 'a="4.17.15";b=1;__lodash_x')] == ["4.17.15"]
    assert [v for v, _t, _o in libs._matches(ex, 'a="4.17.15.1beta";__lodash_x')] == []


def test_bundled_repository_compiles_completely():
    repo = libs.load_repository()
    assert repo is not None and repo.skipped_patterns == 0
    assert len(repo.libraries) >= 70 and "retire-example" not in repo.libraries
    assert repo.dont_check, "the 'dont check' URI list is honoured"


def test_prefilters_never_change_results():
    """The literal/token prefilter and the windowed search must give exactly what a full regex scan gives."""
    repo = libs.load_repository()
    texts = [(LIBS_DIR / "jquery-deparam-0.5.3.js").read_text(encoding="utf-8"),
             "/*! jQuery v1.12.4 | (c) jQuery Foundation */" + "x" * 5000 + "/*! jQuery v3.1.0 */",
             "/**\n * @license\n * Lodash <https://lodash.com/>\n */\n" + "var a=1;" * 900 + "var VERSION = '4.17.15';",
             "/*\n AngularJS v1.8.2\n (c) 2010-2020 Google LLC. http://angularjs.org\n License: MIT\n*/\n" + "q" * 9000]
    for text in texts:
        fast = [(d.component, d.version) for d in libs.scan_content(text, repo)]
        saved = {}
        for lib in repo.libraries.values():
            for ex in lib.filecontent + lib.filecontentreplace:
                saved[id(ex)] = (ex.literal, ex.need, ex.bound)
                ex.literal, ex.need, ex.bound = "", "", None
        try:
            slow = [(d.component, d.version) for d in libs.scan_content(text, repo)]
        finally:
            for lib in repo.libraries.values():
                for ex in lib.filecontent + lib.filecontentreplace:
                    ex.literal, ex.need, ex.bound = saved[id(ex)]
        assert fast == slow


@pytest.mark.parametrize("literal, need", [
    (" jQuery v", "\njQuery\n"), ("xios v", "xios\n"), ("* Chart", "\nChart"), ("Prototype", "Prototype"), ("v1", ""),
])
def test_token_requirement(literal, need):
    assert libs.token_requirement(literal) == need


def test_required_literal_is_conservative():
    assert libs.required_literal("ab+cd") in ("ab", "")
    assert libs.required_literal("foo|barbaz") == ""
    assert libs.required_literal(r"/\*! jQuery v([0-9]+)") == "/*! jQuery v"     # escaped: a literal "*"
    assert libs.required_literal(r"/*! jQuery v([0-9]+)") == "! jQuery v"       # unescaped: "/" repeated 0+ times
    assert libs.required_literal("(?i)Hello World") == ""


def test_speed_one_megabyte(tmp_path):
    repo = libs.load_repository()
    filler = "".join(f"function f{i}(a,b){{return a*b+{i}}};var v{i}=f{i}(1,2);" for i in range(20000))[:1_000_000]
    libs.scan_content(filler[:5000], repo)        # warm-up
    t = time.perf_counter()
    libs.scan_content(filler, repo)
    elapsed = time.perf_counter() - t
    assert elapsed < 0.5, f"retire matching took {elapsed:.3f}s for 1 MB (target ≤ 50 ms on CI-class hardware)"


# ----------------------------------------------------------------------------------------------- run(): WEB054 / WEB803

def _script_resp(url: str, body: bytes | str, **kw) -> Response:
    if isinstance(body, str):
        body = body.encode("utf-8")
    return Response(url=url, status=200, headers=HeaderList.of(("Content-Type", "text/javascript")), body=body,
                    kind="script", source="subresource", **kw)


def _ctx(make_ctx, make_page, html: str, scripts: dict | None = None, **kw):
    page = make_page(html, url="https://shop.example.test/")
    subs = [_script_resp(u, b) for u, b in (scripts or {}).items()]
    return make_ctx(target="https://shop.example.test/", entry=page, subresources=subs, coverage=Coverage(), **kw)


def _rules(issues):
    return sorted({i.rule for i in issues})


def test_web054_and_web803_from_url(make_ctx, make_page):
    ctx = _ctx(make_ctx, make_page, '<script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>')
    issues = libs.run(ctx)
    assert _rules(issues) == ["WEB054", "WEB803"]
    v = next(i for i in issues if i.rule == "WEB054")
    assert v.confidence == "firm" and v.params["library"] == "jQuery" and v.params["version"] == "1.12.4"
    assert v.params["fixed"] == "3.5.0" and "CVE-2020-11022" in v.params["cves"]
    assert v.severity == "medium" and v.url == "https://shop.example.test/"
    assert all(not validate_issue(i) for i in issues)
    eol = next(i for i in issues if i.rule == "WEB803")
    assert eol.params["branch"] in ("1", "1.x")
    assert ctx.coverage.state("WEB054").state == "fail"
    assert ctx.inventory["libraries"][0]["component"] == "jquery"


def test_content_detection_on_renamed_bundle(make_ctx, make_page):
    js = "/*! jQuery v2.2.4 | (c) jQuery Foundation | jquery.org/license */\n!function(a){}(window);\n"
    ctx = _ctx(make_ctx, make_page, '<script src="/static/app.vendor.js"></script>',
               {"https://shop.example.test/static/app.vendor.js": js})
    issues = libs.run(ctx)
    v = next(i for i in issues if i.rule == "WEB054")
    assert v.params["detection"] == "filecontent" and v.params["version"] == "2.2.4"
    assert v.evidence.request["url"].endswith("/static/app.vendor.js")


def test_hash_detection_is_certain(make_ctx, make_page):
    body = (LIBS_DIR / "jquery-deparam-0.5.3.js").read_bytes()
    ctx = _ctx(make_ctx, make_page, '<script src="/static/vendor.js"></script>',
               {"https://shop.example.test/static/vendor.js": body})
    issues = libs.run(ctx)
    assert [i.rule for i in issues] == ["WEB054"]
    assert issues[0].confidence == "certain" and issues[0].params["detection"] == "hash"
    assert issues[0].severity == "high" and issues[0].params["version"] == "0.5.3"


def test_hash_skipped_for_truncated_body(make_ctx, make_page):
    body = (LIBS_DIR / "jquery-deparam-0.5.3.js").read_bytes()
    page = make_page('<script src="/static/vendor.js"></script>', url="https://shop.example.test/")
    sub = _script_resp("https://shop.example.test/static/vendor.js", body, truncated=True)
    ctx = make_ctx(target="https://shop.example.test/", entry=page, subresources=[sub])
    assert libs.run(ctx) == []


def test_inline_script_banner(make_ctx, make_page):
    html = "<script>/*! jQuery v1.8.1 | (c) jQuery Foundation */ window.x=1;</script>"
    issues = libs.run(_ctx(make_ctx, make_page, html))
    assert "WEB054" in _rules(issues)


def test_prose_is_not_a_library(make_ctx, make_page):
    html = ("<h1>jQuery 1.4 tutorial</h1><p>In this tutorial we download jquery-1.4.2.min.js and compare it with "
            "jQuery 3.7.</p><pre>/*! jQuery v1.4.2 */</pre>")
    assert libs.run(_ctx(make_ctx, make_page, html)) == []


def test_current_version_is_clean(make_ctx, make_page):
    js = "/*! jQuery v3.7.1 | (c) OpenJS Foundation and other contributors | jquery.org/license */\n"
    ctx = _ctx(make_ctx, make_page, '<script src="/static/jquery-3.7.1.min.js"></script>',
               {"https://shop.example.test/static/jquery-3.7.1.min.js": js})
    assert libs.run(ctx) == []
    assert ctx.coverage.state("WEB054").state == "pass" and ctx.coverage.state("WEB803").state == "pass"
    assert ctx.inventory["libraries"][0]["version"] == "3.7.1"


def test_script_that_is_not_served_is_not_reported(make_ctx, make_page):
    page = make_page('<script src="/js/jquery-1.12.4.min.js"></script>', url="https://shop.example.test/")
    missing = Response(url="https://shop.example.test/js/jquery-1.12.4.min.js", status=404,
                       headers=HeaderList.of(("Content-Type", "text/html")), body=b"<html>not found</html>",
                       kind="error_page", source="subresource")
    ctx = make_ctx(target="https://shop.example.test/", entry=page, subresources=[missing])
    assert libs.run(ctx) == []


def test_one_finding_per_library_version_per_site(make_ctx, make_page):
    p1 = make_page('<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/1.12.4/jquery.min.js"></script>',
                   url="https://shop.example.test/")
    p2 = make_page('<script src="/js/jquery-1.12.4.min.js"></script>', url="https://shop.example.test/about")
    ctx = make_ctx(target="https://shop.example.test/", entry=p1, pages=[p2])
    assert [i.rule for i in libs.run(ctx)].count("WEB054") == 1


def test_dont_check_urls_are_skipped(make_ctx, make_page):
    ctx = _ctx(make_ctx, make_page, '<script src="https://www.google-analytics.com/ga.js"></script>')
    assert libs.run(ctx) == []


def test_template_and_noscript_scripts_are_not_loaded(make_ctx, make_page):
    html = '<template><script src="https://code.jquery.com/jquery-1.12.4.min.js"></script></template>'
    assert libs.run(_ctx(make_ctx, make_page, html)) == []


def test_eol_from_snapshot_and_builtin(fixed_now):
    eol = data.load_json("eol.json")
    assert libs.eol_status("angularjs", "1.8.2", fixed_now.date(), eol, [])[0] == "1.8"
    assert libs.eol_status("bootstrap", "3.3.7", fixed_now.date(), eol, [])[0] == "3"
    assert libs.eol_status("jquery", "3.7.1", fixed_now.date(), eol, []) is None
    assert libs.eol_status("vue", "2.7.16", fixed_now.date(), None, [])[1] == "2023-12-31"   # built-in fallback
    assert libs.eol_status("bootstrap", "5.3.3", fixed_now.date(), None, []) is None


def test_missing_data_is_not_tested(make_ctx, make_page):
    class NoData:
        @staticmethod
        def load_json(name):
            raise FileNotFoundError(name)
    ctx = _ctx(make_ctx, make_page, '<script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>', data=NoData)
    assert libs.run(ctx) == []
    st = ctx.coverage.state("WEB054")
    assert st.state == "not_tested" and st.reasons[0][0] == "data_missing"


def test_no_document_is_not_tested(make_ctx):
    ctx = make_ctx(target="https://shop.example.test/", coverage=Coverage())
    assert libs.run(ctx) == []
    assert ctx.coverage.state("WEB803").state == "not_tested"


def test_notes_are_bilingual_and_catalogued():
    catalog, patterns = libs.i18n_catalog()
    assert patterns and all(isinstance(k, str) for k in catalog)
    for en, ar in libs.STR.values():
        assert en and ar and en != ar or "retire.js" in en


# ----------------------------------------------------------------------------------------------- C-LIB corpus cases

BENCH = ROOT / "bench" / "web"


def _corpus():
    if str(BENCH) not in sys.path:
        sys.path.insert(0, str(BENCH))
    return importlib.import_module("corpus")


def corpus_context(c, make_ctx):
    """A ScanContext for a static corpus case, as the engine would build it (entry page + same-site scripts)."""
    corpus = _corpus()
    host = f"https://{c.host}"

    def to_response(path: str, r) -> Response:
        body = r.body.encode("utf-8") if isinstance(r.body, str) else r.body
        body = body.replace(b"{NONCE}", b"n0nce").replace(b"{RAND}", b"0123456789abcdef")
        ess = next((v for k, v in r.headers if k.lower() == "content-type"), "")
        kind = "document" if "html" in ess else ("script" if "javascript" in ess else "other")
        return Response(url=host + path, status=r.status, headers=HeaderList.of(*r.headers), body=body, kind=kind,
                        source="entry" if path == c.path else "subresource")

    entry = to_response(c.path, c.routes[c.path])
    page = Page(entry, htmlparse.parse_response(entry), 0)
    routes = dict(c.routes)
    if "fixture:retire-hash" in c.requires:          # the file WP16's server serves for this case
        fixture = sorted(LIBS_DIR.glob("*.js"))[0]
        routes["/static/vendor.js"] = corpus.R(200, [("Content-Type", "text/javascript")], fixture.read_bytes())
    subs = []
    for el in page.doc.find_all("script"):
        src = el.get("src")
        if src and src.startswith("/") and src in routes:
            subs.append(to_response(src, routes[src]))
    return make_ctx(target=host + "/", entry=page, subresources=subs, sensitivity=c.sensitivity, coverage=Coverage())


def lib_cases(rules: set[str]):
    corpus = _corpus()
    return [c for c in corpus.CASES if c.group == "C-LIB" and rules.intersection(c.labels)]


@pytest.mark.parametrize("case_id", [c.id for c in lib_cases({"WEB054", "WEB803"})])
def test_corpus_c_lib(case_id, make_ctx):
    c = next(x for x in _corpus().CASES if x.id == case_id)
    ctx = corpus_context(c, make_ctx)
    issues = [i for i in libs.run(ctx) if ctx.options.reports(i.confidence)]
    fired = {i.rule for i in issues}
    for rule, must in c.labels.items():
        if rule not in ("WEB054", "WEB803"):
            continue
        assert (rule in fired) is must, (case_id, rule, must, [(i.rule, i.params) for i in issues])
