"""DOM analysis of served JavaScript (spec §2.6 WEB520–WEB522, WP12). Offline: synthetic responses only."""

from __future__ import annotations

import importlib
import os
import pathlib
import sys
import tempfile

import pytest

from vulnscan.webscan import domxss, htmlparse
from vulnscan.webscan.coverage import Coverage
from vulnscan.webscan.rules import RULES, validate_issue
from vulnscan.webscan.types import HeaderList, Page, Response, ScanContext, ScanOptions

DATA = pathlib.Path(__file__).parent / "data" / "dom"
ROOT = pathlib.Path(__file__).resolve().parents[2]
SITE = "https://app.example.test"
HEAD = '<!doctype html>\n<html><head><title>t</title></head>\n<body>\n<div id="out"></div>\n'


def fixture(name: str) -> str:
    return (DATA / name).read_text(encoding="utf-8")


def marker_line(text: str) -> int:
    for i, ln in enumerate(text.split("\n"), 1):
        if "/*sink*/" in ln:
            return i
    raise AssertionError("fixture without /*sink*/ marker")


def html_page(html: str, url: str = SITE + "/", kind: str = "document", **fields) -> Page:
    r = Response(url=url, headers=HeaderList.of(("Content-Type", "text/html; charset=utf-8")), body=html.encode("utf-8"),
                 kind=kind, **fields)
    return Page(r, htmlparse.parse_response(r))


def script(code: str | bytes, url: str, ctype: str = "text/javascript", **fields) -> Response:
    body = code.encode("utf-8") if isinstance(code, str) else code
    fields.setdefault("kind", "script")
    return Response(url=url, headers=HeaderList.of(("Content-Type", ctype)), body=body, source="subresource", **fields)


def scan(pages: list[Page], subresources: list[Response] = (), sensitivity: str = "paranoid", **fields):
    cov = Coverage()
    ctx = ScanContext(options=ScanOptions(sensitivity=sensitivity), target=SITE + "/",
                      entry=pages[0].response if pages else None, pages=list(pages), subresources=list(subresources),
                      coverage=cov, **fields)
    issues = domxss.run(ctx)
    for i in issues:
        assert validate_issue(i) == [], validate_issue(i)
    return issues, cov, ctx


def scan_files(*names: str, sensitivity: str = "paranoid"):
    tags = "".join(f'<script src="/static/{n}"></script>\n' for n in names)
    page = html_page(HEAD + tags + "</body></html>\n")
    subs = [script(fixture(n), f"{SITE}/static/{n}") for n in names]
    return scan([page], subs, sensitivity=sensitivity)


# ----------------------------------------------------------------------------------------------- fixtures, one by one

CASES = [
    # file, expected rules, confidence of the main rule
    ("innerhtml_hash.js", {"WEB520"}, "firm"),
    ("document_write_search.js", {"WEB520"}, "firm"),
    ("eval_hash.js", {"WEB520"}, "firm"),
    ("settimeout_string.js", {"WEB520"}, "firm"),
    ("jquery_html.js", {"WEB520"}, "firm"),
    ("insert_adjacent.js", {"WEB520"}, "firm"),
    ("innerhtml_append.js", {"WEB520"}, "firm"),
    ("storage_source.js", {"WEB520"}, "tentative"),
    ("location_param.js", {"WEB521"}, "firm"),
    ("location_assign.js", {"WEB521"}, "firm"),
    ("window_open.js", {"WEB521"}, "firm"),
    ("message_no_origin.js", {"WEB522"}, "tentative"),
    ("location_const.js", set(), None),
    ("location_local_var.js", set(), None),
    ("textcontent.js", set(), None),
    ("sanitised.js", set(), None),
    ("pushstate.js", set(), None),
    ("server_code.js", set(), None),
    ("message_origin.js", set(), None),
    ("message_worker.js", set(), None),
    ("message_delegate.js", set(), None),
    ("message_class.js", set(), None),
]


@pytest.mark.parametrize("name,rules,conf", CASES, ids=[c[0] for c in CASES])
def test_fixture(name, rules, conf):
    issues, cov, _ctx = scan_files(name)
    assert {i.rule for i in issues} == rules
    if rules:
        main = [i for i in issues if i.rule in rules]
        assert {i.confidence for i in main} == {conf}
        text = fixture(name)
        assert main[0].params["line"] == marker_line(text)
        assert main[0].params["file"] == f"{SITE}/static/{name}"
        assert main[0].evidence.match["name"] == f"{SITE}/static/{name}"
        for r in rules:
            assert cov.state(r).state == "fail"
    for r in {"WEB520", "WEB521", "WEB522"} - rules:
        assert cov.state(r).state == "pass"


def test_message_data_into_eval_is_firm():
    issues, _cov, _ctx = scan_files("message_sink.js")
    by_rule = {i.rule: i for i in issues}
    assert by_rule["WEB522"].confidence == "firm"
    assert by_rule["WEB522"].params["line"] == marker_line(fixture("message_sink.js"))
    assert by_rule["WEB522"].params["sink"] == "eval"
    assert any("eval" in en for en, _ar in by_rule["WEB522"].notes)


def test_message_data_into_location_is_firm():
    issues, _cov, _ctx = scan_files("message_location.js")
    w522 = [i for i in issues if i.rule == "WEB522"]
    assert len(w522) == 1 and w522[0].confidence == "firm" and w522[0].params["sink"] == "location"
    assert w522[0].params["line"] == marker_line(fixture("message_location.js"))


def test_cross_file_flow_is_tentative_and_names_both_files():
    issues, _cov, _ctx = scan_files("cross_lib.js", "cross_page.js")
    assert [(i.rule, i.confidence) for i in issues] == [("WEB520", "tentative")]
    i = issues[0]
    assert i.params["file"].endswith("/cross_page.js") and i.params["line"] == 2
    assert i.params["sink"] == "innerHTML"
    joined = " ".join(en for en, _ar in i.notes)
    assert "cross_lib.js" in joined and "cross_page.js" in joined


def test_flow_between_pages_that_do_not_share_scripts_is_dropped():
    a = html_page(HEAD + '<script>function render(h){ document.getElementById("out").innerHTML = h; }</script>',
                  url=SITE + "/a")
    b = html_page(HEAD + "<script>render(location.hash);</script>", url=SITE + "/b")
    issues, _cov, _ctx = scan([a, b])
    assert issues == []


def test_inline_scripts_map_to_page_lines_and_offsets():
    html = HEAD + "<p>x</p>\n<script>\nvar a = 1;\n</script>\n<script>\nvar h = location.hash;\n" \
                  "document.getElementById('out').innerHTML = h;\n</script>\n</body></html>\n"
    page = html_page(html)
    issues, _cov, _ctx = scan([page])
    assert [i.rule for i in issues] == ["WEB520"]
    i = issues[0]
    lines = html.split("\n")
    want = next(n for n, ln in enumerate(lines, 1) if ".innerHTML" in ln)
    assert i.params["line"] == want and i.params["inline"] is True and i.params["file"] == SITE + "/"
    off = i.evidence.match["offset"]
    assert page.response.text()[off:].startswith("document.getElementById('out').innerHTML")
    assert i.url == SITE + "/"


def test_inline_script_on_the_same_line_as_the_tag_keeps_its_column():
    html = HEAD + '<script>document.getElementById("out").innerHTML = location.hash;</script>\n'
    issues, _cov, _ctx = scan([html_page(html)])
    assert len(issues) == 1
    col = html.split("\n")[issues[0].params["line"] - 1].index("document")
    assert issues[0].params["column"] == col + 1


def test_identical_inline_scripts_are_analysed_once_and_reported_per_page(monkeypatch):
    code = "<script>\ndocument.getElementById('out').innerHTML = location.hash;\n</script>\n"
    p1 = html_page(HEAD + code, url=SITE + "/one")
    p2 = html_page(HEAD + "<p>extra</p>\n<p>lines</p>\n" + code, url=SITE + "/two")
    seen = []
    from vulnscan import taint
    real = taint.analyze_project_full

    def spy(files, *a, **kw):
        seen.append(sorted(files))
        return real(files, *a, **kw)

    monkeypatch.setattr(taint, "analyze_project_full", spy)
    issues, _cov, _ctx = scan([p1, p2])
    assert len(seen) == 1 and len(seen[0]) == 1          # one unit for both pages
    assert sorted((i.url, i.params["line"]) for i in issues) == [(SITE + "/one", 6), (SITE + "/two", 8)]
    assert len({i.group_value for i in issues}) == 1      # grouped across pages by group.py


def test_minified_file_is_reflowed_and_maps_line_and_column():
    text = fixture("minified_flow.js")
    assert len(text.split("\n")[0]) > domxss.LONG_LINE
    issues, _cov, _ctx = scan_files("minified_flow.js")
    assert [i.rule for i in issues] == ["WEB520"]
    i = issues[0]
    assert i.params["line"] == 1
    col = text.index('document.getElementById("o").innerHTML')
    assert i.params["column"] == col + 1
    assert i.evidence.match["offset"] == col
    assert any("minified" in en for en, _ar in i.notes)


def test_reflow_only_inserts_newlines_outside_literals():
    src = ('var s="a;b{c}";var r=/;{}/g,t=`x;${a?{b:1}:2};y`;/* ; { */var d=1/2;// ; {\n'
           "if(a){b()}else{c()};" + "x=1;" * 300)
    new, line_map = domxss.reflow(src)
    assert line_map is not None
    assert new.replace("\n", "") == src.replace("\n", "")
    assert '"a;b{c}"' in new and "/;{}/g" in new and "/* ; { */" in new
    assert "`x;${" in new and "};y`" in new             # template text untouched (code inside ${ } may be split)
    assert "// ; {\n" in new
    orig = src.split("\n")
    for k, ln in enumerate(new.split("\n")):
        line, col = line_map[k]
        assert orig[line - 1][col:col + len(ln)] == ln
    assert domxss.reflow("short;\ncode;")[1] is None


def test_library_files_are_skipped_without_lowering_coverage():
    issues, cov, ctx = scan_files("jquery_like.js")
    assert issues == []
    skipped = ctx.inventory["dom_scripts"]["skipped"]
    assert skipped and skipped[0]["reason"] == "library"
    assert cov.state("WEB520").state == "not_applicable"


@pytest.mark.parametrize("url,text,known", [
    (SITE + "/static/jquery-3.7.1.min.js", "var x;", ()),
    (SITE + "/static/react-dom.production.min.js", "var x;", ()),
    (SITE + "/static/lodash.js", "var x;", ()),
    (SITE + "/vendor/anything.js", "var x;", ()),
    (SITE + "/static/x.js", "/*! Vue.js v2.6.14\n * (c) 2014-2021 Evan You */\nvar x;", ()),
    (SITE + "/static/y.js", "/*! mylib v1.2.3 | MIT License */\n(function(g,f){typeof exports==='object'&&typeof module"
                            "!=='undefined'?module.exports=f():g.m=f()})(this,function(){});", ()),
    (SITE + "/static/app.4f3a.js", "var x;", (SITE + "/static/app.4f3a.js",)),
])
def test_library_detection(url, text, known):
    assert domxss.library_name(url, text, domxss.library_names(), known)


@pytest.mark.parametrize("url,text", [
    (SITE + "/static/app.js", "var x;"),
    (SITE + "/static/react-app.js", "var x;"),
    (SITE + "/static/main.min.js", "/*! For license information please see main.min.js.LICENSE.txt */\nvar x;"),
    (SITE + "/static/site.js", "/*! site build 2.1 */\nvar x;"),
])
def test_site_code_is_not_a_library(url, text):
    assert domxss.library_name(url, text, domxss.library_names()) is None


def test_libs_inventory_marks_a_renamed_library():
    page = html_page(HEAD + '<script src="/static/a.js"></script>')
    sub = script(fixture("innerhtml_hash.js"), SITE + "/static/a.js")
    inv = {"libraries": [{"name": "jQuery", "component": "jquery", "version": "1.12.4", "detection": "hash",
                          "url": SITE + "/static/a.js"}]}
    issues, _cov, _ctx = scan([page], [sub], inventory=inv)
    assert issues == []


def test_big_bundle_is_skipped_and_noted():
    flow = 'document.getElementById("out").innerHTML=location.hash;'
    big = (flow + "".join(f"function f{i}(a){{return a+{i}}};" for i in range(80000)))[:2_100_000]
    page = html_page(HEAD + '<script src="/static/bundle.min.js"></script>')
    issues, cov, ctx = scan([page], [script(big, SITE + "/static/bundle.min.js")])
    assert issues == []
    st = cov.state("WEB520")
    assert st.state == "not_tested" and st.reasons[0][0] == "truncated"
    assert "bundle.min.js" in st.reasons[0][1] and "bundle.min.js" in st.reasons[0][2]
    assert ctx.inventory["dom_scripts"]["skipped"][0]["reason"] == "truncated"


def test_engine_size_limit_is_noted(monkeypatch):
    monkeypatch.setattr(domxss, "ENGINE_MAX_CHARS", 100)
    issues, cov, _ctx = scan_files("innerhtml_hash.js")
    assert issues == []
    assert cov.state("WEB520").state == "not_tested"


@pytest.mark.parametrize("fields,reason", [({"truncated": True}, "truncated"), ({"encoding": "br"}, "unsupported_coding")])
def test_truncated_or_opaque_bodies_are_not_analysed(fields, reason):
    page = html_page(HEAD + '<script src="/static/a.js"></script>')
    issues, cov, _ctx = scan([page], [script(fixture("innerhtml_hash.js"), SITE + "/static/a.js", **fields)])
    assert issues == []
    assert cov.state("WEB520").state == "not_tested" and cov.state("WEB520").reasons[0][0] == reason


def test_third_party_scripts_are_not_analysed():
    page = html_page(HEAD + '<script src="https://cdn.other.test/a.js"></script>')
    issues, cov, _ctx = scan([page], [script(fixture("innerhtml_hash.js"), "https://cdn.other.test/a.js")])
    assert issues == []
    assert cov.state("WEB520").state == "not_applicable"


def test_same_site_subdomain_script_is_analysed():
    page = html_page(HEAD + '<script src="https://static.example.test/a.js"></script>')
    issues, _cov, _ctx = scan([page], [script(fixture("innerhtml_hash.js"), "https://static.example.test/a.js")])
    assert [i.rule for i in issues] == ["WEB520"]


def test_at_most_15_files():
    names = [f"f{i:02d}.js" for i in range(17)]
    page = html_page(HEAD + "".join(f'<script src="/s/{n}"></script>' for n in names))
    subs = [script("var a%d = 1;" % i, f"{SITE}/s/{n}") for i, n in enumerate(names)]
    _issues, cov, ctx = scan([page], subs)
    assert len(ctx.inventory["dom_scripts"]["analysed"]) == domxss.MAX_FILES
    assert [s["reason"] for s in ctx.inventory["dom_scripts"]["skipped"]] == ["budget", "budget"]
    assert cov.state("WEB520").state == "not_tested"


def test_non_javascript_and_non_live_scripts_are_ignored():
    html = (HEAD + '<script type="text/template">document.body.innerHTML = location.hash;</script>\n'
            "<template><script>document.body.innerHTML = location.hash;</script></template>\n"
            "<noscript><script>document.body.innerHTML = location.hash;</script></noscript>\n"
            '<script type="application/ld+json">{"a": 1}</script>\n'
            '<script type="text/x-template" src="/static/t.js"></script>\n')
    t = script(fixture("innerhtml_hash.js"), SITE + "/static/t.js")
    issues, cov, _ctx = scan([html_page(html)], [t])
    assert issues == []
    assert cov.state("WEB520").state == "not_applicable"


def test_module_script_is_analysed():
    html = HEAD + '<script type="module">\ndocument.getElementById("out").innerHTML = location.hash;\n</script>\n'
    issues, _cov, _ctx = scan([html_page(html)])
    assert [i.rule for i in issues] == ["WEB520"]


def test_only_documents_are_analysed():
    code = "<script>document.body.innerHTML = location.hash;</script>"
    soft = html_page(HEAD + code, url=SITE + "/missing", kind="soft404")
    err = html_page(HEAD + code, url=SITE + "/err", kind="error_page", status=500)
    issues, cov, _ctx = scan([soft, err])
    assert issues == []
    assert cov.state("WEB520").state == "not_tested"     # no document at all


def test_waf_entry_makes_the_checks_inconclusive():
    page = html_page(HEAD + "<script>document.body.innerHTML = location.hash;</script>", kind="waf_challenge")
    issues, cov, _ctx = scan([page])
    assert issues == []
    assert {cov.state(c).state for c in domxss.CHECKS} == {"inconclusive"}


def test_tentative_finding_at_default_sensitivity_is_not_shown_as_passed():
    _issues, cov, _ctx = scan_files("message_no_origin.js", sensitivity="default")
    st = cov.state("WEB522")
    assert st.state == "not_tested" and st.reasons[0][0] == "sensitivity"
    _issues, cov, _ctx = scan_files("message_no_origin.js", sensitivity="paranoid")
    assert cov.state("WEB522").state == "fail"


def test_temp_dir_is_removed_and_nothing_is_written_elsewhere(monkeypatch, tmp_path):
    made = []
    real = tempfile.mkdtemp

    def mk(*a, **kw):
        kw.setdefault("dir", str(tmp_path))
        d = real(*a, **kw)
        made.append(d)
        return d

    monkeypatch.setattr(tempfile, "mkdtemp", mk)
    monkeypatch.chdir(tmp_path)
    issues, _cov, _ctx = scan_files("innerhtml_hash.js", "cross_lib.js")
    assert issues
    assert len(made) == 1 and not os.path.exists(made[0])
    assert list(tmp_path.iterdir()) == []


def test_engine_crash_is_contained_and_cleans_up(monkeypatch, tmp_path):
    made = []
    real = tempfile.mkdtemp
    monkeypatch.setattr(tempfile, "mkdtemp", lambda *a, **kw: made.append(real(dir=str(tmp_path))) or made[-1])
    from vulnscan import taint

    def boom(*_a, **_kw):
        raise RuntimeError("engine bug")

    monkeypatch.setattr(taint, "analyze_project_full", boom)
    issues, cov, _ctx = scan_files("innerhtml_hash.js")
    assert issues == []
    st = cov.state("WEB520")
    assert st.state == "not_tested" and st.reasons[0][0] == "error" and "engine bug" in st.reasons[0][1]
    assert made and not os.path.exists(made[0])


def test_files_are_written_under_inline_and_src(monkeypatch):
    seen = {}
    from vulnscan import taint
    real = taint.analyze_project_full

    def spy(files, *a, **kw):
        seen.update(files)
        return real(files, *a, **kw)

    monkeypatch.setattr(taint, "analyze_project_full", spy)
    page = html_page(HEAD + '<script>var a = 1;</script><script src="/static/x/../app.min.js"></script>')
    scan([page], [script("var b = 2;", SITE + "/static/app.min.js")])
    assert sorted(seen) == ["inline/index-0.js", "src/app.example.test/static/app.min.js.js"]


def test_hostile_script_url_cannot_escape_the_temp_dir():
    rel = domxss._rel_for_url("https://evil.test/%2e%2e/%2e%2e/..%5c..%5cetc/passwd", set())
    assert rel.startswith("src/") and ".." not in rel.split("/") and "\\" not in rel


def test_hostile_code_does_not_crash():
    deep = "x=" + "[" * 5000 + "]" * 5000 + ";"
    weird = "\x00\x1b[31m<!-- ﻿`${`${`" + "/" * 50 + "'\"\\"
    page = html_page(HEAD + f"<script>{deep}</script><script>{weird}</script>")
    issues, cov, _ctx = scan([page])
    assert issues == []
    assert cov.state("WEB520").state in ("pass", "not_tested")


def test_notes_strip_control_characters_from_urls():
    page = html_page(HEAD + "<script>\ndocument.body.innerHTML = location.hash;\n</script>",
                     url=SITE + "/a\x1b[31mred")
    issues, _cov, _ctx = scan([page])
    assert issues
    for en, ar in issues[0].notes:
        assert "\x1b" not in en and "\x1b" not in ar


@pytest.mark.parametrize("label,dom", [
    ("req.hash", True), ("req.search", True), ("req.referrer", True), ("req.name", True), ("document.URL", True),
    ("location.pathname", True), ("window.location.search", True), ("URLSearchParams.get()", True),
    ("localStorage.getItem()", True), ("$route.query", True), ("req.query", False), ("req.body", False),
    ("process.env", False), ("ctx.query", False), ("prompt()", False), ("req.headers", False), ("", False),
])
def test_dom_sources(label, dom):
    assert domxss.is_dom_source(label) is dom


def test_registry_and_i18n():
    assert domxss.CHECKS == ("WEB520", "WEB521", "WEB522")
    for r in domxss.CHECKS:
        assert RULES[r].module == "domxss"
    catalog, patterns = domxss.i18n_catalog()
    import re
    for key, (en, ar) in domxss.STR.items():
        values = {n: "X1" for n in re.findall(r"\{([a-z_]+)\}", en)}
        filled_en, filled_ar = domxss._note(key, **values)
        if filled_ar in catalog:
            assert catalog[filled_ar] == filled_en
            continue
        for rx, repl in patterns:
            m = re.match(rx, filled_ar)
            if m:
                assert m.expand(repl) == filled_en
                break
        else:
            raise AssertionError(f"no i18n entry for {key}")


# ----------------------------------------------------------------------------------------------- corpus (§5.2 C-DOM)

def _corpus():
    sys.path.insert(0, str(ROOT / "bench" / "web"))
    try:
        return importlib.import_module("corpus")
    finally:
        sys.path.pop(0)


def _render(c, value) -> tuple[int, list, bytes] | None:
    corpus = _corpus()
    if value is None:
        return None
    if callable(value):
        try:
            value = value(None)
        except Exception:  # noqa: BLE001 - handlers that need the live server are out of scope here
            return None
    body = value.body
    if isinstance(body, str):
        body = (body.replace("{NONCE}", "bm9uY2Utbm9uY2Utbm9uY2U=").replace("{RAND}", "0" * 32)
                .replace("{CASE}", c.id))
        body = corpus._TOKEN.sub(lambda m: f"https://{c.host}", body).encode("utf-8")
    return value.status, value.headers, body


def _case_context(c, sensitivity=None):
    base = f"https://{c.host}"
    rendered = _render(c, c.routes.get(c.path) or c.routes.get("/"))
    if rendered is None:
        return None
    status, headers, body = rendered
    r = Response(url=base + c.path, status=status, headers=HeaderList.of(*headers), body=body, kind="document")
    page = Page(r, htmlparse.parse_response(r))
    subs = []
    for el in page.doc.find_all("script"):
        src = el.get("src")
        if not src:
            continue
        url = page.doc.resolve(src)
        path = url[len(base):] if url.startswith(base) else None
        if path is None or path not in c.routes:
            continue
        sub = _render(c, c.routes[path])
        if sub is not None:
            subs.append(Response(url=url, status=sub[0], headers=HeaderList.of(*sub[1]), body=sub[2], kind="script",
                                 source="subresource"))
    cov = Coverage()
    ctx = ScanContext(options=ScanOptions(profile=c.profile, sensitivity=sensitivity or c.sensitivity), target=base + "/",
                      entry=r, pages=[page], subresources=subs, coverage=cov)
    return ctx, cov


def _c_dom_cases():
    return [c for c in _corpus().CASES if c.group == "C-DOM"]


@pytest.mark.parametrize("case_id", [c.id for c in _c_dom_cases()])
def test_corpus_c_dom(case_id):
    c = next(x for x in _c_dom_cases() if x.id == case_id)
    ctx, _cov = _case_context(c)
    issues = domxss.run(ctx)
    shown = {i.rule for i in issues if ctx.options.reports(i.confidence)}
    for rule, must in c.labels.items():
        assert (rule in shown) is must, (case_id, rule, must, [(i.rule, i.confidence) for i in issues])


def test_corpus_noise_outside_c_dom():
    """Inline scripts elsewhere in the corpus (constant redirects, analytics, miners, keys) raise no DOM finding."""
    corpus = _corpus()
    checked = 0
    for c in corpus.CASES:
        if c.group == "C-DOM" or any(r.startswith("WEB52") for r in c.labels):
            continue
        made = _case_context(c, sensitivity="paranoid")
        if made is None:
            continue
        ctx, _cov = made
        if not ctx.pages[0].doc.inline_scripts and not ctx.subresources:
            continue
        issues = domxss.run(ctx)
        assert issues == [], (c.id, [(i.rule, i.notes[0][0]) for i in issues])
        checked += 1
    assert checked >= 20
