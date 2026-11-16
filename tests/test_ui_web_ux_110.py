"""The web-scan parts of the local UI (vulnscan/ui): URL field, tabs, progress and cancel controls, grade colours,
the findings page's web panel (grade cards and coverage above the list, the rest collapsed below it) and the web
finding detail (evidence instead of a file location). Static checks of index.html / app.js / styles.css, plus the real
app.js functions run under Node.js when it is installed. Offline."""

from __future__ import annotations

import json
import pathlib
import re
import shutil
import subprocess

import pytest

UI = pathlib.Path(__file__).resolve().parents[1] / "vulnscan" / "ui"
JS = (UI / "app.js").read_text(encoding="utf-8")
HTML = (UI / "index.html").read_text(encoding="utf-8")
CSS = (UI / "styles.css").read_text(encoding="utf-8")
NODE = shutil.which("node")


def _keys(lang: str) -> dict[str, str]:
    start = JS.index(f"\n  {lang}: {{")
    end = JS.index("\n  },", start)
    return dict(re.findall(r"'([a-z0-9]+\.[A-Za-z0-9_.]+)': '((?:[^'\\]|\\.)*)'", JS[start:end]))


AR, EN = _keys("ar"), _keys("en")


def _slice(start: str, end: str) -> str:
    return JS[JS.index(start):JS.index(end)]


def _node(body: str, data) -> dict:
    """Run the helpers of app.js plus ``body`` (which writes a JSON result) under Node.js with ``data`` on stdin."""
    stub = ("globalThis.localStorage = {getItem: () => null, setItem: () => {}};\n"
            "globalThis.document = {querySelector: () => ({addEventListener() {}}), querySelectorAll: () => []};\n")
    code = (stub + JS[:JS.index("/* Localized engine text")] + _slice("/* Localized engine text", "/* ------------------------------------------------------- i18n / theme */")
            + "\nconst triageHTML = () => '<section class=\"tri-sec\">TRIAGE</section>';\n"
            + _slice("/* Where a finding is:", "const sideHTML")
            + _slice("const SCHEME = ", "const urlKey")
            + _slice("/* A web finding: no file location", "/* -------------------------------------------------------------- triage */")
            + "\nconst D = JSON.parse(require('fs').readFileSync(0, 'utf8'));\n" + body)
    res = subprocess.run([NODE, "-e", code], input=json.dumps(data), capture_output=True, text=True, encoding="utf-8",
                         timeout=60)
    assert res.returncode == 0, res.stderr
    return json.loads(res.stdout)


# ----------------------------------------------------------------------------------------------- static

def test_scan_tabs_are_aria_tabs_with_short_names_on_phones():
    assert 'id="scan-tabs" role="tablist" aria-label=' in HTML
    for name in ("path", "upload", "url"):
        assert (f'role="tab" id="tab-{name}" aria-controls="pane-{name}"' in HTML
                and f'id="pane-{name}" aria-labelledby="tab-{name}"' in HTML), name
    assert HTML.count('class="tl-short"') == 3 and AR["scan.tabUrlShort"] == "ويب" and EN["scan.tabUrlShort"] == "Web"
    assert "@media (max-width:479px)" in CSS and "#scan-tabs .tl-long{display:none}" in CSS
    # keyboard: arrows (reversed in right-to-left text), Home and End, roving tabindex
    tabs = _slice("function setupTabs(", "const selectScanTab")
    for needle in ("ArrowRight: rtl ? -1 : 1", "ArrowLeft: rtl ? 1 : -1", "'Home'", "'End'", "x.tabIndex = on ? 0 : -1",
                   "getAttribute('aria-controls')", "list.setAttribute('aria-label'"):
        assert needle in tabs, needle
    assert "aria-label=\"${esc(label)}\"" in JS and 'aria-labelledby="${id(\'t\', i)}"' in JS     # panel tabs too


def test_url_field_progress_cancel_and_settings_controls():
    assert 'id="url-input"' in HTML and 'aria-describedby="url-msg"' in HTML and 'id="url-msg"' in HTML
    assert '<select id="url-profile" class="input" aria-describedby="url-profile-hint">' in HTML
    assert 'id="url-profile-hint"' in HTML and 'id="url-auth-text"' in HTML
    assert 'id="scan-cancel"' in HTML and 'id="scan-bar" role="progressbar"' in HTML
    assert 'name="web_delay" type="number" min="0.2"' in HTML
    assert "Math.max(0.2, +f.web_delay.value" in JS
    send = _slice("$('#url-btn').onclick", "let pending = [];")
    assert "kind: 'url'" in send and "!listedTarget(p.url)" in send and "crawl.checked && !crawl.disabled" in send
    assert "$('#toast').classList.add('hidden');" in _slice("async function startScan(", "$('#path-btn').onclick")
    assert "setScanBusy(true)" in JS and "b.setAttribute('aria-busy', String(busy))" in JS
    assert "aria-valuenow" in JS and "aria-valuemax" in JS and "/cancel`" in JS


def test_labels_of_the_web_form():
    assert AR["web.mapping"] == "الربط بمعايير الاختبار (WSTG وASVS)"
    assert AR["scan.webMore"] == "خيارات متقدمة" and EN["scan.webMore"] == "Advanced options"
    assert '<summary data-i18n="scan.webMore">' in HTML
    assert AR["scan.crawl"].startswith("الزحف على صفحات الموقع وفحص كل منها")
    assert "scan.deep" not in AR and "scan.deep" not in EN               # the 1.0 checkbox is gone
    # the brand is written «كاشِف» (with its kasra) in every UI string
    assert "brand: 'كاشِف'" in JS and "كاشف" not in JS and "كاشف" not in HTML
    assert "الشيفرة" not in JS and "الشيفرة" not in HTML
    for k in ("scan.authorizeHost", "scan.hStandard", "scan.badScheme", "web.baseline", "web.evidence", "web.detected"):
        assert k in AR and k in EN and not re.search("[؀-ۿ]", EN[k]), k
    assert "{host}" in AR["scan.authorizeHost"] and "{host}" in EN["scan.authorizeHost"]


def test_grade_colours_for_light_and_dark():
    for cls in ("a", "b", "c", "d", "f", "none"):
        assert f".g-grade-{cls}{{--g:var(--g-{cls})}}" in CSS, cls
    assert ':root[data-theme="dark"]{--g-b:' in CSS and ':root:not([data-theme="light"]){--g-b:' in CSS


# ----------------------------------------------------------------------------------------------- under Node

@pytest.mark.skipif(NODE is None, reason="Node.js is not installed")
def test_parse_target_adds_https_and_refuses_other_schemes():
    cases = ["example.org", "Example.ORG:8443/a?b=1", "http://127.0.0.1:8080", "HTTPS://example.org", "localhost:3000",
             "ftp://example.org", "javascript:alert(1)", "mailto:a@b.c", "file:///etc/passwd", "http://", "exa mple.org",
             "  ", "data:text/html,x"]
    got = _node("process.stdout.write(JSON.stringify(D.map(parseTarget)));", cases)
    res = dict(zip(cases, got))
    assert res["example.org"] == {"url": "https://example.org/", "host": "example.org"}
    assert res["Example.ORG:8443/a?b=1"] == {"url": "https://example.org:8443/a?b=1", "host": "example.org:8443"}
    assert res["http://127.0.0.1:8080"]["url"] == "http://127.0.0.1:8080/"
    assert res["HTTPS://example.org"]["url"] == "https://example.org/"
    assert res["localhost:3000"]["url"] == "https://localhost:3000/"        # a port, not a scheme
    for bad in ("ftp://example.org", "javascript:alert(1)", "mailto:a@b.c", "file:///etc/passwd", "data:text/html,x"):
        assert res[bad] == {"error": "scan.badScheme"}, bad
    assert res["http://"] == {"error": "scan.badUrl"} and res["exa mple.org"] == {"error": "scan.badUrl"}
    assert res["  "] == {"empty": True}


@pytest.mark.skipif(NODE is None, reason="Node.js is not installed")
def test_grade_classes_and_meanings():
    got = _node("lang = 'ar'; const r = D.map((g) => [gradeClass(g), gradeMeaning(g)]); lang = 'en';"
                "process.stdout.write(JSON.stringify([r, D.map(gradeMeaning)]));",
                ["A+", "B", "C-", "D", "E", "F*", "T", "M", "?", "", None, "—"])
    ar, en = got
    assert [c for c, _ in ar] == ["g-grade-a", "g-grade-b", "g-grade-c", "g-grade-d", "g-grade-d", "g-grade-f",
                                  "g-grade-f", "g-grade-f", "g-grade-none", "g-grade-none", "g-grade-none", "g-grade-none"]
    assert ar[0][1] == "جيدة" and ar[5][1] == "راسبة" and en[0] == "Good" and en[-1] == "Not graded"


VIEW = {
    "facts": {"profile": "standard", "requests": 9, "core_requests": 7, "budget": 45, "sensitivity": "default",
              "final_url": "https://example.org/", "data_date": "2026-11-12"},
    "grades": [{"key": "kashif", "name": "درجة كاشِف للويب", "grade": "B+", "score": 81.5, "caps": [], "notes": []},
               {"key": "observatory", "name": "Observatory", "grade": "F", "score": 0, "max": 165}],
    "coverage": {"counts": {"pass": 3, "fail": 1}, "states": {"pass": "ناجح"},
                 "problems": [["WEB070", "لم يُجرَ", "الهدف عبر HTTP فقط", "شهادة TLS"]],
                 "groups": [{"state": "not_tested", "state_label": "لم يُجرَ", "reason": "الهدف عبر HTTP فقط",
                             "checks": [{"id": "WEB-strict-transport-security", "title": "ترويسة HSTS مفقودة"}]}]},
    "diff": {"comparable": True, "notes": [], "new": [], "resolved": [{"rule": "WEB040", "severity": "medium", "title": "x"}],
             "unchanged": 4, "not_retested": 1,
             "not_retested_rows": [{"rule": "WEB062", "severity": "high", "title": "مجلد ‎.git‎ مكشوف", "reason": "deep فقط"}],
             "posture": [], "grades": []},
    "compare": {"asked": True, "previous": True},
    "inventory": [{"id": "headers", "label": "ترويسات الأمان", "head": ["a"], "rows": [["b"]]}],
    "remediation": [{"id": "S-CSP", "title": "سياسة CSP", "summary": "s",
                     "detected": [{"platform": "any", "name": "كل المنصات", "code": ""},
                                  {"platform": "nginx", "name": "nginx", "lang": "nginx", "code": "add_header X 1;"}],
                     "other": [{"platform": "apache", "name": "Apache", "code": "Header set X 1"}]}],
}


@pytest.mark.skipif(NODE is None, reason="Node.js is not installed")
def test_panel_top_holds_grades_and_coverage_only_and_the_rest_is_collapsed():
    got = _node("lang = 'ar'; const top = webPanelTop(D); const more = webPanelMore(D);"
                "const base = webPanelMore({...D, diff: null, compare: {asked: true, previous: false}});"
                "process.stdout.write(JSON.stringify({top, more, base}));", VIEW)
    top, more = got["top"], got["more"]
    assert "grade-card" in top and "cov-chips" in top and "wtabs" not in top and "web-details" not in top
    assert "7 من 45 طلبًا" in top and "<bdi dir=\"ltr\">standard</bdi>" in top     # one requests fact, with the profile
    assert 'class="grade-card g-kashif g-grade-b"' in top and 'g-grade-f' in top
    # below the list: every section is a collapsed <details>
    assert re.findall(r'<details class="web-details" id="(web-[a-z]+)"', more) == ["web-cov", "web-diff", "web-inv", "web-fixes"]
    assert '<details class="web-details" id="web-diff">' in more and " open" not in more.split("web-fixes")[0]
    assert '<details class="snip" id="snip-S-CSP">' in more
    # coverage: grouped rows, IDs in nowrap left-to-right code
    assert '<tr class="grp">' in more and '<td class="cid"><code dir="ltr">WEB-strict-transport-security</code></td>' in more
    # not re-checked findings are listed apart, not as resolved
    assert "لم يُعَد فحصها" in more and "WEB062" in more
    # no previous scan: the comparison says this one becomes the baseline
    assert "سيكون هذا الفحص أساس المقارنة" in got["base"]
    # the fix tabs open on the first detected platform that has code, and detected platforms are marked
    tabs = re.findall(r'<button class="tab( active)?" type="button" role="tab" id="wt-rem0-(\d)" aria-controls="wp-rem0-\d" '
                      r'aria-selected="(true|false)" tabindex="(0|-1)"', more)
    assert tabs == [("", "0", "false", "-1"), (" active", "1", "true", "0"), ("", "2", "false", "-1")]
    assert more.count('<span class="tag det">مكتشفة</span>') == 2
    assert 'role="tablist" aria-label="منصّات الإصلاح S-CSP"' in more and 'aria-label="جداول جرد الموقع"' in more


FINDING = {
    "rule_id": "WEB-strict-transport-security", "severity": "medium", "title": "Missing HSTS",
    "title_ar": "ترويسة HSTS مفقودة", "file": "example.org", "line": 0, "snippet": "HTTP", "advice": "أرسل HSTS.",
    "cwe": "CWE-319", "source": "web", "fingerprint": "abc",
    "extra": {"url": "https://example.org/login?next=/", "page_count": 3, "pages": ["https://example.org/", "a", "b"],
              "confidence": "certain", "wstg": ["WSTG-CONF-07"], "asvs4": ["14.4.5"], "remediation": ["S-CSP"],
              "evidence": {"status": 200, "request": {"method": "GET", "url": "https://example.org/login"},
                           "chain": [{"url": "http://example.org/", "status": 301, "location": "https://example.org/"}],
                           "headers": [["Server", "nginx"], ["Content-Security-Policy", "default-src 'self'"]],
                           "match": {"where": "header", "name": "content-security-policy", "excerpt": "<b>x</b>"},
                           "curl": "curl -sS https://example.org/"}},
}


@pytest.mark.skipif(NODE is None, reason="Node.js is not installed")
def test_web_finding_detail_shows_evidence_not_a_file_location():
    got = _node("lang = 'ar'; webView = D.view; const d = webFindingHTML(D.f, 0); const m = locMeta(D.f);"
                "process.stdout.write(JSON.stringify({d, m}));", {"view": VIEW, "f": FINDING})
    d, m = got["d"], got["m"]
    assert t_absent(d, ("الموقع</h2>", "المقتطف</h2>", "مطابقة نمط"))
    i_page, i_ev, i_curl, i_fix, i_tri = (d.index(x) for x in ("الصفحة</h2>", "الدليل</h2>", "أمر يعيد الطلب نفسه",
                                                                "إصلاح جاهز للنسخ", "TRIAGE"))
    assert i_page < i_ev < i_curl < i_fix < i_tri                       # all before the triage form
    assert '<tr class="hit"><th scope="row"><mark>Content-Security-Policy</mark></th>' in d
    assert '<details class="ev-headers" open>' in d
    assert '<pre class="ev-excerpt" tabindex="0" dir="ltr"><code>&lt;b&gt;x&lt;/b&gt;</code></pre>' in d
    assert '<ol class="ev-chain" dir="ltr"><li><code>301</code>' in d
    assert "add_header X 1;" in d and 'data-snip="S-CSP"' in d          # the detected platform's fix, inline
    assert ">WSTG-CONF-07<" in d and "WSTG WSTG-" not in d and ">ASVS 4 14.4.5<" in d
    assert m == ('<span class="loc" dir="ltr" title="https://example.org/login?next=/">/login?next=/</span>'
                 '<span class="sep">·</span><span class="pages">ظهرت في 3 صفحات</span>')


def t_absent(html: str, needles) -> bool:
    return not any(n in html for n in needles)


def test_fix_chip_is_hidden_for_web_scans_and_covered_notes_are_not_repeated():
    load = _slice("async function loadFindings(", "function renderFindings()")
    assert "$('#fix-filter').classList.toggle('hidden', cur.kind === 'url')" in load
    assert "covered.has(i) ? ''" in load and "notes_covered" in load
    assert "hasFix(f) && f.source !== 'web'" in JS
    assert 'id="findings-web-more"' in HTML and HTML.index('id="findings-list"') < HTML.index('id="findings-web-more"')


def test_copy_buttons_announce_and_relabel():
    clicks = _slice("document.addEventListener('click', async (e) => {", "/* ---------------------------------------------------------------- scan */")
    assert "cp.setAttribute('aria-label', t('find.copied'))" in clicks and "toast(t('find.copied'))" in clicks
    assert 'id="toast" class="toast hidden" role="status" aria-live="polite"' in HTML


def test_failed_scan_title_keeps_the_raw_error_apart():
    fail = _slice("function failureHTML(s)", "function progressHTML(")
    assert "bidi(why)" in fail and '<bdi dir="ltr">${esc(raw)}</bdi>' in fail
    assert "setHTML($('#scan-status-title'), failureHTML(s))" in JS
