"""Kashif 1.1.0 command line for passive web scanning (WP15b, spec §4.5): the web options and their help in both
languages, option checks before any request, the request-budget note, --compare-previous / --compare, the
``update-data --web`` sub-command, and the CLI end to end on 10 corpus cases in Arabic and in English.

Offline: every scanned site is a server on 127.0.0.1 started by the test (the corpus cases resolve through the
test-only resolver hook, exactly as bench/web/run_kashif.py runs them).
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import pathlib
import re
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from vulnscan import cli
from vulnscan.cli import build_parser, main

ROOT = pathlib.Path(__file__).resolve().parents[1]
BENCH = ROOT / "bench" / "web"
PROXY_VARS = ("http_proxy", "https_proxy", "all_proxy", "no_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")
ARABIC = re.compile(r"[؀-ۿ]")
WEB_OPTIONS = ("--web-profile", "--web-sensitivity", "--ignore-robots", "--third-party-lookups", "--compare-previous",
               "--compare", "--web-cookie-ignore", "--no-proxy", "--deep", "--crawl", "--max-pages", "--max-depth",
               "--delay", "--timeout")


@pytest.fixture(autouse=True)
def _offline(monkeypatch, tmp_path):
    for k in PROXY_VARS:
        monkeypatch.delenv(k, raising=False)
    rmap = tmp_path / "resolve.json"
    rmap.write_text(json.dumps({"version": 1, "hosts": {},
                                "default": {"status": "ok", "addresses": ["192.0.2.1"], "public": True}}),
                    encoding="utf-8")
    monkeypatch.setenv("KASHIF_TEST_RESOLVE", "1")
    monkeypatch.setenv("KASHIF_TEST_RESOLVE_MAP", str(rmap))
    monkeypatch.delenv("KASHIF_TEST_CAFILE", raising=False)
    monkeypatch.setenv("KASHIF_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("VULNSCAN_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(cli, "_is_arabic_locale", lambda environ=None: False)
    from vulnscan.webscan import data
    data.clear_cache()
    yield
    data.clear_cache()


class Site(BaseHTTPRequestHandler):
    """A small site with a login form, a session cookie and a CSP; ``Site.csp`` can change between scans."""
    csp = "script-src 'self' 'unsafe-inline'"
    requests: list = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        Site.requests.append((self.command, self.path, dict(self.headers)))
        if self.path != "/":
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = (b"<!doctype html><html><head><meta charset=utf-8><title>Shop</title></head><body>"
                b"<form action=/login method=post><input type=password name=pw></form></body></html>")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", Site.csp)
        self.send_header("Set-Cookie", "sessionid=0123456789abcdef0123456789abcdef; Path=/")
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def site():
    Site.csp = "script-src 'self' 'unsafe-inline'"
    Site.requests = []
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Site)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}/"
    httpd.shutdown()
    httpd.server_close()


def _web(argv, capsys=None):
    code = main(argv)
    out = capsys.readouterr() if capsys is not None else None
    return code, out


# ----------------------------------------------------------------------------------------------- options

def test_every_web_option_exists_with_help_in_both_languages():
    en, ar = build_parser("en"), build_parser("ar")
    opts = {o: a for a in en._actions for o in a.option_strings}
    for opt in WEB_OPTIONS:
        assert opt in opts, opt
        assert opts[opt].help and not ARABIC.search(opts[opt].help), opt
    ar_opts = {o: a for a in ar._actions for o in a.option_strings}
    for opt in WEB_OPTIONS:
        assert ARABIC.search(ar_opts[opt].help), opt
    assert opts["--web-profile"].choices == ("minimal", "standard", "deep")
    assert opts["--web-sensitivity"].choices == ("strict", "default", "paranoid")
    assert opts["--web-sensitivity"].default == "default" and opts["--web-profile"].default is None
    assert not ARABIC.search(en.format_help())
    both = build_parser("both").format_help()
    assert "--web-profile" in both and "ملف الفحص السلبي" in both and "passive scan profile" in both
    # the 1.0 "one request only" wording is gone from the help
    assert "single request" not in en.format_help() and "طلب واحد فقط" not in ar.format_help()


def test_help_tables_have_the_same_keys_and_placeholders():
    t = cli._WEB_HELP
    assert set(t["ar"]) == set(t["en"])
    for k in t["en"]:
        assert sorted(re.findall(r"\{(\w+)\}", t["en"][k])) == sorted(re.findall(r"\{(\w+)\}", t["ar"][k])), k
        assert ARABIC.search(t["ar"][k]) and not ARABIC.search(t["en"][k]), k


@pytest.mark.parametrize("n,profile,ar_req", [(10, "minimal", "10 طلبات"), (45, "standard", "45 طلبًا"),
                                               (150, "deep", "150 طلبًا")])
def test_budget_note_states_the_real_request_budget(n, profile, ar_req):
    ar, en = cli.web_budget_note(profile)
    assert ar_req in ar and f"at most {n} requests" in en and profile in ar and profile in en
    ar, en = cli.web_budget_note(profile, crawl=True, max_pages=1)
    assert "صفحة واحدة" in ar and "1 page crawled" in en
    ar, en = cli.web_budget_note(profile, crawl=True, max_pages=2)
    assert "صفحتين" in ar and "2 pages crawled" in en


@pytest.mark.parametrize("argv,needle", [
    (["--compare-previous"], "--compare-previous"),
    (["--compare", "x.json"], "--compare"),
])
def test_compare_options_need_a_web_target(tmp_path, argv, needle, capsys):
    with pytest.raises(SystemExit) as e:
        main([str(tmp_path), "--no-deps", "--no-external", "--lang", "en"] + argv)
    assert e.value.code == 2
    assert needle in capsys.readouterr().err


def test_conflicting_web_options_are_usage_errors_before_any_request(site, capsys):
    with pytest.raises(SystemExit) as e:
        main([site, "--authorized", "--deep", "--web-profile", "minimal", "--lang", "en"])
    assert e.value.code == 2 and "--web-profile deep" in capsys.readouterr().err
    with pytest.raises(SystemExit) as e:
        main([site, "--authorized", "--compare", "a", "--compare-previous", "--lang", "ar"])
    assert e.value.code == 2 and "--compare-previous" in capsys.readouterr().err
    with pytest.raises(SystemExit) as e:
        main([site, "--authorized", "--web-profile", "huge", "--lang", "en"])
    assert e.value.code == 2
    assert Site.requests == []


def test_without_authorization_nothing_is_sent(site, capsys):
    with pytest.raises(SystemExit) as e:
        main([site, "--web-profile", "deep", "--lang", "en", "--no-proxy"])
    assert e.value.code == 2 and Site.requests == []


def test_missing_or_foreign_compare_file_exits_2_before_scanning(site, tmp_path, capsys):
    code = main([site, "--authorized", "--compare", str(tmp_path / "missing.json"), "--lang", "en", "--no-proxy"])
    assert code == 2 and "not found" in capsys.readouterr().err
    other = tmp_path / "source-report.json"
    other.write_text(json.dumps({"findings": [], "summary": {}}), encoding="utf-8")
    code = main([site, "--authorized", "--compare", str(other), "--lang", "ar", "--no-proxy"])
    assert code == 2 and "web.snapshot" in capsys.readouterr().err
    assert Site.requests == []


# ----------------------------------------------------------------------------------------------- scans

def test_web_scan_passes_every_option_to_the_engine(site, monkeypatch):
    seen = {}
    from vulnscan import web

    real = web.scan_web

    def spy(url, **kw):
        import dataclasses
        seen.update(kw["options"].__dict__)
        kw["options"] = dataclasses.replace(kw["options"], profile="minimal", crawl=False)   # fast: one request
        return real(url, **kw)
    monkeypatch.setattr(web, "scan_web", spy)
    main([site, "--authorized", "--web-profile", "minimal", "--web-sensitivity", "paranoid", "--ignore-robots",
          "--third-party-lookups", "--web-cookie-ignore", "a", "--web-cookie-ignore", "b", "--no-proxy", "--delay",
          "0.3", "--timeout", "7", "--crawl", "--max-pages", "3", "--max-depth", "1", "-f", "json", "-o", os.devnull])
    assert seen["profile"] == "minimal" and seen["sensitivity"] == "paranoid" and seen["respect_robots"] is False
    assert seen["third_party_lookups"] is True and seen["cookie_ignore"] == ("a", "b") and seen["use_proxy"] is False
    assert seen["delay"] == 0.3 and seen["timeout"] == 7 and seen["crawl"] is True and seen["max_pages"] == 3
    assert seen["max_depth"] == 1
    seen.clear()
    main([site, "--authorized", "--deep", "--no-proxy", "-f", "json", "-o", os.devnull])
    assert seen["profile"] == "deep" and seen["sensitivity"] == "default" and seen["respect_robots"] is True


def test_json_report_and_english_output_of_a_web_scan(site, tmp_path, capsys):
    prefix = tmp_path / "r"
    code = main([site, "--authorized", "--no-proxy", "--lang", "en", "--no-color", "--all-formats", str(prefix)])
    out = capsys.readouterr().out
    assert code == 0
    doc = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))
    assert doc["web"]["profile"] == "standard" and doc["web"]["grades"]["kashif"]["grade"]
    assert doc["notes_en"][0] == "Profile standard: at most 45 requests; no active test."
    # "standard: 45" no longer joins into one left-to-right run that shows 45 beside "ملف الفحص" (ux-i18n review)
    assert doc["notes"][0].startswith("ملف الفحص standard: بحدٍّ أقصى 45 طلبًا")
    for text in (out, *(prefix.with_suffix(f".{x}").read_text(encoding="utf-8") for x in ("md", "html", "sarif"))):
        assert not ARABIC.search(text), sorted(set(ARABIC.findall(text)))[:20]
    assert "Kashif Web Grade" in prefix.with_suffix(".html").read_text(encoding="utf-8")
    assert all(m == "GET" for m, _p, _h in Site.requests)


def test_compare_previous_saves_and_diffs(site, tmp_path, capsys):
    base = [site, "--authorized", "--no-proxy", "--web-profile", "minimal", "--compare-previous", "-f", "json",
            "--lang", "en"]
    assert main(base + ["-o", str(tmp_path / "1.json")]) == 0
    first = json.loads((tmp_path / "1.json").read_text(encoding="utf-8"))
    assert first["web"]["diff"] is None
    assert any("No earlier saved scan" in n for n in first["notes_en"])
    err = capsys.readouterr().err
    assert "Scan saved in the local history" in err
    Site.csp = "script-src 'self'; object-src 'none'; base-uri 'none'"       # the site fixed its CSP
    assert main(base + ["-o", str(tmp_path / "2.json")]) == 0
    second = json.loads((tmp_path / "2.json").read_text(encoding="utf-8"))
    d = second["web"]["diff"]
    assert d["comparable"] is True
    resolved = {r["rule"] for r in d["findings"]["resolved"]}
    assert "WEB040" in resolved and d["counts"]["unchanged"] >= 1
    assert any(p["kind"] == "csp" for p in d["posture"])
    from vulnscan.store import Store
    scans = Store().list_scans()
    assert len(scans) == 2 and all(s["kind"] == "url" and s["status"] == "done" for s in scans)
    assert all("web" not in s and "web_snapshot" not in s and s["web_brief"]["snapshot"] for s in scans)
    # --compare with a scan id of the history, and with the JSON report of the first run
    assert main([site, "--authorized", "--no-proxy", "--web-profile", "minimal", "--compare", scans[-1]["id"],
                 "-f", "json", "-o", str(tmp_path / "3.json")]) == 0
    assert json.loads((tmp_path / "3.json").read_text(encoding="utf-8"))["web"]["diff"]["comparable"] is True
    assert main([site, "--authorized", "--no-proxy", "--web-profile", "minimal", "--compare", str(tmp_path / "1.json"),
                 "--lang", "en", "-f", "markdown", "-o", str(tmp_path / "4.md")]) == 0
    md = (tmp_path / "4.md").read_text(encoding="utf-8")
    assert "Compared with the previous scan" in md and "Resolved findings" in md
    assert len(Store().list_scans()) == 2                 # --compare alone never writes to the history


def test_unreachable_site_exits_2_with_the_explanation(capsys):
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    code = main([f"http://127.0.0.1:{port}/", "--authorized", "--no-proxy", "--timeout", "1", "--lang", "en"])
    assert code == 2 and "refused" in capsys.readouterr().err.lower()


# ----------------------------------------------------------------------------------------------- update-data

def test_update_data_web(monkeypatch, capsys):
    from vulnscan import updater
    calls = []

    def fake(check_only=False, **kw):
        calls.append(check_only)
        return {"ok": True, "status": "available" if check_only else "installed", "message": "تتوفر بيانات ويب أحدث",
                "message_en": "Newer web data is available", "path": "/x/webdata/2026-11-20", "notes": []}
    monkeypatch.setattr(updater, "update_web_data", fake)
    assert main(["update-data", "--web", "--check", "--lang", "en"]) == 10
    assert "Newer web data is available" in capsys.readouterr().out
    assert main(["update-data", "--web", "--lang", "ar"]) == 0
    out = capsys.readouterr().out
    assert "تتوفر بيانات ويب أحدث" in out and "المجلد" in out
    assert calls == [True, False]

    def boom(**kw):
        raise updater.WebDataError("webdata_invalid", "bad sha256")
    monkeypatch.setattr(updater, "update_web_data", boom)
    assert main(["update-data", "--web", "--lang", "en"]) == 1
    err = capsys.readouterr().err
    assert "invalid" in err and "bad sha256" in err
    with pytest.raises(SystemExit) as e:
        main(["update-data", "--lang", "en"])
    assert e.value.code == 2 and "--web" in capsys.readouterr().err


def test_update_data_is_listed_and_has_help(capsys):
    from vulnscan.cli import SUBCOMMANDS, _subcommand_help
    assert "update-data" in SUBCOMMANDS
    assert not ARABIC.search(_subcommand_help("en")) and "update-data" in _subcommand_help("ar")
    with pytest.raises(SystemExit):
        main(["update-data", "--help", "--lang", "en"])
    text = capsys.readouterr().out
    assert text.startswith("usage: kashif update-data") and "--web" in text and not ARABIC.search(text)
    with pytest.raises(SystemExit):
        main(["--lang", "ar", "update-data", "--help"])
    assert ARABIC.search(capsys.readouterr().out)


# ----------------------------------------------------------------------------------------------- corpus, end to end

E2E_CASES = ("red-http-200", "hsts-missing", "csp-missing", "hdr-xfo-missing-login", "cors-reflect-creds",
             "ck-session-no-secure-no-hsts", "html-script-http", "disc-server-version", "lib-jquery-url",
             "hostile-markup-ansi")


@pytest.fixture(scope="module")
def corpus_server():
    sys.path.insert(0, str(BENCH))
    import corpus
    srv = corpus.CorpusServer(mode="host").start()
    yield corpus, srv
    srv.stop()


def _run_case(corpus, srv, c, lang: str, work: pathlib.Path) -> dict:
    d = work / f"{c.id}-{lang}"
    d.mkdir(parents=True)
    ca = str(srv.material.root) if srv.material else None
    rmap = d / "resolve.json"
    rmap.write_text(json.dumps(srv.resolver_map(c, ca)), encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if k not in PROXY_VARS and not k.startswith("KASHIF_TEST_")}
    env.update({"KASHIF_TEST_RESOLVE": "1", "KASHIF_TEST_RESOLVE_MAP": str(rmap), "HOME": str(d), "USERPROFILE": str(d),
                "KASHIF_HOME": str(d / "kh"), "VULNSCAN_HOME": str(d / "vh"), "PYTHONIOENCODING": "utf-8",
                "PYTHONUTF8": "1", "PYTHONPATH": str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")})
    if ca:
        env["KASHIF_TEST_CAFILE"] = ca
    prefix = d / "report"
    cmd = [sys.executable, "-m", "vulnscan", srv.url(c), "--authorized", "--no-color", "--lang", lang,
           "--web-profile", c.profile, "--web-sensitivity", c.sensitivity, "--delay", "0.2", "--timeout", "10",
           "--no-proxy", "--all-formats", str(prefix)]
    p = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, timeout=240, check=False)
    files = {x: prefix.with_suffix(f".{x}").read_text(encoding="utf-8") for x in ("json", "md", "html", "sarif")
             if prefix.with_suffix(f".{x}").is_file()}
    return {"exit": p.returncode, "stdout": p.stdout.decode("utf-8", "replace"),
            "stderr": p.stderr.decode("utf-8", "replace"), "files": files}


def test_cli_end_to_end_on_ten_corpus_cases_in_both_languages(corpus_server, tmp_path):
    corpus, srv = corpus_server
    labels = json.loads((BENCH / "labels.json").read_text(encoding="utf-8"))["cases"]
    cases = [srv.by_id[cid] for cid in E2E_CASES]
    jobs = [(c, lang) for c in cases for lang in ("ar", "en")]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        results = list(zip(jobs, ex.map(lambda j: _run_case(corpus, srv, j[0], j[1], tmp_path), jobs)))
    problems = []
    for (c, lang), r in results:
        where = f"{c.id} [{lang}]"
        if r["exit"] not in (0, 1) or "Traceback" in r["stderr"] or set(r["files"]) != {"json", "md", "html", "sarif"}:
            problems.append(f"{where}: exit {r['exit']} {r['stderr'][-400:]}")
            continue
        doc = json.loads(r["files"]["json"])
        fired = {f["rule_id"] for f in doc["findings"]}
        for rule, want in labels[c.id]["labels"].items():
            if bool(want) != (rule in fired):
                problems.append(f"{where}: {rule} expected {want}, fired {rule in fired}")
        web = doc.get("web") or {}
        if not (web.get("grades", {}).get("kashif") and web.get("coverage") and web.get("inventory")):
            problems.append(f"{where}: incomplete web object")
        sarif = json.loads(r["files"]["sarif"])
        if "grades" not in sarif["runs"][0]["properties"]:
            problems.append(f"{where}: no grades in the SARIF run")
        html, md = r["files"]["html"], r["files"]["md"]
        for text, name in ((html, "html"), (md, "md")):
            if '<script>alert("kashif-xss")' in text or "\x1b" in text:
                problems.append(f"{where}: unescaped target text in the {name} report")
        if "\x1b" in r["stdout"]:
            problems.append(f"{where}: ANSI escape from the target reached the terminal")
        if lang == "en":
            for name, text in (("console", r["stdout"]), ("md", md), ("html", html), ("sarif", r["files"]["sarif"])):
                left = sorted(set(ARABIC.findall(text)))
                if left:
                    problems.append(f"{where}: Arabic in the English {name}: {left[:10]}")
        else:
            if 'dir="rtl"' not in html or not ARABIC.search(r["stdout"]) or "تغطية الفحوص" not in md:
                problems.append(f"{where}: the Arabic report is not Arabic")
        for rec in srv.requests_for(c.id):
            if rec.method != "GET":
                problems.append(f"{where}: {rec.method} {rec.path}")
    assert not problems, "\n".join(problems)
