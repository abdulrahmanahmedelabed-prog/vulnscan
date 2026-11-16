"""Exposure, well-known files, deep probe and takeover (webscan/exposure.py, WP11, spec §2.10).

Unit tests use synthetic Responses; the deep probe uses a recording fake Fetcher; the C-EXP corpus cases are rendered
in-process (no sockets). Nothing here touches the network.
"""

from __future__ import annotations

import importlib
import json
import re
import sys
import urllib.parse
from pathlib import Path

import pytest

from vulnscan.webscan import classify, coverage, data, exposure, htmlparse, sectxt
from vulnscan.webscan.rules import RULES
from vulnscan.webscan.types import CookieFact, DnsRecord, HeaderList, Page, Response, ScanContext, ScanOptions

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "vulnscan" / "data" / "web"
OWN = set(exposure.CHECKS)
BASE = "https://example.test"
PLAIN = "text/plain; charset=utf-8"
HTML = "text/html; charset=utf-8"
FUTURE = "2027-05-13T00:00:00Z"


def resp(path: str = "/", status: int | None = 200, ctype: str | None = PLAIN, body: str | bytes = b"", *,
         source: str = "probe", base: str = BASE, headers: tuple = (), **kw) -> Response:
    hs = list(headers)
    if ctype is not None:
        hs.insert(0, ("Content-Type", ctype))
    b = body.encode("utf-8") if isinstance(body, str) else body
    url = path if "://" in path else base + path
    r = Response(url=url, status=status, headers=HeaderList(tuple(hs)), body=b, source=source, **kw)
    classify.classify(r, htmlparse.parse_response(r) if r.essence == "text/html" and b else None)
    return r


def page(title: str = "Example", body: str = "<p>Welcome to the example site. Nothing to see.</p>") -> str:
    return f"<!doctype html><html><head><title>{title}</title></head><body>{body}</body></html>"


ENTRY_HTML = page("Example shop", "<h1>Example shop</h1><p>" + "Products and prices for everyone. " * 20 + "</p>")


def ctx_for(*, profile: str = "deep", entry: Response | None = None, probes=(), baselines=(), wellknown=None,
            sensitivity: str = "default", **fields) -> ScanContext:
    entry = entry or resp("/", 200, HTML, ENTRY_HTML, source="entry")
    ctx = ScanContext(options=ScanOptions(profile=profile, sensitivity=sensitivity), target=BASE + "/", entry=entry,
                      probes=list(probes), baselines=list(baselines), wellknown=dict(wellknown or {}), **fields)
    if entry.essence == "text/html" and entry.status == 200:
        ctx.pages.append(Page(entry, htmlparse.parse_response(entry), 0))
    ctx.coverage = coverage.Coverage()
    ctx.inventory.setdefault("deep_probe", {"planned": [{"path": "/x"}], "fetched": len(ctx.probes),
                                            "skipped": [], "skipped_reason": ""})
    return ctx


def run(ctx: ScanContext):
    issues = exposure.run(ctx)
    for i in issues:
        meta = RULES[i.rule]
        assert i.confidence in meta.allowed_confidences, i
        assert (i.severity or meta.severity) in meta.allowed_severities, i
        assert i.evidence.match is not None
        json.dumps(i.evidence.to_dict())
        for en, ar in i.notes:
            assert en and ar
    return issues


def rules_of(issues) -> dict[str, list]:
    out: dict[str, list] = {}
    for i in issues:
        out.setdefault(i.rule, []).append(i)
    return out


def state(ctx: ScanContext, check: str) -> str:
    return ctx.coverage.state(check).state


# =============================================================================================== data files

def _load(name: str):
    return json.loads((DATA / name).read_text(encoding="utf-8"))


def _tech_deep_paths() -> list[dict]:
    return [d for t in _load("tech.json")["technologies"] for d in t.get("deep_paths") or []]


def test_exposed_paths_and_takeover_validate_against_their_schemas():
    for name in ("exposed-paths.json", "takeover.json"):
        assert data.validate_file(DATA / name) == [], name


def test_every_deep_path_has_a_signature():
    for d in _load("exposed-paths.json")["paths"] + _tech_deep_paths():
        sig = d["signature"]
        conds = (sig.get("all") or []) + (sig.get("any") or [])
        assert conds, d["path"]
        for c in conds + (sig.get("none") or []):
            if c["type"] == "regex":
                exposure._rx(c["pattern"], c.get("flags", ""))         # compiles
            elif c["type"] == "magic":
                assert bytes.fromhex(c["pattern"])
        if d["strength"] == "weak":
            assert "document" in d["kinds"], d["path"]                 # weak = HTML by nature
        else:
            # strong: never judged on an HTML page (not_html, a magic prefix, or no HTML kind at all)
            assert sig.get("not_html") or any(c["type"] == "magic" for c in conds) or "document" not in d["kinds"], \
                d["path"]


def test_exposed_list_is_small_unique_and_ordered_by_rule():
    paths = [d["path"] for d in _load("exposed-paths.json")["paths"]]
    assert len(paths) == len(set(paths)) <= 40
    assert all(d["rule"] == "WEB062" for d in _load("exposed-paths.json")["paths"])
    for d in _load("exposed-paths.json")["paths"] + _tech_deep_paths():
        assert d["severity"] in RULES[d["rule"]].allowed_severities, d
        for sev in (d.get("severity_if") or {}).values():
            assert sev in RULES[d["rule"]].allowed_severities, d
        assert any("؀" <= ch <= "ۿ" for ch in d["title_ar"] + d["advice_ar"]), d["path"]


def test_exposed_paths_and_tech_deep_paths_are_disjoint():
    exposed = {d["path"] for d in _load("exposed-paths.json")["paths"]}
    platform = {d["path"] for d in _tech_deep_paths()}
    assert exposed and platform
    assert not exposed & platform
    assert "/storage/logs/laravel.log" in exposed and "/storage/logs/laravel.log" not in platform


NEVER = re.compile(r"(?i)heap-?dump|thread-?dump|pprof|/actuator/(?:shutdown|restart|refresh|loggers|caches|logfile|jolokia)"
                   r"|cache[-_/]?(?:clear|purge|flush)|/install|/setup\b|/upgrade\b|/wp-cron|/cron\b|/purge")


def test_no_never_list_path_in_any_data_file():
    # §0.1 and §6 phase D: endpoints whose GET does expensive or state-changing work are never listed.
    for d in _load("exposed-paths.json")["paths"] + _tech_deep_paths():
        assert not NEVER.search(d["path"]), d["path"]
        assert not exposure.NEVER_LIST.search(d["path"]), d["path"]
    for name in ("exposed-paths.json",):
        doc = _load(name)
        assert not any(NEVER.search(p["path"]) for p in doc["paths"])


@pytest.mark.parametrize("path", ["/actuator/heapdump", "/actuator/threaddump", "/debug/pprof/profile", "/debug/pprof/",
                                  "/actuator/shutdown", "/cache/purge", "/install.php", "/wp-cron.php", "/setup/"])
def test_never_list_regex_refuses(path):
    assert exposure.NEVER_LIST.search(path)


@pytest.mark.parametrize("path", ["/actuator", "/actuator/env", "/.git/HEAD", "/server-status", "/wp-login.php",
                                  "/xmlrpc.php", "/phpinfo.php"])
def test_never_list_regex_allows(path):
    assert not exposure.NEVER_LIST.search(path)


def test_plan_never_exceeds_the_budget_and_never_lists_forbidden_paths(make_ctx):
    ctx = make_ctx(profile="deep")
    every = [t["id"] for t in _load("tech.json")["technologies"] if t.get("deep_paths")]
    items = exposure.plan(ctx, every)
    paths = [p.path for p in items]
    assert len(paths) <= exposure.MAX_PROBES == 70
    assert len(paths) == len(set(paths))
    assert "/crossdomain.xml" in paths and "/clientaccesspolicy.xml" in paths
    assert not any(exposure.NEVER_LIST.search(p) for p in paths)
    sev = [p.severity for p in items[:len(exposure.exposed_paths())]]
    order = ["critical", "high", "medium", "low", "info"]
    assert sev == sorted(sev, key=order.index)                      # most severe first


def test_takeover_data_is_what_the_refresh_script_produces():
    sys.path.insert(0, str(ROOT / "tools" / "webdata"))
    try:
        takeover_tool = importlib.import_module("takeover")
    finally:
        sys.path.pop(0)
    assert takeover_tool.main(["--check"]) == 0
    provs = exposure.providers()
    assert any(p.name == "GitHub Pages" and p.vulnerable and p.status == 404 for p in provs)
    assert any(not p.vulnerable for p in provs)                       # mitigated providers are kept, never fire


# =============================================================================================== signatures

SAMPLES: dict[str, tuple[str, bytes | str]] = {
    "/.git/HEAD": (PLAIN, "ref: refs/heads/main\n"),
    "/.git/config": (PLAIN, "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"),
    "/.svn/entries": (PLAIN, "12\n"),
    "/.svn/wc.db": ("application/octet-stream", b"SQLite format 3\x00" + b"\x10\x00" * 20),
    "/.hg/requires": (PLAIN, "dotencode\nfncache\nrevlogv1\nstore\n"),
    "/.DS_Store": ("application/octet-stream", b"\x00\x00\x00\x01Bud1" + b"\x00" * 30),
    "/.env": (PLAIN, "APP_ENV=production\nDB_PASSWORD=hunter2hunter2\n"),
    "/.env.bak": (PLAIN, "APP_ENV=production\nDB_PASSWORD=hunter2hunter2\n"),
    "/.env.local": (PLAIN, "APP_ENV=local\nSECRET_KEY=abcdefghijklmnop\n"),
    "/.env.production": (PLAIN, "NODE_ENV=production\nAPI_TOKEN=abcdefghijklmnop\n"),
    "/wp-config.php.bak": (PLAIN, "<?php\ndefine( 'DB_PASSWORD', 'hunter2hunter2' );\n"),
    "/wp-config.php~": (PLAIN, "<?php\ndefine( 'DB_PASSWORD', 'hunter2hunter2' );\n"),
    "/wp-config.old": (PLAIN, "<?php\ndefine( 'DB_PASSWORD', 'hunter2hunter2' );\n"),
    "/config.php.bak": (PLAIN, "<?php\n$db_password = 'hunter2hunter2';\n"),
    "/backup.sql": (PLAIN, "-- MySQL dump 10.13  Distrib 8.0.35\n--\nCREATE TABLE `users` (id int);\n"),
    "/dump.sql": (PLAIN, "-- PostgreSQL database dump\n\nCREATE TABLE public.users (id integer);\n"),
    "/db.sql": (PLAIN, "INSERT INTO users VALUES (1,'admin');\n"),
    "/.aws/credentials": (PLAIN, "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"),
    "/.htaccess": (PLAIN, "RewriteEngine On\nRewriteRule ^(.*)$ index.php [L]\n"),
    "/.htpasswd": (PLAIN, "admin:$apr1$abcdefgh$0123456789abcdefghijkl\n"),
    "/web.config": ("application/xml", '<?xml version="1.0"?>\n<configuration>\n <system.webServer/>\n</configuration>\n'),
    "/WEB-INF/web.xml": ("application/xml", '<?xml version="1.0"?>\n<web-app version="4.0"></web-app>\n'),
    "/.idea/workspace.xml": ("application/xml", '<?xml version="1.0"?>\n<project version="4"></project>\n'),
    "/.vscode/sftp.json": ("application/json", '{"host": "203.0.113.9", "username": "deploy", "password": "hunter2x"}'),
    "/docker-compose.yml": (PLAIN, "version: '3'\nservices:\n  web:\n    image: nginx:1.25\n"),
    "/.npmrc": (PLAIN, "//registry.npmjs.org/:_authToken=npm_abcdefghijklmnopqrstuvwxyz\n"),
    "/phpinfo.php": (HTML, page("PHP 8.2.12 - phpinfo()", '<h1 class="p">PHP Version 8.2.12</h1><table><tr>'
                                '<td class="e">System </td><td class="v">Linux</td></tr></table>')),
    "/info.php": (HTML, page("PHP 8.2.12 - phpinfo()", "<h1>PHP Version 8.2.12</h1>")),
    "/server-status": (HTML, page("Apache Status", "<h1>Apache Server Status for example.test</h1>")),
    "/nginx_status": (PLAIN, "Active connections: 2 \nserver accepts handled requests\n 10 10 20 \n"),
    "/actuator/env": ("application/json", '{"activeProfiles": [], "propertySources": []}'),
    "/actuator": ("application/json", '{"_links": {"self": {"href": "https://example.test/actuator"}}}'),
    "/swagger-ui/index.html": (HTML, page("Swagger UI", '<div id="swagger-ui"></div>'
                                          '<script src="./swagger-ui-bundle.js"></script>')),
    "/v3/api-docs": ("application/json", '{"openapi": "3.0.1", "info": {"title": "API"}}'),
    "/graphql": (HTML, page("GraphiQL", '<div id="graphiql">Loading…</div>')),
    "/telescope": (HTML, page("Telescope", "<script>window.Telescope = {path: 'telescope'};</script>")),
    "/_profiler": (HTML, page("Symfony Profiler", '<div class="sf-toolbar"></div>')),
    "/storage/logs/laravel.log": (PLAIN, "[2026-11-01 10:00:00] production.ERROR: SQLSTATE[HY000] boom\n"),
    "/error_log": (PLAIN, "[01-Nov-2026 10:00:00 UTC] PHP Warning:  Undefined variable $x in /var/www/a.php\n"),
    "/debug.log": (PLAIN, "[01-Nov-2026 10:00:00 UTC] PHP Fatal error:  Uncaught Error in /var/www/a.php\n"),
}
GENERIC_NEGATIVES = [
    (HTML, ENTRY_HTML), (PLAIN, "OK\n"), (PLAIN, "Not Found\n"), ("application/json", '{"status": "ok"}'),
    (HTML, page("Login", '<form><input name="u"><input type="password" name="p"></form>')), (PLAIN, ""),
]


def test_every_exposed_path_has_a_positive_sample():
    assert {p.path for p in exposure.exposed_paths()} == set(SAMPLES)


@pytest.mark.parametrize("path", sorted(SAMPLES))
def test_signature_matches_its_sample(path):
    spec = next(p for p in exposure.exposed_paths() if p.path == path)
    ctype, body = SAMPLES[path]
    r = resp(path, 200, ctype, body)
    v = exposure.judge(r, spec, classify.Soft404Index(), {})
    assert v.state == "exposed", (path, v.reason)


@pytest.mark.parametrize("path", sorted(SAMPLES))
def test_signature_rejects_generic_pages(path):
    spec = next(p for p in exposure.exposed_paths() if p.path == path)
    for ctype, body in GENERIC_NEGATIVES:
        r = resp(path, 200, ctype, body)
        assert exposure.judge(r, spec, classify.Soft404Index(), {}).state == "clean", (path, body[:40])


def test_env_needs_two_assignment_lines_and_no_html():
    spec = next(p for p in exposure.exposed_paths() if p.path == "/.env")
    assert exposure.match_signature(spec.signature, b"APP_ENV=production\n") is None
    assert exposure.match_signature(spec.signature, b"<html><body>APP_ENV=x\nDB_HOST=y\n</body></html>") is None
    assert exposure.match_signature(spec.signature, b"APP_ENV=x\nDB_HOST=y\n")


def test_git_head_also_accepts_a_detached_sha():
    spec = next(p for p in exposure.exposed_paths() if p.path == "/.git/HEAD")
    assert exposure.match_signature(spec.signature, b"0123456789abcdef0123456789abcdef01234567\n")
    assert exposure.match_signature(spec.signature, b"see refs: refs/heads/main\n") is None


def test_tech_deep_path_samples():
    specs = {p.path: p for p in exposure.platform_paths()}
    samples = {
        "/core/CHANGELOG.txt": (PLAIN, "Drupal 10.1.6, 2023-11-01\n----\n"),
        "/wp-content/debug.log": (PLAIN, "[01-Nov-2026 10:00:00 UTC] PHP Notice:  Undefined index\n"),
        "/configuration.php-dist": (PLAIN, "<?php\nclass JConfig {\n public $password = '';\n}\n"),
        "/wp-login.php": (HTML, page("Log In", '<form id="loginform"><input type="password" name="pwd">'
                                     '<input type="submit" name="wp-submit"></form>')),
    }
    for path, (ctype, body) in samples.items():
        r = resp(path, 200, ctype, body)
        assert exposure.judge(r, specs[path], classify.Soft404Index(), {}).state == "exposed", path


# =============================================================================================== the §2.10 gate

def _spec(path: str):
    return next(p for p in exposure.exposed_paths() + exposure.platform_paths() if p.path == path)


def _index(*baselines: Response, wellknown=None, entry=None) -> classify.Soft404Index:
    idx = classify.Soft404Index()
    for b in baselines:
        idx.add_baseline(b)
    if wellknown:
        idx.add_natural(wellknown, entry)
    return idx


def test_strong_signature_is_decisive_against_a_similar_catch_all_baseline():
    # rev-git-head-catchall: a 23-byte catch-all page must not hide a real 21-byte .git/HEAD (§2.10, critique 26)
    base = resp("/.git/kashif-404-0123456789abcdef", 200, PLAIN, "Nothing to see here :)\n", source="baseline")
    root = resp("/kashif-404-0123456789abcdee", 200, PLAIN, "Nothing to see here :)\n", source="baseline")
    probe = resp("/.git/HEAD", 200, PLAIN, "ref: refs/heads/main\n")
    idx = _index(root, base)
    assert classify.similar(classify.signature(probe), classify.signature(base))       # length-similar …
    v = exposure.judge(probe, _spec("/.git/HEAD"), idx, {base.url: base, root.url: root})
    assert v.state == "exposed" and v.baseline and v.baseline["url"] == base.url       # … but the signature decides


def test_strong_signature_clean_when_the_baseline_matches_it_too():
    body = "ref: refs/heads/main\n"
    base = resp("/.git/kashif-404-0123456789abcdef", 200, PLAIN, body + " ", source="baseline")
    probe = resp("/.git/HEAD", 200, PLAIN, body)
    v = exposure.judge(probe, _spec("/.git/HEAD"), _index(base), {base.url: base})
    assert v.state == "clean" and "baseline" in v.reason


def test_identical_body_baseline_is_clean():
    blob = b"\x00\x00\x00\x01Bud1" + b"\x00" * 20
    base = resp("/kashif-404-0123456789abcdef", 200, "application/octet-stream", blob, source="baseline")
    probe = resp("/.DS_Store", 200, "application/octet-stream", blob)
    v = exposure.judge(probe, _spec("/.DS_Store"), _index(base), {})
    assert v.state == "clean"


def test_weak_signature_clean_when_similar_to_the_baseline():
    shell = page("Swagger UI", '<div id="swagger-ui"></div><script src="./swagger-ui-bundle.js"></script>' + "<p>x</p>" * 50)
    base = resp("/swagger-ui/kashif-404-0123456789abcdef", 200, HTML, shell.replace("<p>x</p>", "<p>y</p>", 1),
                source="baseline")
    probe = resp("/swagger-ui/index.html", 200, HTML, shell)
    # the baseline is an HTML page too, so the signature matching both is enough to dismiss it
    assert exposure.judge(probe, _spec("/swagger-ui/index.html"), _index(base), {base.url: base}).state == "clean"
    # a weak signature also yields to plain similarity (no signature match on the baseline needed)
    base2 = resp("/swagger-ui/kashif-404-0123456789abcdef", 200, HTML, page("App", "<p>x</p>" * 50), source="baseline")
    probe2 = resp("/swagger-ui/index.html", 200, HTML, page("App", "<p>x</p>" * 50 + '<div id="swagger-ui"></div>'))
    assert exposure.judge(probe2, _spec("/swagger-ui/index.html"), _index(base2), {}).state == "clean"


def test_weak_signature_exposed_when_the_server_returns_real_404s():
    base = resp("/kashif-404-0123456789abcdef", 404, HTML, page("Not found", "<h1>Not found</h1>"), source="baseline")
    ctype, body = SAMPLES["/phpinfo.php"]
    probe = resp("/phpinfo.php", 200, ctype, body)
    v = exposure.judge(probe, _spec("/phpinfo.php"), _index(base), {base.url: base})
    assert v.state == "exposed"


def test_weak_signature_clean_when_it_is_the_spa_shell():
    shell = page("App", '<div id="root"></div><div id="swagger-ui"></div>' + "<p>s</p>" * 40)
    entry = resp("/", 200, HTML, shell, source="entry")
    probe = resp("/swagger-ui/index.html", 200, HTML, shell)
    v = exposure.judge(probe, _spec("/swagger-ui/index.html"), classify.Soft404Index(), {}, entry)
    assert v.state == "clean" and "entry" in v.reason


def test_natural_catch_all_counts_as_a_baseline():
    shell = page("App", "<p>Welcome</p>" * 30)
    wk = {"/robots.txt": resp("/robots.txt", 200, HTML, shell, source="wellknown"),
          "/.well-known/security.txt": resp("/.well-known/security.txt", 200, HTML, shell, source="wellknown")}
    idx = _index(wellknown=wk)
    probe = resp("/graphql", 200, HTML, shell.replace("Welcome", "Welcome graphiql.min.js", 1))
    assert exposure.judge(probe, _spec("/graphql"), idx, {}).state == "clean"


@pytest.mark.parametrize("status, want", [(200, "exposed"), (206, "exposed"), (403, "clean"), (404, "clean"),
                                          (301, "clean"), (500, "clean")])
def test_status_gate(status, want):
    probe = resp("/.git/HEAD", status, PLAIN, "ref: refs/heads/main\n")
    assert exposure.judge(probe, _spec("/.git/HEAD"), classify.Soft404Index(), {}).state == want


def test_kind_gate_html_env_page_is_clean_but_mislabelled_text_is_judged():
    html_page = resp("/.env", 200, HTML, page("Env", "<pre>APP_ENV=x\nDB_HOST=y\n</pre>"))
    assert exposure.judge(html_page, _spec("/.env"), classify.Soft404Index(), {}).state == "clean"
    mislabelled = resp("/.env", 200, "text/html", "APP_ENV=production\nDB_PASSWORD=hunter2hunter2\n")
    assert exposure.judge(mislabelled, _spec("/.env"), classify.Soft404Index(), {}).state == "exposed"
    # an HTML-only exposure served as JSON is not the page
    as_json = resp("/phpinfo.php", 200, "application/json", '{"x": "PHP Version <td class=\\"e\\"> <td class=\\"v\\">"}')
    assert exposure.judge(as_json, _spec("/phpinfo.php"), classify.Soft404Index(), {}).state == "clean"


def test_unreceived_waf_and_opaque_responses_are_never_pass():
    spec = _spec("/.git/HEAD")
    err = resp("/.git/HEAD", None, None, b"", error="timed out", flags=frozenset({"error:timeout"}))
    assert exposure.judge(err, spec, classify.Soft404Index(), {}).state == "not_tested"
    budget = resp("/.git/HEAD", None, None, b"", error="budget", flags=frozenset({"error:budget"}))
    assert exposure.judge(budget, spec, classify.Soft404Index(), {}).reason == "budget"
    waf = resp("/.git/HEAD", 403, HTML, page("Just a moment...", "cf-chl-"), headers=(("cf-mitigated", "challenge"),))
    assert exposure.judge(waf, spec, classify.Soft404Index(), {}).state == "inconclusive"
    opaque = resp("/.git/HEAD", 200, PLAIN, b"", flags=frozenset({"opaque-coding"}))
    assert exposure.judge(opaque, spec, classify.Soft404Index(), {}).state == "not_tested"


# =============================================================================================== WEB062 via run()

def test_exposed_env_is_critical_certain_with_redacted_evidence():
    ctype, body = SAMPLES["/.env"]
    base = resp("/kashif-404-0123456789abcdef", 404, HTML, page("Not found"), source="baseline")
    ctx = ctx_for(probes=[resp("/.env", 200, ctype, body)], baselines=[base])
    issues = rules_of(run(ctx))
    (i,) = issues["WEB062"]
    assert i.severity == "critical" and i.confidence == "certain" and i.params["path"] == "/.env"
    ev = i.evidence.to_dict()
    assert "hunter2hunter2" not in json.dumps(ev) and "production" not in ev["match"]["excerpt"]
    assert ev["curl"].startswith("curl ") and "'https://example.test/.env'" in ev["curl"] or "https://example.test/.env" \
        in ev["curl"]
    assert ev["baseline"]["url"].endswith("kashif-404-0123456789abcdef")
    assert state(ctx, "WEB062") == "fail"
    assert ctx.inventory["deep_probe_hits"][0]["path"] == "/.env"


def test_redact_values():
    assert exposure.redact_values("DB_PASSWORD=hunter2hunter2") == "DB_PASSWORD=hunt…r2"
    assert exposure.redact_values('"password": "hunter2xyz"') == '"password": "hunt…yz"'
    assert "s3cr3tpass" not in exposure.redact_values("DATABASE_URL=postgres://app:s3cr3tpass@db/app")


def test_actuator_index_listing_heapdump_is_high_and_not_requested():
    body = ('{"_links": {"self": {"href": "https://example.test/actuator"}, '
            '"heapdump": {"href": "https://example.test/actuator/heapdump"}, '
            '"env": {"href": "https://example.test/actuator/env"}}}')
    ctx = ctx_for(probes=[resp("/actuator", 200, "application/vnd.spring-boot.actuator.v3+json", body)])
    (i,) = rules_of(run(ctx))["WEB062"]
    assert i.severity == "high"
    assert any("heapdump" in en and "heapdump" in ar for en, ar in i.notes)
    plain = ctx_for(probes=[resp("/actuator", 200, "application/json", SAMPLES["/actuator"][1])])
    (j,) = rules_of(run(plain))["WEB062"]
    assert j.severity == "low"


def test_api_docs_linked_from_the_site_are_info():
    entry = resp("/", 200, HTML, page("API", '<a href="/v3/api-docs">API reference</a>' + "<p>docs</p>" * 30),
                 source="entry")
    ctx = ctx_for(entry=entry, probes=[resp("/v3/api-docs", 200, *SAMPLES["/v3/api-docs"])])
    (i,) = rules_of(run(ctx))["WEB062"]
    assert i.severity == "info"
    ctx2 = ctx_for(probes=[resp("/v3/api-docs", 200, *SAMPLES["/v3/api-docs"])])
    assert rules_of(run(ctx2))["WEB062"][0].severity == "low"


def test_deep_rules_not_tested_without_deep():
    ctx = ctx_for(profile="standard")
    ctx.inventory.pop("deep_probe")
    run(ctx)
    for c in ("WEB062", "WEB082", "WEB083", "WEB903"):
        st = ctx.coverage.state(c)
        assert st.state == "not_tested" and st.reasons[0][0] == "deep_off"


def test_deep_skipped_for_waf_is_inconclusive():
    ctx = ctx_for()
    ctx.inventory["deep_probe"] = {"planned": [], "fetched": 0, "skipped": [], "skipped_reason": "waf"}
    run(ctx)
    assert state(ctx, "WEB062") == "inconclusive"


def test_clean_probes_pass_and_platform_rules_not_applicable():
    ctx = ctx_for(probes=[resp("/.git/HEAD", 404, HTML, page("Not found")), resp("/.env", 404, HTML, page("NF"))])
    assert not run(ctx)
    assert state(ctx, "WEB062") == "pass"
    assert state(ctx, "WEB082") == "not_applicable" and state(ctx, "WEB083") == "not_applicable"


def test_one_timed_out_probe_keeps_the_check_not_tested():
    err = resp("/.env", None, None, b"", error="timed out", flags=frozenset({"error:timeout"}))
    ctx = ctx_for(probes=[resp("/.git/HEAD", 404, HTML, page("NF")), err])
    run(ctx)
    st = ctx.coverage.state("WEB062")
    assert st.state == "not_tested" and st.reasons[0][0] == "timeout"


# =============================================================================================== WEB082 / WEB083

def test_platform_file_and_login_page():
    ctx = ctx_for(probes=[resp("/core/CHANGELOG.txt", 200, PLAIN, "Drupal 10.1.6, 2023-11-01\n"),
                          resp("/wp-login.php", 200, HTML, page("Log In", '<form id="loginform"><input name="log">'
                                                                '<input type="password" name="pwd">'
                                                                '<input type="submit" name="wp-submit"></form>'))])
    issues = rules_of(run(ctx))
    (a,) = issues["WEB082"]
    assert a.severity == "high" and a.params["platform"] == "Drupal" and a.params["path"] == "/core/CHANGELOG.txt"
    (b,) = issues["WEB083"]
    assert b.confidence == "firm" and b.params["platform"] == "WordPress"


def test_login_marker_without_live_password_field_is_not_web083():
    # only the password regex matched, and the field lives inside <template> (not rendered)
    body = page("Moodle", '<template><input type="password" name="p"></template>')
    spec = _spec("/phpmyadmin/")
    probe = resp("/phpmyadmin/", 200, HTML, body)
    v = exposure.judge(probe, spec, classify.Soft404Index(), {})
    assert v.state == "exposed" and not exposure._live_login(probe, v.matches)


# =============================================================================================== WEB903

CROSSDOMAIN_ANY = ('<?xml version="1.0"?>\n<cross-domain-policy><allow-access-from domain="*" secure="false"/>'
                   "</cross-domain-policy>\n")


def _session_cookie(r: Response) -> CookieFact:
    return CookieFact(name="sessionid", value="x" * 32, attrs={"secure": "", "httponly": ""}, raw="sessionid=x",
                      response=r, host="example.test", secure_context=True, cls="session")


def test_crossdomain_wildcard_medium_with_session_low_without():
    probe = resp("/crossdomain.xml", 200, "text/x-cross-domain-policy", CROSSDOMAIN_ANY)
    ctx = ctx_for(probes=[probe])
    ctx.cookies = [_session_cookie(ctx.entry)]
    (i,) = rules_of(run(ctx))["WEB903"]
    assert i.severity == "medium" and any('secure="false"' in en for en, _ in i.notes)
    ctx2 = ctx_for(probes=[resp("/crossdomain.xml", 200, "text/x-cross-domain-policy", CROSSDOMAIN_ANY)])
    assert rules_of(run(ctx2))["WEB903"][0].severity == "low"


def test_crossdomain_restricted_and_clientaccesspolicy():
    restricted = resp("/crossdomain.xml", 200, "text/xml", '<cross-domain-policy><allow-access-from domain="*.example.test"/>'
                      "</cross-domain-policy>")
    assert not run(ctx_for(probes=[restricted]))
    cap = ('<?xml version="1.0"?><access-policy><cross-domain-access><policy><allow-from http-request-headers="*">'
           '<domain uri="*"/></allow-from><grant-to><resource path="/" include-subpaths="true"/></grant-to></policy>'
           "</cross-domain-access></access-policy>")
    issues = rules_of(run(ctx_for(probes=[resp("/clientaccesspolicy.xml", 200, "text/xml", cap)])))
    assert issues["WEB903"][0].params["path"] == "/clientaccesspolicy.xml"
    grant_only = cap.replace('<domain uri="*"/>', '<domain uri="https://example.test"/>')
    assert not run(ctx_for(probes=[resp("/clientaccesspolicy.xml", 200, "text/xml", grant_only)]))


# =============================================================================================== probe() (the only fetcher use)

class FakeFetcher:
    def __init__(self, routes: dict[str, tuple[int, str, str | bytes]] | None = None, budget: int = 150):
        self.routes = routes or {}
        self.calls: list[tuple[str, str, bool, str | None]] = []
        self.budget = budget

    def remaining_requests(self, source: str = "entry") -> int:
        return self.budget - len(self.calls)

    def fetch(self, url, *, source="entry", follow=True, accept=None, **kw):
        self.calls.append((url, source, follow, accept))
        path = urllib.parse.urlsplit(url).path
        status, ctype, body = self.routes.get(path, (404, HTML, page("Not found")))
        return resp(url, status, ctype, body, source=source)


def test_probe_fetches_baselines_then_paths_without_following_redirects():
    f = FakeFetcher({"/.git/HEAD": (200, PLAIN, "ref: refs/heads/main\n")})
    ctx = ctx_for(fetcher=f)
    ctx.inventory.pop("deep_probe")
    report = exposure.probe(ctx)
    assert report["fetched"] == len(ctx.probes) == len(report["planned"]) <= 70
    assert all(not follow and accept == "probe" for _u, _s, follow, accept in f.calls)
    srcs = [s for _u, s, _f, _a in f.calls]
    assert srcs[: report["baselines"]] == ["baseline"] * report["baselines"] and 1 <= report["baselines"] <= 5
    assert all(classify.is_baseline_url(u) for u, s, _f, _a in f.calls if s == "baseline")
    paths = [urllib.parse.urlsplit(u).path for u, s, _f, _a in f.calls if s == "probe"]
    assert len(paths) == len(set(paths)) and not any(exposure.NEVER_LIST.search(p) for p in paths)
    assert all(u.startswith(BASE + "/") for u, *_ in f.calls)
    classify.classify_context(ctx)
    issues = rules_of(run(ctx))
    assert [i.params["path"] for i in issues["WEB062"]] == ["/.git/HEAD"]
    assert state(ctx, "WEB903") == "pass"


def test_probe_respects_the_request_budget():
    f = FakeFetcher(budget=12)
    ctx = ctx_for(fetcher=f)
    report = exposure.probe(ctx)
    assert len(f.calls) == 12 and report["skipped"]
    run(ctx)
    st = ctx.coverage.state("WEB062")
    assert st.state == "not_tested" and any(code == "budget" for code, _en, _ar in st.reasons)


def test_probe_does_nothing_without_deep_or_on_a_waf_or_offsite():
    f = FakeFetcher()
    ctx = ctx_for(profile="standard", fetcher=f)
    assert exposure.probe(ctx)["skipped_reason"] == "deep_off" and not f.calls
    waf_entry = resp("/", 403, HTML, page("Just a moment...", "cf-chl-"), source="entry",
                     headers=(("cf-mitigated", "challenge"),))
    ctx = ctx_for(entry=waf_entry, fetcher=f)
    assert exposure.probe(ctx)["skipped_reason"] == "waf" and not f.calls
    off = resp("https://login.other-site.test/", 200, HTML, ENTRY_HTML, source="entry")
    ctx = ctx_for(entry=off, fetcher=f)
    assert exposure.probe(ctx)["skipped_reason"] == "offsite" and not f.calls
    run(ctx)
    st = ctx.coverage.state("WEB062")
    assert st.state == "not_tested" and "another site" in st.reasons[0][1]


def test_probe_refuses_never_list_paths_even_if_a_data_file_lists_them():
    class Stub:
        def load_json(self, name):
            if name == "exposed-paths.json":
                base = _load(name)
                base["paths"] = [dict(base["paths"][0], path="/actuator/heapdump"),
                                 dict(base["paths"][0], path="/debug/pprof/profile"), base["paths"][0]]
                return base
            return data.load_json(name)
    f = FakeFetcher()
    ctx = ctx_for(fetcher=f, data=Stub())
    exposure.probe(ctx, platforms=[])
    paths = {urllib.parse.urlsplit(u).path for u, *_ in f.calls}
    assert "/actuator/heapdump" not in paths and "/debug/pprof/profile" not in paths and "/.git/HEAD" in paths


def test_probe_includes_detected_platform_paths_only():
    f = FakeFetcher()
    ctx = ctx_for(fetcher=f)
    ctx.inventory["technologies"] = [{"id": "drupal", "name": "Drupal", "confidence": 100}]
    exposure.probe(ctx)
    paths = {urllib.parse.urlsplit(u).path for u, *_ in f.calls}
    assert "/core/CHANGELOG.txt" in paths and "/wp-login.php" not in paths
    weak = ctx_for(fetcher=FakeFetcher())
    weak.inventory["technologies"] = [{"id": "wordpress", "name": "WordPress", "confidence": 25}]
    assert "wordpress" not in exposure.detected_platforms(weak)
    weak.options.sensitivity = "paranoid"
    assert "wordpress" in exposure.detected_platforms(weak)


# =============================================================================================== WEB060 / WEB900

def _wk(path: str, status: int, body: str = "", ctype: str | None = PLAIN, base: str = BASE) -> Response:
    return resp(path, status, ctype, body, source="wellknown", base=base)


VALID_SECTXT = f"Contact: mailto:security@example.test\nExpires: {FUTURE}\n"


def test_valid_security_txt_passes_both():
    ctx = ctx_for(profile="standard", wellknown={"/.well-known/security.txt": _wk("/.well-known/security.txt", 200,
                                                                                    VALID_SECTXT)})
    assert not run(ctx)
    assert state(ctx, "WEB060") == "pass" and state(ctx, "WEB900") == "pass"
    assert ctx.inventory["security_txt"]["present"] is True


def test_missing_security_txt_is_web060_info():
    ctx = ctx_for(profile="standard", wellknown={"/.well-known/security.txt": _wk("/.well-known/security.txt", 404),
                                                 "/security.txt": _wk("/security.txt", 404)})
    (i,) = rules_of(run(ctx))["WEB060"]
    assert (i.severity or "info") == "info" and i.confidence == "certain"
    assert state(ctx, "WEB900") == "not_applicable"


def test_legacy_only_security_txt_is_web900_info():
    ctx = ctx_for(profile="standard", wellknown={"/.well-known/security.txt": _wk("/.well-known/security.txt", 404),
                                                 "/security.txt": _wk("/security.txt", 200, VALID_SECTXT)})
    (i,) = rules_of(run(ctx))["WEB900"]
    assert i.severity == "info" and i.params["problems"] == ["legacy_location"]
    assert state(ctx, "WEB060") == "pass"


def test_expired_security_txt_is_low_and_lists_every_problem():
    body = "Contact: mailto:security@example.test\nExpires: 2026-01-01T00:00:00Z\nBounty: yes\n"
    ctx = ctx_for(profile="standard", wellknown={"/.well-known/security.txt": _wk("/.well-known/security.txt", 200, body)})
    (i,) = rules_of(run(ctx))["WEB900"]
    assert i.severity == "low" and set(i.params["problems"]) == {"expired", "unknown_field"}
    assert len(i.notes) == 2


def test_security_txt_html_catch_all_or_text_catch_all_is_absent():
    shell = page("Home", "<p>Welcome to the site.</p>" * 20)
    ctx = ctx_for(profile="standard", wellknown={"/.well-known/security.txt": _wk("/.well-known/security.txt", 200, shell,
                                                                                    HTML)})
    issues = rules_of(run(ctx))
    assert "WEB060" in issues and "WEB900" not in issues
    ok = ctx_for(profile="standard", wellknown={"/.well-known/security.txt": _wk("/.well-known/security.txt", 200, "OK\n"),
                                                "/robots.txt": _wk("/robots.txt", 200, "OK\n")})
    issues = rules_of(run(ok))
    assert "WEB060" in issues and "WEB900" not in issues and state(ok, "WEB061") == "not_applicable"


def test_security_txt_forbidden_is_absent_and_server_error_not_tested():
    ctx = ctx_for(profile="standard", wellknown={"/.well-known/security.txt": _wk("/.well-known/security.txt", 403, "no")})
    assert "WEB060" in rules_of(run(ctx))
    ctx = ctx_for(profile="standard", wellknown={"/.well-known/security.txt": _wk("/.well-known/security.txt", 503, "x")})
    assert not run(ctx)
    assert state(ctx, "WEB060") == "not_tested" and state(ctx, "WEB900") == "not_tested"


def test_security_txt_over_http_is_low():
    entry = resp("/", 200, HTML, ENTRY_HTML, source="entry", base="http://example.test")
    ctx = ctx_for(profile="standard", entry=entry, wellknown={
        "/.well-known/security.txt": _wk("/.well-known/security.txt", 200, VALID_SECTXT, base="http://example.test")})
    (i,) = rules_of(run(ctx))["WEB900"]
    assert i.severity == "low" and "http_only" in i.params["problems"]


def test_minimal_profile_does_not_judge_well_known_files():
    ctx = ctx_for(profile="minimal")
    assert not run(ctx)
    for c in ("WEB060", "WEB900", "WEB061"):
        assert ctx.coverage.state(c).reasons[0][0] == "profile"


# =============================================================================================== WEB061

@pytest.mark.parametrize("path, hit", [
    ("/admin/", True), ("/backup.zip", True), ("/.git", True), ("/.env", True), ("/app/config/", True),
    ("/old", True), ("/phpmyadmin/", True), ("/administration-guide", False), ("/wp-admin/", False),
    ("/testimonials", False), ("/search", False), ("/*.sql$", False), ("/dbz/", False), ("/development-blog", False),
])
def test_sensitive_robots_path(path, hit):
    assert exposure.sensitive_robots_path(path) is hit


def test_robots_reveals_paths_info_firm_and_inventory():
    body = "User-agent: *\nDisallow: /admin/\nDisallow: /search\nAllow: /backup/\nSitemap: https://example.test/s.xml\n"
    ctx = ctx_for(profile="standard", wellknown={"/robots.txt": _wk("/robots.txt", 200, body)})
    (i,) = rules_of(run(ctx))["WEB061"]
    assert i.confidence == "firm" and i.params["paths"] == ["/admin/", "/backup/"]
    assert ctx.inventory["robots"]["disallow"] == ["/admin/", "/search"]
    assert ctx.inventory["robots"]["sitemaps"] == ["https://example.test/s.xml"]


def test_robots_without_sensitive_paths_passes():
    ctx = ctx_for(profile="standard", wellknown={"/robots.txt": _wk("/robots.txt", 200, "User-agent: *\nDisallow: /tmp/\n")})
    assert not run(ctx) and state(ctx, "WEB061") == "pass"


def test_robots_html_page_is_not_robots():
    ctx = ctx_for(profile="standard", wellknown={"/robots.txt": _wk("/robots.txt", 200, page("x", "Disallow: /admin/"),
                                                                    HTML)})
    assert not run(ctx) and state(ctx, "WEB061") == "not_applicable"


# =============================================================================================== WEB901

GH_404 = page("Site not found", "<h1>404</h1><p><strong>There isn't a GitHub Pages site here.</strong></p>")
HOST = "www.example.test"


def _takeover_ctx(record: DnsRecord | None, *, status: int = 404, body: str = GH_404, **kw) -> ScanContext:
    entry = resp(f"https://{HOST}/", status, HTML, body, source="entry", base=f"https://{HOST}")
    ctx = ScanContext(options=ScanOptions(profile="standard"), target=f"https://{HOST}/", entry=entry, **kw)
    if record is not None:
        ctx.dns[HOST] = record
    ctx.coverage = coverage.Coverage()
    return ctx


def test_takeover_matches_the_canonical_name_index_0():
    # gethostbyname_ex("www.victim.test") -> ("victim.github.io", ["www.victim.test"], [...]) (probe/p10_dnsserver.py)
    rec = DnsRecord(HOST, "ok", ("127.0.0.1",), canonical="gone-user.github.io", aliases=(HOST,))
    ctx = _takeover_ctx(rec)
    (i,) = rules_of(run(ctx))["WEB901"]
    assert i.severity in (None, "high") and i.confidence == "firm"
    assert i.params == {"provider": "GitHub Pages", "cname": "gone-user.github.io"}
    assert i.evidence.match["where"] == "dns" and "There isn't a GitHub Pages site here." in i.evidence.match["excerpt"]
    assert state(ctx, "WEB901") == "fail"


def test_takeover_matches_an_intermediate_alias():
    rec = DnsRecord(HOST, "ok", ("127.0.0.1",), canonical="edge.cdn-front.test", aliases=(HOST, "gone-user.github.io"))
    assert "WEB901" in rules_of(run(_takeover_ctx(rec)))


def test_takeover_needs_cname_body_and_status():
    no_cname = DnsRecord(HOST, "ok", ("127.0.0.1",), canonical=HOST, aliases=())
    ctx = _takeover_ctx(no_cname)
    assert not run(ctx) and state(ctx, "WEB901") == "pass"
    cname = DnsRecord(HOST, "ok", ("127.0.0.1",), canonical="user.github.io", aliases=(HOST,))
    assert not run(_takeover_ctx(cname, body=page("My blog", "<p>hello</p>")))      # live site: no fingerprint
    assert not run(_takeover_ctx(cname, status=200))                                  # wrong status for the template


def test_takeover_on_a_provider_that_no_longer_allows_it_is_never_reported():
    rec = DnsRecord(HOST, "ok", ("127.0.0.1",), canonical="gone.herokuapp.com", aliases=(HOST,))
    ctx = _takeover_ctx(rec, body=page("Heroku", "<p>No such app</p>"))
    assert not run(ctx)
    assert ctx.inventory["takeover"][0]["fingerprint"] is True and ctx.inventory["takeover"][0]["vulnerable"] is False


def test_takeover_on_the_providers_own_name_is_not_a_cname():
    host = "user.github.io"
    entry = resp(f"https://{host}/", 404, HTML, GH_404, source="entry", base=f"https://{host}")
    ctx = ScanContext(options=ScanOptions(), target=f"https://{host}/", entry=entry)
    ctx.dns[host] = DnsRecord(host, "ok", ("127.0.0.1",), canonical=host)
    ctx.coverage = coverage.Coverage()
    assert not run(ctx)


def test_takeover_states_for_proxy_ip_and_missing_dns():
    rec = DnsRecord(HOST, "ok", canonical="gone-user.github.io", aliases=(HOST,))
    ctx = _takeover_ctx(rec, proxied=True)
    assert not run(ctx) and ctx.coverage.state("WEB901").reasons[0][0] == "proxied"
    ctx = _takeover_ctx(None)
    assert not run(ctx) and state(ctx, "WEB901") == "not_tested"
    entry = resp("https://127.0.0.1/", 404, HTML, GH_404, source="entry", base="https://127.0.0.1")
    ctx = ScanContext(options=ScanOptions(), target="https://127.0.0.1/", entry=entry)
    ctx.coverage = coverage.Coverage()
    assert not run(ctx) and state(ctx, "WEB901") == "not_applicable"
    nt = DnsRecord(HOST, "not_tested", reason="proxied")
    ctx = _takeover_ctx(nt)
    assert not run(ctx) and state(ctx, "WEB901") == "not_tested"


def test_cname_provider_helper():
    provs = exposure.providers()
    hit = exposure.cname_provider("shop.example.test", "x.myshopify.com", ["shop.example.test"], provs)
    assert hit and hit[0].name == "Shopify" and hit[1] == "x.myshopify.com"
    assert exposure.cname_provider("a.example.test", "notgithub.io.example.test", [], provs) is None
    assert exposure.cname_provider("a.example.test", "evilgithub.io", [], provs) is None       # suffix, not substring


def test_dangling_hint_is_bilingual():
    en, ar = exposure.dangling_hint()
    assert "dangling DNS record" in en and "DNS" in ar and any("؀" <= c <= "ۿ" for c in ar)


# =============================================================================================== robustness, i18n

def test_run_with_an_empty_context_never_raises_and_records_every_check(make_ctx):
    ctx = make_ctx(profile="deep")
    ctx.coverage = coverage.Coverage()
    assert exposure.run(ctx) == []
    for c in OWN:
        assert ctx.coverage.state(c).state in ("not_tested", "not_applicable"), c


def test_hostile_bodies_do_not_crash_or_leak_controls():
    nasty = "\x1b[31mAPP_ENV=x\x07\nDB_PASSWORD=\x1b]8;;http://evil\x07y\n" + "A" * 300_000
    ctx = ctx_for(probes=[resp("/.env", 200, PLAIN, nasty)],
                  wellknown={"/.well-known/security.txt": _wk("/.well-known/security.txt", 200,
                                                              "Contact: \x1b[2Jmailto:x@example.test\nExpires: x\n"),
                             "/robots.txt": _wk("/robots.txt", 200, "Disallow: /admin/\x1b[0m\n" * 5000)})
    for i in run(ctx):
        blob = json.dumps(i.evidence.to_dict()) + json.dumps(i.notes)
        assert "\\u001b" not in blob and "\\u0007" not in blob, i.rule


def test_i18n_catalog_has_every_note_and_path_text():
    catalog, patterns = exposure.i18n_catalog()
    for p in exposure.exposed_paths():
        assert catalog[p.title_ar] == p.title_en
    assert catalog[exposure.STR["dangling"][1]] == exposure.STR["dangling"][0]
    assert patterns
    for en, ar in exposure.STR.values():
        assert en and ar and any("؀" <= c <= "ۿ" for c in ar)
    assert sectxt.STR["no_contact"][1] in catalog


# =============================================================================================== C-EXP corpus (offline)

sys.path.insert(0, str(ROOT / "bench" / "web"))
try:
    corpus = importlib.import_module("corpus")
except Exception:                                     # pragma: no cover - bench/ absent in a trimmed checkout
    corpus = None
finally:
    sys.path.pop(0)
CORPUS_CASES = [c for c in corpus.CASES if set(c.labels) & OWN] if corpus else []


class _Sim:
    """Renders one corpus case in-process the way the engine would fetch it (no sockets): the entry chain, the
    well-known files (legacy security.txt only after a 404), and for ``probe()`` a Fetcher-like object."""

    def __init__(self, case):
        self.case = case
        self.srv = corpus.CorpusServer([case], mode="host", with_tls=False)
        self.srv.http_port, self.srv.https_port = 8080, 8443
        self.hosts = {h.lower(): a for h, a in case.all_hosts().items()}
        self.calls: list[str] = []

    def url(self, path: str) -> str:
        return f"{self.case.scheme}://{self.case.host}:{self.srv.port_for(self.case, self.case.scheme)}{path}"

    def remaining_requests(self, source: str = "entry") -> int:
        return 150 - len(self.calls)

    def fetch(self, url: str, *, source: str = "entry", follow: bool = True, accept=None, **kw) -> Response:
        hops: list[Response] = []
        for _ in range(10):
            self.calls.append(url)
            p = urllib.parse.urlsplit(url)
            alias = self.hosts.get((p.hostname or "").lower())
            if alias is None:
                return Response(url=url, status=None, error="unroutable", source=source,
                                flags=frozenset({"error:network"}))
            hdrs = {"user-agent": ["Kashif-test"], "accept": ["*/*"]}
            hits, case_hits = self.srv.count(self.case.id, alias, p.path or "/")
            req = corpus.Req(self.case, alias, p.path or "/", p.query, hdrs, p.scheme, hits, case_hits, self.srv,
                             p.netloc)
            r = self.srv.respond(req)
            per: dict = {}
            hl = [(n, corpus._render(v, req, per) if isinstance(v, str) else v.decode("latin-1")) for n, v in r.headers]
            body = r.body if isinstance(r.body, bytes) else corpus._render(r.body, req, per).encode("utf-8")
            resp_ = Response(url=url, status=r.status, headers=HeaderList(tuple(hl)), body=body, source=source,
                             request_headers=HeaderList((("User-Agent", "Kashif-test"), ("Accept", "*/*"))),
                             ip="127.0.0.1")
            loc = resp_.location
            if follow and resp_.status and 300 <= resp_.status < 400 and loc:
                hops.append(resp_)
                url = loc
                continue
            resp_.chain = hops
            return resp_
        last = hops.pop()
        last.chain = hops
        return last

    def context(self) -> ScanContext:
        from vulnscan.webscan import tech               # tests may combine modules; check modules never do
        c = self.case
        opts = ScanOptions(profile=c.profile, sensitivity=c.sensitivity)
        entry = self.fetch(self.url(c.path))
        ctx = ScanContext(options=opts, target=self.url(c.path), entry=entry, fetcher=self)
        ctx.coverage = coverage.Coverage()
        if c.profile != "minimal":
            for p in ("/robots.txt", "/.well-known/security.txt", "/favicon.ico"):
                ctx.wellknown[p] = self.fetch(self.url(p), source="wellknown")
            if ctx.wellknown["/.well-known/security.txt"].status == 404:
                ctx.wellknown["/security.txt"] = self.fetch(self.url("/security.txt"), source="wellknown")
        host = c.host
        spec = c.dns.get(host) or {}
        if spec.get("status", "ok") == "ok":
            ctx.dns[host] = DnsRecord(host, "ok", ("127.0.0.1",), canonical=spec.get("canonical", host),
                                      aliases=tuple(spec.get("aliases", ())))
        else:
            ctx.dns[host] = DnsRecord(host, spec["status"])
        for r in ctx.all_responses():
            classify.classify(r, htmlparse.parse_response(r) if r.essence in ("text/html", "") and r.body else None)
        if entry.kind == "document":
            ctx.pages.append(Page(entry, htmlparse.parse_response(entry), 0))
        tech.detect(ctx)
        exposure.probe(ctx)
        classify.classify_context(ctx)
        return ctx


@pytest.mark.skipif(corpus is None, reason="bench/web/corpus.py not present")
@pytest.mark.parametrize("case", CORPUS_CASES, ids=[c.id for c in CORPUS_CASES])
def test_corpus_case_labels(case):
    sim = _Sim(case)
    ctx = sim.context()
    issues = exposure.run(ctx)
    shown = {}
    for i in issues:
        if ctx.options.reports(i.confidence):
            shown.setdefault(i.rule, []).append(i)
    for rule, want in case.labels.items():
        if rule in OWN:
            got = shown.get(rule, [])
            assert bool(got) is want, f"{case.id}: {rule} expected {'to fire' if want else 'silent'}, got " \
                                      f"{[(i.params, i.notes[:1]) for i in got]!r}"
            if not want:
                assert ctx.coverage.state(rule).state != "fail", (case.id, rule)
    for path in case.expect.get("server_never", []):
        assert not any(urllib.parse.urlsplit(u).path == path for u in sim.calls), (case.id, path)


@pytest.mark.skipif(corpus is None, reason="bench/web/corpus.py not present")
def test_corpus_covers_every_wp11_rule_with_positive_and_trap_cases():
    groups = {c.id for c in corpus.CASES if c.group == "C-EXP"}
    assert groups <= {c.id for c in CORPUS_CASES}
    for rule in OWN:
        labels = [c.labels[rule] for c in CORPUS_CASES if rule in c.labels]
        assert True in labels, rule


# =============================================================================================== adversarial review

SHORT_SECTXT = "Contact: mailto:s@example.test\nExpires: 2027-05-13T00:00:00Z\n"
OK_BASELINE = "/kashif-404-0123456789abcdef"


def test_short_real_security_txt_is_not_dismissed_by_a_short_catch_all_baseline():
    # deep mode, every unknown path answers 200 text/plain "OK": a 60-byte security.txt is within 64 bytes of it
    base = resp(OK_BASELINE, 200, PLAIN, "OK\n", source="baseline")
    wk = resp("/.well-known/security.txt", 200, PLAIN, SHORT_SECTXT, source="wellknown")
    assert classify.Soft404Index.match(_index(base), wk) is not None          # the §3.2 test alone says "similar"
    ctx = ctx_for(wellknown={"/.well-known/security.txt": wk}, baselines=[base])
    classify.classify_context(ctx)
    issues = rules_of(run(ctx))
    assert "WEB060" not in issues and state(ctx, "WEB060") == "pass" and state(ctx, "WEB900") == "pass"


def test_catch_all_that_serves_the_same_security_txt_everywhere_is_still_absent():
    base = resp(OK_BASELINE, 200, PLAIN, SHORT_SECTXT, source="baseline")
    wk = resp("/.well-known/security.txt", 200, PLAIN, SHORT_SECTXT, source="wellknown")
    ctx = ctx_for(wellknown={"/.well-known/security.txt": wk}, baselines=[base])
    classify.classify_context(ctx)
    assert "WEB060" in rules_of(run(ctx))


def test_short_robots_txt_next_to_a_short_catch_all_is_still_judged():
    base = resp(OK_BASELINE, 200, PLAIN, "OK\n", source="baseline")
    rb = resp("/robots.txt", 200, PLAIN, "User-agent: *\nDisallow: /admin/\n", source="wellknown")
    ctx = ctx_for(wellknown={"/robots.txt": rb}, baselines=[base])
    classify.classify_context(ctx)
    assert "WEB061" in rules_of(run(ctx))


def test_html_page_with_a_contact_line_is_not_a_security_txt():
    body = ("<!doctype html>\n<html><head><title>Not found</title></head><body>\nContact: support@example.test\n"
            "</body></html>\n")
    wk = resp("/.well-known/security.txt", 200, HTML, body, source="wellknown")
    ctx = ctx_for(profile="standard", wellknown={"/.well-known/security.txt": wk})
    issues = rules_of(run(ctx))
    assert "WEB900" not in issues and "WEB060" in issues


def test_real_security_txt_served_as_text_html_is_present_and_invalid():
    wk = resp("/.well-known/security.txt", 200, "text/html", SHORT_SECTXT, source="wellknown")
    ctx = ctx_for(profile="standard", wellknown={"/.well-known/security.txt": wk})
    (i,) = rules_of(run(ctx))["WEB900"]
    assert "content_type" in i.params["problems"]


_MOODLE_ENTRY = page("My University", "<a href='/login/index.php'>Log in</a>" + "<p>Moodle courses for everyone</p>" * 20)
_MOODLE_LOGIN = page("My University: Log in to the site", '<form action="/login/index.php" method="post">'
                     '<input name="username"><input type="password" name="password"></form><p>moodle</p>')


@pytest.mark.parametrize("path, entry_body, body, base_path", [
    ("/login/index.php", _MOODLE_ENTRY, _MOODLE_LOGIN, "/login/kashif-404-0123456789abcdef.php"),
    ("/wp-login.php", page("Blog", "<p>Post</p>" * 30 + "<a href='/wp-login.php'>Log in</a>"),
     page("Log In", '<form id="loginform" action="/wp-login.php"><input name="log"><input type="password" name="pwd">'
                    '<input type="submit" name="wp-submit"></form>'), "/kashif-404-0123456789abcdef.php"),
])
def test_login_page_is_found_when_the_homepage_links_to_it_and_unknown_paths_redirect(path, entry_body, body,
                                                                                    base_path):
    # a "404 to homepage" redirect is a baseline that answered: unknown paths do not get the login page, so the entry
    # document carrying the marker (Moodle's name, WordPress's "Log in" link) says nothing about this probe
    entry = resp("/", 200, HTML, entry_body, source="entry")
    base = resp(base_path, 301, HTML, "", source="baseline", headers=(("Location", BASE + "/"),))
    v = exposure.judge(resp(path, 200, HTML, body), _spec(path), _index(base), {}, entry)
    assert v.state == "exposed"
    # without any baseline the entry check stays (it may be the shell of an SPA)
    v = exposure.judge(resp(path, 200, HTML, body), _spec(path), classify.Soft404Index(), {}, entry)
    assert v.state == "clean"


def test_phpinfo_signature_is_bounded_on_a_hostile_body():
    import time
    body = ("<html><body>" + "PHP Version " * 25_000)[:256_000].encode()
    t = time.perf_counter()
    assert exposure.match_signature(_spec("/phpinfo.php").signature, body) is None
    assert time.perf_counter() - t < 1.0


GH_CLAIMED_404 = page("Page not found", "<h1>404</h1><p><strong>File not found</strong></p><p>The site configured at "
                      "this address does not contain the requested file.</p><p>For root URLs (like "
                      "<code>http://example.com/</code>) you must provide an index.html file.</p>")


def test_github_pages_missing_file_on_a_claimed_site_is_not_a_takeover():
    rec = DnsRecord(HOST, "ok", ("127.0.0.1",), canonical="owner.github.io", aliases=(HOST,))
    ctx = _takeover_ctx(rec, body=GH_CLAIMED_404)
    assert not run(ctx) and state(ctx, "WEB901") == "pass"


def test_takeover_is_judged_on_the_site_root_only():
    # Big Cartel's fingerprint is its ordinary 404 page: a live shop shows it for a missing deep URL too
    rec = DnsRecord(HOST, "ok", ("127.0.0.1",), canonical="shop.bigcartel.com", aliases=(HOST,))
    oops = page("Oops", "<h1>Oops! We couldn&#8217;t find that page.</h1>")
    deep = resp(f"https://{HOST}/products/old-item", 404, HTML, oops, source="entry", base=f"https://{HOST}")
    ctx = ScanContext(options=ScanOptions(profile="standard"), target=deep.url, entry=deep)
    ctx.dns[HOST] = rec
    ctx.coverage = coverage.Coverage()
    assert not run(ctx)
    st = ctx.coverage.state("WEB901")
    assert st.state == "not_tested" and "root" in st.reasons[0][1]
    assert "WEB901" in rules_of(run(_takeover_ctx(rec, body=oops)))           # at "/" it is the unclaimed page


def test_campaign_monitor_live_page_is_not_a_takeover():
    rec = DnsRecord(HOST, "ok", ("127.0.0.1",), canonical="example.createsend.com", aliases=(HOST,))
    live = page("Subscribe", '<link rel="stylesheet" href="https://css.createsend1.com/css/social.min.css">')
    assert not run(_takeover_ctx(rec, status=200, body=live))
    names = {p.name for p in exposure.providers()}
    assert "GitHub Pages" in names and "Campaign Monitor" not in names


def test_optional_all_words_of_a_provider_must_all_appear():
    class Stub:
        def load_json(self, name):
            if name == "takeover.json":
                return {"providers": [{"name": "Two Words", "cname": ["twowords.test"], "fingerprints": ["first"],
                                       "fingerprints_all": ["second"], "status": None, "vulnerable": True}]}
            return data.load_json(name)
    rec = DnsRecord(HOST, "ok", ("127.0.0.1",), canonical="x.twowords.test", aliases=(HOST,))
    assert not run(_takeover_ctx(rec, body=page("x", "first"), data=Stub()))
    assert "WEB901" in rules_of(run(_takeover_ctx(rec, body=page("x", "first and second"), data=Stub())))


def test_robots_paths_with_control_characters_are_cleaned_in_params():
    rb = resp("/robots.txt", 200, PLAIN, "User-agent: *\nDisallow: /admin/\x1b[2J\n", source="wellknown")
    ctx = ctx_for(profile="standard", wellknown={"/robots.txt": rb})
    (i,) = rules_of(run(ctx))["WEB061"]
    assert all("\x1b" not in p for p in i.params["paths"])
    assert all("\x1b" not in p for p in ctx.inventory["robots"]["disallow"])


def test_crossdomain_evidence_shows_the_wildcard_element_not_the_first_one():
    body = ('<?xml version="1.0"?><cross-domain-policy><allow-access-from domain="*.example.test"/>'
            '<allow-access-from domain="*" secure="false"/></cross-domain-policy>')
    (i,) = rules_of(run(ctx_for(probes=[resp("/crossdomain.xml", 200, "text/xml", body)])))["WEB903"]
    assert 'domain="*"' in i.evidence.match["value"] and any('secure="false"' in en for en, _ in i.notes)
    safe = body.replace(' secure="false"', "").replace('*.example.test"/>', '*.example.test" secure="false"/>')
    (j,) = rules_of(run(ctx_for(probes=[resp("/crossdomain.xml", 200, "text/xml", safe)])))["WEB903"]
    assert not any('secure="false"' in en for en, _ in j.notes)


def test_hostile_deeply_nested_actuator_index_does_not_abort_the_deep_checks():
    body = '{"_links": {"self": {"href": "https://example.test/actuator"}}, "x": ' + "[" * 200_000
    probes = [resp("/actuator", 200, "application/json", body),
              resp("/.git/HEAD", 200, PLAIN, "ref: refs/heads/main\n")]
    base = resp("/kashif-404-0123456789abcdef", 404, HTML, page("Not found"), source="baseline")
    ctx = ctx_for(probes=probes, baselines=[base])
    issues = rules_of(run(ctx))
    assert {i.params["path"] for i in issues["WEB062"]} == {"/actuator", "/.git/HEAD"}


_HOSTILE_FRAGMENTS = ("\n", "\n ", " \n", "\t", "PHP Version ", "<access-policy><allow-from>", "<allow-from>", "$a[x]",
                      "[", "services:\n", '"host":', "<input ")


@pytest.mark.parametrize("fragment", _HOSTILE_FRAGMENTS)
def test_every_exposed_path_signature_is_linear_on_a_hostile_probe_body(fragment):
    # a probe body is capped at 256 KB (http.CAPS["probe"]); "^\s*" under re.M made /.htaccess take ~40 min on
    # 256 KB of newlines (quadratic backtracking), which a hostile server could use to stall the scan
    import time
    body = (fragment * (256_000 // len(fragment) + 1))[:256_000].encode()
    for spec in exposure.exposed_paths() + list(exposure.POLICY_FILES.values()):
        t = time.perf_counter()
        exposure.match_signature(spec.signature, body)
        assert time.perf_counter() - t < 1.5, (spec.path, fragment)
