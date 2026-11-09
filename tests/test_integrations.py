"""SARIF output, stable fingerprints, baselines, provider-token rules and entropy secret detection.

Fake tokens are assembled by concatenation so the test source never contains a literal that looks like a
real credential (keeps GitHub push protection and other scanners quiet)."""

import json

from vulnscan.baseline import apply_baseline, load_baseline, save_baseline
from vulnscan.cli import main
from vulnscan.model import Finding, assign_fingerprints
from vulnscan.report import render_sarif
from vulnscan.scanner import _entropy_findings, _shannon, scan_path


def _f(rule="X1", file="a.py", line=1, snippet="bad()", sev="high", **extra):
    return Finding(rule, sev, "T", "ع", file, line, snippet, "advice", "CWE-89", extra=dict(extra))


def _ids(findings):
    return {f.rule_id for f in findings}


# ---------------------------------------------------------------- fingerprints

def test_fingerprint_ignores_line_and_whitespace():
    a = _f(line=3, snippet='secret = "x"')
    b = _f(line=40, snippet='secret="x"')
    assert a.fingerprint() == b.fingerprint()


def test_fingerprint_differs_by_rule_file_snippet():
    base = _f()
    assert base.fingerprint() != _f(rule="X2").fingerprint()
    assert base.fingerprint() != _f(file="b.py").fingerprint()
    assert base.fingerprint() != _f(snippet="other()").fingerprint()


def test_duplicate_findings_get_distinct_fingerprints():
    fs = [_f(line=1), _f(line=9)]
    assign_fingerprints(fs)
    assert len({f.fingerprint() for f in fs}) == 2
    fs2 = [_f(line=9), _f(line=1)]          # order of discovery must not matter
    assign_fingerprints(fs2)
    assert {f.fingerprint() for f in fs} == {f.fingerprint() for f in fs2}


def test_to_dict_carries_fingerprint():
    assert _f().to_dict()["fingerprint"].endswith(":0")


# ---------------------------------------------------------------- SARIF

def test_sarif_structure():
    fs = [_f(rule="A1", sev="critical", path=[{"file": "a.py", "line": 1, "what": "source"},
                                           {"file": "a.py", "line": 5, "what": "sink"}]),
          _f(rule="B2", sev="low", file="dir/b.js", line=7)]
    doc = json.loads(render_sarif(fs, "/proj", 2, []))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "vulnscan"
    rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    assert set(rules) == {"A1", "B2"}
    assert rules["A1"]["properties"]["security-severity"] == "9.5"
    res = {r["ruleId"]: r for r in run["results"]}
    assert res["A1"]["level"] == "error" and res["B2"]["level"] == "note"
    loc = res["B2"]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "dir/b.js" and loc["region"]["startLine"] == 7
    assert res["A1"]["partialFingerprints"]["vulnscan/v1"]
    assert res["A1"].get("codeFlows")


def test_sarif_file_level_finding_has_valid_region(tmp_path):
    doc = json.loads(render_sarif([_f(line=0)], str(tmp_path), 1, []))
    region = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"].get("region")
    assert region is None or region.get("startLine", 1) >= 1     # SARIF requires startLine >= 1


def test_cli_sarif(tmp_path, capsys):
    (tmp_path / "app.py").write_text("import pickle\npickle.loads(d)\n")
    out = tmp_path / "r.sarif"
    main([str(tmp_path), "--no-deps", "--no-external", "-f", "sarif", "-o", str(out)])
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["runs"][0]["results"]


# ---------------------------------------------------------------- baseline

def test_baseline_roundtrip(tmp_path):
    p = tmp_path / "b.json"
    fs = [_f(), _f(rule="X2")]
    assert save_baseline(fs, str(p)) == 2
    assert len(load_baseline(str(p))) == 2
    new, suppressed, size = apply_baseline([_f(line=99), _f(rule="X3")], str(p))
    assert (suppressed, size) == (1, 2)
    assert [f.rule_id for f in new] == ["X3"] and new[0].extra["new"] is True


def test_baseline_missing_file_marks_all_new(tmp_path):
    new, suppressed, size = apply_baseline([_f()], str(tmp_path / "nope.json"))
    assert (len(new), suppressed, size) == (1, 0, 0)


def test_baseline_corrupt_file(tmp_path):
    p = tmp_path / "b.json"
    p.write_text("{not json")
    assert load_baseline(str(p)) == set()


def test_baseline_second_duplicate_is_new(tmp_path):
    """Baseline has one copy of an issue; a second identical copy appearing later must be reported."""
    p = tmp_path / "b.json"
    save_baseline([_f(line=1)], str(p))
    new, suppressed, _ = apply_baseline([_f(line=1), _f(line=20)], str(p))
    assert suppressed == 1 and len(new) == 1


def test_cli_baseline_flow(tmp_path, capsys):
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text("import pickle\npickle.loads(d)\n")
    base = tmp_path / "base.json"
    assert main([str(src), "--no-deps", "--no-external", "--write-baseline", str(base)]) == 0
    out = tmp_path / "r.json"
    main([str(src), "--no-deps", "--no-external", "--baseline", str(base), "-f", "json", "-o", str(out)])
    assert json.loads(out.read_text(encoding="utf-8"))["findings"] == []
    # reformat the known line and add a new issue: only the new one is reported, and --fail-on sees it
    (src / "app.py").write_text("import pickle, subprocess\n\n\npickle.loads( d )\nsubprocess.call(c, shell=True)\n")
    rc = main([str(src), "--no-deps", "--no-external", "--baseline", str(base), "-f", "json", "-o", str(out),
               "--fail-on", "high"])
    found = json.loads(out.read_text(encoding="utf-8"))["findings"]
    assert found and all("pickle" not in f["snippet"] for f in found)
    assert rc == 1


# ---------------------------------------------------------------- provider token rules

def _scan(tmp_path, name, text):
    (tmp_path / name).write_text(text)
    findings, _ = scan_path(tmp_path, [], set())
    return findings


def test_provider_tokens(tmp_path):
    sg = "SG." + "aB3dE5fG7hJ9kL1mN3pQ5r" + "." + "sT7uV9wX1yZ3aB5cD7eF9gH1jK3lM5nP7qR9sT1uV3w"
    gh_npm = "npm_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
    text = f'SENDGRID = "{sg}"\nNPM = "{gh_npm}"\n'
    assert "SEC007" in _ids(_scan(tmp_path, "cfg.py", text))


def test_webhook_rule(tmp_path):
    url = "https://hooks." + "slack.com/services/" + "T01ABCDEF/B01ABCDEF/" + "aBcDeFgHiJkLmNoPqRsTuVwX"
    assert "SEC008" in _ids(_scan(tmp_path, "notify.py", f'HOOK = "{url}"\n'))


def test_gcp_service_account(tmp_path):
    doc = '{\n  "type": "service' + '_account",\n  "project_id": "p"\n}\n'
    assert "SEC009" in _ids(_scan(tmp_path, "key.json", doc))


def test_azure_storage(tmp_path):
    cs = "DefaultEndpoints" + "Protocol=https;AccountName=acct;AccountKey=" + "Zm9vYmFy" * 8 + "=="
    assert "SEC010" in _ids(_scan(tmp_path, "settings.py", f'CONN = "{cs}"\n'))


# ---------------------------------------------------------------- entropy

def test_shannon():
    assert _shannon("") == 0 and _shannon("aaaa") == 0
    assert abs(_shannon("ab") - 1.0) < 1e-9


def test_entropy_flags_secret_assignment():
    tok = "q8Zr" + "T3vLx9" + "Pw2Nk7Ys" + "4Hd6Bm1C"
    fs = _entropy_findings("a.py", 1, f'api_key = "{tok}"')
    assert fs and fs[0].rule_id == "SEC011"


def test_entropy_flags_standalone_long_token():
    tok = "Xk9" + "pQ2vLr7TzN4wYb8HsJ3mCd6Fg1Ke5RaU0" + "oVi2Wq8Ex4Zt"
    assert _entropy_findings("a.py", 1, f'X = "{tok}"')


def test_entropy_skips_benign():
    benign = [
        'commit = "3f786850e387550fdab836ed7e6dc881de23001b"',                 # hex sha, no secret name
        'api_key = "your_api_key_here_please_replace"',                         # placeholder
        'token = os.environ["GITHUB_TOKEN_FOR_DEPLOYMENTS"]',                   # env lookup, no digits
        'import x from "./components/SomethingVeryLongComponentName"',
        '<script integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC">',
        'img = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAD"',
    ]
    for line in benign:
        assert not _entropy_findings("a.py", 1, line), line


def test_entropy_not_duplicated_when_regex_rule_hits(tmp_path):
    fs = _scan(tmp_path, "c.py", "AWS = 'AKIA" + "IOSFODNN7" + "QWERTZ'\n")
    assert "SEC011" not in _ids(fs)


def test_entropy_respects_ignore_rule(tmp_path):
    tok = "Xk9" + "pQ2vLr7TzN4wYb8HsJ3mCd6Fg1Ke5RaU0" + "oVi2Wq8Ex4Zt"
    (tmp_path / "a.py").write_text(f'BLOB = "{tok}"\n')
    assert "SEC011" in _ids(scan_path(tmp_path, [], set())[0])
    assert "SEC011" not in _ids(scan_path(tmp_path, [], {"SEC011"})[0])


def test_list_rules_includes_new_rules(capsys):
    main(["--list-rules"])
    out = capsys.readouterr().out
    for rid in ("SEC007", "SEC008", "SEC009", "SEC010", "SEC011"):
        assert rid in out


# ---------------------------------------------------------------- regressions from adversarial review

def _sarif_of(tmp_path, files):
    for name, body in files.items():
        p = tmp_path / "src" / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    out = tmp_path / "r.sarif"
    main([str(tmp_path / "src"), "--no-deps", "--no-external", "-f", "sarif", "-o", str(out)])
    return json.loads(out.read_text(encoding="utf-8"))


def test_sarif_uris_are_percent_encoded(tmp_path):
    doc = _sarif_of(tmp_path, {"my dir/app 1.py": "eval(input())\n", "مجلد/ملف.py": "eval(input())\n",
                               "a#b%20.py": "eval(input())\n", "fix:eval.py": "eval(input())\n"})
    uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in doc["runs"][0]["results"]}
    assert "my%20dir/app%201.py" in uris and "a%23b%2520.py" in uris and "fix%3Aeval.py" in uris
    assert any(u.startswith("%D9%85") for u in uris)          # Arabic, UTF-8 percent-encoded
    assert all(" " not in u and "#" not in u for u in uris)
    assert doc["runs"][0]["originalUriBaseIds"]["%SRCROOT%"]["uri"].startswith("file:///")


def test_sarif_web_findings_point_at_url():
    f = Finding("WEB-x-frame-options", "medium", "Missing X-Frame-Options", "ع", "example.com:8443", 0,
                "HTTP 200", "advice", "CWE-1021", source="web")
    loc = json.loads(render_sarif([f], "https://example.com:8443/", 1, []))["runs"][0]["results"][0]
    phys = loc["locations"][0]["physicalLocation"]
    assert phys["artifactLocation"]["uri"] == "https://example.com:8443/" and "region" not in phys


def test_all_reports_share_fingerprints(tmp_path):
    src = tmp_path / "p"
    src.mkdir()
    (src / "a.py").write_text("import os\nos.system(cmd)\n")
    base = tmp_path / "b.json"
    main([str(src), "--no-deps", "--no-external", "--write-baseline", str(base)])
    (src / "a.py").write_text("import os\nos.system(cmd)\nos.system(cmd)\n")
    prefix = tmp_path / "out"
    main([str(src), "--no-deps", "--no-external", "--baseline", str(base), "--all-formats", str(prefix)])
    known = load_baseline(str(base))
    js = [f["fingerprint"] for f in json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))["findings"]]
    sf = [r["partialFingerprints"]["vulnscan/v1"]
          for r in json.loads((tmp_path / "out.sarif").read_text(encoding="utf-8"))["runs"][0]["results"]]
    assert js == sf and len(js) == 1 and js[0] not in known


def test_json_report_fingerprints_unique_without_baseline(tmp_path):
    (tmp_path / "a.py").write_text("import os\nos.system(cmd)\nx = 1\nos.system(cmd)\n")
    out = tmp_path / "r.json"
    main([str(tmp_path), "--no-deps", "--no-external", "-f", "json", "-o", str(out)])
    fps = [f["fingerprint"] for f in json.loads(out.read_text(encoding="utf-8"))["findings"]]
    assert len(fps) == len(set(fps))


def test_baseline_ignores_min_severity(tmp_path):
    src = tmp_path / "q"
    src.mkdir()
    (src / "a.py").write_text("import os, hashlib\nos.system(cmd)\nh = hashlib.md5(x)\n")
    base = tmp_path / "b.json"
    main([str(src), "--no-deps", "--no-external", "--min-severity", "high", "--write-baseline", str(base)])
    assert main([str(src), "--no-deps", "--no-external", "--baseline", str(base), "--fail-on", "low",
                 "-o", str(tmp_path / "r.txt")]) == 0


def test_baseline_survives_archive_rename(tmp_path):
    import zipfile
    for name in ("app-1.0.zip", "app-1.1.zip"):
        with zipfile.ZipFile(tmp_path / name, "w") as z:
            z.writestr("a.py", "import os\nos.system(cmd)\n")
    base = tmp_path / "b.json"
    main([str(tmp_path / "app-1.0.zip"), "--no-deps", "--no-external", "--no-jadx", "--write-baseline", str(base)])
    assert main([str(tmp_path / "app-1.1.zip"), "--no-deps", "--no-external", "--no-jadx", "--baseline", str(base),
                 "--fail-on", "low", "-o", str(tmp_path / "r.txt")]) == 0


def test_web_fingerprint_ignores_cookie_value_and_status():
    def ck(val, status="HTTP 200"):
        return (Finding("WEB021", "medium", "Cookie without HttpOnly flag: sid", "ع", "h", 0, f"sid={val}; Path=/",
                        "a", source="web"),
                Finding("WEB-csp", "medium", "Missing CSP", "ع", "h", 0, status, "a", source="web"))
    a, b = ck("1111"), ck("2222", "HTTP 302")
    assert a[0].fingerprint() == b[0].fingerprint() and a[1].fingerprint() == b[1].fingerprint()


def test_entropy_precision_regressions():
    tok = "Zk3p" + "Q9vX2mT7bN4cR8wY1hL6jF0sD5gA"
    for line in (f'STRIPE_SECRET = "{tok}"  # latest', f'DB_PASSWORD = "{tok}"  # attestation',
                 f'config["api_key"] = "{tok}"', f'h = {{"Authorization": "Bearer {tok}"}}', f'apiKey := "{tok}"'):
        assert _entropy_findings("a", 1, line), line
    uuid = "9b2f6c1e-4d3a-4e8f-a1b2-7c9d0e3f5a61"
    for line in ("findViewById(R.id.authButtonSignInWithGoogle2);",
                 "import org.springframework.security.oauth2.server.resource.authentication.JwtConverter2",
                 "t('auth.loginForm.passwordResetConfirmation2FA')", f'author_id = "{uuid}"', f'csrf_token = "{uuid}"',
                 "ca_bundle: MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJRTESMBAGA1UE",
                 "https://docs.google.com/document/d/1aB2cD3eF4gH5iJ6kL7mN8oP9qR0sT1uV2wX3yZ4AbCd/edit"):
        assert not _entropy_findings("a", 1, line), line


def test_sec007_boundaries_and_facebook(tmp_path):
    from vulnscan.rules import RULES
    pat = next(r for r in RULES if r.id == "SEC007").pattern
    assert pat.search('v = "123456789:AA' + "b" * 32 + '-"')
    assert pat.search('v = "SG.' + "a" * 22 + "." + "b" * 42 + '-"')
    assert pat.search('v = "EAAG' + "aB3" * 40 + '"')
    assert not pat.search("TASK" + "0" * 32)


def test_cli_unreachable_web_returns_2(capsys):
    assert main(["http://127.0.0.1:1/", "--authorized", "--timeout", "1"]) == 2


# ---------------------------------------------------------------- regressions from the second review round

def test_entropy_line_length_is_linear():
    import time
    line = ".".join("abcd_efgh_ijkl_mnop_q1" for _ in range(173))
    t = time.time()
    _entropy_findings("a", 1, line)
    assert time.time() - t < 0.5


def test_entropy_typed_and_call_bindings():
    tok = "Zk3p" + "Q9vX2mT7bN4cR8wY1hL6jF0sD5gA"
    for line in (f'api_key: str = "{tok}"', f'const apiKey: string = "{tok}";', f'var apiKey string = "{tok}"',
                 f"define('API_KEY', '{tok}');", f'props.setProperty("password", "{tok}");',
                 f'<add key="ApiKey" value="{tok}" />', f"ENV API_KEY {tok}", f"apiKey: `{tok}`",
                 f'API_KEY = os.environ.get("API_KEY", "{tok}")', f'"Authorization" => "Basic {tok}"',
                 f'DB_PASSWORD = "{tok}"  # integrity checked', f'export API_TOKEN="{tok}"; echo "${{API_TOKEN}}"'):
        assert _entropy_findings("a", 1, line), line


def test_entropy_reference_names_and_slugs():
    for line in ("secretName: my-app-tls-cert-2024", 'SECRET_ID = "prod/payments/stripe-webhook-v3"',
                 'password_reset_template = "emails/password_reset_v2"', 'pwd = "/home/runner/work/app2/build"',
                 'token_env = "GITHUB_TOKEN_FOR_CI_2"', 'auth: "github-oauth2-provider-v1"',
                 'passwordInputId = "loginForm-passwordInput2"', 'authClass: "OAuth2PasswordBearerV2"'):
        assert not _entropy_findings("a", 1, line), line


def test_bang_in_ordinary_path_is_not_an_archive():
    a = _f(rule="EXE004", file="tools/legacy!a.py", snippet="os.system(cmd)")
    b = _f(rule="EXE004", file="a.py", snippet="os.system(cmd)")
    assert a.fingerprint() != b.fingerprint()


def test_web_volatile_title_and_cookie_attributes():
    def w(rule, title, snip):
        return Finding(rule, "medium", title, "ع", "h", 0, snip, "a", source="web").fingerprint()
    assert w("WEB071", "TLS certificate expires in 10 days", "Nov 18") == \
        w("WEB071", "TLS certificate expires in 9 days", "Nov 18")
    t = "Cookie without HttpOnly flag: sid"
    assert w("WEB021", t, "sid=abc; Path=/; Expires=Sun, 08 Nov 2026 10:00:00 GMT") == \
        w("WEB021", t, ("sid=" + "A" * 100 + "; Path=/; Expires=Mon, 09 Nov 2026 10:00:01 GMT")[:120])


def test_sarif_web_page_urls():
    f = Finding("WEB051", "high", "Form over HTTP", "ع", "/a%20b/p.html", 0, "x", "a", source="web",
                extra={"page": "http://h/a%20b/p.html?x=1"})
    g = Finding("WEB051", "high", "Form over HTTP", "ع", "h", 0, "x", "a", source="web")
    doc = json.loads(render_sarif([f, g], "http://h/dir/q.html?a=1", 1, []))
    uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in doc["runs"][0]["results"]}
    assert uris == {"http://h/a%20b/p.html?x=1", "http://h/dir/q.html?a=1"}


def test_sarif_archive_members_use_archive_root(tmp_path):
    import zipfile
    with zipfile.ZipFile(tmp_path / "app.zip", "w") as z:
        z.writestr("t.py", "import subprocess\nx = input()\nsubprocess.call(x, shell=True)\n")
    out = tmp_path / "r.sarif"
    main([str(tmp_path / "app.zip"), "--no-deps", "--no-external", "--no-jadx", "-f", "sarif", "-o", str(out)])
    run = json.loads(out.read_text(encoding="utf-8"))["runs"][0]
    locs = [r["locations"][0]["physicalLocation"]["artifactLocation"] for r in run["results"]]
    assert locs and all(l["uriBaseId"] == "%ARCHIVEROOT%" and "!" not in l["uri"] for l in locs)
    assert "%ARCHIVEROOT%" in run["originalUriBaseIds"]


def test_server_scan_fingerprints_unique(tmp_path):
    from vulnscan.server import Store, run_scan
    proj = tmp_path / "p"
    proj.mkdir()
    (proj / "a.py").write_text("import os\nos.system(cmd)\nx = 1\nos.system(cmd)\n")
    store = Store(tmp_path / "home")
    scan = store.new_scan(str(proj), "path")
    run_scan(store, scan, {"use_osv": False, "use_external": False, "use_jadx": False}, False)
    fps = [f["fingerprint"] for f in store.get_scan(scan["id"])["findings"]]
    assert len(fps) == 2 and len(set(fps)) == 2


# ---------------------------------------------------------------- regressions from the third review round

def test_sarif_web_urls_encoded_and_probe_locations():
    probe = Finding("WEB062", "high", "Exposed .git", "ع", "h", 0, "/.git/config → HTTP 200", "a", source="web",
                    extra={"page": "http://h/.git/config"})
    entry = Finding("WEB051", "high", "Form over HTTP", "ع", "h", 0, "x", "a", source="web",
                    extra={"pages": ["http://h/sub/p.html"]})
    doc = json.loads(render_sarif([probe, entry], "http://h/?q={x}|^", 1, []))
    uris = {r["ruleId"]: r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for r in doc["runs"][0]["results"]}
    assert uris == {"WEB062": "http://h/.git/config", "WEB051": "http://h/?q=%7Bx%7D%7C%5E"}


def test_web_fingerprint_digit_and_query_handling():
    def ck(name):
        return Finding("WEB021", "medium", f"Cookie without HttpOnly flag: {name}", "ع", "h", 0, f"{name}=v",
                       "a", source="web").fingerprint()
    assert ck("sid1") != ck("sid2")

    def js(url):
        return Finding("WEB053", "low", "External script without SRI", "ع", "h", 0, url, "a",
                       source="web").fingerprint()
    assert js("https://cdn.x/app.js?v=1699") == js("https://cdn.x/app.js?v=1700")
    assert js("https://cdn.x/app.js") != js("https://cdn.x/other.js")


def test_sarif_apex_virtual_file_points_at_export():
    f = Finding("DF001", "high", "DOM XSS", "ع", "f100.sql!Static/app.js", 3, "innerHTML = h", "a")
    loc = json.loads(render_sarif([f], "/nonexistent", 1, []))["runs"][0]["results"][0]["locations"][0]
    phys = loc["physicalLocation"]
    assert phys["artifactLocation"]["uri"] == "f100.sql" and "region" not in phys
    assert phys["properties"]["embeddedFile"] == "Static/app.js"


# ---------------------------------------------------------------- regressions from the fourth review round

_T4 = "q8Fz" + "3LkP9wXr2TmV7bNc4HdJ6sYe1Ga5"


def test_entropy_bindings_round4():
    t = _T4
    for line in (f'\tAPIToken = "{t}"', f'var DBPassword = "{t}";', f'String JWTSecret = "{t}";', f'AWSSecretKey: "{t}",',
                 f'OPENAI_KEY = "{t}"', f"api.key={t}", f"NEXT_PUBLIC_STRIPE_KEY={t}",
                 f'<meta-data android:name="com.google.android.geo.API_KEY" android:value="{t}"/>',
                 f'const API_KEY: &str = "{t}";', f"static API_TOKEN: &'static str = \"{t}\";",
                 f'const char api_key[] = "{t}";', f'#define API_KEY "{t}"', f'let api_key = String::from("{t}");',
                 f"<password>{t}</password>", f'<string name="api_key">{t}</string>',
                 "SECRET_KEY = 'django-insecure-x9$2k#m8w4z6p1r5t0v8n2b7c4d9f3w1q7'",
                 "SECRET_KEY2 = 'z8(9h_1o2x!4k-3m)7q+5w6e*r8t^y0u&i2o#p4a@s6d'",
                 f'app.secret_key = b"{t}"', f'const API_KEY = process.env.API_KEY || "{t}";',
                 f"ENV.fetch('API_KEY') {{ '{t}' }}", f'@Value("${{api.key:{t}}}")',
                 f'public string ApiKey {{ get; set; }} = "{t}";', f'REDIS_URL = "redis://:{t}@localhost:6379/0"'):
        assert _entropy_findings("a", 1, line), line
    for line in ('cache_key = "aB3dE5fG7hJ9kL1mN3pQ"', '<string name="app_name">MyApp2024ProdBuildRelease</string>',
                 "db_password: ENC[AES256_GCM,data:Tr7o1HhFzK3qPwX9vLm2NcB8yJ4dQeR6sUa,iv:Ab3dE5fG7hJ9kL1mN=,type:str]",
                 "password: ${{ secrets.DB_PASSWORD }}"):
        assert not _entropy_findings("a", 1, line), line


def test_entropy_file_level_round4(tmp_path):
    t = _T4
    (tmp_path / "dep.yaml").write_text(f"env:\n  - name: API_KEY\n    value: {t}\n  - name: LOG_LEVEL\n"
                                       "    value: aB3dE5fG7hJ9kL1mN3pQ5rS\n")
    (tmp_path / "vars.tf").write_text(f'variable "db_password" {{\n  default = "{t}"\n}}\n')
    body = "\n".join("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo" for _ in range(20))
    (tmp_path / "ca.crt").write_text(f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n")
    (tmp_path / "sealed.yaml").write_text("kind: SealedSecret\nspec:\n  encryptedData:\n"
                                          "    password: AgBy3i4OJSWK+PiTySYZZA9rO43cGDEq8Hd2kLmN5pQrS7tUvWx\n")
    hits = sorted((f.file, f.line) for f in scan_path(tmp_path, [], set())[0] if f.rule_id == "SEC011")
    assert hits == [("dep.yaml", 3), ("vars.tf", 2)]


def test_python_parser_overflow_does_not_abort_scan(tmp_path):
    (tmp_path / "notes.py").write_text("a " * 1500 + "\n")
    (tmp_path / "app.py").write_text('import os\ndef f(request):\n    os.system(request.GET["c"])\n')
    ids = {f.rule_id for f in scan_path(tmp_path, [], set())[0]}
    assert any(i.startswith("DF") for i in ids)          # app.py is still analyzed


# ---------------------------------------------------------------- flow-sensitive refinement and audit profile

def _flow_ids(tmp_path, code, audit=False):
    (tmp_path / "app.py").write_text(code)
    return {(f.rule_id, f.line) for f in scan_path(tmp_path, [], set(), audit=audit)[0]}


def test_flow_dead_branch_and_strong_update(tmp_path):
    code = ("from flask import request\nimport os\n"
            "@app.route('/a')\ndef a():\n"
            "    param = request.args.get('x')\n"
            "    num = 86\n"
            "    if 7 * 42 - num > 200:\n"
            "        bar = 'safe'\n"
            "    else:\n"
            "        bar = param\n"
            "    os.system(bar)\n"                          # line 11: dead-branch taint only
            "    v = param\n"
            "    v = 'constant'\n"
            "    os.system(v)\n"                            # line 14: overwritten
            "    w = 'ok' if 3 > 5 else param\n"
            "    os.system(w)\n"                            # line 16: IfExp takes the tainted side
            "    m = {}\n    m['a'] = param\n    m['b'] = 'safe'\n"
            "    os.system(m['b'])\n"                       # line 20: other key
            "    os.system(m['a'])\n")                      # line 21: tainted key
    hits = {ln for rid, ln in _flow_ids(tmp_path, code) if rid.startswith("DF")}
    assert 11 not in hits and 14 not in hits and 20 not in hits
    assert 16 in hits and 21 in hits


def test_flow_keeps_real_flows_through_loops_and_try(tmp_path):
    code = ("from flask import request\nimport os\n"
            "@app.route('/a')\ndef a():\n"
            "    acc = ''\n"
            "    for part in request.args.getlist('p'):\n"
            "        acc += part\n"
            "    try:\n"
            "        x = acc\n"
            "    except Exception:\n"
            "        x = ''\n"
            "    os.system(x)\n")
    assert any(rid.startswith("DF") and ln == 12 for rid, ln in _flow_ids(tmp_path, code))


def test_audit_profile_gates_pattern_hits(tmp_path):
    code = ("import os\n"
            "def handler():\n"
            "    cmd = 'ls -l'\n"
            "    os.system(cmd + ' /tmp')\n"            # constant command: not an injection
            "def wrapper(cmd):\n"
            "    os.system('echo ' + cmd)\n")           # wrapper: callers control cmd -> kept
    default = _flow_ids(tmp_path, code)
    assert ("EXE004", 4) not in default and ("EXE004", 6) in default
    assert ("EXE004", 4) in _flow_ids(tmp_path, code, audit=True)


def test_dataflow_finding_carries_full_path(tmp_path):
    (tmp_path / "app.py").write_text(
        "import os\nfrom flask import Flask, request\napp = Flask(__name__)\n@app.route('/ping')\ndef ping():\n"
        "    host = request.args.get('host')\n    cmd = 'ping -c 1 ' + host\n    os.system(cmd)\n    return 'ok'\n")
    df = [f for f in scan_path(tmp_path, [], set())[0] if f.rule_id == "DF002"]
    assert df and [s["line"] for s in df[0].extra["path"]] == [6, 7, 8]
