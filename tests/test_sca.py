"""Dependency analysis (SCA): manifest coverage, OSV queries through a replayed fetcher, CVSS, reachability.

OSV.dev is never contacted: ``Replay`` answers the querybatch and vulns endpoints from tests/data/sca/osv
(advisories in OSV schema, trimmed from the public records).
"""

from __future__ import annotations

import json
import pathlib
import shutil
import time
import urllib.error

import pytest

from vulnscan import deps, sca
from vulnscan.cli import main
from vulnscan.deps import _cvss_score, _fixed_version, _severity_from_vuln, _vkey, audit_dependencies, collect_packages
from vulnscan.i18n import has_arabic, to_en, translated
from vulnscan.model import assign_fingerprints

DATA = pathlib.Path(__file__).resolve().parent / "data" / "sca"
MANIFESTS = DATA / "manifests"
OSV = DATA / "osv"


class Replay:
    """Injectable fetcher: recorded OSV answers, with call accounting and optional failures."""

    def __init__(self, fail: Exception | None = None, page: bool = False):
        self.batch = json.loads((OSV / "querybatch.json").read_text(encoding="utf-8"))
        self.fail, self.page = fail, page
        self.batches: list[int] = []
        self.details: list[str] = []

    def __call__(self, url, payload, timeout):
        if self.fail:
            raise self.fail
        if payload is None:
            vid = url.rsplit("/", 1)[1]
            self.details.append(vid)
            path = OSV / "vulns" / f"{vid}.json"
            if not path.exists():
                raise urllib.error.HTTPError(url, 404, "Not Found", None, None)
            return json.loads(path.read_text(encoding="utf-8"))
        assert url == deps.OSV_BATCH
        self.batches.append(len(payload["queries"]))
        results = []
        for q in payload["queries"]:
            ids = self.batch.get(f"{q['package']['ecosystem']}/{q['package']['name']}@{q['version']}", [])
            if self.page and len(ids) > 1:           # one advisory per page
                at = int(q.get("page_token") or 0)
                res = {"vulns": [{"id": ids[at]}]}
                if at + 1 < len(ids):
                    res["next_page_token"] = str(at + 1)
                results.append(res)
            else:
                results.append({"vulns": [{"id": i, "modified": "2024-01-01T00:00:00Z"} for i in ids]} if ids else {})
        return {"results": results}


def audit(root, tmp_path, fetcher=None, **kw):
    return audit_dependencies(root, fetcher=fetcher or Replay(), cache_dir=tmp_path / "cache", **kw)


def by_pkg(findings):
    return {f.extra["package"]: f for f in findings}


def pk(name: str) -> set:
    return {(p.ecosystem, p.name, p.version, p.relation) for p in sca.collect(MANIFESTS / name)}


# ------------------------------------------------------------------ 1) manifests

def test_requirements_pins_extras_markers_hashes():
    assert pk("pip") == {("PyPI", "requests", "2.19.0", "direct"), ("PyPI", "flask", "2.0.1", "direct"),
                         ("PyPI", "pyyaml", "5.3", "direct")}          # unpinned, wildcard and -r lines are skipped


def test_pip_compile_marks_transitive():
    assert pk("pipcompile") == {("PyPI", "flask", "2.0.1", "direct"), ("PyPI", "jinja2", "2.11.2", "transitive"),
                                ("PyPI", "markupsafe", "1.1.1", "transitive")}


def test_pyproject_pep621_and_poetry():
    assert pk("pep621") == {("PyPI", "requests", "2.19.0", "direct"), ("PyPI", "pyyaml", "5.3", "direct")}
    assert pk("poetrymanifest") == {("PyPI", "requests", "2.19.0", "direct"), ("PyPI", "pyyaml", "5.3", "direct")}


def test_python_lockfiles_win_and_mark_transitive():
    want = {("PyPI", "requests", "2.19.0", "direct"), ("PyPI", "urllib3", "1.23", "transitive")}
    assert pk("poetry") == want | {("PyPI", "pyyaml", "5.3", "direct")}
    assert {p.manifest for p in sca.collect(MANIFESTS / "poetry")} == {"poetry.lock"}     # pyproject.toml is not re-read
    assert pk("uv") == want                                           # the project itself is not a dependency
    assert pk("pipenv") == want | {("PyPI", "pytest", "7.0.0", "direct")}
    assert [p.dev for p in sca.collect(MANIFESTS / "pipenv") if p.name == "pytest"] == [True]


def test_npm_lockfiles_v1_v3_and_manifest():
    assert pk("npm1") == {("npm", "express", "4.16.0", "direct"), ("npm", "qs", "6.5.1", "transitive"),
                          ("npm", "mocha", "5.2.0", "direct"), ("npm", "lodash", "4.17.15", "transitive")}
    assert pk("npm3") == {("npm", "lodash", "4.17.15", "direct"), ("npm", "@scope/pkg", "1.0.0", "direct"),
                          ("npm", "mocha", "5.2.0", "direct"), ("npm", "minimist", "0.0.8", "transitive")}
    assert pk("npmmanifest") == {("npm", "lodash", "4.17.15", "direct")}   # ^ranges are not exact versions


def test_yarn_and_pnpm():
    assert pk("yarn1") == {("npm", "@babel/code-frame", "7.8.3", "transitive"), ("npm", "lodash", "4.17.15", "direct")}
    assert pk("yarnberry") == {("npm", "lodash", "4.17.15", "unknown"), ("npm", "@scope/pkg", "1.0.0", "unknown")}
    assert pk("pnpm9") == {("npm", "lodash", "4.17.15", "direct"), ("npm", "@babel/core", "7.0.0", "transitive")}
    assert pk("pnpm5") == {("npm", "lodash", "4.17.15", "direct"), ("npm", "@babel/core", "7.0.0", "transitive"),
                           ("npm", "minimist", "1.2.0", "transitive")}


def test_maven_properties_and_management():
    assert pk("maven") == {("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1", "direct"),
                           ("Maven", "com.fasterxml.jackson.core:jackson-databind", "2.9.8", "direct"),
                           ("Maven", "commons-collections:commons-collections", "3.2.1", "direct"),
                           ("Maven", "com.example:sibling", "1.4.2", "direct"), ("Maven", "junit:junit", "4.12", "direct")}


def test_pom_with_entities_is_not_parsed(tmp_path):
    (tmp_path / "pom.xml").write_text('<!DOCTYPE p [<!ENTITY a "aaaa">]><project><dependencies><dependency><groupId>g.x</groupId>'
                                      "<artifactId>a</artifactId><version>1.0</version></dependency></dependencies></project>")
    assert sca.collect(tmp_path) == []


def test_gradle_scripts_and_lockfile():
    assert pk("gradle") == {("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1", "direct"),
                            ("Maven", "com.fasterxml.jackson.core:jackson-databind", "2.9.8", "direct"),
                            ("Maven", "junit:junit", "4.12", "direct")}
    assert pk("gradlekts") == {("Maven", "com.squareup.okhttp3:okhttp", "3.12.0", "direct"),
                               ("Maven", "org.yaml:snakeyaml", "1.26", "direct"),
                               ("Maven", "org.springframework.boot:spring-boot-dependencies", "2.5.0", "direct")}
    assert pk("gradlelock") == {("Maven", "org.yaml:snakeyaml", "1.26", "direct"),
                                ("Maven", "org.slf4j:slf4j-api", "1.7.30", "transitive"),
                                ("Maven", "junit:junit", "4.12", "transitive")}


def test_go_mod_and_sum():
    assert pk("go") == {("Go", "github.com/gin-gonic/gin", "1.6.3", "direct"), ("Go", "golang.org/x/text", "0.3.5", "direct"),
                        ("Go", "gopkg.in/yaml.v2", "2.2.2", "transitive")}      # replace/exclude are not requirements
    assert pk("gosum") == {("Go", "golang.org/x/text", "0.3.5", "unknown"), ("Go", "gopkg.in/yaml.v2", "2.2.2", "unknown")}


def test_composer_gems_cargo_nuget_pub():
    assert pk("composer") == {("Packagist", "guzzlehttp/guzzle", "6.5.0", "direct"),
                              ("Packagist", "symfony/http-kernel", "4.4.0", "transitive"),
                              ("Packagist", "phpunit/phpunit", "9.5.0", "direct")}
    assert pk("ruby") == {("RubyGems", "nokogiri", "1.10.4", "direct"), ("RubyGems", "mini_portile2", "2.4.0", "transitive"),
                          ("RubyGems", "rack", "2.0.6", "direct")}
    assert pk("cargo") == {("crates.io", "regex", "1.5.4", "direct"), ("crates.io", "memchr", "2.4.0", "transitive"),
                           ("crates.io", "tempfile", "3.2.0", "direct")}
    assert pk("nugetlock") == {("NuGet", "Newtonsoft.Json", "12.0.1", "direct"),
                               ("NuGet", "System.Text.Encodings.Web", "4.5.0", "transitive")}
    assert pk("csproj") == {("NuGet", "Newtonsoft.Json", "12.0.1", "direct"), ("NuGet", "log4net", "2.0.8", "direct")}
    assert pk("pub") == {("Pub", "http", "0.12.0", "direct"), ("Pub", "path", "1.8.0", "transitive")}


def test_collect_whole_tree_dedups_and_survives_broken_files():
    pkgs = sca.collect(MANIFESTS)
    keys = [(p.ecosystem, p.name, p.version) for p in pkgs]
    assert len(keys) == len(set(keys)) and len(keys) > 40
    assert not any(p.name == "skipped" for p in pkgs)                 # node_modules is never read
    lodash = next(p for p in pkgs if p.name == "lodash")
    assert lodash.direct is True and len(lodash.also_in) >= 4         # direct anywhere = direct
    assert {p.ecosystem for p in pkgs} == {"PyPI", "npm", "Maven", "Go", "Packagist", "RubyGems", "crates.io", "NuGet", "Pub"}
    assert all(len(t) == 4 for t in collect_packages(MANIFESTS))      # the old tuple API still works


# ------------------------------------------------------------------ 2) OSV: batches, cache, severity, fixes

def test_cvss31_base_scores():
    for vector, score in [("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8), ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
                          ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1), ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H", 9.0),
                          ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5), ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4),
                          ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6), ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H", 7.4),
                          ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.8), ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0)]:
        assert _cvss_score(vector) == score, vector
    assert _cvss_score("CVSS:3.1/AV:N/AC:L") is None and _cvss_score("CVSS:4.0/AV:N") is None and _cvss_score("garbage") is None


def test_severity_sources():
    v3 = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}], "database_specific": {"severity": "LOW"}}
    assert _severity_from_vuln(v3) == "critical"                      # the computed score wins over the label
    assert _severity_from_vuln({"database_specific": {"severity": "MODERATE"}}) == "medium"
    assert _severity_from_vuln({"affected": [{"ecosystem_specific": {"severity": "HIGH"}}]}) == "high"
    v4 = {"severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"}]}
    assert _severity_from_vuln(v4) == "high"                          # v4 only: scored through its v3.1 equivalent
    assert _severity_from_vuln({}) == "medium"


def test_version_order_and_fixed_version():
    assert _vkey("1.0.0-rc1") < _vkey("1.0") == _vkey("1.0.0") < _vkey("1.0.1") < _vkey("1.10") < _vkey("2.0.0.RELEASE")
    detail = json.loads((OSV / "vulns" / "GHSA-xvch-5gv4-984h.json").read_text(encoding="utf-8"))
    assert _fixed_version(detail, "minimist", "npm", "1.2.0") == "1.2.6"     # the fix of the installed branch
    assert _fixed_version(detail, "minimist", "npm", "0.0.8") == "0.2.4"
    assert _fixed_version(detail, "minimist") == "0.2.4" and _fixed_version(detail, "other", "npm", "1.0") is None


def test_audit_reports_upgrade_and_metadata(tmp_path):
    findings, err = audit(DATA / "app", tmp_path)
    assert err is None
    got = by_pkg(findings)
    assert set(got) == {"requests", "pyyaml", "urllib3", "jinja2", "lodash", "minimist", "golang.org/x/text", "gopkg.in/yaml.v2",
                        "org.apache.logging.log4j:log4j-core", "commons-collections:commons-collections", "guzzlehttp/guzzle",
                        "nokogiri", "rack"}                            # the withdrawn advisory is dropped
    r = got["requests"]
    assert (r.rule_id, r.file, r.line, r.source, r.cwe) == ("OSV:GHSA-x84v-xcm2-53pg", "requirements.txt", 0, "osv", "CWE-522")
    assert r.title == "Vulnerable dependency requests 2.19.0 (GHSA-x84v-xcm2-53pg, CVE-2018-18074)"
    assert r.advice.startswith("حدّث requests إلى 2.20.0.") and r.extra["fixed_version"] == "2.20.0"
    assert r.extra["cvss_score"] == 9.8 and r.severity == "critical" and r.extra["dependency"] == "direct"
    assert got["minimist"].extra["fixed_version"] == "1.2.6" and got["minimist"].extra["dependency"] == "transitive"
    assert got["gopkg.in/yaml.v2"].extra["dependency"] == "transitive"
    assert "اعتمادية غير مباشرة" in got["gopkg.in/yaml.v2"].advice


def test_batches_are_chunked_and_paged(tmp_path, monkeypatch):
    monkeypatch.setattr(deps, "BATCH_SIZE", 5)
    replay = Replay(page=True)
    findings, err = audit(DATA / "app", tmp_path, replay)
    assert err is None and len(findings) == 13
    assert sorted(replay.batches) == [1, 3, 5, 5]                     # 13 packages in chunks of 5, plus page 2 of requests
    assert sorted(replay.details) == sorted(p.stem for p in (OSV / "vulns").glob("*.json"))


def test_disk_cache_is_keyed_by_package_version_for_24h(tmp_path, monkeypatch):
    first = Replay()
    a, _ = audit(DATA / "app", tmp_path, first)
    again = Replay()
    b, _ = audit(DATA / "app", tmp_path, again)
    assert again.batches == [] and again.details == []                # everything came from the cache
    assert [f.to_dict() for f in a] == [f.to_dict() for f in b]
    assert len(list((tmp_path / "cache").glob("pkg-*.json"))) == 13
    rec = json.loads(next((tmp_path / "cache").glob("pkg-*.json")).read_text(encoding="utf-8"))
    assert "@" in rec["key"] and isinstance(rec["value"], list)
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + 25 * 3600)     # a day later the cache has expired
    later = Replay()
    audit(DATA / "app", tmp_path, later)
    assert later.batches == [13]
    off = Replay()
    audit(DATA / "app", tmp_path, off, use_cache=False)
    assert off.batches == [13]


def test_cache_location(tmp_path, monkeypatch):
    monkeypatch.delenv("KASHIF_HOME", raising=False)
    monkeypatch.setenv("VULNSCAN_HOME", str(tmp_path / "home"))
    assert deps.default_cache_dir() == tmp_path / "home" / "cache" / "osv"
    monkeypatch.delenv("VULNSCAN_HOME")
    assert "vulnscan-osv-cache" in deps.default_cache_dir().name
    monkeypatch.setenv("VULNSCAN_OSV_CACHE", "0")
    assert deps._Cache(tmp_path / "c").enabled is False


def test_http_retries_transient_errors(monkeypatch):
    calls = []

    class Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, *a):
            return b'{"results": []}'

    def fake(req, timeout):
        calls.append(req.full_url)
        if len(calls) < 3:
            raise urllib.error.HTTPError(req.full_url, 503, "busy", None, None)
        return Resp()

    monkeypatch.setattr(deps.urllib.request, "urlopen", fake)
    monkeypatch.setattr(deps.time, "sleep", lambda s: None)
    assert deps._http(deps.OSV_BATCH, {"queries": []}, 1.0) == {"results": []} and len(calls) == 3
    calls.clear()

    def gone(req, timeout):
        calls.append(1)
        raise urllib.error.HTTPError(req.full_url, 400, "bad", None, None)

    monkeypatch.setattr(deps.urllib.request, "urlopen", gone)
    with pytest.raises(urllib.error.HTTPError):
        deps._http(deps.OSV_BATCH, {}, 1.0)
    assert calls == [1]                                               # a client error is not retried


# ------------------------------------------------------------------ 3) reachability

def test_reachability_vulnerable_app(tmp_path):
    got = by_pkg(audit(DATA / "app", tmp_path)[0])
    reach = {k: f.extra["reachability"] for k, f in got.items()}
    assert reach == {
        "pyyaml": "vulnerable_function_called",                       # import yaml as y; y.load(...)
        "jinja2": "vulnerable_function_called",                       # Environment().from_string(...)
        "lodash": "vulnerable_function_called",                       # _.zipObjectDeep(...)
        "golang.org/x/text": "vulnerable_function_called",            # language.ParseAcceptLanguage(...)
        "org.apache.logging.log4j:log4j-core": "vulnerable_function_called",
        "requests": "imported", "guzzlehttp/guzzle": "imported", "nokogiri": "imported",
        "urllib3": "not_imported", "minimist": "not_imported", "gopkg.in/yaml.v2": "not_imported",
        "commons-collections:commons-collections": "not_imported", "rack": "not_imported",
    }
    assert got["pyyaml"].extra["called_functions"] == ["yaml.load"]
    assert got["golang.org/x/text"].extra["called_functions"] == ["golang.org/x/text/language.ParseAcceptLanguage"]
    assert got["lodash"].extra["called_functions"] == ["lodash.zipObjectDeep"]
    assert got["pyyaml"].severity == "critical" and "severity_original" not in got["pyyaml"].extra
    # never imported: one level lower, with a note, never hidden
    assert (got["urllib3"].severity, got["urllib3"].extra["severity_original"]) == ("medium", "high")
    assert (got["minimist"].severity, got["minimist"].extra["severity_original"]) == ("high", "critical")
    assert (got["rack"].severity, got["rack"].extra["severity_original"]) == ("low", "medium")
    assert "خُفِّضت الخطورة" in got["urllib3"].advice and "lowered one level" in got["urllib3"].extra["reachability_note_en"]


def test_reachability_safe_twin(tmp_path):
    got = by_pkg(audit(DATA / "app_safe", tmp_path)[0])
    reach = {k: f.extra["reachability"] for k, f in got.items()}
    assert len(got) == 13                                             # same dependencies: nothing is hidden
    assert "vulnerable_function_called" not in reach.values()
    # imported, but yaml.safe_load / json.load / lodash chunk / x/text/cases are not the vulnerable functions
    assert reach["pyyaml"] == reach["lodash"] == reach["golang.org/x/text"] == reach["requests"] == "imported"
    assert "called_functions" not in got["pyyaml"].extra and got["pyyaml"].extra["vulnerable_functions"][0] == "yaml.load"
    assert "لم يُعثر على استدعاء للدوال المصابة" in got["pyyaml"].advice and got["pyyaml"].severity == "critical"
    for name in ("jinja2", "org.apache.logging.log4j:log4j-core", "guzzlehttp/guzzle", "nokogiri", "urllib3"):
        assert reach[name] == "not_imported", name
    assert got["org.apache.logging.log4j:log4j-core"].severity == "high"        # critical, lowered one level
    assert got["guzzlehttp/guzzle"].severity == "medium"


def test_vendored_code_does_not_count_as_usage(tmp_path):
    # vendor/ holds a copy of x/text that imports yaml.v2: that is not the project using yaml.v2
    assert by_pkg(audit(DATA / "app", tmp_path)[0])["gopkg.in/yaml.v2"].extra["reachability"] == "not_imported"


def test_reachability_unknown_without_sources(tmp_path):
    shutil.copy(DATA / "app" / "requirements.txt", tmp_path / "requirements.txt")
    findings, _ = audit(tmp_path, tmp_path)
    assert findings and all(f.extra["reachability"] == "unknown" for f in findings)
    assert by_pkg(findings)["urllib3"].severity == "high"             # unknown is never downgraded
    none, _ = audit(tmp_path, tmp_path, reachability=False)
    assert all("reachability" not in f.extra for f in none)


def _index(tmp_path, files: dict) -> sca.ImportIndex:
    for name, text in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return sca.ImportIndex(tmp_path)


def _status(index, eco, name, symbols=None, **kw):
    return index.reach(sca.Package(eco, name, "1.0.0", "m", **kw), symbols)[0]


def test_python_distribution_to_import_names(tmp_path):
    ix = _index(tmp_path, {
        "a.py": "import yaml, bs4\nfrom PIL import Image\nfrom google.cloud import storage\nimport OpenSSL.crypto\n"
                "from sklearn.linear_model import LinearRegression\nimport jwt\n",
        "settings.py": "INSTALLED_APPS = ['rest_framework', 'corsheaders']\n",
        "old.py": "import cv2\nprint 'python 2 file'\n"})
    for dist in ("PyYAML", "beautifulsoup4", "Pillow", "google-cloud-storage", "pyOpenSSL", "scikit-learn", "PyJWT",
                 "djangorestframework", "django-cors-headers", "opencv-python"):
        assert _status(ix, "PyPI", dist) == "imported", dist
    for dist in ("requests", "python-dateutil", "pycryptodome"):
        assert _status(ix, "PyPI", dist) == "not_imported", dist


def test_python_function_calls_resolve_aliases(tmp_path):
    ix = _index(tmp_path, {"a.py": "from yaml import load as yload\nimport json\nimport lxml.etree as ET\n"
                                   "yload(x)\njson.load(f)\nET.fromstring(s)\n"})
    assert _status(ix, "PyPI", "pyyaml", [("", "yaml.load")]) == "vulnerable_function_called"
    assert _status(ix, "PyPI", "pyyaml", [("", "yaml.full_load")]) == "imported"
    assert _status(ix, "PyPI", "lxml", [("", "lxml.etree.fromstring")]) == "vulnerable_function_called"
    assert _status(ix, "PyPI", "lxml", [("", "lxml.etree.parse")]) == "imported"


def test_js_java_go_php_ruby_rust_csharp_dart_imports(tmp_path):
    ix = _index(tmp_path, {
        "a.ts": "import express from 'express';\nimport {x} from '@scope/pkg/sub';\nconst l = await import('left-pad');\nimport './local';\n",
        "package.json": '{"scripts": {"build": "webpack --mode production"}}',
        "A.java": "import com.google.common.collect.Lists;\nimport static org.apache.commons.io.FileUtils.readFileToString;\n"
                  "import com.acme.util.*;\n",
        "B.kt": "import okhttp3.OkHttpClient\n",
        "m.go": 'package m\nimport y "gopkg.in/yaml.v2"\nimport "github.com/gin-gonic/gin/binding"\nvar _ = y.Unmarshal\n',
        "x.php": "<?php\nuse Symfony\\Component\\HttpKernel\\Kernel;\n$m = new \\Monolog\\Logger('x');\n",
        "r.rb": "require 'active_support/core_ext'\nrequire 'net/ldap'\n",
        "l.rs": "use serde_json::Value;\nfn f() { regex::Regex::new(\"x\"); }\n",
        "c.cs": "using Newtonsoft.Json.Linq;\nusing static System.Math;\n",
        "d.dart": "import 'package:http/http.dart' as http;\n"})
    yes = [("npm", "express"), ("npm", "@scope/pkg"), ("npm", "left-pad"), ("npm", "webpack"), ("Maven", "com.google.guava:guava"),
           ("Maven", "commons-io:commons-io"), ("Maven", "com.squareup.okhttp3:okhttp"), ("Maven", "com.acme:acme-util"),
           ("Go", "gopkg.in/yaml.v2"), ("Go", "github.com/gin-gonic/gin"), ("RubyGems", "activesupport"), ("RubyGems", "net-ldap"),
           ("crates.io", "serde_json"), ("crates.io", "regex"), ("NuGet", "Newtonsoft.Json"), ("Pub", "http")]
    for eco, name in yes:
        assert _status(ix, eco, name) == "imported", name
    assert _status(ix, "Packagist", "symfony/http-kernel", namespaces=("Symfony\\Component\\HttpKernel\\",)) == "imported"
    assert _status(ix, "Packagist", "monolog/monolog") == "imported"                 # namespace guessed from the name
    no = [("npm", "lodash"), ("Maven", "org.yaml:snakeyaml"), ("Maven", "com.fasterxml.jackson.core:jackson-databind"),
          ("Go", "golang.org/x/text"), ("RubyGems", "nokogiri"), ("crates.io", "openssl"), ("Pub", "path")]
    for eco, name in no:
        assert _status(ix, eco, name) == "not_imported", name
    assert _status(ix, "Packagist", "guzzlehttp/guzzle", namespaces=("GuzzleHttp\\",)) == "not_imported"
    # no reliable mapping from the package to what the code would import: say so, do not guess
    for eco, name in [("Maven", "mysql:mysql-connector-java"), ("Maven", "oddgroup:thing"), ("Maven", "com.acme.other:lib"),
                      ("NuGet", "Some.Package"), ("Packagist", "acme/unknown"), ("npm", "@types/node")]:
        assert _status(ix, eco, name) == "unknown", name
    assert _status(ix, "Go", "gopkg.in/yaml.v2", [("gopkg.in/yaml.v2", "Unmarshal")]) == "vulnerable_function_called"   # aliased y
    assert _status(ix, "Go", "gopkg.in/yaml.v2", [("gopkg.in/yaml.v2", "Marshal")]) == "imported"
    assert _status(ix, "Go", "github.com/gin-gonic/gin", [("github.com/gin-gonic/gin", "Default")]) == "imported"      # other subpackage


def test_bundler_require_makes_unrequired_gems_unknown(tmp_path):
    ix = _index(tmp_path, {"config/application.rb": "require 'rails/all'\nBundler.require(*Rails.groups)\n"})
    assert _status(ix, "RubyGems", "nokogiri") == "unknown" and _status(ix, "RubyGems", "railties") == "imported"


# ------------------------------------------------------------------ fingerprints, i18n, offline, CLI

def test_fingerprints_are_stable_and_independent_of_reachability(tmp_path):
    a, _ = audit(DATA / "app", tmp_path)
    b, _ = audit(DATA / "app_safe", tmp_path)
    c, _ = audit(DATA / "app", tmp_path, reachability=False)
    for fs in (a, b, c):
        assign_fingerprints(fs)
    assert [f.fingerprint() for f in a] == [f.fingerprint() for f in b] == [f.fingerprint() for f in c]
    # identity is rule + manifest + advisory summary, exactly as before reachability existed
    r = by_pkg(a)["requests"]
    assert (r.rule_id, r.file, r.snippet) == ("OSV:GHSA-x84v-xcm2-53pg", "requirements.txt", "Insufficiently Protected Credentials in Requests")
    assert len(r.base_fingerprint()) == 16


def test_every_string_has_english(tmp_path):
    for app in ("app", "app_safe"):
        for f in audit(DATA / app, tmp_path)[0]:
            d = f.to_dict()
            assert translated(f.advice) and translated(f.title_ar), f.advice
            assert not has_arabic(d["advice_en"]) and not has_arabic(f.extra["reachability_note_en"])
            assert has_arabic(f.extra["reachability_note"])
    en = to_en(by_pkg(audit(DATA / "app", tmp_path)[0])["gopkg.in/yaml.v2"].advice)
    assert en == ("Upgrade gopkg.in/yaml.v2 to 2.2.4. This is a transitive dependency: upgrade the package that pulls it in, "
                  "or pin the patched version. The scanned code never imports this package, so the severity was lowered one level.")
    assert to_en(by_pkg(audit(DATA / "app", tmp_path)[0])["pyyaml"].advice) == \
        "Upgrade pyyaml to 5.4. The code calls vulnerable functions of this package: yaml.load."


def test_offline_note_is_clear(tmp_path):
    down = Replay(fail=urllib.error.URLError("[Errno -3] Temporary failure in name resolution"))
    findings, err = audit(DATA / "app", tmp_path, down)
    assert findings == [] and "OSV.dev" in err and "--no-deps" in err and "13" in err
    en = to_en(err)
    assert not has_arabic(en) and "NOT checked" in en and "name resolution" in en and "--no-deps" in en


def test_offline_falls_back_to_expired_cache(tmp_path, monkeypatch):
    audit(DATA / "app", tmp_path)
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + 3 * 24 * 3600)
    (tmp_path / "proj").mkdir()
    (tmp_path / "proj" / "requirements.txt").write_text("requests==2.19.0\nnewpkg==1.0.0\n")
    findings, err = audit(tmp_path / "proj", tmp_path, Replay(fail=OSError("network is unreachable")))
    assert [f.extra["package"] for f in findings] == ["requests"] and findings[0].severity == "critical"
    assert not has_arabic(to_en(err)) and "1 dependencies were left unchecked" in to_en(err)


def test_malformed_osv_answer_is_an_error_not_a_crash(tmp_path):
    findings, err = audit(DATA / "app", tmp_path, lambda url, payload, timeout: {"results": [{}]})
    assert findings == [] and err and translated(err)


def test_no_manifests_no_network(tmp_path):
    (tmp_path / "a.py").write_text("import os\n")

    def boom(*a):
        raise AssertionError("no query expected")

    assert audit(tmp_path, tmp_path, boom) == ([], None)


def test_cli_no_deps_disables_osv(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("OSV must not be queried with --no-deps")

    monkeypatch.setattr("vulnscan.cli.audit_dependencies", boom)
    monkeypatch.setattr(deps, "_http", boom)
    out = tmp_path / "r.json"
    main([str(DATA / "app"), "--no-deps", "--no-external", "-f", "json", "-o", str(out)])
    assert not any(f["source"] == "osv" for f in json.loads(out.read_text(encoding="utf-8"))["findings"])


def test_cli_reports_dependencies_and_offline_note(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("VULNSCAN_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("KASHIF_HOME", raising=False)
    replay = Replay()
    monkeypatch.setattr(deps, "_http", replay)
    out = tmp_path / "r.json"
    main([str(DATA / "app"), "--no-external", "--lang", "en", "-f", "json", "-o", str(out)])
    osv = [f for f in json.loads(out.read_text(encoding="utf-8"))["findings"] if f["source"] == "osv"]
    assert len(osv) == 13 and replay.batches == [13]
    assert {f["extra"]["reachability"] for f in osv} == {"vulnerable_function_called", "imported", "not_imported"}
    assert (tmp_path / "home" / "cache" / "osv").is_dir()
    monkeypatch.setenv("VULNSCAN_OSV_CACHE", "0")
    monkeypatch.setattr(deps, "_http", Replay(fail=urllib.error.URLError("connection refused")))
    main([str(DATA / "app"), "--no-external", "--lang", "en", "-f", "json", "-o", str(out)])
    report = json.loads(out.read_text(encoding="utf-8"))
    assert not any(f["source"] == "osv" for f in report["findings"])
    assert "Could not reach OSV.dev" in json.dumps(report) + capsys.readouterr().err + capsys.readouterr().out


# ------------------------------------------------------------------ 4) adversarial review (1.0)

def test_cvss_scores_match_nvd_for_published_vectors():
    # base scores as published by NVD for these (vector, CVE) pairs
    nvd = {
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,      # CVE-2021-44228 (Log4Shell)
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,       # CVE-2022-22965 (Spring4Shell)
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H": 8.1,       # CVE-2021-45046 (as first scored)
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N": 7.5,       # CVE-2014-0160 (Heartbleed, v3 rescoring)
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H": 7.5,       # CVE-2022-24999 (qs prototype pollution)
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 8.8,       # CVE-2019-10744 class (low-privilege RCE)
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 7.8,       # CVE-2021-4034 (PwnKit)
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N": 5.3,       # CVE-2018-18074 class info leak
        "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H": 7.2,       # admin-only RCE
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H": 8.8,       # CVE-2022-0847 (Dirty Pipe, scope changed)
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N": 5.4,       # stored XSS
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N": 3.1,
        "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N": 4.6,
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H": 9.9,       # CVE-2019-5736 class (container escape)
        "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H": 6.7,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N": 6.5,
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,       # CVE-2017-5638 (Struts, scored with v3.0)
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H/RL:O/RC:C": 9.8,   # temporal metrics never change the base
    }
    for vector, score in nvd.items():
        assert _cvss_score(vector) == score, vector
    for bad in ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/AV:L",        # a metric twice: invalid, not 8.4
                "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "cvss:3.1/av:n/ac:l/pr:n/ui:n/s:u/c:h/i:h/a:h",
                "CVSS:3.2/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", None, 5):
        assert _cvss_score(bad) is None, bad


@pytest.mark.parametrize("eco, chain", [
    ("PyPI", ["0.9", "1.0.dev1", "1.0a1.dev1", "1.0a1", "1.0b1", "1.0rc1", "1.0", "1.0.post1.dev1", "1.0.post1", "1.0.1", "1.10", "1!0.5"]),
    ("npm", ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11",
             "1.0.0-rc.1", "1.0.0", "1.0.1", "1.10.0"]),
    ("Maven", ["1.0-alpha-1", "1.0-beta", "1.0-milestone-1", "1.0-rc1", "1.0-SNAPSHOT", "1.0", "1.0-sp1", "1.0.1", "2.0.0.RELEASE"]),
    ("Go", ["v1.2.3", "v1.2.4-0.20210101000000-abcdefabcdef", "v1.2.4-0.20220101000000-012345abcdef", "v1.2.4", "v1.3.0-pre",
            "v1.3.0", "v1.10.0"]),
    ("RubyGems", ["1.0.0.beta1", "1.0.0.pre", "1.0.0.rc1", "1.0.0", "1.0.0.1"]),
    ("Packagist", ["1.0.0-dev", "1.0.0-alpha1", "1.0.0-beta2", "1.0.0-RC1", "1.0.0", "1.0.0-p1", "1.0.1"]),
    ("NuGet", ["1.0.0-preview.1", "1.0.0", "1.0.0.1", "1.0.1"]),
])
def test_version_order_per_ecosystem(eco, chain):
    keys = [_vkey(v, eco) for v in chain]
    assert keys == sorted(keys) and len(set(keys)) == len(keys), chain
    assert _vkey("1.0", "Maven") == _vkey("1.0.Final", "Maven") == _vkey("1.0.GA", "Maven")
    assert _vkey("1.0.0", "npm") == _vkey("1.0.0+build.7", "npm") and _vkey("v1.0.0", "Go") == _vkey("1.0.0", "Go")
    mixed = chain + ["", "abc", "1..2", "-", "1.0-", "1!x", "999999999999999999999.1"]
    assert sorted(mixed, key=lambda v: _vkey(v, eco))                 # junk and mixed shapes never raise


def test_fixed_version_respects_prereleases_and_pseudo_versions():
    go = {"affected": [{"package": {"name": "example.com/m", "ecosystem": "Go"},
                        "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.4"}]}]}]}
    # a pseudo-version of the unreleased 1.2.4 is older than 1.2.4: the fix is still 1.2.4
    assert _fixed_version(go, "example.com/m", "Go", "1.2.4-0.20210101000000-abcdefabcdef") == "1.2.4"
    py = {"affected": [{"package": {"name": "p", "ecosystem": "PyPI"},
                        "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "2.0.post1"}, {"fixed": "2.0rc2"}]}]}]}
    assert _fixed_version(py, "p", "PyPI", "2.0rc1") == "2.0rc2" and _fixed_version(py, "p", "PyPI", "2.0") == "2.0.post1"


def test_malformed_advisories_degrade_instead_of_crashing():
    pkg = sca.Package("PyPI", "a", "1.0", "requirements.txt", True)
    for rec in ({"affected": [None, "x", {"package": None, "ranges": [None, {"events": None}], "severity": "x"}]},
                {"affected": "x", "severity": [None, "a", {"score": 5}], "aliases": "CVE-1", "summary": 3,
                 "database_specific": [], "withdrawn": None}, [], None, "x"):
        assert _severity_from_vuln(rec) == "medium" and _fixed_version(rec, "a", "PyPI", "1.0") is None
        assert deps.vulnerable_symbols(rec, "a", "PyPI") == [] and deps.cvss(rec) == (None, "")
        f = deps._finding(pkg, "X-1", rec, None)
        assert f.severity == "medium" and f.title.endswith("(X-1)")


def test_corrupted_cache_files_are_ignored(tmp_path):
    audit(DATA / "app", tmp_path)
    for p in (tmp_path / "cache").glob("*.json"):
        rec = json.loads(p.read_text(encoding="utf-8"))
        rec["value"] = [[1], {"x": 1}] if p.name.startswith("pkg-") else {"id": "OTHER", "affected": "x"}
        p.write_text(json.dumps(rec))
    findings, err = audit(DATA / "app", tmp_path)                   # re-queried, not crashed, same answer
    assert err is None and len(findings) == 13


def test_cache_directory_must_not_be_writable_by_others(tmp_path):
    d = tmp_path / "c"
    d.mkdir()
    d.chmod(0o777)
    cache = deps._Cache(d)
    if hasattr(deps.os, "getuid"):
        assert cache.enabled and d.stat().st_mode & 0o077 == 0         # tightened, then trusted


def test_network_loss_mid_run_stops_advisory_lookups_and_says_so(tmp_path):
    replay = Replay()
    calls = []

    def flaky(url, payload, timeout):
        if payload is None:                                           # querybatch works, then the network drops
            calls.append(url)
            raise urllib.error.URLError("timed out")
        return replay(url, payload, timeout)

    findings, err = audit(DATA / "app", tmp_path, flaky)
    # 14: without its details the withdrawn advisory cannot be recognised as withdrawn; nothing is hidden
    assert len(findings) == 14 and {f.severity for f in findings} <= {"medium", "low"}
    assert len(calls) <= 8                                            # one per worker at most, not one per advisory
    en = to_en(err)
    assert not has_arabic(en) and "Could not fetch the details of" in en and "without a fixed version" in en


@pytest.mark.parametrize("name, text", [
    ("pyproject.toml", "[" + " " * 30000 + "x"),                       # was cubic in the section regex
    ("Pipfile", "[" + " " * 30000 + "x"),
    ("requirements.txt", "a" + " " * 100000 + "[x]" + " " * 100000 + "== 1" + " " * 100000 + "x"),
    ("build.gradle", "def" + " " * 200000 + "\nimplementation" + " " * 200000 + "x"),
    ("x.csproj", "<!--" * 50000 + '<PackageReference Include="a" ' * 20000),
    ("Directory.Packages.props", '<PackageVersion Include="a">' * 30000),
])
def test_crafted_manifests_parse_in_linear_time(tmp_path, name, text):
    (tmp_path / name).write_text(text)
    start = time.monotonic()
    sca.collect(tmp_path)
    assert time.monotonic() - start < 3


def test_crafted_go_source_does_not_stall_reachability(tmp_path):
    (tmp_path / "a.go").write_text("package a\n" + "import (" * 100000)
    start = time.monotonic()
    sca.ImportIndex(tmp_path)
    assert time.monotonic() - start < 3


def test_csproj_bodies_and_comments_still_parse(tmp_path):
    (tmp_path / "a.csproj").write_text(
        '<Project><!-- <PackageReference Include="Hidden" Version="1.0.0" /> -->\n'
        '<PackageReference Include="A" Version="1.0.0" />\n'
        '<PackageReference Include="B"><Version>2.0.0</Version></PackageReference>\n'
        '<PackageReference Include="C"></PackageReference><PackageReference Include="D"><Version>3.0.0</Version></PackageReference>\n'
        '</Project>')
    assert {(p.name, p.version) for p in sca.collect(tmp_path)} == {("A", "1.0.0"), ("B", "2.0.0"), ("D", "3.0.0")}


def test_npm_aliases_query_the_real_package_and_match_the_alias(tmp_path):
    (tmp_path / "yarn.lock").write_text('"lodash4@npm:lodash@^4.17.20":\n  version "4.17.20"\n\n'
                                        '"left-pad@npm:^1.3.0":\n  version "1.3.0"\n')
    (tmp_path / "package.json").write_text('{"dependencies": {"lodash4": "npm:lodash@^4.17.20", "left-pad": "^1.3.0"}}')
    pkgs = {p.name: p for p in sca.collect(tmp_path)}
    assert set(pkgs) == {"lodash", "left-pad"} and pkgs["lodash"].aliases == ("lodash4",) and pkgs["left-pad"].aliases == ()
    assert pkgs["lodash"].direct is True
    v1 = tmp_path / "v1"
    v1.mkdir()
    (v1 / "package-lock.json").write_text('{"lockfileVersion": 1, "dependencies": {"lodash4": {"version": "npm:lodash@4.17.20"}}}')
    assert [(p.name, p.version, p.aliases) for p in sca.collect(v1)] == [("lodash", "4.17.20", ("lodash4",))]
    v3 = tmp_path / "v3"
    v3.mkdir()
    (v3 / "package-lock.json").write_text('{"lockfileVersion": 3, "packages": {"": {"dependencies": {"lodash4": "npm:lodash@4"}},'
                                          ' "node_modules/lodash4": {"name": "lodash", "version": "4.17.20"}}}')
    p = sca.collect(v3)[0]
    assert (p.name, p.aliases, p.direct) == ("lodash", ("lodash4",), True)
    (v3 / "a.js").write_text("const _ = require('lodash4');\n_.zipObjectDeep(a, b);\n")
    assert _status(sca.ImportIndex(v3), "npm", "lodash", [("", "zipObjectDeep")], aliases=("lodash4",)) == "vulnerable_function_called"
    assert _status(sca.ImportIndex(v3), "npm", "lodash") == "not_imported"     # safe twin: the alias is unknown


@pytest.mark.parametrize("eco, name, files", [
    ("PyPI", "pyyaml", {"nb.ipynb": json.dumps({"cells": [{"cell_type": "code", "source": ["%matplotlib inline\n", "import yaml\n"]}]})}),
    ("PyPI", "gunicorn", {"Procfile": "web: gunicorn app:app\n"}),
    ("PyPI", "uvicorn", {"Dockerfile": 'CMD ["uvicorn", "main:app"]\n'}),
    ("PyPI", "pymdown-extensions", {"mkdocs.yml": "markdown_extensions:\n  - pymdownx.superfences\n"}),
    ("PyPI", "markdown-it-py", {"b.py": "from markdown_it import MarkdownIt\n"}),
    ("PyPI", "pysocks", {"b.py": "import socks\n"}),
    ("PyPI", "opentelemetry-api", {"b.py": "from opentelemetry import trace\n"}),
    ("PyPI", "pyyaml", {"b.py": "print 'python 2'\nimport os, yaml\n"}),
    ("npm", "lodash", {"a.js": "const _ = await import(`lodash`)\n"}),
    ("npm", "lodash", {"a.js": "require.resolve('lodash')\n"}),
    ("npm", "babel-loader", {"webpack.config.js": "module.exports = {module: {rules: [{loader: 'babel-loader'}]}}\n"}),
    ("npm", "@babel/preset-env", {".babelrc": '{"presets": ["@babel/preset-env"]}'}),
    ("npm", "eslint-plugin-react", {"package.json": '{"eslintConfig": {"plugins": ["eslint-plugin-react"]}}'}),
    ("npm", "jquery", {"index.html": '<script src="node_modules/jquery/dist/jquery.js"></script>'}),
    ("Maven", "org.yaml:snakeyaml", {"A.java": "class A { Object y = new org.yaml.snakeyaml.Yaml(); }\n"}),
    ("crates.io", "bar", {"src/b.rs": "use foo::X;\n", "Cargo.toml": '[dependencies]\nfoo = { package = "bar", version = "1" }\n'}),
    ("crates.io", "bar-baz", {"src/b.rs": "use foo::X;\n", "Cargo.toml": '[dependencies.foo]\npackage = "bar-baz"\n'}),
])
def test_indirect_usage_is_not_reported_as_not_imported(tmp_path, eco, name, files):
    base = {"PyPI": {"a.py": "import json\n"}, "npm": {"a.js": "require('express')\n"}, "Maven": {},
            "crates.io": {}}[eco]
    index = _index(tmp_path, {**base, **files})
    assert _status(index, eco, name) == "imported"


@pytest.mark.parametrize("eco, name, files", [
    ("PyPI", "pyyaml", {"a.py": "import importlib\nimportlib.import_module(name)\n"}),
    ("Maven", "org.apache.tomcat.embed:tomcat-embed-core", {"A.java": "import org.springframework.boot.SpringApplication;\n"}),
    ("Maven", "com.fasterxml.jackson.core:jackson-databind", {"A.java": "import org.springframework.web.bind.annotation.RestController;\n"}),
    ("Maven", "org.yaml:snakeyaml", {"A.java": "import org.springframework.boot.SpringApplication;\n"}),
])
def test_runtime_loaded_packages_are_unknown_not_unused(tmp_path, eco, name, files):
    assert _status(_index(tmp_path, files), eco, name) == "unknown"


@pytest.mark.parametrize("eco, name, files", [
    ("PyPI", "pyyaml", {"a.py": "import json, importlib\nimportlib.import_module('json')\n", "Procfile": "web: gunicorn app:app\n"}),
    ("npm", "lodash", {"a.js": "require('express')\nconst s = 'lodash is great'\n", "webpack.config.js": "module.exports = {}\n"}),
    ("Maven", "org.yaml:snakeyaml", {"A.java": "import java.util.List;\nclass A { String s = \"org.other.Yaml\"; }\n"}),
    ("Maven", "com.fasterxml.jackson.core:jackson-databind", {"A.java": "import java.util.List;\n"}),
    ("crates.io", "bar", {"src/a.rs": "use baz::X;\n", "Cargo.toml": '[dependencies]\nfoo = { package = "qux", version = "1" }\n'}),
])
def test_safe_twins_stay_not_imported(tmp_path, eco, name, files):
    assert _status(_index(tmp_path, files), eco, name) == "not_imported"


def test_reachability_index_survives_hostile_files(tmp_path):
    _index(tmp_path, {"a.py": "import yaml\n", "nb.ipynb": "{not json", "n2.ipynb": '{"cells": "x"}', "n3.ipynb": "[1]",
                      "Cargo.toml": "[" * 5000, "package.json": "[" * 100000, ".babelrc": "\x00\xff",
                      "Procfile": "", "index.html": "<script>" * 1000})
    assert _status(sca.ImportIndex(tmp_path), "PyPI", "pyyaml") == "imported"
