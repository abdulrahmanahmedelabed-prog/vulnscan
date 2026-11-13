"""WP17: web data refresh tooling (tools/webdata/refresh.py, validate.py) and the user-side update_web_data() (§4.4).

Offline only: upstream downloads are replaced by a synthetic mirror (a fake `fetch`), and the GitHub release API and
its download host by a local HTTP server on 127.0.0.1 injected through updater.Net (as in tests/test_updater.py).
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import importlib.util
import io
import json
import os
import shutil
import sys
import tarfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from vulnscan import updater
from vulnscan.i18n import has_arabic
from vulnscan.webscan import data

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools" / "webdata"
DAY = "2026-11-20"


def _load(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, TOOLS / file)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


refresh = _load("kashif_webdata_refresh_test", "refresh.py")
validate = refresh.validate            # the instance refresh.py itself uses


@pytest.fixture(autouse=True)
def _fresh_data_cache():
    data.clear_cache()
    yield
    data.clear_cache()


def _small_hsts() -> bytes:
    """A valid but small hsts-preload.json.gz: schema-validating the real 50k-entry file costs ~0.3 s per call."""
    meta = json.loads(gzip.decompress((data.BUNDLED_DIR / "hsts-preload.json.gz").read_bytes()))["meta"]
    doc = {"meta": meta, "tlds": ["dev"], "entries": {"dev": True, "example.com": False}}
    return gzip.compress(json.dumps(doc, separators=(",", ":")).encode(), 9, mtime=0)


def _copy_bundled(dest: Path, small: bool = True) -> Path:
    dest.mkdir(parents=True)
    for n in validate.expected_files():
        shutil.copyfile(data.BUNDLED_DIR / n, dest / n)
    if small:
        (dest / "hsts-preload.json.gz").write_bytes(_small_hsts())
    return dest


@pytest.fixture
def snap(tmp_path) -> Path:
    """A copy of the bundled snapshot (data files only) with a generated manifest."""
    d = _copy_bundled(tmp_path / "snap")
    validate.write_manifest(d)
    return d


# ===================================================================================== validate.py

def test_bundled_snapshot_validates_file_by_file():
    errs = validate.validate_dir(data.BUNDLED_DIR)
    assert errs == [], "\n".join(errs)


def test_every_data_file_has_exactly_one_refresh_step():
    outputs = [o for s in refresh.STEPS for o in s.outputs]
    assert len(outputs) == len(set(outputs))
    assert sorted(outputs) == sorted(validate.expected_files())
    for s in refresh.STEPS:
        if s.module:
            assert (TOOLS / f"{s.module}.py").is_file(), s.name


def test_bundled_manifest_is_generated_and_current():
    path = data.BUNDLED_DIR / data.MANIFEST
    if not path.exists():
        pytest.skip("MANIFEST.json is generated at assembly: python tools/webdata/validate.py")
    assert validate.manifest_current(data.BUNDLED_DIR), "run python tools/webdata/validate.py"


def test_manifest_lists_every_file_with_sha256_and_is_deterministic(snap):
    man = validate.build_manifest(snap)
    assert data.validate(data.MANIFEST_SCHEMA, man) == []
    assert set(man["files"]) == set(validate.expected_files())
    for name, entry in man["files"].items():
        raw = (snap / name).read_bytes()
        assert entry["sha256"] == hashlib.sha256(raw).hexdigest() and entry["size"] == len(raw)
        assert entry["license"] and entry["source"] and entry["date"]
    assert man["generated"] == max(e["date"] for e in man["files"].values())
    assert validate.render_manifest(man) == validate.render_manifest(validate.build_manifest(snap))
    assert (snap / data.MANIFEST).read_bytes() == validate.render_manifest(man)
    assert data._load_manifest(snap) == man                       # the loader accepts what validate.py writes


def _set_meta(path: Path, **kw) -> None:
    obj = json.loads(path.read_text(encoding="utf-8"))
    obj["meta"].update(kw)
    path.write_text(json.dumps(obj, indent=1, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")


@pytest.mark.parametrize("damage, needle", [
    (lambda d: (d / "takeover.json").write_text('{"meta": {}}\n', encoding="utf-8"), "takeover.json: $.meta: missing"),
    (lambda d: (d / "csp-bypass.json").write_text("{not json", encoding="utf-8"), "csp-bypass.json: unreadable"),
    (lambda d: (d / "eol.json").unlink(), "eol.json: missing"),
    (lambda d: (d / "extra.json").write_text("{}", encoding="utf-8"), "extra.json: unknown data file"),
    (lambda d: _set_meta(d / "takeover.json", schema_version=2), "schema_version 2"),
    (lambda d: (d / "tls-profiles.json").write_bytes((d / "tls-profiles.json").read_bytes().replace(b"\n", b"\r\n")),
     "tls-profiles.json: CR line endings"),
    (lambda d: (d / "psl.dat.gz").write_bytes(gzip.compress(b"x\n", mtime=1)), "psl.dat.gz: gzip header carries a timestamp"),
    (lambda d: (d / "psl.dat.gz").write_bytes(gzip.compress(gzip.decompress((d / "psl.dat.gz").read_bytes()) + b"x\n",
                                                            mtime=0)), "psl.dat.meta.json: sha256 does not match"),
])
def test_validate_reports_each_kind_of_problem(snap, damage, needle):
    damage(snap)
    errs = validate.validate_dir(snap)
    assert any(needle in e for e in errs), errs
    assert validate.main(["--dir", str(snap)]) == 1


def test_validate_rejects_regexes_that_do_not_compile(snap):
    obj = json.loads((snap / "malicious-hosts.json").read_text(encoding="utf-8"))
    obj["signatures"][0]["pattern"] = "(unclosed"
    (snap / "malicious-hosts.json").write_text(json.dumps(obj, indent=1) + "\n", encoding="utf-8", newline="\n")
    assert any("regex does not compile" in e for e in validate.validate_dir(snap))


def test_validate_enforces_disjoint_deep_lists_and_the_never_list(snap):
    exposed = json.loads((snap / "exposed-paths.json").read_text(encoding="utf-8"))
    tech = json.loads((snap / "tech.json").read_text(encoding="utf-8"))
    platform = next(p for t in tech["technologies"] for p in t.get("deep_paths", []))
    exposed["paths"][0] = dict(exposed["paths"][0], path=platform["path"])
    exposed["paths"][1] = dict(exposed["paths"][1], path="/actuator/heapdump")
    (snap / "exposed-paths.json").write_text(json.dumps(exposed, indent=1) + "\n", encoding="utf-8", newline="\n")
    errs = validate.validate_dir(snap)
    assert any("listed in both files" in e for e in errs), errs
    assert any("never-list" in e and "heapdump" in e for e in errs), errs


def test_validate_size_budget(snap, monkeypatch):
    assert not validate.validate_dir(snap)
    monkeypatch.setattr(validate, "SIZE_BUDGET", 1000)
    assert any("budget" in e for e in validate.validate_dir(snap))


def test_release_checklist_max_age(snap):
    from datetime import date, timedelta
    newest = max(validate.build_manifest(snap)["files"].values(), key=lambda e: e["date"])["date"]
    oldest = min(e["date"] for e in validate.build_manifest(snap)["files"].values())
    ok_day = date.fromisoformat(oldest) + timedelta(days=30)
    assert validate.validate_dir(snap, max_age=30, today=ok_day) == []
    late = date.fromisoformat(newest) + timedelta(days=31)
    errs = validate.validate_dir(snap, max_age=30, today=late)
    assert errs and all("days old (limit 30)" in e for e in errs)
    assert any(e.startswith("psl.dat.gz:") for e in errs)          # a sidecar's age is reported on its data file
    assert validate.main(["--dir", str(snap), "--check", "--max-age", "30", "--today", late.isoformat()]) == 1


def test_validate_cli_writes_then_checks_the_manifest(tmp_path, capsys):
    d = _copy_bundled(tmp_path / "d")
    assert validate.main(["--dir", str(d), "--check"]) == 1           # no manifest yet
    assert validate.main(["--dir", str(d)]) == 0
    assert validate.main(["--dir", str(d), "--check"]) == 0
    _set_meta(d / "takeover.json", notes="changed")
    assert validate.main(["--dir", str(d), "--check"]) == 1           # stale manifest
    capsys.readouterr()


def test_pack_is_deterministic_flat_and_complete(snap, tmp_path):
    a = validate.pack(snap, tmp_path / "a")
    b = validate.pack(snap, tmp_path / "b")
    assert a.name == f"kashif-webdata-{validate.build_manifest(snap)['generated']}.tar.gz"
    assert a.read_bytes() == b.read_bytes()
    raw = a.read_bytes()
    assert raw[4:8] == b"\0\0\0\0" and not raw[3] & 0x08              # gzip: no timestamp, no file name
    with tarfile.open(a, "r:gz") as tar:
        members = tar.getmembers()
        names = [m.name for m in members]
        assert names == sorted(names) and set(names) == set(validate.expected_files()) | {data.MANIFEST}
        assert all(m.isreg() and "/" not in m.name and m.uid == 0 and m.gid == 0 and m.mode == 0o644 for m in members)
        for m in members:
            assert tar.extractfile(m).read() == (snap / m.name).read_bytes()
    assert validate.sha256_line(a) == f"{hashlib.sha256(raw).hexdigest()}  {a.name}"


# ====================================================================================== refresh.py

def _b64id(i: int) -> str:
    return base64.b64encode(hashlib.sha256(str(i).encode()).digest()).decode()


def _observatory_files(m) -> dict[str, str]:
    grades = ["A+", "A", "A-", "B+", "B", "B-", "C+", "C", "C-", "D+", "D", "D-", "F"]
    chart = ",\n".join(f'  [{100 - 5 * i}, "{grades[min(i, 12)]}"]' for i in range(21))
    tests = [t.split(":") for t in m.TEST_FILES]
    exps = [f"T{i}{k}" for i in range(len(tests)) for k in ("Pass", "Fail")]
    files = {
        "src/types.js": "export const Expectation = {\n" + "".join(f'  {e}: "{e.lower()}-slug",\n' for e in exps) + "};\n",
        "src/grader/charts.js": "export const GRADE_CHART = new Map([\n" + chart + "\n]);\n"
                                "export const MINIMUM_SCORE_FOR_EXTRA_CREDIT = 90;\n"
                                "export const SCORE_TABLE = new Map([\n" +
                                "".join(f'  [Expectation.{e}, {{ description: "d", modifier: {0 if e.endswith("Pass") else -5} }}],\n'
                                        for e in exps) + "]);\n",
        "src/constants.js": "export const ALGORITHM_VERSION = 6;\n",
    }
    for i, (name, stem) in enumerate(tests):
        files[f"src/analyzer/tests/{stem}.js"] = (f'export class T {{\n  static name = "{name}";\n'
                                                  f"  static possibleResults = [Expectation.T{i}Pass, Expectation.T{i}Fail];\n}}\n")
    return files


def _tls_profile(versions):
    return {"tls_versions": versions, "ciphersuites": ["TLS_AES_128_GCM_SHA256"],
            "ciphers": {"iana": ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"], "openssl": ["ECDHE-RSA-AES128-GCM-SHA256"]},
            "tls_curves": ["X25519"], "certificate_types": ["ecdsa"], "rsa_key_size": 2048,
            "maximum_certificate_lifespan": 366, "ocsp_staple": False}


def synthetic_mirror(variant: str = "") -> dict[str, bytes | None]:
    """URL -> body for every upstream input: tiny, but in each upstream's real format. `variant` changes content."""
    out: dict[str, bytes | None] = {}
    for step in refresh.STEPS:
        if step.kind != "upstream":
            continue
        m = refresh.load_module(step.module)
        inputs = step.inputs(m)
        body: dict[str, bytes | None] = {}
        if step.name == "psl":
            body["public_suffix_list.dat"] = ("// ===BEGIN ICANN DOMAINS===\ncom\nco.uk\nsa\n// ===END ICANN DOMAINS===\n"
                                              "// ===BEGIN PRIVATE DOMAINS===\ngithub.io\n" + variant +
                                              "// ===END PRIVATE DOMAINS===\n").encode()
        elif step.name == "hsts_preload":
            entries = [{"name": "dev", "mode": "force-https", "include_subdomains": True},
                       {"name": "example.com", "mode": "force-https"}, {"name": "pin.example", "policy": "custom"}]
            body["transport_security_state_static.json"] = ("// comment\n" + json.dumps({"entries": entries})).encode()
        elif step.name == "retire":
            body["jsrepository-v4.json"] = json.dumps({"jquery": {"vulnerabilities": [], "extractors": {
                "uri": ["/(§§version§§)/jquery(\\.min)?\\.js"]}}, "retire-example": {}}).encode()
        elif step.name == "csp_bypass":
            for i in inputs:
                key = Path(i.rel).stem
                body[i.rel] = json.dumps({"urls": [f"//{key}.example/cb?x=1", f"https://{key}2.example/a"],
                                          "needsEval": []}).encode()
        elif step.name == "cookies":
            body["open-cookie-database.csv"] = ("ID,Platform,Category,Cookie / Data Key name,Domain,Description,"
                                                "Retention period,Data Controller,User Privacy & GDPR Rights Portals,"
                                                "Wildcard match\n1,ExampleAnalytics,Analytics,_exa_visitor_id,,d,1y,c,,0\n"
                                                "2,Cookiebot,Functional,CookieConsentX,,d,1y,c,,0\n").encode()
        elif step.name == "tech":
            body["tech-detect.yaml"] = b"id: tech-detect\nhttp:\n  - method: GET\n    matchers:\n"
        elif step.name == "favicons":
            body["favicon-detect.yaml"] = ('id: favicon-detect\nhttp:\n  - matchers:\n'
                                           '      - type: dsl\n        name: "jenkins"\n        dsl:\n'
                                           '          - "\\"81586312\\"==mmh3(base64_py(body))"\n').encode()
        elif step.name == "eol":
            for n, i in enumerate(inputs):
                if n < 12:
                    body[i.rel] = (f"---\ntitle: P{n}\nreleases:\n-   releaseCycle: \"1.{n}\"\n    eol: 2030-01-01\n"
                                   f"    latest: \"1.{n}.3\"\n    releaseDate: 2020-01-0{n % 9 + 1}\n---\n\nText.\n").encode()
                else:
                    body[i.rel] = None                                  # 404 upstream: optional
        elif step.name == "server_cve":
            vulns = [{"cve": f"CVE-2020-{1000 + i}", "severity": "high", "name": f"issue {i}",
                      "affected": [{"introduced": "1.0", "fixed": f"1.{i + 1}"}]} for i in range(10)]
            for i in inputs:
                if i.rel.endswith("known-vulnerabilities.json"):
                    body[i.rel] = json.dumps({"vulnerabilities": vulns}).encode()
                elif i.rel == "security_advisories.xml":
                    items = "".join(f'<item name="bug {k}" severity="major" cve="2021-{2000 + k}" good="1.{k}.1+" '
                                    f'vulnerable="1.{k}.0"/>' for k in range(10))
                    body[i.rel] = f"<security>{items}</security>".encode()
                else:
                    body[i.rel] = (b'<document><section name="Fixed in Apache Tomcat 9.0.1"><p><strong>Important: '
                                   b"X</strong><cve>CVE-2022-3000</cve></p><p>Affects: 9.0.0</p></section></document>")
        elif step.name == "ct_logs":
            logs = [{"log_id": _b64id(k), "description": f"log {k}", "state": {"usable": {"timestamp": "2025-01-01T00:00:00Z"}}}
                    for k in range(3)]
            body["log_list.json"] = json.dumps({"version": "9.1", "log_list_timestamp": "2026-11-18T00:00:00Z",
                                                "operators": [{"name": "Op", "logs": logs}]}).encode()
        elif step.name == "tls_profiles":
            body[inputs[0].rel] = json.dumps({"version": 6.0, "configurations": {
                "intermediate": _tls_profile(["TLSv1.2", "TLSv1.3"]), "modern": _tls_profile(["TLSv1.3"])}}).encode()
        elif step.name == "observatory":
            body.update({rel: text.encode() for rel, text in _observatory_files(m).items()})
        for i in inputs:
            assert i.rel in body, (step.name, i.rel)
            out[i.urls[0]] = body[i.rel]
    return out


def _relax(name: str, m) -> None:
    """Synthetic inputs are tiny: relax the generators' 'suspiciously small' guards (module constants only)."""
    for attr in ("MIN_RULES", "MIN_ENTRIES", "MIN_TLDS", "MIN_LIBS", "MIN_HASHES", "MIN_LOGS", "MIN_JSONP", "MIN_ANGULAR"):
        if hasattr(m, attr):
            setattr(m, attr, 1)


def _fake_fetch(table: dict, hits: list | None = None):
    def fetch(url: str):
        if hits is not None:
            hits.append(url)
        assert url.startswith("https://") and url in table, url
        return table[url]
    return fetch


def _quiet(*_a, **_k):
    pass


@pytest.fixture(scope="module")
def mirror(tmp_path_factory):
    d = tmp_path_factory.mktemp("mirror")
    hits: list[str] = []
    refresh.record(refresh.STEPS, d, DAY, fetch=_fake_fetch(synthetic_mirror(), hits), log=_quiet)
    return d


def test_record_writes_sources_index(mirror):
    index = json.loads((mirror / refresh.SOURCES_INDEX).read_text(encoding="utf-8"))
    assert index["date"] == DAY
    eol = index["inputs"]["eol"]
    assert sum(1 for e in eol.values() if e.get("missing")) == len(eol) - 12
    psl = index["inputs"]["psl"]["public_suffix_list.dat"]
    raw = (mirror / "psl" / "public_suffix_list.dat").read_bytes()
    assert psl["sha256"] == hashlib.sha256(raw).hexdigest() and psl["url"].startswith("https://publicsuffix.org/")


def _run(out: Path, mirror: Path, **kw) -> dict:
    return refresh.refresh(out=out, sources=mirror, module_hook=_relax, log=_quiet, **kw)


def test_refresh_is_byte_identical_twice(mirror, tmp_path):
    a = _copy_bundled(tmp_path / "a")
    b = _copy_bundled(tmp_path / "b")
    ra = _run(a, mirror, pack_dir=tmp_path / "pa")
    rb = _run(b, mirror, pack_dir=tmp_path / "pb")
    assert ra["date"] == rb["date"] == DAY                          # --sources defaults to the recording date
    names = sorted(p.name for p in a.iterdir())
    assert names == sorted(p.name for p in b.iterdir()) == sorted([*validate.expected_files(), data.MANIFEST])
    for n in names:
        assert (a / n).read_bytes() == (b / n).read_bytes(), n
    assert Path(ra["asset"]).read_bytes() == Path(rb["asset"]).read_bytes()
    assert validate.validate_dir(a) == [] and validate.manifest_current(a)
    # every upstream-derived file was rebuilt from the mirror with the refresh date (ct-logs keeps the list's own)
    man = json.loads((a / data.MANIFEST).read_text(encoding="utf-8"))
    dates = {n: e["date"] for n, e in man["files"].items()}
    assert dates.pop("ct-logs.json") == "2026-11-18"
    assert set(dates.values()) == {DAY} and man["generated"] == DAY
    retire = json.loads(gzip.decompress((a / "retire-jsrepository.json.gz").read_bytes()))
    assert set(retire["repository"]) == {"jquery"} and retire["meta"]["upstream_version"].startswith("master@")
    # a second run over its own output changes nothing
    assert _run(a, mirror)["changed"] == []


def test_refresh_check_mode_reports_and_installs_nothing(mirror, tmp_path):
    out = _copy_bundled(tmp_path / "out")
    before = {p.name: p.read_bytes() for p in out.iterdir()}
    res = _run(out, mirror, check=True)
    assert data.MANIFEST in res["changed"] and "psl.dat.gz" in res["changed"]
    assert {p.name: p.read_bytes() for p in out.iterdir()} == before
    _run(out, mirror)
    assert _run(out, mirror, check=True)["changed"] == []
    assert refresh.main(["--out", str(out), "--sources", str(mirror), "--check", "--only", "errors,takeover"]) == 0


def test_refresh_only_some_steps_keeps_the_other_files(mirror, tmp_path):
    out = _copy_bundled(tmp_path / "out")
    keep = (out / "eol.json").read_bytes()
    res = _run(out, mirror, steps=refresh.select("psl,takeover"))
    assert set(res["changed"]) == {"psl.dat.gz", "psl.dat.meta.json", "takeover.json", data.MANIFEST}
    assert (out / "eol.json").read_bytes() == keep
    with pytest.raises(refresh.RefreshError, match="unknown step"):
        refresh.select("nope")


def test_a_failing_step_installs_nothing(mirror, tmp_path):
    out = _copy_bundled(tmp_path / "out")
    before = {p.name: p.read_bytes() for p in out.iterdir()}
    with pytest.raises(refresh.RefreshError, match="psl"):
        refresh.refresh(out=out, sources=mirror, log=_quiet)          # real guards: the synthetic PSL is too small
    assert {p.name: p.read_bytes() for p in out.iterdir()} == before


def test_a_tampered_mirror_never_builds(mirror, tmp_path):
    bad = tmp_path / "bad"
    shutil.copytree(mirror, bad)
    p = bad / "retire" / "jsrepository-v4.json"
    p.write_bytes(p.read_bytes().replace(b"jquery", b"jquerx"))
    out = _copy_bundled(tmp_path / "out")
    with pytest.raises(refresh.RefreshError, match="recorded sha256"):
        _run(out, bad)
    assert not (out / data.MANIFEST).exists()


def test_download_falls_back_to_a_mirror_and_says_so(tmp_path):
    table = synthetic_mirror()
    first = refresh._psl_inputs(refresh.load_module("psl"))[0].urls

    def fetch(url):
        if url == first[0]:
            raise refresh.RefreshError("blocked")
        return table.get(url, table[first[0]] if url == first[1] else None)

    mirror = tmp_path / "m"
    refresh.record([refresh.BY_NAME["psl"]], mirror, DAY, fetch=fetch, log=_quiet)
    out = _copy_bundled(tmp_path / "out")
    _run(out, mirror, steps=[refresh.BY_NAME["psl"]])
    meta = json.loads((out / "psl.dat.meta.json").read_text(encoding="utf-8"))["meta"]
    assert meta["notes"] == f"downloaded from {first[1]}"
    with pytest.raises(refresh.RefreshError, match="blocked"):
        refresh.record([refresh.BY_NAME["psl"]], tmp_path / "m2", DAY,
                       fetch=lambda u: (_ for _ in ()).throw(refresh.RefreshError("blocked")), log=_quiet)


def test_inputs_change_the_output_and_its_provenance(tmp_path):
    m1, m2 = tmp_path / "m1", tmp_path / "m2"
    psl = [refresh.BY_NAME["psl"]]
    refresh.record(psl, m1, DAY, fetch=_fake_fetch(synthetic_mirror()), log=_quiet)
    refresh.record(psl, m2, DAY, fetch=_fake_fetch(synthetic_mirror("example.app\n")), log=_quiet)
    a, b = _copy_bundled(tmp_path / "a"), _copy_bundled(tmp_path / "b")
    _run(a, m1, steps=psl)
    _run(b, m2, steps=psl)
    assert (a / "psl.dat.gz").read_bytes() != (b / "psl.dat.gz").read_bytes()
    assert json.loads((b / "psl.dat.meta.json").read_text(encoding="utf-8"))["rules"] == 5


def test_restamp_changes_only_the_meta_date():
    text = '{\n "items": [{"date": "2026-01-01"}],\n "meta": {"x": 1, "date": "2026-01-01"}\n}\n'
    out = refresh.restamp(text, "2026-12-01")
    assert out == '{\n "items": [{"date": "2026-01-01"}],\n "meta": {"x": 1, "date": "2026-12-01"}\n}\n'
    assert refresh.restamp(out, "2026-12-01") == out
    with pytest.raises(refresh.RefreshError):
        refresh.restamp('{"meta": {}}', "2026-12-01")


def test_curated_dates_can_be_kept(mirror, tmp_path):
    out = _copy_bundled(tmp_path / "out")
    before = (out / "exposed-paths.json").read_bytes()
    _run(out, mirror, steps=[refresh.BY_NAME["exposed-paths.json"]], keep_curated_dates=True)
    assert (out / "exposed-paths.json").read_bytes() == before
    _run(out, mirror, steps=[refresh.BY_NAME["exposed-paths.json"]])
    after = json.loads((out / "exposed-paths.json").read_text(encoding="utf-8"))
    old = json.loads(before.decode("utf-8"))
    assert after["meta"]["date"] == DAY and after["paths"] == old["paths"]


@pytest.mark.parametrize("url", ["http://raw.githubusercontent.com/x", "https://evil.example/x",
                                 "https://user:pw@raw.githubusercontent.com/x", "https://raw.githubusercontent.com:8443/x",
                                 "file:///etc/passwd"])
def test_downloads_are_https_on_allowlisted_hosts_only(url):
    with pytest.raises(refresh.RefreshError, match="refusing"):
        refresh.check_url(url)
    refresh.check_url("https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v4.json")


def test_refresh_list_names_every_upstream(capsys):
    assert refresh.main(["--list"]) == 0
    text = capsys.readouterr().out
    for s in refresh.STEPS:
        assert s.name in text


# ============================================================================ update_web_data() (updater)

class Fake:
    """A local stand-in for the GitHub release API and its download host. routes: path -> (status, body)."""

    def __init__(self):
        self.routes: dict[str, tuple[int, bytes]] = {}
        self.hits: list[str] = []
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                fake.hits.append(self.path)
                status, body = fake.routes.get(self.path, (404, b"{}"))
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        self.net = updater.Net(api_url=self.base + "/api/latest", allowed_hosts=frozenset({"127.0.0.1"}),
                               require_https=False, asset_path="/dl/{tag}/{name}")

    def release(self, files: dict[str, bytes], tag: str = "v1.1.3", sums: str | None = None, urls: dict | None = None):
        if sums is None:
            sums = "".join(f"{hashlib.sha256(b).hexdigest()}  {n}\n" for n, b in files.items())
        assets = []
        for name, body in {**files, "SHA256SUMS.txt": sums.encode()}.items():
            self.routes[f"/dl/{tag}/{name}"] = (200, body)
            url = (urls or {}).get(name, f"{self.base}/dl/{tag}/{name}")
            assets.append({"name": name, "browser_download_url": url, "size": len(body)})
        self.routes["/api/latest"] = (200, json.dumps({"tag_name": tag, "prerelease": False, "draft": False, "body": "",
                                                       "html_url": "", "published_at": "", "assets": assets}).encode())

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def fake():
    f = Fake()
    yield f
    f.close()


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("KASHIF_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("VULNSCAN_HOME", raising=False)
    return tmp_path / "home" / "webdata"


def _snapshot(tmp_path: Path, day: str, name: str = "src") -> Path:
    """A complete snapshot dated `day` (every file restamped), with its manifest."""
    d = _copy_bundled(tmp_path / f"{name}-{day}")
    for n in validate.expected_files():
        if n in data.SCHEMAS and not n.endswith(".gz"):
            (d / n).write_text(refresh.restamp((d / n).read_text(encoding="utf-8"), day), encoding="utf-8", newline="\n")
        elif n in data.SCHEMAS:
            obj = json.loads(gzip.decompress((d / n).read_bytes()))
            obj["meta"]["date"] = day
            (d / n).write_bytes(gzip.compress(json.dumps(obj, separators=(",", ":")).encode(), 9, mtime=0))
    validate.write_manifest(d)
    return d


_ASSETS: dict[str, tuple[str, bytes]] = {}


def _asset(tmp_path: Path, day: str) -> tuple[str, bytes]:
    """The release asset of a complete snapshot dated `day` (built once per day: packing is the slow part)."""
    if day not in _ASSETS:
        p = validate.pack(_snapshot(tmp_path, day), tmp_path / f"pack-{day}")
        _ASSETS[day] = (p.name, p.read_bytes())
    return _ASSETS[day]


def _tar(members: dict[str, bytes], kinds: dict[str, bytes] | None = None) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, raw in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            tar.addfile(info, io.BytesIO(raw))
        for name, kind in (kinds or {}).items():
            info = tarfile.TarInfo(name)
            info.type = kind
            info.linkname = "/etc/passwd"
            tar.addfile(info)
    return buf.getvalue()


def _bundled_date() -> str:
    return data._bundled_generated()


def test_update_installs_a_verified_newer_snapshot(fake, home, tmp_path):
    name, body = _asset(tmp_path, "2099-01-02")
    fake.release({name: body, "kashif-linux-x86_64": b"bin"})
    phases = []
    res = updater.update_web_data(net=fake.net, progress=lambda p, d, t: phases.append(p))
    assert res["status"] == "installed" and res["current"] == res["installed"] == "2099-01-02"
    assert res["path"] == str(home / "2099-01-02") and res["asset"] == name and res["release"] == "1.1.3"
    assert {"check", "download", "verify", "install"} <= set(phases)
    assert has_arabic(res["message"]) and "2099-01-02" in res["message"] and res["message_en"].startswith("Installed")
    assert sorted(p.name for p in home.iterdir()) == ["2099-01-02"]          # no temp leftovers
    files = sorted(p.name for p in (home / "2099-01-02").iterdir())
    assert files == sorted([*validate.expected_files(), data.MANIFEST])
    # the loader now uses it, file by file, and the staleness notes follow it
    assert data.user_dir() == home / "2099-01-02"
    assert data.path_for("takeover.json") == (home / "2099-01-02" / "takeover.json", "user")
    assert data.meta("takeover.json")["date"] == "2099-01-02"
    assert res["notes"] == data.staleness()
    # nothing but the API, SHA256SUMS.txt and the asset was requested
    assert fake.hits == ["/api/latest", "/dl/v1.1.3/SHA256SUMS.txt", f"/dl/v1.1.3/{name}"]


def test_check_only_and_up_to_date(fake, home, tmp_path):
    name, body = _asset(tmp_path, "2099-01-02")
    fake.release({name: body})
    res = updater.update_web_data(net=fake.net, check_only=True)
    assert res["status"] == "available" and res["latest"] == "2099-01-02" and not home.exists()
    assert fake.hits == ["/api/latest"]
    updater.update_web_data(net=fake.net)
    res = updater.update_web_data(net=fake.net)
    assert res["status"] == "up_to_date" and res["current"] == "2099-01-02" and res["path"] == str(home / "2099-01-02")
    assert "2099-01-02" in res["message_en"] and has_arabic(res["message"])


def test_an_archive_older_than_the_bundled_data_is_not_installed(fake, home, tmp_path):
    name, body = _asset(tmp_path, "2020-01-01")
    fake.release({name: body})
    res = updater.update_web_data(net=fake.net)
    assert res["status"] == "up_to_date" and res["current"] == _bundled_date() and not home.exists()


def test_newest_asset_of_several_is_chosen(fake, home, tmp_path):
    n1, b1 = _asset(tmp_path, "2099-01-02")
    n2, b2 = _asset(tmp_path, "2099-03-04")
    fake.release({n1: b1, n2: b2})
    assert updater.update_web_data(net=fake.net)["installed"] == "2099-03-04"


@pytest.mark.parametrize("case, code", [
    ("no_asset", "webdata_missing"), ("no_sums", "checksum_missing"), ("sums_without_line", "checksum_missing"),
    ("mismatch", "checksum_mismatch"), ("foreign_url", "bad_host"),
])
def test_release_level_failures_change_nothing(fake, home, tmp_path, case, code):
    name, body = _asset(tmp_path, "2099-01-02")
    if case == "no_asset":
        fake.release({"kashif-linux-x86_64": b"x"})
    elif case == "no_sums":
        fake.release({name: body})
        api = json.loads(fake.routes["/api/latest"][1])
        api["assets"] = [a for a in api["assets"] if a["name"] != "SHA256SUMS.txt"]
        fake.routes["/api/latest"] = (200, json.dumps(api).encode())
    elif case == "sums_without_line":
        fake.release({name: body}, sums=f"{'0' * 64}  kashif-linux-x86_64\n")
    elif case == "mismatch":
        fake.release({name: body}, sums=f"{'0' * 64}  {name}\n")
    else:
        fake.release({name: body}, urls={name: f"{fake.base}/elsewhere/{name}"})
    with pytest.raises(updater.UpdateError) as e:
        updater.update_web_data(net=fake.net)
    assert e.value.code == code
    assert not home.exists() or list(home.iterdir()) == []
    assert data.user_dir() is None and data.path_for("takeover.json")[1] == "bundled"


_BAD: dict[str, bytes] = {}


def _bad_archives(tmp_path: Path) -> dict[str, bytes]:
    if _BAD:
        return _BAD
    good = _snapshot(tmp_path, "2099-01-02", name="bad")
    files = {p.name: p.read_bytes() for p in good.iterdir()}
    man = json.loads(files[data.MANIFEST])

    def with_manifest(f, m):
        return _tar({**f, data.MANIFEST: json.dumps(m).encode()})

    tampered = dict(files, **{"takeover.json": files["takeover.json"].replace(b"github", b"githab")})
    unlisted = dict(files, **{"zzz.json": b"{}"})
    bad_schema = json.loads(files["takeover.json"])
    bad_schema["providers"] = []
    raw = json.dumps(bad_schema).encode()
    man_bad_schema = json.loads(json.dumps(man))
    man_bad_schema["files"]["takeover.json"].update(sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))
    _BAD.update({
        "garbage": b"not a tar.gz",
        "traversal": _tar({"../evil.json": b"{}", **files}),
        "subdir": _tar({"sub/takeover.json": b"{}"}),
        "symlink": _tar({}, {"takeover.json": tarfile.SYMTYPE}),
        "hardlink": _tar({}, {"takeover.json": tarfile.LNKTYPE}),
        "no_manifest": _tar({k: v for k, v in files.items() if k != data.MANIFEST}),
        "tampered": _tar(tampered),
        "unlisted": _tar(unlisted),
        "wrong_date": with_manifest(files, dict(man, generated="2099-01-03")),
        "schema_invalid": with_manifest(dict(files, **{"takeover.json": raw}), man_bad_schema),
    })
    return _BAD


@pytest.mark.parametrize("kind", ["garbage", "traversal", "subdir", "symlink", "hardlink", "no_manifest", "tampered",
                                  "unlisted", "wrong_date", "schema_invalid"])
def test_invalid_archives_are_refused_and_nothing_changes(fake, home, tmp_path, kind):
    body = _bad_archives(tmp_path)[kind]
    name = "kashif-webdata-2099-01-02.tar.gz"
    fake.release({name: body})                       # SHA256SUMS matches: the content checks must catch it
    with pytest.raises(updater.WebDataError) as e:
        updater.update_web_data(net=fake.net)
    assert e.value.code == "webdata_invalid"
    assert e.value.to_dict()["message_en"] and has_arabic(e.value.to_dict()["message"])
    assert list(home.iterdir()) == []                # the temp download was removed, nothing was installed
    assert not (tmp_path / "evil.json").exists() and not (home.parent / "evil.json").exists()
    assert data.user_dir() is None


def test_newer_schema_version_is_refused_with_its_own_message(fake, home, tmp_path):
    good = _snapshot(tmp_path, "2099-01-02")
    man = json.loads((good / data.MANIFEST).read_text(encoding="utf-8"))
    man["schema_version"] = data.SCHEMA_VERSION + 1
    files = {p.name: p.read_bytes() for p in good.iterdir()}
    fake.release({"kashif-webdata-2099-01-02.tar.gz": _tar({**files, data.MANIFEST: json.dumps(man).encode()})})
    with pytest.raises(updater.WebDataError) as e:
        updater.update_web_data(net=fake.net)
    assert e.value.code == "webdata_schema" and "newer version of Kashif" in e.value.message_en
    assert list(home.iterdir()) == []


def test_offline_keeps_the_bundled_snapshot(fake, home):
    fake.close()
    with pytest.raises(updater.UpdateError) as e:
        updater.update_web_data(net=fake.net)
    assert e.value.code == "offline"
    assert data.user_dir() is None and data.path_for("eol.json") == (data.BUNDLED_DIR / "eol.json", "bundled")
    fake.close = lambda: None


def test_too_large_archive_is_refused(fake, home, tmp_path, monkeypatch):
    name, body = _asset(tmp_path, "2099-01-02")
    fake.release({name: body})
    monkeypatch.setattr(updater, "MAX_WEBDATA", 1000)
    with pytest.raises(updater.UpdateError) as e:
        updater.update_web_data(net=fake.net)
    assert e.value.code == "too_large"
    assert not home.exists() or list(home.iterdir()) == []


def test_a_corrupted_installed_file_falls_back_to_the_bundled_one(fake, home, tmp_path):
    name, body = _asset(tmp_path, "2099-01-02")
    fake.release({name: body})
    updater.update_web_data(net=fake.net)
    (home / "2099-01-02" / "takeover.json").write_text('{"meta": {}}', encoding="utf-8")
    data.clear_cache()
    assert data.path_for("takeover.json") == (data.BUNDLED_DIR / "takeover.json", "bundled")
    assert data.path_for("eol.json")[1] == "user"
    # and the updater no longer counts it as installed: the same date is reinstalled (repaired) atomically
    res = updater.update_web_data(net=fake.net)
    assert res["status"] == "installed" and json.loads((home / "2099-01-02" / "takeover.json").read_bytes())["providers"]
    assert sorted(p.name for p in home.iterdir()) == ["2099-01-02"]


def test_old_snapshots_are_pruned_and_leftovers_removed(fake, home, tmp_path):
    home.mkdir(parents=True)
    stale = home / ".incoming-abc"
    stale.mkdir()
    os.utime(stale, (1, 1))
    fresh = home / ".incoming-new"
    fresh.mkdir()
    (home / "notes.txt").write_text("mine", encoding="utf-8")
    for day in ("2099-01-02", "2099-02-03", "2099-03-04"):
        name, body = _asset(tmp_path, day)
        fake.release({name: body})
        updater.update_web_data(net=fake.net)
    assert sorted(p.name for p in home.iterdir()) == [".incoming-new", "2099-02-03", "2099-03-04", "notes.txt"]
    assert data.user_dir() == home / "2099-03-04"


def test_an_unknown_future_file_is_carried_in_the_manifest_but_not_installed(fake, home, tmp_path):
    good = _snapshot(tmp_path, "2099-01-02")
    (good / "future.json").write_text('{"meta": {}}\n', encoding="utf-8")
    files = {p.name: p.read_bytes() for p in good.iterdir()}
    man = json.loads(files[data.MANIFEST])
    man["files"]["future.json"] = {"sha256": hashlib.sha256(files["future.json"]).hexdigest(), "size": len(files["future.json"])}
    fake.release({"kashif-webdata-2099-01-02.tar.gz": _tar({**files, data.MANIFEST: json.dumps(man).encode()})})
    res = updater.update_web_data(net=fake.net)
    assert res["status"] == "installed" and not (home / "2099-01-02" / "future.json").exists()
    assert data.path_for("eol.json")[1] == "user"


def test_staleness_notes_follow_the_installed_snapshot(fake, home, tmp_path):
    from datetime import datetime, timedelta
    late = datetime.fromisoformat(_bundled_date() + "T00:00:00+00:00") + timedelta(days=200)
    notes = data.staleness(now=late)
    assert {"data_old", "vuln_data_old"} <= {n["code"] for n in notes}
    assert all(has_arabic(n["ar"]) and not has_arabic(n["en"]) for n in notes)
    day = (late - timedelta(days=10)).date().isoformat()
    name, body = _asset(tmp_path, day)
    fake.release({name: body})
    updater.update_web_data(net=fake.net)
    assert data.snapshot_date().isoformat() == day
    assert data.staleness(now=late) == []
    assert data.as_of("en") == f"web data as of {day}"


def test_web_data_messages_are_bilingual():
    for code, (ar, en) in updater.WEB_DATA_TEXT.items():
        assert has_arabic(ar) and en and not has_arabic(en), code
        assert ("{date}" in ar) == ("{date}" in en), code
    e = updater.WebDataError("webdata_invalid", "x")
    assert isinstance(e, updater.UpdateError) and e.to_dict()["error"] == "webdata_invalid"


def test_release_layout_temp_names_are_not_next_to_the_binary():
    """update_web_data works in <home>/webdata only; the binary updater's mkstemp/glob prefixes are untouched."""
    src = (ROOT / "vulnscan" / "updater.py").read_text(encoding="utf-8")
    assert 'mkstemp(prefix=_WEB_TMP' in src and 'dir=root' in src
