"""Rule-authoring kit: annotations, the fixture test runner, lint, scaffolding, pack / install safety."""
import io
import json
import pathlib
import zipfile
from xml.etree import ElementTree as ET

import pytest

from vulnscan import ruletest as rt
from vulnscan.scanner import scan_path


@pytest.fixture()
def pack(tmp_path):
    return rt.new_pack(tmp_path / "acme", language="python")


def _model(pack):
    return pack / "models" / "acme.json"


def _edit_model(pack, fn):
    data = json.loads(_model(pack).read_text(encoding="utf-8"))
    fn(data)
    _model(pack).write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")


def _codes(rep, level="error"):
    return {i.code for i in rep.issues if i.level == level}


# ------------------------------------------------------------------------------------------------ annotations
def test_parse_annotations_trailing_standalone_and_stacked():
    text = "\n".join([
        "x = 1  # kashif: expect DF004, cwe-89",          # 1: trailing -> its own line
        "# kashif: expect ACME001",                        # 2: stacked, both speak about line 5
        "// kashif: expect-none ACME002",                  # 3
        "",                                                # 4
        "run(x)",                                          # 5
        "safe(x)  /* kashif: expect-none */",              # 6
        "gap(x)  -- kashif: expect-todo ACME003 -- tracked in ISSUE-1",   # 7
    ])
    exps, problems = rt.parse_annotations(text)
    assert not problems
    got = {(e.at, e.line, e.kind, e.ids) for e in exps}
    assert got == {(1, 1, "expect", ("DF004", "CWE-89")), (2, 5, "expect", ("ACME001",)),
                   (3, 5, "none", ("ACME002",)), (6, 6, "none", ()), (7, 7, "todo", ("ACME003",))}


def test_parse_annotations_reports_malformed_ones():
    exps, problems = rt.parse_annotations("a()  # kashif: expect\n# kashif: expect X1\n")
    assert exps == [] and problems == [(1, "annot_no_ids"), (2, "annot_no_target")]
    assert rt.parse_annotations("# kashif: expectation of nothing\nfoo()\n") == ([], [])


# ---------------------------------------------------------------------------------------------- scaffolding
@pytest.mark.parametrize("language", rt.SCAFFOLD_LANGUAGES)
def test_scaffold_is_green_in_every_language(tmp_path, language):
    p = rt.new_pack(tmp_path / f"demo-{language}", language=language)
    for rel in ("kashifpack.json", "README.md", "queries/debug-enabled.vql"):
        assert (p / rel).is_file()
    lint = rt.lint_pack(p)
    assert lint.ok and not lint.issues, lint.to_text()
    rep = rt.run_tests(p)
    assert rep.exit_code == 0, rep.to_text()
    assert rep.expected == 5 and rep.matched == 5 and len(rep.files) == 2
    model = json.loads(next((p / "models").glob("*.json")).read_text(encoding="utf-8"))
    assert "_comment" in model["sinks"][0] and "_comment" in model["sources"][0]      # every field is explained


def test_new_pack_refuses_bad_input(tmp_path, pack):
    with pytest.raises(rt.PackError):
        rt.new_pack(pack)                                    # not empty
    with pytest.raises(rt.PackError):
        rt.new_pack(tmp_path / "x", name="Bad Name")
    with pytest.raises(rt.PackError):
        rt.new_pack(tmp_path / "y", language="cobol")
    assert rt.new_pack(pack, force=True) == pack


# ---------------------------------------------------------------------------------------------- test runner
def test_runner_reports_missing_and_unexpected_per_line(pack):
    vuln = pack / "fixtures" / "vulnerable.py"
    vuln.write_text(vuln.read_text(encoding="utf-8").replace("expect ACME001", "expect ACME999"), encoding="utf-8")
    safe = pack / "fixtures" / "safe.py"
    safe.write_text(safe.read_text(encoding="utf-8") + "\n\ndef leak():\n    examplelib.run_report(examplelib.read_untrusted())\n",
                    encoding="utf-8")
    rep = rt.run_tests(pack)
    assert rep.exit_code == 1 and not rep.passed
    assert (rep.missing, rep.unexpected) == (1, 2)
    by = {(o.file, o.status, o.rule, o.line) for f in rep.files for o in f.outcomes if o.failed}
    leak_line = safe.read_text(encoding="utf-8").splitlines().index("    examplelib.run_report(examplelib.read_untrusted())") + 1
    assert by == {("vulnerable.py", "missing", "ACME999", 7), ("vulnerable.py", "unexpected", "ACME001", 7),
                  ("safe.py", "unexpected", "ACME001", leak_line)}
    text = rep.to_text()
    assert "FAIL vulnerable.py" in text and "  - line 7: expected ACME999" in text and "  + line 7: unexpected ACME001" in text
    assert "| examplelib.run_report(query)" in text and text.rstrip().endswith("FAILED")
    d = rep.to_dict()
    assert d["exit_code"] == 1 and d["missing"] == 1 and json.dumps(d)


def test_runner_junit_xml(pack, tmp_path):
    ok = ET.fromstring(rt.run_tests(pack).to_junit())
    assert ok.tag == "testsuites" and ok.get("tests") == "2" and ok.get("failures") == "0"
    (pack / "fixtures" / "safe.py").write_text("import examplelib\nexamplelib.enable_debug()  # kashif: expect-none\n", encoding="utf-8")
    out = tmp_path / "junit.xml"
    assert rt.main(["test", str(pack), "--junit", str(out), "-q"]) == 1
    root = ET.parse(out).getroot()
    assert root.get("failures") == "1"
    cases = {c.get("name"): c for c in root.iter("testcase")}
    assert set(cases) == {"safe.py", "vulnerable.py"}
    assert cases["vulnerable.py"].find("failure") is None
    assert "expect-none" in cases["safe.py"].find("failure").text


def test_runner_cwe_expectation_todo_and_scope(tmp_path):
    fx = tmp_path / "fx"
    fx.mkdir()
    (fx / "app.py").write_text(
        "import os\nfrom flask import request\n\n\ndef run():\n"
        "    os.system(request.args['c'])  # kashif: expect CWE-78\n"
        "    os.system(request.args['d'])\n"
        "    print('x')  # kashif: expect-todo NOPE001 -- not detected yet\n", encoding="utf-8")
    rep = rt.run_tests(None, fx)                              # built-in rules only
    assert rep.exit_code == 0, rep.to_text()                  # line 7 is not annotated, but scope=pack tolerates built-ins
    assert rep.to_dict()["known_gaps"] == 1 and "~ line 8" in rep.to_text()
    strict = rt.run_tests(None, fx, scope="all")
    assert strict.exit_code == 1 and {o.line for f in strict.files for o in f.outcomes if o.status == "unexpected"} == {7}
    (fx / "app.py").write_text("import os\nfrom flask import request\n\n\ndef run():\n"
                               "    os.system(request.args['c'])  # kashif: expect CWE-79\n", encoding="utf-8")
    assert rt.run_tests(None, fx).missing == 1


def test_runner_errors_stop_the_run(pack, tmp_path):
    assert rt.run_tests(tmp_path / "nope").exit_code == 2
    assert rt.run_tests(pack, tmp_path / "no-fixtures").exit_code == 2
    _model(pack).write_text("{not json", encoding="utf-8")          # the engine would silently skip it
    rep = rt.run_tests(pack)
    assert rep.exit_code == 2 and "acme.json" in rep.errors[0] and "ERROR" in rep.to_text()
    assert ET.fromstring(rep.to_junit()).get("errors") == "1"


def test_runner_broken_query_and_malformed_annotation(pack):
    (pack / "queries" / "debug-enabled.vql").write_text("from call c where select", encoding="utf-8")
    assert rt.run_tests(pack).exit_code == 2
    rt.new_pack(pack, force=True)
    (pack / "fixtures" / "extra.py").write_text("x = 1  # kashif: expect\n", encoding="utf-8")
    rep = rt.run_tests(pack)
    assert rep.exit_code == 2 and "extra.py:1" in rep.errors[0]


def test_runner_arabic_output(pack):
    text = rt.run_tests(pack, lang="ar").to_text()
    assert "نجح" in text and "PASS" not in text


# ----------------------------------------------------------------------------------------------------- lint
def test_lint_model_schema_errors_are_precise(pack):
    def breakit(d):
        d["languages"] = ["cobol"]
        d["sources"] = [{"kind": "magic"}, {"kind": "call"}, "oops"]
        s = d["sinks"][0]
        s.update(severity="urgent", cwe="89", args=[0, -1, "me"], receiver="(", shell="yes", names="run")
        d["sinks"].append({"names": ["x.y"]})
        d["sanitizers"] = "clean"
    _edit_model(pack, breakit)
    rep = rt.lint_pack(pack)
    assert not rep.ok and rep.exit_code == 1
    got = {(i.where, i.code) for i in rep.errors if i.file == "models/acme.json"}
    for want in [("languages[0]", "J006"), ("sources[0].kind", "J006"), ("sources[1]", "J005"), ("sources[2]", "J004"),
                 ("sinks[0].severity", "J006"), ("sinks[0].cwe", "J006"), ("sinks[0].args[1]", "J006"),
                 ("sinks[0].args[2]", "J006"), ("sinks[0].receiver", "J006"), ("sinks[0].shell", "J004"),
                 ("sinks[0].names", "J004"), ("sinks[1]", "J005"), ("sinks[1]", "J007"), ("sanitizers", "J004")]:
        assert want in got, (want, sorted(got))
    text = rep.to_text()
    assert "models/acme.json: sinks[0].severity: must be one of critical, high, medium, low, info [J006]" in text
    assert "models/acme.json: sinks[1]: 'rule' is required [J005]" in text


def test_lint_invalid_json_gives_line_and_column(pack):
    _model(pack).write_text('{\n  "sinks": [,]\n}\n', encoding="utf-8")
    rep = rt.lint_pack(pack)
    msg = next(i for i in rep.errors if i.code == "J001")
    assert "line 2, column 13" in msg.message and msg.file == "models/acme.json"


def test_lint_metadata_must_be_complete_and_bilingual(pack):
    def strip(d):
        del d["sinks"][0]["advice_en"]
        del d["sinks"][0]["title_ar"]
    _edit_model(pack, strip)
    q = pack / "queries" / "debug-enabled.vql"
    q.write_text("\n".join(ln for ln in q.read_text(encoding="utf-8").splitlines()
                           if "@cwe" not in ln and "@name_ar" not in ln) + "\n", encoding="utf-8")
    rep = rt.lint_pack(pack)
    assert {"J007", "Q002", "Q004"} <= _codes(rep)
    assert any("@cwe" in i.message for i in rep.errors if i.code == "Q002")
    relaxed = rt.lint_pack(pack, allow_monolingual=True)
    assert _codes(relaxed) == {"Q002"} and {"J007", "Q004"} <= _codes(relaxed, "warning")


def test_lint_query_must_parse_and_ids_must_be_unique(pack):
    q = pack / "queries" / "debug-enabled.vql"
    good = q.read_text(encoding="utf-8")
    (pack / "queries" / "copy.vql").write_text(good, encoding="utf-8")
    assert "I001" in _codes(rt.lint_pack(pack))                         # two queries, one id
    (pack / "queries" / "copy.vql").write_text(good.replace("@id acme/debug-enabled", "@id ACME001"), encoding="utf-8")
    assert "I002" in _codes(rt.lint_pack(pack))                         # query id == model rule id
    (pack / "queries" / "copy.vql").write_text(good.replace("@id acme/debug-enabled", "@id DF004"), encoding="utf-8")
    assert "I003" in _codes(rt.lint_pack(pack))                         # id of a built-in rule
    (pack / "queries" / "copy.vql").unlink()
    q.write_text(good.replace("from call c", "from nowhere c"), encoding="utf-8")
    bad = rt.lint_pack(pack)
    assert _codes(bad) & {"Q001", "Q005"}, bad.to_text()
    q.write_text(good.replace('where c.func = ', "where where "), encoding="utf-8")
    assert "Q001" in _codes(rt.lint_pack(pack))


def test_lint_manifest_and_fixture_checks(pack, tmp_path):
    m = pack / "kashifpack.json"
    data = json.loads(m.read_text(encoding="utf-8"))
    data.update(name="Bad Name", version="one", extra=1)
    del data["description_ar"]
    m.write_text(json.dumps(data), encoding="utf-8")
    (pack / "fixtures" / "safe.py").unlink()
    (pack / "fixtures" / "vulnerable.py").write_text("f()  # kashif: expect TYPO123\n", encoding="utf-8")
    rep = rt.lint_pack(pack)
    assert {"M003", "M004"} <= _codes(rep) and {"M005", "F002", "F004"} <= _codes(rep, "warning")
    assert {i.where for i in rep.errors if i.code == "M003"} == {"name", "version"}
    m.unlink()
    assert "M001" in _codes(rt.lint_pack(pack))
    empty = tmp_path / "empty"
    empty.mkdir()
    assert "P001" in _codes(rt.lint_pack(empty))
    assert rt.lint_pack(tmp_path / "missing").exit_code == 1
    assert json.dumps(rep.to_dict())


def test_lint_arabic_messages(pack):
    _edit_model(pack, lambda d: d["sinks"][0].update(severity="urgent"))
    assert "يجب أن يكون أحد القيم" in rt.lint_pack(pack, lang="ar").to_text()


# ------------------------------------------------------------------------------------------- pack and install
def test_pack_is_reproducible_and_install_roundtrip(pack, tmp_path):
    a = rt.build_pack(pack, tmp_path / "out")
    b = rt.build_pack(pack, tmp_path / "again.kashifpack")
    assert a.path.name == "acme-0.1.0.kashifpack" and a.sha256 == b.sha256 and len(a.sha256) == 64
    assert a.manifest["format"] == rt.PACK_FORMAT and set(a.manifest["rules"]) == {"ACME001", "acme/debug-enabled"}
    assert {f["path"] for f in a.manifest["files"]} >= {"kashifpack.json", "models/acme.json", "queries/debug-enabled.vql"}
    assert rt.verify_pack(a.path, a.sha256)["archive_sha256"] == a.sha256
    with pytest.raises(rt.PackError, match="SHA-256"):
        rt.verify_pack(a.path, "0" * 64)

    packs = tmp_path / "packs"
    res = rt.install_pack(a.path, packs, sha256=a.sha256)
    assert res.path == packs / "acme" and res.models_dir.is_dir() and res.queries_dir.is_dir()
    assert [p["name"] for p in rt.installed_packs(packs)] == ["acme"]
    with pytest.raises(rt.PackError):
        rt.install_pack(a.path, packs)                         # already installed
    rt.install_pack(a.path, packs, force=True)
    assert not [p for p in packs.iterdir() if p.name.startswith(".")]      # no temporary directory left behind

    models, queries = rt.scan_args(packs)
    findings, _n = scan_path(pack / "fixtures", jadx=False, models_dirs=models, query_paths=queries)
    assert {"ACME001", "acme/debug-enabled"} <= {f.rule_id for f in findings}
    assert rt.run_tests(res.path).exit_code == 0               # the installed copy still passes its own fixtures
    assert rt.scan_args(packs, names=["other"]) == ([], [])
    rt.remove_pack("acme", packs)
    assert rt.installed_packs(packs) == []
    with pytest.raises(rt.PackError):
        rt.remove_pack("acme", packs)


def test_pack_refuses_a_pack_with_lint_errors(pack, tmp_path):
    _edit_model(pack, lambda d: d["sinks"][0].update(severity="urgent"))
    with pytest.raises(rt.PackError, match="J006"):
        rt.build_pack(pack, tmp_path)
    assert rt.build_pack(pack, tmp_path, lint=False).path.is_file()
    with pytest.raises(rt.PackError):                           # ... but install lints again and refuses it
        rt.install_pack(tmp_path / "acme-0.1.0.kashifpack", tmp_path / "packs")
    assert not (tmp_path / "packs" / "acme").exists()


def _rezip(src: pathlib.Path, dst: pathlib.Path, extra=(), drop=(), patch=None):
    """Copy an archive entry by entry, optionally adding raw entries (name, bytes[, unix mode]) or changing content."""
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
        for info in zin.infolist():
            if info.filename in drop:
                continue
            data = zin.read(info)
            zout.writestr(info.filename, patch(info.filename, data) if patch else data)
        for item in extra:
            info = zipfile.ZipInfo(item[0])
            if len(item) > 2:
                info.external_attr = item[2] << 16
            zout.writestr(info, item[1])
    return dst


@pytest.mark.parametrize("name", [
    "../evil.json", "models/../../evil.json", "/abs/evil.json", "C:/evil.json", "models\\..\\evil.json",
    "models/sub/deep.json", "queries/run.sh", "bin/tool.py", "evil.py", ".hidden", "models/.x.json", "fixtures/../../x.py",
])
def test_install_refuses_zip_slip_and_foreign_paths(pack, tmp_path, name):
    good = rt.build_pack(pack, tmp_path / "good.kashifpack").path
    bad = _rezip(good, tmp_path / "bad.kashifpack", extra=[(name, b"{}")])
    packs = tmp_path / "packs"
    for call in (lambda: rt.verify_pack(bad), lambda: rt.install_pack(bad, packs)):
        with pytest.raises(rt.PackError, match="unsafe path"):
            call()
    assert not (tmp_path / "evil.json").exists() and not (packs / "acme").exists()
    assert not packs.exists() or not any(packs.iterdir())       # nothing was written, not even a temp directory
    assert rt.main(["install", str(bad), "--packs-dir", str(packs)]) == 2


def test_install_refuses_symlinks_tampering_and_missing_manifest(pack, tmp_path):
    good = rt.build_pack(pack, tmp_path / "good.kashifpack").path
    packs = tmp_path / "packs"
    link = _rezip(good, tmp_path / "link.kashifpack", extra=[("fixtures/link", b"/etc/passwd", 0o120777)])
    with pytest.raises(rt.PackError, match="symbolic link"):
        rt.install_pack(link, packs)
    extra = _rezip(good, tmp_path / "extra.kashifpack", extra=[("models/extra.json", b"{}")])
    with pytest.raises(rt.PackError, match="not listed"):
        rt.install_pack(extra, packs)
    tampered = _rezip(good, tmp_path / "tampered.kashifpack",
                      patch=lambda n, d: d.replace(b"high", b"info") if n == "models/acme.json" else d)
    with pytest.raises(rt.PackError, match="SHA-256"):
        rt.install_pack(tampered, packs)
    missing = _rezip(good, tmp_path / "missing.kashifpack", drop=("queries/debug-enabled.vql",))
    with pytest.raises(rt.PackError, match="missing from the archive"):
        rt.install_pack(missing, packs)
    bare = _rezip(good, tmp_path / "bare.kashifpack", drop=(rt.ARCHIVE_MANIFEST,))
    with pytest.raises(rt.PackError, match="MANIFEST.json"):
        rt.install_pack(bare, packs)
    (tmp_path / "junk.kashifpack").write_bytes(b"this is not a zip")
    with pytest.raises(rt.PackError, match="not a .kashifpack"):
        rt.install_pack(tmp_path / "junk.kashifpack", packs)
    with pytest.raises(rt.PackError):
        rt.install_pack(tmp_path / "absent.kashifpack", packs)
    assert not (packs / "acme").exists()


def test_install_enforces_size_caps(pack, tmp_path, monkeypatch):
    good = rt.build_pack(pack, tmp_path / "good.kashifpack").path
    packs = tmp_path / "packs"
    monkeypatch.setattr(rt, "MAX_FILE_BYTES", 64)
    with pytest.raises(rt.PackError, match="per-file limit"):
        rt.install_pack(good, packs)
    monkeypatch.setattr(rt, "MAX_FILE_BYTES", 5 * 1024 * 1024)
    monkeypatch.setattr(rt, "MAX_TOTAL_BYTES", 512)
    with pytest.raises(rt.PackError, match="expands to more"):
        rt.install_pack(good, packs)
    monkeypatch.setattr(rt, "MAX_TOTAL_BYTES", 50 * 1024 * 1024)
    monkeypatch.setattr(rt, "MAX_ENTRIES", 3)
    with pytest.raises(rt.PackError, match="entries"):
        rt.install_pack(good, packs)
    monkeypatch.setattr(rt, "MAX_ENTRIES", 2000)
    monkeypatch.setattr(rt, "MAX_ARCHIVE_BYTES", 100)
    with pytest.raises(rt.PackError, match="larger than"):
        rt.install_pack(good, packs)
    assert not (packs / "acme").exists()


def test_install_checks_the_decompressed_size_not_the_header(tmp_path, monkeypatch):
    monkeypatch.setattr(rt, "MAX_FILE_BYTES", 1000)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("fixtures/bomb.py", b"#" * 100_000)           # compresses to a few hundred bytes
    blob = bytearray(buf.getvalue())
    size = (100_000).to_bytes(4, "little")
    for i in range(len(blob) - 4):                                # make every header claim a tiny uncompressed size
        if blob[i:i + 4] == size:
            blob[i:i + 4] = (10).to_bytes(4, "little")
    p = tmp_path / "bomb.kashifpack"
    p.write_bytes(bytes(blob))
    with pytest.raises(rt.PackError):
        rt.install_pack(p, tmp_path / "packs")
    assert not (tmp_path / "packs" / "bomb.py").exists()


def test_install_refuses_pack_for_a_newer_kashif(pack, tmp_path):
    m = pack / "kashifpack.json"
    data = json.loads(m.read_text(encoding="utf-8"))
    data["kashif"] = "999.0.0"
    m.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    arc = rt.build_pack(pack, tmp_path).path
    with pytest.raises(rt.PackError, match="999.0.0"):
        rt.install_pack(arc, tmp_path / "packs")


# ------------------------------------------------------------------------------------------------ docs and CLI
def test_reference_documents_every_field_in_both_languages():
    en, ar = rt.rules_reference("en"), rt.rules_reference("ar")
    for key in rt.MODEL_KEYS + ("receiver", "kwargs", "shell", "@advice_en", "expect-none", "expect-todo", "strictcount",
                                "interprocedural", rt.MANIFEST_NAME, rt.PACK_EXT):
        assert f"{key}" in en and f"{key}" in ar, key
    assert en.startswith("# Writing rules for Kashif") and "كتابة القواعد" in ar
    assert set(rt.STR["en"]) == set(rt.STR["ar"])


def test_cli_end_to_end(tmp_path, capsys):
    p = tmp_path / "team-rules"
    assert rt.main(["new", str(p), "--language", "javascript"]) == 0
    assert rt.main(["lint", str(p)]) == 0
    assert rt.main(["test", str(p), "--json"]) == 0
    capsys.readouterr()
    assert rt.main(["--lang", "ar", "test", str(p)]) == 0
    assert "نجحت كل التوقعات" in capsys.readouterr().out
    assert rt.main(["pack", str(p), "-o", str(tmp_path), "--sha256-file"]) == 0
    arc = tmp_path / "team-rules-0.1.0.kashifpack"
    sha = (tmp_path / (arc.name + ".sha256")).read_text(encoding="utf-8").split()[0]
    assert rt.main(["verify", str(arc), "--sha256", sha]) == 0
    assert rt.main(["install", str(arc), "--packs-dir", str(tmp_path / "packs"), "--sha256", sha]) == 0
    capsys.readouterr()
    assert rt.main(["list", "--packs-dir", str(tmp_path / "packs"), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["name"] == "team-rules"
    assert rt.main(["remove", "team-rules", "--packs-dir", str(tmp_path / "packs")]) == 0
    assert rt.main(["docs"]) == 0 and "## VQL queries" in capsys.readouterr().out
    assert rt.main([]) == 2 and rt.main(["test"]) == 2 and rt.main(["lint", str(tmp_path / "nope")]) == 1
    assert rt.main(["install", str(tmp_path / "nope.kashifpack")]) == 2


# ------------------------------------------------------------------------- hardening (adversarial review)
def _repack(src: pathlib.Path, dst: pathlib.Path, extra=None, manifest=None):
    """Rebuild an archive with extra members and a MANIFEST.json that is consistent with them (a hostile but
    well-formed pack: every hash matches)."""
    import hashlib
    with zipfile.ZipFile(src) as zf:
        cont = {i.filename: zf.read(i) for i in zf.infolist()}
    man = json.loads(cont.pop("MANIFEST.json"))
    for name, data in (extra or {}).items():
        cont[name] = data
        man["files"].append({"path": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    man["digest"] = rt._files_digest(man["files"])
    if manifest:
        manifest(man)
    with zipfile.ZipFile(dst, "w") as zf:
        zf.writestr("MANIFEST.json", json.dumps(man))
        for name, data in cont.items():
            zf.writestr(name, data)
    return dst


def test_hostile_json_never_crashes(pack, tmp_path):
    original = _model(pack).read_text(encoding="utf-8")
    _model(pack).write_text("[" * 100_000, encoding="utf-8")            # RecursionError inside json.loads
    assert "J001" in _codes(rt.lint_pack(pack))
    assert rt.run_tests(pack).exit_code == 2
    _edit = json.loads(original)
    _edit["sources"][0]["kind"] = []                                     # unhashable where a string is expected
    _edit["sinks"][0]["severity"] = {}
    _model(pack).write_text(json.dumps(_edit), encoding="utf-8")
    rep = rt.lint_pack(pack)
    assert {"sources[0].kind", "sinks[0].severity"} <= {i.where for i in rep.errors}
    _model(pack).write_text(original, encoding="utf-8")
    (pack / "kashifpack.json").write_text("[" * 100_000, encoding="utf-8")
    assert "M002" in _codes(rt.lint_pack(pack))
    with pytest.raises(rt.PackError):
        rt.build_pack(pack, tmp_path)


def test_model_with_a_byte_order_mark_is_an_error_like_in_the_engine(pack):
    _model(pack).write_text("﻿" + _model(pack).read_text(encoding="utf-8"), encoding="utf-8")
    assert "J001" in _codes(rt.lint_pack(pack))          # the engine would skip the file silently
    assert rt.run_tests(pack).exit_code == 2


def test_annotation_parsing_is_linear():
    import time
    text = "# kashif: expect X1\n" * 60_000 + "run()\n"
    t0 = time.monotonic()
    exps, problems = rt.parse_annotations(text)
    assert time.monotonic() - t0 < 5
    assert len(exps) == 60_000 and {e.line for e in exps} == {60_001} and not problems


def test_oversized_query_is_refused_before_parsing(pack):
    q = pack / "queries" / "debug-enabled.vql"
    q.write_text(q.read_text(encoding="utf-8") + "\n" * (rt.MAX_QUERY_BYTES + 1), encoding="utf-8")
    assert "Q001" in _codes(rt.lint_pack(pack))
    assert rt.run_tests(pack).exit_code == 2


def test_runner_matches_rule_ids_case_insensitively(tmp_path):
    fx = tmp_path / "fx"
    fx.mkdir()
    (fx / "a.py").write_text("import hashlib\n"
                             "hashlib.md5(b'x')  # kashif: expect cwe-328\n"
                             "hashlib.md5(b'y')\n", encoding="utf-8")
    base = rt.run_tests(None, fx, scope="all")
    rule = next(o.rule for f in base.files for o in f.outcomes if o.status == "unexpected" and o.line == 3)
    (fx / "a.py").write_text("import hashlib\n"
                             f"hashlib.md5(b'x')  # kashif: expect {rule.lower()}\n"
                             f"hashlib.md5(b'y')  # kashif: expect-none {rule.lower()}\n"
                             "hashlib.md5(b'z')\n", encoding="utf-8")
    rep = rt.run_tests(None, fx)
    bad = {(o.line, o.status) for f in rep.files for o in f.outcomes if o.failed}
    assert bad == {(3, "unexpected"), (4, "unexpected")}        # line 4: the rule is in scope although spelled lower-case


@pytest.mark.parametrize("name", ["acme.", "con", "nul.rules", "acme\n", "-acme", "a" * 65])
def test_pack_names_that_are_unsafe_directory_names_are_refused(tmp_path, name):
    assert not rt._valid_name(name)
    with pytest.raises(rt.PackError):
        rt.new_pack(tmp_path / "p", name=name)


@pytest.mark.parametrize("member", ["fixtures/a<b>.py", "fixtures/what?.py", "fixtures/star*.py", "fixtures/pipe|x.py",
                                    "fixtures/aux.py", "fixtures/ok‮.py", "fixtures/CON .txt"])
def test_install_refuses_names_windows_cannot_store(pack, tmp_path, member):
    evil = _repack(rt.build_pack(pack, tmp_path).path, tmp_path / "evil.kashifpack", {member: b"x = 1\n"})
    with pytest.raises(rt.PackError):
        rt.install_pack(evil, tmp_path / "packs")
    assert not (tmp_path / "packs" / "acme").exists()


def test_install_refuses_file_directory_collisions(pack, tmp_path):
    good = rt.build_pack(pack, tmp_path).path
    for extra in ({"fixtures/a": b"1", "fixtures/a/b.py": b"2"}, {"fixtures/a/b.py": b"2", "fixtures/A": b"1"},
                  {"fixtures/x.py": b"1", "fixtures/X.PY": b"2"}):
        evil = _repack(good, tmp_path / "evil.kashifpack", extra)
        with pytest.raises(rt.PackError):
            rt.install_pack(evil, tmp_path / "packs")
    assert not list((tmp_path / "packs").glob("*")) or not any(p.name.startswith(".installing") for p in (tmp_path / "packs").iterdir())


def test_install_tolerates_wrongly_typed_manifest_fields(pack, tmp_path):
    good = rt.build_pack(pack, tmp_path).path
    evil = _repack(good, tmp_path / "evil.kashifpack", manifest=lambda m: m.update(kashif=5, description=["x"], rules=7))
    assert rt.install_pack(evil, tmp_path / "packs").name == "acme"       # no TypeError; odd values are just data
    evil = _repack(good, tmp_path / "evil2.kashifpack", manifest=lambda m: m.update(name="acme\n"))
    with pytest.raises(rt.PackError):
        rt.verify_pack(evil)
    deep = tmp_path / "deep.kashifpack"
    with zipfile.ZipFile(deep, "w") as zf:
        zf.writestr("MANIFEST.json", "[" * 100_000)
    with pytest.raises(rt.PackError):
        rt.verify_pack(deep)


def test_force_never_replaces_a_directory_that_is_not_an_installed_pack(pack, tmp_path):
    good = rt.build_pack(pack, tmp_path).path
    home = tmp_path / "home"
    (home / "acme" / "precious").mkdir(parents=True)
    with pytest.raises(rt.PackError):
        rt.install_pack(good, home, force=True)
    assert (home / "acme" / "precious").is_dir()
    with pytest.raises(rt.PackError):
        rt.remove_pack("acme", home)
    assert (home / "acme" / "precious").is_dir()
    packs = tmp_path / "packs"
    rt.install_pack(good, packs)
    assert rt.install_pack(good, packs, force=True).name == "acme"       # a real installed pack is replaced


def test_sha256_argument_must_be_a_sha256(pack, tmp_path):
    res = rt.build_pack(pack, tmp_path)
    with pytest.raises(rt.PackError):
        rt.verify_pack(res.path, "abc123")
    assert rt.verify_pack(res.path, "  " + res.sha256.upper() + "\n")["name"] == "acme"


def test_terminal_escapes_from_a_pack_are_not_printed(pack, tmp_path, capsys):
    good = rt.build_pack(pack, tmp_path).path
    esc = "\x1b[31mred\x1b]0;title\x07 ‮gnp.exe"
    evil = _repack(good, tmp_path / "evil.kashifpack", manifest=lambda m: m.update(description=esc, description_ar=esc))
    rt.install_pack(evil, tmp_path / "packs")
    capsys.readouterr()
    assert rt.main(["list", "--packs-dir", str(tmp_path / "packs")]) == 0
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\x07" not in out and "‮" not in out and "acme 0.1.0" in out


def test_pack_skips_hidden_trees_and_is_platform_independent(pack, tmp_path):
    (pack / ".git" / "objects").mkdir(parents=True)
    (pack / ".git" / "objects" / "blob").write_bytes(b"x")
    (pack / "fixtures" / "__pycache__").mkdir()
    (pack / "fixtures" / "__pycache__" / "a.pyc").write_bytes(b"x")
    res = rt.build_pack(pack, tmp_path)
    assert ".git/" in res.skipped and "fixtures/__pycache__/" in res.skipped
    with zipfile.ZipFile(res.path) as zf:
        assert not [i.filename for i in zf.infolist() if ".git" in i.filename or "pycache" in i.filename]
        assert {i.create_system for i in zf.infolist()} == {3}            # not the packing machine's OS
        assert {i.date_time for i in zf.infolist()} == {(1980, 1, 1, 0, 0, 0)}


def test_reference_states_the_engine_defaults_it_can_back():
    from vulnscan import taint
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        (pathlib.Path(d) / "m.json").write_text(json.dumps({
            "sinks": [{"rule": "T1", "names": ["f"]}], "attr_sinks": [{"rule": "T2", "attrs": ["a"]}],
            "store_sinks": [{"rule": "T3", "roots": ["s"]}]}), encoding="utf-8")
        m = taint.load_models([d])
    sev = {s[0]: s[1] for s in m["sinks"]} | {s[0][0]: s[0][1] for s in m["attr_sinks"]} | {s[0][0]: s[0][1] for s in m["store_sinks"]}
    assert (sev["T1"], sev["T2"], sev["T3"]) == ("high", "medium", "medium")
    assert "`high` for `sinks`, `medium` for `attr_sinks` and `store_sinks`" in rt.rules_reference("en")
