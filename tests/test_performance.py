"""Performance features must never change results: --jobs (per-file work in a process pool) and --cache (incremental
scan cache) give exactly the findings of a plain sequential scan. Plus a generous time-budget smoke test."""

from __future__ import annotations

import dataclasses
import json
import pathlib
import shutil
import time

import pytest

from vulnscan import scanner
from vulnscan.cli import main
from vulnscan.model import Finding
from vulnscan.scanner import ScanCache, scan_path

ROOT = pathlib.Path(__file__).resolve().parent.parent
REGRESS = ROOT / "tests" / "data" / "regress"

PY_VIEW = '''import os
import subprocess
from flask import Flask, request

app = Flask(__name__)


def run(cmd):
    return subprocess.call(cmd, shell=True)


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return str(run("ping -c 1 " + host))


@app.route("/safe")
def safe():
    return str(run("ping -c 1 localhost"))
'''

JS_ROUTE = '''const express = require("express");
const { exec } = require("child_process");
const app = express();
app.get("/x", (req, res) => {
  exec("ls " + req.query.dir, (e, out) => res.send(out));
});
app.get("/y", (req, res) => {
  exec("ls /tmp", (e, out) => res.send(out));
});
module.exports = app;
'''

JAVA_SERVLET = '''package demo;
import javax.servlet.http.*;
import java.sql.*;
public class Lookup extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String id = req.getParameter("id");
        Connection c = DriverManager.getConnection("jdbc:h2:mem:x");
        Statement st = c.createStatement();
        st.executeQuery("SELECT * FROM t WHERE id = '" + id + "'");
        PreparedStatement ps = c.prepareStatement("SELECT * FROM t WHERE id = ?");
        ps.setString(1, id);
        ps.executeQuery();
    }
}
'''


def _project(tmp_path: pathlib.Path, n_extra: int = 30) -> pathlib.Path:
    """A small multi-language project: cross-file Python flow, JS and Java taint, a config file, plus filler files."""
    root = tmp_path / "proj"
    (root / "app").mkdir(parents=True)
    (root / "web").mkdir()
    (root / "src" / "demo").mkdir(parents=True)
    (root / "app" / "__init__.py").write_text("", encoding="utf-8")
    (root / "app" / "views.py").write_text(PY_VIEW, encoding="utf-8")
    (root / "app" / "helpers.py").write_text("import pickle\n\n\ndef load(blob):\n    return pickle.loads(blob)\n",
                                             encoding="utf-8")
    (root / "web" / "server.js").write_text(JS_ROUTE, encoding="utf-8")
    (root / "src" / "demo" / "Lookup.java").write_text(JAVA_SERVLET, encoding="utf-8")
    (root / "config.properties").write_text("db.table=users\n", encoding="utf-8")
    (root / "crlf.py").write_bytes(b"import os\r\n\r\ndef f(x):\r\n    os.system(x)\r\n")
    for i in range(n_extra):
        (root / "app" / f"mod{i}.py").write_text(
            f"from app.helpers import load\n\n\ndef f{i}(v):\n    return load(v) if v else {i}\n", encoding="utf-8")
    return root


def _rows(findings) -> list[str]:
    return sorted(json.dumps(dataclasses.asdict(f), sort_keys=True, default=repr, ensure_ascii=False) for f in findings)


def _scan(target, **kw):
    notes: list[str] = []
    findings, count = scan_path(target, notes=notes, **kw)
    return _rows(findings), notes, count


@pytest.fixture
def pool_always(monkeypatch):
    monkeypatch.setattr(scanner, "PARALLEL_MIN_FILES", 0)


# ------------------------------------------------------------------ --jobs

def test_jobs_same_findings_as_sequential(tmp_path, pool_always):
    root = _project(tmp_path)
    one = _scan(root, jobs=1)
    assert any('"DF' in r for r in one[0]), "the fixture must produce data-flow findings"
    for jobs in (2, 3):
        assert _scan(root, jobs=jobs) == one


def test_jobs_regress_corpus_identical(pool_always):
    assert _scan(REGRESS, jobs=2) == _scan(REGRESS, jobs=1)


def test_jobs_resolution():
    assert scanner.resolve_jobs(1) == 1
    assert scanner.resolve_jobs(3) == 3
    assert scanner.resolve_jobs(None) >= 1
    assert scanner.resolve_jobs(0) >= 1
    assert scanner.resolve_jobs(-2) == 1


# ------------------------------------------------------------------ --cache

def test_cache_cold_equals_warm_and_uncached(tmp_path, pool_always):
    root = _project(tmp_path)
    cache = tmp_path / "cache"
    plain = _scan(root)
    cold = _scan(root, cache_dir=cache, jobs=2)
    warm = _scan(root, cache_dir=cache, jobs=2)
    assert cold == plain
    assert warm == plain
    warm_seq = _scan(root, cache_dir=cache, jobs=1)
    assert warm_seq == plain
    # every entry is plain JSON (never pickle)
    entries = [p for p in cache.rglob("*.json")]
    assert entries
    for p in entries:
        doc = json.loads(p.read_text(encoding="utf-8"))
        assert doc["format"] == scanner.CACHE_FORMAT


def test_cache_warm_rescan_skips_analysis(tmp_path, monkeypatch):
    root = _project(tmp_path)
    cache = tmp_path / "cache"
    first = _scan(root, cache_dir=cache)

    def boom(*a, **k):
        raise AssertionError("an unchanged project must be answered from the cache")
    monkeypatch.setattr(scanner.taint, "analyze_project_full", boom)
    monkeypatch.setattr(scanner, "_file_stage", boom)
    assert _scan(root, cache_dir=cache) == first


def test_cache_invalidated_by_edit(tmp_path):
    root = _project(tmp_path)
    cache = tmp_path / "cache"
    before = _scan(root, cache_dir=cache)
    views = root / "app" / "views.py"
    views.write_text(PY_VIEW + '\n\n@app.route("/ev")\ndef ev():\n    return str(eval(request.args["e"]))\n',
                     encoding="utf-8")
    after = _scan(root, cache_dir=cache)
    assert after == _scan(root)                       # same as an uncached scan of the edited project
    assert after != before
    assert any("views.py" in r and "eval" in r for r in after[0])
    views.write_text(PY_VIEW, encoding="utf-8")       # and back again
    assert _scan(root, cache_dir=cache) == before


def test_cache_reuses_unchanged_files(tmp_path, monkeypatch):
    root = _project(tmp_path)
    cache = tmp_path / "cache"
    _scan(root, cache_dir=cache)
    (root / "app" / "mod0.py").write_text("def f0(v):\n    return v\n", encoding="utf-8")
    calls = []
    real = scanner._file_stage

    def counting(p, rel, *a, **k):
        calls.append(rel)
        return real(p, rel, *a, **k)
    monkeypatch.setattr(scanner, "_file_stage", counting)
    _scan(root, cache_dir=cache)
    assert calls == ["app/mod0.py"]                   # only the edited file is scanned again


def test_cache_options_are_part_of_the_key(tmp_path):
    root = _project(tmp_path)
    cache = tmp_path / "cache"
    _scan(root, cache_dir=cache)
    assert _scan(root, cache_dir=cache, ignore_rules={"DF002"}) == _scan(root, ignore_rules={"DF002"})
    assert _scan(root, cache_dir=cache, audit=True) == _scan(root, audit=True)
    assert _scan(root, cache_dir=cache, include_tests=True) == _scan(root, include_tests=True)


@pytest.mark.parametrize("garbage", [b"", b"\x80\x81not json", b"[1, 2, 3]", b'{"format": 1, "key": "x", "data": 1}',
                                     b'{"format": 1}', b"\x00" * 64])
def test_corrupt_cache_entries_are_ignored(tmp_path, garbage):
    root = _project(tmp_path, n_extra=3)
    cache = tmp_path / "cache"
    plain = _scan(root)
    _scan(root, cache_dir=cache)
    entries = list(cache.rglob("*.json"))
    assert entries
    for p in entries:
        p.write_bytes(garbage)
    assert _scan(root, cache_dir=cache) == plain      # corrupt: recomputed
    assert _scan(root, cache_dir=cache) == plain      # and rewritten


def test_corrupt_file_entry_with_valid_layout_is_ignored(tmp_path):
    root = _project(tmp_path, n_extra=2)
    cache = tmp_path / "cache"
    plain = _scan(root)
    _scan(root, cache_dir=cache)
    shutil.rmtree(cache / f"v{scanner.CACHE_FORMAT}" / "project")
    for p in (cache / f"v{scanner.CACHE_FORMAT}" / "file").rglob("*.json"):
        doc = json.loads(p.read_text(encoding="utf-8"))
        doc["data"]["findings"] = [["bad"]]          # the right key and format, but a malformed finding
        p.write_text(json.dumps(doc), encoding="utf-8")
    assert _scan(root, cache_dir=cache) == plain


def test_unwritable_cache_dir_does_not_break_the_scan(tmp_path):
    root = _project(tmp_path, n_extra=2)
    blocker = tmp_path / "file-not-dir"
    blocker.write_text("x", encoding="utf-8")
    assert _scan(root, cache_dir=blocker / "cache") == _scan(root)


def test_codec_round_trip_and_refuses_objects():
    value = {"a": (1, "x", (2.5, None)), "b": {1, 2}, "c": frozenset({"k"}), "d": {1: "int key", ("t", 1): [True]},
             "\u0000t": "tricky key", "e": [{"\u0000s": [1]}]}
    back = scanner._dec(json.loads(json.dumps(scanner._enc(value))))
    assert back == value
    assert type(back["a"]) is tuple and type(back["b"]) is set and type(back["c"]) is frozenset
    with pytest.raises(scanner._NotPlain):
        scanner._enc({"x": object()})
    f = Finding("R1", "high", "t", "ت", "a.py", 3, "s", "adv", "CWE-1", "taint",
                extra={"path": [{"file": "a.py", "line": 1}], "why": ("x", 1)})
    assert scanner._dec_finding(json.loads(json.dumps(scanner._enc_finding(f)))) == f
    for bad in ([], ["R1"] * 11, ["R1", "high", "t", "t", "a.py", "3", "s", "a", "c", "src", {}]):
        with pytest.raises(ValueError):
            scanner._dec_finding(bad)


def test_cache_entry_written_atomically(tmp_path):
    c = ScanCache(tmp_path / "c")
    assert c.put("file", "ab" * 32, {"x": 1})
    assert c.get("file", "ab" * 32) == {"x": 1}
    assert c.get("file", "cd" * 32) is None
    assert not [p for p in (tmp_path / "c").rglob(".tmp-*")]


def test_default_cache_dir_follows_home(monkeypatch, tmp_path):
    monkeypatch.delenv("KASHIF_HOME", raising=False)
    monkeypatch.setenv("VULNSCAN_HOME", str(tmp_path))
    assert scanner.default_cache_dir() == tmp_path / "cache" / "scan"


# ------------------------------------------------------------------ CLI flags

def test_cli_jobs_and_cache_flags(tmp_path, pool_always):
    root = _project(tmp_path, n_extra=5)
    outs = []
    for extra in (["--jobs", "1"], ["--jobs", "2", "--cache", str(tmp_path / "c")],
                  ["--jobs", "2", "--cache", str(tmp_path / "c")], ["--cache", str(tmp_path / "c"), "--no-cache"]):
        out = tmp_path / f"r{len(outs)}.json"
        main([str(root), "--no-deps", "--no-external", "-f", "json", "-o", str(out), "--lang", "en"] + extra)
        doc = json.loads(out.read_text(encoding="utf-8"))
        outs.append(sorted((f["rule_id"], f["file"], f["line"], f["fingerprint"]) for f in doc["findings"]))
    assert outs[0] and all(o == outs[0] for o in outs)
    assert (tmp_path / "c").is_dir()


# ------------------------------------------------------------------ time budget smoke test

def test_time_budget_smoke(tmp_path):
    """A few hundred files of mixed languages must scan well within a generous budget (catches quadratic blowups)."""
    root = _project(tmp_path, n_extra=200)
    for i in range(60):
        (root / "web" / f"r{i}.js").write_text(JS_ROUTE.replace("/x", f"/x{i}"), encoding="utf-8")
    t = time.monotonic()
    findings, count = scan_path(root, jobs=1)
    assert count >= 260 and findings
    assert time.monotonic() - t < 120
