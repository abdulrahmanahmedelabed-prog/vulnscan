"""PHP and Ruby library models: framework sources, sinks and sanitizers (breadth regression set).

Every program under tests/data/models_phprb/ states on its first line what the data-flow engine must report:

* ``<?php // expect: DF004`` / ``# expect: DF004``   -- a vulnerable program: the rule must be reported.
* ``<?php // expect-none: DF004``                    -- a safe twin (sanitized, parameterized or constant):
                                                        none of the listed rules may be reported.

Vulnerable programs are named ``<case>__vuln.<ext>`` and have a ``<case>__safe.<ext>`` twin.
"""

from __future__ import annotations

import json
import pathlib
import re

import pytest

from vulnscan.i18n import translated
from vulnscan.taint import MODELS_DIR, analyze, load_models_for

DATA = pathlib.Path(__file__).resolve().parent / "data" / "models_phprb"
FILES = sorted([*DATA.glob("*.php"), *DATA.glob("*.rb")])
HEADER = re.compile(r"(expect(?:-none)?):\s*(.+?)\s*$")


def _expectation(path: pathlib.Path) -> tuple[str, set[str]]:
    m = HEADER.search(path.read_text(encoding="utf-8").splitlines()[0])
    assert m, f"{path.name}: bad header"
    return m.group(1), set(m.group(2).split())


def _rules(path: pathlib.Path) -> set[str]:
    return {f.rule_id for f in analyze(path.name, path.read_text(encoding="utf-8"))}


def test_corpus_is_paired():
    def cases(suffix):
        return {p.name[: -len(suffix)] for p in FILES if p.name.endswith(suffix)}
    for ext in ("php", "rb"):
        vuln, safe = cases(f"__vuln.{ext}"), cases(f"__safe.{ext}")
        assert len(vuln) >= 20, ext
        assert vuln == safe, f"unpaired {ext} cases: {sorted(vuln ^ safe)}"


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_model_case(path):
    kind, rules = _expectation(path)
    found = _rules(path)
    if kind == "expect":
        assert rules <= found, f"{path.name}: expected {sorted(rules)}, got {sorted(found)}"
    else:
        assert not rules & found, f"{path.name}: must not report {sorted(rules & found)} (got {sorted(found)})"


def test_finding_points_at_the_sink_line():
    path = DATA / "laravel_db_select__vuln.php"
    lines = path.read_text(encoding="utf-8").splitlines()
    hits = [f for f in analyze(path.name, "\n".join(lines)) if f.rule_id == "DF004"]
    assert hits and "DB::select" in lines[hits[0].line - 1]


@pytest.mark.parametrize("language", ["php", "ruby"])
def test_models_are_well_formed_and_translated(language):
    data = json.loads((MODELS_DIR / f"{language}.json").read_text(encoding="utf-8"))
    for s in data["sinks"]:
        assert s["names"] and isinstance(s.get("args"), list), s
        assert s.get("cwe", "").startswith("CWE-"), s
        assert translated(s.get("advice", "")), s
        assert s.get("title") and (translated(s.get("title_ar", "")) or s["title"].isascii()), s
        if s.get("receiver"):
            re.compile(s["receiver"])
    m = load_models_for(language)
    assert len(m["sinks"]) == len(data["sinks"])
    # PHP variables are lowered without `$` and `->`/`::` become `.`: model names must use the dotted form
    new_sources = [n for s in data["sources"] if s.get("kind") == "call" for n in s["names"]]
    assert "request.getParsedBody" in new_sources or language == "ruby"
