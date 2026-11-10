"""Python library models: framework sources, entry points, sinks and sanitizers (breadth regression set).

Every program under tests/data/models_python/ states on its first line what the data-flow engine must report:

* ``# expect: DF004``             -- a vulnerable program: the rule must be reported.
* ``# expect-none: DF004 DF005``  -- a safe twin (sanitized, parameterized or constant) or a look-alike API:
                                     none of the listed rules may be reported.

Vulnerable programs are named ``<case>__vuln.py`` and have a ``<case>__safe.py`` twin.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from vulnscan.i18n import translated
from vulnscan.taint import DEFAULT_MODELS, analyze, load_models

DATA = pathlib.Path(__file__).resolve().parent / "data" / "models_python"
FILES = sorted(DATA.glob("*.py"))


def _expectation(path: pathlib.Path) -> tuple[str, set[str]]:
    head = path.read_text(encoding="utf-8").splitlines()[0]
    kind, _, rules = head.lstrip("# ").partition(":")
    return kind.strip(), set(rules.split())


def _rules(path: pathlib.Path) -> set[str]:
    return {f.rule_id for f in analyze(path.name, path.read_text(encoding="utf-8"))}


def test_corpus_is_paired():
    vuln = {p.name[: -len("__vuln.py")] for p in FILES if p.name.endswith("__vuln.py")}
    safe = {p.name[: -len("__safe.py")] for p in FILES if p.name.endswith("__safe.py")}
    assert len(vuln) >= 80
    assert vuln <= safe, f"vulnerable cases without a safe twin: {sorted(vuln - safe)}"


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.stem)
def test_model_case(path):
    kind, rules = _expectation(path)
    assert kind in {"expect", "expect-none"} and rules, f"{path.name}: bad header"
    found = _rules(path)
    if kind == "expect":
        assert rules <= found, f"{path.name}: expected {sorted(rules)}, got {sorted(found)}"
    else:
        assert not rules & found, f"{path.name}: must not report {sorted(rules & found)} (got {sorted(found)})"


def test_vulnerable_twin_reports_at_the_sink_line():
    """The finding points at the sink call of the vulnerable program, not at an unrelated line."""
    path = DATA / "paramiko_exec__vuln.py"
    hits = [f for f in analyze(path.name, path.read_text(encoding="utf-8")) if f.rule_id == "DF002"]
    assert hits and "exec_command" in path.read_text(encoding="utf-8").splitlines()[hits[0].line - 1]


def test_python_models_are_well_formed_and_translated():
    data = json.loads(pathlib.Path(DEFAULT_MODELS).read_text(encoding="utf-8"))
    for s in data["sinks"]:
        assert s["names"] and s.get("args") is not None, s
        assert s.get("cwe", "").startswith("CWE-"), s
        assert translated(s.get("advice", "")), s["advice"]
    m = load_models()
    assert len(m["sinks"]) == len(data["sinks"])
    # no bare attribute names that would also match `self.<attr>` of any class
    for roots, attrs, _ in m["attr_sources"]:
        assert not attrs & {"params", "forms", "matchdict", "media"}
