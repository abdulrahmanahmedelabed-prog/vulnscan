"""Java / Kotlin library models: framework sources, entry points, sinks and sanitizers (breadth regression set).

Every program under tests/data/models_jvm/ states on its first line what the data-flow engine must report:

* ``// expect: DF004``             -- a vulnerable program: the rule must be reported.
* ``// expect-none: DF004 DF005``  -- a safe twin (sanitized, parameterized or constant) or a look-alike API:
                                      none of the listed rules may be reported.

Vulnerable programs are named ``<case>__vuln.java|kt`` and have a ``<case>__safe.java|kt`` twin.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from vulnscan.i18n import translated
from vulnscan.taint import MODELS_DIR, analyze, load_models_for

DATA = pathlib.Path(__file__).resolve().parent / "data" / "models_jvm"
FILES = sorted([*DATA.glob("*.java"), *DATA.glob("*.kt")])


def _expectation(path: pathlib.Path) -> tuple[str, set[str]]:
    head = path.read_text(encoding="utf-8").splitlines()[0]
    kind, _, rules = head.lstrip("/ ").partition(":")
    return kind.strip(), set(rules.split())


def _findings(path: pathlib.Path):
    return analyze(path.name, path.read_text(encoding="utf-8"))


def _case(path: pathlib.Path, suffix: str) -> str:
    return path.name[: -len(suffix)]


def test_corpus_is_paired():
    vuln = {_case(p, "__vuln" + p.suffix) + p.suffix for p in FILES if p.stem.endswith("__vuln")}
    safe = {_case(p, "__safe" + p.suffix) + p.suffix for p in FILES if p.stem.endswith("__safe")}
    assert len([v for v in vuln if v.endswith(".java")]) >= 45
    assert len([v for v in vuln if v.endswith(".kt")]) >= 12
    assert vuln <= safe, f"vulnerable cases without a safe twin: {sorted(vuln - safe)}"


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_model_case(path):
    kind, rules = _expectation(path)
    assert kind in {"expect", "expect-none"} and rules, f"{path.name}: bad header"
    found = {f.rule_id for f in _findings(path)}
    if kind == "expect":
        assert rules <= found, f"{path.name}: expected {sorted(rules)}, got {sorted(found)}"
    else:
        assert not rules & found, f"{path.name}: must not report {sorted(rules & found)} (got {sorted(found)})"


@pytest.mark.parametrize("name, rule, needle", [
    ("file_parent_child__vuln.java", "DF005", "new File(\"/var/data\", name)"),     # child argument of File(parent, child)
    ("paths_get_more__vuln.java", "DF005", "Paths.get(\"/srv/reports\""),           # Paths.get(first, more...)
    ("servlet_printf_xss__vuln.java", "DF013", "printf("),
    ("multipart_transfer_to__vuln.java", "DF005", "transferTo("),
    ("files_lines_resolve__vuln.java", "DF005", "Files.lines("),
    ("zip_slip__vuln.java", "DF005", "entry.getName()"),
    ("velocity_static_evaluate__vuln.java", "DF007", "Velocity.evaluate("),       # template is argument 3
    ("freemarker_template_source__vuln.java", "DF007", "new Template("),           # source reader is argument 1
    ("ktor_respond_file__vuln.kt", "DF005", "respondFile("),
    ("exposed_exec__vuln.kt", "DF004", ".exec("),
])
def test_reports_at_the_sink_line(name, rule, needle):
    """The finding points at the modelled sink call, not only at some other sink in the program."""
    path = DATA / name
    lines = path.read_text(encoding="utf-8").splitlines()
    hits = [f for f in _findings(path) if f.rule_id == rule]
    assert any(needle in lines[f.line - 1] for f in hits), [(f.line, lines[f.line - 1]) for f in hits]


def test_finding_cwes():
    """Sinks that share a rule id carry their own CWE (NoSQL, header injection, JNDI)."""
    def cwes(name):
        return {f.cwe for f in _findings(DATA / name)}
    assert "CWE-943" in cwes("mongo_document_parse__vuln.java")
    assert "CWE-113" in cwes("servlet_header_injection__vuln.java")
    assert "CWE-74" in cwes("jaxrs_patch_jndi__vuln.java")


@pytest.mark.parametrize("language", ["java", "kotlin"])
def test_jvm_models_are_well_formed_and_translated(language):
    data = json.loads((MODELS_DIR / f"{language}.json").read_text(encoding="utf-8"))
    assert data["sinks"], f"{language}.json declares no sinks of its own"
    for s in data["sinks"]:
        assert s["names"] and s.get("args"), s
        assert s.get("cwe", "").startswith("CWE-"), s
        assert s.get("title") and s.get("title_ar"), s
        assert translated(s.get("advice", "")), s["advice"]
        assert all(isinstance(i, int) or i == "self" for i in s["args"]), s
    m = load_models_for(language)
    assert len(m["sinks"]) >= len(data["sinks"])
    # bare, very common method names must be constrained by a receiver pattern
    common = {"get", "post", "put", "delete", "run", "send", "exec", "eval", "load", "parse", "process", "filter",
              "lookup", "fetch", "sql", "target", "render", "format", "printf"}
    for s in data["sinks"]:
        bare = common & set(s["names"])
        if bare and not s.get("receiver"):
            # tolerated only where the name already existed before the breadth expansion (Runtime.exec model)
            assert language == "java" and bare <= {"exec"}, (s["rule"], sorted(bare))
