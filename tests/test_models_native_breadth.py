"""Rust / Swift / C / C++ / Kotlin library models: sources, sinks and sanitizers (breadth regression set, round 2).

Every program under tests/data/models_native/ states on its first line what the data-flow engine must report:

* ``// expect: DF004``             -- a vulnerable program: the rule must be reported.
* ``// expect-none: DF004 DF005``  -- a safe twin (sanitized, parameterized or constant) or a look-alike API:
                                      none of the listed rules may be reported.

Vulnerable programs are named ``<case>__vuln.<ext>`` and have a ``<case>__safe.<ext>`` twin.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from vulnscan.cfamily_frontend import parse_cfamily
from vulnscan.i18n import translated
from vulnscan.taint import MODELS_DIR, _name_matches, analyze, load_models, load_models_for

DATA = pathlib.Path(__file__).resolve().parent / "data" / "models_native"
EXTS = (".rs", ".swift", ".c", ".cpp", ".kt")
FILES = sorted(p for p in DATA.iterdir() if p.suffix in EXTS)


def _expectation(path: pathlib.Path) -> tuple[str, set[str]]:
    head = path.read_text(encoding="utf-8").splitlines()[0]
    kind, _, rules = head.lstrip("/ ").partition(":")
    return kind.strip(), set(rules.split())


def _findings(path: pathlib.Path):
    return analyze(path.name, path.read_text(encoding="utf-8"))


def _case(path: pathlib.Path) -> str:
    return path.stem.rsplit("__", 1)[0] + path.suffix


def test_corpus_is_paired():
    vuln = {_case(p) for p in FILES if p.stem.endswith("__vuln")}
    safe = {_case(p) for p in FILES if p.stem.endswith("__safe")}
    per_ext = {e: len([v for v in vuln if v.endswith(e)]) for e in EXTS}
    assert per_ext[".rs"] >= 35 and per_ext[".swift"] >= 28 and per_ext[".kt"] >= 15
    assert per_ext[".c"] + per_ext[".cpp"] >= 40
    assert vuln <= safe, f"vulnerable cases without a safe twin: {sorted(vuln - safe)}"


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_corpus_parses_completely(path):
    """A statement the frontend skips proves nothing: every corpus program must lower without skipped statements."""
    lang = {".rs": "rust", ".swift": "swift", ".kt": "kotlin"}.get(path.suffix, "cpp")
    diag = parse_cfamily(path.read_text(encoding="utf-8"), path.name, lang).vulnscan_diagnostics
    assert not diag["skipped"], diag["lines"]


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
    ("command_sh_c__vuln.rs", "DF002", "Command::new"),
    ("diesel_sql_query__vuln.rs", "DF004", "sql_query("),
    ("cgi_query_string_system__vuln.c", "DF002", "system("),
    ("boost_process_child__vuln.cpp", "DF002", "child"),
    ("ktor_exposed_exec_raw__vuln.kt", "DF004", ".exec("),
    ("android_webview_load_url__vuln.kt", "DF013", "loadUrl("),
])
def test_reports_at_the_sink_line(name, rule, needle):
    """The finding points at the modelled sink call, not only at some other sink in the program."""
    path = DATA / name
    lines = path.read_text(encoding="utf-8").splitlines()
    hits = [f for f in _findings(path) if f.rule_id == rule]
    assert any(needle.lower() in lines[f.line - 1].lower() for f in hits), \
        [(f.line, lines[f.line - 1]) for f in hits]


COMMON = {"get", "post", "put", "delete", "run", "send", "exec", "execute", "eval", "load", "parse", "process", "filter",
          "lookup", "fetch", "sql", "target", "render", "format", "printf", "query", "open", "read", "write", "spawn",
          "output", "status", "request", "new", "from_str", "from_slice", "from_reader", "decode", "deserialize"}


@pytest.mark.parametrize("language", ["rust", "swift", "cpp", "kotlin"])
def test_native_models_are_well_formed_and_translated(language):
    data = json.loads((MODELS_DIR / f"{language}.json").read_text(encoding="utf-8"))
    assert data["sinks"], f"{language}.json declares no sinks of its own"
    for s in data["sinks"]:
        assert s["names"] and s.get("args"), s
        assert s.get("cwe", "").startswith("CWE-"), s
        assert s.get("title") and s.get("title_ar"), s
        assert translated(s.get("advice", "")), s["advice"]
        assert all(isinstance(i, int) or i == "self" for i in s["args"]), s
        assert len(set(s["names"])) == len(s["names"]), (s["rule"], s.get("label"))
    m = load_models_for(language)
    assert len(m["sinks"]) >= len(data["sinks"])
    for key in ("sanitizers", "validators"):
        assert len(set(data.get(key, []))) == len(data.get(key, [])), (language, key)


# Sinks without a receiver pattern are tried in file order and the first match wins, so a name listed in a later
# entry of another rule (or with other arguments) never takes effect. These are the known, deliberate overlaps:
# changing which entry wins would change the rule id, and so the fingerprint, of existing findings.
KNOWN_SHADOWED = {
    "cpp": {"execvp", "execv", "execve", "execl", "execlp", "posix_spawn", "QProcess.start", "QProcess.execute",
            "syslog", "sprintf", "vsprintf", "evbuffer_add_printf", "FCGX_FPrintF"},
    "rust": {"libloading.Library.new", "Library.new", "log.write"},
    "swift": {"UIApplication.shared.open", "NSWorkspace.shared.open", "extensionContext.open", "dlopen",
              "Bundle(path:)", "evaluateJavaScript", "webView.evaluateJavaScript", "callAsyncJavaScript",
              "addUserScript", "unsafeBitCast", "loadHTMLString", "webView.loadHTMLString",
              "WKWebView.loadHTMLString", "NSAttributedString(html:)"},
    "kotlin": {"File", "java.io.File", "Paths.get", "Path.of"},
}


@pytest.mark.parametrize("language", ["rust", "swift", "cpp", "kotlin"])
def test_no_new_dead_sink_names(language):
    m = load_models((), MODELS_DIR / f"{language}.json", language)
    plain = [e for e in m["sinks"] if e[11] is None]
    shadowed = set()
    for i, e in enumerate(plain):
        for name in e[9]:
            canon = name.removeprefix("builtins.")
            first = next((f for f in plain[:i] if any(_name_matches(canon, x) for x in f[9])), e)
            if first is not e and (first[0], first[7]) != (e[0], e[7]):
                shadowed.add(name)
    assert shadowed <= KNOWN_SHADOWED[language], sorted(shadowed - KNOWN_SHADOWED[language])
