"""C# / Go library models: framework sources, entry points, sinks and sanitizers (breadth regression set).

Every program under tests/data/models_csgo/ states on its first line what the data-flow engine must report:

* ``// expect: DF004``             -- a vulnerable program: the rule must be reported.
* ``// expect-none: DF004 DF005``  -- a safe twin (sanitized, parameterized or constant) or a look-alike API:
                                      none of the listed rules may be reported.

Vulnerable programs are named ``<case>__vuln.cs|go`` and have a ``<case>__safe.cs|go`` twin.
"""

from __future__ import annotations

import json
import pathlib
import re

import pytest

from vulnscan import cfamily_frontend
from vulnscan.i18n import translated
from vulnscan.taint import MODELS_DIR, analyze, load_models_for

DATA = pathlib.Path(__file__).resolve().parent / "data" / "models_csgo"
FILES = sorted([*DATA.glob("*.cs"), *DATA.glob("*.go")])


def _expectation(path: pathlib.Path) -> tuple[str, set[str]]:
    head = path.read_text(encoding="utf-8").splitlines()[0]
    kind, _, rules = head.lstrip("/ ").partition(":")
    return kind.strip(), set(rules.split())


def _findings(path: pathlib.Path):
    # The Go frontend keeps receiver methods in a class-level table; methods of Go files parsed earlier in this
    # process must not be attached to this program (each case is analyzed on its own).
    leaked = getattr(cfamily_frontend.Parser, "go_methods", None)
    if isinstance(leaked, dict):
        leaked.clear()
    return analyze(path.name, path.read_text(encoding="utf-8"))


def _case(path: pathlib.Path, suffix: str) -> str:
    return path.name[: -len(suffix)]


def test_corpus_is_paired():
    vuln = {_case(p, "__vuln" + p.suffix) + p.suffix for p in FILES if p.stem.endswith("__vuln")}
    safe = {_case(p, "__safe" + p.suffix) + p.suffix for p in FILES if p.stem.endswith("__safe")}
    assert len([v for v in vuln if v.endswith(".cs")]) >= 30
    assert len([v for v in vuln if v.endswith(".go")]) >= 30
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
    ("sql_query_context__vuln.go", "DF004", "db.QueryContext(ctx,"),          # query is argument 1 after ctx
    ("sqlx_get__vuln.go", "DF004", "db.Get(&u,"),                             # sqlx DB.Get(dest, query)
    ("sqlx_select_func__vuln.go", "DF004", "sqlx.Select(db,"),                # sqlx.Select(q, dest, query)
    ("gorm_first_inline__vuln.go", "DF004", "db.First(&u,"),
    ("pgx_query__vuln.go", "DF004", "pool.Query("),
    ("http_servefile__vuln.go", "DF005", "http.ServeFile("),                  # name is argument 2
    ("zip_slip__vuln.go", "DF005", "os.Create(target)"),
    ("tar_slip__vuln.go", "DF005", "os.OpenFile("),
    ("new_request_ssrf__vuln.go", "DF010", "http.NewRequest("),               # URL is argument 1
    ("new_request_with_context__vuln.go", "DF010", "http.NewRequestWithContext("),
    ("net_dial__vuln.go", "DF010", "net.Dial("),
    ("websocket_dialer__vuln.go", "DF010", "DefaultDialer.Dial("),
    ("gin_redirect__vuln.go", "DF008", "c.Redirect("),
    ("ldap_search_filter__vuln.go", "DF014", "ldap.NewSearchRequest("),       # filter is argument 6
    ("xmlquery_find__vuln.go", "DF015", "xmlquery.Find("),                     # expression is argument 1
    ("expr_compile__vuln.go", "DF012", "expr.Compile("),
    ("echo_htmlblob__vuln.go", "DF013", "c.HTMLBlob("),
    ("command_text__vuln.cs", "DF004", "cmd.CommandText ="),
    ("process_arguments__vuln.cs", "DF002", "psi.Arguments ="),
    ("ldap_filter_property__vuln.cs", "DF014", "searcher.Filter ="),
    ("ldap_searcher_ctor__vuln.cs", "DF014", "new DirectorySearcher(root,"),  # filter is argument 1
    ("file_copy_dest__vuln.cs", "DF005", "File.Copy("),                       # destination is argument 1
    ("zip_slip__vuln.cs", "DF005", "ExtractToFile("),
    ("http_request_message__vuln.cs", "DF010", "new HttpRequestMessage("),     # URI is argument 1
    ("compile_assembly__vuln.cs", "DF007", "CompileAssemblyFromSource("),
    ("jint_execute__vuln.cs", "DF007", "engine.Execute("),
    ("xpath_navigator__vuln.cs", "DF015", "_nav.Select("),
    ("redirect_preserve__vuln.cs", "DF008", "RedirectPreserveMethod("),
    ("webforms_inner_html__vuln.cs", "DF013", "InnerHtml ="),
])
def test_reports_at_the_sink_line(name, rule, needle):
    """The finding points at the modelled sink, not at some other sink or a reflected return in the program."""
    path = DATA / name
    lines = path.read_text(encoding="utf-8").splitlines()
    hits = [f for f in _findings(path) if f.rule_id == rule]
    assert any(needle in lines[f.line - 1] for f in hits), [(f.line, lines[f.line - 1]) for f in hits]


def test_finding_cwes():
    """NoSQL sinks share DF004 with SQL but carry their own CWE."""
    for name in ("mongo_extjson__vuln.go", "mongo_bson_parse__vuln.cs"):
        assert "CWE-943" in {f.cwe for f in _findings(DATA / name) if f.rule_id == "DF004"}, name


def test_go_context_argument_is_not_a_sink():
    """`ctx context.Context` parameters are tainted by name; the *Context APIs must look past them."""
    src = ("package main\n\nimport (\n\t\"context\"\n\t\"database/sql\"\n\t\"net/http\"\n\t\"os/exec\"\n)\n\n"
           "func job(ctx context.Context, db *sql.DB) {\n"
           "\tdb.QueryRowContext(ctx, \"SELECT 1\")\n"
           "\texec.CommandContext(ctx, \"git\", \"gc\").Run()\n"
           "\thttp.NewRequestWithContext(ctx, \"GET\", \"https://example.com\", nil)\n}\n")
    leaked = getattr(cfamily_frontend.Parser, "go_methods", None)
    if isinstance(leaked, dict):
        leaked.clear()
    assert not {f.rule_id for f in analyze("job.go", src)} & {"DF003", "DF004", "DF010"}


@pytest.mark.parametrize("language", ["csharp", "go"])
def test_models_are_well_formed_and_translated(language):
    data = json.loads((MODELS_DIR / f"{language}.json").read_text(encoding="utf-8"))
    for s in data["sinks"] + data.get("attr_sinks", []):
        assert s.get("names") or s.get("attrs"), s
        assert s.get("cwe", "").startswith("CWE-"), s
        assert s.get("title") and s.get("title_ar"), s
        assert translated(s.get("advice", "")), s["advice"]
        assert all(isinstance(i, int) or i == "self" for i in s.get("args", [0])), s
        if s.get("receiver"):
            re.compile(s["receiver"])
    m = load_models_for(language)
    assert len(m["sinks"]) == len(data["sinks"])
    # a name may appear in several entries only when the entries are told apart by a receiver pattern
    seen: dict[str, int] = {}
    for s in data["sinks"]:
        if s.get("receiver"):
            continue
        for n in s["names"]:
            seen[n] = seen.get(n, 0) + 1
    assert not [n for n, k in seen.items() if k > 1], sorted(n for n, k in seen.items() if k > 1)


# very common method names; a model entry may use them bare only where it already did before the breadth expansion
COMMON = {"Get", "Post", "Put", "Delete", "Run", "Send", "Exec", "Execute", "Evaluate", "Select", "Find", "First",
          "Query", "Compile", "Redirect", "Download", "Attachment", "Inline", "SaveFile", "SQL", "PutAsync", "DeleteAsync",
          "PatchAsync", "Matches", "Group", "Or", "Not", "Table", "Distinct", "Pluck", "Take", "Last", "Eval", "Open",
          "Create", "Dial", "Parse", "Write", "Search", "Filter", "Invoke", "Content", "Text", "Start", "Raw"}
LEGACY_BARE = {
    "go": {"Compile", "Dial", "Eval", "Exec", "Find", "Get", "Open", "Parse", "Post", "Query", "Raw", "Redirect",
           "Search", "Select", "Write"},
    "csharp": {"Content", "Create", "Eval", "Evaluate", "Execute", "Filter", "Invoke", "Query", "Raw", "Redirect",
               "Select", "Start", "Text", "Write"},
}


@pytest.mark.parametrize("language", ["csharp", "go"])
def test_common_method_names_are_receiver_constrained(language):
    data = json.loads((MODELS_DIR / f"{language}.json").read_text(encoding="utf-8"))
    bare = {n for s in data["sinks"] if not s.get("receiver") for n in s["names"]} & COMMON
    assert bare <= LEGACY_BARE[language], sorted(bare - LEGACY_BARE[language])


def test_entry_points():
    m = load_models_for("csharp")
    for name in ("OnPostAsync", "OnGetAsync", "Page_Load", "Details", "Edit", "Create"):
        assert name in m["view_methods"], name
    for dec in ("ValidateAntiForgeryToken", "HttpHead", "Authorize"):
        assert dec in m["entry_decorators"], dec
