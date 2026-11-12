"""The MCP server (vulnscan/mcp.py), driven as a subprocess with real MCP messages over stdio.

The project under test is written at run time: views.py reads request.args and passes it to helpers.run_backup(),
which builds an os.system() command (vulnerable, cross-file); its twin goes through shlex.quote() (safe).
"""

from __future__ import annotations

import json
import os
import pathlib
import queue
import shutil
import subprocess
import sys
import threading
import types

import pytest

from vulnscan import mcp
from vulnscan.mcp import (PROTOCOL_VERSIONS, STR, TOOL_NAMES, KashifMCPServer, PathPolicy, ToolError, client_config,
                          explain_rule, list_rules, rule_catalogue, tool_definitions)

ROOT = pathlib.Path(__file__).resolve().parent.parent
TIMEOUT = 90

HELPERS = '''import os
import shlex


def run_backup(name):
    os.system("tar czf backup.tgz " + name)


def run_backup_safely(name):
    os.system("tar czf backup.tgz -- " + shlex.quote(name))
'''
VIEWS = '''from flask import Flask, request

from helpers import run_backup, run_backup_safely

app = Flask(__name__)


@app.route("/backup")
def backup():
    name = request.args.get("name", "")
    run_backup(name)
    return "ok"


@app.route("/backup-safe")
def backup_safe():
    name = request.args.get("name", "")
    run_backup_safely(name)
    return "ok"
'''


def make_project(base: pathlib.Path) -> pathlib.Path:
    proj = base / "proj"
    proj.mkdir(parents=True)
    (proj / "helpers.py").write_text(HELPERS, encoding="utf-8")
    (proj / "views.py").write_text(VIEWS, encoding="utf-8")
    return proj


class Client:
    """A minimal MCP client: newline-delimited JSON-RPC over the server's stdin/stdout."""

    def __init__(self, cwd, *args, roots=None, env=None):
        environ = dict(os.environ, PYTHONPATH=str(ROOT), PYTHONIOENCODING="utf-8")
        environ.pop("VULNSCAN_LANG", None)
        environ.update(env or {})
        self.proc = subprocess.Popen([sys.executable, "-m", "vulnscan.mcp", *args], cwd=str(cwd), env=environ,
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.roots = roots                       # list of paths answered to the server's roots/list request
        self.roots_requests = 0
        self.inbox: queue.Queue = queue.Queue()
        self.raw: list[bytes] = []
        self.next_id = 0
        threading.Thread(target=self._read, daemon=True).start()
        threading.Thread(target=self.proc.stderr.read, daemon=True).start()

    def _read(self):
        for line in self.proc.stdout:
            self.raw.append(line)
            self.inbox.put(json.loads(line.decode("utf-8")))
        self.inbox.put(None)

    def send_raw(self, data: bytes):
        self.proc.stdin.write(data)
        self.proc.stdin.flush()

    def send(self, msg):
        self.send_raw(json.dumps(msg).encode("utf-8") + b"\n")

    def notify(self, method, params=None):
        self.send({"jsonrpc": "2.0", "method": method, **({"params": params} if params is not None else {})})

    def recv(self, want_id=None):
        """Next message from the server; server-to-client requests (roots/list) are answered on the way."""
        while True:
            msg = self.inbox.get(timeout=TIMEOUT)
            assert msg is not None, "server closed its output"
            if isinstance(msg, dict) and msg.get("method") == "roots/list":
                self.roots_requests += 1
                self.send({"jsonrpc": "2.0", "id": msg["id"], "result": {
                    "roots": [{"uri": pathlib.Path(r).resolve().as_uri(), "name": "r"} for r in self.roots or []]}})
                continue
            if want_id is None or (isinstance(msg, dict) and msg.get("id") == want_id):
                return msg

    def request(self, method, params=None):
        self.next_id += 1
        msg = {"jsonrpc": "2.0", "id": self.next_id, "method": method}
        if params is not None:
            msg["params"] = params
        self.send(msg)
        return self.recv(self.next_id)

    def initialize(self, version=PROTOCOL_VERSIONS[0], capabilities=None):
        r = self.request("initialize", {"protocolVersion": version, "capabilities": capabilities or {},
                                        "clientInfo": {"name": "pytest", "version": "1"}})
        self.notify("notifications/initialized")
        return r["result"]

    def tool(self, name, arguments=None):
        """(payload, result): payload is the structured content, or the parsed error object for isError results."""
        r = self.request("tools/call", {"name": name, "arguments": arguments or {}})
        assert "result" in r, r
        result = r["result"]
        text = json.loads(result["content"][0]["text"])
        if result.get("isError"):
            assert "structuredContent" not in result
            return text["error"], result
        assert result["structuredContent"] == text              # the text block is the same JSON
        return result["structuredContent"], result

    def close(self):
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        return self.proc.returncode


@pytest.fixture
def project(tmp_path):
    return make_project(tmp_path)


@pytest.fixture
def client(project):
    c = Client(project)
    c.initialize()
    yield c
    c.close()


# ------------------------------------------------------------------ lifecycle and protocol

def test_initialize_negotiates_version_and_describes_server(project):
    c = Client(project)
    try:
        res = c.initialize("2025-06-18")
        assert res["protocolVersion"] == "2025-06-18"
        assert res["serverInfo"]["name"] == "kashif" and res["serverInfo"]["version"]
        assert "tools" in res["capabilities"] and "resources" in res["capabilities"]
        assert "scan_path" in res["instructions"]
        assert c.request("ping")["result"] == {}
    finally:
        assert c.close() == 0


def test_unknown_protocol_version_gets_latest_supported(project):
    c = Client(project)
    try:
        assert c.initialize("1999-01-01")["protocolVersion"] == PROTOCOL_VERSIONS[0]
    finally:
        c.close()


def test_every_line_on_stdout_is_one_json_message(client):
    client.tool("scan_path", {"path": ".", "lang": "ar"})
    client.request("tools/list")
    for line in client.raw:
        assert line.endswith(b"\n") and line.count(b"\n") == 1
        assert json.loads(line)["jsonrpc"] == "2.0"


def test_tools_list_schemas_and_annotations(client):
    tools = client.request("tools/list")["result"]["tools"]
    assert [t["name"] for t in tools] == list(TOOL_NAMES)
    by = {t["name"]: t for t in tools}
    for t in tools:
        assert t["description"] and t["inputSchema"]["type"] == "object"
        assert t["inputSchema"]["additionalProperties"] is False
        assert t["outputSchema"]["type"] == "object"
        for key in ("anyOf", "oneOf", "allOf"):                # rejected at the top level by some model APIs
            assert key not in t["inputSchema"]
        assert t["annotations"]["openWorldHint"] is False and t["annotations"]["destructiveHint"] is False
    assert by["scan_path"]["inputSchema"]["required"] == ["path"]
    assert set(by["scan_path"]["inputSchema"]["properties"]) >= {"path", "min_severity", "diff_base", "audit", "cursor"}
    assert by["scan_snippet"]["inputSchema"]["required"] == ["code"]
    assert by["get_finding"]["inputSchema"]["required"] == ["path", "fingerprint"]
    for name in ("scan_path", "get_finding", "explain_rule", "list_rules", "suggest_fix"):
        assert by[name]["annotations"]["readOnlyHint"] is True
    assert by["scan_snippet"]["annotations"]["readOnlyHint"] is False      # it writes a temporary file


def test_old_protocol_gets_no_output_schema(project):
    c = Client(project)
    try:
        c.initialize("2024-11-05")
        tools = c.request("tools/list")["result"]["tools"]
        assert all("outputSchema" not in t and "annotations" not in t for t in tools)
    finally:
        c.close()


def test_malformed_json_is_a_parse_error_and_the_server_survives(client):
    client.send_raw(b'{"jsonrpc": "2.0", "id": 1, "method": \n')
    err = client.recv()
    assert err["id"] is None and err["error"]["code"] == -32700
    client.send_raw(b"\n")                                     # blank lines are ignored
    assert client.request("ping")["result"] == {}


def test_unknown_method_notification_and_invalid_requests(client):
    r = client.request("no/such/method")
    assert r["error"]["code"] == -32601
    client.notify("notifications/whatever")                    # unknown notification: no reply at all
    client.send({"id": 77, "method": "ping"})                  # not JSON-RPC 2.0
    r = client.recv()
    assert r["error"]["code"] == -32600
    client.send({"jsonrpc": "2.0", "id": 78})                  # neither request nor response
    assert client.recv(78)["error"]["code"] == -32600
    client.send({"jsonrpc": "2.0", "id": 79, "method": "tools/call", "params": [1]})
    assert client.recv(79)["error"]["code"] == -32602
    assert client.request("ping")["result"] == {}


def test_unknown_tool_is_a_protocol_error_bad_arguments_a_tool_error(client):
    r = client.request("tools/call", {"name": "rm_rf", "arguments": {}})
    assert r["error"]["code"] == -32602
    err, result = client.tool("scan_path", {})
    assert result["isError"] is True and err["code"] == "invalid_arguments" and "path" in err["message"]
    err, _ = client.tool("scan_path", {"path": ".", "min_severity": "catastrophic"})
    assert err["code"] == "invalid_arguments"
    err, _ = client.tool("scan_path", {"path": ".", "command": "id"})
    assert err["code"] == "invalid_arguments" and "command" in err["message"]
    err, _ = client.tool("scan_path", {"path": 5})
    assert err["code"] == "invalid_arguments"
    err, _ = client.tool("scan_path", {"path": ".", "cursor": "%%%"})
    assert err["code"] == "invalid_arguments"


def test_batch_and_eof_flush(project):
    msgs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}},
        [{"jsonrpc": "2.0", "id": 2, "method": "ping"}, {"jsonrpc": "2.0", "method": "notifications/initialized"},
         {"jsonrpc": "2.0", "id": 3, "method": "tools/list"}],
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "scan_path", "arguments": {"path": "."}}},
    ]
    data = b"".join(json.dumps(m).encode() + b"\n" for m in msgs)
    proc = subprocess.run([sys.executable, "-m", "vulnscan.mcp"], input=data, cwd=str(project), capture_output=True,
                          env=dict(os.environ, PYTHONPATH=str(ROOT)), timeout=TIMEOUT)
    assert proc.returncode == 0
    out = [json.loads(line) for line in proc.stdout.splitlines()]
    assert out[0]["id"] == 1
    assert isinstance(out[1], list) and [m["id"] for m in out[1]] == [2, 3]
    assert out[2]["id"] == 4 and out[2]["result"]["isError"] is False     # answered although stdin closed at once


# ------------------------------------------------------------------ scan_path

def test_scan_project_finds_the_cross_file_flow(client):
    body, result = client.tool("scan_path", {"path": "."})
    assert result["isError"] is False
    assert body["files_scanned"] == 2 and body["target"] == "."
    flows = [f for f in body["findings"] if f.get("data_flow")]
    assert len(flows) == 1                                      # the shlex.quote() twin is not reported
    f = flows[0]
    assert f["severity"] == "critical" and f["cwe"] == "CWE-78" and f["file"] == "views.py" and f["line"] == 11
    assert [s["file"] for s in f["data_flow"]] == ["views.py", "views.py", "helpers.py"]
    assert f["data_flow"][-1]["line"] == 6 and "os.system" in f["data_flow"][-1]["note"]
    assert f["tainted_source"] == "request.args"
    assert f["remediation"] and not mcp.has_arabic(f["remediation"]) and f["fingerprint"]
    assert body["summary"]["by_severity"]["critical"] == 1
    assert body["summary"]["total"] >= body["summary"]["matching"] == body["summary"]["returned"] == len(body["findings"])
    assert all(f["severity"] != "info" for f in body["findings"])          # default min_severity is low
    assert any("Offline" in n for n in body["notes"])


def test_scan_absolute_path_single_file_and_arabic(client, project):
    body, _ = client.tool("scan_path", {"path": str(project / "helpers.py"), "lang": "ar"})
    assert body["files_scanned"] == 1 and body["target"] == "helpers.py"
    assert body["findings"] and all(f["file"] == "helpers.py" for f in body["findings"])
    assert mcp.has_arabic(body["findings"][0]["title"]) and mcp.has_arabic(body["findings"][0]["remediation"])


def test_min_severity_and_pagination(client):
    everything, _ = client.tool("scan_path", {"path": ".", "min_severity": "info", "limit": 100})
    total = everything["summary"]["matching"]
    assert total >= 3 and "next_cursor" not in everything
    only_critical, _ = client.tool("scan_path", {"path": ".", "min_severity": "critical"})
    assert {f["severity"] for f in only_critical["findings"]} == {"critical"}
    seen, cursor, pages = [], None, 0
    while True:
        args = {"path": ".", "min_severity": "info", "limit": 1}
        if cursor:
            args["cursor"] = cursor
        page, _ = client.tool("scan_path", args)
        assert len(page["findings"]) == 1
        seen.append(page["findings"][0]["fingerprint"])
        pages += 1
        cursor = page.get("next_cursor")
        if not cursor:
            break
    assert pages == total and seen == [f["fingerprint"] for f in everything["findings"]]


def test_output_size_cap_pages_by_bytes(tmp_path):
    proj = tmp_path / "big"
    proj.mkdir()
    (proj / "many.py").write_text("import os\n" + "".join(f"os.system('ls ' + a{i})\n" for i in range(60)),
                                  encoding="utf-8")
    c = Client(proj, "--max-output", "4000")
    try:
        c.initialize()
        body, result = c.tool("scan_path", {"path": ".", "limit": 100})
        assert body["summary"]["matching"] >= 60
        assert 0 < body["summary"]["returned"] < body["summary"]["matching"] and body["next_cursor"]
        assert len(result["content"][0]["text"].encode()) <= 4200
        nxt, _ = c.tool("scan_path", {"path": ".", "limit": 100, "cursor": body["next_cursor"]})
        assert nxt["findings"][0]["fingerprint"] not in {f["fingerprint"] for f in body["findings"]}
    finally:
        c.close()


def test_result_cache_is_invalidated_when_a_file_changes(client, project):
    first, _ = client.tool("scan_path", {"path": "."})
    (project / "extra.py").write_text("import pickle, sys\npickle.loads(sys.stdin.buffer.read())\n", encoding="utf-8")
    second, _ = client.tool("scan_path", {"path": "."})
    assert second["files_scanned"] == first["files_scanned"] + 1
    assert any(f["file"] == "extra.py" for f in second["findings"])


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
def test_diff_base_reports_only_what_the_change_introduced(tmp_path):
    proj = make_project(tmp_path)

    def git(*args):
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false",
                        *args], cwd=str(proj), check=True, capture_output=True)

    git("init", "-q")
    git("add", "-A")
    git("commit", "-q", "-m", "base")
    (proj / "new_view.py").write_text("import os\nfrom flask import request\n\n\ndef ping():\n"
                                      "    os.system('ping ' + request.args['host'])\n", encoding="utf-8")
    c = Client(proj)
    try:
        c.initialize()
        full, _ = c.tool("scan_path", {"path": "."})
        diff, _ = c.tool("scan_path", {"path": ".", "diff_base": "HEAD"})
        assert {f["file"] for f in full["findings"]} >= {"views.py", "new_view.py"}
        assert diff["findings"] and {f["file"] for f in diff["findings"]} == {"new_view.py"}
        assert all(f["introduced_by"] in ("line", "trail", "file") for f in diff["findings"])
        err, _ = c.tool("scan_path", {"path": ".", "diff_base": "no-such-ref"})
        assert err["code"] == "diff_failed"
        err, _ = c.tool("scan_path", {"path": ".", "diff_base": "--output=/tmp/x"})
        assert err["code"] == "diff_failed"                     # option-looking refs never reach git
    finally:
        c.close()


# ------------------------------------------------------------------ safety: roots

def test_path_outside_roots_is_refused(client, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "x.py").write_text("import os\nos.system(input())\n", encoding="utf-8")
    for path in (str(outside), "../outside", str(outside / "x.py"), outside.as_uri(), "/"):
        err, result = client.tool("scan_path", {"path": path})
        assert result["isError"] is True and err["code"] == "path_outside_roots", path
    err, _ = client.tool("scan_path", {"path": str(tmp_path / "does-not-exist")})
    assert err["code"] == "path_outside_roots"                  # existence outside the roots is not revealed
    err, _ = client.tool("scan_path", {"path": "missing-dir"})
    assert err["code"] == "path_not_found"
    err, _ = client.tool("scan_path", {"path": "https://example.invalid/repo"})
    assert err["code"] == "invalid_arguments"
    err, _ = client.tool("get_finding", {"path": str(outside), "fingerprint": "0" * 16})
    assert err["code"] == "path_outside_roots"


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_symlinks_cannot_escape_the_roots(client, project, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "leak.py").write_text("import os\nos.system(input())\n", encoding="utf-8")
    (project / "link_dir").symlink_to(outside, target_is_directory=True)
    (project / "linked.py").symlink_to(outside / "leak.py")
    err, _ = client.tool("scan_path", {"path": "link_dir"})
    assert err["code"] == "path_outside_roots"
    err, _ = client.tool("scan_path", {"path": "linked.py"})
    assert err["code"] == "path_outside_roots"
    body, _ = client.tool("scan_path", {"path": ".", "min_severity": "info"})
    assert all(f["file"] not in ("linked.py", "link_dir/leak.py") for f in body["findings"])
    assert any("symlink" in n for n in body["notes"])


def test_root_flag_and_client_roots(tmp_path):
    proj = make_project(tmp_path)
    extra = tmp_path / "extra"
    extra.mkdir()
    (extra / "a.py").write_text("import os\nos.system(input())\n", encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    # no cwd root, one --root; the client advertises the project through the MCP roots capability
    c = Client(elsewhere, "--no-cwd-root", "--root", str(extra), roots=[proj])
    try:
        c.initialize(capabilities={"roots": {"listChanged": True}})
        body, _ = c.tool("scan_path", {"path": str(proj)})
        assert c.roots_requests == 1 and any(f.get("data_flow") for f in body["findings"])
        body, _ = c.tool("scan_path", {"path": "a.py"})         # relative to the first root (--root)
        assert body["findings"]
        err, _ = c.tool("scan_path", {"path": str(elsewhere)})
        assert err["code"] == "path_outside_roots" and str(extra.resolve()) in err["hint"]
        c.roots = []                                            # the client withdraws its roots
        c.notify("notifications/roots/list_changed")
        err, _ = c.tool("scan_path", {"path": str(proj)})
        assert c.roots_requests == 2 and err["code"] == "path_outside_roots"
    finally:
        c.close()


def test_client_roots_can_be_ignored_and_no_roots_is_explained(tmp_path):
    proj = make_project(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    c = Client(elsewhere, "--no-cwd-root", "--no-client-roots", roots=[proj])
    try:
        c.initialize(capabilities={"roots": {}})
        err, _ = c.tool("scan_path", {"path": str(proj)})
        assert err["code"] == "no_roots" and "--root" in err["hint"] and c.roots_requests == 0
    finally:
        c.close()


def test_path_policy_unit(tmp_path):
    root = tmp_path / "r"
    (root / "sub").mkdir(parents=True)
    policy = PathPolicy([root])
    assert policy.resolve("sub") == (root / "sub").resolve()
    assert policy.resolve(str(root)) == root.resolve()
    assert policy.resolve((root / "sub").as_uri()) == (root / "sub").resolve()
    for bad in ("", "a\x00b", None, 3):
        with pytest.raises(ToolError) as e:
            policy.resolve(bad)
        assert e.value.code == "invalid_arguments"
    with pytest.raises(ToolError) as e:
        policy.resolve(str(tmp_path / "rr"))                    # a sibling sharing the prefix is not inside
    assert e.value.code == "path_outside_roots"
    policy.set_client_roots(["https://example.invalid/x", (tmp_path).as_uri(), str(tmp_path / "missing")])
    assert policy.roots() == [str(root.resolve()), str(tmp_path.resolve())]


def test_cwd_is_not_an_implicit_root_when_it_is_home_or_filesystem_root(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    assert mcp._safe_cwd_root() is None
    sub = tmp_path / "work"
    sub.mkdir()
    monkeypatch.chdir(sub)
    assert mcp._safe_cwd_root() == str(sub.resolve())


# ------------------------------------------------------------------ scan_snippet

def test_snippet_scan_and_cleanup(project, tmp_path):
    tmpdir = tmp_path / "tmp"
    tmpdir.mkdir()
    c = Client(project, env={"TMPDIR": str(tmpdir), "TEMP": str(tmpdir), "TMP": str(tmpdir)})
    try:
        c.initialize()
        code = "import os\nfrom flask import request\n\n\ndef run():\n    os.system('ping ' + request.args['host'])\n"
        body, result = c.tool("scan_snippet", {"code": code, "language": "python"})
        assert result["isError"] is False and body["target"] == "snippet.py" and body["files_scanned"] == 1
        flow = next(f for f in body["findings"] if f.get("data_flow"))
        assert flow["cwe"] == "CWE-78" and flow["file"] == "snippet.py" and flow["line"] == 6
        body, _ = c.tool("scan_snippet", {"code": "import subprocess\nsubprocess.run(['ls', '-l'])\n", "language": "py"})
        assert body["findings"] == []
        js = "const cp = require('child_process');\napp.get('/x', (req, res) => { cp.exec('ls ' + req.query.d); });\n"
        body, _ = c.tool("scan_snippet", {"code": js, "filename": "../../etc/routes.js"})
        assert body["target"] == "routes.js" and any(f["cwe"] == "CWE-78" for f in body["findings"])
        err, _ = c.tool("scan_snippet", {"code": "x = 1"})
        assert err["code"] == "invalid_arguments"
        err, _ = c.tool("scan_snippet", {"code": "x = 1", "language": "klingon"})
        assert err["code"] == "invalid_arguments" and "python" in err["hint"]
        err, _ = c.tool("scan_snippet", {"code": "#" * (mcp.MAX_SNIPPET_BYTES + 1), "language": "python"})
        assert err["code"] == "too_large"
        assert list(tmpdir.iterdir()) == []                     # every private temp dir was removed
    finally:
        c.close()


def test_snippet_filename_is_reduced_to_a_safe_base_name():
    assert mcp._snippet_filename("../../a b/..\\evil name.py", None, "en") == "evil_name.py"
    assert mcp._snippet_filename(None, "C#", "en") == "Snippet.cs"
    assert mcp._snippet_filename("..", "go", "en") == "snippet.go"
    assert mcp._snippet_filename("Dockerfile", None, "en") == "Dockerfile"
    with pytest.raises(ToolError):
        mcp._snippet_filename("..", None, "en")


# ------------------------------------------------------------------ get_finding, explain_rule, list_rules, suggest_fix

def test_get_finding_full_detail(client):
    body, _ = client.tool("scan_path", {"path": "."})
    flow = next(f for f in body["findings"] if f.get("data_flow"))
    detail, result = client.tool("get_finding", {"path": ".", "fingerprint": flow["fingerprint"]})
    assert result["isError"] is False
    assert detail["finding"]["fingerprint"] == flow["fingerprint"] and len(detail["finding"]["data_flow"]) == 3
    flagged = [ln for ln in detail["code_context"] if ln["flagged"]]
    assert len(flagged) == 1 and flagged[0]["line"] == 11 and "run_backup(name)" in flagged[0]["text"]
    assert detail["rule"]["cwe"] == "CWE-78" and detail["rule"]["why_it_matters"]["en"]
    assert detail["cwe_url"].endswith("/78.html") and "vulnscan: ignore" in detail["suppression"]
    short, _ = client.tool("get_finding", {"path": ".", "fingerprint": flow["fingerprint"].split(":")[0]})
    assert short["finding"]["fingerprint"] == flow["fingerprint"]
    err, result = client.tool("get_finding", {"path": ".", "fingerprint": "feedfacefeedface:0"})
    assert result["isError"] is True and err["code"] == "finding_not_found" and err["hint"]


def test_explain_rule_and_list_rules(client):
    body, _ = client.tool("explain_rule", {"rule_id": "df002"})            # case-insensitive
    assert body["rule_id"] == "DF002" and body["cwe"] == "CWE-78" and body["owasp"].startswith("A03")
    for key in ("title", "why_it_matters", "remediation"):
        assert body[key]["en"] and not mcp.has_arabic(body[key]["en"])
        assert mcp.has_arabic(body[key]["ar"])
    err, result = client.tool("explain_rule", {"rule_id": "DF0002"})
    assert result["isError"] is True and err["code"] == "unknown_rule" and "DF002" in err["hint"]
    everything, _ = client.tool("list_rules")
    assert everything["total"] == len(rule_catalogue()) >= 100
    ids = [r["id"] for r in everything["rules"]]
    cursor = everything.get("next_cursor")
    while cursor:
        page, _ = client.tool("list_rules", {"cursor": cursor})
        ids += [r["id"] for r in page["rules"]]
        cursor = page.get("next_cursor")
    assert len(ids) == len(set(ids)) == everything["total"]
    go, _ = client.tool("list_rules", {"language": "golang"})
    assert 0 < go["total"] < everything["total"]
    assert all("go" in r["languages"] or "any" in r["languages"] for r in go["rules"])
    assert any(r["kind"] == "dataflow" and "go" in r["languages"] for r in go["rules"])


def test_catalogue_api():
    rules = rule_catalogue()
    assert len({r["id"] for r in rules}) == len(rules)
    assert {r["kind"] for r in rules} >= {"pattern", "dataflow", "query"}
    for r in rules:
        info = explain_rule(r["id"])
        assert info["title"]["en"] and info["why_it_matters"]["ar"] and info["remediation"]["en"]
    assert [r["id"] for r in list_rules("py")] == [r["id"] for r in list_rules("python")]
    assert mcp.has_arabic(list_rules("python", "ar")[0]["title"])


def test_suggest_fix_degrades_without_the_autofix_module(client):
    body, _ = client.tool("scan_path", {"path": "."})
    fp = body["findings"][0]["fingerprint"]
    fix, result = client.tool("suggest_fix", {"path": ".", "fingerprint": fp})
    assert result["isError"] is False and fix["finding"]["fingerprint"] == fp
    if not mcp._has_autofix():
        assert fix["available"] is False and "fix" not in fix and fix["reason"]
    else:
        assert isinstance(fix["available"], bool)
    err, _ = client.tool("suggest_fix", {"path": ".", "fingerprint": "feedfacefeedface"})
    assert err["code"] == "finding_not_found"


def test_suggest_fix_returns_the_fix_dict_when_autofix_exists(project, monkeypatch):
    def suggest_fix(finding, root):
        return {"kind": "replace", "file": finding.file, "line": finding.line, "note": "quote it"} \
            if finding.rule_id.startswith("DF") else None

    monkeypatch.setattr(mcp, "_autofix_module", lambda: types.SimpleNamespace(suggest_fix=suggest_fix))
    monkeypatch.setattr(mcp, "_has_autofix", lambda: True)
    server = KashifMCPServer(roots=[project], isolate=False)
    scan = server.call_tool("scan_path", {"path": str(project)})["structuredContent"]
    flow = next(f for f in scan["findings"] if f.get("data_flow"))
    other = next(f for f in scan["findings"] if not f.get("data_flow"))
    got = server.call_tool("suggest_fix", {"path": str(project), "fingerprint": flow["fingerprint"]})
    assert got["isError"] is False
    assert got["structuredContent"]["available"] is True
    assert got["structuredContent"]["fix"] == {"kind": "replace", "file": "views.py", "line": 11, "note": "quote it"}
    none = server.call_tool("suggest_fix", {"path": str(project), "fingerprint": other["fingerprint"]})
    assert none["structuredContent"]["available"] is False and none["structuredContent"]["reason"]

    def attach_fixes(findings, root):                          # the bulk hook: fixes arrive with every scan
        for f in findings:
            f.extra["fix"] = {"patch": f"fix {f.rule_id}"}

    monkeypatch.setattr(mcp, "_autofix_module", lambda: types.SimpleNamespace(attach_fixes=attach_fixes))
    server = KashifMCPServer(roots=[project], isolate=False)
    scan = server.call_tool("scan_path", {"path": str(project)})["structuredContent"]
    assert all(f["fix_available"] for f in scan["findings"])
    got = server.call_tool("suggest_fix", {"path": str(project), "fingerprint": other["fingerprint"]})
    assert got["structuredContent"]["fix"] == {"patch": f"fix {other['rule_id']}"}


# ------------------------------------------------------------------ resources

def test_resources(client):
    res = client.request("resources/list")["result"]["resources"]
    assert [r["uri"] for r in res] == ["kashif://rules"]
    assert client.request("resources/templates/list")["result"]["resourceTemplates"][0]["uriTemplate"] == \
        "kashif://rule/{rule_id}"
    rules = json.loads(client.request("resources/read", {"uri": "kashif://rules"})["result"]["contents"][0]["text"])
    assert len(rules["rules"]) == len(rule_catalogue())
    one = client.request("resources/read", {"uri": "kashif://rule/DF002"})["result"]["contents"][0]
    assert one["mimeType"] == "application/json" and json.loads(one["text"])["cwe"] == "CWE-78"
    assert client.request("resources/read", {"uri": "kashif://rule/NOPE999"})["error"]["code"] == -32002
    assert client.request("resources/read", {"uri": "file:///etc/passwd"})["error"]["code"] == -32002
    assert client.request("resources/read", {})["error"]["code"] == -32602


# ------------------------------------------------------------------ timeouts, cancellation, worker fallback

def test_scan_is_killed_on_timeout(project, monkeypatch):
    monkeypatch.setattr(mcp, "_worker_command", lambda: [sys.executable, "-c", "import time; time.sleep(120)"])
    server = KashifMCPServer(roots=[project], timeout=1)
    server._worker_ok = True
    result = server.call_tool("scan_path", {"path": str(project)})
    err = json.loads(result["content"][0]["text"])["error"]
    assert result["isError"] is True and err["code"] == "timeout" and err["hint"]
    assert not server._children                                  # the worker was killed and reaped


def test_scan_is_cancellable(project, monkeypatch):
    monkeypatch.setattr(mcp, "_worker_command", lambda: [sys.executable, "-c", "import time; time.sleep(120)"])
    server = KashifMCPServer(roots=[project], timeout=60)
    cancel = threading.Event()
    threading.Timer(0.5, cancel.set).start()
    result = server.call_tool("scan_path", {"path": str(project)}, cancel)
    assert json.loads(result["content"][0]["text"])["error"]["code"] == "cancelled" and not server._children


def test_cancelled_notification_suppresses_the_response(project, monkeypatch):
    import io
    monkeypatch.setattr(mcp, "_worker_command", lambda: [sys.executable, "-c", "import time; time.sleep(120)"])
    out = io.BytesIO()
    server = KashifMCPServer(out, roots=[project], timeout=60)
    server.feed_line(json.dumps({"jsonrpc": "2.0", "id": "a1", "method": "tools/call",
                                 "params": {"name": "scan_path", "arguments": {"path": str(project)}}}).encode())
    server.feed_line(json.dumps({"jsonrpc": "2.0", "method": "notifications/cancelled",
                                 "params": {"requestId": "a1", "reason": "user"}}).encode())
    for t in list(server._threads):
        t.join(30)
    assert out.getvalue() == b"" and not server._inflight


def test_falls_back_to_in_process_when_the_worker_cannot_start(project, monkeypatch):
    monkeypatch.setattr(mcp, "_worker_command", lambda: [sys.executable, "-c", "print('usage: no such command')"])
    server = KashifMCPServer(roots=[project])
    result = server.call_tool("scan_path", {"path": str(project)})
    assert result["isError"] is False and server.isolate is False
    assert any(f.get("data_flow") for f in result["structuredContent"]["findings"])


def test_worker_reports_engine_failures_as_tool_errors(project, monkeypatch):
    monkeypatch.setattr(mcp, "_JOBS", {"scan": lambda job: 1 / 0, "diff": mcp.run_diff_job})
    server = KashifMCPServer(roots=[project], isolate=False)
    result = server.call_tool("scan_path", {"path": str(project)})
    err = json.loads(result["content"][0]["text"])["error"]
    assert result["isError"] is True and err["code"] == "scan_failed" and "ZeroDivisionError" in err["message"]


# ------------------------------------------------------------------ strings and client configuration

def test_strings_exist_in_both_languages():
    assert set(STR["en"]) == set(STR["ar"])
    for key, text in STR["ar"].items():
        assert mcp.has_arabic(text), key
    assert not any(mcp.has_arabic(v) for v in STR["en"].values())
    ar = {t["name"]: t for t in tool_definitions("ar")}
    assert set(ar) == set(TOOL_NAMES) and all(mcp.has_arabic(t["description"]) for t in ar.values())


def test_arabic_server_language(project):
    c = Client(project, "--lang", "ar")
    try:
        res = c.initialize()
        assert mcp.has_arabic(res["instructions"])
        err, _ = c.tool("scan_path", {"path": "/"})
        assert mcp.has_arabic(err["message"])
        body, _ = c.tool("scan_path", {"path": ".", "lang": "en"})          # a call may override the language
        assert not mcp.has_arabic(body["findings"][0]["title"])
    finally:
        c.close()


def test_client_config_snippets():
    assert client_config("claude", "kashif", ["mcp"]) == "claude mcp add kashif -- kashif mcp"
    assert json.loads(client_config("cursor", "kashif", ["mcp"])) == \
        {"mcpServers": {"kashif": {"command": "kashif", "args": ["mcp"]}}}
    assert json.loads(client_config("vscode", "kashif", ["mcp"])) == \
        {"servers": {"kashif": {"command": "kashif", "args": ["mcp"], "type": "stdio"}}}
    text = client_config("all", "kashif", ["mcp"])
    for name in ("Claude Code", "Cursor", "VS Code", "Windsurf", "Zed"):
        assert name in text
    with pytest.raises(ValueError):
        client_config("emacs")
    proc = subprocess.run([sys.executable, "-m", "vulnscan.mcp", "--print-config", "claude"], capture_output=True,
                          env=dict(os.environ, PYTHONPATH=str(ROOT)), timeout=TIMEOUT)
    assert proc.returncode == 0 and proc.stdout.decode().startswith("claude mcp add kashif -- ")


# ------------------------------------------------------------------ adversarial review: hostile clients and targets

def _in_process(project, **kw):
    import io
    out = io.BytesIO()
    return KashifMCPServer(out, roots=[project], isolate=False, **kw), out


def _error_of(result):
    assert result["isError"] is True
    return json.loads(result["content"][0]["text"])["error"]


def test_unsolicited_roots_answers_are_ignored(project, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    answer = {"jsonrpc": "2.0", "id": None, "result": {"roots": [{"uri": outside.resolve().as_uri()}]}}
    server, _ = _in_process(project, use_client_roots=False)
    server.feed_line(json.dumps(answer).encode())               # id null used to match "no request pending"
    assert server.policy.roots() == [os.path.realpath(project)]
    server.client_capabilities = {"roots": {}}
    server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert server._roots_request_id is None                     # --no-client-roots: nothing is even asked

    server, out = _in_process(project)
    server.feed_line(json.dumps(answer).encode())
    server.feed_line(json.dumps(dict(answer, id="kashif-roots-1")).encode())     # guessed id, nothing was asked
    assert server.policy.roots() == [os.path.realpath(project)]
    server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                   "params": {"protocolVersion": PROTOCOL_VERSIONS[0], "capabilities": {"roots": {}}}})
    server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"})
    rid = json.loads(out.getvalue().decode().splitlines()[-1])["id"]
    server.handle(dict(answer, id=rid))
    assert os.path.realpath(outside) in server.policy.roots()
    server.handle({"jsonrpc": "2.0", "id": rid, "result": {"roots": []}})        # a replay of the same id
    assert os.path.realpath(outside) in server.policy.roots()


def test_unc_paths_are_refused_before_any_file_system_call(project, monkeypatch):
    import ntpath
    assert mcp._remote_prefix(r"\\evil\share\x", ntpath) == r"\\evil\share"
    assert mcp._remote_prefix("//EVIL/Share/x", ntpath) == r"\\evil\share"
    assert mcp._remote_prefix(r"\\.\PhysicalDrive0", ntpath) and mcp._remote_prefix(r"\\?\C:\x", ntpath)
    assert mcp._remote_prefix(r"C:\proj\a.py", ntpath) == "" and mcp._remote_prefix("//evil/share/x") in ("", r"\\evil\share")

    policy = PathPolicy([project])
    touched = []
    real = os.path.realpath
    monkeypatch.setattr(mcp, "_remote_prefix", lambda path, pathmod=None: r"\\evil\share" if "evil" in path else "")
    monkeypatch.setattr(mcp.os.path, "realpath", lambda p, *a, **k: (touched.append(str(p)), real(p))[1])
    with pytest.raises(ToolError) as e:
        policy.resolve("evil-share/secret.py")
    assert e.value.code == "path_outside_roots" and not touched
    assert policy.resolve("views.py").name == "views.py" and touched


PING_ONLY_WORKER = ("import sys, json\njob = json.loads(sys.stdin.read())\n"
                    "if job.get('op') == 'ping':\n    print(json.dumps({'ok': {'pong': True}}))\n"
                    "else:\n    TAIL\n")


def test_a_worker_that_dies_on_the_target_is_not_replaced_by_an_in_process_scan(project, monkeypatch):
    script = PING_ONLY_WORKER.replace("TAIL", "sys.exit(7)")
    monkeypatch.setattr(mcp, "_worker_command", lambda: [sys.executable, "-c", script])
    called = []
    monkeypatch.setattr(mcp, "run_scan_job", lambda job: called.append(job))
    server = KashifMCPServer(roots=[project])
    err = _error_of(server.call_tool("scan_path", {"path": str(project)}))
    assert err["code"] == "scan_failed" and "status 7" in err["message"]
    assert server.isolate is True and not called


def test_the_worker_gets_a_private_temp_dir_that_is_removed_after_a_kill(project, monkeypatch, tmp_path):
    marker = tmp_path / "where.txt"
    tail = (f"import tempfile, time, pathlib; d = tempfile.gettempdir(); pathlib.Path(d, 'half-extracted').write_text('x');"
            f" pathlib.Path({str(marker)!r}).write_text(d, encoding='utf-8'); time.sleep(120)")
    monkeypatch.setattr(mcp, "_worker_command", lambda: [sys.executable, "-c", PING_ONLY_WORKER.replace("TAIL", tail)])
    server = KashifMCPServer(roots=[project], timeout=3)
    err = _error_of(server.call_tool("scan_path", {"path": str(project)}))
    assert err["code"] == "timeout"
    used = pathlib.Path(marker.read_text(encoding="utf-8"))
    assert used.name.startswith("kashif-mcp-w-") and not used.exists()


def test_decompression_bombs_are_not_extracted(project, monkeypatch):
    import io
    import tarfile
    import zipfile
    code = "import os\nos.system(input())\n"
    with zipfile.ZipFile(project / "ok.zip", "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("app/run.py", code)
    with zipfile.ZipFile(project / "bomb.zip", "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("app/run.py", code)
        zf.writestr("zeros.bin", b"\0" * 3_000_000)
    with tarfile.open(project / "bomb.tar.gz", "w:gz") as tf:
        info = tarfile.TarInfo("zeros.bin")
        info.size = 3_000_000
        tf.addfile(info, io.BytesIO(b"\0" * info.size))
    (project / "broken.zip").write_bytes(b"PK\x03\x04 not a zip")
    assert (project / "bomb.zip").stat().st_size < 50_000
    monkeypatch.setattr(mcp, "MAX_ARCHIVE_BYTES", 1_000_000)
    extracted = []
    from vulnscan import scanner
    real_extract = scanner.extract_archive
    monkeypatch.setattr(scanner, "extract_archive", lambda a: (extracted.append(a.name), real_extract(a))[1])
    server, _ = _in_process(project)
    ok = server.call_tool("scan_path", {"path": "ok.zip"})
    assert ok["isError"] is False and ok["structuredContent"]["findings"]
    for name in ("bomb.zip", "bomb.tar.gz"):
        err = _error_of(server.call_tool("scan_path", {"path": name}))
        assert err["code"] == "too_large" and err["hint"], name
    assert _error_of(server.call_tool("scan_path", {"path": "broken.zip"}))["code"] == "scan_failed"
    assert extracted == ["ok.zip", "broken.zip"]
    monkeypatch.setattr(mcp, "MAX_FILES", 1)                     # the entry count is capped too
    assert _error_of(server.call_tool("scan_path", {"path": "bomb.zip"}))["code"] == "too_large"


@pytest.mark.skipif(shutil.which("git") is None or os.name == "nt", reason="needs git and a POSIX shell")
def test_diff_base_does_not_run_commands_from_the_repository_config(tmp_path):
    proj = make_project(tmp_path)
    pwned = tmp_path / "pwned"

    def git(*args):
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false",
                        *args], cwd=str(proj), check=True, capture_output=True)

    git("init", "-q")
    git("add", "-A")
    git("commit", "-q", "-m", "base")
    (proj / "new_view.py").write_text("import os\nfrom flask import request\n\n\ndef ping():\n"
                                      "    os.system('ping ' + request.args['host'])\n", encoding="utf-8")
    git("config", "core.fsmonitor", f"sh -c 'touch {pwned}-fsmonitor'")
    server, _ = _in_process(proj)
    diff = server.call_tool("scan_path", {"path": ".", "diff_base": "HEAD"})
    assert diff["isError"] is False
    assert {f["file"] for f in diff["structuredContent"]["findings"]} == {"new_view.py"}
    assert not pathlib.Path(f"{pwned}-fsmonitor").exists()
    assert not any(k.startswith("GIT_CONFIG_KEY") and os.environ[k] == "core.fsmonitor" for k in os.environ)

    git("config", "filter.lfs.clean", "git-lfs clean -- %f")     # the standard Git LFS filter is accepted
    assert mcp._repo_git_commands(str(proj)) == []
    git("config", "filter.evil.clean", f"sh -c 'touch {pwned}-filter; cat'")
    (proj / ".gitattributes").write_text("*.py filter=evil\n", encoding="utf-8")
    (proj / "views.py").write_text(VIEWS + "\n# changed\n", encoding="utf-8")
    err = _error_of(server.call_tool("scan_path", {"path": ".", "diff_base": "HEAD"}))
    assert err["code"] == "diff_failed" and "filter.evil.clean" in err["message"] and err["hint"]
    assert not pathlib.Path(f"{pwned}-filter").exists()
    assert server.call_tool("scan_path", {"path": "."})["isError"] is False      # a plain scan needs no git


def test_secret_values_are_masked_in_snippets_and_context(project):
    secret = "".join(["Zx9", "Qm4", "Lp7", "Vt2", "Rk8", "Wn5"])          # built at run time, never a literal
    token = "".join(["AK", "IA", "J7Q2", "M9XK", "4T8B", "W3ZP"])
    (project / "settings.py").write_text(
        f'DEBUG = False\nDB_PASSWORD = "{secret}"\nAWS_ACCESS_KEY_ID = "{token}"\nNAME = "app"\n', encoding="utf-8")
    server, _ = _in_process(project)
    scan = server.call_tool("scan_path", {"path": "settings.py", "min_severity": "info"})
    hits = scan["structuredContent"]["findings"]
    assert hits and secret not in scan["content"][0]["text"] and token not in scan["content"][0]["text"]
    assert any("[redacted" in f["snippet"] for f in hits)
    detail = server.call_tool("get_finding", {"path": "settings.py", "fingerprint": hits[0]["fingerprint"]})
    assert secret not in detail["content"][0]["text"] and token not in detail["content"][0]["text"]
    assert any(row["text"] == "DEBUG = False" for row in detail["structuredContent"]["code_context"])
    views = [f for f in server.call_tool("scan_path", {"path": "."})["structuredContent"]["findings"]
             if f["file"] != "settings.py"]
    assert views and all("[redacted" not in f["snippet"] for f in views)       # other findings are left alone

    shown, _ = _in_process(project, show_secrets=True)
    raw = shown.call_tool("scan_path", {"path": "settings.py", "min_severity": "info"})["content"][0]["text"]
    assert secret in raw or token in raw

    assert mcp.redact_secrets(f"url = 'postgres://app:{secret}@db/x'").count(secret) == 0
    assert mcp.redact_secrets(f"password: {secret}") == f"password: [redacted {len(secret)} chars]"
    assert mcp.redact_secrets("x = compute(1, 2)") == "x = compute(1, 2)"
    assert mcp.redact_secrets('"' * 3000 + "a" * 3000) is not None            # no blow-up on hostile lines


def test_owasp_categories_follow_the_official_cwe_mapping():
    assert all(owasp == "" or owasp in mcp._OWASP for owasp, _, _ in mcp.WHY.values())
    expect = {"CWE-78": "A03", "CWE-89": "A03", "CWE-22": "A01", "CWE-601": "A01", "CWE-502": "A08",
              "CWE-918": "A10", "CWE-611": "A05", "CWE-798": "A07", "CWE-295": "A07", "CWE-297": "A07",
              "CWE-311": "A04", "CWE-319": "A02", "CWE-327": "A02", "CWE-117": "A09", "CWE-1104": "A06",
              # not in any OWASP Top 10:2021 "List of Mapped CWEs": no category is claimed
              "CWE-134": "", "CWE-120": "", "CWE-1336": "", "CWE-732": "", "CWE-489": "", "CWE-693": "",
              "CWE-250": ""}
    assert {cwe: mcp.WHY[cwe][0] for cwe in expect} == expect
    assert explain_rule("DF002")["owasp"] == "A03:2021 Injection"
    unmapped = next(r for r in rule_catalogue() if r["cwe"] == "CWE-732")
    assert explain_rule(unmapped["id"])["owasp"] == ""
    assert "2025" in mcp._OWASP["LLM01"] and "2025" in mcp._OWASP["LLM05"]


def test_client_config_quotes_commands_with_spaces():
    line = client_config("claude", "/opt/my tools/python3", ["-m", "vulnscan.mcp"])
    tail = line.split(" -- ", 1)[1]
    if os.name == "nt":
        assert tail.startswith('"/opt/my tools/python3"')
    else:
        import shlex
        assert shlex.split(tail) == ["/opt/my tools/python3", "-m", "vulnscan.mcp"]
    assert json.loads(client_config("zed", "kashif", ["mcp"])) == \
        {"context_servers": {"kashif": {"command": "kashif", "args": ["mcp"]}}}


def test_old_protocol_results_carry_no_structured_content_and_batches_are_capped(project):
    server, out = _in_process(project)
    call = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "list_rules", "arguments": {}}}
    server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}})
    old = server.handle(call)["result"]
    assert "structuredContent" not in old and json.loads(old["content"][0]["text"])["rules"]
    server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}})
    assert "structuredContent" in server.handle(call)["result"]
    ping = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
    server.feed_line(json.dumps([ping] * (mcp.MAX_BATCH + 1)).encode())
    reply = json.loads(out.getvalue().decode().splitlines()[-1])
    assert reply["error"]["code"] == -32600 and reply["id"] is None
    server.feed_line(json.dumps([ping] * mcp.MAX_BATCH).encode())
    assert len(json.loads(out.getvalue().decode().splitlines()[-1])) == mcp.MAX_BATCH


def test_snippet_names_avoid_windows_devices():
    assert mcp._snippet_filename("CON", None, "en") == "_CON"
    assert mcp._snippet_filename("nul.py", None, "en") == "_nul.py"
    assert mcp._snippet_filename("C:\\x\\COM1.js", None, "en") == "_COM1.js"
    assert mcp._snippet_filename("console.py", None, "en") == "console.py"


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_files_under_a_directory_that_resolves_outside_the_roots_are_excluded(project, tmp_path, monkeypatch):
    outside = tmp_path / "outside"
    (outside / "deep").mkdir(parents=True)
    (outside / "leak.py").write_text("import os\nos.system(input())\n", encoding="utf-8")
    (outside / "deep" / "more.py").write_text("x = 1\n", encoding="utf-8")
    (project / "junction").symlink_to(outside, target_is_directory=True)
    from vulnscan import scanner
    real_iter = scanner.iter_files

    def following(root, excludes):                               # what os.walk does with a Windows junction
        yield from real_iter(root, excludes)
        if not excludes:
            for sub in ("leak.py", "deep/more.py"):
                yield root / "junction" / sub, f"junction/{sub}"

    monkeypatch.setattr(scanner, "iter_files", following)
    server, _ = _in_process(project)
    _, excludes, skipped = server._tree_state(pathlib.Path(os.path.realpath(project)), "en")
    assert excludes == ["junction/*", "junction/deep/*"] and skipped == 2
    body = server.call_tool("scan_path", {"path": "."})["structuredContent"]
    assert any("symlink" in n for n in body["notes"])
    assert scanner._excluded("junction/leak.py", excludes) and not scanner._excluded("views.py", excludes)


def test_tree_walk_is_cancellable_and_get_finding_respects_the_size_cap(project):
    for i in range(300):
        (project / f"f{i}.txt").write_text("x\n", encoding="utf-8")
    server, _ = _in_process(project, max_output=4000)
    cancel = threading.Event()
    cancel.set()
    assert _error_of(server.call_tool("scan_path", {"path": "."}, cancel))["code"] == "cancelled"
    scan = server.call_tool("scan_path", {"path": "."})["structuredContent"]
    fp = next(f for f in scan["findings"] if f.get("data_flow"))["fingerprint"]
    got = server.call_tool("get_finding", {"path": ".", "fingerprint": fp})
    assert got["isError"] is False and len(got["content"][0]["text"].encode("utf-8")) <= 4000
    assert got["structuredContent"]["finding"]["fingerprint"] == fp


def test_hostile_protocol_input_never_kills_the_server(project):
    server, out = _in_process(project)
    lines = [b"[" * 200_000, b'{"jsonrpc":"2.0","id":1,"method":"ping","params":' + b"9" * 10_000 + b"}",
             b'{"jsonrpc":"2.0","id":1,"method":"ping"}\xff', b"null", b'"x"', b"[1, 2]", b'{"jsonrpc":"2.0","id":1.5,"method":"ping"}',
             b'{"jsonrpc":"2.0","id":{"a":1},"method":"ping"}', b'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":[]}',
             b'{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":{"x":1}}}',
             b'{"jsonrpc":"2.0","id":4,"method":"resources/read","params":{"uri":"kashif://rule/%00%ff"}}']
    for line in lines:
        server.feed_line(line)
    replies = [json.loads(x) for x in out.getvalue().decode("utf-8").splitlines()]
    assert len(replies) == len(lines)
    assert all("error" in r or isinstance(r, list) for r in replies)
    for args in ([1], "x", {"path": 7}, {"path": "a\0b"}, {"path": "x" * 5000}, {"path": "views.py", "cursor": "!!"},
                 {"path": "views.py", "limit": True}, {"path": "views.py", "limit": 10 ** 30},
                 {"path": "file://evil.example/share/x"}, {"path": "views.py", "nope": 1}):
        assert _error_of(server.call_tool("scan_path", args))["code"] == "invalid_arguments", args
    assert _error_of(server.call_tool("explain_rule", {"rule_id": "x" * 200_000}))["code"] == "unknown_rule"
    assert _error_of(server.call_tool("scan_snippet", {"code": "x", "language": "y" * 5000}))["code"] == "invalid_arguments"
    assert server.handle({"jsonrpc": "2.0", "id": 9, "method": "ping"})["result"] == {}
