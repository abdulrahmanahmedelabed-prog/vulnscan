"""The language server (vulnscan/lsp.py), driven by real LSP messages over stdio.

The project under test (tests/data/lsp/project) has a cross-file Python flow: views.py reads request.args and passes
it to helpers.run_backup(), which builds an os.system() command (vulnerable); its twin passes the value through
run_backup_safely(), which quotes it with shlex.quote() (safe, must not be reported).
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
import time

import pytest

from vulnscan.i18n import translated
from vulnscan.lsp import (MSG, MessageReader, ParseFailure, encode_message, line_range, path_to_uri,
                          suppression_text, uri_to_path)
from vulnscan.model import Finding
from vulnscan.scanner import SUPPRESS

ROOT = pathlib.Path(__file__).resolve().parent.parent
PROJECT = ROOT / "tests" / "data" / "lsp" / "project"
TIMEOUT = 60


# ------------------------------------------------------------------ framing (unit)

def test_two_messages_in_one_read():
    r = MessageReader()
    data = encode_message({"jsonrpc": "2.0", "id": 1, "method": "a"}) + encode_message({"jsonrpc": "2.0", "method": "b"})
    msgs = r.feed(data)
    assert [m.get("method") for m in msgs] == ["a", "b"]


def test_partial_reads_byte_by_byte():
    r = MessageReader()
    data = encode_message({"jsonrpc": "2.0", "id": 7, "method": "x", "params": {"t": "كاشِف ✓"}})
    got = []
    for i in range(len(data)):
        got += r.feed(data[i:i + 1])
        if i < len(data) - 1:
            assert not got
    assert got == [{"jsonrpc": "2.0", "id": 7, "method": "x", "params": {"t": "كاشِف ✓"}}]


def test_split_across_header_and_body_and_extra_headers():
    r = MessageReader()
    body = json.dumps({"jsonrpc": "2.0", "method": "m"}).encode()
    frame = b"Content-Type: application/vscode-jsonrpc; charset=utf-8\r\ncontent-length: " + \
        str(len(body)).encode() + b"\r\n\r\n" + body
    assert r.feed(frame[:10]) == []
    assert r.feed(frame[10:-3]) == []
    assert r.feed(frame[-3:] + frame[:5]) == [{"jsonrpc": "2.0", "method": "m"}]
    assert r.feed(frame[5:]) == [{"jsonrpc": "2.0", "method": "m"}]


def test_bad_frames_recover():
    r = MessageReader()
    good = encode_message({"jsonrpc": "2.0", "method": "ok"})
    out = r.feed(b"Content-Length: 5\r\n\r\n{bad}" + b"X-Foo: 1\r\n\r\n" + good)
    assert isinstance(out[0], ParseFailure) and isinstance(out[1], ParseFailure)
    assert out[2] == {"jsonrpc": "2.0", "method": "ok"}
    assert isinstance(r.feed(b"x" * 10000)[0], ParseFailure)          # garbage without any header end


# ------------------------------------------------------------------ helpers (unit)

def test_uri_roundtrip(tmp_path):
    p = tmp_path / "dir with space" / "ملف.py"
    uri = path_to_uri(p)
    assert uri.startswith("file://") and "%20" in uri
    assert os.path.normcase(str(uri_to_path(uri))) == os.path.normcase(str(p))
    assert uri_to_path("untitled:Untitled-1") is None
    assert uri_to_path(None) is None


def test_line_range_trims_and_counts_utf16():
    lines = ["x", "    a = '😀' + b   ", ""]
    assert line_range(lines, 2) == {"start": {"line": 1, "character": 4}, "end": {"line": 1, "character": 16}}
    assert line_range(lines, 0)["start"]["line"] == 0          # file-level finding
    assert line_range(lines, 99)["start"] == {"line": 98, "character": 0}


@pytest.mark.parametrize("name,line,expected", [
    ("a.py", "os.system(cmd)", "  # vulnscan: ignore"),
    ("a.js", "eval(x);", " // vulnscan: ignore"),
    ("A.java", "stmt.execute(q);", " // vulnscan: ignore"),
    ("q.sql", "EXECUTE IMMEDIATE v;", " -- vulnscan: ignore"),
    ("p.pkb", "EXECUTE IMMEDIATE v;", " -- vulnscan: ignore"),
    ("i.html", "<script src=x></script>", " <!-- vulnscan: ignore -->"),
    ("c.yml", "password: hunter2", " # vulnscan: ignore"),
])
def test_suppression_comment_is_honoured_by_scanner(name, line, expected):
    text = suppression_text(pathlib.Path(name), line)
    assert text == expected
    assert SUPPRESS.search(line + text)


@pytest.mark.parametrize("name,line", [
    ("a.py", "x = 1  # nosec"),                      # already suppressed
    ("a.py", "cmd = 'a' + \\"),                      # continuation: a comment would break the line
    ("app.properties", "password=secret"),           # no inline comments in .properties: it would become the value
    ("Dockerfile", "RUN curl x | sh"),
    ("x.json", "\"k\": 1"),
    ("v.php", "<?php eval($x); ?>"),
    ("c.tsx", "<div dangerouslySetInnerHTML={{__html: x}} />"),
])
def test_no_suppression_where_a_comment_would_change_the_file(name, line):
    assert suppression_text(pathlib.Path(name), line) is None


def test_messages_have_english():
    assert all(translated(v) for v in MSG.values())


# ------------------------------------------------------------------ end to end over stdio

class Client:
    """A minimal LSP client: frames requests, collects notifications, answers the server's own requests."""

    def __init__(self, *args: str, caps: dict | None = None):
        env = dict(os.environ, PYTHONPATH=str(ROOT) + os.pathsep + os.environ.get("PYTHONPATH", ""))
        self.proc = subprocess.Popen([sys.executable, "-m", "vulnscan", "lsp", *args],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     cwd=str(ROOT), env=env)
        self.inbox: queue.Queue = queue.Queue()
        self.notes: list[dict] = []
        self.server_requests: list[dict] = []
        self._id = 0
        self._lock = threading.Lock()
        threading.Thread(target=self._read, daemon=True).start()
        threading.Thread(target=self._drain_stderr, daemon=True).start()
        self.stderr: list[str] = []

    def _drain_stderr(self):
        for line in self.proc.stderr:
            self.stderr.append(line.decode("utf-8", "replace"))

    def _read(self):
        reader = MessageReader()
        while True:
            chunk = self.proc.stdout.read1(4096)
            if not chunk:
                self.inbox.put(None)
                return
            for m in reader.feed(chunk):
                if isinstance(m, dict) and "method" in m and "id" in m:          # server -> client request
                    self.server_requests.append(m)
                    result = None
                    if m["method"] == "workspace/configuration":
                        result = [None for _ in m["params"]["items"]]
                    elif m["method"] == "window/showDocument":
                        result = {"success": True}
                    self.write({"jsonrpc": "2.0", "id": m["id"], "result": result})
                self.inbox.put(m)

    def write(self, msg):
        with self._lock:
            self.proc.stdin.write(encode_message(msg))
            self.proc.stdin.flush()

    def raw(self, data: bytes):
        with self._lock:
            self.proc.stdin.write(data)
            self.proc.stdin.flush()

    def notify(self, method, params=None):
        self.write({"jsonrpc": "2.0", "method": method, "params": params})

    def request(self, method, params=None, timeout=TIMEOUT):
        self._id += 1
        mid = self._id
        self.write({"jsonrpc": "2.0", "id": mid, "method": method, "params": params})
        return self.wait(lambda m: m.get("id") == mid and "method" not in m, timeout)

    def wait(self, pred, timeout=TIMEOUT):
        end = time.monotonic() + timeout
        for m in self.notes:                               # already received
            if pred(m):
                self.notes.remove(m)
                return m
        while time.monotonic() < end:
            try:
                m = self.inbox.get(timeout=max(0.01, end - time.monotonic()))
            except queue.Empty:
                break
            if m is None:
                raise AssertionError("server closed its output\n" + "".join(self.stderr))
            if pred(m):
                return m
            self.notes.append(m)
        raise AssertionError("timed out waiting for a message\n" + "".join(self.stderr[-30:]))

    def diagnostics(self, uri, pred=lambda d: True, timeout=TIMEOUT):
        msg = self.wait(lambda m: m.get("method") == "textDocument/publishDiagnostics"
                        and m["params"]["uri"] == uri and pred(m["params"]["diagnostics"]), timeout)
        return msg["params"]["diagnostics"]

    def close(self):
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.wait(10)
        for s in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
            try:
                s.close()
            except OSError:
                pass


@pytest.fixture
def project(tmp_path):
    dest = tmp_path / "proj"
    shutil.copytree(PROJECT, dest)
    return dest


@pytest.fixture
def client():
    c = Client("--stdio", "--debounce", "0.05")
    yield c
    c.close()


def _init(c: Client, root: pathlib.Path, options: dict | None = None):
    caps = {"window": {"showDocument": {"support": True}, "workDoneProgress": True},
            "workspace": {"configuration": True, "workspaceFolders": True},
            "textDocument": {"publishDiagnostics": {"relatedInformation": True}}}
    res = c.request("initialize", {"processId": os.getpid(), "rootUri": path_to_uri(root),
                                   "workspaceFolders": [{"uri": path_to_uri(root), "name": root.name}],
                                   "capabilities": caps, "initializationOptions": options or {}})
    c.notify("initialized", {})
    return res


def _open(c: Client, path: pathlib.Path):
    c.notify("textDocument/didOpen", {"textDocument": {"uri": path_to_uri(path), "languageId": "python", "version": 1,
                                                       "text": path.read_text(encoding="utf-8")}})


def _df002(diags):
    return [d for d in diags if d["code"] == "DF002"]


def test_initialize_result(client, project):
    res = _init(client, project)["result"]
    caps = res["capabilities"]
    assert res["serverInfo"]["name"] == "Kashif"
    assert caps["textDocumentSync"]["openClose"] and caps["textDocumentSync"]["save"] is not None
    assert caps["hoverProvider"] is True
    assert "quickfix" in caps["codeActionProvider"]["codeActionKinds"]
    assert set(caps["executeCommandProvider"]["commands"]) >= {"kashif.server.addToBaseline", "kashif.server.openCwe"}
    assert caps["workspace"]["workspaceFolders"]["supported"] is True
    assert client.request("shutdown")["result"] is None
    client.notify("exit")
    assert client.proc.wait(20) == 0


def test_diagnostics_hover_code_actions_and_suppress(client, project):
    _init(client, project)
    views = project / "views.py"
    helpers = project / "helpers.py"
    uri = path_to_uri(views)
    _open(client, views)
    diags = client.diagnostics(uri, lambda ds: bool(_df002(ds)))

    # the vulnerable call (line 11) is reported, with the full trail; its sanitized twin (line 18) is not
    [d] = _df002(diags)
    assert d["range"]["start"] == {"line": 10, "character": 4}
    assert d["range"]["end"]["line"] == 10
    assert d["severity"] == 1 and d["source"] == "Kashif"
    assert d["codeDescription"]["href"] == "https://cwe.mitre.org/data/definitions/78.html"
    assert "os.system" in d["message"] and "argument list" in d["message"]          # English title + remediation
    assert isinstance(d["data"], str) and ":" in d["data"]                          # the fingerprint
    rel = d["relatedInformation"]
    assert [r["location"]["range"]["start"]["line"] for r in rel] == [9, 10, 5]
    assert rel[-1]["location"]["uri"] == path_to_uri(helpers) and "os.system" in rel[-1]["message"]
    assert not [x for x in diags if x["range"]["start"]["line"] == 17 and x["code"].startswith("DF")]

    # the pattern finding in the other file is published as well (whole-project scan)
    hd = client.diagnostics(path_to_uri(helpers), lambda ds: any(x["code"] == "EXE004" for x in ds))
    assert all(x["range"]["start"]["line"] != 9 for x in hd)                          # shlex.quote() twin is clean

    # hover
    hov = client.request("textDocument/hover", {"textDocument": {"uri": uri}, "position": {"line": 10, "character": 6}})
    text = hov["result"]["contents"]["value"]
    assert hov["result"]["contents"]["kind"] == "markdown"
    assert "CWE-78" in text and "Data-flow trail" in text and "Remediation" in text and "helpers.py:6" in text
    assert client.request("textDocument/hover", {"textDocument": {"uri": uri},
                                                 "position": {"line": 2, "character": 0}})["result"] is None

    # code actions
    acts = client.request("textDocument/codeAction", {
        "textDocument": {"uri": uri}, "range": d["range"], "context": {"diagnostics": [d]}})["result"]
    titles = [a["title"] for a in acts]
    assert any("Suppress this finding" in t for t in titles)
    assert any("Add to baseline" in t for t in titles)
    assert any("Open CWE" in t for t in titles)
    sup = next(a for a in acts if "Suppress" in a["title"])
    [edit] = sup["edit"]["changes"][uri]
    assert edit["range"]["start"]["line"] == 10 and edit["newText"] == "  # vulnscan: ignore"

    # Open CWE asks the editor to open the page
    cwe = next(a for a in acts if "Open CWE" in a["title"])["command"]
    client.request("workspace/executeCommand", {"command": cwe["command"], "arguments": cwe["arguments"]})
    show = client.wait(lambda m: m.get("method") == "window/showDocument")
    assert show["params"] == {"uri": "https://cwe.mitre.org/data/definitions/78.html", "external": True}

    # apply the suppression edit the way an editor does, then save: the diagnostic goes away
    lines = views.read_text(encoding="utf-8").split("\n")
    ln = lines[10]
    lines[10] = ln[:edit["range"]["start"]["character"]] + edit["newText"] + ln[edit["range"]["end"]["character"]:]
    new_text = "\n".join(lines)
    views.write_text(new_text, encoding="utf-8")
    client.notify("textDocument/didChange", {"textDocument": {"uri": uri, "version": 2},
                                             "contentChanges": [{"text": new_text}]})
    client.notify("textDocument/didSave", {"textDocument": {"uri": uri}})
    after = client.diagnostics(uri, lambda ds: not _df002(ds))
    assert not _df002(after)

    assert client.request("shutdown")["result"] is None
    client.notify("exit")
    assert client.proc.wait(20) == 0


def test_add_to_baseline_and_settings(client, project):
    _init(client, project, {"kashif": {"minSeverity": "low"}})
    helpers = project / "helpers.py"
    huri = path_to_uri(helpers)
    _open(client, helpers)
    hd = client.diagnostics(huri, lambda ds: any(x["code"] == "EXE004" for x in ds))
    exe = next(x for x in hd if x["code"] == "EXE004")
    # minSeverity=low hides the info-level VQL findings in views.py
    vd = client.diagnostics(path_to_uri(project / "views.py"), lambda ds: bool(ds))
    assert all(x["severity"] != 4 for x in vd)

    acts = client.request("textDocument/codeAction", {"textDocument": {"uri": huri}, "range": exe["range"],
                                                      "context": {"diagnostics": [exe]}})["result"]
    cmd = next(a for a in acts if "Add to baseline" in a["title"])["command"]
    res = client.request("workspace/executeCommand", {"command": cmd["command"], "arguments": cmd["arguments"]})
    assert res["result"]["added"] is True
    base = project / ".vulnscan-baseline.json"
    data = json.loads(base.read_text(encoding="utf-8"))
    assert data["schema"] == "vulnscan-baseline/1" and data["fingerprints"][0]["fp"] == exe["data"]
    client.diagnostics(huri, lambda ds: not any(x["code"] == "EXE004" for x in ds))
    again = client.request("workspace/executeCommand", {"command": cmd["command"], "arguments": cmd["arguments"]})
    assert again["result"]["added"] is False

    # the CLI honours the baseline the editor wrote
    from vulnscan.cli import main
    assert main([str(project), "--no-deps", "--no-external", "--baseline", str(base), "-f", "json", "-o",
                 str(project.parent / "r.json")]) == 0
    rules = {f["rule_id"] for f in json.loads((project.parent / "r.json").read_text(encoding="utf-8"))["findings"]}
    assert "EXE004" not in rules and "DF002" in rules

    # language switch republishes in Arabic
    client.notify("workspace/didChangeConfiguration", {"settings": {"kashif": {"language": "ar"}}})
    vd = client.diagnostics(path_to_uri(project / "views.py"),
                            lambda ds: any(x["code"] == "DF002" and "بيانات" in x["message"] for x in ds))
    assert vd


def test_protocol_errors_do_not_crash(client, project):
    # a request before initialize
    early = client.request("textDocument/hover", {"textDocument": {"uri": "file:///x.py"}, "position": {"line": 0,
                                                                                                         "character": 0}})
    assert early["error"]["code"] == -32002
    _init(client, project)
    # malformed JSON gets a Parse error and the server keeps going
    client.raw(b"Content-Length: 9\r\n\r\n{not json")
    perr = client.wait(lambda m: m.get("error", {}).get("code") == -32700)
    assert perr["id"] is None
    assert client.request("no/such/method", {})["error"]["code"] == -32601
    assert client.request("workspace/executeCommand", {"command": "kashif.server.openCwe",
                                                       "arguments": ["https://evil.example/"]})["error"]["code"] == -32602
    assert client.request("textDocument/codeAction", {"textDocument": {"uri": "untitled:1"}})["result"] == []
    assert client.request("textDocument/hover", {"textDocument": {"uri": path_to_uri(project / "views.py")},
                                                 "position": "bad"})["error"]["code"] == -32602
    client.notify("textDocument/didOpen", {"textDocument": 5})                 # ignored, logged
    client.write({"jsonrpc": "2.0", "id": {"bad": 1}, "method": "x"})         # invalid id
    assert client.wait(lambda m: m.get("error", {}).get("code") == -32600)
    assert client.request("shutdown")["result"] is None
    assert client.request("textDocument/hover", {})["error"]["code"] == -32600   # after shutdown
    client.notify("exit")
    assert client.proc.wait(20) == 0


def test_exit_without_shutdown_is_an_error(client, project):
    _init(client, project)
    client.notify("exit")
    assert client.proc.wait(20) == 1


def test_baseline_refuses_to_clobber_foreign_json(tmp_path):
    from vulnscan.lsp import add_to_baseline
    p = tmp_path / "package.json"
    p.write_text('{"name": "x"}', encoding="utf-8")
    f = Finding("A1", "high", "t", "ت", "a.py", 1, "x", "y")
    with pytest.raises(ValueError):
        add_to_baseline(p, f)
    assert json.loads(p.read_text(encoding="utf-8")) == {"name": "x"}
    q = tmp_path / "b.json"
    assert add_to_baseline(q, f) is True and add_to_baseline(q, f) is False


def test_stale_scan_is_discarded_and_server_stays_responsive(tmp_path):
    """A save during a scan makes that scan stale: its results are never published; requests are answered meanwhile."""
    import io
    from vulnscan.lsp import KashifLanguageServer

    class Out(io.BytesIO):
        def __init__(self):
            super().__init__()
            self.lock = threading.Lock()

    (tmp_path / "a.py").write_text("x = 1\ny = 2\n", encoding="utf-8")
    out = Out()
    srv = KashifLanguageServer(out, debounce=0)
    started, release = threading.Event(), threading.Event()
    calls = []

    def fake_scan(folder, settings):
        calls.append(1)
        if len(calls) == 1:
            started.set()
            release.wait(10)
            rule = "OLD1"
        else:
            rule = "NEW1"
        f = Finding(rule, "high", "t", "ت", "a.py", 2, "y = 2", "")
        f.extra["fp_index"] = 0
        return [f]

    srv._scan = fake_scan
    uri = path_to_uri(tmp_path / "a.py")
    srv.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"rootUri": path_to_uri(tmp_path), "capabilities": {}}})
    srv.handle({"jsonrpc": "2.0", "method": "initialized", "params": {}})
    srv.handle({"jsonrpc": "2.0", "method": "textDocument/didOpen",
                "params": {"textDocument": {"uri": uri, "text": "x = 1\ny = 2\n", "version": 1}}})
    assert started.wait(10)
    srv.handle({"jsonrpc": "2.0", "method": "textDocument/didSave", "params": {"textDocument": {"uri": uri}}})
    srv.handle({"jsonrpc": "2.0", "id": 2, "method": "textDocument/hover",
                "params": {"textDocument": {"uri": uri}, "position": {"line": 1, "character": 0}}})
    release.set()
    end = time.monotonic() + 10
    while time.monotonic() < end and b"NEW1" not in out.getvalue():
        time.sleep(0.02)
    msgs = MessageReader().feed(out.getvalue())
    assert any(m.get("id") == 2 and "result" in m for m in msgs)            # answered while the scan ran
    pubs = [m for m in msgs if m.get("method") == "textDocument/publishDiagnostics"]
    assert pubs and all(d["code"] == "NEW1" for m in pubs for d in m["params"]["diagnostics"])
    assert len(calls) == 2
    srv.handle({"jsonrpc": "2.0", "id": 3, "method": "shutdown"})


# ------------------------------------------------------------------ adversarial regressions

def _server(tmp_path, findings, debounce=0.0):
    """An in-process server whose scan returns ``findings`` (rule, file, line) and an output buffer to read."""
    import io
    from vulnscan.lsp import KashifLanguageServer

    out = io.BytesIO()
    srv = KashifLanguageServer(out, debounce=debounce)

    def fake_scan(folder, settings):
        res = []
        for i, (rule, file, line) in enumerate(findings):
            f = Finding(rule, "high", "t", "ت", file, line, "", "")
            f.extra["fp_index"] = i
            res.append(f)
        return res

    srv._scan = fake_scan
    srv.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"rootUri": path_to_uri(tmp_path), "capabilities": {}}})
    srv.handle({"jsonrpc": "2.0", "method": "initialized", "params": {}})
    return srv, out


def _msgs(out):
    return MessageReader().feed(out.getvalue())


def _wait_for(out, pred, timeout=10):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if any(pred(m) for m in _msgs(out) if isinstance(m, dict)):
            return True
        time.sleep(0.02)
    return False


def test_junk_glued_before_a_frame_does_not_cost_that_frame():
    r = MessageReader()
    good = encode_message({"jsonrpc": "2.0", "id": 2, "method": "ok"})
    nxt = encode_message({"jsonrpc": "2.0", "id": 3, "method": "next"})
    out = r.feed(b"stray output without newline" + good + nxt)
    assert [m.get("id") for m in out if isinstance(m, dict)] == [2, 3]
    out = r.feed(b"Content-Type: x\r\n\r\n" + nxt)                      # a header without a length
    assert isinstance(out[0], ParseFailure) and out[1] == {"jsonrpc": "2.0", "id": 3, "method": "next"}


def test_array_params_are_invalid_params_not_internal_error(tmp_path):
    srv, out = _server(tmp_path, [])
    srv.handle({"jsonrpc": "2.0", "id": 5, "method": "textDocument/codeAction", "params": [1, 2]})
    [reply] = [m for m in _msgs(out) if m.get("id") == 5]
    assert reply["error"]["code"] == -32602
    srv.handle({"jsonrpc": "2.0", "id": 6, "method": "shutdown"})


@pytest.mark.parametrize("ext,src,inside,outside", [
    # JS template literal used for SQL: line 0 ends inside the literal; the closing line does not
    (".js", "db.query(`SELECT * FROM t\n  WHERE id = ${req.query.id}`);\nx(`a`); // `\n", {0}, {1, 2}),
    (".ts", "const q = `a ${f({a: `b\nc`})} d\ne`;\nconst z = 1;\n", {0, 1}, {2, 3}),
    # Java text block: after the opening """ even a comment is a compile error
    (".java", 'st.executeQuery("""\n    SELECT 1\n    """);\nrun("x"); // """\n', {0, 1}, {2, 3}),
    (".go", "q := `SELECT\n x` + id\ny := '`'\n", {0}, {1, 2}),
    (".php", "<?php\n$a = <<<EOT\nhi $x\n  EOT;\nsystem($a); # '\n$b = 'multi\nline';\n", {1, 2, 5}, {0, 3, 4, 6}),
    (".cs", 'var a = @"x""\ny";\nvar b = $"""\n q\n """;\nvar c = "s";\n', {0, 2, 3}, {1, 4, 5}),
    (".rs", "fn f<'a>(x: &'a str) {\n let s = r#\"a\n\"b\"#;\n let t = \"m\nn\";\n}\n", {1, 3}, {0, 2, 4, 5}),
    (".cpp", 'auto s = R"x(a\nb)x";\nint y = 1; // "\n', {0}, {1, 2}),
])
def test_multiline_string_lines_found_for_c_family_and_php(ext, src, inside, outside):
    from vulnscan.lsp import _clike_multiline_string_lines
    got = _clike_multiline_string_lines(src, ext)
    assert inside <= got and not (outside & got)


def test_no_suppress_quick_fix_inside_a_template_literal(tmp_path):
    src = ("const cp = require('child_process');\n"
           "db.query(`SELECT * FROM t\n  WHERE id = ${req.query.id}`);\n"
           "cp.exec('ls ' + req.query.x);\n")
    (tmp_path / "a.js").write_text(src, encoding="utf-8")
    srv, out = _server(tmp_path, [("SQL1", "a.js", 2), ("CMD1", "a.js", 4)])
    uri = path_to_uri(tmp_path / "a.js")
    srv.handle({"jsonrpc": "2.0", "method": "textDocument/didOpen",
                "params": {"textDocument": {"uri": uri, "text": src, "version": 1}}})
    assert _wait_for(out, lambda m: m.get("method") == "textDocument/publishDiagnostics")

    def actions(line, mid):
        srv.handle({"jsonrpc": "2.0", "id": mid, "method": "textDocument/codeAction",
                    "params": {"textDocument": {"uri": uri}, "range": {"start": {"line": line, "character": 0},
                                                                       "end": {"line": line, "character": 0}},
                               "context": {"diagnostics": []}}})
        return next(m for m in _msgs(out) if m.get("id") == mid)["result"]

    in_literal = actions(1, 10)
    assert in_literal and not [a for a in in_literal if "edit" in a]     # baseline/CWE still offered, no comment
    plain = actions(3, 11)
    [edit] = [a for a in plain if "edit" in a][0]["edit"]["changes"][uri]
    assert edit["newText"] == " // vulnscan: ignore" and edit["range"]["start"]["line"] == 3
    srv.handle({"jsonrpc": "2.0", "id": 12, "method": "shutdown"})


def test_watched_file_events_ignore_skipped_dirs_and_drop_deleted_lone_files(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "a.py").write_text("x = 1\n", encoding="utf-8")
    srv, out = _server(proj, [("R1", "a.py", 1)])
    uri = path_to_uri(proj / "a.py")
    srv.handle({"jsonrpc": "2.0", "method": "textDocument/didOpen",
                "params": {"textDocument": {"uri": uri, "text": "x = 1\n", "version": 1}}})
    assert _wait_for(out, lambda m: m.get("method") == "textDocument/publishDiagnostics")
    key = next(iter(srv.folders))
    gen = srv.folders[key].gen
    srv.handle({"jsonrpc": "2.0", "method": "workspace/didChangeWatchedFiles", "params": {"changes": [
        {"uri": path_to_uri(proj / ".git" / "index.lock"), "type": 3},
        {"uri": path_to_uri(proj / "node_modules" / "x" / "i.js"), "type": 3}]}})
    assert srv.folders[key].gen == gen                                     # git/npm noise: no re-scan
    srv.handle({"jsonrpc": "2.0", "method": "workspace/didChangeWatchedFiles",
                "params": {"changes": [{"uri": path_to_uri(proj / "b.py"), "type": 3}]}})
    assert srv.folders[key].gen == gen + 1                                 # a real deletion: re-scan

    lone = tmp_path / "outside.py"
    lone.write_text("y = 2\n", encoding="utf-8")
    luri = path_to_uri(lone)
    srv._scan = lambda folder, settings: [Finding("R2", "high", "t", "ت", "outside.py", 1, "", "")]
    srv.handle({"jsonrpc": "2.0", "method": "textDocument/didOpen",
                "params": {"textDocument": {"uri": luri, "text": "y = 2\n", "version": 1}}})
    assert _wait_for(out, lambda m: m.get("method") == "textDocument/publishDiagnostics"
                     and m["params"]["uri"] == luri and m["params"]["diagnostics"])
    lone.unlink()
    out.seek(0)
    out.truncate()
    srv.handle({"jsonrpc": "2.0", "method": "workspace/didChangeWatchedFiles",
                "params": {"changes": [{"uri": luri, "type": 3}]}})
    assert _wait_for(out, lambda m: m.get("method") == "textDocument/publishDiagnostics"
                     and m["params"] == {"uri": luri, "diagnostics": []})
    assert all(not f.is_file for f in srv.folders.values())
    srv.handle({"jsonrpc": "2.0", "id": 9, "method": "shutdown"})


def test_added_workspace_folder_absorbs_lone_files_and_flat_settings(tmp_path):
    from vulnscan.lsp import KashifLanguageServer, Settings
    s = Settings()
    assert s.update({"kashif.minSeverity": "high", "kashif.language": "ar", "other.x": 1}) == ["min_severity",
                                                                                             "language"]
    import io
    srv = KashifLanguageServer(io.BytesIO(), debounce=60)                  # no scan runs during this test
    srv.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"capabilities": {}}})
    srv.handle({"jsonrpc": "2.0", "method": "initialized", "params": {}})
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    srv.handle({"jsonrpc": "2.0", "method": "textDocument/didOpen",
                "params": {"textDocument": {"uri": path_to_uri(tmp_path / "a.py"), "text": "x = 1\n"}}})
    assert [f.is_file for f in srv.folders.values()] == [True]
    srv.handle({"jsonrpc": "2.0", "method": "workspace/didChangeWorkspaceFolders",
                "params": {"event": {"added": [{"uri": path_to_uri(tmp_path), "name": "p"}], "removed": []}}})
    assert [f.is_file for f in srv.folders.values()] == [False]            # one scan root, no duplicate results
    srv.handle({"jsonrpc": "2.0", "id": 2, "method": "shutdown"})
