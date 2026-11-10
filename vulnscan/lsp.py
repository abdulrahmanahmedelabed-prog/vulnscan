"""Language Server Protocol (LSP 3.17) server: Kashif inside any editor.

One implementation serves VS Code, JetBrains IDEs (through LSP4IJ), Neovim, Helix, Zed, Sublime Text (LSP package)
and Emacs (eglot): ``vulnscan lsp`` speaks JSON-RPC 2.0 over stdio with ``Content-Length`` framing.

What it does
------------
* When a document is opened or saved (debounced), the WHOLE workspace folder that contains it is scanned with
  ``scan_path`` (so cross-file data flow is found exactly as on the command line), in a worker thread so the
  server keeps answering hover and code-action requests. A scan overtaken by a newer save is thrown away.
* Results are cached per folder and published as ``textDocument/publishDiagnostics``; only files whose
  diagnostics changed are re-published. Each diagnostic carries the rule id, a CWE link, the data-flow trail as
  ``relatedInformation`` and the finding's stable fingerprint as ``data``.
* Hover on a flagged line shows title, CWE, remediation and trail; code actions offer "Suppress this finding"
  (the ``vulnscan: ignore`` comment the scanner honours), "Add to baseline" and "Open CWE".
* Offline by design: no OSV.dev query, no external tools, no jadx.

Settings (``initializationOptions`` or ``workspace/didChangeConfiguration``, section ``kashif``):
``minSeverity`` (info), ``audit`` (false), ``exclude`` ([] of globs), ``baseline`` (".vulnscan-baseline.json",
relative to the folder), ``language`` ("en" or "ar").

Standard library only. Logs go to stderr; stdout carries the protocol and nothing else.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import pathlib
import re
import sys
import threading
import time
import tokenize
import traceback
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from . import __version__
from .baseline import SCHEMA as BASELINE_SCHEMA, load_baseline
from .i18n import localize, to_en
from .model import SEVERITIES, SEVERITY_AR, SEVERITY_EN, SEVERITY_RANK, Finding, assign_fingerprints
from .plsql_frontend import PLSQL_EXTS
from .scanner import SKIP_DIRS, SUPPRESS, scan_path

# ------------------------------------------------------------------ JSON-RPC constants

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603
SERVER_NOT_INITIALIZED = -32002

# LSP DiagnosticSeverity: Error=1, Warning=2, Information=3, Hint=4
DIAG_SEVERITY = {"critical": 1, "high": 1, "medium": 2, "low": 3, "info": 4}

SOURCE = "Kashif"
DEFAULT_BASELINE = ".vulnscan-baseline.json"
SUPPRESS_MARK = "vulnscan: ignore"

CMD_SCAN = "kashif.server.scanWorkspace"
CMD_BASELINE = "kashif.server.addToBaseline"
CMD_CWE = "kashif.server.openCwe"
COMMANDS = (CMD_SCAN, CMD_BASELINE, CMD_CWE)

# User-facing text. Arabic in the source (project convention); the English is in vulnscan/i18n/cat_integrations.py.
MSG = {
    "suppress": "اكتم هذه النتيجة",
    "baseline": "أضِف إلى خط الأساس",
    "cwe": "افتح وصف الضعف في CWE",
    "severity": "الخطورة",
    "rule": "القاعدة",
    "remediation": "المعالجة",
    "trail": "مسار البيانات",
    "baseline_added": "أُضيفت النتيجة إلى خط الأساس ولن تظهر بعد الآن.",
    "baseline_known": "النتيجة موجودة في خط الأساس مسبقًا.",
    "baseline_failed": "تعذّر حفظ خط الأساس؛ تحقّق من أن الملف قابل للكتابة وأنه JSON صالح.",
    "finding_gone": "لم تعد هذه النتيجة موجودة؛ أعد الفحص ثم حاول مجددًا.",
    "open_cwe": "افتح هذا الرابط لقراءة وصف الضعف:",
}


def log(*parts) -> None:
    """Diagnostics for the editor's server log (stderr). Never stdout: that is the protocol channel."""
    try:
        print("[kashif-lsp]", *parts, file=sys.stderr, flush=True)
    except (OSError, ValueError):
        pass


# ------------------------------------------------------------------ framing

class ParseFailure:
    """A frame that could not be decoded; the server answers it with a JSON-RPC Parse error."""

    def __init__(self, reason: str):
        self.reason = reason

    def __repr__(self) -> str:
        return f"ParseFailure({self.reason!r})"


_CONTENT_LENGTH = re.compile(r"content-length[ \t]*:[ \t]*(\d+)[ \t]*(?:\r\n|$)", re.I)


class MessageReader:
    """Incremental ``Content-Length`` frame decoder.

    ``feed`` accepts any chunk of bytes: several messages in one read, a message split over many reads, a header
    cut in the middle. It returns the complete messages (decoded JSON values) and ParseFailure markers."""

    MAX_BODY = 64 * 1024 * 1024
    MAX_HEADER = 8192

    def __init__(self) -> None:
        self._buf = bytearray()
        self._need: int | None = None     # body length of the frame whose header was already consumed

    def feed(self, data: bytes) -> list:
        self._buf += data
        out: list = []
        while True:
            if self._need is None:
                end = self._buf.find(b"\r\n\r\n")
                if end < 0:
                    if len(self._buf) > self.MAX_HEADER:     # garbage without a header terminator
                        self._buf.clear()
                        out.append(ParseFailure("header too long"))
                    return out
                header = bytes(self._buf[:end]).decode("ascii", "replace")
                del self._buf[:end + 4]
                # search rather than split: stray bytes glued before a header (a crashed writer, a stray print)
                # must not cost the frame that follows them as well
                m = _CONTENT_LENGTH.findall(header)
                length = int(m[-1]) if m else None
                if length is None or length < 0 or length > self.MAX_BODY:
                    out.append(ParseFailure("missing or invalid Content-Length"))
                    continue
                self._need = length
            if len(self._buf) < self._need:
                return out
            body = bytes(self._buf[:self._need])
            del self._buf[:self._need]
            self._need = None
            try:
                out.append(json.loads(body.decode("utf-8")))
            except (UnicodeDecodeError, ValueError) as e:
                out.append(ParseFailure(f"invalid JSON: {e}"))


def encode_message(msg: dict) -> bytes:
    body = json.dumps(msg, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n\r\n" + body


class RpcError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


# ------------------------------------------------------------------ helpers

def uri_to_path(uri: str) -> pathlib.Path | None:
    """file:// URI -> absolute path (handles percent-encoding and Windows drive letters); None for other schemes."""
    if not isinstance(uri, str):
        return None
    parts = urllib.parse.urlsplit(uri)
    if parts.scheme != "file":
        return None
    path = urllib.request.url2pathname(urllib.parse.unquote(parts.path))
    if parts.netloc and parts.netloc != "localhost":          # UNC share: file://server/share/x
        path = f"\\\\{parts.netloc}{path}" if os.name == "nt" else f"//{parts.netloc}{path}"
    if os.name == "nt" and re.match(r"^[\\/][A-Za-z]:", path):
        path = path[1:]
    return pathlib.Path(path)


def path_to_uri(path: pathlib.Path) -> str:
    return pathlib.Path(os.path.abspath(path)).as_uri()


def path_key(path: pathlib.Path) -> str:
    return os.path.normcase(os.path.abspath(path))


def split_lines(text: str) -> list[str]:
    """Lines as editors and Python's tokenizer count them (\\n, \\r\\n and \\r end a line)."""
    return re.split(r"\r\n|\r|\n", text)


def utf16_len(text: str) -> int:
    return len(text.encode("utf-16-le")) // 2


def line_range(lines: list[str], line: int) -> dict:
    """LSP range of a 1-based line, trimmed of surrounding whitespace (line 0 = file-level: the first line)."""
    idx = max(line, 1) - 1
    text = lines[idx] if 0 <= idx < len(lines) else ""
    start = utf16_len(text) - utf16_len(text.lstrip())
    end = utf16_len(text.rstrip())
    if end < start:
        end = start
    return {"start": {"line": idx, "character": start}, "end": {"line": idx, "character": end}}


def cwe_href(cwe: str) -> str | None:
    m = re.fullmatch(r"\s*CWE-(\d+)\s*", cwe or "", re.I)
    return f"https://cwe.mitre.org/data/definitions/{m.group(1)}.html" if m else None


_MD_SPECIAL = re.compile(r"([\\`*_\[\]<>#|])")


def md(text: str) -> str:
    return _MD_SPECIAL.sub(r"\\\1", text or "")


_HASH = {".py", ".pyw", ".pyi", ".rb", ".rake", ".gemspec", ".sh", ".bash", ".zsh", ".yaml", ".yml", ".toml", ".pl",
         ".pm", ".r", ".ps1", ".tf", ".hcl", ".nix", ".cmake"}
_SLASH = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".java", ".kt", ".kts", ".cs", ".go", ".php",
          ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx", ".rs", ".swift", ".scala", ".dart", ".groovy",
          ".gradle", ".jsonc", ".m", ".mm"}
_DASH = set(PLSQL_EXTS) | {".lua", ".hs"}
_ANGLE = {".html", ".htm", ".xhtml", ".xml", ".svg"}
_BLOCK = {".css", ".scss", ".less"}


def suppression_text(path: pathlib.Path, line_text: str) -> str | None:
    """The end-of-line comment that makes the scanner skip this line, or None where a trailing comment could change
    the meaning of the file (line continuations, PHP/JSX markup, config formats without inline comments)."""
    ext = path.suffix.lower()
    stripped = line_text.rstrip()
    if not stripped or SUPPRESS.search(line_text) or stripped.endswith("\\"):
        return None
    if ext in _HASH:
        return f"  # {SUPPRESS_MARK}" if ext in (".py", ".pyw", ".pyi") else f" # {SUPPRESS_MARK}"
    if ext in _SLASH:
        if ext == ".php" and "?>" in stripped:
            return None
        if ext in (".jsx", ".tsx") and (stripped.lstrip().startswith("<") or stripped.endswith(">")):
            return None
        return f" // {SUPPRESS_MARK}"
    if ext in _DASH:
        return f" -- {SUPPRESS_MARK}"
    if ext in _ANGLE:
        return None if "<?xml" in stripped or "--" in stripped else f" <!-- {SUPPRESS_MARK} -->"
    if ext in _BLOCK:
        return f" /* {SUPPRESS_MARK} */"
    return None


def _python_multiline_string_lines(text: str) -> set[int]:
    """0-based lines that end inside a multi-line string literal: a trailing comment there would become data."""
    inside: set[int] = set()
    try:
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            if tok.type == tokenize.STRING and tok.end[0] > tok.start[0]:
                inside.update(range(tok.start[0] - 1, tok.end[0] - 1))
            elif getattr(tokenize, "FSTRING_MIDDLE", None) == tok.type and tok.end[0] > tok.start[0]:
                inside.update(range(tok.start[0] - 1, tok.end[0] - 1))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        pass
    return inside


_JS = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
_TRIPLE = {".java", ".kt", ".kts", ".scala", ".groovy", ".gradle", ".swift", ".cs", ".dart"}
_TRIPLE_SINGLE = {".groovy", ".gradle", ".dart", ".scala"}
_CPP = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx", ".m", ".mm"}
_RUST_CHAR = re.compile(r"'(?:\\.[^']{0,8}|[^\\'\n])'")
_CPP_RAW = re.compile(r'(?<![\w])(?:u8|[uUL])?R"([^()\\\s"]{0,16})\(')
_RUST_RAW = re.compile(r'(?<![\w])b?r(#*)"')
_PHP_HEREDOC = re.compile(r"<<<[ \t]*(['\"]?)([A-Za-z_]\w*)\1[ \t]*$")


def _clike_multiline_string_lines(text: str, ext: str) -> set[int]:
    """0-based lines of a C-family / PHP file that end inside a string literal which continues on the next line
    (JS template literal, Go raw string, Java/Kotlin/C#/Swift text block, C# verbatim string, Rust and PHP strings,
    C++ and Rust raw strings, PHP heredoc). A trailing comment there would become part of the string, or, after a
    Java text block's opening delimiter, a compile error. A small lexer, deliberately conservative: when in doubt
    (a regex literal that contains a quote, say) it reports a line as inside, which only withholds the quick fix."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    js, go, php, rust, cs = ext in _JS, ext == ".go", ext == ".php", ext == ".rs", ext == ".cs"
    triple, cpp = ext in _TRIPLE, ext in _CPP
    out: set[int] = set()
    n, i, line = len(text), 0, 0
    # state: None = code; ("s", closer, multiline, escapes) = string; "block" = /* */; "line" = // comment;
    # ("here", ident) = PHP heredoc/nowdoc
    state = None
    braces: list[int] = []          # JS: open "{" count of each enclosing template ${ ... } expression
    while i < n:
        ch = text[i]
        if ch == "\n":
            if isinstance(state, tuple):
                if state[0] == "here":
                    out.add(line)
                    nxt = text[i + 1:i + 1 + 256].lstrip(" \t")
                    ident = state[1]
                    if nxt.startswith(ident) and not (nxt[len(ident):len(ident) + 1].isalnum()
                                                      or nxt[len(ident):len(ident) + 1] == "_"):
                        state = None
                        i = text.index(ident, i + 1) + len(ident)
                        line += 1
                        continue
                elif state[2]:
                    out.add(line)
                else:
                    state = None                # unterminated one-line string: recover at the line end
            elif state == "line":
                state = None
            elif state == "block":
                pass
            line += 1
            i += 1
            continue
        if state is None:
            two = text[i:i + 2]
            if two == "//" or (php and ch == "#" and text[i:i + 2] != "#["):
                state = "line"
                i += 1
                continue
            if two == "/*":
                state = "block"
                i += 2
                continue
            if php and text.startswith("<<<", i):
                m = _PHP_HEREDOC.match(text, i, text.find("\n", i) if "\n" in text[i:] else n)
                if m:
                    state = ("here", m.group(2))
                    i = m.end()
                    continue
            if cpp and ch in "uULR":
                m = _CPP_RAW.match(text, i)
                if m and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")):
                    state = ("s", ")" + m.group(1) + '"', True, False)
                    i = m.end()
                    continue
            if rust and ch in "br":
                m = _RUST_RAW.match(text, i)
                if m and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")):
                    state = ("s", '"' + m.group(1), True, False)
                    i = m.end()
                    continue
            if cs and ch in "@$":
                m = re.match(r'(?:\$@|@\$|@)"', text[i:i + 3])
                if m:
                    state = ("s", '"', True, False)          # verbatim: "" is the escape, handled below
                    i += m.end()
                    continue
            if triple and text.startswith('"""', i):
                state = ("s", '"""', True, True)
                i += 3
                continue
            if ext in _TRIPLE_SINGLE and text.startswith("'''", i):
                state = ("s", "'''", True, True)
                i += 3
                continue
            if ch == "`" and (js or go):
                state = ("s", "`", True, js)
                i += 1
                continue
            if ch == '"':
                state = ("s", '"', rust or php, True)
                i += 1
                continue
            if ch == "'":
                if rust:
                    m = _RUST_CHAR.match(text, i)
                    i = m.end() if m else i + 1             # a lifetime ('a) is not a literal
                    continue
                state = ("s", "'", php, True)
                i += 1
                continue
            if braces:
                if ch == "{":
                    braces[-1] += 1
                elif ch == "}":
                    if braces[-1] == 0:
                        braces.pop()
                        state = ("s", "`", True, True)      # back into the template literal
                    else:
                        braces[-1] -= 1
            i += 1
            continue
        if state == "line":
            i += 1
            continue
        if state == "block":
            if text.startswith("*/", i):
                state = None
                i += 2
            else:
                i += 1
            continue
        if state[0] == "here":
            i += 1
            continue
        closer, _multi, escapes = state[1], state[2], state[3]
        if escapes and ch == "\\":
            i += 2 if text[i + 1:i + 2] != "\n" else 1
            continue
        if js and closer == "`" and text.startswith("${", i):
            braces.append(0)
            state = None
            i += 2
            continue
        if text.startswith(closer, i):
            if cs and closer == '"' and not escapes and text.startswith('""', i):
                i += 2                                      # "" inside a verbatim string
                continue
            state = None
            i += len(closer)
            continue
        i += 1
    return out


# ------------------------------------------------------------------ state

@dataclass
class Settings:
    min_severity: str = "info"
    audit: bool = False
    exclude: list[str] = field(default_factory=list)
    baseline: str = ""
    language: str = "en"

    def update(self, raw) -> list[str]:
        """Apply a settings object (``{"kashif": {...}}`` or the section itself). Returns the names that changed."""
        if not isinstance(raw, dict):
            return []
        if isinstance(raw.get("kashif"), dict):
            raw = raw["kashif"]
        elif any(isinstance(k, str) and k.startswith("kashif.") for k in raw):    # flat {"kashif.audit": true}
            raw = {k[len("kashif."):]: v for k, v in raw.items() if isinstance(k, str) and k.startswith("kashif.")}
        changed = []

        def put(name, value):
            if getattr(self, name) != value:
                setattr(self, name, value)
                changed.append(name)

        sev = raw.get("minSeverity")
        if isinstance(sev, str) and sev.lower() in SEVERITY_RANK:
            put("min_severity", sev.lower())
        if isinstance(raw.get("audit"), bool):
            put("audit", raw["audit"])
        exc = raw.get("exclude")
        if isinstance(exc, str):
            exc = [exc]
        if isinstance(exc, list):
            put("exclude", [e for e in exc if isinstance(e, str) and e.strip()])
        if isinstance(raw.get("baseline"), str):
            put("baseline", raw["baseline"].strip())
        lang = raw.get("language")
        if isinstance(lang, str) and lang.lower() in ("en", "ar"):
            put("language", lang.lower())
        return changed


@dataclass
class Folder:
    """A scan root: a workspace folder, or a lone file opened outside every workspace folder."""
    path: pathlib.Path
    is_file: bool = False
    gen: int = 0                                   # bumped by every scan request; a finished scan of an older gen is stale
    findings: list[Finding] | None = None          # every finding of the last completed scan (fingerprinted)
    published: dict[str, str] = field(default_factory=dict)        # uri -> JSON of the diagnostics last sent
    visible: dict[str, list[tuple[Finding, dict]]] = field(default_factory=dict)   # path key -> (finding, diagnostic)

    @property
    def base(self) -> pathlib.Path:
        return self.path.parent if self.is_file else self.path

    def file_of(self, finding: Finding) -> pathlib.Path:
        return self.path if self.is_file else self.path / finding.file


@dataclass
class Document:
    uri: str
    text: str
    version: int = 0


# ------------------------------------------------------------------ server

class KashifLanguageServer:
    def __init__(self, out=None, debounce: float = 0.4):
        self._out = out if out is not None else sys.stdout.buffer
        self._wlock = threading.Lock()
        self._lock = threading.RLock()
        self._cv = threading.Condition(self._lock)
        self._publish_lock = threading.Lock()
        self.debounce = debounce
        self.settings = Settings()
        self.folders: dict[str, Folder] = {}
        self.docs: dict[str, Document] = {}
        self._due: dict[str, float] = {}               # folder key -> monotonic time when its scan may start
        self._next_id = 0
        self._replies: dict = {}                       # id of a request we sent -> callback(result, error)
        self.client_caps: dict = {}
        self.status_notifications = False
        self.initialized = False
        self.shutdown_requested = False
        self.exit_code: int | None = None
        self._stopped = False
        self._worker = threading.Thread(target=self._scan_loop, name="kashif-scan", daemon=True)
        self._worker.start()

    # ---------------------------------------------------------------- transport

    def send(self, msg: dict) -> None:
        data = encode_message(msg)
        with self._wlock:
            try:
                self._out.write(data)
                self._out.flush()
            except (OSError, ValueError) as e:
                log("write failed:", e)

    def notify(self, method: str, params) -> None:
        self.send({"jsonrpc": "2.0", "method": method, "params": params})

    def request(self, method: str, params, callback=None) -> None:
        with self._lock:
            self._next_id += 1
            rid = f"kashif-{self._next_id}"
            if callback is not None:
                self._replies[rid] = callback
        self.send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})

    def handle(self, msg) -> None:
        """Dispatch one decoded message (or ParseFailure). Never raises."""
        if isinstance(msg, ParseFailure):
            log("parse error:", msg.reason)
            self.send({"jsonrpc": "2.0", "id": None, "error": {"code": PARSE_ERROR, "message": msg.reason}})
            return
        if isinstance(msg, list):          # JSON-RPC batch: LSP does not use them, but answer correctly
            if not msg:
                self.send({"jsonrpc": "2.0", "id": None, "error": {"code": INVALID_REQUEST, "message": "empty batch"}})
            for m in msg:
                self.handle(m)
            return
        if not isinstance(msg, dict):
            self.send({"jsonrpc": "2.0", "id": None, "error": {"code": INVALID_REQUEST, "message": "not an object"}})
            return
        method = msg.get("method")
        mid = msg.get("id")
        has_id = "id" in msg and (mid is None or isinstance(mid, (int, str))) and not isinstance(mid, bool)
        if method is None:                 # a response to one of our requests
            cb = self._replies.pop(mid, None) if isinstance(mid, (int, str)) else None
            if cb is not None:
                try:
                    cb(msg.get("result"), msg.get("error"))
                except Exception:          # noqa: BLE001 - a client reply must never kill the server
                    log("reply handler failed:\n" + traceback.format_exc())
            return
        if not isinstance(method, str) or ("id" in msg and not has_id):
            self.send({"jsonrpc": "2.0", "id": mid if has_id else None,
                       "error": {"code": INVALID_REQUEST, "message": "invalid request"}})
            return
        params = msg.get("params")
        if params is None:
            params = {}
        if has_id:
            self._handle_request(mid, method, params)
        else:
            self._handle_notification(method, params)

    def _handle_request(self, mid, method: str, params) -> None:
        try:
            if self.shutdown_requested and method != "shutdown":
                raise RpcError(INVALID_REQUEST, "server is shutting down")
            if not self.initialized and method != "initialize":
                raise RpcError(SERVER_NOT_INITIALIZED, "server not initialized")
            handler = self.REQUESTS.get(method)
            if handler is None:
                raise RpcError(METHOD_NOT_FOUND, f"method not found: {method}")
            if not isinstance(params, dict):            # every LSP request this server handles takes an object
                raise RpcError(INVALID_PARAMS, "params must be an object")
            result = handler(self, params)
            self.send({"jsonrpc": "2.0", "id": mid, "result": result})
        except RpcError as e:
            self.send({"jsonrpc": "2.0", "id": mid, "error": {"code": e.code, "message": e.message}})
        except Exception as e:             # noqa: BLE001 - report, never crash
            log(f"{method} failed:\n" + traceback.format_exc())
            self.send({"jsonrpc": "2.0", "id": mid,
                       "error": {"code": INTERNAL_ERROR, "message": f"{type(e).__name__}: {e}"}})

    def _handle_notification(self, method: str, params) -> None:
        if method == "exit":
            self.exit_code = 0 if self.shutdown_requested else 1
            return
        if not self.initialized or self.shutdown_requested:
            return
        handler = self.NOTIFICATIONS.get(method)
        if handler is None:
            if not method.startswith("$/"):
                log("ignored notification:", method)
            return
        if not isinstance(params, dict):
            log("ignored notification with bad params:", method)
            return
        try:
            handler(self, params)
        except Exception:                  # noqa: BLE001
            log(f"{method} failed:\n" + traceback.format_exc())

    # ---------------------------------------------------------------- lifecycle

    def on_initialize(self, params: dict):
        if self.initialized:
            raise RpcError(INVALID_REQUEST, "already initialized")
        caps = params.get("capabilities")
        self.client_caps = caps if isinstance(caps, dict) else {}
        opts = params.get("initializationOptions")
        if isinstance(opts, dict):
            self.settings.update(opts)
            self.status_notifications = bool(opts.get("statusNotifications"))
        folders = params.get("workspaceFolders")
        if isinstance(folders, list) and folders:
            for wf in folders:
                if isinstance(wf, dict):
                    self._add_folder(wf.get("uri"))
        elif isinstance(params.get("rootUri"), str):
            self._add_folder(params["rootUri"])
        elif isinstance(params.get("rootPath"), str) and params["rootPath"]:
            self._add_folder(path_to_uri(pathlib.Path(params["rootPath"])))  # nosec - the editor names its own workspace
        pid = params.get("processId")
        if isinstance(pid, int) and pid > 0 and os.name != "nt":
            threading.Thread(target=self._watch_parent, args=(pid,), name="kashif-parent", daemon=True).start()
        self.initialized = True
        return {
            "capabilities": {
                "positionEncoding": "utf-16",
                "textDocumentSync": {"openClose": True, "change": 1, "save": {"includeText": False}},
                "hoverProvider": True,
                "codeActionProvider": {"codeActionKinds": ["quickfix"]},
                "executeCommandProvider": {"commands": list(COMMANDS)},
                "workspace": {"workspaceFolders": {"supported": True, "changeNotifications": True}},
            },
            "serverInfo": {"name": SOURCE, "version": __version__},
        }

    def on_initialized(self, params: dict) -> None:
        if self._cap("workspace", "configuration"):
            self.request("workspace/configuration", {"items": [{"section": "kashif"}]}, self._on_configuration)

    def on_shutdown(self, params) -> None:
        self.shutdown_requested = True
        with self._cv:
            self._due.clear()
            self._stopped = True
            self._cv.notify_all()
        return None

    def _watch_parent(self, pid: int) -> None:
        while self.exit_code is None:
            time.sleep(5)
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                log("editor process is gone; exiting")
                os._exit(1)
            except OSError:
                pass

    def _cap(self, *keys) -> bool:
        node = self.client_caps
        for k in keys:
            if not isinstance(node, dict):
                return False
            node = node.get(k)
        return bool(node)

    # ---------------------------------------------------------------- settings

    def _on_configuration(self, result, error) -> None:
        if error or not isinstance(result, list) or not result:
            return
        self._apply_settings(result[0])

    def on_did_change_configuration(self, params: dict) -> None:
        settings = params.get("settings")
        if isinstance(settings, dict) and settings:
            self._apply_settings(settings)
        elif self._cap("workspace", "configuration"):       # pull model: settings is null, ask for them
            self.request("workspace/configuration", {"items": [{"section": "kashif"}]}, self._on_configuration)

    def _apply_settings(self, raw) -> None:
        with self._lock:
            changed = self.settings.update(raw)
        if not changed:
            return
        log("settings changed:", ", ".join(changed))
        if {"audit", "exclude"} & set(changed):
            with self._lock:
                keys = [k for k, f in self.folders.items() if f.findings is not None or k in self._due]
            for k in keys:
                self._schedule(k, delay=0)
        else:
            self._republish_all()

    # ---------------------------------------------------------------- folders and documents

    def _add_folder(self, uri) -> str | None:
        path = uri_to_path(uri)
        if path is None:
            return None
        key = path_key(path)
        with self._lock:
            if key not in self.folders:
                self.folders[key] = Folder(pathlib.Path(os.path.abspath(path)))
        return key

    def _remove_folder(self, key: str) -> None:
        with self._lock:
            folder = self.folders.pop(key, None)
            self._due.pop(key, None)
        if folder is not None:
            with self._publish_lock:
                for uri in list(folder.published):
                    self.notify("textDocument/publishDiagnostics", {"uri": uri, "diagnostics": []})
                folder.published.clear()
            self._send_status()

    def _folder_for(self, path: pathlib.Path, create: bool = True) -> str | None:
        """The innermost workspace folder containing ``path``; else a single-file scan root for it."""
        target = path_key(path)
        best = None
        with self._lock:
            for key, folder in self.folders.items():
                if folder.is_file:
                    continue
                if target == key or target.startswith(key.rstrip(os.sep) + os.sep):
                    if best is None or len(key) > len(best):
                        best = key
            if best is None and target in self.folders:
                best = target
            if best is None and create:
                self.folders[target] = Folder(pathlib.Path(os.path.abspath(path)), is_file=True)
                best = target
        return best

    def on_did_change_workspace_folders(self, params: dict) -> None:
        event = params.get("event") if isinstance(params.get("event"), dict) else {}
        for wf in event.get("removed") or []:
            path = uri_to_path(wf.get("uri")) if isinstance(wf, dict) else None
            if path is not None:
                self._remove_folder(path_key(path))
        for wf in event.get("added") or []:
            key = self._add_folder(wf.get("uri")) if isinstance(wf, dict) else None
            if key is None:
                continue
            with self._lock:                            # lone files the new folder now contains: scanned with it
                lone = [k for k, f in self.folders.items() if f.is_file and k.startswith(key.rstrip(os.sep) + os.sep)]
            for k in lone:
                self._remove_folder(k)
            if any(self._folder_for(uri_to_path(d.uri), create=False) == key
                                       for d in list(self.docs.values())):
                self._schedule(key)

    def _doc_params(self, params: dict) -> tuple[str, pathlib.Path]:
        td = params.get("textDocument")
        uri = td.get("uri") if isinstance(td, dict) else None
        path = uri_to_path(uri)
        if path is None:
            raise RpcError(INVALID_PARAMS, "textDocument.uri must be a file:// URI")
        return uri, path

    def on_did_open(self, params: dict) -> None:
        try:
            uri, path = self._doc_params(params)
        except RpcError:
            return                                      # untitled: buffers, git: diffs ... nothing to scan
        td = params["textDocument"]
        text = td.get("text") if isinstance(td.get("text"), str) else ""
        with self._lock:
            self.docs[path_key(path)] = Document(uri, text, td.get("version") or 0)
        key = self._folder_for(path)
        with self._lock:
            folder = self.folders.get(key)
            fresh = folder is not None and folder.findings is None and key not in self._due
        if fresh:
            self._schedule(key)

    def on_did_change(self, params: dict) -> None:
        try:
            _, path = self._doc_params(params)
        except RpcError:
            return
        changes = params.get("contentChanges")
        with self._lock:
            doc = self.docs.get(path_key(path))
            if doc is None or not isinstance(changes, list):
                return
            for ch in changes:                          # full sync: the last full text wins
                if isinstance(ch, dict) and isinstance(ch.get("text"), str) and "range" not in ch:
                    doc.text = ch["text"]
            version = params["textDocument"].get("version")
            if isinstance(version, int):
                doc.version = version

    def on_did_save(self, params: dict) -> None:
        try:
            _, path = self._doc_params(params)
        except RpcError:
            return
        if isinstance(params.get("text"), str):
            with self._lock:
                doc = self.docs.get(path_key(path))
                if doc is not None:
                    doc.text = params["text"]
        key = self._folder_for(path)
        if key is not None:
            self._schedule(key)

    def on_did_close(self, params: dict) -> None:
        try:
            _, path = self._doc_params(params)
        except RpcError:
            return
        pk = path_key(path)
        with self._lock:
            self.docs.pop(pk, None)
            folder = self.folders.get(pk)
        if folder is not None and folder.is_file:       # a lone file: its diagnostics leave with it
            self._remove_folder(pk)

    def on_did_change_watched_files(self, params: dict) -> None:
        keys, gone = set(), set()
        for ch in params.get("changes") or []:
            path = uri_to_path(ch.get("uri")) if isinstance(ch, dict) else None
            if path is None:
                continue
            key = self._folder_for(path, create=False)
            with self._lock:
                folder = self.folders.get(key) if key is not None else None
            if folder is None or folder.findings is None:
                continue
            if folder.is_file:
                if ch.get("type") == 3 and key == path_key(path):
                    gone.add(key)                       # a lone file was deleted: its diagnostics go with it
                else:
                    keys.add(key)
                continue
            try:
                rel = path.relative_to(folder.path).parts[:-1]
            except ValueError:
                rel = ()
            if any(part in SKIP_DIRS for part in rel):
                continue                                # .git/index.lock, node_modules ...: never scanned anyway
            keys.add(key)
        for key in gone:
            self._remove_folder(key)
        for key in keys - gone:
            self._schedule(key)

    # ---------------------------------------------------------------- scanning

    def _schedule(self, key: str, delay: float | None = None) -> None:
        with self._cv:
            folder = self.folders.get(key)
            if folder is None or self._stopped:
                return
            folder.gen += 1
            self._due[key] = time.monotonic() + (self.debounce if delay is None else delay)
            self._cv.notify_all()

    def _scan_loop(self) -> None:
        while True:
            with self._cv:
                while True:
                    if self._stopped:
                        return
                    now = time.monotonic()
                    ready = [k for k, t in self._due.items() if t <= now]
                    if ready:
                        key = min(ready, key=lambda k: self._due[k])
                        del self._due[key]
                        folder = self.folders.get(key)
                        if folder is None:
                            continue
                        gen = folder.gen
                        settings = Settings(self.settings.min_severity, self.settings.audit,
                                            list(self.settings.exclude), self.settings.baseline, self.settings.language)
                        break
                    self._cv.wait(min(self._due.values()) - now if self._due else None)
            token = self._progress_begin(folder)
            try:
                started = time.monotonic()
                findings = self._scan(folder, settings)
                log(f"scanned {folder.path} in {time.monotonic() - started:.2f}s: {len(findings)} findings")
            except Exception:              # noqa: BLE001 - a scanner bug must not take the editor's server down
                log(f"scan of {folder.path} failed:\n" + traceback.format_exc())
                findings = None
            finally:
                self._progress_end(token)
            with self._lock:
                stale = folder.gen != gen or self.folders.get(key) is not folder or self._stopped
                if findings is not None and not stale:
                    folder.findings = findings
            if stale:
                log(f"discarded a stale scan of {folder.path}")
                continue
            if findings is not None:
                self._publish(folder)
                self._send_status()

    def _scan(self, folder: Folder, settings: Settings) -> list[Finding]:
        notes: list[str] = []
        findings, _files = scan_path(folder.path, list(settings.exclude), jadx=False, notes=notes, audit=settings.audit)
        assign_fingerprints(findings)                  # on the complete list, exactly as the CLI does
        return findings

    def _progress_begin(self, folder: Folder):
        """Start a work-done progress (shown by Neovim, Helix, Zed, VS Code ...). The token is used only once the
        client has acknowledged it, as the protocol requires."""
        if self.status_notifications:
            self.notify("kashif/status", {"state": "scanning"})
        if not self._cap("window", "workDoneProgress"):
            return None
        with self._lock:
            self._next_id += 1
            state = {"token": f"kashif-scan-{self._next_id}", "begun": False, "done": False}

        def acknowledged(result, error):
            with self._lock:
                if error or state["done"]:
                    return
                state["begun"] = True
            self.notify("$/progress", {"token": state["token"], "value": {
                "kind": "begin", "title": SOURCE, "message": folder.path.name, "cancellable": False}})

        self.request("window/workDoneProgress/create", {"token": state["token"]}, acknowledged)
        return state

    def _progress_end(self, state) -> None:
        if state is None:
            return
        with self._lock:
            state["done"] = True
            begun = state["begun"]
        if begun:
            self.notify("$/progress", {"token": state["token"], "value": {"kind": "end"}})

    # ---------------------------------------------------------------- diagnostics

    def _baseline_path(self, folder: Folder, settings: Settings | None = None) -> pathlib.Path:
        settings = settings or self.settings
        p = pathlib.Path(os.path.expanduser(settings.baseline or DEFAULT_BASELINE))
        return p if p.is_absolute() else folder.base / p

    def _text_lines(self, path: pathlib.Path, cache: dict) -> list[str]:
        key = path_key(path)
        if key not in cache:
            try:
                cache[key] = split_lines(path.read_text("utf-8", errors="replace"))
            except OSError:
                cache[key] = []
        return cache[key]

    def _message(self, f: Finding) -> str:
        en = self.settings.language == "en"
        title = (f.title or to_en(f.title_ar)) if en else (f.title_ar or f.title)
        advice = to_en(f.advice or "") if en else (f.advice or "")
        return f"{title}\n{advice}" if advice else (title or f.rule_id)

    def _diagnostic(self, folder: Folder, f: Finding, lines: list[str], cache: dict) -> dict:
        diag = {"range": line_range(lines, f.line), "severity": DIAG_SEVERITY.get(f.severity, 2), "source": SOURCE,
                "code": f.rule_id, "message": self._message(f), "data": f.fingerprint()}
        href = cwe_href(f.cwe)
        if href:
            diag["codeDescription"] = {"href": href}
        related = []
        for step in f.extra.get("path") or []:
            if not isinstance(step, dict):
                continue
            try:
                sline = int(step.get("line") or 1)
            except (TypeError, ValueError):
                sline = 1
            sfile = str(step.get("file") or f.file)
            spath = folder.path if folder.is_file and sfile == f.file else folder.base / sfile
            text = str(step.get("text", ""))
            related.append({"location": {"uri": path_to_uri(spath),
                                         "range": line_range(self._text_lines(spath, cache), sline)},
                            "message": to_en(text) if self.settings.language == "en" else text})
        if related:
            diag["relatedInformation"] = related
        return diag

    def _publish(self, folder: Folder) -> None:
        """Filter the folder's cached findings with the current settings and publish what changed."""
        with self._publish_lock:
            with self._lock:
                findings = list(folder.findings or [])
                min_rank = SEVERITY_RANK[self.settings.min_severity]
                known = load_baseline(str(self._baseline_path(folder)))
            cache: dict[str, list[str]] = {}
            by_uri: dict[str, list[dict]] = {}
            visible: dict[str, list[tuple[Finding, dict]]] = {}
            for f in findings:
                if SEVERITY_RANK.get(f.severity, 9) > min_rank or f.fingerprint() in known:
                    continue
                if f.source == "web" or "!" in f.file or not f.file:
                    continue                            # nothing an editor can open
                fpath = folder.file_of(f)
                lines = self._text_lines(fpath, cache)  # nosec - a file our own scan reported inside the folder
                if 0 < f.line <= len(lines) and SUPPRESS.search(lines[f.line - 1]):
                    continue                            # the editor honours the marker for every kind of check
                diag = self._diagnostic(folder, f, lines, cache)
                uri = path_to_uri(fpath)
                with self._lock:
                    doc = self.docs.get(path_key(fpath))
                if doc is not None:
                    uri = doc.uri                       # the client's own spelling of the URI
                by_uri.setdefault(uri, []).append(diag)
                visible.setdefault(path_key(fpath), []).append((f, diag))
            for diags in by_uri.values():
                diags.sort(key=lambda d: (d["range"]["start"]["line"], d["severity"], d["code"]))
            sent = 0
            for uri in sorted(set(by_uri) | set(folder.published)):
                diags = by_uri.get(uri, [])
                blob = json.dumps(diags, sort_keys=True, ensure_ascii=False)
                if folder.published.get(uri) == blob:
                    continue
                self.notify("textDocument/publishDiagnostics", {"uri": uri, "diagnostics": diags})
                sent += 1
                if diags:
                    folder.published[uri] = blob
                else:
                    folder.published.pop(uri, None)
            with self._lock:
                folder.visible = visible
            log(f"published diagnostics for {sent} file(s) of {folder.path}")

    def _republish_all(self) -> None:
        with self._lock:
            folders = [f for f in self.folders.values() if f.findings is not None]
        for folder in folders:
            self._publish(folder)
        self._send_status()

    def _send_status(self) -> None:
        if not self.status_notifications:
            return
        counts = {s: 0 for s in SEVERITIES}
        with self._lock:
            scanning = bool(self._due)
            for folder in self.folders.values():
                for items in folder.visible.values():
                    for f, _ in items:
                        counts[f.severity] = counts.get(f.severity, 0) + 1
        self.notify("kashif/status", {"state": "scanning" if scanning else "idle", "counts": counts,
                                      "total": sum(counts.values())})

    def _findings_at(self, path: pathlib.Path, first: int, last: int) -> list[tuple[Finding, dict, Folder]]:
        key = path_key(path)
        out = []
        with self._lock:
            for folder in self.folders.values():
                for f, diag in folder.visible.get(key, []):
                    if first <= diag["range"]["start"]["line"] <= last:
                        out.append((f, diag, folder))
        return out

    # ---------------------------------------------------------------- hover

    def on_hover(self, params: dict):
        try:
            _, path = self._doc_params(params)
        except RpcError:
            return None
        pos = params.get("position")
        if not isinstance(pos, dict) or not isinstance(pos.get("line"), int):
            raise RpcError(INVALID_PARAMS, "position is required")
        hits = self._findings_at(path, pos["line"], pos["line"])
        if not hits:
            return None
        lang = self.settings.language
        parts = []
        for f, diag, _folder in hits:
            title = (f.title or to_en(f.title_ar)) if lang == "en" else (f.title_ar or f.title)
            sev = SEVERITY_EN[f.severity] if lang == "en" else SEVERITY_AR.get(f.severity, f.severity)
            href = cwe_href(f.cwe)
            head = f"**{md(title)}**\n\n{localize(MSG['severity'], lang)}: {sev} · {localize(MSG['rule'], lang)}: `{f.rule_id}`"
            if href:
                head += f" · [{f.cwe}]({href})"
            block = [head]
            advice = to_en(f.advice or "") if lang == "en" else (f.advice or "")
            if advice:
                block.append(f"**{localize(MSG['remediation'], lang)}:** {md(advice)}")
            steps = [st for st in f.extra.get("path") or [] if isinstance(st, dict)]
            if steps:
                block.append(f"**{localize(MSG['trail'], lang)}:**")
                block.append("\n".join(
                    f"{i}. `{st.get('file') or f.file}:{st.get('line', '?')}` — "
                    f"{md(to_en(str(st.get('text', ''))) if lang == 'en' else str(st.get('text', '')))}"
                    for i, st in enumerate(steps, 1)))
            parts.append("\n\n".join(block))
        first = hits[0][1]["range"]
        return {"contents": {"kind": "markdown", "value": "\n\n---\n\n".join(parts)}, "range": first}

    # ---------------------------------------------------------------- code actions

    def on_code_action(self, params: dict):
        try:
            uri, path = self._doc_params(params)
        except RpcError:
            return []
        rng = params.get("range")
        try:
            first, last = int(rng["start"]["line"]), int(rng["end"]["line"])
        except (TypeError, KeyError, ValueError):
            raise RpcError(INVALID_PARAMS, "range is required") from None
        ctx = params.get("context") if isinstance(params.get("context"), dict) else {}
        only = ctx.get("only")
        if isinstance(only, list) and only and not any(k == "quickfix" or "quickfix".startswith(f"{k}.") or k == ""
                                                       for k in only if isinstance(k, str)):
            return []
        wanted = {d.get("data") for d in ctx.get("diagnostics") or []
                  if isinstance(d, dict) and d.get("source") == SOURCE and isinstance(d.get("data"), str)}
        hits = self._findings_at(path, first, last)
        if wanted:
            hits = [h for h in hits if h[0].fingerprint() in wanted] or hits
        if not hits:
            return []
        lang = self.settings.language
        with self._lock:
            doc = self.docs.get(path_key(path))
            text = doc.text if doc is not None else None
        if text is None:
            try:
                text = path.read_text("utf-8", errors="replace")
            except OSError:
                text = ""
        lines = split_lines(text)
        ext = path.suffix.lower()
        if ext in (".py", ".pyw", ".pyi"):
            in_string = _python_multiline_string_lines(text)
        elif ext in _SLASH:
            in_string = _clike_multiline_string_lines(text, ext)
        else:
            in_string = set()
        actions = []
        suppressed_lines = set()
        for f, diag, folder in hits:
            idx = diag["range"]["start"]["line"]
            line_text = lines[idx] if 0 <= idx < len(lines) else ""
            comment = None if (f.line <= 0 or idx in in_string) else suppression_text(path, line_text)
            if comment and idx not in suppressed_lines:
                suppressed_lines.add(idx)
                end = utf16_len(line_text.rstrip())
                actions.append({
                    "title": f"{SOURCE}: {localize(MSG['suppress'], lang)} ({f.rule_id})",
                    "kind": "quickfix",
                    "diagnostics": [diag],
                    "edit": {"changes": {uri: [{"range": {"start": {"line": idx, "character": end},
                                                          "end": {"line": idx, "character": utf16_len(line_text)}},
                                                "newText": comment}]}},
                })
            actions.append({"title": f"{SOURCE}: {localize(MSG['baseline'], lang)} ({f.rule_id})", "kind": "quickfix",
                            "diagnostics": [diag],
                            "command": {"title": localize(MSG["baseline"], lang), "command": CMD_BASELINE,
                                        "arguments": [path_to_uri(folder.file_of(f)), f.fingerprint()]}})
            href = cwe_href(f.cwe)
            if href:
                actions.append({"title": f"{SOURCE}: {localize(MSG['cwe'], lang)} ({f.cwe})", "kind": "quickfix",
                                "diagnostics": [diag],
                                "command": {"title": f.cwe, "command": CMD_CWE, "arguments": [href]}})
        return actions

    # ---------------------------------------------------------------- commands

    def on_execute_command(self, params: dict):
        cmd = params.get("command")
        args = params.get("arguments") if isinstance(params.get("arguments"), list) else []
        if cmd == CMD_SCAN:
            with self._lock:
                keys = list(self.folders)
            for k in keys:
                self._schedule(k, delay=0)
            return {"folders": len(keys)}
        if cmd == CMD_CWE:
            href = args[0] if args else None
            if not isinstance(href, str) or not re.fullmatch(r"https://cwe\.mitre\.org/data/definitions/\d+\.html", href):
                raise RpcError(INVALID_PARAMS, "expected a cwe.mitre.org definition URL")
            if self._cap("window", "showDocument", "support"):
                self.request("window/showDocument", {"uri": href, "external": True}, lambda r, e: None)
            else:
                self.notify("window/showMessage",
                            {"type": 3, "message": f"{localize(MSG['open_cwe'], self.settings.language)} {href}"})
            return None
        if cmd == CMD_BASELINE:
            if len(args) < 2 or not isinstance(args[1], str):
                raise RpcError(INVALID_PARAMS, "expected [fileUri, fingerprint]")
            return self._add_to_baseline(args[0], args[1])
        raise RpcError(INVALID_PARAMS, f"unknown command: {cmd}")

    def _add_to_baseline(self, uri, fingerprint: str):
        lang = self.settings.language
        path = uri_to_path(uri)
        found = None
        with self._lock:
            for folder in self.folders.values():
                for f in folder.findings or []:
                    if f.fingerprint() == fingerprint and (path is None or path_key(folder.file_of(f)) == path_key(path)):
                        found = (folder, f)
                        break
                if found:
                    break
        if found is None:
            self.notify("window/showMessage", {"type": 2, "message": localize(MSG["finding_gone"], lang)})
            return {"added": False}
        folder, f = found
        bpath = self._baseline_path(folder)
        try:
            added = add_to_baseline(bpath, f)
        except (OSError, ValueError) as e:
            log(f"baseline {bpath}: {e}")
            self.notify("window/showMessage", {"type": 1, "message": localize(MSG["baseline_failed"], lang)})
            return {"added": False, "baseline": str(bpath)}
        self.notify("window/showMessage",
                    {"type": 3, "message": localize(MSG["baseline_added" if added else "baseline_known"], lang)})
        self._publish(folder)
        self._send_status()
        return {"added": added, "baseline": str(bpath)}

    REQUESTS = {
        "initialize": on_initialize,
        "shutdown": on_shutdown,
        "textDocument/hover": on_hover,
        "textDocument/codeAction": on_code_action,
        "workspace/executeCommand": on_execute_command,
    }
    NOTIFICATIONS = {
        "initialized": on_initialized,
        "textDocument/didOpen": on_did_open,
        "textDocument/didChange": on_did_change,
        "textDocument/didSave": on_did_save,
        "textDocument/didClose": on_did_close,
        "workspace/didChangeConfiguration": on_did_change_configuration,
        "workspace/didChangeWorkspaceFolders": on_did_change_workspace_folders,
        "workspace/didChangeWatchedFiles": on_did_change_watched_files,
    }

    # ---------------------------------------------------------------- main loop

    def serve(self, stream) -> int:
        reader = MessageReader()
        read = getattr(stream, "read1", None) or stream.read
        while self.exit_code is None:
            try:
                chunk = read(65536)
            except (OSError, ValueError) as e:
                log("read failed:", e)
                break
            if not chunk:
                break
            for msg in reader.feed(chunk):
                self.handle(msg)
                if self.exit_code is not None:
                    break
        with self._cv:
            self._stopped = True
            self._cv.notify_all()
        return self.exit_code if self.exit_code is not None else (0 if self.shutdown_requested else 1)


def add_to_baseline(path: pathlib.Path, finding: Finding) -> bool:
    """Add one finding's fingerprint to a baseline file (same schema as ``vulnscan --write-baseline``), keeping the
    entries already there. Returns False when it was already recorded. Refuses to overwrite a file that exists but
    is not a baseline (ValueError), so a typo in the setting cannot destroy unrelated JSON."""
    fp = finding.fingerprint()
    entries: list = []
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("fingerprints"), list):
            raise ValueError(f"{path} is not a vulnscan baseline")
        entries = [e for e in data["fingerprints"] if isinstance(e, dict)]
        if fp in load_baseline(str(path)):
            return False
    entries.append({"fp": fp, "rule": finding.rule_id, "file": finding.file, "severity": finding.severity})
    entries.sort(key=lambda e: str(e.get("fp", "")))
    data = {"schema": BASELINE_SCHEMA, "tool_version": __version__, "count": len(entries), "fingerprints": entries}
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)
    return True


def main(argv: list[str] | None = None) -> int:
    """``vulnscan lsp [--stdio]``: run the language server on stdin/stdout."""
    p = argparse.ArgumentParser(prog="vulnscan lsp", description="Kashif language server (LSP over stdio).")
    p.add_argument("--stdio", action="store_true", help="accepted for editor compatibility; stdio is the only transport")
    p.add_argument("--debounce", type=float, default=0.4, help=argparse.SUPPRESS)
    args, unknown = p.parse_known_args(argv)
    if unknown:
        log("ignoring arguments:", " ".join(unknown))
    out = sys.stdout.buffer
    stdin = sys.stdin.buffer
    sys.stdout = sys.stderr                    # nothing printed by accident may corrupt the protocol stream
    log(f"Kashif {__version__} language server on stdio")
    server = KashifLanguageServer(out, debounce=max(0.0, args.debounce))
    return server.serve(stdin)
