"""Type-aware, inter-procedural, cross-file taint analysis for Python.  (vulnscan: ignore-file)

Design (the parts that mirror CodeQL):

* **Models as data** -- sources, sinks, sanitizers, framework entry points and
  validators are declared in JSON (``vulnscan/models/python.json``); users add
  their own files with ``--models DIR``. No code change is needed to model a
  new library.
* **Whole-program model**: every file is parsed, functions/classes/methods are
  indexed globally and imports (absolute, aliased and relative) are resolved,
  so calls are followed across files. Names are canonicalised through the
  import aliases (``import subprocess as sp; sp.run`` matches ``subprocess.run``).
* **Type-aware call resolution**: variables get a class from constructors,
  annotations, ``self``, typed fields and known return types; methods are
  resolved through the MRO with virtual dispatch over subclass overrides.
  Function values (``h = helper``, ``functools.partial``) are followed too.
* **Field- and container-sensitive flow**: ``self.x`` across methods,
  constructor arguments into fields, ``append``/subscript stores/literals.
* **Framework entry points**: parameters of routed handlers (Flask/FastAPI/
  Django views, class-based views, CLI commands) are sources.
* **Barrier guards** (path sensitivity): a sink under ``if x in ALLOWED`` /
  ``x.isalnum()`` / ``re.fullmatch(..., x)`` / after ``if not valid(x): return``
  is not reported.
* **Flow paths**: every finding carries the step-by-step path from the source,
  through assignments and calls, to the sink.
* Summaries (returns-untrusted, params/fields that reach a sink, return type,
  return location) are computed to a fixpoint so flows compose across hops.

Still not CodeQL: no full points-to analysis, no query language (models are
declarative JSON, not QL), Python only.
"""

from __future__ import annotations

import ast
import json
import pathlib
import re
import time

from . import flow as _flow
from . import php_include as _php_include
from .model import Finding

MAX_PASSES = 16
SUPPRESS = re.compile(r"(nosec|vulnscan:\s*ignore|noqa:\s*S\d+)", re.I)
DEFAULT_MODELS = pathlib.Path(__file__).parent / "models" / "python.json"
DEFAULT_JS_MODELS = pathlib.Path(__file__).parent / "models" / "javascript.json"
PY_EXTS = (".py",)
JS_EXTS = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")
CFAMILY = {".java": "java", ".kt": "kotlin", ".kts": "kotlin", ".cs": "csharp", ".go": "go", ".php": "php", ".phtml": "php",
           ".c": "cpp", ".h": "cpp", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hh": "cpp", ".hxx": "cpp",
           ".rs": "rust", ".swift": "swift", ".rb": "ruby", ".rake": "ruby", ".erb": "ruby"}   # .erb: Rails views (erb_frontend)
CFAMILY_LANGS = ("java", "kotlin", "csharp", "go", "php", "cpp", "rust", "swift", "ruby")
MODELS_DIR = pathlib.Path(__file__).parent / "models"
_KEYED_READS = {"get", "getOrDefault", "getFirst", "getLast", "peek", "peekFirst", "peekLast", "element", "first", "last",
                "getProperty", "getAttribute"}
CONTAINER_WRITES = {"append", "extend", "insert", "add", "update", "put", "setdefault", "set", "setProperty", "__setitem__",
                    "push", "addAll", "putAll", "appendleft", "unshift", "Add", "AddRange", "write", "concat"}
ARG_INJECTION = ("DF009", "medium", "Tainted data reaches a subprocess argument",
                 "بيانات غير موثوقة تصل إلى وسيط لأمر خارجي",
                 "تحقّق من الوسيط بقائمة بيضاء، وارفض القيم التي تبدأ بـ -، ولا تمرّر مسارات غير مُطبَّعة.",
                 "CWE-88", "subprocess argument", [0], False)
DYNAMIC_DISPATCH = ("DF026", "high", "Tainted data selects the class or function that is invoked (unsafe reflection)",
                    "بيانات غير موثوقة تختار الصنف أو الدالة المستدعاة (انعكاس غير آمن)",
                    "لا تختر صنفًا أو دالة أو وحدة باسم من المدخلات؛ اربط القيم المسموحة بقاموس ثابت (allow-list) من الأسماء إلى الدوال.",
                    "CWE-470", "dynamic method call", ["slice"], False)
REFLECTED_RETURN = ("DF013", "medium", "Tainted data returned in an HTTP response (reflected XSS)",
                    "بيانات غير موثوقة تُعاد في استجابة HTTP (XSS انعكاسي)",
                    "هرّب المخرجات (html.escape / markupsafe) أو استخدم قوالب تُهرِّب تلقائيًا.",
                    "CWE-79", "HTTP response", [0], False)


# ------------------------------------------------------------------ models
def load_models(extra_dirs=(), base=None, language="python") -> dict:
    """Merge the built-in models for a language with every *.json in the given directories."""
    m = {"attr_sources": [], "call_sources": [], "name_sources": [], "prefix_sources": [], "entry_decorators": set(),
         "view_bases": set(), "view_methods": set(), "request_params": {"request", "req", "self"},
         "sinks": [], "attr_sinks": [], "store_sinks": [], "sanitizers": set(), "user_sanitizers": set(), "safe_return_calls": set(), "validators": set(),
         "language": language}
    paths = [base or DEFAULT_MODELS]
    for d in extra_dirs or ():
        p = pathlib.Path(d)
        if p.is_file() and p.suffix == ".json":
            paths.append(p)
        elif p.is_dir():
            paths.extend(sorted(p.glob("*.json")))
    for path in paths:
        try:
            data = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        langs = data.get("languages")
        if langs and language not in langs:
            continue
        for a in data.get("attr_sinks", []):
            m["attr_sinks"].append(((a["rule"], a.get("severity", "medium"), a.get("title", a["rule"]), a.get("title_ar", a.get("title", a["rule"])),
                                     a.get("advice", ""), a.get("cwe", ""), a.get("label", a["rule"]), [0], False), set(a.get("attrs", []))))
        for s in data.get("sources", []):
            kind = s.get("kind")
            if kind == "attr":
                m["attr_sources"].append((set(s.get("roots", [])), set(s.get("attrs", [])), s.get("label", "request.{attr}")))
            elif kind == "call":
                m["call_sources"].append((list(s.get("names", [])), s.get("label", "{name}()")))
            elif kind == "name":
                m["name_sources"].append((list(s.get("names", [])), s.get("label", "{name}")))
            elif kind == "prefix":   # any dotted name starting with a prefix, e.g. apex_item.P10_NAME (an APEX page item)
                m["prefix_sources"].append((tuple(s.get("prefixes", [])), s.get("label", "{name}")))
        for e in data.get("entry_points", []):
            m["entry_decorators"] |= set(e.get("decorators", []))
            m["view_bases"] |= set(e.get("view_bases", []))
            m["view_methods"] |= set(e.get("methods", []))
            m["request_params"] |= set(e.get("param_names", []))
        for k in data.get("sinks", []):
            m["sinks"].append((k["rule"], k.get("severity", "high"), k.get("title", k["rule"]), k.get("title_ar", k.get("title", k["rule"])),
                               k.get("advice", ""), k.get("cwe", ""), k.get("label", k["rule"]), list(k.get("args", [0])),
                               bool(k.get("shell", False)), list(k.get("names", [])),
                               frozenset(x.lower() for x in k.get("kwargs", [])),
                               re.compile(k["receiver"]) if k.get("receiver") else None,
                               {kw: frozenset(v) for kw, v in (k.get("safe_kwargs") or {}).items()} or None,
                               re.compile(k["receiver_not"]) if k.get("receiver_not") else None))
        for st in data.get("store_sinks", []):
            # `session[key] = value`: writing untrusted data into a trusted store (trust boundary violation)
            m["store_sinks"].append(((st["rule"], st.get("severity", "medium"), st.get("title", st["rule"]),
                                      st.get("title_ar", st.get("title", st["rule"])), st.get("advice", ""), st.get("cwe", ""),
                                      st.get("label", st["rule"]), [0], False), set(st.get("roots", []))))
        m["sanitizers"] |= set(data.get("sanitizers", []))
        if path != paths[0]:                   # declared by the user in their own model files: taken at its word
            m["user_sanitizers"] |= set(data.get("sanitizers", []))
        m["safe_return_calls"] |= set(data.get("safe_return_calls", []))
        m["validators"] |= set(data.get("validators", []))
    return m


def _name_matches(canon: str, name: str) -> bool:
    """Model-name matching: 'builtins.open' = bare call only; 'pkg.fn' = dotted suffix; 'fn' = any last segment."""
    if name.startswith("builtins."):
        return canon == name[len("builtins."):]
    if "." in name:
        return canon == name or canon.endswith("." + name)
    return canon.split(".")[-1] == name


MAX_AST_DEPTH = 300   # far beyond hand-written code; protects every recursive analysis from hostile nesting


def _receiver_text(node) -> str:
    """Text of a call receiver for receiver-pattern sinks (`request.getSession()` -> "request.getSession()")."""
    d = _dotted(node)
    if d:
        return d
    try:
        return ast.unparse(node)[:200]
    except Exception:  # noqa: BLE001
        return ""


def too_deep(tree, limit: int = MAX_AST_DEPTH) -> bool:
    """Iterative depth check (no recursion): True when the syntax tree nests deeper than `limit`."""
    stack = [(tree, 0)]
    while stack:
        node, d = stack.pop()
        if d > limit:
            return True
        for ch in ast.iter_child_nodes(node):
            stack.append((ch, d + 1))
    return False


def _prune_too_deep(tree, limit: int = MAX_AST_DEPTH) -> list:
    """Replace over-deep function bodies / top-level statements with `pass`; returns what was left out."""
    pruned = []

    def visit(container, depth_offset):
        body = getattr(container, "body", None)
        if not isinstance(body, list):
            return
        for i, st in enumerate(body):
            if not too_deep(st, limit - depth_offset):
                continue
            if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and isinstance(st, ast.ClassDef):
                visit(st, depth_offset + 1)
                if not too_deep(st, limit - depth_offset):
                    continue
            name = getattr(st, "name", None) or f"line {getattr(st, 'lineno', '?')}"
            if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
                st.body = [ast.Pass(lineno=st.lineno, col_offset=0)]
            else:
                body[i] = ast.Pass(lineno=getattr(st, "lineno", 0), col_offset=0)
            pruned.append(name)
    visit(tree, 1)
    return pruned


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return ""


_SCOPE_CACHE: dict = {}


def release_caches() -> None:
    """Drop module-level caches that point into a finished project's syntax trees (long-running hosts such as the
    UI and the language server would otherwise keep every scanned tree alive)."""
    _SCOPE_CACHE.clear()
    _TEMPLATES.clear()


def _scope_nodes(fn: ast.AST):
    """Nodes of a scope's body, without descending into nested functions, classes or lambdas (cached per node)."""
    key = id(fn)
    hit = _SCOPE_CACHE.get(key)
    if hit is not None and hit[0] is fn:
        return hit[1]
    out = []
    stack = list(reversed(getattr(fn, "body", []) or []))
    while stack:
        n = stack.pop()
        out.append(n)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        stack.extend(reversed(list(ast.iter_child_nodes(n))))
    _SCOPE_CACHE[key] = (fn, out)
    return out


def _param_names(fn: ast.AST) -> list[str]:
    a = fn.args
    names = [p.arg for p in (a.posonlyargs + a.args + a.kwonlyargs)]
    if a.vararg:
        names.append(a.vararg.arg)
    if a.kwarg:
        names.append(a.kwarg.arg)
    return names


def _annotation_name(ann: ast.AST | None) -> str | None:
    if ann is None:
        return None
    if isinstance(ann, ast.Constant) and isinstance(ann.value, str):
        return ann.value
    if isinstance(ann, ast.Subscript):
        return _annotation_name(ann.slice)
    if isinstance(ann, ast.BinOp):
        return _annotation_name(ann.left) or _annotation_name(ann.right)
    return _dotted(ann) or None


def _exits(stmts: list) -> bool:
    return bool(stmts) and isinstance(stmts[-1], (ast.Return, ast.Raise, ast.Continue, ast.Break))


_TEST_DECORATOR_ROOTS = frozenset({"unittest", "mock", "pytest", "_pytest", "responses", "respx", "freezegun",
                                   "hypothesis", "pytest_mock", "asynctest", "aioresponses", "httpretty", "vcr"})


_SAFE_SCALARS = frozenset({"int", "float", "bool", "complex", "UUID", "UUID1", "UUID3", "UUID4", "UUID5", "Decimal", "date",
                           "datetime", "time", "timedelta", "PositiveInt", "NegativeInt", "NonNegativeInt",
                           "NonPositiveInt", "PositiveFloat", "NegativeFloat", "StrictInt", "StrictFloat", "StrictBool",
                           "PastDate", "FutureDate", "AwareDatetime", "NaiveDatetime", "IPv4Address", "IPv6Address"})
_SCHEMA_BASES = frozenset({"BaseModel", "SQLModel", "Schema", "ModelSchema", "BaseSettings", "RootModel"})
_WTFORMS_BASES = frozenset({"Form", "FlaskForm", "BaseForm", "SecureForm"})
_SAFE_FIELD_TYPES = frozenset({
    # Django forms / DRF serializers
    "IntegerField", "FloatField", "DecimalField", "BooleanField", "NullBooleanField", "DateField", "DateTimeField",
    "TimeField", "DurationField", "UUIDField", "ChoiceField", "TypedChoiceField", "MultipleChoiceField",
    "TypedMultipleChoiceField", "SlugField", "GenericIPAddressField", "IPAddressField", "ModelChoiceField",
    "PrimaryKeyRelatedField", "SmallIntegerField", "BigIntegerField", "PositiveIntegerField",
    # WTForms
    "IntegerRangeField", "DecimalRangeField", "SelectField", "RadioField", "SelectMultipleField", "DateTimeLocalField",
    "MonthField", "WeekField",
    # marshmallow
    "Int", "Integer", "Float", "Bool", "Boolean", "Date", "DateTime", "Time", "UUID", "Decimal", "Number",
    "TimeDelta", "AwareDateTime", "NaiveDateTime", "IP", "IPv4", "IPv6", "Enum"})
_EMAIL_FIELD_TYPES = frozenset({"EmailField", "Email"})
_FORM_BASES = frozenset({"Form", "ModelForm", "BaseForm", "FlaskForm", "SecureForm", "Serializer", "ModelSerializer",
                         "HyperlinkedModelSerializer"})


_NUMERIC_STATIC_TYPES = frozenset({"int", "long", "short", "byte", "double", "float", "boolean", "bool", "char", "Integer",
                                   "Long", "Short", "Byte", "Double", "Float", "Boolean", "BigDecimal", "BigInteger", "UUID",
                                   "Guid", "LocalDate", "LocalDateTime", "LocalTime", "OffsetDateTime", "ZonedDateTime",
                                   "Instant", "Date", "DateTime", "DateTimeOffset", "TimeSpan", "decimal", "uint", "ulong",
                                   "ushort", "sbyte", "Int", "Int32", "Int64", "Int16", "UInt", "Double", "Decimal"})


_ENUM_DECL = re.compile(r"\benum\s+(?:class\s+)?([A-Z]\w*)")
_JS_TYPED_SCHEMA = re.compile(r"(^|\.)(z|zod|Joi|joi|yup|v|t)\.(coerce\.)?(number|boolean|bigint|date|enum|nativeEnum|literal|"
                              r"uuid|int|integer|bool|isodate)\b|\.(int|integer|uuid|positive|negative|port)$")
_EXPRESS_STRICT = frozenset({"isInt", "isNumeric", "isFloat", "isDecimal", "isBoolean", "isUUID", "isMongoId", "isIn",
                             "isISO8601", "isDate", "toInt", "toFloat", "toBoolean", "toDate", "isAlphanumeric", "isAlpha",
                             "isHexadecimal", "isPort", "isIP", "isEmail"})


def _express_validated(fn) -> set:
    """Request fields a route's express-validator middleware (`query('id').isInt()`, `param('x').isUUID()`,
    `check('n').isIn([...])`) constrains to a shape that carries no payload."""
    out = set()
    for d in getattr(fn, "decorator_list", []):
        call, chain = d, []
        while isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute):
            chain.append(call.func.attr)
            call = call.func.value
        if isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id in ("query", "param", "body", "check", "cookie", "header") \
                and call.args and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str) \
                and set(chain) & _EXPRESS_STRICT:
            out.add(call.args[0].value)
    return out


_OUTPUT_TYPES = frozenset({"ResponseWriter", "HttpServletResponse", "ServletResponse", "HttpResponse", "Writer",
                           "PrintWriter", "OutputStream", "ServerResponse", "Reply", "FastifyReply", "Response",
                           "NextResponse", "NextApiResponse", "HttpResponseMessage", "Model", "ModelMap",
                           "RedirectAttributes", "BindingResult", "Errors", "ILogger", "Logger"})
_LIBRARY_METHOD_NAMES = frozenset({
    "toString", "getValue", "getKey", "get", "set", "put", "add", "append", "insert", "remove", "equals", "hashCode",
    "length", "size", "close", "read", "write", "run", "call", "apply", "accept", "test", "iterator", "next",
    "hasNext", "valueOf", "substring", "trim", "split", "replace", "replaceAll", "getBytes", "getName", "getId",
    "toLowerCase", "toUpperCase", "format", "join", "keys", "values", "items", "update", "copy", "clone", "compareTo",
    "contains", "containsKey", "isEmpty", "clear", "getAttribute", "setAttribute", "getParameter", "toArray", "stream",
    "map", "filter", "collect", "forEach", "then", "catch", "push", "pop", "shift", "slice", "concat", "parse",
    "decode", "encode", "execute", "invoke", "send", "open", "flush", "print", "println", "getOrDefault", "first",
    "last", "count", "sort", "reverse", "lower", "upper", "strip", "startswith", "endswith", "find", "index", "load",
    "loads", "dump", "dumps", "getText", "Text", "ToString", "Get", "Add", "Remove", "Contains"})
_CRLF_CWES = frozenset({"CWE-117", "CWE-93", "CWE-113"})


def _const_text(e) -> str:
    """The pattern text of a literal or a lowered regex literal (`re.compile("/[\\r\\n]/g")`)."""
    if isinstance(e, ast.Call) and e.args and _dotted(e.func) in ("re.compile", "RegExp", "Regexp.new", "Regex"):
        e = e.args[0]
    return e.value if isinstance(e, ast.Constant) and isinstance(e.value, str) else ""
_SCALAR_CASTS = frozenset({"String", "Number", "parseInt", "parseFloat", "Boolean", "BigInt", "toString", "escape",
                           "sanitize", "mongoSanitize", "ObjectId", "toInt", "toNumber", "trim", "toLowerCase", "toUpperCase"})


def _has_raw_leaf(d, scalar_names=frozenset(), tainted_names=None) -> bool:
    """Does an object literal hold a value that may be an attacker-shaped object (not a constant, a scalar cast,
    a template string or an Express route parameter, which is always a string)? `scalar_names` are variables
    known to hold such a scalar (`const id = req.params.id`)."""
    stack = [d]
    while stack:
        e = stack.pop()
        if isinstance(e, ast.Dict):
            for k, v in zip(e.keys, e.values):
                if isinstance(k, ast.Constant) and k.value in ("$where", "$function", "$accumulator") and v is not None \
                        and not isinstance(v, ast.Constant):
                    return True          # server-side JavaScript: any user text in it is code injection
                if v is not None:
                    stack.append(v)
            continue
        if isinstance(e, (ast.List, ast.Tuple)):
            stack.extend(e.elts)
            continue
        if isinstance(e, (ast.Constant, ast.JoinedStr)):
            continue
        if isinstance(e, ast.Call):
            n = e.func.attr if isinstance(e.func, ast.Attribute) else getattr(e.func, "id", "")
            if n in _SCALAR_CASTS:
                continue
        if isinstance(e, ast.Attribute) and re.match(r"^\w+\.params\.\w+$", _chain(e) or ""):
            continue
        if isinstance(e, ast.BinOp):
            continue                     # string concatenation / arithmetic: a scalar
        if isinstance(e, ast.Name) and (e.id in scalar_names or (tainted_names is not None and e.id not in tainted_names)):
            continue                     # a route-parameter alias, or a value no request data reaches (`model: Product`)
        return True
    return False


def _abstract(fn) -> bool:
    """An interface / abstract method: no body to summarize."""
    body = [st for st in getattr(fn, "body", []) if not (isinstance(st, ast.Expr) and isinstance(st.value, ast.Constant))]
    return not body or all(isinstance(st, ast.Pass) for st in body)


def _safe_static_param(ann) -> bool:
    """A statically typed handler parameter the framework converts to a number / date / UUID (binding fails
    otherwise), or a String constrained by an anchored @Pattern with no catch-all part."""
    if ann is None:
        return False
    name = (_annotation_name(ann) or "").split(".")[-1]
    if name in _NUMERIC_STATIC_TYPES:
        return True
    pat = getattr(ann, "vulnscan_pattern", None)
    return bool(pat) and pat.startswith("^") and pat.endswith("$") and not _PERMISSIVE_RE.search(pat)


class _TrackDict(dict):
    """A dict that records which keys are read while `holder[0]` is a set: the dependencies of the function being
    summarized, so the fixpoint re-analyzes only functions whose inputs changed (a worklist, not 16 full passes)."""
    __slots__ = ("holder", "kind")

    def __init__(self, data, holder, kind):
        super().__init__(data)
        self.holder, self.kind = holder, kind

    def get(self, k, d=None):
        deps = self.holder[0]
        if deps is not None:
            deps.add((self.kind, k))
        return dict.get(self, k, d)

    def __getitem__(self, k):
        deps = self.holder[0]
        if deps is not None:
            deps.add((self.kind, k))
        return dict.__getitem__(self, k)


class _Env:
    __slots__ = ("tainted", "types", "inst", "elem", "funcs", "consts", "dk", "webreq", "params", "vfields")

    def __init__(self):
        self.vfields: set = set()  # request fields an express-validator route middleware checked strictly
        self.webreq: set = set()  # parameters that are inbound web request objects (request.args … are sources)
        self.params: set = set()  # every parameter name of the function
        self.tainted: dict = {}   # var -> origin  (kind, label, trail)
        self.types: dict = {}     # var -> class qual
        self.inst: dict = {}      # var -> {field: origin}
        self.elem: set = set()    # vars tainted only through a non-head container element
        self.funcs: dict = {}     # var -> function qual (h = helper / partial)
        self.consts: dict = {}    # var -> known constant at this point (flow refinement only)
        self.dk: dict = {}        # var -> ({const key: origin}, other-keys origin) (flow refinement only)


_CONFINEMENT = {"is_relative_to", "isRelativeTo"}
# patterns that accept (almost) any text: `.*`, `.{1,64}`, `\S+`, `[^x]+`, `[\s\S]*`, `[\w\W]` …, `\W`, `(?s)`
_PERMISSIVE_RE = re.compile(r"(?<!\\)\.(?:[*+]|\{\d*,?\d*\})|\\S(?:[*+]|\{)|\[\^[^\]]*\](?:[*+]|\{)|\\W|\(\?s\)"
                            r"|\[(?:[^\]]*?)(?:\\s[^\]]*\\S|\\S[^\]]*\\s|\\w[^\]]*\\W|\\W[^\]]*\\w|\\d[^\]]*\\D|\\D[^\]]*\\d)")
_NOT_VALIDATION = {"startswith", "endswith", "starts_with", "ends_with", "str_starts_with", "str_ends_with", "exists",
                   "fileexists", "file_exists", "isset", "empty", "isempty", "isnullorempty", "isnullorwhitespace", "is_dir",
                   "is_file", "strpos", "str_contains", "isascii", "isblank", "notempty", "notnull", "isnotempty"}
_MEMBERSHIP = {"contains", "includes", "containskey", "containsvalue", "has", "haskey", "in_array", "array_key_exists",
               "array_search", "key?", "include?", "member?", "issubset"}
_SHAPE_CHECKS = {"isalnum", "isalpha", "isdigit", "isdecimal", "isnumeric", "isidentifier", "fullmatch", "matches"}


def _chain(e) -> str:
    """`a.b.c` for a pure attribute chain rooted at a name, else ""."""
    parts = []
    while isinstance(e, ast.Attribute):
        parts.append(e.attr)
        e = e.value
    if isinstance(e, ast.Name):
        return ".".join([e.id] + parts[::-1])
    return ""


# Attributes of a Python web request object that the SERVER fills in: the session store (server-side, or a signed
# cookie the client cannot change), the authenticated user, the matched route, the application object. Reading them
# is not reading client input (request.GET / .POST / .META / .body / .headers stay sources).
_SERVER_STATE_ATTRS = frozenset({"session", "user", "auser", "resolver_match", "urlconf", "app", "config_dict",
                                 "current_app", "state", "_messages", "csrf_processing_done"})

_TEST_MODULE = re.compile(r"(^|/)(tests?|testing)(/|$)|(^|/)test_[^/]*$|_tests?\.py$|(^|/)testcases\.py$|(^|/)conftest\.py$")

_MEMBERSHIP_CALLS = {"hasOwnProperty", "hasOwn", "has", "includes", "contains", "containsKey", "has_key",
                     "key?", "include?", "array_key_exists", "in_array"}

def _key_guard(test, value):
    """A ternary `test ? value : other` that lets `value` through only when it is a member of a fixed table:
    `k in table ? k : d`, `table.hasOwnProperty(k) ? k : d`, `allowed.includes(k) ? k : d` (an allow-list
    check, as `if k in ALLOWED` is) -> "all"; `table[k] ? k : d` (the key names an entry of `table`, so a
    later `table[k](…)` can only call what the table holds, or a built-in Object.prototype method, never a
    function the caller names) -> safe for dynamic dispatch only. None when the test checks something else.
    The second value is the table / allow-list expression: a guard against a table the CLIENT fills
    (`k in req.query ? k : ''`) proves nothing, so the caller drops the guard when that expression is tainted."""
    k = _chain(value)
    if not k:
        return None, None
    if isinstance(test, ast.Subscript) and _chain(test.slice) == k and _chain(test.value):
        return frozenset({"DF026@" + _chain(test.value)}), test.value   # safe only for a dispatch on that same table
    if isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.In) and _chain(test.left) == k:
        return "all", test.comparators[0]
    if isinstance(test, ast.Call):
        name = test.func.attr if isinstance(test.func, ast.Attribute) else test.func.id if isinstance(test.func, ast.Name) else ""
        args = test.args
        table = test.func.value if isinstance(test.func, ast.Attribute) else None
        if name == "call" and isinstance(test.func, ast.Attribute) and isinstance(test.func.value, ast.Attribute):
            name, table, args = test.func.value.attr, (args[0] if args else None), args[1:]  # Object.prototype.hasOwnProperty.call(t, k)
        if name in _MEMBERSHIP_CALLS and any(_chain(a) == k for a in (args[-1:] if name == "hasOwn" else args[:1])):
            if name == "hasOwn" or (isinstance(test.func, ast.Name) and len(args) > 1):
                table = test.args[0] if name == "hasOwn" else args[1]   # Object.hasOwn(t, k) / in_array($k, $allowed)
            return "all", table              # Object.hasOwn(t, k) / PHP in_array($k, $allowed) / array_key_exists($k, $t)
    return None, None


def _paths(expr) -> set:
    """Access paths read by an expression: names, and whole attribute chains (`file.filename`), so validating
    one field of an object does not validate its other fields. A subscript stands for its container's path."""
    out: set = set()
    if expr is None:
        return out
    stack = [expr]
    while stack:
        e = stack.pop()
        c = _chain(e) if isinstance(e, (ast.Name, ast.Attribute)) else ""
        if c:
            out.add(c)
            continue
        if isinstance(e, ast.Subscript):
            stack.append(e.value)
            stack.append(e.slice)
            continue
        if isinstance(e, ast.Call) and isinstance(e.func, ast.Attribute) and e.func.attr in _STR_TRANSFORMS:
            stack.append(e.func.value)          # x.strip().lower(): still the value of x
            stack.extend(e.args)
            continue
        stack.extend(ast.iter_child_nodes(e))
    return out


_STR_TRANSFORMS = frozenset({"strip", "lstrip", "rstrip", "lower", "upper", "casefold", "title", "trim", "trimStart",
                             "trimEnd", "toLowerCase", "toUpperCase", "toLower", "toUpper", "ToLower", "ToUpper", "Trim",
                             "decode", "encode", "toString", "ToString", "intern"})


def _path_covered(p: str, validated: set) -> bool:
    return any(p == v or p.startswith(v + ".") for v in validated)


def _names(expr) -> set:
    return {n.id for n in ast.walk(expr) if isinstance(n, ast.Name)} if expr is not None else set()


def _step(path, line, text):
    return {"file": path, "line": line, "text": text}


def _trail(o):
    return o[2] if len(o) > 2 else ()


def _with_step(o, step):
    return (o[0], o[1], _trail(o) + (step,)) + tuple(o[3:])


_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"}
_SHELL_FLAGS = {"-c", "-lc", "-ec", "-xc", "/c", "/C", "/k", "/K", "-Command", "-command"}


def _shell_launcher(elts) -> bool:
    """["sh", "-c", script] / ["cmd", "/c", line]: the third element is a whole command line, not one argument."""
    if len(elts) < 3 or not all(isinstance(e, ast.Constant) and isinstance(e.value, str) for e in elts[:2]):
        return False
    return elts[0].value.replace("\\", "/").rsplit("/", 1)[-1] in _SHELLS and elts[1].value in _SHELL_FLAGS


def _origin_params(o) -> set:
    """Parameters a "param" origin stands for: its own and any others merged into the same value (o[4])."""
    if not o or o[0] != "param":
        return set()
    return {o[1]} | set(o[4] if len(o) > 4 else ())


def _with_params(o, names) -> tuple:
    extra = frozenset((set(o[4]) if len(o) > 4 else set()) | (set(names) - {o[1]}))
    return (o[0], o[1], _trail(o), _safe_for(o), extra) + tuple(o[5:])


def _safe_for(o) -> frozenset:
    """CWEs this origin was escaped for (context-specific sanitizers), e.g. html.escape -> XSS only."""
    return o[3] if len(o) > 3 else frozenset()


def _unsafe_for(o, si) -> bool:
    """Does taint origin `o` still matter for sink `si`? False when it was escaped for that sink's CWE, or when a
    LOCAL source (command line, environment, console) names a file or a URL: the operator choosing what to open or
    fetch is the program's function, not an attack (CodeQL's default threat model likewise leaves local sources out)."""
    if not o:
        return False
    sf = _safe_for(o)
    return not si or (si[5] not in sf and si[0] not in sf and (len(si) <= 10 or si[10] not in sf))


_PATH_CWES = frozenset({"CWE-22", "CWE-23", "CWE-36", "CWE-73"})
# What the operator's own input (command line, environment, console) may legitimately choose: which file to open
# and which URL to fetch are the program's function, not an attack on it.
_LOCAL_SAFE_CWES = _PATH_CWES | {"CWE-918", "CWE-79", "CWE-80", "CWE-601", "CWE-117", "CWE-93", "CWE-113", "CWE-470"}
# (the operator cannot attack their own terminal, log or browser redirect: remote-only classes, as CodeQL's
# default threat model; injection into a shell, SQL or code from local input stays reported)
# Local sources (the operator's own command line, environment, console): naming a file is the program's
# function, so they are "safe for" path sinks. Matched on canonical source names, never on labels or helpers.
_LOCAL_SOURCE_NAMES = frozenset({
    "sys.argv", "os.environ", "os.getenv", "os.environ.get", "getenv", "input", "raw_input", "sys.stdin.read",
    "sys.stdin.readline", "getpass.getpass", "click.prompt", "argparse.ArgumentParser.parse_args",
    "process.argv", "process.env", "System.getenv", "System.getProperty", "os.Args", "Environment.GetCommandLineArgs",
    "Environment.GetEnvironmentVariable", "CommandLine.arguments", "ProcessInfo.processInfo.arguments",
    "ProcessInfo.processInfo.environment", "ARGV", "ENV", "STDIN", "$argv", "argv", "environ", "std.cin", "cin"})


# What a context-specific sanitizer neutralizes, recognised by naming conventions shared across languages.
# A sanitizer that matches none of these (int(), parseInt, uuid.UUID, len, hash …) converts the value to
# something inert and is universal. Order matters: the first match wins.
_XSS = ("CWE-79", "CWE-80", "CWE-116")
_SANITIZER_CONTEXTS = [
    (re.compile(r"(?i)shell|shlex|escapeshell|shellwords|encodeforos|forcommand"), ("CWE-78", "CWE-88")),
    (re.compile(r"(?i)sql|real_escape|addslashes|quote_ident|identifier|enquote|dbms_assert|quote_string|"
                r"quote_column|quote_table|connection\.quote|mysql.*escape|pg.*escape|escape_?literal"), ("CWE-89", "CWE-564")),
    (re.compile(r"(?i)ldap|filter_chars|fordn\b"), ("CWE-90",)),
    (re.compile(r"(?i)xpath"), ("CWE-643",)),
    (re.compile(r"(?i)^re\.escape$|(^|\.)escape_?regex|quotemeta|regex\.escape|preg_quote"), ("CWE-625", "CWE-730", "CWE-1333")),
    (re.compile(r"(?i)javascript|jsescape|js_?string|forjs"), ("CWE-94", "CWE-95") + _XSS),
    (re.compile(r"(?i)json\.dumps|json\.stringify|^repr$|^ascii$"), ("CWE-94", "CWE-95")),   # does not escape < >
    # component encoders also encode '/' (and so defeat ../ traversal); encodeURI / urllib quote() keep '/'
    (re.compile(r"(?i)encodeuricomponent|quote_plus|queryescape|pathescape|rawurlencode|^urlencode$|"
                r"urlencoder\.encode|urlencode$|encodeurlparameter|topercentencoding|curl_easy_escape|encodeforurl|forurl$|foruricomponent"),
     ("CWE-113", "CWE-93", "CWE-22", "CWE-23", "CWE-36", "CWE-73") + _XSS),
    (re.compile(r"(?i)(^|[._])(url|uri)|url_?(en|de)code|encodeuri|urlescape|^quote$|\.quote$|percent|http_build_query"),
     ("CWE-113", "CWE-93") + _XSS),
    (re.compile(r"(?i)basename|secure_filename|getname$|filepath\.base|path\.base|^base$|lastpathcomponent|"
                r"(^|\.)filename$|(^|\.)stem$"), ("CWE-22", "CWE-23", "CWE-36", "CWE-73")),
    (re.compile(r"(?i)html|xml|escape|sanitize|purify|bleach|strip_tags|markup|he\.encode|forhtml|encode_text|"
                r"encode_safe|askama"), _XSS),
]


_JS_CTX = ("CWE-94", "CWE-95") + _XSS
_REGEX_CTX = ("CWE-625", "CWE-730", "CWE-1333")
# Exact names whose meaning the naming conventions would get wrong. "none" = not a sanitizer at all.
_SANITIZER_OVERRIDES = {
    "realpath": "none", "normalize": "none", "Normalizer.normalize": "none", "Paths.normalize": "none",
    "os.path.normpath": "none", "normpath": "none", "path.normalize": "none", "filepath.Clean": "none",
    "Pattern.quote": _REGEX_CTX, "json_encode": _JS_CTX, "esc_js": _JS_CTX, "e": _XSS, "esc_attr": _XSS,
    "esc_html": _XSS, "wp_kses": _XSS, "Jsoup.clean": _XSS, "xss": _XSS, "filter_var": _XSS, "filter_input": _XSS,
    "strip_tags": _XSS, "htmlspecialchars": _XSS, "htmlentities": _XSS,
}
# escape/quote methods on a database handle quote SQL literals (mysql connection.escape, PDO::quote, knex.raw …)
_DB_ESCAPE = re.compile(r"(?i)(^|[.$])(connection|conn|con|pool|db|database|mysql|mysqli|pg|pgp|client|pdo|knex|sequelize|"
                        r"sql|cursor|dbh|link)\.(escape|escapeid|escape_string|real_escape_string|quote|escapeliteral|"
                        r"escapeidentifier|quote_ident|quote_literal)$")


def sanitizer_context(name: str):
    """frozenset of CWEs a sanitizer neutralizes, None when it is universal (value conversion), or "none" when
    the name is not a sanitizer at all (realpath / normalize resolve a path, they do not confine it)."""
    ov = _SANITIZER_OVERRIDES.get(name) or _SANITIZER_OVERRIDES.get(name.split(".")[-1] if name.count(".") == 0 else name)
    if ov == "none":
        return "none"
    if ov:
        return frozenset(ov)
    if _DB_ESCAPE.search(name):
        return frozenset(("CWE-89", "CWE-564"))
    for rx, cwes in _SANITIZER_CONTEXTS:
        if rx.search(name):
            return frozenset(cwes)
    if re.search(r"(?i)encode|escape|quote|sanitiz|clean|purif", name):
        return frozenset(_XSS + ("CWE-113", "CWE-93"))   # an escaper of unknown context: output encoding at most
    return None


def _class_facts(c: dict) -> tuple:
    """Snapshot of the class facts a method analysis may update (compared to detect a real change)."""
    return (dict(c["tainted_fields"]), dict(c["ctor_param_fields"]), dict(c["field_types"]),
            {m: {p: set(f) for p, f in slot.items()} for m, slot in c["method_param_fields"].items()})


class Project:
    def __init__(self, models: dict | None = None):
        self.m = models or load_models()
        self.files: dict[str, dict] = {}
        self.diagnostics: dict[str, dict] = {}   # rel path -> frontend parse diagnostics (skipped statements)
        self.too_deep: list[str] = []             # files left out of dataflow: nesting too deep to analyze safely
        self.field_precise_locals = False         # PL/SQL: `rec.col := v` taints the field, not the whole record
        self.gfuncs: dict[str, dict] = {}
        self.classes: dict[str, dict] = {}
        self.simple_funcs: dict[str, list] = {}
        self._by_mod: dict = {}     # (index id, short name, module) -> quals: O(1) same-module lookups
        self.simple_methods: dict[str, list] = {}
        self.simple_classes: dict[str, list] = {}
        self.summaries: dict[str, dict] = {}
        self.lines_by_path: dict[str, list] = {}
        self._parents_cache: dict[int, dict] = {}
        self._calls_cache: dict = {}
        self._sink_cache: dict = {}
        self._source_cache: dict = {}
        self._sanitizer_cache: dict = {}
        self._resolve_cache: dict = {}
        self.findings: list[Finding] = []

    # ------------------------------------------------------------ building
    def add_file(self, mod: str, path: str, text: str, is_pkg: bool = False, tree: ast.AST | None = None,
                 lines: list | None = None) -> bool:
        if tree is None:
            try:
                tree = ast.parse(text)
            except (SyntaxError, ValueError, MemoryError, RecursionError):   # generated/hostile code: skip the file
                return False
        facts = self.__dict__.get("_shared_file_facts")
        hit = facts.get(id(tree)) if facts is not None else None
        if hit is not None and hit[0] is not tree:
            hit = None
        if hit is None and too_deep(tree):
            # generated / hostile nesting would overflow the recursive analyses: leave out only the functions or
            # top-level statements that are too deep, keep analysing the rest of the file
            pruned = _prune_too_deep(tree)
            self.too_deep.append(path + (f" ({', '.join(pruned[:3])}{' …' if len(pruned) > 3 else ''})" if pruned else ""))
            if too_deep(tree):
                return False
        if hit is None or hit[1] != (mod, is_pkg):
            hit = (tree, (mod, is_pkg), self._aliases(tree, mod, is_pkg))
            if facts is not None:
                facts[id(tree)] = hit          # a tree that passed the depth check, and its import aliases
        file = {"path": path, "tree": tree, "aliases": dict(hit[2]), "funcs": {},
                "classes": {}, "lines": lines if lines is not None else text.splitlines(), "assign_aliases": []}
        self.files[mod] = file
        self.lines_by_path[path] = file["lines"]
        for st in tree.body:
            if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name) \
                    and isinstance(st.value, (ast.Name, ast.Attribute)):
                local, dotted = st.targets[0].id, _dotted(st.value)
                file["assign_aliases"].append((local, dotted))
                # name aliases of imported things: fs = __req1 / run = subprocess.run / exec = cp.exec
                first, _, rest = dotted.partition(".")
                tgt = file["aliases"].get(first)
                if tgt and local not in file["aliases"]:
                    base = tgt[1] if tgt[0] == "mod" else (f"{tgt[1]}.{tgt[2]}" if tgt[1] else tgt[2])
                    full = f"{base}.{rest}" if rest else base
                    modpart, _, name = full.rpartition(".")
                    file["aliases"][local] = ("from", modpart, name) if modpart else ("mod", full)

        def visit(node, cls_qual, parent_func=None):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.ClassDef):
                    cq = f"{mod}::{child.name}"
                    self.classes[cq] = {"node": child, "mod": mod, "name": child.name, "path": path,
                                        "base_names": [_dotted(b) for b in child.bases], "bases": [],
                                        "methods": {}, "subclasses": set(), "field_types": {},
                                        "tainted_fields": {}, "ctor_param_fields": {}, "method_param_fields": {}}
                    file["classes"][child.name] = cq
                    self.simple_classes.setdefault(child.name, []).append(cq)
                    self._by_mod.setdefault((id(self.simple_classes), child.name, mod), []).append(cq)
                    visit(child, cq, parent_func)
                elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if cls_qual:
                        q = f"{cls_qual}.{child.name}"
                        self.classes[cls_qual]["methods"][child.name] = q
                        self.simple_methods.setdefault(child.name, []).append(q)
                    else:
                        q = f"{mod}::{child.name}"
                        file["funcs"][child.name] = q
                        self.simple_funcs.setdefault(child.name, []).append(q)
                        self._by_mod.setdefault((id(self.simple_funcs), child.name, mod), []).append(q)
                    self.gfuncs[q] = {"node": child, "mod": mod, "name": child.name, "cls": cls_qual, "path": path,
                                      "enclosing": ([parent_func] + self.gfuncs[parent_func]["enclosing"]) if parent_func else []}
                    visit(child, None, q)
                else:
                    visit(child, cls_qual, parent_func)

        visit(tree, None, None)
        return True

    @staticmethod
    def _aliases(tree: ast.AST, mod: str, is_pkg: bool) -> dict:
        al = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if node.level:
                    base = mod if is_pkg else ".".join(mod.split(".")[:-1])
                    for _ in range(node.level - 1):
                        base = ".".join(base.split(".")[:-1])
                    module = f"{base}.{module}" if module and base else (base or module)
                for a in node.names:
                    al[a.asname or a.name] = ("from", module, a.name)
            elif isinstance(node, ast.Import):
                for a in node.names:
                    al[a.asname or a.name] = ("mod", a.name)
        return al

    def link(self):
        self._hier_cache = {}
        for cq, c in self.classes.items():
            for bname in c["base_names"]:
                bq = self._resolve_class(c["mod"], bname)
                if bq and bq != cq:
                    c["bases"].append(bq)
                    self.classes[bq]["subclasses"].add(cq)
        for mod, file in self.files.items():
            for local, target in file["assign_aliases"]:
                q = self._resolve_function(mod, target)
                if q and local not in file["funcs"]:
                    file["funcs"][local] = q

    # ---------------------------------------------------------- resolution
    def _canon(self, mod: str, node: ast.AST) -> str:
        """Dotted name with import aliases expanded (sp.run -> subprocess.run)."""
        name = _dotted(node)
        if not name:
            return ""
        first, _, rest = name.partition(".")
        tgt = self.files.get(mod, {}).get("aliases", {}).get(first)
        if tgt:
            base = tgt[1] if tgt[0] == "mod" else (f"{tgt[1]}.{tgt[2]}" if tgt[1] else tgt[2])
            return f"{base}.{rest}" if rest else base
        return name

    def _match(self, index: dict, name: str, modhint: str, caller: str | None = None) -> str | None:
        cands = index.get(name)
        if not cands:
            return None
        hint = modhint.lstrip(".")
        if hint:
            exact = self._by_mod.get((id(index), name, hint))
            if exact:
                return exact[0]
            pool = cands
            if len(cands) > 64:              # large projects: suffix matches only among modules sharing the last part
                tail = hint.split(".")[-1]
                pool = [q for q in cands if q.split("::")[0].split(".")[-1] == tail or hint.endswith(q.split("::")[0])]
            best = [q for q in pool if q.split("::")[0].endswith(hint) or hint.endswith(q.split("::")[0])]
            if len(best) > 1 and caller is not None:
                # `import libuser` resolves like Python's sys.path: the importing module's own package first, then
                # the module sharing the longest package prefix; production code never to a tests/ module
                cpkg = caller.split(".")[:-1]

                def rank(q):
                    qp = q.split("::")[0].split(".")
                    common = 0
                    for a, b in zip(cpkg, qp[:-1]):
                        if a != b:
                            break
                        common += 1
                    testy = any(x in ("tests", "test", "testing") for x in qp[:-1]) and not any(x in ("tests", "test", "testing") for x in cpkg)
                    return (testy, -common)
                best = sorted(best, key=rank)
            if best:
                return best[0]
        return cands[0] if len(cands) == 1 else None

    def _resolve_class(self, mod: str, name: str) -> str | None:
        if not name:
            return None
        key = ("c", mod, name)
        if key in self._resolve_cache:
            return self._resolve_cache[key]
        res = self._resolve_class_uncached(mod, name)
        self._resolve_cache[key] = res
        return res

    def _resolve_class_uncached(self, mod: str, name: str) -> str | None:
        file = self.files.get(mod, {})
        short = name.split(".")[-1]
        if name == short and short in file.get("classes", {}):
            return file["classes"][short]
        tgt = file.get("aliases", {}).get(name) or file.get("aliases", {}).get(name.split(".")[0])
        if tgt and tgt[0] == "from":
            q = self._match(self.simple_classes, tgt[2] if name == name.split(".")[0] else short, tgt[1])
            if q:
                return q
        if "." in name:
            parts = name.split(".")
            q = self._match(self.simple_classes, parts[-1], ".".join(parts[:-1]))
            if q:
                return q
        cands = self.simple_classes.get(short)
        if cands:
            same = self._by_mod.get((id(self.simple_classes), short, mod))
            if same:
                return same[0]
            if len(cands) == 1:
                return cands[0]
        return None

    def _resolve_function(self, mod: str, name: str) -> str | None:
        key = ("f", mod, name)
        if key in self._resolve_cache:
            return self._resolve_cache[key]
        res = self._resolve_function_uncached(mod, name)
        self._resolve_cache[key] = res
        return res

    def _external_module(self, modname: str) -> bool:
        """Python only: is `modname` (an imported module) outside the scanned project (`json`, `os.path`,
        `requests`)? Its functions are library code, never a project function that happens to share the name
        (`json.load(resp)` is not the project's own `triage.load`)."""
        if self.m.get("language") != "python" or not modname or modname.startswith("."):
            return False
        known = self.__dict__.get("_project_mod_parts")
        if known is None or known[0] != len(self.files):
            parts: set = set()
            for m in self.files:
                segs = m.split(".")
                # every run of segments: suffixes (`import b` inside package `pkg` finds pkg.b), prefixes (`import pkg`
                # then `pkg.b.load()`) and middle runs (src layout without __init__.py: `src.pkg.sub.helpers` is
                # imported as `pkg.sub.helpers` and called through `import pkg` as `pkg.sub.helpers.run()`)
                for i in range(len(segs)):
                    for j in range(i + 1, len(segs) + 1):
                        parts.add(".".join(segs[i:j]))
            known = self.__dict__["_project_mod_parts"] = (len(self.files), parts)
        return modname not in known[1]

    def _resolve_function_uncached(self, mod: str, name: str) -> str | None:
        file = self.files.get(mod, {})
        short = name.split(".")[-1]
        if name == short and short in file.get("funcs", {}):
            return file["funcs"][short]
        tgt = file.get("aliases", {}).get(name) or file.get("aliases", {}).get(short)
        if tgt and tgt[0] == "from":
            if self._external_module(tgt[1]) and (name == short or file.get("aliases", {}).get(name) is tgt):
                return None                     # `from json import load`: the library function
            q = self._match(self.simple_funcs, tgt[2], tgt[1], mod)
            if q:
                return q
        if "." in name:
            parts = name.split(".")
            if parts[0] in ("self", "cls", "this") and len(parts) == 2:
                return None                     # `self._json(...)`: a method (or field) of the object, never a module
                                                # function that happens to share the name (`sca._json`)
            head = file.get("aliases", {}).get(parts[0])
            if head and head[0] == "mod" and self._external_module(head[1]):
                return None                     # `json.load(...)` after `import json`: the library function
            q = self._match(self.simple_funcs, parts[-1], ".".join(parts[:-1]), mod)
            if q:
                return q
        cands = self.simple_funcs.get(short)
        if cands:
            same = self._by_mod.get((id(self.simple_funcs), short, mod))
            if same:
                return same[0]
            if len(cands) == 1:
                return cands[0]
        return None

    def _mro(self, cq: str) -> list[str]:
        cache = self.__dict__.setdefault("_hier_cache", {})
        key = ("mro", cq)
        hit = cache.get(key)
        if hit is None:
            hit = cache[key] = self._mro_uncached(cq)
        return hit

    def _mro_uncached(self, cq: str) -> list[str]:
        out, stack = [], [cq]
        while stack:
            c = stack.pop(0)
            if c in out or c not in self.classes:
                continue
            out.append(c)
            stack.extend(self.classes[c]["bases"])
        return out

    def _all_subclasses(self, cq: str) -> set[str]:
        cache = self.__dict__.setdefault("_hier_cache", {})
        key = ("sub", cq)
        hit = cache.get(key)
        if hit is None:
            hit = cache[key] = self._all_subclasses_uncached(cq)
        return hit

    def _all_subclasses_uncached(self, cq: str) -> set[str]:
        out, stack = set(), [cq]
        while stack:
            c = stack.pop()
            for s in self.classes.get(c, {}).get("subclasses", ()):
                if s not in out:
                    out.add(s)
                    stack.append(s)
        return out

    def _class_fields(self, cq: str, key: str) -> dict:
        merged: dict = {}
        for c in reversed(self._mro(cq)):
            merged.update(self.classes[c][key])
        return merged

    def _lookup_method(self, cq: str, name: str) -> list[str]:
        cache = self.__dict__.setdefault("_hier_cache", {})
        key = ("m", cq, name)
        hit = cache.get(key)
        if hit is None:
            hit = cache[key] = self._lookup_method_uncached(cq, name)
        return list(hit)

    def _lookup_method_uncached(self, cq: str, name: str) -> list[str]:
        found = []
        for c in self._mro(cq):
            q = self.classes[c]["methods"].get(name)
            if q:
                found.append(q)
                break
        prod = not _TEST_MODULE.search(self.classes[cq]["path"]) if cq in self.classes else True
        for s in self._all_subclasses(cq):
            if prod and _TEST_MODULE.search(self.classes[s]["path"]):
                continue            # an override in a test module never runs in production: `self.form_valid()`
                                    # in Django's ProcessFormView is not the test suite's subclass
            q = self.classes[s]["methods"].get(name)
            if q and q not in found:
                found.append(q)
        return found

    def _callees(self, mod: str, cls: str | None, call: ast.Call, env: _Env) -> tuple[list[str], str | None]:
        """Static resolution (types, imports, names) unioned with points-to resolution (objects, function values)."""
        static, ctor = self._callees_static(mod, cls, call, env)
        pt = getattr(self, "pt", None)
        if pt is not None and not ctor:
            extra = [q for q in pt.callees_for_call(call) if q not in static and q in self.gfuncs]
            if extra:
                return static + sorted(extra), None
        return static, ctor

    def _dotted_safe(self, node) -> str:
        return _dotted(node)

    def _callees_static(self, mod: str, cls: str | None, call: ast.Call, env: _Env) -> tuple[list[str], str | None]:
        f = call.func
        if isinstance(f, ast.Name):
            if f.id in env.funcs:
                return [env.funcs[f.id]], None
            cq = self._resolve_class(mod, f.id)
            if cq:
                return self._lookup_method(cq, "__init__"), cq
            q = self._resolve_function(mod, f.id)
            if q is None and cls and cls in self.classes and self.m.get("language") not in ("python", "javascript", "plsql"):
                # Java / C# / Kotlin / Ruby / Swift / C++: a bare `find(id)` inside a class is `this.find(id)`
                found = self._lookup_method(cls, f.id)
                if found:
                    return found, None
            return ([q] if q else []), None
        if isinstance(f, ast.Attribute):
            recv = f.value
            is_super = (isinstance(recv, ast.Name) and recv.id == "super") or \
                (isinstance(recv, ast.Call) and isinstance(recv.func, ast.Name) and recv.func.id == "super")
            if is_super and cls and cls in self.classes:
                # Java / C# / PHP `super.execute(...)`: the implementation inherited from a base class
                for c in self._mro(cls)[1:]:
                    q = self.classes[c]["methods"].get(f.attr)
                    if q:
                        return [q], None
            rtype = cls if (isinstance(recv, ast.Name) and recv.id in {"self", "cls"} and cls) else self._type_of(mod, cls, recv, env)
            if rtype:
                return self._lookup_method(rtype, f.attr), None
            if isinstance(recv, (ast.Name, ast.Attribute)) and not (isinstance(recv, ast.Name) and recv.id in env.tainted):
                # Student.create(...) / models.Student.create(...): a static or class method called on the class
                rd = _dotted(recv)
                cq = self._resolve_class(mod, rd) if rd and rd.split(".")[-1][:1].isupper() else None
                if cq:
                    found = self._lookup_method(cq, f.attr)
                    if found:
                        return found, None
            if isinstance(recv, ast.Name):
                tgt = self.files.get(mod, {}).get("aliases", {}).get(recv.id)
                if tgt and tgt[0] == "mod":
                    if self._external_module(tgt[1]):
                        return [], None         # `json.load(resp)`: a library function, not a project function `load`
                    q = self._match(self.simple_funcs, f.attr, tgt[1], mod)
                    if q:
                        return [q], None
                    cq = self._match(self.simple_classes, f.attr, tgt[1], mod)
                    if cq:
                        return self._lookup_method(cq, "__init__"), cq
            name = _dotted(f)
            if "." in name:
                q = self._resolve_function(mod, name)
                if q:
                    return [q], None
            if self._container_field(cls, recv):
                return [], None                 # self.parts.add(x) on a list field is a list write, not Cmd.add
            cands = self.simple_methods.get(f.attr, [])
            if len(cands) == 1 and not isinstance(recv, ast.Call) and f.attr not in _LIBRARY_METHOD_NAMES:
                # the only project method with that name; never for a call on a library value
                # (`new StringBuilder(x).toString()`, `entry.getValue()`): that resolves to an unrelated class
                return cands, None
            same = [q for q in cands if q.split("::")[0] == mod]
            if len(same) == 1:
                if isinstance(recv, ast.Call) and not is_super and not any(self._callees(mod, cls, recv, env)):
                    # a call on a library value (`Base64.getDecoder().decode(s)`) is not this file's own `decode`
                    return [], None
                return same, None
        return [], None

    _CONTAINER_CTORS = {"list", "dict", "set", "frozenset", "tuple", "deque", "defaultdict", "OrderedDict", "Counter",
                        "ArrayList", "LinkedList", "Vector", "HashMap", "LinkedHashMap", "TreeMap", "Hashtable", "HashSet",
                        "LinkedHashSet", "TreeSet", "ArrayDeque", "ConcurrentHashMap", "CopyOnWriteArrayList",
                        "StringBuilder", "StringBuffer", "List", "Dictionary", "HashSet", "Queue", "Stack", "Map", "Set",
                        "mutableListOf", "mutableMapOf", "mutableSetOf", "arrayListOf", "hashMapOf", "make"}

    def _container_field(self, cls, recv) -> bool:
        """Is `recv` a `self.<field>` that the class initialises with a collection (`self.parts = []`,
        `private List<String> parts = new ArrayList<>()`)?"""
        if not (cls and isinstance(recv, ast.Attribute) and isinstance(recv.value, ast.Name) and recv.value.id == "self"):
            return False
        cache = self.__dict__.setdefault("_container_fields", {})
        if cls not in cache:
            found = set()
            node = self.classes.get(cls, {}).get("node")
            for n in ast.walk(node) if node is not None else ():
                if isinstance(n, (ast.Assign, ast.AnnAssign)) and n.value is not None:
                    v = n.value
                    is_coll = isinstance(v, (ast.List, ast.Dict, ast.Set, ast.ListComp, ast.DictComp, ast.SetComp)) or (
                        isinstance(v, ast.Call) and _dotted(v.func).split(".")[-1] in self._CONTAINER_CTORS)
                    for t in (n.targets if isinstance(n, ast.Assign) else [n.target]):
                        if is_coll and isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) and t.value.id == "self":
                            found.add(t.attr)
            cache[cls] = found
        return recv.attr in cache[cls]

    # ---------------------------------------------------------------- types
    def _type_of(self, mod, cls, node, env) -> str | None:
        t = self._type_of_static(mod, cls, node, env)
        if t is None:
            pt = getattr(self, "pt", None)
            if pt is not None:
                cs = pt.classes_for(node)
                if len(cs) == 1:
                    return next(iter(cs))
        return t

    def _type_of_static(self, mod, cls, node, env) -> str | None:
        if isinstance(node, ast.Name):
            if node.id in {"self", "cls"} and cls:
                return cls
            return env.types.get(node.id)
        if isinstance(node, ast.Attribute):
            base = self._type_of(mod, cls, node.value, env)
            return self._class_fields(base, "field_types").get(node.attr) if base else None
        if isinstance(node, ast.Call):
            callees, ctor = self._callees(mod, cls, node, env)
            if ctor:
                return ctor
            for q in callees:
                rt = self.summaries.get(q, {}).get("ret_type")
                if rt:
                    return rt
            return None
        if isinstance(node, ast.Await):
            return self._type_of(mod, cls, node.value, env)
        return None

    # -------------------------------------------------------------- sources
    def _is_source(self, mod: str, node: ast.AST, cls=None, env=None) -> str | None:
        key = (mod, id(node))
        hit = self._source_cache.get(key)
        if hit is not None and hit[0] is node:
            res = hit[1]
        else:
            self._cur_cls = cls
            res = self._is_source_uncached(mod, node)
            self._source_cache[key] = (node, res)
        if res is None and env is not None and env.webreq and self.m.get("language") == "javascript":
            res = self._webreq_attr(node, env)
        if isinstance(res, tuple):          # ("?req", root, label): a bare `request.x`, decided per function
            _, root, label = res
            if env is not None and (root in env.webreq or (root not in env.params and self._web_module(mod))):
                return label
            if env is None and self._web_module(mod):
                return label
            return None
        return res

    def _webreq_attr(self, node, env):
        """`r.query` / `_p0.body` / `r.get('h')` where r is the request parameter of a route callback (any name)."""
        cur = node
        if isinstance(cur, ast.Call) and isinstance(cur.func, ast.Attribute):
            if cur.func.attr in ("get", "header", "param", "cookie", "accepts") and isinstance(cur.func.value, ast.Name) \
                    and cur.func.value.id in env.webreq:
                return f"req.{cur.func.attr}()"
            cur = cur.func.value if cur.func.attr in ("get", "getAll", "has") else cur.func
        if isinstance(cur, ast.Subscript):
            cur = cur.value
        if isinstance(cur, ast.Attribute) and isinstance(cur.value, ast.Name) and cur.value.id in env.webreq:
            koa = cur.value.id == "ctx"          # Koa's context: ctx.body is the response, not the request
            for roots, attrs, label in self.m["attr_sources"]:
                if cur.attr in attrs and (("ctx" in roots) if koa else ("req" in roots or "request" in roots)):
                    return label.replace("{attr}", cur.attr)
        return None

    # --------------------------------------------- which names are inbound web requests (Python / JavaScript)
    _PY_WEB = ("django", "flask", "quart", "starlette", "fastapi", "aiohttp", "tornado", "pyramid", "falcon", "bottle",
               "sanic", "rest_framework", "werkzeug", "cherrypy", "litestar", "hug", "ninja", "channels", "connexion",
               "flask_restful", "flask_restx", "responder", "webob", "web", "masonite", "molten", "emmett", "blacksheep")
    _JS_WEB = ("express", "koa", "fastify", "@hapi/hapi", "hapi", "restify", "next", "next/server", "http", "https",
               "node:http", "node:https", "connect", "polka", "@nestjs/common", "micro", "h3", "hono", "@koa/router",
               "koa-router", "express-serve-static-core", "@remix-run/node", "@sveltejs/kit", "aws-lambda", "@vercel/node",
               "@netlify/functions", "@azure/functions", "body-parser", "multer", "router")
    _WEB_REQUEST_TYPES = frozenset({
        "Request", "HttpRequest", "WSGIRequest", "ASGIRequest", "HTTPServerRequest", "BaseRequest", "WebSocket",
        "HTTPConnection", "NextRequest", "NextApiRequest", "IncomingMessage", "FastifyRequest", "Context",
        "ParameterizedContext", "RouterContext", "APIGatewayProxyEvent", "APIGatewayProxyEventV2", "HttpRequestMessage",
        "RequestEvent", "LoaderFunctionArgs", "ActionFunctionArgs", "Req", "HandlerEvent", "ALBEvent"})
    _NOT_WEB_REQUEST_MODULES = ("requests", "httpx", "urllib", "pytest", "_pytest", "unittest", "aiohttp.client",
                                "botocore", "google.auth", "grpc", "http.client", "node-fetch", "undici", "got", "axios",
                                "superagent", "supertest")

    def _web_module(self, mod) -> bool:
        """Does the module import a web framework (so a bare `request` / `req` is an inbound request)?"""
        cache = self.__dict__.setdefault("_web_mods", {})
        hit = cache.get(mod)
        if hit is None:
            al = (self.files.get(mod) or {}).get("aliases", {})
            web = self._JS_WEB if self.m.get("language") == "javascript" else self._PY_WEB
            hit = False
            for v in al.values():
                for x in (v[1:] if isinstance(v, tuple) else (v,)):
                    if isinstance(x, str) and x and (x in web or x.split(".")[0] in web or x.split("/")[0] in web):
                        hit = True
            cache[mod] = hit
        return hit

    def _gated_language(self) -> bool:
        return self.m.get("language") in ("python", "javascript")

    def _webreq_param(self, mod, cls, fn, p) -> bool:
        """Is parameter `p` (named like a request) an inbound web request? By its annotation when there is one
        (a web Request type yes; PreparedRequest, pytest.FixtureRequest, a local dataclass no), else by the module
        importing a web framework. Test fixtures never are."""
        for d in getattr(fn, "decorator_list", []):
            if _dotted(d.func if isinstance(d, ast.Call) else d).split(".")[-1] in ("fixture", "yield_fixture"):
                return False
        ann = getattr(p, "annotation", None)
        if ann is not None:
            name = _annotation_name(ann) or ""
            parts = [n for n in ast.walk(ann) if isinstance(n, (ast.Name, ast.Attribute))] or [ann]
            for part in parts:                      # `Request | PreparedRequest`: every alternative counts
                canon = self._canon(mod, part) if isinstance(part, (ast.Name, ast.Attribute)) else name
                if any(canon == m or canon.startswith(m + ".") for m in self._NOT_WEB_REQUEST_MODULES):
                    return False
            if name.split(".")[-1] in self._WEB_REQUEST_TYPES:
                return True
            return False
        if self.m.get("language") == "python" and p.arg != "request":
            # `req` is a view's request in a module that imports a web framework, or in a handler shape (falcon
            # `on_get(self, req, resp)`); in setup.py `def _pip_requirement(req)` it is a requirement line
            names = {x.arg for x in fn.args.posonlyargs + fn.args.args}
            return self._web_module(mod) or bool(names & {"resp", "res", "response"}) \
                or getattr(fn, "name", "").startswith("on_")
        if self.m.get("language") != "javascript" or self._web_module(mod):
            return True        # Python: an unannotated `request` parameter is a view's request by convention
        # JavaScript without a framework import: a handler shape `(req, res)`, `(ctx, next)`, `(event, context)`
        # or a conventional handler name; `flushSegment(request, d)` in a renderer is not an HTTP request
        names = [x.arg for x in fn.args.args]
        if set(names) & {"res", "response", "reply", "next", "h", "context", "callback", "cb", "resp", "done"}:
            return True
        if p.arg == "ctx" and len(names) == 1:
            return True
        if p.arg == "event" and getattr(fn, "name", "") not in ("handler", "default", "main", "lambdaHandler"):
            return False
        return getattr(fn, "name", "") in ("handler", "default", "main", "GET", "POST", "PUT", "PATCH", "DELETE",
                                            "HEAD", "OPTIONS", "middleware", "loader", "action")

    def _is_source_uncached(self, mod: str, node: ast.AST) -> str | None:
        cur = node
        if isinstance(cur, ast.Call) and isinstance(cur.func, ast.Attribute) \
                and cur.func.attr in {"get", "getlist", "getall", "get_argument", "getone"}:
            cur = cur.func.value
        elif isinstance(cur, ast.Call) and isinstance(cur.func, ast.Attribute):
            cur = cur.func                     # request.get_json() / request.get_data(): a call on a source attribute
        if isinstance(cur, ast.Subscript):
            cur = cur.value
        if isinstance(cur, ast.Attribute):
            root = _dotted(cur.value)
            for roots, attrs, label in self.m["attr_sources"]:
                if cur.attr in attrs and (root in roots or root in self.m["request_params"]
                                          or any(root.endswith("." + r) for r in roots)):
                    if root == "ctx" and self.m.get("language") == "javascript" and "ctx" not in roots:
                        continue                    # Koa: ctx.body is the response body (request: ctx.request.body)
                    if roots == {"ctx"} and root != "ctx":
                        continue                    # the Koa-only group: not for req / request
                    if self._gated_language() and root == "self":
                        # `self.path` / `self.headers` are request data only in a request-handler class
                        if not self._handler_class(getattr(self, "_cur_cls", None)):
                            continue
                    elif self._gated_language() and (root in self.m["request_params"] or root == "context"):
                        tgt = (self.files.get(mod) or {}).get("aliases", {}).get(root)
                        if tgt and tgt[0] == "from" and (tgt[1] or "").split(".")[0] in self._PY_WEB + self._JS_WEB:
                            return label.replace("{attr}", cur.attr)     # from flask import request
                        return ("?req", root, label.replace("{attr}", cur.attr))
                    return label.replace("{attr}", cur.attr)
        canon = self._canon(mod, node) if isinstance(node, (ast.Name, ast.Attribute, ast.Call)) else ""
        if isinstance(node, ast.Subscript):
            canon = self._canon(mod, node.value)
        if canon:
            for names, label in self.m["name_sources"]:
                if any(canon == n for n in names):
                    return label.replace("{name}", canon)
            if isinstance(node, (ast.Name, ast.Attribute)):
                for prefixes, label in self.m["prefix_sources"]:
                    if any(canon == p or (p.endswith(".") and canon.startswith(p)) for p in prefixes):
                        return label.replace("{name}", canon).replace("{last}", canon.rsplit(".", 1)[-1])
            if isinstance(node, ast.Call):
                for names, label in self.m["call_sources"]:
                    if any(_name_matches(canon, n) for n in names):
                        return label.replace("{name}", canon)
        return None

    _HANDLER_BASES = frozenset({"BaseHTTPRequestHandler", "SimpleHTTPRequestHandler", "CGIHTTPRequestHandler",
                                "StreamRequestHandler", "BaseRequestHandler", "DatagramRequestHandler", "WSGIRequestHandler"})

    def _handler_class(self, cls) -> bool:
        if not cls or cls not in self.classes:
            return False
        for c in self._mro(cls):
            if {b.split(".")[-1] for b in self.classes[c]["base_names"]} & self._HANDLER_BASES:
                return True
        return False

    def _is_local_source(self, mod, node) -> bool:
        cur = node.value if isinstance(node, ast.Subscript) else node
        if isinstance(cur, ast.Call) and isinstance(cur.func, ast.Attribute) and cur.func.attr in ("get", "getenv"):
            inner = self._canon(mod, cur.func.value)
            if inner in ("os.environ", "process.env", "ENV"):
                return True
        canon = self._canon(mod, cur.func if isinstance(cur, ast.Call) else cur) if isinstance(cur, (ast.Name, ast.Attribute, ast.Call)) else ""
        if canon in _LOCAL_SOURCE_NAMES:
            return True
        if canon.endswith((".parse_args", ".parse_known_args")) and isinstance(cur, ast.Call):
            # argparse only: Flask-RESTful reqparse.RequestParser().parse_args() reads the HTTP request
            aliases = (self.files.get(mod) or {}).get("aliases", {})
            mods = {str(v) for v in aliases.values()}
            return any("argparse" in m for m in mods) and not any("reqparse" in m or "flask_restful" in m for m in mods)
        return False

    def _is_sanitizer(self, canon: str) -> bool:
        """Universal sanitizer (the value becomes inert for every sink)."""
        return self._sanitizer_kind(canon) == "all"

    def _sanitizer_kind(self, canon: str):
        """None: not a sanitizer. "all": universal. frozenset: the CWEs it escapes for (context-specific)."""
        key = ("kind", canon)
        if key in self._sanitizer_cache:
            return self._sanitizer_cache[key]
        # the most specific model name wins (shlex.quote over a bare `quote`), independent of set order
        matches = [s for s in self.m["sanitizers"] if _name_matches(canon, s)]
        name = max(matches, key=lambda s: (s.count("."), len(s), s)) if matches else None
        kind = None
        if name is not None:
            if name in {"stored_db_read", "stored_db_config"} or name in self.m.get("user_sanitizers", ()):
                kind = "all"
            else:
                # the call's own name first (connection.escape is SQL even when the model only lists `escape`)
                ctx = sanitizer_context(canon) if (_DB_ESCAPE.search(canon) or canon in _SANITIZER_OVERRIDES) \
                    else sanitizer_context(name)
                kind = None if ctx == "none" else "all" if ctx is None else ctx
        self._sanitizer_cache[key] = kind
        return kind

    # ---------------------------------------------------------------- sinks
    def _sink_info(self, mod: str, call: ast.Call):
        key = (mod, id(call))
        hit = self._sink_cache.get(key)
        if hit is not None and hit[0] is call:
            return hit[1]
        # `getattr(logger, level)(msg, *args)` calls what getattr RETURNED: the outer call is not getattr itself
        canon = "" if isinstance(call.func, ast.Call) else self._canon(mod, call.func)
        res = None
        if canon:
            # sinks constrained by a receiver pattern are more specific than bare method names: try them first
            ordered = self.__dict__.get("_sinks_ordered")
            if ordered is None or ordered[0] is not self.m["sinks"] or ordered[1] != len(self.m["sinks"]):
                ordered = (self.m["sinks"], len(self.m["sinks"]),
                           sorted(self.m["sinks"], key=lambda e: 0 if len(e) > 11 and e[11] is not None else 1))
                self.__dict__["_sinks_ordered"] = ordered
            by_canon = self.__dict__.setdefault("_sinks_by_canon", {})
            cands = by_canon.get((id(ordered[2]), canon))
            if cands is None:
                # every way a model name can match (bare, dotted suffix, builtins.) needs the same last segment:
                # only those entries are tested, in the same order
                by_last = self.__dict__.get("_sinks_by_last")
                if by_last is None or by_last[0] is not ordered[2]:
                    idx: dict = {}
                    for i, e in enumerate(ordered[2]):
                        for n in e[9]:
                            lst = idx.setdefault(n.split(".")[-1], [])
                            if not lst or lst[-1] != i:
                                lst.append(i)
                    by_last = self.__dict__["_sinks_by_last"] = (ordered[2], idx)
                entries = ordered[2]
                cands = by_canon[(id(ordered[2]), canon)] = [
                    entries[i] for i in by_last[1].get(canon.split(".")[-1], ())
                    if any(_name_matches(canon, n) for n in entries[i][9])]
            for entry in cands:
                if True:
                    rx = entry[11] if len(entry) > 11 else None
                    if rx is not None and not (isinstance(call.func, ast.Attribute) and rx.search(_receiver_text(call.func.value))):
                        continue                        # e.g. `search` is LDAP only on a connection-like receiver
                    rxn = entry[13] if len(entry) > 13 else None
                    if rxn is not None and isinstance(call.func, ast.Attribute) and rxn.search(_receiver_text(call.func.value)):
                        continue                        # e.g. QuerySet.exists() is not pathlib's Path.exists()
                    safe_kw = entry[12] if len(entry) > 12 else None
                    if safe_kw and any(k.arg in safe_kw and (_dotted(k.value) or str(getattr(k.value, "value", ""))).split(".")[-1]
                                       in safe_kw[k.arg] for k in call.keywords):
                        continue                        # yaml.load(x, Loader=SafeLoader): the safe variant of the API
                    res = entry[:9] + entry[10:11]      # drop the name list, keep the named-argument set at index 9
                    break
        self._sink_cache[key] = (call, res)
        return res

    def _subprocess_elem_only(self, mod, cls, call, env) -> bool:
        kw = {k.arg: k.value for k in call.keywords}
        if isinstance(kw.get("shell"), ast.Constant) and kw["shell"].value is True:
            return False
        arg = call.args[0] if call.args else kw.get("args")
        if arg is None:
            return False
        if isinstance(arg, (ast.List, ast.Tuple)):
            return bool(arg.elts) and self._taint(mod, cls, arg.elts[0], env) is None and not _shell_launcher(arg.elts)
        if isinstance(arg, ast.Name):
            return arg.id in env.elem
        return False

    def _attr_sink(self, node):
        """Assignment to a modelled attribute (e.g. innerHTML) -> (sink info, value expr) or None."""
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            return None
        tgts = node.targets if isinstance(node, ast.Assign) else [node.target]
        for tgt in tgts:
            if isinstance(tgt, ast.Attribute):
                for si, attrs in self.m["attr_sinks"]:
                    if tgt.attr in attrs:
                        return si, node.value
            if isinstance(tgt, ast.Subscript) and self.m.get("store_sinks"):
                base = _dotted(tgt.value) or ""
                for si, roots in self.m["store_sinks"]:
                    if base in roots or base.split(".")[-1] in roots:
                        # both the key and the value cross the boundary
                        return si, ast.Tuple(elts=[tgt.slice, node.value], ctx=ast.Load())
        return None

    @staticmethod
    def _sink_args(si, call) -> list:
        """Argument expressions a sink inspects: positional indices plus named arguments (PL/SQL `p_sql => x`, Python kw)."""
        out = [call.args[i] for i in si[7] if isinstance(i, int) and i < len(call.args)]
        if "slice" in si[7] and isinstance(call.func, ast.Subscript):
            out.append(call.func.slice)
        if "self" in si[7] and isinstance(call.func, ast.Attribute):
            out.append(call.func.value)         # the receiver itself is the dangerous value (pathlib: p.read_text())
        kws = si[9] if len(si) > 9 else ()
        if kws:
            out.extend(k.value for k in call.keywords if k.arg and k.arg.lower() in kws)
        return out

    def _list_elem_only(self, mod, cls, arg, env) -> bool:
        """An argv list whose program (element 0) is fixed and not a shell: only its arguments can be tainted."""
        if isinstance(arg, (ast.List, ast.Tuple)):
            return bool(arg.elts) and self._taint(mod, cls, arg.elts[0], env) is None and not _shell_launcher(arg.elts)
        return isinstance(arg, ast.Name) and arg.id in env.elem

    def _at_call_site(self, mod, cls, arg, env, entries) -> list:
        """Summary sink entries as they apply to the argument passed here: a helper `run(cmd)` that executes its
        parameter is argument injection, not command injection, when this caller passes ["git", "log", x]."""
        if not any(e[0][0] == "DF003" and not e[0][8] for e in entries) or not self._list_elem_only(mod, cls, arg, env):
            return entries
        return [(ARG_INJECTION,) + tuple(e[1:]) if e[0][0] == "DF003" and not e[0][8] else e for e in entries]

    def _sink(self, mod, cls, call, env):
        si = self._sink_info(mod, call)
        if si and isinstance(call.func, ast.Attribute) and si[0] != "DFSTORE" and not si[0].startswith("stored"):
            # `super.execute(...)` / `service.search(q)` on a project class that defines the method: its own summary
            # decides where the data goes, a library sink with the same bare name does not apply
            recv = call.func.value
            if isinstance(recv, ast.Name) and recv.id in ("super", "this", "self") and cls:
                rtype = cls
            else:
                rtype = self._type_of(mod, cls, recv, env) if isinstance(recv, (ast.Name, ast.Attribute)) else None
            if rtype and rtype in self.classes:
                owners = [q for q in self._lookup_method(rtype, call.func.attr)
                          if not isinstance(recv, ast.Name) or recv.id != "super" or not q.startswith(rtype + ".")]
                if any(not _abstract(self.gfuncs[q]["node"]) for q in owners if q in self.gfuncs):
                    return None
        if si and isinstance(call.func, ast.Name) and si[0] != "DFSTORE" and not si[0].startswith("stored") \
                and self.m.get("language") not in ("python", "javascript", "plsql") and call.func.id not in env.funcs:
            ruby = self.m.get("language") == "ruby"
            fq = self._resolve_function(mod, call.func.id)
            # Ruby / Java / C#: a bare `warn(env, msg)` inside a class that defines `warn` (itself, a base class or
            # an included module) is `self.warn(...)`; its own summary decides where the data goes (rack-protection
            # logs only `msg`), not Kernel#warn's model
            if cls and cls in self.classes and (not fq or ruby) and any(
                    q in self.gfuncs and not _abstract(self.gfuncs[q]["node"]) for q in self._lookup_method(cls, call.func.id)):
                return None
            # Ruby: a top-level `def warn` in the same file is a method of every object: it replaces Kernel#warn too
            if ruby and fq and fq.startswith(mod + "::") and fq in self.gfuncs and not _abstract(self.gfuncs[fq]["node"]):
                return None
        if si is None and isinstance(call.func, ast.Attribute) and call.func.attr in ("write", "write_text") \
                and call.args and self.m.get("language") == "python" and self._template_source(mod, call.args[0]):
            return TEMPLATE_SOURCE_WRITE     # f.write(f"{{% extends 'base.html' %}}…{content}…"): a template built from data
        if si is None and isinstance(call.func, ast.Subscript) and self.m.get("language") in ("javascript", "php") \
                and not isinstance(call.func.slice, (ast.Constant, ast.Slice)):
            table = _chain(call.func.value)
            # obj[name](...): the caller picks which method runs. The extra field names the table, so a key checked
            # against that same table (`t[k] ? k : 'home'`, see _key_guard) is safe here and only here.
            return DYNAMIC_DISPATCH + ((), "DF026@" + table) if table else DYNAMIC_DISPATCH
        if si and si[0] == "DF003" and not si[8] and self._subprocess_elem_only(mod, cls, call, env):
            return ARG_INJECTION
        return si

    # ---------------------------------------------------------------- taint
    def _map_args(self, call: ast.Call, qual: str) -> dict:
        fn = self.gfuncs[qual]["node"]
        a = fn.args
        pos = [p.arg for p in (a.posonlyargs + a.args)]
        offset = 1 if (pos and pos[0] in {"self", "cls"}) else 0
        m = {}
        extra_pos, extra_kw = [], []
        for i, arg in enumerate(call.args):
            j = i + offset
            if j < len(pos):
                m[pos[j]] = arg
            elif a.vararg:
                extra_pos.append(arg)
        kwonly = {p.arg for p in a.kwonlyargs}
        for kw in call.keywords:
            if kw.arg in pos or kw.arg in kwonly:
                m[kw.arg] = kw.value
            elif a.kwarg:
                extra_kw.append(kw.value)
        if extra_pos:
            m[a.vararg.arg] = ast.Tuple(elts=extra_pos, ctx=ast.Load())
        if extra_kw:
            m[a.kwarg.arg] = ast.Dict(keys=[None] * len(extra_kw), values=extra_kw)
        # `p.keys()` inside the callee is tracked separately: for a dict literal argument only its keys count
        for pname, arg in list(m.items()):
            if isinstance(arg, ast.Dict):
                m[pname + ".keys"] = ast.List(elts=[k for k in arg.keys if k is not None], ctx=ast.Load())
            else:
                m[pname + ".keys"] = arg
        return m

    def _ctor_inst_fields(self, mod, cls, call, env) -> dict:
        callees, ctor = self._callees(mod, cls, call, env)
        if not ctor:
            return {}
        out: dict = {}
        pf = self._class_fields(ctor, "ctor_param_fields")
        for q in callees:
            mapping = self._map_args(call, q)
            for pname, fld in pf.items():
                arg = mapping.get(pname)
                if arg is None:
                    continue
                o = self._taint(mod, cls, arg, env)
                if o and fld not in out:
                    out[fld] = o
        return out

    @staticmethod
    def _note_param_field(c, method, o, field) -> bool:
        """Record that `method` stores parameter(s) of origin `o` in self.`field`; True if that is new."""
        slot = c["method_param_fields"].setdefault(method, {})
        new = False
        for pname in _origin_params(o):
            flds = slot.setdefault(pname, set())
            if field not in flds:
                flds.add(field)
                new = True
        return new

    def _method_inst_fields(self, mod, cls, call, env) -> dict:
        """Fields of the receiver that a method call fills from its (tainted) arguments: `d.set(x)` with
        `def set(self, p): self.s = p` -> {"s": origin of x}."""
        callees, ctor = self._callees(mod, cls, call, env)
        if ctor or not callees:
            return {}
        out: dict = {}
        for q in callees:
            info = self.gfuncs.get(q)
            if not info or not info["cls"] or info["cls"] not in self.classes:
                continue
            pf = self.classes[info["cls"]]["method_param_fields"].get(info["name"], {})
            if not pf:
                continue
            mapping = self._map_args(call, q)
            for pname, flds in pf.items():
                arg = mapping.get(pname)
                o = self._taint(mod, cls, arg, env) if arg is not None else None
                if o:
                    for fld in flds:
                        out.setdefault(fld, o)
        return out

    def _receiver_fields(self, mod, cls, call, env) -> tuple[dict, bool]:
        f = call.func
        if not isinstance(f, ast.Attribute):
            return {}, False
        recv = f.value
        if isinstance(recv, ast.Name) and recv.id in {"self", "cls"} and cls:
            return dict(self._class_fields(cls, "tainted_fields")), True
        fields: dict = {}
        if isinstance(recv, ast.Name) and recv.id in env.inst:
            fields.update(env.inst[recv.id])
        if isinstance(recv, ast.Call):
            fields.update(self._ctor_inst_fields(mod, cls, recv, env))
        rtype = self._type_of(mod, cls, recv, env)
        if rtype:
            fields.update(self._class_fields(rtype, "tainted_fields"))
        pt = getattr(self, "pt", None)
        if pt is not None:
            self._note_dep(("o", 0))
            by_oid = self.__dict__.get("obj_taint_by_oid") or {}
            for o in pt.objs(recv):
                for attr, origin in (by_oid.get(id(o)) or {}).items():
                    if attr not in fields:
                        fields[attr] = origin
        return fields, False

    _ORIGIN_RANK = {"source": 0, "retsource": 1, "param": 2, "field": 3}

    def _taint(self, mod, cls, node, env):
        """The most significant taint origin of an expression (sources before parameters before fields)."""
        origins = self._taints(mod, cls, node, env)
        if not origins:
            return None
        best = min(origins, key=lambda o: self._ORIGIN_RANK.get(o[0], 9))
        # escaping is merged among origins of the same nature: a parameter or field next to a source is followed
        # through its own summary, so `home or os.environ.get(...)` keeps the environment's path-safety
        symbolic = best[0] in ("param", "field")
        common = frozenset.intersection(*[_safe_for(o) for o in origins if (o[0] in ("param", "field")) == symbolic])
        # escape(a) + b: the merged value is only as escaped as its least-escaped part
        out = best if common == _safe_for(best) else (best[0], best[1], _trail(best), common) + tuple(best[4:])
        if out[0] == "param" and len(origins) > 1:
            # `table + id`: every parameter that reaches the value, so a summary maps each of them to the return
            more = set().union(*[_origin_params(o) for o in origins]) - _origin_params(out)
            if more:
                out = _with_params(out, more)
        return out

    def _module_const(self, mod, name):
        """The value of a module-level name bound exactly once, by a plain top-level assignment, and never rebound
        anywhere else in the module (a loop, an import, a `global` in a function …); None otherwise."""
        cache = self.__dict__.setdefault("_modconst_cache", {})
        key = (mod, name)
        if key not in cache:
            tree = (self.files.get(mod) or {}).get("tree")
            value, binds = None, 0
            for st in getattr(tree, "body", []):
                if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name) \
                        and st.targets[0].id == name:
                    value, binds = st.value, binds + 1
                    continue
                for n in ast.walk(st):
                    if (isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, ast.Store)) \
                            or (isinstance(n, ast.Global) and name in n.names) \
                            or (isinstance(n, ast.alias) and (n.asname or n.name) == name):
                        binds += 2
                        break
            cache[key] = value if binds == 1 else None
        return cache[key]

    def _fixed_host_url(self, mod, node) -> bool:
        """`"https://api.example.com/v1/" + x` / f"https://host/{x}" / TEMPLATE.format(id=x): the request can only
        go to that host, so tainted path or query parts are not server-side request forgery."""
        def const_str(e):
            if isinstance(e, ast.Constant) and isinstance(e.value, str):
                return e.value
            if isinstance(e, ast.Name) and e.id.isupper():   # a module-level CONSTANT template, never a local
                v = self._module_const(mod, e.id)
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    return v.value
            return None
        head = None
        if isinstance(node, ast.JoinedStr) and node.values:
            head = const_str(node.values[0])
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = node
            while isinstance(left, ast.BinOp) and isinstance(left.op, ast.Add):
                left = left.left
            head = const_str(left)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            head = const_str(node.func.value)
        return bool(head) and bool(re.match(r"(?i)^[a-z][a-z0-9+.-]*://[^/{}%?#@]+/", head))

    def _sink_taint(self, mod, cls, node, env, si):
        """The most significant origin of `node` that still matters for sink `si` (context-escaped ones don't)."""
        if si and si[5] == "CWE-918" and self._fixed_host_url(mod, node):
            return None
        origins = [o for o in self._taints(mod, cls, node, env) if _unsafe_for(o, si)]
        if not origins:
            return None
        return min(origins, key=lambda o: self._ORIGIN_RANK.get(o[0], 9))

    def _taints(self, mod, cls, node, env) -> list:
        """All taint origins of an expression: a + b carries both a's and b's origins, so a parameter
        concatenated with a field still reaches the sink summary as a parameter flow."""
        if isinstance(node, ast.BinOp):
            return self._taints(mod, cls, node.left, env) + self._taints(mod, cls, node.right, env)
        if isinstance(node, ast.BoolOp):
            out = []
            for v in node.values:
                out.extend(self._taints(mod, cls, v, env))
            return out
        if isinstance(node, ast.IfExp):
            if env.consts or isinstance(node.test, ast.Constant):
                t = _flow.fold(node.test, env.consts)
                if t is not _flow._MISSING:
                    return self._taints(mod, cls, node.body if t else node.orelse, env)
            test, body, orelse = node.test, node.body, node.orelse
            if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
                test, body, orelse = test.operand, orelse, body          # `!pages[k] ? 'home' : k`
            out = self._taints(mod, cls, body, env)
            guard, table = _key_guard(test, body) if out else (None, None)
            if guard and table is not None and self._taints(mod, cls, table, env):
                guard = None                 # `k in req.query ? k : ''`: membership in client data validates nothing
            if guard == "all":
                out = []
            elif guard:
                out = [(o[0], o[1], _trail(o), _safe_for(o) | guard) + tuple(o[4:]) for o in out]
            return out + self._taints(mod, cls, orelse, env)
        if isinstance(node, ast.JoinedStr):
            out = []
            for v in node.values:
                if isinstance(v, ast.FormattedValue):
                    out.extend(self._taints(mod, cls, v.value, env))
            return out
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            return self._comprehension_taints(mod, cls, node, env)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            out = []
            for e in node.elts:
                out.extend(self._taints(mod, cls, e, env))
            return out
        if isinstance(node, ast.Dict):
            out = []
            for e in list(node.keys) + list(node.values):
                if e is not None:
                    out.extend(self._taints(mod, cls, e, env))
            return out
        o = self._taint_one(mod, cls, node, env)
        return [o] if o else []

    def _comprehension_taints(self, mod, cls, node, env) -> list:
        """`[dict(r) for r in rows]` / `{k: v for k, v in pairs}`: the element expression, with each loop variable
        carrying the taint of what it iterates (and an outer name it shadows hidden). The `if` filters are not
        validation. The loop variables are bound only while the element is evaluated."""
        saved: dict = {}
        try:
            for g in node.generators:
                oi = self._taint(mod, cls, g.iter, env)
                for t in ast.walk(g.target):
                    if isinstance(t, ast.Name):
                        if t.id not in saved:
                            saved[t.id] = env.tainted.get(t.id)
                        if oi:
                            env.tainted[t.id] = oi
                        else:
                            env.tainted.pop(t.id, None)
            out = []
            for e in ((node.key, node.value) if isinstance(node, ast.DictComp) else (node.elt,)):
                out.extend(self._taints(mod, cls, e, env))
            return out
        finally:
            for name, o in saved.items():
                if o is None:
                    env.tainted.pop(name, None)
                else:
                    env.tainted[name] = o

    def _taint_one(self, mod, cls, node, env):
        if self.m.get("language") == "javascript":
            if env.vfields and isinstance(node, ast.Attribute) and isinstance(node.value, ast.Attribute) \
                    and isinstance(node.value.value, ast.Name) and node.value.value.id in env.webreq \
                    and node.attr in env.vfields:
                return None          # req.query.id after query('id').isInt() in the route's middleware
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                    and node.func.attr in ("parse", "parseAsync", "validate", "validateAsync", "attempt", "cast") \
                    and _JS_TYPED_SCHEMA.search(_receiver_text(node.func.value)):
                return None          # z.number().parse(x) / Joi.number().validate(x): a number, boolean, date, enum value
        if self.m.get("language") == "python" and isinstance(node, (ast.Subscript, ast.Attribute, ast.Call)):
            v = self._schema_validated(mod, cls, node, env)
            if v is not None:
                if v == "all":
                    return None
                inner = node.value if isinstance(node, (ast.Subscript, ast.Attribute)) else node.func
                o = self._taint(mod, cls, inner, env)
                return (o[0], o[1], _trail(o), _safe_for(o) | v) + tuple(o[4:]) if o else None
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr in ("replace", "replaceAll", "gsub", "sub", "Replace") and node.args \
                and any(x in _const_text(node.args[0]) for x in ("\r", "\n", "\\r", "\\n", "\\s")):
            o = self._taint(mod, cls, node.func.value, env)    # CR/LF stripped: no forged log lines / headers
            return (o[0], o[1], _trail(o), _safe_for(o) | _CRLF_CWES) + tuple(o[4:]) if o else None
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get" \
                and any(k.arg == "type" and isinstance(k.value, ast.Name) and k.value.id in ("int", "float", "bool")
                        for k in node.keywords):
            return None              # werkzeug MultiDict.get(k, type=int): converted to a number (or the default)
        src = self._is_source(mod, node, cls, env)
        if src:
            inc = getattr(node, _php_include.MARK, None)
            trail = (_step((self.files.get(mod) or {}).get("path", ""), node.lineno, f"include {inc}"),) if inc else ()
            if self._is_local_source(mod, node):
                return ("source", src, trail, _LOCAL_SAFE_CWES)
            return ("source", src, trail)
        if isinstance(node, ast.Name):
            return env.tainted.get(node.id)
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id in env.dk:
            m, other = env.dk[node.value.id]
            key = _flow.fold(node.slice, env.consts)
            if key is not _flow._MISSING and _flow._hashable(key):
                return m.get(key, other)
            return next((v for v in list(m.values()) + [other] if v), None)
        if isinstance(node, (ast.Subscript, ast.Starred, ast.Await)):
            o = self._taint(mod, cls, node.value, env)
            if o and isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant) \
                    and isinstance(node.slice.value, str) and not self._stored_column_written(o, node.slice.value):
                return None          # row["id"] of a row read with SELECT *: a column no user wrote
            return o
        if isinstance(node, ast.Attribute):
            recv = node.value
            if isinstance(recv, ast.Name) and recv.id in env.webreq and node.attr in _SERVER_STATE_ATTRS \
                    and self.m.get("language") == "python":
                return None          # request.session / request.user: server-side state, not what the client sent
            if isinstance(recv, ast.Name) and recv.id in {"self", "cls"} and cls:
                tf = self._class_fields(cls, "tainted_fields")
                if node.attr in tf:
                    return tf[node.attr]
                return ("field", node.attr, ())
            if isinstance(recv, ast.Name) and recv.id in env.inst and node.attr in env.inst[recv.id]:
                return env.inst[recv.id][node.attr]
            if isinstance(recv, ast.Call):
                tmp = self._ctor_inst_fields(mod, cls, recv, env)
                if node.attr in tmp:
                    return tmp[node.attr]
            pt = getattr(self, "pt", None)
            if pt is not None:
                self._note_dep(("o", 0))
                for o in pt.objs(recv):
                    hit = self.obj_taint.get((id(o), node.attr))
                    if hit:
                        return hit
            rtype = self._type_of(mod, cls, recv, env)
            if rtype:
                tf = self._class_fields(rtype, "tainted_fields")
                if node.attr in tf:
                    return tf[node.attr]
            return self._taint(mod, cls, recv, env)
        if isinstance(node, ast.Call):
            canon = self._canon(mod, node.func)
            skind = self._sanitizer_kind(canon)
            if skind == "all":
                return None
            if skind:
                # escaped for one context only: still tainted for every other kind of sink
                for a in list(node.args) + [k.value for k in node.keywords] + \
                        ([node.func.value] if isinstance(node.func, ast.Attribute) else []):
                    o = self._taint(mod, cls, a, env)
                    if o:
                        return (o[0], o[1], _trail(o), _safe_for(o) | skind)
                return None
            f = node.func
            if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id in env.dk \
                    and f.attr in _KEYED_READS:
                m, other = env.dk[f.value.id]
                if f.attr in ("getFirst", "peek", "peekFirst", "element", "first"):
                    key = 0
                elif f.attr in ("getLast", "peekLast", "last"):
                    key = -1
                else:
                    key = _flow.fold(node.args[0], env.consts) if node.args else _flow._MISSING
                if key is not _flow._MISSING and _flow._hashable(key):
                    hit = m.get(key, other) if key in m else other
                    if hit is None and len(node.args) > 1:            # dict.get(key, default) / getOrDefault
                        return self._taint(mod, cls, node.args[1], env)
                    return hit
                return next((v for v in list(m.values()) + [other] if v), None)
            if isinstance(node.func, ast.Attribute) and node.func.attr == "keys" and not node.args \
                    and isinstance(node.func.value, ast.Name):
                o = env.tainted.get(node.func.value.id)
                if o and o[0] == "param":                 # keys of a parameter: their own origin (see _map_args)
                    return ("param", o[1] + ".keys", _trail(o)) + tuple(o[3:])
            callees, ctor = self._callees(mod, cls, node, env)
            if ctor:
                if ctor in self.classes and self._class_has_base(ctor, _FORM_BASES):
                    # a form / serializer bound to request data carries it (cleaned_data / validated_data / .data)
                    for a in list(node.args) + [k.value for k in node.keywords if k.arg in ("data", "formdata", None)]:
                        o = self._taint(mod, cls, a, env)
                        if o:
                            return o
                    if not node.args and self._class_has_base(ctor, {"FlaskForm"}):
                        return ("source", "request.form", ())     # Flask-WTF binds request.form implicitly
                return None
            if callees:
                fields, is_self = self._receiver_fields(mod, cls, node, env)
                for q in callees:
                    summ = self.summaries.get(q)
                    if not summ:
                        continue
                    if summ["source_return"]:
                        o = summ["source_return"]
                        return ("retsource", self.gfuncs[q]["name"], _trail(o) + (
                            _step(self.gfuncs[q]["path"], summ["ret_line"], f"return من {self.gfuncs[q]['name']}()"),)) + tuple(o[3:])
                    mapping = self._map_args(node, q)
                    for pname in summ["ret_params"]:
                        arg = mapping.get(pname)
                        if arg is None and pname in self._captured_names(q):
                            arg = ast.Name(id=pname, ctx=ast.Load())    # captured by the closure: the caller's variable
                        if arg is not None:
                            o = self._taint(mod, cls, arg, env)
                            if o:
                                return _with_step(o, _step(self.gfuncs[q]["path"], summ["ret_line"],
                                                           f"يمرّ عبر {self.gfuncs[q]['name']}() ويُعاد"))
                    for fld in summ["ret_fields"]:
                        if fld in fields:
                            return fields[fld]
                        if is_self:
                            return ("field", fld, ())
                return None
            if isinstance(node.func, ast.Attribute):
                o = self._taint(mod, cls, node.func.value, env)
                if o:
                    return o
            for a in list(node.args) + [k.value for k in node.keywords]:
                o = self._taint(mod, cls, a, env)
                if o:
                    return o
            return None
        return None

    # ------------------------------------------------- form / schema validation (Django, DRF, WTForms, pydantic)
    def _class_field_value(self, cq, field):
        """The expression a form/schema class assigns to `field` (`age = forms.IntegerField()`) or its annotation
        (`age: int`), searched through the class hierarchy: ("assign", expr) / ("ann", annotation) / None."""
        for c in self._mro(cq):
            node = self.classes[c]["node"]
            for st in node.body:
                if isinstance(st, ast.Assign) and any(isinstance(t, ast.Name) and t.id == field for t in st.targets):
                    return ("assign", st.value)
                if isinstance(st, ast.AnnAssign) and isinstance(st.target, ast.Name) and st.target.id == field:
                    return ("ann", st.annotation) if st.value is None or not isinstance(st.value, ast.Call) \
                        else ("annassign", st)
        return None

    def _class_has_base(self, cq, names) -> bool:
        return any({b.split(".")[-1] for b in self.classes[c]["base_names"]} & names for c in self._mro(cq))

    def _field_safety(self, mod, cq, field):
        """What a validated field of form/schema class `cq` cannot carry: "all" (numbers, dates, UUIDs, booleans, choices
        from a fixed list, slugs), a frozenset of CWEs (an e-mail address cannot hold markup), or None (free text)."""
        hit = self._class_field_value(cq, field)
        if hit is None:
            return None
        kind, val = hit
        if kind in ("ann", "annassign"):
            ann = val if kind == "ann" else val.annotation
            if self._class_has_base(cq, _SCHEMA_BASES) and self._safe_annotation(mod, ann):
                return "all"
            return None
        if not isinstance(val, ast.Call):
            return None
        ftype = _dotted(val.func).split(".")[-1]
        if ftype in _SAFE_FIELD_TYPES:
            return "all"
        if ftype in _EMAIL_FIELD_TYPES:
            return frozenset(_XSS)
        if ftype in ("StringField", "TextField", "CharField", "String", "Str", "TextAreaField", "SearchField"):
            for k in val.keywords:
                if k.arg in ("validators", "validate", "choices"):
                    if k.arg == "choices":
                        return "all"
                    for v in (k.value.elts if isinstance(k.value, (ast.List, ast.Tuple)) else [k.value]):
                        vn = _dotted(v.func if isinstance(v, ast.Call) else v).split(".")[-1]
                        if vn in ("AnyOf", "OneOf", "ContainsOnly"):
                            return "all"
                        if vn in ("Regexp", "Regex", "RegexValidator") and isinstance(v, ast.Call) and v.args \
                                and isinstance(v.args[0], ast.Constant) and isinstance(v.args[0].value, str):
                            pat = v.args[0].value
                            if pat.startswith("^") and pat.endswith(("$", "\\Z", "\\z")) and not _PERMISSIVE_RE.search(pat):
                                return "all"
        return None

    def _safe_annotation(self, mod, ann) -> bool:
        """int / float / bool / UUID / date / Decimal / an Enum / Literal[...] / conint …, optionally Optional[...]:
        a parsed value of that type cannot carry an injection payload."""
        if ann is None:
            return False
        if isinstance(ann, ast.Subscript):
            head = _dotted(ann.value).split(".")[-1]
            if head == "Literal":
                return True
            if head in ("Optional", "Annotated"):
                inner = ann.slice.elts[0] if isinstance(ann.slice, ast.Tuple) else ann.slice
                return self._safe_annotation(mod, inner)
            if head == "Union":
                elts = ann.slice.elts if isinstance(ann.slice, ast.Tuple) else [ann.slice]
                return all(self._safe_annotation(mod, e) or (isinstance(e, ast.Constant) and e.value is None) for e in elts)
            return False
        if isinstance(ann, ast.BinOp) and isinstance(ann.op, ast.BitOr):
            return all(self._safe_annotation(mod, e) or (isinstance(e, ast.Constant) and e.value is None)
                       for e in (ann.left, ann.right))
        if isinstance(ann, ast.Call):
            return _dotted(ann.func).split(".")[-1] in ("conint", "confloat", "condecimal", "condate")
        name = _annotation_name(ann) or ""
        if name.split(".")[-1] in _SAFE_SCALARS:
            return True
        cq = self._resolve_class(mod, name)
        return bool(cq) and self._class_has_base(cq, {"Enum", "IntEnum", "StrEnum", "Flag", "IntFlag"})

    def _schema_validated(self, mod, cls, node, env):
        """`form.cleaned_data["age"]`, `serializer.validated_data["age"]`, `form.age.data`, `item.age` (pydantic):
        the field's validated type decides what the value can still carry. None = no opinion."""
        key, holder = None, None
        if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str) \
                and isinstance(node.value, ast.Attribute) and node.value.attr in ("cleaned_data", "validated_data"):
            key, holder = node.slice.value, node.value.value
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get" and node.args \
                and isinstance(node.args[0], ast.Constant) and isinstance(node.func.value, ast.Attribute) \
                and node.func.value.attr in ("cleaned_data", "validated_data"):
            key, holder = node.args[0].value, node.func.value.value
        elif isinstance(node, ast.Attribute) and node.attr == "data" and isinstance(node.value, ast.Attribute):
            key, holder = node.value.attr, node.value.value          # WTForms form.field.data
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            key, holder = node.attr, node.value                      # pydantic model.field
        if key is None or not isinstance(key, str):
            return None
        cq = self._type_of(mod, cls, holder, env)
        if not cq or cq not in self.classes:
            return None
        if isinstance(node, ast.Attribute) and node.attr != "data" and not self._class_has_base(cq, _SCHEMA_BASES):
            return None
        if isinstance(node, ast.Attribute) and node.attr == "data":
            if not self._class_has_base(cq, _WTFORMS_BASES):
                return None
            # WTForms enforces validators and choices only in validate(): require the form to be validated
            hname = _chain(holder)
            lines = (self.files.get(mod) or {}).get("lines") or []
            if not hname or not any(f"{hname}.validate" in ln for ln in lines):
                return None
        return self._field_safety(mod, cq, key)

    # ---------------------------------------------------------- entry points
    def _meta_entry_annotation(self, mod, name: str, depth: int = 0) -> bool:
        """Java composed annotation: `@interface MyMapping` declared in the project and itself annotated with
        `@RequestMapping` / `@GetMapping` … (Spring meta-annotations) routes the methods it marks."""
        cq = self._resolve_class(mod, name)
        c = self.classes.get(cq) if cq else None
        if c is None or depth > 2:
            return False
        for d in getattr(c["node"], "decorator_list", ()):
            dn = _dotted(d.func if isinstance(d, ast.Call) else d).split(".")[-1]
            if dn in self.m["entry_decorators"] or (dn != name and self._meta_entry_annotation(c["mod"], dn, depth + 1)):
                return True
        return False

    def _is_entry(self, mod, cls, fn) -> bool:
        """A routed handler / CLI command / framework view method, with or without parameters."""
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return False
        for d in fn.decorator_list:
            dn = _dotted(d.func if isinstance(d, ast.Call) else d).split(".")[-1]
            if dn in self.m["entry_decorators"]:
                # unittest.mock.patch / pytest marks are test machinery, not an HTTP PATCH route
                canon = self._canon(mod, d.func if isinstance(d, ast.Call) else d)
                if canon.split(".")[0] in _TEST_DECORATOR_ROOTS:
                    continue
                return True
            if self.m.get("language") == "java" and self._meta_entry_annotation(mod, dn):
                return True
        if cls and fn.name in self.m["view_methods"]:
            bases = set()
            for c in self._mro(cls):
                bases |= {b.split(".")[-1] for b in self.classes[c]["base_names"]}
            if bases & self.m["view_bases"]:
                return True
        if not cls and self._is_django_function_view(mod, fn):
            return True
        return False

    _RENDER_FUNCS = frozenset({"render_template", "render", "TemplateResponse", "render_to_response", "render_to_string",
                               "render_template_async", "stream_template", "template"})

    def _template_context(self, mod, call):
        """(variable, value) pairs a render call passes to a template that prints that variable unescaped."""
        fname = _dotted(call.func).split(".")[-1]
        if fname not in self._RENDER_FUNCS:
            return []
        tname, ctx = None, []
        for i, a in enumerate(call.args[:3]):
            if isinstance(a, ast.Constant) and isinstance(a.value, str) and a.value.lower().endswith(TEMPLATE_EXTS):
                tname = a.value
                rest = call.args[i + 1:]
                for d in rest:
                    if isinstance(d, ast.Dict):
                        ctx += [(k.value, v) for k, v in zip(d.keys, d.values) if isinstance(k, ast.Constant) and isinstance(k.value, str)]
                break
        if tname is None:
            for k in call.keywords:
                if k.arg in ("template_name", "name", "template") and isinstance(k.value, ast.Constant) and isinstance(k.value.value, str):
                    tname = k.value.value
        if tname is None:
            return []
        for k in call.keywords:
            if k.arg in ("context", "ctx") and isinstance(k.value, ast.Dict):
                ctx += [(kk.value, v) for kk, v in zip(k.value.keys, k.value.values) if isinstance(kk, ast.Constant)]
            elif k.arg and k.arg not in ("template_name", "name", "template", "request", "status", "status_code"):
                ctx.append((k.arg, k.value))
        unsafe = _template_unsafe_vars(tname)
        return [(n, v) for n, v in ctx if n in unsafe]

    def _project_enum(self, ann) -> bool:
        """Is this parameter type an enum the project declares (`enum Sort { NAME, AGE }`, Kotlin `enum class`)?"""
        name = (_annotation_name(ann) or "").split(".")[-1] if ann is not None else ""
        if not name:
            return False
        enums = self.__dict__.get("_enum_names")
        if enums is None:
            enums = set()
            for f in self.files.values():
                for ln in f.get("lines") or ():
                    if "enum" in ln:
                        enums.update(_ENUM_DECL.findall(ln))
            self.__dict__["_enum_names"] = enums
        return name in enums

    _JS_VIEW_RECEIVERS = frozenset({"res", "response", "resp", "ctx", "context", "reply", "h"})

    def _js_template_context(self, fn, call):
        """(variable, value) pairs a JavaScript view render passes to a view that prints that variable unescaped:
        `res.render("app/products", {output})`, `await ctx.render("x", data)`, `reply.view("/t.ejs", {...})`.
        A spread (`{...user}`) or an object that is not a literal here stands for every variable ("*")."""
        f = call.func
        if not (isinstance(f, ast.Attribute) and f.attr in ("render", "view") and len(call.args) >= 2
                and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str)
                and _dotted(f.value).split(".")[-1] in self._JS_VIEW_RECEIVERS):
            return []
        unsafe = _js_template_unsafe_vars(call.args[0].value, self._js_autoescape_off())
        if not unsafe:
            return []
        ctx = call.args[1]
        if isinstance(ctx, ast.Name):
            binds = [n.value for n in _scope_nodes(fn) if isinstance(n, ast.Assign) and len(n.targets) == 1
                     and isinstance(n.targets[0], ast.Name) and n.targets[0].id == ctx.id]
            if len(binds) == 1 and isinstance(binds[0], ast.Dict):
                ctx = binds[0]
        if not isinstance(ctx, ast.Dict):
            return [("*", ctx)]
        out = []
        for k, v in zip(ctx.keys, ctx.values):
            if k is None:
                out.append(("*", v))
            elif isinstance(k, ast.Constant) and k.value in unsafe:
                fields = unsafe[k.value]
                obj = v
                if isinstance(obj, ast.Name):
                    binds = [n.value for n in _scope_nodes(fn) if isinstance(n, ast.Assign) and len(n.targets) == 1
                             and isinstance(n.targets[0], ast.Name) and n.targets[0].id == obj.id]
                    obj = binds[0] if len(binds) == 1 else obj
                if None in fields or not isinstance(obj, ast.Dict) or None in obj.keys:
                    out.append((k.value, v))
                    continue
                # only the printed fields of an object literal: {searchTerm: req.body.q, safe: x} with output.searchTerm
                out += [(k.value, fv) for fk, fv in zip(obj.keys, obj.values)
                        if isinstance(fk, ast.Constant) and fk.value in fields]
        return out

    def _js_autoescape_off(self) -> bool:
        """Does the project turn HTML escaping off for its Swig / Nunjucks views
        (`swig.setDefaults({autoescape: false})`, `nunjucks.configure(dir, {autoescape: false})`)?"""
        hit = self.__dict__.get("_js_noescape")
        if hit is None:
            hit = False
            for f in self.files.values():
                lines = f.get("lines") or ()
                if any(_JS_AE_OFF.search(ln) for ln in lines) and any(_JS_AE_ENGINE.search(ln) for ln in lines):
                    hit = True
                    break
            self.__dict__["_js_noescape"] = hit
        return hit

    def _template_source(self, mod, node) -> bool:
        """Is `node` template SOURCE text built with data: an f-string / concatenation / .format() whose literal parts
        hold Jinja / Django tags (`{% … %}`, `{{ … }}`), or a name the module binds to one?"""
        if isinstance(node, ast.Name):
            cache = self.__dict__.setdefault("_tpl_src_names", {})
            names = cache.get(mod)
            if names is None:
                names = cache[mod] = set()
                tree = (self.files.get(mod) or {}).get("tree")
                for n in ast.walk(tree) if tree is not None else ():
                    if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) \
                            and not isinstance(n.value, ast.Name) and self._template_source(mod, n.value):
                        names.add(n.targets[0].id)
                cache[mod] = names
            return node.id in names
        parts = []
        if isinstance(node, ast.JoinedStr) and any(isinstance(v, ast.FormattedValue) for v in node.values):
            parts = [v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str)]
        elif isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            parts = [n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format" \
                and isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str):
            parts = [node.func.value.value.replace("{{", "{").replace("}}", "}")]
        text = "".join(parts)
        return bool(_JINJA_TAG.search(text))

    def _aiohttp_template(self, mod, fn) -> str | None:
        """The template of an aiohttp_jinja2 `@template("name")` handler."""
        for d in getattr(fn, "decorator_list", ()):
            if isinstance(d, ast.Call) and d.args and isinstance(d.args[0], ast.Constant) and isinstance(d.args[0].value, str) \
                    and self._canon(mod, d.func) in ("aiohttp_jinja2.template", "aiohttp_jinja2.template.template"):
                return d.args[0].value
        return None

    def _aiohttp_unescaped(self) -> bool:
        """Does the project set up aiohttp_jinja2 with autoescape=False (`aiohttp_jinja2.setup(app, autoescape=False)`)?
        Then every variable its templates print is written to the page raw."""
        hit = self.__dict__.get("_aiohttp_noescape")
        if hit is None:
            hit = False
            for mod, f in self.files.items():
                if not any("aiohttp_jinja2" in ln for ln in f.get("lines") or ()):
                    continue
                for n in ast.walk(f["tree"]):
                    if isinstance(n, ast.Call) and self._canon(mod, n.func) == "aiohttp_jinja2.setup" and any(
                            k.arg == "autoescape" and isinstance(k.value, ast.Constant) and k.value.value is False
                            for k in n.keywords):
                        hit = True
                        break
                if hit:
                    break
            self.__dict__["_aiohttp_noescape"] = hit
        return hit

    _JSON_SHAPES = (ast.Dict, ast.List, ast.ListComp, ast.DictComp, ast.Set, ast.SetComp)
    _NON_HTML_TYPE = re.compile(r"(?i)json|event-stream|text/plain|octet-stream|text/csv|image/|application/(?!xhtml)")

    _XML_HARDENING = re.compile(r"disallow-doctype-decl['\"]?\s*,\s*true|external-(general|parameter)-entities['\"]?\s*,\s*false|"
                                r"setExpandEntityReferences\s*\(\s*false|ACCESS_EXTERNAL_(DTD|SCHEMA|STYLESHEET)|"
                                r"SUPPORT_DTD['\"]?\s*,\s*(false|Boolean\.FALSE)|IS_SUPPORTING_EXTERNAL_ENTITIES['\"]?\s*,\s*(false|Boolean\.FALSE)|"
                                r"setEntityResolver\s*\(|load-external-dtd['\"]?\s*,\s*false|DtdProcessing\.Prohibit|XmlResolver\s*=\s*null")

    def _xml_hardened(self, fn) -> bool:
        """Does the function configure its XML parser against XXE (a hardening call anywhere in its body)?"""
        cache = self.__dict__.setdefault("_xml_hard", {})
        hit = cache.get(id(fn))
        if hit is None or hit[0] is not fn:
            found = False
            for n in ast.walk(fn) if hasattr(fn, "body") else ():
                if isinstance(n, ast.Call):
                    try:
                        text = ast.unparse(n)
                    except Exception:  # noqa: BLE001
                        continue
                    if self._XML_HARDENING.search(text.replace("True", "true").replace("False", "false")):
                        found = True
                        break
            hit = cache[id(fn)] = (fn, found)
        return hit[1]

    def _sink_arg_ok(self, fn, si, arg, env=None) -> bool:
        """JavaScript XSS sinks (res.send / res.write / reply.send): an object or array argument is serialised as
        JSON, and a handler that set a non-HTML Content-Type (JSON, event stream, plain text) writes no HTML."""
        if si[5] == "CWE-611" and self._xml_hardened(fn):
            return False                     # the parser was configured without DTDs / external entities
        if self.m.get("language") != "javascript":
            return True
        if si[0] == "DF016" and isinstance(arg, (ast.Dict, ast.List)):
            return False                     # structured logging (pino / bunyan objects) is serialised as JSON
        if si[0] == "DF004" and isinstance(arg, ast.Dict):
            # findOne({ where: { login: String(x) } }) / updateOne({ _id: String(id) }): every value is a scalar the
            # driver binds as a parameter; only a raw (possibly object-valued) request value can inject operators
            scalars = frozenset(n for n, o in env.tainted.items() if o and o[0] == "source"
                                and re.search(r"(^|\.)params$", str(o[1]))) if env is not None else frozenset()
            return _has_raw_leaf(arg, scalars, frozenset(env.tainted) if env is not None else None)
        if si[0] != "DF013":
            return True
        if isinstance(arg, self._JSON_SHAPES):
            return False
        if isinstance(arg, ast.Call) and _dotted(arg.func) in ("JSON.stringify", "json.dumps"):
            return False
        cache = self.__dict__.setdefault("_non_html_fns", {})
        hit = cache.get(id(fn))
        if hit is None or hit[0] is not fn:
            found = False
            for n in _scope_nodes(fn):
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and \
                        n.func.attr in ("setHeader", "set", "type", "header", "writeHead", "contentType", "json"):
                    if n.func.attr == "json":
                        continue
                    for a in n.args:
                        for c in ast.walk(a):
                            if isinstance(c, ast.Constant) and isinstance(c.value, str) and self._NON_HTML_TYPE.search(c.value):
                                found = True
            hit = cache[id(fn)] = (fn, found)
        return not hit[1]

    def _html_return(self, mod, fn, v) -> bool:
        """Can `return v` from this entry point be an HTML response body? Not for a task / CLI / message handler
        (the value goes to a result backend or the terminal), not for a dict or list (Flask >= 1.1, FastAPI and DRF
        serialise it as JSON), not for FastAPI/Starlette unless the route declares an HTML response, and not for
        JavaScript handlers unless the value is an HTML string (Express ignores the return value)."""
        lang = self.m.get("language")
        if lang == "go":
            return False         # Go handlers write the response (w.Write / c.String); their return value is an error
        if lang == "javascript":
            return any(isinstance(n, ast.Constant) and isinstance(n.value, str) and "<" in n.value for n in ast.walk(v))
        if lang != "python":
            return True
        names = {_dotted(d.func if isinstance(d, ast.Call) else d).split(".")[-1] for d in getattr(fn, "decorator_list", [])}
        if names & {"task", "shared_task", "command", "subcommand", "on_message", "callback", "group", "periodic_task",
                    "actor", "job"} and not names & {"route", "get", "post", "put", "patch", "delete", "api_route", "view"}:
            return False
        if isinstance(v, self._JSON_SHAPES) or (isinstance(v, ast.Tuple) and v.elts and isinstance(v.elts[0], self._JSON_SHAPES)):
            return False
        al = (self.files.get(mod) or {}).get("aliases", {})
        if any(isinstance(t, tuple) and any(isinstance(x, str) and x.split(".")[0] in ("fastapi", "starlette", "litestar",
                                                                                    "ninja") for x in t[1:]) for t in al.values()):
            for d in getattr(fn, "decorator_list", []):
                if isinstance(d, ast.Call):
                    for k in d.keywords:
                        if k.arg in ("response_class", "media_type") and re.search(r"(?i)html|plain|text",
                                                                                 _dotted(k.value) or str(getattr(k.value, "value", ""))):
                            return True
            return isinstance(v, ast.Call) and re.search(r"(?i)HTMLResponse|PlainTextResponse|Response$", _dotted(v.func) or "") is not None
        return True

    @staticmethod
    def _cli_entry(fn) -> bool:
        """An entry point that is only a command-line command (click / typer / argparse sub-command), not a route."""
        names = [_dotted(d.func if isinstance(d, ast.Call) else d).split(".")[-1] for d in getattr(fn, "decorator_list", [])]
        return bool(set(names) & {"command", "subcommand", "group", "callback"}) and \
            not set(names) & {"route", "get", "post", "put", "patch", "delete", "api_route", "websocket", "middleware"}

    def _is_django_function_view(self, mod, fn) -> bool:
        """`def view(request, slug)` in a module that imports Django: the parameters after `request` are captured
        from the URL by the URL configuration (path("<str:slug>/", view)). A function the project itself calls
        (`get_exception_response(request, resolver, 404, exc)`) is a helper: its arguments come from its callers."""
        params = fn.args.posonlyargs + fn.args.args
        if len(params) < 2 or params[0].arg != "request":
            return False
        key = ("django", mod)
        cache = self.__dict__.setdefault("_django_mods", {})
        if key not in cache:
            al = (self.files.get(mod) or {}).get("aliases", {})
            cache[key] = any(isinstance(x, str) and (x == "django" or x.startswith("django."))
                             for v in al.values() for x in (v if isinstance(v, tuple) else (v,)))
        if not cache[key] or self._called_by_name(mod, fn.name):
            return False
        routed = self._django_routed_names()
        # with URL configurations in the project, a view is a function they route to: `render(request, template,
        # context)` in django/shortcuts.py takes a request but is a helper. Without any (a scan of one app's views
        # without its urls.py), the signature is all there is to go by.
        return routed is None or fn.name in routed

    _DJANGO_ROUTE_CALLS = frozenset({"path", "re_path", "url"})
    _DJANGO_HANDLERS = frozenset({"handler400", "handler403", "handler404", "handler500"})
    _VIEW_ONLY_DECORATORS = frozenset({"login_required", "permission_required", "user_passes_test", "staff_member_required",
                                       "csrf_exempt", "csrf_protect", "ensure_csrf_cookie", "requires_csrf_token",
                                       "cache_page", "never_cache", "vary_on_headers", "vary_on_cookie", "xframe_options_exempt",
                                       "xframe_options_deny", "xframe_options_sameorigin", "sensitive_post_parameters",
                                       "condition", "etag", "last_modified", "gzip_page", "cache_control"})

    def _django_routed_names(self):
        """Names of the functions the project's Django URL configurations route to (`path("x/", views.fn)`,
        `re_path(r"…", fn)`, `url(r"…", "app.views.fn")`, `handler404 = "app.views.not_found"`), plus functions
        wearing a decorator only views wear (`@login_required`, `@csrf_exempt` …). None: the project has no URL
        configuration at all."""
        hit = self.__dict__.get("_django_routed")
        if hit is not None:
            return hit[0]
        names: set = set()
        found = False

        def ref(e):
            if isinstance(e, ast.Constant) and isinstance(e.value, str) and re.fullmatch(r"[\w.]+", e.value):
                names.add(e.value.split(".")[-1])
            elif isinstance(e, (ast.Name, ast.Attribute)):
                names.add(_dotted(e).split(".")[-1])
            elif isinstance(e, ast.Call):
                # a wrapped view: path("x/", login_required(views.fn)), path("y/", cache_page(60)(views.fn))
                for a in e.args:
                    ref(a)
        for info in self.files.values():
            for n in ast.walk(info["tree"]):
                if isinstance(n, ast.Call) and len(n.args) >= 2 \
                        and _dotted(n.func).split(".")[-1] in self._DJANGO_ROUTE_CALLS:
                    found = True
                    ref(n.args[1])
                elif isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id in self._DJANGO_HANDLERS for t in n.targets):
                    ref(n.value)
                elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
                        _dotted(d.func if isinstance(d, ast.Call) else d).split(".")[-1] in self._VIEW_ONLY_DECORATORS
                        for d in n.decorator_list):
                    names.add(n.name)
        res = names if found else None
        self.__dict__["_django_routed"] = (res,)
        return res

    def _name_calls(self, mod) -> set:
        """Names called as a bare `name(...)` in a module (cached)."""
        cache = self.__dict__.setdefault("_name_calls_cache", {})
        hit = cache.get(mod)
        if hit is None:
            tree = (self.files.get(mod) or {}).get("tree")
            hit = cache[mod] = {n.func.id for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)} \
                if tree is not None else set()
        return hit

    def _called_by_name(self, mod, name) -> bool:
        """Is module-level function `name` of `mod` called directly: in its own module, or as an imported name
        (`from .exception import name`) in a module that calls it?"""
        if name in self._name_calls(mod):
            return True
        importers = self.__dict__.get("_from_importers")
        if importers is None:
            importers = self.__dict__["_from_importers"] = {}
            for m, f in self.files.items():
                for local, tgt in f.get("aliases", {}).items():
                    if tgt and tgt[0] == "from":
                        importers.setdefault(tgt[2], []).append((m, local, tgt[1]))
        # the scan root may cut the package prefix off module names: `django.core.x` imported, `core.x` scanned
        return any(local in self._name_calls(m) for m, local, tm in importers.get(name, ())
                   if (tm == mod or tm.endswith("." + mod) or mod.endswith("." + tm))
                   and not _TEST_MODULE.search(self.files[m]["path"]))    # a test calling the view is not a caller


    def _entry_params(self, mod, cls, fn) -> list[str]:
        if not self._is_entry(mod, cls, fn):
            return []
        params = [p for p in _param_names(fn) if p not in {"self", "cls"}]
        if self._js_route_callback(fn):
            return []          # the request object is a web request (_js_request_param), the others are not input
        return params

    def _js_route_callback(self, fn) -> bool:
        if self.m.get("language") != "javascript":
            return False
        return any(isinstance(d, ast.Name) and d.id in ("route", "middleware") for d in getattr(fn, "decorator_list", []))

    @staticmethod
    def _js_request_param(fn) -> str | None:
        """The request parameter of an Express/Koa/Fastify/hapi callback: the first one, or the second in an
        error handler `(err, req, res, next)`."""
        names = [p.arg for p in fn.args.args if p.arg not in ("self", "cls")]
        if not names:
            return None
        if len(names) == 4 or (len(names) >= 2 and names[0] in ("err", "error", "e")):
            return names[1]
        return names[0]

    # --------------------------------------------------------- environment
    def _env(self, mod, cls, fn, path, seed_params: bool, entry: bool = False) -> _Env:
        env = _Env()
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            entry_params = set(self._entry_params(mod, cls, fn)) if entry else set()
            gated = self._gated_language()
            js_req = self._js_request_param(fn) if self._js_route_callback(fn) else None
            if js_req:
                env.webreq.add(js_req)
                env.vfields = _express_validated(fn)
            for p in fn.args.posonlyargs + fn.args.args + fn.args.kwonlyargs:
                if p.arg in {"self", "cls"}:
                    continue
                env.params.add(p.arg)
                if (_annotation_name(p.annotation) or "").split(".")[-1] in _OUTPUT_TYPES:
                    continue             # the response writer of a handler is output, not input
                if gated and p.annotation is not None and \
                        (_annotation_name(p.annotation) or "").split(".")[-1] in self._WEB_REQUEST_TYPES - {"Context", "WebSocket"} \
                        and self._webreq_param(mod, cls, fn, p):
                    env.webreq.add(p.arg)        # `({ query }: Request, res)`: whatever the parameter is called
                is_req = p.arg in self.m["request_params"] - {"self"}
                if is_req and gated:
                    is_req = p.arg in entry_params or self._webreq_param(mod, cls, fn, p)
                if is_req:
                    env.webreq.add(p.arg)
                if is_req and self.m.get("language") == "javascript":
                    is_req = False     # JS: request DATA (req.query, req.body …) is the source, not req.session / req.user
                t = self._resolve_class(mod, _annotation_name(p.annotation) or "")
                if t:
                    env.types[p.arg] = t
                if seed_params:
                    env.tainted[p.arg] = ("param", p.arg, ())
                elif p.arg in entry_params and self.m.get("language") == "python" and self._safe_annotation(mod, p.annotation):
                    pass             # FastAPI / typed handler parameter `age: int`: parsed and validated by the framework
                elif p.arg in entry_params and self.m.get("language") in ("java", "kotlin", "csharp") \
                        and (_safe_static_param(p.annotation) or self._project_enum(p.annotation)):
                    pass             # Spring `@RequestParam int id` / `@Pattern(regexp="^[a-z]+$") String code`: bound and checked
                    #                  (`@RequestParam Sort sort` of a project enum: binding accepts only its constants)
                elif p.arg in entry_params or is_req:
                    env.tainted[p.arg] = ("source", f"معامل نقطة الدخول {p.arg}", (_step(path, fn.lineno, f"def {fn.name}({p.arg})"),))
                    if p.arg in entry_params and self._cli_entry(fn):
                        # a command-line argument: a local source (see _LOCAL_SAFE_CWES)
                        env.tainted[p.arg] = env.tainted[p.arg] + (_LOCAL_SAFE_CWES,)
            for extra in (fn.args.vararg, fn.args.kwarg):
                if extra is not None and seed_params:
                    env.tainted[extra.arg] = ("param", extra.arg, ())
            if not seed_params:
                self._seed_captured(mod, fn, env)
        changed, passes = True, 0
        while changed and passes < MAX_PASSES:
            changed, passes = False, passes + 1
            for node in _scope_nodes(fn):
                targets, value, ann = None, None, None
                if isinstance(node, ast.Assign):
                    targets, value = node.targets, node.value
                elif isinstance(node, ast.AnnAssign):
                    targets, value, ann = [node.target], node.value, node.annotation
                elif isinstance(node, ast.AugAssign):
                    targets, value = [node.target], node.value
                elif isinstance(node, (ast.For, ast.AsyncFor)):
                    targets, value = [node.target], node.iter
                elif isinstance(node, ast.withitem) and node.optional_vars is not None:
                    targets, value = [node.optional_vars], node.context_expr
                elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                    c = node.value
                    root = c.func.value if isinstance(c.func, ast.Attribute) else None
                    while isinstance(root, ast.Call) and isinstance(root.func, ast.Attribute):
                        root = root.func.value             # sb.append(a).append(x): the write lands in sb
                    if isinstance(c.func, ast.Attribute) and c.func.attr in CONTAINER_WRITES and isinstance(root, ast.Name):
                        for a in list(c.args) + [k.value for k in c.keywords]:
                            o = self._taint(mod, cls, a, env)
                            if o and root.id not in env.tainted:
                                env.tainted[root.id] = _with_step(o, _step(path, node.lineno, f"{root.id}.{c.func.attr}(...)"))
                                env.elem.add(root.id)
                                changed = True
                    if isinstance(root, ast.Name) and root.id not in {"self", "cls"}:
                        # obj.setX(x) / builder.add(x).add(y): methods that store a parameter in a field of obj
                        link = c
                        while isinstance(link, ast.Call) and isinstance(link.func, ast.Attribute):
                            for fld, o in self._method_inst_fields(mod, cls, link, env).items():
                                if fld not in env.inst.setdefault(root.id, {}):
                                    env.inst[root.id][fld] = _with_step(o, _step(path, node.lineno, f"{root.id}.{link.func.attr}(...)"))
                                    changed = True
                            link = link.func.value
                    continue
                else:
                    continue
                line = getattr(node, "lineno", None) or getattr(getattr(node, "context_expr", None), "lineno", 0) or 0
                for tgt in targets or []:
                    # function values: h = helper / partial(helper, ...)
                    if value is not None and isinstance(tgt, ast.Name):
                        fq = None
                        if isinstance(value, (ast.Name, ast.Attribute)):
                            fq = self._resolve_function(mod, _dotted(value))
                            if fq is None and isinstance(value, ast.Attribute):
                                cands, _ = self._callees(mod, cls, ast.Call(func=value, args=[], keywords=[]), env)
                                fq = cands[0] if cands else None
                        elif isinstance(value, ast.Call) and self._canon(mod, value.func).split(".")[-1] == "partial" and value.args:
                            fq = self._resolve_function(mod, _dotted(value.args[0]))
                        if fq and env.funcs.get(tgt.id) != fq:
                            env.funcs[tgt.id] = fq
                            changed = True
                    # types
                    t = self._resolve_class(mod, _annotation_name(ann) or "") if ann is not None else None
                    if t is None and value is not None:
                        t = self._type_of(mod, cls, value, env)
                    if t and isinstance(tgt, ast.Name) and env.types.get(tgt.id) != t:
                        env.types[tgt.id] = t
                        changed = True
                    # instances built with tainted constructor args
                    if value is not None and isinstance(tgt, ast.Name) and isinstance(value, ast.Call):
                        for fld, o in self._ctor_inst_fields(mod, cls, value, env).items():
                            if fld not in env.inst.setdefault(tgt.id, {}):
                                env.inst[tgt.id][fld] = o
                                changed = True
                    if value is not None and isinstance(tgt, ast.Name) and isinstance(value, ast.Name) \
                            and value.id in env.inst and tgt.id not in env.inst:
                        env.inst[tgt.id] = dict(env.inst[value.id])
                        changed = True
                    if value is None:
                        continue
                    o = self._taint(mod, cls, value, env)
                    if o is None:
                        continue
                    if self.field_precise_locals and isinstance(tgt, ast.Attribute) and isinstance(tgt.value, ast.Name) \
                            and tgt.value.id not in {"self", "cls"}:
                        # record.field := v  (PL/SQL records / cursor rows): taint that field only
                        if tgt.attr not in env.inst.setdefault(tgt.value.id, {}):
                            env.inst[tgt.value.id][tgt.attr] = _with_step(o, _step(path, line, f"{tgt.value.id}.{tgt.attr} = …"))
                            changed = True
                        continue
                    if isinstance(tgt, ast.Subscript) and isinstance(tgt.value, ast.Name):
                        names, elem = [tgt.value.id], True
                    else:
                        names = [n.id for n in ast.walk(tgt) if isinstance(n, ast.Name)]
                        if isinstance(node, ast.AugAssign) or isinstance(value, ast.Dict):
                            elem = True
                        elif isinstance(value, (ast.List, ast.Tuple)):
                            elem = bool(value.elts) and self._taint(mod, cls, value.elts[0], env) is None \
                                and not _shell_launcher(value.elts)
                        else:
                            elem = False
                    for nm in names:
                        if nm not in env.tainted:
                            env.tainted[nm] = _with_step(o, _step(path, line, f"{nm} = …"))
                            if elem:
                                env.elem.add(nm)
                            changed = True
                        elif _safe_for(env.tainted[nm]) - _safe_for(o):
                            # another assignment brings a less-escaped value: keep only what both were escaped for
                            old_o = env.tainted[nm]
                            env.tainted[nm] = (old_o[0], old_o[1], _trail(old_o), _safe_for(old_o) & _safe_for(o)) \
                                + tuple(old_o[4:])
                            changed = True
                        elif not elem and nm in env.elem:
                            env.elem.discard(nm)
                            changed = True
        return env

    def _captured_names(self, q) -> frozenset:
        """Free variables of nested function q that a function around it binds (its parameters or assignments)."""
        cache = self.__dict__.setdefault("_captured_cache", {})
        hit = cache.get(q)
        if hit is not None:
            return hit
        info = self.gfuncs.get(q)
        out: set = set()
        if info and info["enclosing"]:
            fn = info["node"]

            def bound(f) -> set:
                a = f.args
                names = {p.arg for p in a.posonlyargs + a.args + a.kwonlyargs}
                names.update(x.arg for x in (a.vararg, a.kwarg) if x is not None)
                for n in _scope_nodes(f):
                    tgts = n.targets if isinstance(n, ast.Assign) else [getattr(n, "target", None)] \
                        if isinstance(n, (ast.AnnAssign, ast.AugAssign, ast.For, ast.AsyncFor)) else \
                        [n.optional_vars] if isinstance(n, ast.withitem) else []
                    for t in tgts:
                        for x in ast.walk(t) if t is not None else ():
                            if isinstance(x, ast.Name):
                                names.add(x.id)
                return names

            local = bound(fn)
            outer: set = set()
            for oq in info["enclosing"]:
                oi = self.gfuncs.get(oq)
                if oi is not None and isinstance(oi["node"], (ast.FunctionDef, ast.AsyncFunctionDef)):
                    outer |= bound(oi["node"])
            out = {n.id for n in _scope_nodes(fn) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)
                   and n.id not in local and n.id in outer}
        cache[q] = frozenset(out)
        return cache[q]

    def _seed_captured(self, mod, fn, env) -> None:
        """A nested function / callback reads variables of the function around it (closures: `const name =
        req.query.name; fs.stat(p, () => exec('ls ' + name))`): seed those free variables from the outer function."""
        idx = self.__dict__.get("_fn_qual")
        if idx is None:
            idx = self.__dict__["_fn_qual"] = {id(i["node"]): q for q, i in self.gfuncs.items()}
        q = idx.get(id(fn))
        if q is None or not self.gfuncs[q]["enclosing"]:
            return
        outer_q = self.gfuncs[q]["enclosing"][0]
        if outer_q not in self.gfuncs:
            return
        cache = self.__dict__.setdefault("_outer_envs", {})
        oinfo = self.gfuncs[outer_q]
        oenv = cache.get(outer_q)
        if oenv is None:
            cache[outer_q] = _Env()           # guard against cycles while it is computed
            oenv = cache[outer_q] = self._env(oinfo["mod"], oinfo["cls"], oinfo["node"], oinfo["path"], seed_params=False, entry=True)
        if not oenv.tainted and not oenv.webreq:
            return
        local = set(env.params)
        for n in _scope_nodes(fn):
            for t in (n.targets if isinstance(n, ast.Assign) else [getattr(n, "target", None)]
                      if isinstance(n, (ast.AnnAssign, ast.AugAssign, ast.For)) else []):
                for x in ast.walk(t) if t is not None else ():
                    if isinstance(x, ast.Name):
                        local.add(x.id)
        for n in _scope_nodes(fn):
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id not in local and n.id in oenv.webreq:
                env.webreq.add(n.id)      # `db.find().then(rows => res.render(v, {q: req.query.q}))`: the route's req
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id not in local and n.id in oenv.tainted \
                    and n.id not in env.tainted:
                env.tainted[n.id] = oenv.tainted[n.id]
                if n.id in oenv.elem:
                    env.elem.add(n.id)

    def _flow_at(self, mod, cls, fn, env, node):
        """The environment that holds at `node` according to the flow-sensitive refinement (see flow.py), or
        None when `node` is in code proven unreachable. Falls back to `env` wherever the refinement has no
        state for the node, so it can only remove taint, never add it."""
        if not getattr(self, "flow_refine", True):
            return env
        cache = self.__dict__.setdefault("_flow_cache", {})
        hit = cache.get(id(env))
        if hit is None or hit[0] is not env:
            try:
                fpath = (self.files.get(mod) or {}).get("path", "")
                fi = _flow.FlowInterpreter(self, mod, cls, fn, env, fpath).run()
            except (RecursionError, MemoryError, ValueError, TypeError, AttributeError, KeyError):
                fi = None
            hit = (env, fi)
            cache[id(env)] = hit
        fi = hit[1]
        if fi is None:
            return env
        st = fi.snap.get(id(node))
        if st is not None:
            return fi.env_for(st)
        if fi.dead:
            parents = self._parents(fn)
            n = node
            while n is not None:
                if id(n) in fi.dead:
                    return None
                n = parents.get(n)
        return env

    def _calls(self, fn: ast.AST):
        key = id(fn)
        hit = self._calls_cache.get(key)
        if hit is not None and hit[0] is fn:
            return hit[1]
        out = [n for n in _scope_nodes(fn) if isinstance(n, ast.Call)]
        self._calls_cache[key] = (fn, out)
        return out

    # ------------------------------------------------------------- guards
    def _parents(self, fn) -> dict:
        key = id(fn)
        if key in self._parents_cache:
            return self._parents_cache[key]
        parents: dict = {}
        stack = list(getattr(fn, "body", []) or [])
        for st in stack:
            parents[st] = fn
        while stack:
            n = stack.pop()
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)) and n is not fn:
                continue
            for ch in ast.iter_child_nodes(n):
                parents[ch] = n
                stack.append(ch)
        self._parents_cache[key] = parents
        return parents

    def _validated(self, mod, test, positive: bool, cwe: str | None = None) -> set:
        """Names a condition validates on the path where it is `positive` (True) or not.

        Real validation only: allow-lists (`x in ALLOWED`, `x == c`, exit on `x not in ALLOWED` / `x != c`),
        validator calls, whole-value character-class checks (`x.isalnum()`, `x.isdigit()`, `re.fullmatch(p, x)`).
        A deny-list exit validates only for the sink it actually protects: rejecting `..` guards a file path
        (CWE-22), nothing else. Prefix/suffix checks (`startswith`, `endswith`) and truthiness / None / length
        checks validate nothing."""
        if not positive:
            if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
                return self._validated(mod, test.operand, True, cwe)
            if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.Or):
                # all parts are False on this path: every rejection held
                return set().union(*[self._validated(mod, v, False, cwe) for v in test.values])
            if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And):
                # some part is False on this path, which one is unknown: only what each part's failure validates.
                # `(url or accepts_html) and not is_safe(url)` failing: url is empty, or it passed is_safe
                parts = [self._validated(mod, v, False, cwe) for v in test.values]
                return set.intersection(*parts) if parts else set()
            if isinstance(test, (ast.Name, ast.Attribute)) and _chain(test):
                return {_chain(test)}        # `if url: …` not taken: url is falsy (None / "" / 0) and carries no data
            if isinstance(test, ast.Compare) and len(test.ops) == 1:
                op = test.ops[0]
                path_sink = cwe in _PATH_CWES
                if isinstance(op, ast.In) and isinstance(test.left, ast.Constant) and isinstance(test.left.value, str) \
                        and path_sink and ".." in test.left.value:
                    return _names(test.comparators[0])          # `if '..' in p: reject` guards a path
                if isinstance(op, ast.NotIn):
                    return {_chain(test.left)} if _chain(test.left) else set()   # x not in ALLOWED -> exit
                if isinstance(op, ast.NotEq) and _chain(test.left) and isinstance(test.comparators[0], ast.Constant):
                    return {_chain(test.left)}
                if path_sink and isinstance(op, (ast.Gt, ast.GtE, ast.NotEq)) and isinstance(test.left, ast.Call) \
                        and isinstance(test.left.func, ast.Attribute) and test.left.func.attr in ("find", "index", "count", "indexOf") \
                        and test.left.args and isinstance(test.left.args[0], ast.Constant) and ".." in str(test.left.args[0].value):
                    return _names(test.left.func.value)          # p.find('..') != -1 -> exit
            if isinstance(test, ast.Call) and cwe in _PATH_CWES:
                fname = self._canon(mod, test.func).split(".")[-1]
                if fname in ("contains", "includes") and test.args and isinstance(test.args[0], ast.Constant) \
                        and ".." in str(test.args[0].value) and isinstance(test.func, ast.Attribute):
                    return _names(test.func.value)               # p.contains("..") -> exit (Java/JS)
            return set()
        if isinstance(test, ast.BoolOp):
            parts = [self._validated(mod, v, True, cwe) for v in test.values]
            if isinstance(test.op, ast.And):
                return set().union(*parts)
            return set.intersection(*parts) if parts else set()
        if isinstance(test, ast.Compare):
            out = set()
            if _chain(test.left) and any(isinstance(op, (ast.In, ast.Eq)) for op in test.ops):
                out.add(_chain(test.left))
            return out
        if isinstance(test, ast.Call) and isinstance(test.func, ast.Attribute) and test.func.attr in _CONFINEMENT \
                and cwe in _PATH_CWES:
            return _names(test.func.value)  # p.resolve().is_relative_to(base): the path is confined to base
        if isinstance(test, ast.Call) and isinstance(test.func, ast.Attribute) and test.func.attr in _SHAPE_CHECKS:
            if test.func.attr in ("fullmatch", "matches"):
                # re.fullmatch(p, x) / pat.fullmatch(x) / x.matches(regex): the checked value, not the pattern
                module_call = isinstance(test.func.value, ast.Name) and test.func.value.id == "re"
                pat = test.args[0] if (module_call or test.func.attr == "matches") and test.args else None
                if pat is None and isinstance(test.func.value, ast.Name):
                    # NAME_RE.fullmatch(x) with a module-level NAME_RE = re.compile("…")
                    comp = self._module_const(mod, test.func.value.id)
                    if isinstance(comp, ast.Call) and comp.args and self._canon(mod, comp.func).split(".")[-1] == "compile":
                        pat = comp.args[0]
                pat = self._module_const(mod, pat.id) if isinstance(pat, ast.Name) and self._module_const(mod, pat.id) \
                    is not None else pat
                if isinstance(pat, ast.Constant) and isinstance(pat.value, str) and _PERMISSIVE_RE.search(pat.value):
                    return set()             # `.+@.+` / `.*` accept almost anything: not validation
                vals = test.args[1:] if module_call else ([test.func.value] if test.func.attr == "matches" else test.args[:1])
                return set().union(*[_paths(a) for a in vals]) if vals else set()
            return _paths(test.func.value)                      # x.isalnum() / x.isdigit() …
        if isinstance(test, ast.Call):
            fname = self._canon(mod, test.func).split(".")[-1]
            if fname.lower().rstrip("?") in _NOT_VALIDATION:
                return set()                 # prefix / suffix / existence / emptiness checks confine nothing
            if not test.args and isinstance(test.func, ast.Attribute) and (fname in ("is_valid", "validate_on_submit") or (
                    fname in ("validate", "full_clean") and re.search(r"(?i)form|serializer|schema", _chain(test.func.value) or ""))):
                return set()                 # a whole form: each field is as safe as its type (_schema_validated)
            # access paths, not base names: allowed_file(file.filename) validates the name, not file.stream
            arg_names = set().union(*[_paths(a) for a in list(test.args) + [k.value for k in test.keywords]]) \
                if (test.args or test.keywords) else set()
            if fname.lower() in _MEMBERSHIP:
                return arg_names             # ALLOWED.contains(x) / in_array(x, $allowed): the looked-up value
            names = set(arg_names)
            if isinstance(test.func, ast.Attribute) and _chain(test.func.value):
                names.add(_chain(test.func.value))
            if fname in self.m["validators"] or any(v in fname for v in ("valid", "safe", "allowed", "check", "verify")):
                return names
        return set()

    def _guarded(self, mod, fn, call, names: set, si=None, depth: int = 0) -> bool:
        """True when every tainted name feeding the sink was validated on the path to it."""
        if not names:
            return False
        parents = self._parents(fn)
        validated: set = set()
        node = call
        while node in parents:
            parent = parents[node]
            if isinstance(parent, ast.If):
                in_body = any(node is x for x in parent.body)
                validated |= self._validated(mod, parent.test, positive=in_body, cwe=si[5] if si else None)
            for field in ("body", "orelse", "finalbody"):
                block = getattr(parent, field, None)
                if isinstance(block, list) and any(node is x for x in block):
                    idx = next(i for i, x in enumerate(block) if x is node)
                    for prev in block[:idx]:
                        if isinstance(prev, ast.If) and _exits(prev.body) and not prev.orelse:
                            validated |= self._validated(mod, prev.test, positive=False, cwe=si[5] if si else None)
                        elif isinstance(prev, ast.If) and not prev.orelse:
                            # `if not is_safe(url): url = "/"`: past it the value was either validated or replaced
                            neg = self._validated(mod, prev.test, positive=False, cwe=si[5] if si else None)
                            validated |= {n for n in neg if self._rebinds_safely(mod, prev.body, n, si)}
            node = parent
        return all(_path_covered(p, validated) or self._derived_from_guarded(mod, fn, call, p, si, depth)
                   for p in names)

    def _derived_from_guarded(self, mod, fn, call, name: str, si, depth: int) -> bool:
        """`nt = translate(next_url, code)` assigned once, before the sink, from values that were all validated at
        that assignment: `nt` is derived from validated data, as `next_url + "?x"` written at the sink would be."""
        if depth >= 3 or "." in name or not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return False
        line = getattr(call, "lineno", 0)
        stores = [x for x in ast.walk(fn) if isinstance(x, ast.Name) and x.id == name and not isinstance(x.ctx, ast.Load)]
        assigns = [st for st in ast.walk(fn) if isinstance(st, ast.Assign) and len(st.targets) == 1
                   and isinstance(st.targets[0], ast.Name) and st.targets[0].id == name]
        if len(stores) != 1 or len(assigns) != 1 or name in {a.arg for a in fn.args.args + fn.args.kwonlyargs}:
            return False                          # rebound elsewhere (loop target, augmented, a parameter): unknown
        st = assigns[0]
        if not (0 < st.lineno < line):
            return False
        funcs = {id(c.func) for c in ast.walk(st.value) if isinstance(c, ast.Call)}
        used = {x.id for x in ast.walk(st.value) if isinstance(x, ast.Name) and isinstance(x.ctx, ast.Load)
                and id(x) not in funcs}
        return bool(used) and self._guarded(mod, fn, st, used, si, depth + 1)

    def _rebinds_safely(self, mod, body, name, si) -> bool:
        """Does `body` end by giving `name` a constant (or by validating it again the same way)?"""
        for st in reversed(body):
            if isinstance(st, (ast.Assign, ast.AnnAssign)):
                tgts = st.targets if isinstance(st, ast.Assign) else [st.target]
                if any(isinstance(t, ast.Name) and t.id == name for t in tgts):
                    return isinstance(st.value, ast.Constant)
            elif isinstance(st, ast.If) and not st.orelse and any(
                    isinstance(x, ast.Name) and x.id == name and isinstance(x.ctx, ast.Store)
                    for b in st.body for x in ast.walk(b)):
                return name in self._validated(mod, st.test, positive=False, cwe=si[5] if si else None) \
                    and self._rebinds_safely(mod, st.body, name, si)
            elif any(isinstance(x, ast.Name) and x.id == name and isinstance(x.ctx, ast.Store) for x in ast.walk(st)):
                return False
        return False

    _DB_GENERATED = frozenset({"ID", "PK", "UUID", "CREATEDAT", "UPDATEDAT", "MODIFIEDAT", "ROWID", "OID", "VERSION"})

    def _stored_column_written(self, o, key: str) -> bool:
        """For taint from a stored row (second-order source): was column `key` of that table written by a user?
        Table and columns come from the stored-source models (stored_db.T.C); DB-generated keys never were."""
        if not (o and o[0] == "source" and isinstance(o[1], str) and STORED_SOURCE_MARK in o[1]):
            return True
        m = re.search(r"([A-Z0-9_$#]+)\.([A-Z0-9_$#*]+)", o[1])
        if not m:
            return True
        table, col = m.group(1), re.sub(r"[^0-9A-Za-z]", "", key).upper()
        if table == "ANY_TABLE":
            return col not in self._DB_GENERATED
        written = set()
        for names, _label in self.m.get("prefix_sources", []):
            for n in names:
                parts = n.split(".")
                if len(parts) == 3 and parts[0] == "stored_db" and parts[1] == table and parts[2]:
                    written.add(parts[2])
        if not written or "*" in written:
            return col not in self._DB_GENERATED
        return col in written

    def _note_dep(self, tok) -> None:
        deps = self._dep_holder[0] if hasattr(self, "_dep_holder") else None
        if deps is not None:
            deps.add(tok)

    def over_budget(self) -> bool:
        """Past the project-wide analysis deadline (see analyze_project_full): degrade instead of running on."""
        dl = getattr(self, "deadline", None)
        if dl is not None and time.monotonic() > dl:
            self.budget_hit = True
            return True
        return False

    def _tainted_names_in(self, expr, env) -> set:
        return {p for p in _paths(expr) if p.split(".")[0] in env.tainted or p.split(".")[0] in env.webreq}

    # ------------------------------------------------------------ summaries
    def build(self):
        self._resolve_cache.clear()
        self.link()
        self._resolve_cache.clear()
        self.obj_taint: dict = {}
        self.obj_taint_by_oid: dict = {}
        self._dep_holder = holder = [None]
        self.classes = _TrackDict(self.classes, holder, "c")
        self._hier_cache = {}
        shared = getattr(self, "shared_pointsto", None)
        reuse = shared.get("pt") if shared is not None else None
        if reuse is not None:
            # stored-data passes rebuild the project over the same trees with more sources / sinks: points-to does
            # not read the models (only the code and its name resolution), so the first pass's solution holds
            reuse.p = self
            self.pt = reuse
        else:
            try:
                from .pointsto import PointsTo
                self.pt = PointsTo(self)
            except Exception:  # noqa: BLE001 - points-to is an enhancement; never block the scan
                self.pt = None
            if shared is not None and self.pt is not None and not self.pt.timed_out:
                shared["pt"] = self.pt
        self.summaries = _TrackDict({}, holder, "s")
        for q in self.gfuncs:
            self.summaries[q] = {"source_return": None, "ret_params": set(), "sink_params": {},
                                 "sink_fields": {}, "ret_fields": set(), "ret_type": None, "ret_line": 0, "cb_calls": []}
        # Worklist fixpoint: a function is analyzed again only when something it read (a callee summary, a class's
        # fields, points-to object fields) changed after its last analysis.
        epoch = 0
        changed_at: dict = {}            # dependency token -> epoch of its last change
        analyzed_at: dict = {}           # function -> (epoch of its last analysis, its dependency tokens)
        changed, passes = True, 0
        self.build_passes = 0
        # Some facts are "last writer wins" across methods (two methods assign different types to one field), so a
        # pass can end in exactly the state the previous pass ended in while still reporting changes. A pass that
        # repeats the previous one (same analyses, same outcomes, nothing new in the object facts) leaves every later
        # pass identical too: stop there instead of repeating it until MAX_PASSES.
        prev_transcript = None
        while changed and passes < MAX_PASSES:
            changed, passes = False, passes + 1
            self.build_passes = passes
            self.__dict__["_flow_cache"] = {}
            if self.over_budget():
                break                    # degrade: keep the summaries computed so far
            transcript: list | None = []
            for q, info in self.gfuncs.items():
                if self.over_budget():
                    break
                prev = analyzed_at.get(q)
                if prev is not None and not any(changed_at.get(t, -1) > prev[0] for t in prev[1]):
                    continue
                deps = set()
                holder[0] = deps
                epoch += 1
                start_epoch = epoch
                obj_chg = cls_chg = False
                try:
                    summ_changed = self._summarize(q, info, deps)
                finally:
                    holder[0] = None
                    # flow states are cached per environment object, and each analysis builds its own: once it
                    # is done they can never be hit again (keeping them held every function's states in memory)
                    self.__dict__["_flow_cache"] = {}
                obj_chg, cls_chg = self._last_obj_chg, self._last_cls_chg
                analyzed_at[q] = (start_epoch, deps)
                if transcript is not None:
                    if obj_chg:
                        transcript = None
                    else:
                        cq = info["cls"]
                        transcript.append((q, summ_changed, cls_chg, dict(dict.__getitem__(self.summaries, q)),
                                           _class_facts(dict.__getitem__(self.classes, cq)) if cq in self.classes else None))
                if summ_changed or obj_chg or cls_chg:
                    changed = True
                    epoch += 1
                    if summ_changed:
                        changed_at[("s", q)] = epoch
                    if obj_chg:
                        changed_at[("o", 0)] = epoch
                    if cls_chg and info["cls"]:
                        changed_at[("c", info["cls"])] = epoch
            if changed and transcript is not None and transcript == prev_transcript:
                break
            prev_transcript = transcript

    def _summarize(self, q, info, deps) -> bool:
        """One analysis of function q: updates its summary (and class / object field facts); True if the summary changed."""
        changed = obj_chg = cls_chg = False
        mod, fn, cls, path = info["mod"], info["node"], info["cls"], info["path"]
        summ = dict.__getitem__(self.summaries, q)   # its own summary: not a dependency
        cls_before = _class_facts(dict.__getitem__(self.classes, cls)) if cls in self.classes else None
        env = self._env(mod, cls, fn, path, seed_params=True)
        for nm in self._captured_names(q):
            # a closure's free variable is a hidden parameter: `crit = () => ({$where: "…" + t})` returns what the
            # caller's `t` holds, mapped back at the call site (see the `ret_params` use in _taint)
            env.tainted.setdefault(nm, ("param", nm, ()))
        new = {"source_return": summ["source_return"], "ret_params": set(summ["ret_params"]),
               "sink_params": {k: list(v) for k, v in summ["sink_params"].items()},
               "sink_fields": {k: list(v) for k, v in summ["sink_fields"].items()},
               "ret_fields": set(summ["ret_fields"]), "ret_type": summ["ret_type"], "ret_line": summ["ret_line"],
               "cb_calls": list(summ["cb_calls"])}
        rt = self._resolve_class(mod, _annotation_name(getattr(fn, "returns", None)) or "")
        if rt:
            new["ret_type"] = rt
        for node in _scope_nodes(fn):
            if isinstance(node, ast.Return) and node.value is not None:
                renv = self._flow_at(mod, cls, fn, env, node)
                o = self._taint(mod, cls, node.value, renv) if renv is not None else None
                if o and o[0] in {"source", "retsource"} and not new["source_return"]:
                    new["source_return"] = o
                    new["ret_line"] = node.lineno
                elif o and o[0] == "param" and not self._guarded(mod, fn, node, self._tainted_names_in(node.value, renv)):
                    # (a guarded return gives back a validated value: `if (!SAFE.matcher(s).matches()) return null;`)
                    new["ret_params"].update(_origin_params(o))
                    new["ret_line"] = new["ret_line"] or node.lineno
                elif o and o[0] == "field":
                    new["ret_fields"].add(o[1])
                if new["ret_type"] is None:
                    t = self._type_of(mod, cls, node.value, env)
                    if t:
                        new["ret_type"] = t
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None and self.pt is not None:
                for tgt in (node.targets if isinstance(node, ast.Assign) else [node.target]):
                    if isinstance(tgt, ast.Attribute):
                        o = self._taint(mod, cls, node.value, env)
                        if o and o[0] in {"source", "retsource"}:
                            for obj in self.pt.objs(tgt.value):
                                key = (id(obj), tgt.attr)
                                if key not in self.obj_taint:
                                    self.obj_taint[key] = _with_step(o, _step(path, node.lineno, f"{_dotted(tgt.value)}.{tgt.attr} = …"))
                                    self.obj_taint_by_oid.setdefault(id(obj), {})[tgt.attr] = self.obj_taint[key]
                                    obj_chg = True
            if cls and isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                tgts = node.targets if isinstance(node, ast.Assign) else [node.target]
                for tgt in tgts:
                    if isinstance(tgt, ast.Attribute) and isinstance(tgt.value, ast.Name) and tgt.value.id == "self":
                        c = self.classes[cls]
                        o = self._taint(mod, cls, node.value, env)
                        if o and o[0] in {"source", "retsource"} and tgt.attr not in c["tainted_fields"]:
                            c["tainted_fields"][tgt.attr] = _with_step(o, _step(path, node.lineno, f"self.{tgt.attr} = …"))
                            cls_chg = True
                        if o and o[0] == "param" and info["name"] == "__init__" and c["ctor_param_fields"].get(o[1]) != tgt.attr:
                            c["ctor_param_fields"][o[1]] = tgt.attr
                            cls_chg = True
                        if o and o[0] == "param" and info["name"] != "__init__":
                            cls_chg |= self._note_param_field(c, info["name"], o, tgt.attr)
                        t = self._type_of(mod, cls, node.value, env)
                        if t and c["field_types"].get(tgt.attr) != t:
                            c["field_types"][tgt.attr] = t
                            cls_chg = True
            if cls and isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) \
                    and isinstance(node.value.func, ast.Attribute) and node.value.func.attr in CONTAINER_WRITES:
                # self.parts.append(p) / parts.add(p): the parameter lands in the field
                holder = node.value.func.value
                if isinstance(holder, ast.Attribute) and isinstance(holder.value, ast.Name) and holder.value.id == "self":
                    c = self.classes[cls]
                    for a in list(node.value.args) + [k.value for k in node.value.keywords]:
                        o = self._taint(mod, cls, a, env)
                        if o and o[0] == "param":
                            cls_chg |= self._note_param_field(c, info["name"], o, holder.attr)
                            if info["name"] == "__init__" and o[1] not in c["ctor_param_fields"]:
                                c["ctor_param_fields"][o[1]] = holder.attr
                                cls_chg = True
        for call in self._calls(fn):
            self._absorb_sinks(mod, cls, fn, path, call, env, new)
        for node in _scope_nodes(fn):
            hit = self._attr_sink(node)
            if hit:
                si, value = hit
                aenv = self._flow_at(mod, cls, fn, env, node)
                for o in (self._taints(mod, cls, value, aenv) if aenv is not None else []):
                    if not _unsafe_for(o, si):
                        continue
                    if o[0] in {"param", "field"} and not self._suppressed(path, node.lineno):
                        lst = (new["sink_params"] if o[0] == "param" else new["sink_fields"]).setdefault(o[1], [])
                        if (si, path, node.lineno) not in lst:
                            lst.append((si, path, node.lineno))
        if new != summ:
            summ.update(new)
            changed = True
        if cls_chg and cls_before is not None:
            # facts overwritten and then restored within one analysis (`self.a = p; self.b = p` maps p to a, then b;
            # two types assigned to one field) are not a change: reporting them kept the fixpoint re-analysing the
            # class's dependents until MAX_PASSES with identical results
            cls_chg = _class_facts(dict.__getitem__(self.classes, cls)) != cls_before
        self._last_obj_chg, self._last_cls_chg = obj_chg, cls_chg
        return changed

    def _absorb_sinks(self, mod, cls, fn, path, call, env, new):
        def record(origin, entry):
            if origin[0] == "param":
                lst = new["sink_params"].setdefault(origin[1], [])
            elif origin[0] == "field":
                lst = new["sink_fields"].setdefault(origin[1], [])
            else:
                return
            if entry not in lst:
                lst.append(entry)

        env = self._flow_at(mod, cls, fn, env, call)
        if env is None:
            return                                  # unreachable code
        si = self._sink(mod, cls, call, env)
        # a sink whose text lives in another file (a MyBatis mapper XML statement) is reported there
        at_path, at_line = getattr(call, "vulnscan_at", None) or (path, call.lineno)
        if si and not self._suppressed(at_path, at_line):
            for arg in self._sink_args(si, call):
                if not self._sink_arg_ok(fn, si, arg, env):
                    continue
                origins = [o for o in self._taints(mod, cls, arg, env) if _unsafe_for(o, si)]
                if origins and not self._guarded(mod, fn, call, self._tainted_names_in(arg, env), si):
                    for o in origins:
                        record(o, (si, at_path, at_line))
        cb_param = self._callback_param(fn, call)
        if cb_param is not None:
            pos = [(i, self._taint(mod, cls, a, env)) for i, a in enumerate(call.args)]
            kwo = {k.arg: self._taint(mod, cls, k.value, env) for k in call.keywords if k.arg}
            entry = (cb_param, [(i, o) for i, o in pos if o], {k: o for k, o in kwo.items() if o}, path, call.lineno)
            if entry not in new["cb_calls"]:
                new["cb_calls"].append(entry)
            return
        callees, ctor = self._callees(mod, cls, call, env)
        if ctor:
            return
        fields, is_self = self._receiver_fields(mod, cls, call, env)
        for q in callees:
            summ = self.summaries.get(q)
            if not summ:
                continue
            mapping = self._map_args(call, q)
            for pname, entries in summ["sink_params"].items():
                arg = mapping.get(pname)
                if arg is None:
                    continue
                origins = self._taints(mod, cls, arg, env)
                if origins and not self._guarded(mod, fn, call, self._tainted_names_in(arg, env)):
                    entries = self._at_call_site(mod, cls, arg, env, entries)
                    for o in origins:
                        for e in entries:
                            if _unsafe_for(o, e[0]):
                                record(o, e)
            if is_self:
                for fld, entries in summ["sink_fields"].items():
                    for e in entries:
                        record(("field", fld, ()), e)
            # the callee itself calls one of ITS parameters: resolve the function value passed here, per call site
            for cb in summ["cb_calls"]:
                self._apply_callback(mod, cls, fn, path, call, env, q, cb, record, None)

    @staticmethod
    def _callback_param(fn, call):
        """Name of the parameter of fn that this call invokes (f(x) where f is a parameter), else None."""
        if isinstance(call.func, ast.Name) and isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if call.func.id in _param_names(fn):
                return call.func.id
        return None

    def _func_values(self, mod, cls, expr, env) -> list[str]:
        """Function quals an argument expression may evaluate to (static name or points-to function objects)."""
        out = []
        if isinstance(expr, (ast.Name, ast.Attribute)):
            q = self._resolve_function(mod, _dotted(expr))
            if q:
                out.append(q)
            if isinstance(expr, ast.Name) and expr.id in env.funcs:
                out.append(env.funcs[expr.id])
        pt = getattr(self, "pt", None)
        if pt is not None:
            out.extend(q for q in pt.funcs_for(expr) if q in self.gfuncs)
        return sorted(set(out))

    def _apply_callback(self, mod, cls, fn, path, call, env, q, cb, record, emit_ctx):
        """At a call site of q, resolve the function value passed for q's callback parameter and
        propagate its sinks: per call site, so run_all(shell, t) and run_all(logger, t) differ."""
        cb_param, pos_origins, kw_origins, cb_path, cb_line = cb
        mapping = self._map_args(call, q)
        cb_arg = mapping.get(cb_param)
        if cb_arg is None:
            return
        for q2 in self._func_values(mod, cls, cb_arg, env):
            summ2 = self.summaries.get(q2)
            if not summ2:
                continue
            fn2 = self.gfuncs[q2]["node"]
            a2 = fn2.args
            pos2 = [p.arg for p in (a2.posonlyargs + a2.args)]
            off2 = 1 if (pos2 and pos2[0] in {"self", "cls"} and isinstance(cb_arg, ast.Attribute)) else 0
            def actual(origin):
                # origin inside q: a param of q -> the argument passed here; a real source -> itself
                if origin[0] == "param":
                    arg = mapping.get(origin[1])
                    return self._taint(mod, cls, arg, env) if arg is not None else None
                return origin
            bindings = []
            for i, o in pos_origins:
                j = i + off2
                if j < len(pos2):
                    bindings.append((pos2[j], actual(o)))
                elif a2.vararg:
                    bindings.append((a2.vararg.arg, actual(o)))
            for k, o in kw_origins.items():
                bindings.append((k, actual(o)))
            for pname2, o in bindings:
                if not o:
                    continue
                for e in summ2["sink_params"].get(pname2, []):
                    if emit_ctx is None:
                        record(o, e)
                    elif o[0] in {"source", "retsource"}:
                        self._emit(e[0], emit_ctx[0], emit_ctx[1], o, self.gfuncs[q2]["name"], e)

    # ------------------------------------------------------------ reporting
    def report(self) -> list[Finding]:
        scopes = [(i["mod"], i["cls"], i["node"], i["path"]) for i in self.gfuncs.values()]
        for mod, file in self.files.items():
            scopes.append((mod, None, file["tree"], file["path"]))
        self.__dict__["_flow_cache"] = {}
        self.__dict__["_outer_envs"] = {}
        hard = getattr(self, "hard_deadline", None)
        for mod, cls, fn, path in scopes:
            if hard is not None and time.monotonic() > hard:
                self.budget_hit = self.report_cut = True
                break                        # keep what was found so far; the scan notes say it was cut short
            self.__dict__["_flow_cache"] = {}  # (per environment: the previous scope's states are never hit again)
            fenv = self._env(mod, cls, fn, path, seed_params=False, entry=True)
            is_entry = self._is_entry(mod, cls, fn)
            for call in self._calls(fn):
                env = self._flow_at(mod, cls, fn, fenv, call)
                if env is None:
                    continue                        # unreachable code
                si = self._sink(mod, cls, call, env)
                if si:
                    for arg in self._sink_args(si, call):
                        if not self._sink_arg_ok(fn, si, arg, env):
                            continue
                        o = self._sink_taint(mod, cls, arg, env, si)
                        if o and o[0] in {"source", "retsource"} \
                                and not self._guarded(mod, fn, call, self._tainted_names_in(arg, env), si):
                            self._emit(si, path, call.lineno, o, None, None)
                            break
                if self._callback_param(fn, call) is not None:
                    continue
                callees, ctor = self._callees(mod, cls, call, env)
                if ctor:
                    continue
                fields, _ = self._receiver_fields(mod, cls, call, env)
                for q in callees:
                    summ = self.summaries.get(q)
                    if not summ:
                        continue
                    name = self.gfuncs[q]["name"]
                    mapping = self._map_args(call, q)
                    done = False
                    for pname, entries in summ["sink_params"].items():
                        arg = mapping.get(pname)
                        if arg is None:
                            continue
                        entries = self._at_call_site(mod, cls, arg, env, entries)
                        live = [e for e in entries if any(_unsafe_for(x, e[0]) for x in self._taints(mod, cls, arg, env))]
                        # one finding per kind of sink the callee reaches: a helper that logs the path and then
                        # reads the file is both log injection and path traversal (java-sec-code PathTraversal)
                        kinds: dict = {}
                        for e in live:
                            kinds.setdefault(e[0][0], e)
                        if len(callees) > 1:
                            kinds = dict(list(kinds.items())[:1])   # an ambiguous call: only its first sink kind
                        for e in kinds.values():
                            o = self._sink_taint(mod, cls, arg, env, e[0])
                            if o and o[0] in {"source", "retsource"} \
                                    and not self._guarded(mod, fn, call, self._tainted_names_in(arg, env), e[0]):
                                self._emit(e[0], path, call.lineno, o, name, e)
                                done = True
                        if done:
                            break
                    if done:
                        continue
                    for fld, entries in summ["sink_fields"].items():
                        if fld in fields:
                            self._emit(entries[0][0], path, call.lineno, fields[fld], name, entries[0])
                            break
                    for cb in summ["cb_calls"]:
                        self._apply_callback(mod, cls, fn, path, call, env, q, cb, None, (path, call.lineno))
            for node in _scope_nodes(fn):
                hit = self._attr_sink(node)
                if hit:
                    si, value = hit
                    env = self._flow_at(mod, cls, fn, fenv, node)
                    o = self._sink_taint(mod, cls, value, env, si) if env is not None else None
                    if o and o[0] in {"source", "retsource"} and not self._guarded(mod, fn, node, self._tainted_names_in(value, env), si):
                        self._emit(si, path, node.lineno, o, None, None)
            # server-side templates: render_template("t.html", var=tainted) where t.html prints {{ var|safe }}
            if self.m.get("language") == "python" and _TEMPLATES:
                for call in self._calls(fn):
                    for kw_name, value in self._template_context(mod, call):
                        env = self._flow_at(mod, cls, fn, fenv, call)
                        o = self._sink_taint(mod, cls, value, env, TEMPLATE_UNESCAPED) if env is not None else None
                        if o and o[0] in {"source", "retsource"}:
                            self._emit(TEMPLATE_UNESCAPED, path, call.lineno, o, None, None)
                            break
                # aiohttp_jinja2: `@template("t.jinja2")` handlers return the template context as a dict
                tname = self._aiohttp_template(mod, fn)
                if tname:
                    unsafe = _template_unsafe_vars(tname, all_vars=self._aiohttp_unescaped())
                    for node in _scope_nodes(fn):
                        if unsafe and isinstance(node, ast.Return) and isinstance(node.value, ast.Dict):
                            env = None
                            for k, v in zip(node.value.keys, node.value.values):
                                if isinstance(k, ast.Constant) and k.value in unsafe:
                                    env = env or self._flow_at(mod, cls, fn, fenv, node)
                                    o = self._sink_taint(mod, cls, v, env, TEMPLATE_UNESCAPED) if env is not None else None
                                    if o and o[0] in {"source", "retsource"}:
                                        self._emit(TEMPLATE_UNESCAPED, path, node.lineno, o, None, None)
                                        break
            # Express / Koa / Fastify views: res.render("view", {x: tainted}) where the view prints x unescaped
            # (EJS <%- x %>, Handlebars {{{x}}}, Pug !{x} / p!= x, Swig / Nunjucks with autoescape off)
            if self.m.get("language") == "javascript" and _TEMPLATES:
                for call in self._calls(fn):
                    for kw_name, value in self._js_template_context(fn, call):
                        env = self._flow_at(mod, cls, fn, fenv, call)
                        o = self._sink_taint(mod, cls, value, env, JS_TEMPLATE_UNESCAPED) if env is not None else None
                        if o and o[0] in {"source", "retsource"} and not self._guarded(
                                mod, fn, call, self._tainted_names_in(value, env), JS_TEMPLATE_UNESCAPED):
                            self._emit(JS_TEMPLATE_UNESCAPED, path, call.lineno, o, None, None)
                            break
            # reflected output from an entry point: `return tainted`
            if is_entry:
                for node in _scope_nodes(fn):
                    if isinstance(node, ast.Return) and node.value is not None:
                        v = node.value
                        body = v.elts[0] if isinstance(v, ast.Tuple) and v.elts else v   # Flask `return jsonify(x), 200`
                        if isinstance(body, ast.Call) and any(_name_matches(self._canon(mod, body.func), s) for s in self.m["safe_return_calls"]):
                            continue
                        if not self._html_return(mod, fn, v):
                            continue
                        env = self._flow_at(mod, cls, fn, fenv, node)
                        o = self._sink_taint(mod, cls, v, env, REFLECTED_RETURN) if env is not None else None
                        if o and o[0] in {"source", "retsource"} \
                                and not self._guarded(mod, fn, node, self._tainted_names_in(v, env), REFLECTED_RETURN):
                            self._emit(REFLECTED_RETURN, path, node.lineno, o, None, None)
        seen, uniq = set(), []
        for f in self.findings:
            k = (f.rule_id, f.file, f.line, f.title if f.rule_id == "DFSTORE" else "")   # one internal write per column
            if k not in seen:
                seen.add(k)
                uniq.append(f)
        return uniq

    @staticmethod
    def _label(origin) -> str:
        if origin[0] == "retsource":
            return f"قيمة من {origin[1]}()"
        return origin[1]

    def _suppressed(self, path, line) -> bool:
        lines = self.lines_by_path.get(path) or []
        return 0 < line <= len(lines) and bool(SUPPRESS.search(lines[line - 1]))

    def _emit(self, si, path, line, origin, callee, deep):
        if self._suppressed(path, line) or (deep and self._suppressed(deep[1], deep[2])):
            return
        if _php_include.INLINED and (path, line) in _php_include.INLINED:
            # the sink is in code a PHP include spliced in at this line (see php_include): a source spliced in at
            # the same include means the flow lies wholly inside the included file, which reports it itself
            if any(st.get("file") == path and st.get("line") == line and str(st.get("text", "")).startswith("include ")
                   for st in _trail(origin) if isinstance(st, dict)):
                return
            callee = callee or "include"
        rule, sev, title, title_ar, advice, cwe, label = si[:7]
        source_label = self._label(origin)
        steps = list(_trail(origin))
        steps.append(_step(path, line, f"استدعاء {callee}()" if callee else f"نقطة الخطر: {label}"))
        if deep and (deep[1], deep[2]) != (path, line):
            steps.append(_step(deep[1], deep[2], f"نقطة الخطر: {label}"))
        extra = {"analysis": "dataflow", "taint_source": source_label, "path": steps}
        if callee:
            title = f"Tainted data flows through {callee}() into {label}"
            title_ar = f"بيانات غير موثوقة تمرّ عبر {callee}() وتصل إلى {label}"
            snippet = f"المصدر: {source_label} ← {callee}()"
            extra.update(interprocedural=True, callee=callee)
        else:
            snippet = f"المصدر: {source_label}"
            if origin[0] == "retsource":
                extra["interprocedural"] = True
        self.findings.append(Finding(rule, sev, title, title_ar, path, line, snippet, advice, cwe,
                                     source="taint", extra=extra))


def _module_name(rel: str) -> str:
    rel = rel.replace("\\", "/")
    rel = rel[:-3] if rel.endswith(".py") else rel
    rel = rel[:-9] if rel.endswith("/__init__") else rel
    return rel.replace("/", ".")


def _language(rel: str) -> str | None:
    low = rel.lower()
    from .plsql_frontend import PLSQL_EXTS
    if low.endswith(PLSQL_EXTS + (".yaml", ".yml", ".xml", ".json")):
        return "plsql"     # .yaml/.xml/.json only reach the engine when they carry Oracle code (see scanner)
    if low.endswith(PY_EXTS):
        return "python"
    if low.endswith(JS_EXTS) and not low.endswith((".d.ts", ".min.js")):
        return "javascript"
    for ext, lang in CFAMILY.items():
        if low.endswith(ext):
            return lang
    return None


def load_models_for(language: str, extra_dirs=()) -> dict:
    """Built-in models for a language (Kotlin layers on Java), plus user model dirs."""
    base = {"python": DEFAULT_MODELS, "javascript": DEFAULT_JS_MODELS}.get(language, MODELS_DIR / f"{language}.json")
    m = load_models(extra_dirs, base, language)
    if language == "kotlin":
        j = load_models(extra_dirs, MODELS_DIR / "java.json", "kotlin")
        for k in ("attr_sources", "call_sources", "name_sources", "sinks", "attr_sinks"):
            m[k] = m[k] + [x for x in j[k] if x not in m[k]]
        for k in ("entry_decorators", "view_bases", "view_methods", "request_params", "sanitizers", "safe_return_calls", "validators"):
            m[k] = m[k] | j[k]
    return m


def _view_code(rel: str, text: str) -> str:
    """The code the engine analyses for a file: an ERB view becomes Ruby (see erb_frontend), the rest is as is."""
    from . import erb_frontend
    return erb_frontend.to_ruby(text, rel) if erb_frontend.is_erb(rel) else text


def analyze_project(files: dict[str, str], models_dirs=None, config: dict | None = None) -> list[Finding]:
    """Analyze a whole project: Python natively, the other languages through the lowering frontends."""
    return analyze_project_full(files, models_dirs, config)[1]


# Wall-clock budget for the whole data-flow step. Past it the engine degrades instead of running on: no further
# summary passes or stored-data passes, then (past 1.5x) no further reporting scopes. Rule, secret and finished
# taint findings are always kept, with a note.
DATAFLOW_BUDGET_SECONDS = 900.0


def preparse(rel: str, text: str):
    """The tree _analyze_groups would build for this file, when building it is worth doing ahead of time in a worker
    process (the JavaScript and C-family frontends are written in Python; Python itself parses faster than its tree
    can be shipped between processes). None: the analysis parses (or skips) the file itself."""
    lang = _language(rel)
    if lang == "javascript":
        if len(text) > 600_000 or any(len(ln) > 5000 for ln in text.splitlines()[:50]):
            return None
        from . import js_frontend
        return js_frontend.parse_js(text, rel)
    if lang in CFAMILY_LANGS:
        if len(text) > 600_000:
            return None
        from . import cfamily_frontend
        return cfamily_frontend.parse_cfamily(_view_code(rel, text), rel, lang)
    return None


def analyze_project_full(files: dict[str, str], models_dirs=None, config: dict | None = None, budget: float | None = None,
                         trees: dict | None = None):
    """Like analyze_project but also returns the built Project models (for VQL queries).

    `config` holds key/values from the project's configuration files (.env, YAML, properties …), used to resolve
    table names and SQL that code reads from configuration. `trees` maps a file to the tree already built for its
    current text (by the scanner's per-file stage, see preparse); the analysis takes ownership of them."""
    if config is None:
        from . import stored as _st
        config = {}
        for rel, text in files.items():
            if _st.is_config_file(rel):
                config.update(_st.parse_config(rel, text))
    _TEMPLATES.clear()
    _TEMPLATES.update({rel: text for rel, text in files.items() if rel.lower().endswith(TEMPLATE_EXTS + JS_TEMPLATE_EXTS)})
    budget = DATAFLOW_BUDGET_SECONDS if budget is None else budget
    t0 = time.monotonic()
    _BUDGET["deadline"], _BUDGET["hard"] = t0 + budget, t0 + budget * 1.5
    try:
        return _analyze_groups(files, models_dirs, config, trees or {})
    finally:
        _BUDGET["deadline"] = _BUDGET["hard"] = None


def _analyze_groups(files, models_dirs, config, trees=None):
    trees = trees if trees is not None else {}
    projects: list = []
    groups: dict[str, dict[str, str]] = {}
    mybatis: dict = {}
    for rel, text in files.items():
        lang = _language(rel)
        if lang == "plsql" and rel.lower().endswith(".xml"):
            from . import cfamily_frontend
            if cfamily_frontend.is_mybatis_mapper(text):    # MyBatis mapper XML: SQL of Java mapper interfaces
                ns, stmts = cfamily_frontend.mybatis_statements(text)
                if ns and stmts:
                    mybatis[ns] = (rel, stmts)
                continue
        if lang:
            groups.setdefault(lang, {})[rel] = text
    findings: list[Finding] = []
    if "python" in groups:
        entries = []
        for rel, text in groups["python"].items():
            tree = trees.pop(rel, None)
            if tree is None:
                try:
                    tree = ast.parse(text)
                except (SyntaxError, ValueError, MemoryError, RecursionError):   # generated/hostile code: skip the file
                    continue
            entries.append(_Entry(_module_name(rel), rel, text, tree, is_pkg=rel.replace("\\", "/").endswith("__init__.py")))
        proj, flows = _stored_build(load_models(models_dirs or (), DEFAULT_MODELS, "python"), entries, config=config)
        if proj.files:
            findings.extend(flows)
            projects.append(proj)
    if "javascript" in groups:
        from . import js_frontend
        entries = []
        for rel, text in groups["javascript"].items():
            if len(text) > 600_000 or any(len(l) > 5000 for l in text.splitlines()[:50]):
                continue  # bundles / minified
            tree = trees.pop(rel, None)
            entries.append(_Entry(js_frontend.module_name(rel), rel, text, tree if tree is not None else js_frontend.parse_js(text, rel)))
        proj, flows = _stored_build(load_models(models_dirs or (), DEFAULT_JS_MODELS, "javascript"), entries, config=config)
        if proj.files:
            findings.extend(flows)
            projects.append(proj)
    for lang in CFAMILY_LANGS:
        if lang not in groups:
            continue
        from . import cfamily_frontend
        entries, diags = [], {}
        for rel, text in groups[lang].items():
            if len(text) > 600_000:
                continue
            tree = trees.pop(rel, None)
            if tree is None:
                tree = cfamily_frontend.parse_cfamily(_view_code(rel, text), rel, lang)
            if mybatis and lang in ("java", "kotlin"):
                cfamily_frontend.apply_mybatis_xml(tree, cfamily_frontend.module_name(rel), mybatis)
            entries.append(_Entry(cfamily_frontend.module_name(rel), rel, text, tree))
            diag = getattr(tree, "vulnscan_diagnostics", None)
            if diag:
                diags[rel] = diag
        if lang == "php":
            _php_include.inline_includes({e.rel: e.tree for e in entries})
        try:
            proj, flows = _stored_build(load_models_for(lang, models_dirs or ()), entries, diagnostics=diags, config=config)
        finally:
            _php_include.INLINED.clear()
        if proj.files:
            findings.extend(flows)
            projects.append(proj)
    if "plsql" in groups:
        p_projects, p_findings = _analyze_plsql(groups["plsql"], models_dirs or ())
        projects.extend(p_projects)
        findings.extend(p_findings)
    return projects, findings


_BUDGET: dict = {"deadline": None, "hard": None}
TEMPLATE_EXTS = (".html", ".htm", ".jinja", ".jinja2", ".j2", ".tmpl", ".djhtml", ".txt.jinja")
_TEMPLATES: dict = {}       # rel path -> text of the project's server-side templates (template-aware XSS sinks)
_TPL_UNSAFE = re.compile(r"\{\{-?\s*([A-Za-z_][\w.]*)(?:\[[^\]]*\])?\s*(?:\|[^}]*?)?\|\s*safe\b[^}]*\}\}")
_TPL_ANY = re.compile(r"\{\{-?\s*([A-Za-z_][\w.]*)")
_TPL_FOR = re.compile(r"\{%-?\s*for\s+([A-Za-z_]\w*)(?:\s*,\s*([A-Za-z_]\w*))?\s+in\s+([A-Za-z_][\w.]*)")
_TPL_AE_OFF = re.compile(r"\{%-?\s*autoescape\s+(?:false|off)\s*-?%\}(.*?)\{%-?\s*endautoescape\s*-?%\}", re.S)
_JINJA_TAG = re.compile(r"\{%-?\s*(extends|block|include|import|macro|for|if|set)\b|\{\{-?\s*[A-Za-z_]")
TEMPLATE_SOURCE_WRITE = ("DF007", "high", "Tainted data written into a template's source (stored SSTI)",
                         "بيانات غير موثوقة تُكتب في نص قالب يُعرض لاحقًا (حقن قوالب مخزّن SSTI)",
                         "لا تبنِ نص القالب من مدخلات المستخدم؛ خزّن المحتوى بيانات ومرّره متغيرًا إلى قالب ثابت.",
                         "CWE-1336", "template source written to a file", [0], False)
TEMPLATE_UNESCAPED = ("DF013", "medium", "Tainted data rendered unescaped by a template (|safe / autoescape off)",
                      "بيانات غير موثوقة تُعرض في قالب دون تهريب (|safe أو autoescape off)",
                      "لا تستخدم |safe أو autoescape off مع بيانات المستخدم؛ دع القالب يهرّب القيمة أو عقّمها (bleach) أولًا.",
                      "CWE-79", "template |safe", [0], False)


_TPL_EXPR = re.compile(r"\{\{-?\s*([A-Za-z_][\w.]*)([^}]*)\}\}")
_TPL_ESCAPING = re.compile(r"\|\s*(e|escape|forceescape|int|float|length|count|urlencode|tojson|striptags|wordcount|"
                           r"filesizeformat|round|abs|date|time)\b")


def _template_unsafe_vars(name: str, all_vars: bool = False) -> set:
    """Context variables a template prints without escaping: `{{ x|safe }}`, `{{ post.text|safe }}` inside
    `{% for post in posts %}` (-> posts), anything printed inside `{% autoescape false %}`. With `all_vars` (the
    template environment was created with autoescape off) every printed variable except escaped ones (`|e`)."""
    cache = _TEMPLATES.setdefault("\0cache", {})
    if all_vars:
        key = "\0all\0" + name
        if key not in cache:
            cache[key] = _template_unsafe_vars(name) | _template_printed_vars(name)
        return cache[key]
    if name in cache:
        return cache[name]
    norm = name.replace("\\", "/").lstrip("./")
    cands = [r for r in _TEMPLATES if isinstance(_TEMPLATES[r], str) and (r == norm or r.endswith("/" + norm))]
    cands.sort(key=lambda r: (0 if "/templates/" in "/" + r else 1, len(r)))
    out: set = set()
    if cands:
        text = _TEMPLATES[cands[0]]
        loops = {}
        for m in _TPL_FOR.finditer(text):
            for v in (m.group(1), m.group(2)):
                if v:
                    loops[v] = m.group(3).split(".")[0]
        raw = [m.group(1) for m in _TPL_UNSAFE.finditer(text)]
        for m in _TPL_AE_OFF.finditer(text):
            raw += [x.group(1) for x in _TPL_ANY.finditer(m.group(1))]
        for v in raw:
            root = v.split(".")[0]
            seen = set()
            while root in loops and root not in seen:
                seen.add(root)
                root = loops[root]
            if root not in ("request", "csrf_token", "url_for", "config", "loop", "super", "self", "g", "static"):
                out.add(root)
    cache[name] = out
    return out


def _template_printed_vars(name: str) -> set:
    """Root variables of every `{{ expr }}` a template prints without an escaping / numeric filter."""
    norm = name.replace("\\", "/").lstrip("./")
    cands = [r for r in _TEMPLATES if isinstance(_TEMPLATES[r], str) and (r == norm or r.endswith("/" + norm))]
    cands.sort(key=lambda r: (0 if "/templates/" in "/" + r else 1, len(r)))
    if not cands:
        return set()
    text = _TEMPLATES[cands[0]]
    loops = {}
    for m in _TPL_FOR.finditer(text):
        for v in (m.group(1), m.group(2)):
            if v:
                loops[v] = m.group(3).split(".")[0]
    out = set()
    for m in _TPL_EXPR.finditer(text):
        if _TPL_ESCAPING.search(m.group(2)):
            continue
        root, seen = m.group(1).split(".")[0], set()
        while root in loops and root not in seen:
            seen.add(root)
            root = loops[root]
        if root not in ("request", "csrf_token", "url_for", "config", "loop", "super", "self", "g", "static"):
            out.add(root)
    return out


JS_TEMPLATE_EXTS = (".ejs", ".hbs", ".handlebars", ".mustache", ".pug", ".jade", ".njk", ".nunjucks", ".swig")
JS_TEMPLATE_UNESCAPED = ("DF013", "medium", "Tainted data rendered unescaped by a view template (<%- %>, {{{ }}}, != or autoescape off)",
                         "بيانات غير موثوقة تُعرض في قالب عرض دون تهريب (<%- %> أو {{{ }}} أو != أو autoescape off)",
                         "اطبع القيمة بالوسم المهرِّب (<%= %> أو {{ }} أو #{}) وأبقِ autoescape مفعّلًا، أو عقّمها (DOMPurify) أولًا.",
                         "CWE-79", "unescaped view output", [0], False)
_JS_AE_OFF = re.compile(r"\bautoescape\s*:\s*false\b")
_JS_AE_ENGINE = re.compile(r"\b(swig|nunjucks)\b")
_EJS_RAW = re.compile(r"<%-(.*?)[-_]?%>", re.S)
_HBS_RAW = re.compile(r"\{\{\{\s*([^}]*?)\s*\}\}\}|\{\{&\s*([^}]*?)\s*\}\}")
_HBS_EACH = re.compile(r"\{\{#(?:each|with)\s+([A-Za-z_$][\w$]*)")
_PUG_RAW = re.compile(r"!\{([^}]*)\}|^[ \t]*(?:[\w.#:-]+(?:\([^)\n]*\))?)?!=[ \t]*(\S.*)$", re.M)
_JS_LOOP = re.compile(r"([A-Za-z_$][\w$]*)(?:\.[\w$]+)*\s*\.\s*(?:forEach|map|filter|some|every)\s*\(\s*(?:async\s+)?"
                      r"(?:function\s*[\w$]*\s*)?\(?\s*([A-Za-z_$][\w$]*)"
                      r"|for\s*\(\s*(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s+(?:of|in)\s+([A-Za-z_$][\w$]*)"
                      r"|^[ \t]*each\s+([A-Za-z_$][\w$]*)(?:\s*,\s*[A-Za-z_$][\w$]*)?\s+in\s+([A-Za-z_$][\w$]*)", re.M)
_JS_IDENT = re.compile(r"(?<![\w$.'\"])([A-Za-z_$][\w$]*)(?:\s*\.\s*([A-Za-z_$][\w$]*))?")
_JS_NOT_VARS = frozenset({"include", "locals", "JSON", "String", "Number", "Math", "Object", "Array", "Date", "true", "false",
                          "null", "undefined", "typeof", "new", "this", "function", "var", "let", "const", "if", "else",
                          "return", "for", "of", "in", "encodeURIComponent", "encodeURI", "escape", "escapeHtml"})
# a call that escapes / sanitizes what it prints: `<%- escapeHtml(x) %>`, `!{DOMPurify.sanitize(x)}`, `{{{sanitize x}}}`
_JS_SAFE_CALL = re.compile(r"(?i)^(?!.*(?:unescape|decode|unsafe|raw))[\w$.]*(?:escape|sanitiz|purif|encode|striptags|strip_tags|xss)[\w$]*$")
_JS_STR = re.compile(r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"")
_JS_NON_TEXT_FIELDS = frozenset({"length", "size"})


def _js_printed_expr(e: str, helper_syntax: bool = False) -> str:
    """The part of a raw-output expression whose value is printed: string literals, the condition of a ternary
    (`<%- sel ? "selected" : "" %>`) and the arguments of escaping / sanitizing calls (`<%- escapeHtml(x) %>`,
    Handlebars `{{{sanitize body}}}`) are removed."""
    e = _JS_STR.sub('""', e)
    if helper_syntax:
        head = e.split(None, 1)
        if head and _JS_SAFE_CALL.match(head[0]):
            return ""
    depth = 0
    for i, c in enumerate(e):                       # a top-level `cond ? a : b`: only a and b are printed
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "?" and depth == 0 and e[i + 1:i + 2] not in ("?", ".") and e[i - 1:i] != "?":
            e = e[i + 1:]
            break
    out, i = [], 0
    for m in re.finditer(r"([A-Za-z_$][\w$.]*)\s*\(", e):
        if m.start() < i or not _JS_SAFE_CALL.match(m.group(1)):
            continue
        depth, j = 0, m.end() - 1
        while j < len(e):
            depth += {"(": 1, ")": -1}.get(e[j], 0)
            j += 1
            if depth == 0:
                break
        out.append(e[i:m.start()])
        out.append('""')
        i = j
    out.append(e[i:])
    return "".join(out)


def _js_view_file(name: str) -> str | None:
    """The project file of a JavaScript view name: "app/products" -> views/app/products.ejs."""
    norm = name.replace("\\", "/").lstrip("./").lstrip("/")
    if not norm:
        return None
    exts = JS_TEMPLATE_EXTS + TEMPLATE_EXTS
    cands = []
    for r, text in _TEMPLATES.items():
        if not isinstance(text, str):
            continue
        rr = r.replace("\\", "/")
        low = rr.lower()
        if low.endswith(exts) and (rr == norm or rr.endswith("/" + norm)):
            cands.append(rr)
            continue
        stem, dot, ext = rr.rpartition(".")
        if dot and ("." + ext.lower()) in exts and (stem == norm or stem.endswith("/" + norm)):
            cands.append(rr)
    if not cands:
        return None
    cands.sort(key=lambda r: (0 if "/views/" in "/" + r else 1, len(r)))
    return cands[0]


def _js_template_unsafe_vars(name: str, autoescape_off: bool = False) -> dict:
    """Variables a JavaScript view prints without HTML escaping: roots of the expressions in EJS `<%- … %>`,
    Handlebars / Mustache `{{{ … }}}` / `{{& … }}`, Pug `!{…}` / `tag!= …`, Jinja-style `{{ x|safe }}` (Nunjucks,
    Swig) and, when the project turns autoescape off, every `{{ x }}`. Loop variables map to the collection they
    iterate (`products.forEach(function (p) {` / `{{#each products}}` / `each p in products`).
    Returns {variable: the fields of it that are printed (`output.searchTerm` -> "searchTerm"), None = all of it}."""
    cache = _TEMPLATES.setdefault("\0cache", {})
    key = ("\0js\0", name, autoescape_off)
    if key in cache:
        return cache[key]
    out: dict = {}

    def add(root, fld):
        out.setdefault(root, set()).add(fld)
    rel = _js_view_file(name)
    if rel is not None:
        text = _TEMPLATES[rel]
        loops = {}
        for m in _JS_LOOP.finditer(text):
            if m.group(2):
                loops[m.group(2)] = m.group(1)
            elif m.group(3):
                loops[m.group(3)] = m.group(4)
            elif m.group(5):
                loops[m.group(5)] = m.group(6)
        exprs = [e.strip() for e in _EJS_RAW.findall(text)]
        exprs = [e for e in exprs if not e.startswith("include")]
        exprs = [_js_printed_expr(e) for e in exprs]
        each = [m.group(1) for m in _HBS_EACH.finditer(text)]
        for m in _HBS_RAW.finditer(text):
            e = _js_printed_expr((m.group(1) or m.group(2) or "").strip(), helper_syntax=True)
            if not e.strip() and (m.group(1) or m.group(2) or "").strip():
                continue                    # {{{sanitize body}}}: a sanitizing helper prints it
            if e.startswith(("this", ".")) or not e:
                for v in each:              # {{{this.body}}} inside {{#each posts}}: the collection's items
                    add(v, None)
            exprs.append(e)
        if rel.lower().endswith((".pug", ".jade")):
            exprs += [_js_printed_expr((m.group(1) or m.group(2) or "").strip()) for m in _PUG_RAW.finditer(text)]
        for e in exprs:
            for ident, fld in _JS_IDENT.findall(e):
                if ident in _JS_NOT_VARS or fld in _JS_NON_TEXT_FIELDS:
                    continue                # (`<%- items.length %>` prints a number)
                root, seen = ident, set()
                while root in loops and root not in seen:
                    seen.add(root)
                    root = loops[root]
                add(root, fld if root == ident and fld else None)
        if "{{" in text or "{%" in text:
            for root in _template_unsafe_vars(rel, all_vars=autoescape_off):
                add(root, None)
    cache[key] = out
    return out


class _Entry:
    __slots__ = ("mod", "rel", "text", "tree", "is_pkg", "lines")

    def __init__(self, mod, rel, text, tree, is_pkg=False, lines=None):
        self.mod, self.rel, self.text, self.tree, self.is_pkg, self.lines = mod, rel, text, tree, is_pkg, lines


def _stored_build(models: dict, entries: list, diagnostics: dict | None = None, instrument_db: bool = True,
                  field_precise: bool = False, config: dict | None = None):
    """Build and report a project, following user data through database tables (second-order flows).

    Pass 1 learns which TABLE.COLUMNs receive user data (internal sinks stored_db_write__T__C); later passes
    make those columns sources wherever they are read, until no new column appears."""
    from . import stored as st
    if instrument_db and entries:
        triples = [(e.text, e.tree, e.rel) for e in entries]
        mods = st.model_names(triples)
        ctors = st.ctor_param_names(triples, mods)
        sigs = st.helper_signatures(triples, mods)
        fc = st.FoldContext(triples, config)
        for e in entries:
            try:
                st.instrument(e.tree, mods, ctors, sigs, fc)
            except Exception:  # noqa: BLE001 - instrumentation is an enhancement; never block the scan
                pass
    store_names = sorted({n.func.id for e in entries for n in ast.walk(e.tree)
                          if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id.startswith("stored_db_write__")})
    def store_col(nm):
        return nm[len("stored_db_write__"):].upper().replace("__", ".", 1)
    # the column is in the title and the label, so flows through helpers (titled "… into <label>") keep it
    store_sinks = [("DFSTORE", "info", "store:" + store_col(nm), "", "", "", "store:" + store_col(nm),
                    [0], False, [nm], frozenset()) for nm in store_names]

    shared_pt: dict = {}

    def run_pass(prefix_sources):
        m = dict(models)
        m["sanitizers"] = models["sanitizers"] | {"stored_db_read", "stored_db_config"}
        m["sinks"] = models["sinks"] + store_sinks
        m["prefix_sources"] = models["prefix_sources"] + prefix_sources
        pr = Project(m)
        pr.deadline, pr.hard_deadline = _BUDGET["deadline"], _BUDGET["hard"]
        pr.field_precise_locals = field_precise
        # every pass analyses the same (already instrumented) trees: facts that depend only on the code are shared
        pr.shared_pointsto = shared_pt
        pr._parents_cache = shared_pt.setdefault("parents", {})
        pr._calls_cache = shared_pt.setdefault("calls", {})
        pr.__dict__["_flow_struct"] = shared_pt.setdefault("flow_struct", {})
        pr.__dict__["_shared_file_facts"] = shared_pt.setdefault("file_facts", {})
        for e in entries:
            pr.add_file(e.mod, e.rel, e.text, is_pkg=e.is_pkg, tree=e.tree, lines=e.lines)
        pr.diagnostics.update(diagnostics or {})
        if pr.files:
            pr.build()
            return pr, pr.report()
        return pr, []

    stored: dict = {}
    prev_prefixes = 0
    proj, flows = run_pass([])
    for _ in range(4 if store_sinks else 0):
        if getattr(proj, "budget_hit", False) or proj.over_budget():
            break                    # out of time: report the first-order flows found so far
        new = {}
        for f in flows:
            if f.rule_id == "DFSTORE":
                m = re.search(r"store:([\w$#*]+\.[\w$#*]+)", f.title)
                col = m.group(1) if m else None
                if col and col not in stored and col not in new:
                    new[col] = f
        if not new:
            break
        stored.update(new)
        prefix = []
        for col, f in stored.items():
            table, column = col.split(".", 1)
            where = f"(كتبها مستخدم في {f.file}:{f.line})"
            if table == "ANY_TABLE":
                # written to a table chosen at run time: any read of that column may see it
                label = f"{STORED_SOURCE_MARK} في العمود {column} {RUNTIME_TABLE_MARK} {where}"
                prefix.append(((f"stored_db.ANY_TABLE.{column}", "stored_db.ANY_TABLE.*"), label))
                continue
            label = f"{STORED_SOURCE_MARK} في {col} {where}"
            names = [f"stored_db.{col}", f"stored_db.{table}.*"]
            if column == "*":
                names.append(f"stored_db.{table}.")              # unknown columns written: every column of the table
            prefix.append((tuple(names), label))
            if column != "*":                                     # read back through a run-time-chosen table
                prefix.append(((f"stored_db.ANY_TABLE.{column}",),
                               f"{STORED_SOURCE_MARK} في {col} وقُرئت من جدول {RUNTIME_TABLE_MARK} {where}"))
        if not _prefixes_read(proj, entries, prefix[prev_prefixes:]):
            # no code reads any of the newly written columns: the next pass would only add sources that match
            # nothing, i.e. repeat this one exactly. Record the sources (as that pass would) and stop.
            proj.m["prefix_sources"] = models["prefix_sources"] + prefix
            break
        prev_prefixes = len(prefix)
        proj = None                  # the previous pass's project is not needed: free it before building the next
        proj, flows = run_pass(prefix)
    flows = [f for f in flows if f.rule_id != "DFSTORE"]
    _retag_stored(flows)
    return proj, flows


def _prefixes_read(proj, entries, new_prefixes) -> bool:
    """Could any of `new_prefixes` (stored-column sources) match a name the code reads? Prefix sources match the
    canonical dotted name of a Name / Attribute (see _is_source_uncached); instrumented reads are spelled
    `stored_db.TABLE.COLUMN`, and a canonical name only differs from the dotted one through an import alias."""
    if not new_prefixes:
        return False
    names = proj.__dict__.get("_stored_read_names")
    if names is None:
        names = set()
        for f in proj.files.values():
            for tgt in f.get("aliases", {}).values():
                if any("stored_db" in str(x) for x in tgt):
                    names = None            # an import named like the instrumentation: be conservative
                    break
            if names is None:
                break
        if names is not None:
            for e in entries:
                for n in ast.walk(e.tree):
                    if isinstance(n, ast.Attribute):
                        d = _dotted(n)
                        if d.startswith("stored_db"):
                            names.add(d)
                    elif isinstance(n, ast.Name) and n.id.startswith("stored_db"):
                        names.add(n.id)
        proj.__dict__["_stored_read_names"] = names
    if names is None:
        return True
    for prefixes, _label in new_prefixes:
        for p in prefixes:
            if any(d == p or (p.endswith(".") and d.startswith(p)) for d in names):
                return True
    return False


AI_SOURCE_MARK = "الذكاء الاصطناعي"
AI_OUTPUT_RULES = {
    "DF004": ("DF020", "critical", "CWE-1426", "AI-generated text executed as SQL / code",
              "نص يولّده الذكاء الاصطناعي يُنفَّذ كـ SQL أو كود",
              "لا تنفّذ مخرجات النموذج مباشرة: اسمح فقط بقوالب استعلام ثابتة بمتغيرات ربط، أو تحقّق من الناتج بمحلّل وقائمة بيضاء، "
              "ونفّذ بحساب قراءة فقط محدود الصلاحيات."),
    "DF012": ("DF020", "critical", "CWE-1426", "AI-generated text executed as SQL / code",
              "نص يولّده الذكاء الاصطناعي يُنفَّذ كـ SQL أو كود",
              "لا تنفّذ كودًا يولّده النموذج؛ اربط أفعاله بإجراءات ثابتة مسموحة."),
    "DF013": ("DF021", "high", "CWE-1426", "AI-generated text rendered as HTML without escaping",
              "نص يولّده الذكاء الاصطناعي يُعرض كـ HTML دون تهريب (XSS عبر النموذج)",
              "هرّب مخرجات النموذج بـ apex_escape.html أو اعرضها كنص؛ النموذج قد يُخدع ليولّد سكربتًا."),
}


STORED_SOURCE_MARK = "بيانات مخزّنة"
STORED_RULES = {
    "DF004": ("DF023", "high", "CWE-89", "Second-order SQL injection: stored user data executed as SQL",
              "حقن SQL من الدرجة الثانية: بيانات خزّنها مستخدم تُنفَّذ لاحقًا كـ SQL",
              "عامل البيانات المقروءة من الجداول كمدخلات غير موثوقة: استخدم متغيرات الربط وDBMS_ASSERT عند بناء SQL منها."),
    "DF012": ("DF023", "high", "CWE-94", "Second-order injection: stored user data executed as code",
              "حقن من الدرجة الثانية: بيانات خزّنها مستخدم تُنفَّذ لاحقًا ككود",
              "لا تنفّذ كودًا مبنيًا من بيانات مخزّنة؛ استخدم إجراءات ثابتة."),
    "DF002": ("DF023", "high", "CWE-78", "Second-order command injection: stored user data reaches a shell command",
              "حقن أوامر من الدرجة الثانية: بيانات خزّنها مستخدم تصل لاحقًا إلى أمر نظام",
              "عامل البيانات المقروءة من قاعدة البيانات كمدخلات غير موثوقة: لا تمرّرها إلى الصدفة."),
    "DF003": ("DF023", "high", "CWE-78", "Second-order command injection: stored user data reaches process execution",
              "حقن أوامر من الدرجة الثانية: بيانات خزّنها مستخدم تصل لاحقًا إلى تنفيذ عملية",
              "تحقق من البيانات المخزّنة بقائمة بيضاء قبل تمريرها كوسائط."),
    "DF013": ("DF024", "high", "CWE-79", "Stored XSS: data a user saved is written to the page unescaped",
              "XSS مخزّن: بيانات حفظها مستخدم تُكتب في الصفحة دون تهريب",
              "هرّب القيمة عند العرض (apex_escape.html / htf.escape_sc) لا عند الحفظ فقط."),
}


RUNTIME_TABLE_MARK = "يُحدَّد وقت التشغيل"
_LOWER = {"critical": "high", "high": "medium", "medium": "low", "low": "low", "info": "info"}


def _retag_stored(findings: list) -> None:
    """A flow whose source is a table column a user wrote earlier is a second-order / stored vulnerability.
    When the table is only known at run time the link is by column name: one severity level lower, and said so."""
    for f in findings:
        src = str(f.extra.get("taint_source", ""))
        trail = f.extra.get("path") or []
        if STORED_SOURCE_MARK not in src and trail and STORED_SOURCE_MARK in str(trail[0].get("text", "")):
            src = str(trail[0].get("text", ""))      # `rows` read from the table in a helper, returned to the view
        if STORED_SOURCE_MARK in src and f.rule_id in STORED_RULES:
            f.rule_id, f.severity, f.cwe, f.title, f.title_ar, f.advice = STORED_RULES[f.rule_id]
            if RUNTIME_TABLE_MARK in src:
                f.severity = _LOWER.get(f.severity, f.severity)
                f.title += " (table chosen at run time; linked by column name)"
                f.title_ar += " — الجدول يُحدَّد وقت التشغيل (الربط باسم العمود)"
                f.extra["runtime_table"] = True


def _retag_ai_output(findings: list) -> None:
    """A flow whose source is generated-AI output is insecure output handling (OWASP LLM05), not plain injection."""
    for f in findings:
        if AI_SOURCE_MARK in str(f.extra.get("taint_source", "")) and f.rule_id in AI_OUTPUT_RULES:
            f.rule_id, f.severity, f.cwe, f.title, f.title_ar, f.advice = AI_OUTPUT_RULES[f.rule_id]


def _label_findings(findings: list, ranges: list) -> None:
    """Prefix findings inside an APEX export with the component they belong to (page › process: name)."""
    by_file: dict = {}
    for rel, start, end, label in ranges:
        by_file.setdefault(rel, []).append((start, end, label))
    for f in findings:
        for start, end, label in by_file.get(f.file, ()):
            if start <= f.line <= end:
                f.extra["apex_component"] = label
                if not str(f.snippet).startswith("["):
                    f.snippet = f"[{label}] {f.snippet}"
                break


def _analyze_plsql(files: dict[str, str], models_dirs) -> tuple[list, list]:
    """PL/SQL sources and Oracle APEX exports (application / page / plug-in), plus embedded JavaScript and Java."""
    from . import apex_export, cfamily_frontend, js_frontend
    from . import plsql_frontend as pf
    projects, findings = [], []
    units_by_file: list = []
    shared_lines: dict = {}
    texts: dict = {}
    diags: dict = {}
    ranges: list = []
    js_trees: list = []          # (module, rel, tree)
    js_files: dict = {}          # decoded static files (virtual path -> text)
    java_trees: list = []
    def add_blocks(rel, blocks, diag):
        """Extracted code blocks (APEX export / readable YAML / ORDS handlers) -> units at their real lines."""
        for b in blocks:
            ranges.append((rel, b.line, b.line + b.code.count("\n"), b.label))
            delta = b.line - 1
            if b.kind.startswith("plsql"):
                units, d = pf.parse_plsql(apex_export.wrapped_plsql(b))
                apex_export.anchor_wrapper_sink(b, units)
            elif b.kind == "sql":                       # static query: follow the PL/SQL functions it calls
                units, d = pf.sql_call_units(b.code, b.unit)
            elif b.kind == "js":
                tree = js_frontend.parse_js(b.code, rel)
                js_trees.append((b.unit, rel, pf.shift_lines(tree, delta)))
                continue
            else:
                continue
            for u in units:
                for node in u.body:
                    pf.shift_lines(node, delta)
            units_by_file.append((rel, units))
            diag["statements"] += d["statements"]
            diag["skipped"] += d["skipped"]
            diag["lines"].extend((ln + delta, f"[{b.label}] {msg}") for ln, msg in d["lines"])

    def add_plsql_text(rel, text, delta, diag):
        """Plain PL/SQL (a .sql/.pkb file or a script inside XML): units, ORDS handlers, Java sources."""
        units, d = pf.parse_plsql(text)
        for u in units:
            for node in u.body:
                pf.shift_lines(node, delta)
        units_by_file.append((rel, units))
        diag["statements"] += d["statements"]
        diag["skipped"] += d["skipped"]
        diag["lines"].extend((ln + delta, msg) for ln, msg in d["lines"])
        findings.extend(apex_export.password_findings(text, rel, 1 + delta))   # custom authentication in packages
        ords = apex_export.extract_ords(text, rel)
        for b in ords:
            b.line += delta
        add_blocks(rel, ords, diag)
        for name, start, code in pf.java_sources(text):
            tree = cfamily_frontend.parse_cfamily(code, f"{name}.java", "java")
            java_trees.append((re.sub(r"\W", "_", f"java_{name}").lower(), rel, pf.shift_lines(tree, start - 1 + delta)))

    for rel, text in files.items():
        if len(text) > 60_000_000:
            continue
        low = rel.lower()
        texts[rel] = text
        shared_lines[rel] = text.splitlines()
        diag = {"language": "plsql", "statements": 0, "skipped": 0, "lines": []}
        if low.endswith((".yaml", ".yml")):
            if not apex_export.is_apex_yaml(text, rel):
                continue
            diag["language"] = "apex-yaml"
            blocks, afind, _ = apex_export.extract_yaml(text, rel)
            findings.extend(afind)
            add_blocks(rel, blocks, diag)
        elif low.endswith(".xml"):
            diag["language"] = "xml"
            for start, script in apex_export.xml_scripts(text):
                add_plsql_text(rel, script, start - 1, diag)
        elif low.endswith(".json"):
            diag["language"] = "ords-json"
            add_blocks(rel, apex_export.extract_json_ords(text, rel), diag)
        elif apex_export.is_apex_export(text):
            diag["language"] = "apex"
            blocks, afind, sfiles = apex_export.extract(text, rel)
            findings.extend(afind)
            js_files.update(sfiles)
            add_blocks(rel, blocks + apex_export.extract_ords(text, rel), diag)
        else:
            add_plsql_text(rel, text, 0, diag)
        diags[rel] = diag
    # Java stored in the database runs in the same project, so PL/SQL call specs flow into the Java methods
    models = load_models_for("plsql", models_dirs)
    if java_trees:
        jm = load_models_for("java", models_dirs)
        for k in ("attr_sources", "call_sources", "name_sources", "sinks", "attr_sinks"):
            models[k] = models[k] + [x for x in jm[k] if x not in models[k]]
        for k in ("sanitizers", "safe_return_calls", "validators"):
            models[k] = models[k] | jm[k]
    java_classes = {n.name: mname for mname, rel, tree in java_trees for n in tree.body if isinstance(n, ast.ClassDef)}
    modules = pf.build_modules(units_by_file, java_classes)
    entries = [_Entry(mname, rel, texts[rel], mod, lines=shared_lines[rel]) for mname, rel, mod in modules]
    entries += [_Entry(mname, rel, texts[rel], tree, lines=shared_lines[rel]) for mname, rel, tree in java_trees]
    proj, flows = _stored_build(models, entries, diagnostics=diags, instrument_db=False, field_precise=True)
    if proj.files:
        _retag_ai_output(flows)
        findings.extend(flows)
        projects.append(proj)
    if js_trees or js_files:
        jproj = Project(load_models(models_dirs, DEFAULT_JS_MODELS, "javascript"))
        for mname, rel, tree in js_trees:
            jproj.add_file(mname, rel, texts[rel], tree=tree, lines=shared_lines[rel])
        for vpath, content in js_files.items():
            jproj.add_file(js_frontend.module_name(vpath.replace("!", "/")), vpath, content, tree=js_frontend.parse_js(content, vpath))
        jproj.build()
        findings.extend(jproj.report())
        projects.append(jproj)
    _label_findings(findings, ranges)
    return projects, findings


def analyze(path: str, text: str, models_dirs=None) -> list[Finding]:
    return analyze_project({path: text}, models_dirs)


def _catalogue() -> list[dict]:
    """Every data-flow rule of every language model, the AI output-handling rules and the APEX export rules."""
    seen, out = set(), []
    entries = load_models()["sinks"] + load_models((), DEFAULT_JS_MODELS, "javascript")["sinks"]
    for path in sorted(MODELS_DIR.glob("*.json")):
        if path.stem not in ("python", "javascript"):
            entries += load_models((), path, path.stem)["sinks"]
    stores = [si for si, _ in load_models()["store_sinks"]]
    for e in entries + stores + [ARG_INJECTION + (None,), REFLECTED_RETURN + (None,), DYNAMIC_DISPATCH + (None,),
                                 TEMPLATE_UNESCAPED + (None,), TEMPLATE_SOURCE_WRITE + (None,)]:
        if e[0] in seen:
            continue
        seen.add(e[0])
        out.append({"id": e[0], "severity": e[1], "cwe": e[5], "title": e[2], "title_ar": e[3], "advice": e[4]})
    for rule, sev, cwe, title, title_ar, advice in list(AI_OUTPUT_RULES.values()) + list(STORED_RULES.values()):
        if rule not in seen:
            seen.add(rule)
            out.append({"id": rule, "severity": sev, "cwe": cwe, "title": title, "title_ar": title_ar, "advice": advice})
    from .apex_export import APEX_RULES
    for r in APEX_RULES:
        if r["id"] not in seen:
            seen.add(r["id"])
            out.append({k: r[k] for k in ("id", "severity", "cwe", "title", "title_ar", "advice")})
    return sorted(out, key=lambda d: d["id"])


TAINT_RULES = _catalogue()
