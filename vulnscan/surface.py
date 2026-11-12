"""Attack-surface map: every externally reachable entry point of a project, ranked by risk.  (vulnscan: ignore-file)

INTEGRATION NOTES
=================
(This module was written as a stand-alone file; nothing else in the package imports it yet.)

* CLI -- add a sub-command (or flag) to ``vulnscan/cli.py``::

      vulnscan surface PATH [-f json|markdown|csv|mermaid|dot|openapi] [-o FILE] [--lang en|ar]
                            [--exclude GLOB ...] [--models DIR ...] [--no-engine] [--include-tests] [--max-depth N]
                            [--top N] [--server-url URL] [--fail-on-unauth-sink]

  Simplest wiring: ``if argv[:1] == ["surface"]: return surface.main(argv[1:])``. A flag on a normal scan
  (``vulnscan PATH --surface surface.json``) can call ``build_surface(root, findings=findings)`` after the scan so
  that the fingerprints in the surface are exactly those of the report/baseline (pass the complete finding list).
  Cost: with the engine the map costs one data-flow analysis (the same as a scan); to avoid analysing twice, hand
  the models the scan built to ``build_surface_from_files(files, findings=..., projects=...)``. ``--no-engine``
  gives the route / parameter / auth inventory in seconds.
  Exit codes of ``main``: 0 ok, 2 usage error / unreadable path, 1 only with ``--fail-on-unauth-sink`` when an
  unauthenticated entry point reaches a dangerous sink (a CI gate).

* Web UI (``ui/``, ``server.py``) -- suggested hooks:
    - ``GET /api/surface?scan=<id>`` returning ``build_surface(root, findings=saved_findings).to_dict(lang)``;
    - a "Attack surface / سطح الهجوم" tab: a sortable table of ``entries`` (risk, method, path, handler, auth, params,
      sinks, findings) where ``entries[i].findings[j].fingerprint`` deep-links to the finding card, plus a graph pane
      fed by ``render_mermaid`` and a "Download OpenAPI" button fed by ``render_openapi``;
    - the per-finding card can show "reachable from: METHOD /path" by inverting ``entries[*].findings``.
  ``store.py`` can persist ``Surface.to_dict()`` next to a saved scan (plain JSON, no objects).

* LSP (``lsp.py``) -- a code lens above each handler ("entry point: GET /users/{id} - no visible auth - reaches SQL")
  from ``Surface.entries`` (``file``, ``line``).

* PyInstaller (``vulnscan.spec``) -- add ``"vulnscan.surface"`` to ``hiddenimports`` (it is imported lazily by the
  CLI/server once wired). No data files: everything is in this module.

* README -- suggested text:
    "**Attack-surface map** (``vulnscan surface .``): lists every HTTP route, CLI command, queue consumer and
    scheduled job with its untrusted parameters, the authentication guard that is (or is not) visible, the dangerous
    sinks reachable through the call graph and the proven taint findings behind it; exports Markdown, CSV, JSON,
    Mermaid/Graphviz and an OpenAPI 3.1 skeleton to seed ZAP or Burp. Static analysis only: no request is ever sent."
  Arabic: "**خريطة سطح الهجوم**: تسرد كل مسار HTTP وأمر CLI ومستهلك رسائل ومهمة مجدولة مع المدخلات غير الموثوقة،
  وحارس المصادقة الظاهر (أو غيابه)، والمصارف الخطرة التي يصل إليها عبر مخطط الاستدعاءات، والنتائج المثبتة المرتبطة
  بها؛ وتصدّر Markdown و CSV و JSON و Mermaid/Graphviz وهيكل OpenAPI 3.1 لتغذية ZAP أو Burp. تحليل ساكن فقط."

* i18n -- user-facing strings live in ``STR`` below (English and Arabic); nothing was added to the shared catalogs.

What it does
============
1. **Discovers entry points** from the source text with framework-specific extractors (Python uses the real
   ``ast``; the other languages use comment/string-aware scanners, because route DSLs such as ``routes.rb``,
   Laravel route groups or chi sub-routers are not ordinary calls):

   ========== ==========================================================================================
   Python     Flask/Quart/Bottle/Sanic decorators and ``add_url_rule``, FastAPI/Starlette (``APIRouter``
              prefixes, ``Depends``), Django ``urls.py`` (``path``/``re_path``/``include``) + function and
              class views, DRF (``@api_view``, routers + view sets, ``@action``), aiohttp, click/typer,
              argparse, Celery/RQ/Dramatiq tasks, APScheduler, Socket.IO, AWS Lambda handlers
   JS / TS    Express, Koa router, Fastify (``.get`` and ``.route({...})``), NestJS controllers (HTTP,
              message patterns, cron), Next.js ``pages/api`` and app-router ``route.ts``
   Java/Kotlin Spring MVC/WebFlux annotations (+ ``SecurityFilterChain`` matcher rules), JAX-RS, servlets
              (``@WebServlet`` and ``web.xml``), Kafka/Rabbit/JMS listeners, ``@Scheduled``, ``main``
   C#         ASP.NET Core controllers (attribute and conventional routing), minimal APIs (``MapGet`` ...,
              ``MapGroup``), Azure Functions triggers, ``Main``
   Go         net/http (incl. Go 1.22 method patterns), gin, echo, fiber, chi, gorilla/mux, cobra, ``flag``
   PHP        Laravel routes (groups, prefixes, middleware, resources), Symfony attributes/annotations
              (+ ``security.yaml`` access_control), plain scripts reading superglobals, console commands
   Ruby       Rails ``routes.rb`` (resources, namespaces, scopes, member/collection, mounts) + controllers
              (``before_action`` filters, inheritance), Sinatra, Sidekiq/ActiveJob, rake tasks
   ========== ==========================================================================================

2. For each entry point: the **untrusted parameters** (query / body / form / header / cookie / path / file, with
   names), the **authentication or authorization guard** that is visible (decorator, annotation, middleware,
   dependency, configuration rule, inline check) or its absence, the **dangerous sinks reachable** through the
   call graph of the existing taint engine (``taint.Project``: SQL, command, file, SSRF, deserialization, template,
   redirect, code, XSS, XXE/XPath, LDAP, NoSQL), the **proven taint findings** behind it (linked by fingerprint) and
   the **data stores** touched (SQL tables, ORM models, Mongo collections, Redis ...).

3. **Ranks** entries by risk: unauthenticated entries that reach a sink come first.

Static analysis only: scanned code is never imported or executed and no network request is ever made. The OpenAPI
document is a *skeleton* to seed a DAST tool; it is not a contract.

Limits (honest list)
====================
* Route discovery outside Python is textual: paths built at run time (string concatenation, constants from another
  file, reflection, convention-over-configuration beyond what is listed above) are missed or reported with the
  literal part only. Ktor, Play, Micronaut, Tornado, Grape, Slim, CodeIgniter, gRPC services and GraphQL resolvers
  are not recognised yet.
* "No visible auth" means no guard was *visible* in the code that was read: a reverse proxy, an API gateway or a
  global filter registered elsewhere can still protect the route. Guards are recognised by NAME (decorator,
  middleware, annotation, configuration rule): "protected" means "a guard with an auth-looking name applies", not
  "the guard is correct". The vocabulary errs towards "none": rate limiters, CSRF/CSP helpers,
  ``passport.initialize()`` and friends are not guards; optional authentication (``jwt_required(optional=True)``,
  ``credentialsRequired: false``, ``permitAll()``, DRF ``...OrReadOnly`` on a safe method) is reported "public".
  An inline check counts only when the handler also rejects somebody (401/403, abort, redirect, raise/throw);
  merely reading ``req.user`` / ``current_user`` does not.
* Express: a router mounted at two prefixes is listed under the last one only; middleware registered with a path
  prefix guards only the routes under it, and only when it is registered before them.
* Hostile or generated input is bounded, and every bound that cuts something is written in ``notes``: files larger
  than ``MAX_SOURCE_BYTES`` are not read, the map stops at ``MAX_ENTRIES`` entry points, route-DSL nesting is followed
  ``_MAX_NESTING`` levels deep, handler text is scanned within a budget, Python files that do not parse are counted.
  Regular expressions and path patterns taken from the project (Symfony ``access_control``, Spring matchers,
  ``web.xml``) are evaluated only when cheap (a pattern with a quantified group is ignored).
* OpenAPI: routes whose path still contains regular-expression syntax after conversion are not emitted (they are
  listed under ``x-kashif-skipped-paths``); ``ANY`` is emitted as GET and POST; the ``inferredAuth`` security scheme
  is a placeholder (the real scheme is not determined); request/response schemas are not inferred.
* Reports escape everything that comes from the project (file names, routes, handler names): Markdown/HTML markup,
  control and bidirectional characters, spreadsheet formulas in CSV, label syntax in Mermaid/DOT. Quoted literals of
  24+ characters inside a guard's arguments are replaced by ``...`` so a key passed to a middleware is not copied.
* With the engine the map costs one data-flow analysis of the project (as long as a scan); ``--no-engine`` is
  instant but then sinks are textual matches inside the handler body and nothing is proven.
* Where the lowering frontends of the engine do not model a construct (PHP attributes, some closures, C# lambdas)
  the handler body is complemented with textual sink patterns (``origin: "pattern"``), which see one function only.
* Calls through very generic method names (``get``, ``save``, ``run`` ...) on a receiver of unknown type are not
  followed, to avoid linking every ``request.GET.get()`` to an unrelated ``get`` method; such edges can be missed.
* The reachable-sink list is a call-graph over-approximation (name-based resolution where types are unknown, depth
  limited); only the entries under ``findings`` are proven source-to-sink flows.
"""

from __future__ import annotations

import ast
import bisect
import csv
import io
import json
import pathlib
import posixpath
import re
import sys
from dataclasses import dataclass, field

__all__ = ["Param", "Sink", "EntryPoint", "Surface", "build_surface", "build_surface_from_files", "render",
           "render_json", "render_markdown", "render_csv", "render_mermaid", "render_dot", "render_openapi",
           "FORMATS", "STR", "main"]

FORMATS = ("json", "markdown", "csv", "mermaid", "dot", "openapi")
SINK_CATEGORIES = ("sql", "command", "code", "deserialization", "file", "ssrf", "template", "redirect", "nosql",
                   "ldap", "xml", "xss")
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_ENTRIES = 20000          # hostile / generated projects: the map stops growing here (a note says so)
_MAX_NESTING = 64            # route-DSL block nesting that is still followed
SOURCE_EXTS = (".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".java", ".kt", ".kts", ".cs", ".go",
               ".php", ".phtml", ".rb", ".rake")
CONFIG_NAMES = ("web.xml", "security.yaml", "security.yml")

# ------------------------------------------------------------------------------------------------ strings (en / ar)
STR = {
    "en": {
        "title": "Attack surface map",
        "intro": "Static analysis only: no request was sent and no scanned code was executed.",
        "summary": "Summary",
        "entries": "Entry points",
        "http": "HTTP routes", "cli": "CLI commands", "consumer": "Message consumers", "job": "Scheduled / background jobs",
        "unauth": "Without visible authentication",
        "unauth_sink": "Without visible authentication AND reaching a dangerous sink",
        "with_findings": "With proven taint findings",
        "frameworks": "Frameworks",
        "col_rank": "#", "col_risk": "Risk", "col_kind": "Kind", "col_method": "Method", "col_path": "Path / name",
        "col_handler": "Handler", "col_location": "Location", "col_framework": "Framework", "col_auth": "Auth",
        "col_params": "Untrusted parameters", "col_sinks": "Reachable sinks", "col_findings": "Proven findings",
        "col_stores": "Data stores", "col_language": "Language", "col_score": "Score", "col_reasons": "Why",
        "auth_none": "none visible", "auth_public": "explicitly public", "auth_protected": "protected",
        "details": "Details of the riskiest entry points",
        "reachable": "Reachable functions", "none": "-", "notes": "Notes",
        "no_entries": "No entry point was recognised in this project.",
        "risk_critical": "critical", "risk_high": "high", "risk_medium": "medium", "risk_low": "low",
        "r_unauth": "no visible authentication", "r_public": "explicitly public",
        "r_sink": "reaches a dangerous sink ({cats})", "r_finding": "proven taint finding ({n})",
        "r_finding_indirect": "shares a function with a proven taint finding ({n})",
        "r_params": "{n} untrusted parameter(s)", "r_write": "state-changing method without visible authentication",
        "r_local": "not remotely reachable by itself ({kind})",
        "note_engine_off": "Call-graph analysis was disabled: sinks come from textual patterns in the handler only.",
        "note_engine_failed": "The data-flow engine failed ({err}); sinks come from textual patterns only.",
        "note_truncated": "Graph limited to the {n} riskiest entry points.",
        "openapi_desc": ("Skeleton generated by static analysis (Kashif attack-surface map). Paths, parameters and "
                         "authentication are inferred from source code and may be incomplete. No request was sent."),
        "openapi_resp": "Response (not analysed statically)",
        "openapi_auth": "A guard is visible in the code; the real scheme was not determined statically.",
        "cli_desc": "Attack-surface map: entry points, untrusted parameters, authentication, reachable sinks.",
        "err_path": "path not found: {path}",
        "written": "written: {path}",
        "legend_unauth": "red border = no visible authentication",
        "note_extractor": "The {name} extractor failed ({err}); its entry points may be missing.",
        "note_limit": "More than {n} entry points: the map was cut at {n} (generated or hostile code?).",
        "note_skipped": "{n} source file(s) larger than {mb} MB were not read; their entry points are missing.",
        "note_unparsed": "{n} Python file(s) could not be parsed (e.g. {file}); their entry points are missing.",
        "err_write": "cannot write {path}: {err}",
        "note_budget": ("Handlers are nested or repeated abnormally: the scan budget ran out, so parameters, inline "
                        "checks, textual sinks and stores are incomplete for some entry points."),
        "kind_http": "http", "kind_cli": "cli", "kind_consumer": "consumer", "kind_job": "job",
    },
    "ar": {
        "title": "خريطة سطح الهجوم",
        "intro": "تحليل ساكن فقط: لم يُرسَل أي طلب ولم يُنفَّذ أي كود مفحوص.",
        "summary": "الملخص",
        "entries": "نقاط الدخول",
        "http": "مسارات HTTP", "cli": "أوامر سطر الأوامر", "consumer": "مستهلكو الرسائل", "job": "مهام مجدولة / خلفية",
        "unauth": "بلا مصادقة ظاهرة",
        "unauth_sink": "بلا مصادقة ظاهرة وتصل إلى مصرف خطر",
        "with_findings": "لها نتائج تدفق مثبتة",
        "frameworks": "الأُطر",
        "col_rank": "#", "col_risk": "الخطورة", "col_kind": "النوع", "col_method": "الطريقة", "col_path": "المسار / الاسم",
        "col_handler": "المعالج", "col_location": "الموقع", "col_framework": "الإطار", "col_auth": "المصادقة",
        "col_params": "المدخلات غير الموثوقة", "col_sinks": "المصارف التي يصل إليها", "col_findings": "نتائج مثبتة",
        "col_stores": "مخازن البيانات", "col_language": "اللغة", "col_score": "الدرجة", "col_reasons": "السبب",
        "auth_none": "لا شيء ظاهر", "auth_public": "عام صراحةً", "auth_protected": "محمي",
        "details": "تفاصيل أخطر نقاط الدخول",
        "reachable": "الدوال التي يصل إليها", "none": "-", "notes": "ملاحظات",
        "no_entries": "لم يُتعرَّف على أي نقطة دخول في هذا المشروع.",
        "risk_critical": "حرج", "risk_high": "عالٍ", "risk_medium": "متوسط", "risk_low": "منخفض",
        "r_unauth": "لا مصادقة ظاهرة", "r_public": "عام صراحةً",
        "r_sink": "يصل إلى مصرف خطر ({cats})", "r_finding": "نتيجة تدفق مثبتة ({n})",
        "r_finding_indirect": "يشترك في دالة مع نتيجة تدفق مثبتة ({n})",
        "r_params": "{n} مدخل غير موثوق", "r_write": "طريقة تغيّر الحالة بلا مصادقة ظاهرة",
        "r_local": "لا يمكن الوصول إليه عن بُعد بذاته ({kind})",
        "note_engine_off": "عُطِّل تحليل مخطط الاستدعاءات: المصارف مستخرجة من أنماط نصية داخل المعالج فقط.",
        "note_engine_failed": "تعذّر تشغيل محرك تدفق البيانات ({err})؛ المصارف مستخرجة من أنماط نصية فقط.",
        "note_truncated": "اقتُصر المخطط على أخطر {n} نقطة دخول.",
        "openapi_desc": ("هيكل مولَّد بالتحليل الساكن (خريطة سطح الهجوم من كاشِف). المسارات والمدخلات والمصادقة مستنتجة "
                         "من الكود وقد تكون ناقصة. لم يُرسَل أي طلب."),
        "openapi_resp": "الاستجابة (لم تُحلَّل ساكنًا)",
        "openapi_auth": "يوجد حارس ظاهر في الكود؛ لم يُحدَّد المخطط الفعلي ساكنًا.",
        "cli_desc": "خريطة سطح الهجوم: نقاط الدخول، المدخلات غير الموثوقة، المصادقة، المصارف التي يمكن الوصول إليها.",
        "err_path": "المسار غير موجود: {path}",
        "written": "كُتب: {path}",
        "legend_unauth": "إطار أحمر = لا مصادقة ظاهرة",
        "note_extractor": "تعذّر تشغيل مستخرِج {name} ({err})؛ قد تكون نقاط دخوله ناقصة.",
        "note_limit": "أكثر من {n} نقطة دخول: قُطعت الخريطة عند {n} (كود مولَّد أو عدائي؟).",
        "note_skipped": "لم يُقرأ {n} ملف مصدري أكبر من {mb} ميغابايت؛ نقاط دخولها غير مدرجة.",
        "note_unparsed": "تعذّر تحليل {n} ملف بايثون (مثل {file})؛ نقاط دخولها غير مدرجة.",
        "err_write": "تعذّرت الكتابة إلى {path}: {err}",
        "note_budget": ("المعالجات متداخلة أو مكررة بشكل غير طبيعي: استُنفدت ميزانية الفحص، فالمدخلات والفحوص الداخلية "
                        "والمصارف النصية ومخازن البيانات ناقصة لبعض نقاط الدخول."),
        "kind_http": "HTTP", "kind_cli": "سطر أوامر", "kind_consumer": "مستهلك رسائل", "kind_job": "مهمة",
    },
}


def _t(lang: str, key: str, **kw) -> str:
    text = STR.get(lang, STR["en"]).get(key) or STR["en"].get(key, key)
    return text.format(**kw) if kw else text


# ------------------------------------------------------------------------------------------------------ data model
@dataclass
class Param:
    """One untrusted input of an entry point. ``location``: query | path | body | form | header | cookie | file |
    arg (CLI argument) | message (queue payload) | any (source not distinguished, e.g. PHP ``$_REQUEST``)."""
    name: str
    location: str
    type: str = ""

    def to_dict(self) -> dict:
        d = {"name": self.name, "in": self.location}
        if self.type:
            d["type"] = self.type
        return d


@dataclass
class Sink:
    """A dangerous call reachable from an entry point. ``origin`` is ``model`` (the taint engine's sink models) or
    ``pattern`` (textual fallback); ``proven`` is True when a taint finding ends on this line."""
    category: str
    name: str
    file: str
    line: int
    function: str = ""
    depth: int = 0
    cwe: str = ""
    rule: str = ""
    origin: str = "model"
    proven: bool = False

    def to_dict(self) -> dict:
        return {"category": self.category, "name": self.name, "file": self.file, "line": self.line,
                "function": self.function, "depth": self.depth, "cwe": self.cwe, "rule": self.rule,
                "origin": self.origin, "proven": self.proven}


@dataclass
class EntryPoint:
    """One externally reachable entry point.

    ``kind``: http | cli | consumer | job.  ``methods``: HTTP methods (``ANY`` when the framework does not restrict
    them).  ``path``: the route pattern as written, with mount prefixes applied (or the command / queue / schedule
    name for the other kinds).  ``auth``: ``{"status": "protected" | "public" | "none", "guards": [{"name", "kind"}]}``.
    """
    kind: str
    methods: list
    path: str
    handler: str
    file: str
    line: int
    framework: str
    language: str
    params: list = field(default_factory=list)
    auth: dict = field(default_factory=lambda: {"status": "none", "guards": []})
    sinks: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    stores: list = field(default_factory=list)
    reachable: list = field(default_factory=list)
    risk: int = 0
    risk_level: str = "low"
    reasons: list = field(default_factory=list)       # reason keys + arguments, rendered per language
    id: str = ""
    # --- internal (not exported)
    spans: list = field(default_factory=list, repr=False)          # [(file, first line, last line)] of the handler body
    module_level: bool = field(default=False, repr=False)          # the handler is the file's top-level code
    guards: list = field(default_factory=list, repr=False)         # [(name, kind, is_public)]
    edges: list = field(default_factory=list, repr=False)          # call-graph edges (caller label, callee label)

    @property
    def method(self) -> str:
        return ",".join(self.methods)

    @property
    def unauthenticated(self) -> bool:
        return self.auth.get("status") != "protected"

    @property
    def sink_categories(self) -> list:
        seen = []
        for s in self.sinks:
            if s.category not in seen:
                seen.append(s.category)
        return seen

    @property
    def reaches_sink(self) -> bool:
        """True when a dangerous sink other than a reflected-output (XSS) one is reachable."""
        return any(s.category != "xss" for s in self.sinks)

    def reasons_text(self, lang: str = "en") -> list:
        return [_t(lang, key, **args) for key, args in self.reasons]

    def to_dict(self, lang: str = "en") -> dict:
        return {"id": self.id, "kind": self.kind, "method": self.method, "methods": list(self.methods), "path": self.path,
                "openapi_path": openapi_path(self.path) if self.kind == "http" else "",
                "handler": self.handler, "file": self.file, "line": self.line, "framework": self.framework,
                "language": self.language, "params": [p.to_dict() for p in self.params], "auth": self.auth,
                "sinks": [s.to_dict() for s in self.sinks], "sink_categories": self.sink_categories,
                "findings": list(self.findings), "stores": list(self.stores), "reachable": list(self.reachable),
                "risk": self.risk, "risk_level": self.risk_level, "unauthenticated": self.unauthenticated,
                "reaches_sink": self.reaches_sink, "reasons": self.reasons_text(lang)}


@dataclass
class Surface:
    """The attack surface of a project: ``entries`` sorted by risk (riskiest first) and analysis ``notes``."""
    root: str
    entries: list = field(default_factory=list)
    notes: list = field(default_factory=list)          # [(key, args)] rendered per language
    files_read: int = 0

    def summary(self) -> dict:
        kinds = {k: 0 for k in ("http", "cli", "consumer", "job")}
        frameworks: dict = {}
        for e in self.entries:
            kinds[e.kind] = kinds.get(e.kind, 0) + 1
            frameworks[e.framework] = frameworks.get(e.framework, 0) + 1
        return {"entries": len(self.entries), "by_kind": kinds,
                "frameworks": dict(sorted(frameworks.items(), key=lambda kv: (-kv[1], kv[0]))),
                "unauthenticated": sum(1 for e in self.entries if e.kind == "http" and e.unauthenticated),
                "unauthenticated_reaching_sink": sum(1 for e in self.entries
                                                     if e.kind == "http" and e.unauthenticated and e.reaches_sink),
                "with_findings": sum(1 for e in self.entries if e.findings),
                "files_read": self.files_read}

    def notes_text(self, lang: str = "en") -> list:
        return [_t(lang, key, **args) for key, args in self.notes]

    def to_dict(self, lang: str = "en") -> dict:
        return {"tool": "kashif-surface", "schema": 1, "root": self.root, "static_only": True, "summary": self.summary(),
                "entries": [e.to_dict(lang) for e in self.entries], "notes": self.notes_text(lang)}


# ------------------------------------------------------------------------------------------------- text utilities
_CLIKE = {"javascript", "java", "kotlin", "csharp", "go"}


def _language(rel: str) -> str | None:
    low = rel.lower()
    if low.endswith(".py"):
        return "python"
    if low.endswith((".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")):
        return None if low.endswith((".d.ts", ".min.js")) else "javascript"
    for exts, lang in (((".java",), "java"), ((".kt", ".kts"), "kotlin"), ((".cs",), "csharp"), ((".go",), "go"),
                       ((".php", ".phtml"), "php"), ((".rb", ".rake"), "ruby")):
        if low.endswith(exts):
            return lang
    return None


def _mask(text: str, lang: str) -> tuple[str, str]:
    """Two same-length copies of ``text``: ``code`` with comments blanked, ``bare`` with comments and the contents
    of string literals blanked (quotes kept). Newlines are preserved so offsets and line numbers stay valid."""
    n = len(text)
    code = list(text)
    bare = list(text)
    i = 0
    hash_comments = lang in ("php", "ruby", "python")
    slash_comments = lang in _CLIKE or lang == "php"
    while i < n:
        c = text[i]
        if slash_comments and c == "/" and i + 1 < n and text[i + 1] in "/*":
            if text[i + 1] == "/":
                j = text.find("\n", i)
                j = n if j < 0 else j
            else:
                j = text.find("*/", i + 2)
                j = n if j < 0 else j + 2
            for k in range(i, j):
                if text[k] != "\n":
                    code[k] = bare[k] = " "
            i = j
            continue
        if hash_comments and c == "#" and not (lang == "php" and i + 1 < n and text[i + 1] == "[") \
                and not (lang == "ruby" and i + 1 < n and text[i + 1] == "{"):
            j = text.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                code[k] = bare[k] = " "
            i = j
            continue
        if c in "\"'" or (c == "`" and lang in ("javascript", "go", "ruby", "php")):
            triple = text.startswith(c * 3, i) and c == '"' and lang in ("java", "kotlin", "csharp", "python")
            q = c * 3 if triple else c
            multiline = triple or c == "`" or lang in ("php", "ruby")
            if c == "'" and lang in ("java", "kotlin", "csharp", "go") and not re.match(r"'(\\.|[^\\'])'", text[i:i + 4]):
                i += 1            # a lone apostrophe (generic bounds, labels): not a char literal
                continue
            j = i + len(q)
            while j < n:
                if text[j] == "\\" and not (c == "`" and lang == "go"):
                    j += 2
                    continue
                if text.startswith(q, j):
                    break
                if text[j] == "\n" and not multiline:
                    break
                j += 1
            end = min(n, j + len(q)) if j < n and text.startswith(q, j) else min(n, j)
            for k in range(i + len(q), min(j, n)):
                if text[k] != "\n":
                    bare[k] = " "
            i = max(end, i + 1)
            continue
        i += 1
    return "".join(code), "".join(bare)


class _Lines:
    """Offset -> 1-based line number."""

    def __init__(self, text: str):
        self.starts = [0]
        for m in re.finditer("\n", text):
            self.starts.append(m.end())

    def of(self, offset: int) -> int:
        return bisect.bisect_right(self.starts, max(0, offset))

    def start(self, line: int) -> int:
        return self.starts[min(max(line, 1), len(self.starts)) - 1]


_PAIRS = {"(": ")", "[": "]", "{": "}"}


_BRACKET_RE = re.compile(r"[()\[\]{}]")
_MATCH_CACHE: dict = {}      # text -> {offset of an opening bracket: offset of its closing bracket}
_MATCH_CACHE_MAX = 24


def _match_table(bare: str) -> dict:
    """All bracket pairs of ``bare`` in ONE pass (brackets are not typed, like the scan it replaces). Without this
    table every ``_close`` call on an unbalanced file walks to the end of the file: quadratic time on hostile
    input such as 100 000 unclosed ``app.get(``."""
    table = _MATCH_CACHE.get(bare)
    if table is None:
        table, stack = {}, []
        for m in _BRACKET_RE.finditer(bare):
            if m.group(0) in "([{":
                stack.append(m.start())
            elif stack:
                table[stack.pop()] = m.start()
        while len(_MATCH_CACHE) >= _MATCH_CACHE_MAX:
            _MATCH_CACHE.pop(next(iter(_MATCH_CACHE)))
        _MATCH_CACHE[bare] = table
    return table


def _close(bare: str, i: int) -> int:
    """Index of the bracket matching ``bare[i]`` (``(``, ``[`` or ``{``), or -1."""
    n = len(bare)
    if not 0 <= i < n:
        return -1
    if n > 512:
        if bare[i] not in "([{":                  # callers may point just before the bracket (leading blanks)
            m = _BRACKET_RE.search(bare, i)
            if m is None or m.group(0) not in "([{":
                return -1
            i = m.start()
        return _match_table(bare).get(i, -1)
    depth = 0
    j = i
    while j < n:
        ch = bare[j]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                return j
        j += 1
    return -1


_SPLIT_RES: dict = {}


def _split_top(bare: str, start: int, end: int, sep: str = ",") -> list:
    """Top-level ``sep``-separated pieces of ``bare[start:end]`` as (start, end) offsets. Nested brackets are
    jumped over with the bracket table, so the cost is the top-level text only (deeply nested route groups would
    otherwise be re-read once per level)."""
    rx = _SPLIT_RES.get(sep)
    if rx is None:
        rx = _SPLIT_RES[sep] = re.compile("[(\\[{" + re.escape(sep) + "]")
    out, a, j = [], start, start
    while j < end:
        m = rx.search(bare, j, end)
        if m is None:
            break
        j = m.start()
        if bare[j] == sep:
            out.append((a, j))
            a = j + 1
            j += 1
            continue
        k = _close(bare, j)
        if k < 0 or k >= end:
            break                                           # unbalanced: the rest is one piece
        j = k + 1
    if bare[a:end].strip() or out:
        out.append((a, end))
    return [(s, e) for s, e in out if bare[s:e].strip()]


_STR_RE = re.compile(r"""(?s)(['"`])((?:\\.|(?!\1).)*)\1""")


def _first_str(segment: str) -> str | None:
    m = _STR_RE.search(segment)
    return m.group(2) if m else None


def _all_strs(segment: str) -> list:
    return [m.group(2) for m in _STR_RE.finditer(segment)]


def _block_after(bare: str, pos: int, limit: int = 1500) -> tuple[int, int] | None:
    """The ``{...}`` block that starts at or after ``pos`` (parenthesised groups are skipped; a ``;`` first means
    there is no block). Returns (offset of ``{``, offset of the matching ``}``)."""
    j, n = pos, min(len(bare), pos + limit)
    while j < n:
        ch = bare[j]
        if ch in "([":
            k = _close(bare, j)
            if k < 0:
                return None
            j = k + 1
            continue
        if ch == "{":
            k = _close(bare, j)
            return (j, k) if k > 0 else None
        if ch == ";":
            return None
        j += 1
    return None


def _join_path(*parts: str) -> str:
    out = ""
    for p in parts:
        if p is None or p == "":
            continue
        p = str(p)
        out = out.rstrip("/") + "/" + p.lstrip("/") if out else p
    if not out.startswith("/"):
        out = "/" + out
    return re.sub(r"/{2,}", "/", out)


_PATH_VAR_RES = (
    (re.compile(r"\(\?P<(\w+)>(?:[^()]|\([^()]*\))*\)"), r"{\1}"),      # Django re_path named group
    (re.compile(r"<(?:[^<>:]+:)?(\w+)>"), r"{\1}"),                      # Flask / Django <int:id>
    (re.compile(r"\{(\w+)\s*[:=?][^{}]*(?:\{[^{}]*\}[^{}]*)*\}"), r"{\1}"),   # {id:[0-9]+} {id:int} {id?} {id=5}
    (re.compile(r"\{[*.]{1,3}(\w+)\}"), r"{\1}"),                         # {*rest} {...rest}
    (re.compile(r"\[\[?\.\.\.(\w+)\]?\]"), r"{\1}"),                      # Next.js [...slug] [[...slug]]
    (re.compile(r"\[(\w+)\]"), r"{\1}"),                                  # Next.js [id]
    (re.compile(r"(?<=/)[:*](\w+)[?*+]?(?:\([^)]*\))?"), r"{\1}"),        # Express/gin/Rails :id  *path
    (re.compile(r"(?<=[\-.}]):([A-Za-z_]\w*)[?*+]?(?:\([^)]*\))?"), r"{\1}"),   # Express /:from-:to  /:file.:ext
    (re.compile(r"\{(\w+)\?\}"), r"{\1}"),                                # Laravel {id?}
)


def openapi_path(path: str) -> str:
    """Normalise a framework route pattern to an OpenAPI path template (``/users/{id}``)."""
    p = path.strip()
    p = re.sub(r"^\^", "", p)
    p = re.sub(r"\$$", "", p)
    p = p.replace("(.:format)", "")                          # Rails optional format suffix
    p = re.sub(r"/?\{\$\}$", lambda m: "/" if m.group(0).startswith("/") else "", p)   # Go 1.22 end anchor {$}
    p = re.sub(r"\{(\w+)\.\.\.\}", r"{\1}", p)              # Go 1.22 remainder wildcard {path...}
    p = re.sub(r"\{!?(\w+)(?:<[^{}]*>)?(?:\?[^{}]*)?\}", r"{\1}", p)   # Symfony {id<\d+>} {!page} {page<\d+>?1}
    for rx, rep in _PATH_VAR_RES:
        p = rx.sub(rep, p)
    p = p.replace("\\", "")
    p = re.sub(r"(?<=/)\*+$", "{wildcard}", p)
    p = re.sub(r"\*+", "{wildcard}", p)
    p = re.sub(r"\(\.:format\)|\?$", "", p)
    if not p.startswith("/"):
        p = "/" + p
    seen: dict = {}

    def uniq(m):
        name = m.group(1)
        seen[name] = seen.get(name, 0) + 1
        return "{%s}" % (name if seen[name] == 1 else f"{name}{seen[name]}")

    return re.sub(r"\{(\w+)\}", uniq, re.sub(r"/{2,}", "/", p))


_OPENAPI_PATH_OK = re.compile(r"/(?:[^{}\s?#()\[\]*+^$|\\]|\{\w+\})*\Z")


def _path_vars(path: str) -> list:
    return re.findall(r"\{(\w+)\}", openapi_path(path))


# ----------------------------------------------------------------------------------------------- auth vocabulary
_PUBLIC_RE = re.compile(r"(?i)^(allow_?anonymous|permit_?all|allow_?any|public|skip_?auth\w*|is_?public|no_?auth\w*|"
                        r"anonymous|unauthenticated|optional_?auth\w*|public_?access|is_authenticated_anonymously|guest)$")
_AUTH_RE = re.compile(
    r"(?i)(auth(?!or(?!i[sz]))|log(?:ged)?_?in|signed_?in|jwt|bearer|token_?(required|auth|verif)|verify_?(token|jwt|user|session|api)|"
    r"require_?(login|user|admin|role|permission|scope|session|staff|superuser)|permission|is_?(admin|staff|superuser)|"
    r"admin_?(only|required)|ensure_?(logged|admin|user)|protect|guard|rbac|\bacl\b|oauth|oidc|session_?required|"
    r"check_?(login|session|role|admin|user)|roles?_?(allowed|required|accepted)|\broles?\b|secured|passport|sanctum|"
    r"keycloak|has_?(any_?)?(role|permission|authority|scope)|\bcan\b|staff_member|superuser|api_?key|is_?granted|"
    r"deny_?all|principal|current_?user|verified|scopes?_?required|access_?control|policy)")
# Names that contain an auth-looking word but do NOT enforce authentication. Calling one of these a guard would mark
# an open route "protected" - the dangerous direction for this report - so the list errs on the side of "not a guard".
_NOT_AUTH_RE = re.compile(r"(?i)(csrf|xsrf|forgery|authenticity_token|cors|throttle|rate_?limit|limiter|slow_?down|unauthor|"
                          r"author(?!i[sz])|set_current_user|oauth_?callback|passport\.(?:initialize|session)\b|"
                          r"(?:content_?security|referrer|permissions|cross_?origin\w*|feature)_?policy|\bcsp\b|helmet|"
                          r"user_?loader|error_?handler|exception_?handler|(?:^|[._])log(?:ger|ging)?_?auth|auth\w*_?log(?:ger)?$|"
                          r"audit|authorize_redirect|login_?(?:page|form|view|url|redirect)|logout)")
_OPTIONAL_AUTH_RE = re.compile(r"(?i)(?:^|[._:])(?:optional|(?:jwt|auth|login|token|user)_?optional|optional_?(?:jwt|auth|login|"
                               r"token|user)\w*|try_?auth\w*)$")
_PUBLIC_ARGS_RE = re.compile(r"(?i)\boptional\s*[=:]\s*true\b|credentials_?required\s*[=:]\s*false\b|"
                             r"^\s*['\"]\s*(?:permitAll(?:\(\))?|isAnonymous\(\))\s*['\"]\s*$|\bAllowAnonymous\b")


_READONLY_PUBLIC_RE = re.compile(r"Or(?:Anon)?ReadOnly\b")


def _is_auth_name(name: str) -> bool:
    return bool(name) and not _NOT_AUTH_RE.search(name) and bool(_AUTH_RE.search(name))


def _guard(name: str, kind: str) -> tuple | None:
    """Classify a decorator / middleware / annotation name: (name, kind, is_public) or None when it is not about
    authentication."""
    name = name.strip()
    head, _sep, args = name.partition("(")
    tail = re.split(r"[.:\\>]+", head)[-1]
    if _PUBLIC_RE.match(tail) or _PUBLIC_RE.match(re.sub(r"\W", "", name)):
        return (name, kind, True)
    if _is_auth_name(head) or _is_auth_name(name):
        # authentication that is attempted but not required leaves the route open: jwt_required(optional=True),
        # expressjwt({credentialsRequired: false}), auth.optional, @PreAuthorize("permitAll()")
        if _OPTIONAL_AUTH_RE.search(head.strip()) or _PUBLIC_ARGS_RE.search(args.rsplit(")", 1)[0]):
            return (name, kind, True)
        return (name, kind, False)
    return None


# A guard is shown with its arguments (roles, scopes); a long quoted literal there is more likely a key than a role
# name, and a report must never carry one.
_LONG_LITERAL_RE = re.compile(r"""(['"`])[^'"`\s]{24,}\1""")


def _auth_from_guards(guards: list) -> dict:
    """``guards`` is ordered from the most specific (the route itself) to the least (global configuration): the
    first one decides, so ``[AllowAnonymous]`` on a method overrides ``[Authorize]`` on its class."""
    seen, uniq = set(), []
    for g in guards:
        if g and g[:2] not in seen:
            seen.add(g[:2])
            uniq.append(g)
    if not uniq:
        return {"status": "none", "guards": []}
    status = "public" if uniq[0][2] else "protected"
    shown = [g for g in uniq if g[2] == (status == "public")]
    return {"status": status, "guards": [{"name": _LONG_LITERAL_RE.sub(r"\1...\1", g[0])[:120], "kind": g[1]} for g in shown]}


# -------------------------------------------------------------------------------------- parameter / inline-auth scan
_Q = r"""\s*['"]([^'"\n]{1,80})['"]"""
_PARAM_PATTERNS = {
    "python": [
        (r"\brequest\.(?:args|GET|query_params|query|rel_url\.query)(?:\.(?:get|getlist|pop)\(|\[)" + _Q, "query"),
        (r"\brequest\.(?:form|POST)(?:\.(?:get|getlist|pop)\(|\[)" + _Q, "form"),
        (r"\brequest\.(?:values|params|REQUEST)(?:\.get\(|\[)" + _Q, "any"),
        (r"\brequest\.(?:json|data|get_json\(\)|json\(\))(?:\.get\(|\[)" + _Q, "body"),
        (r"\brequest\.(?:headers|META)(?:\.get\(|\[)" + _Q, "header"),
        (r"\brequest\.(?:cookies|COOKIES)(?:\.get\(|\[)" + _Q, "cookie"),
        (r"\brequest\.(?:files|FILES)(?:\.get\(|\[)" + _Q, "file"),
    ],
    "javascript": [
        (r"\b{R}\.query\.([A-Za-z_$][\w$]*)", "query"), (r"\b{R}\.query\[" + _Q, "query"),
        (r"\bsearchParams\.get\(" + _Q, "query"),
        (r"\b{R}\.(?:body|payload)\.([A-Za-z_$][\w$]*)", "body"), (r"\b{R}\.(?:body|payload)\[" + _Q, "body"),
        (r"\b{R}\.params\.([A-Za-z_$][\w$]*)", "path"), (r"\b{R}\.params\[" + _Q, "path"),
        (r"\b{R}\.headers\.([A-Za-z_$][\w$]*)", "header"), (r"\b{R}\.headers\[" + _Q, "header"),
        (r"\b{R}\.(?:get|header)\(" + _Q, "header"), (r"\bheaders\(\)\.get\(" + _Q, "header"),
        (r"\b{R}\.headers\.get\(" + _Q, "header"),
        (r"\b{R}\.(?:signedCookies|cookies)\.(?!get\b)([A-Za-z_$][\w$]*)", "cookie"),
        (r"\b{R}\.(?:signedCookies|cookies)(?:\[|\.get\()" + _Q, "cookie"), (r"\bcookies\(\)\.get\(" + _Q, "cookie"),
    ],
    "go": [
        (r"\.URL\.Query\(\)\.Get\(" + _Q, "query"), (r"\.URL\.Query\(\)\[" + _Q, "query"),
        (r"\.(?:Query|DefaultQuery|QueryParam|GetQuery|QueryArray|QueryInt)\(" + _Q, "query"),
        (r"\.(?:FormValue|PostFormValue|PostForm|DefaultPostForm)\(" + _Q, "form"),
        (r"\.(?:Param|PathValue|Params)\(" + _Q, "path"), (r"\bURLParam\(\s*\w+\s*," + _Q, "path"),
        (r"\bmux\.Vars\(\s*\w+\s*\)\[" + _Q, "path"),
        (r"\.Header\.Get\(" + _Q, "header"), (r"\.GetHeader\(" + _Q, "header"),
        (r"\.Cookies?\(" + _Q, "cookie"), (r"\.FormFile\(" + _Q, "file"),
    ],
    "java": [
        (r"\.getParameter(?:Values)?\(" + _Q, "query"), (r"\.getHeaders?\(" + _Q, "header"),
        (r"\.getPart\(" + _Q, "file"), (r"\.(?:queryParam|getQueryParams\(\)\.getFirst)\(" + _Q, "query"),
    ],
    "csharp": [
        (r"\bRequest\.Query\[" + _Q, "query"), (r"\bRequest\.Form\[" + _Q, "form"),
        (r"\bRequest\.Headers\[" + _Q, "header"), (r"\bRequest\.Cookies\[" + _Q, "cookie"),
        (r"\bRouteData\.Values\[" + _Q, "path"), (r"\bRequest\.QueryString\[" + _Q, "query"),
        (r"\bRequest\.Params\[" + _Q, "any"),
    ],
    "php": [
        (r"\$_GET\[" + _Q, "query"), (r"\$_POST\[" + _Q, "form"), (r"\$_REQUEST\[" + _Q, "any"),
        (r"\$_COOKIE\[" + _Q, "cookie"), (r"\$_FILES\[" + _Q, "file"), (r"\$_SERVER\[\s*['\"](HTTP_\w+)['\"]", "header"),
        (r"\$_SERVER\[\s*['\"](REQUEST_URI|QUERY_STRING|PATH_INFO|PHP_SELF)['\"]", "any"),
        (r"\bfilter_input\(\s*INPUT_GET\s*," + _Q, "query"), (r"\bfilter_input\(\s*INPUT_POST\s*," + _Q, "form"),
        (r"->query->get\(" + _Q, "query"), (r"->request->get\(" + _Q, "form"), (r"->headers->get\(" + _Q, "header"),
        (r"->cookies->get\(" + _Q, "cookie"), (r"->files->get\(" + _Q, "file"),
        (r"\$\w*[Rr]eq\w*->(?:input|get|post|string|integer|boolean|json|date|enum)\(" + _Q, "any"),
        (r"\$\w*[Rr]eq\w*->query\(" + _Q, "query"), (r"\$\w*[Rr]eq\w*->header\(" + _Q, "header"),
        (r"\$\w*[Rr]eq\w*->cookie\(" + _Q, "cookie"), (r"\$\w*[Rr]eq\w*->file\(" + _Q, "file"),
        (r"\brequest\(" + _Q, "any"),
    ],
    "ruby": [
        (r"\bparams\[\s*:?['\"]?(\w+)", "any"), (r"\bparams\.(?:fetch|require|delete|dig)\(\s*:?['\"]?(\w+)", "any"),
        (r"\brequest\.headers\[" + _Q, "header"), (r"\brequest\.env\[\s*['\"](HTTP_\w+)['\"]", "header"),
        (r"\bcookies(?:\.\w+)?\[\s*:?['\"]?(\w+)", "cookie"),
    ],
}
_PARAM_PATTERNS["kotlin"] = _PARAM_PATTERNS["java"]
_BODY_MARKERS = {
    "python": r"\brequest\.(?:get_json\(|json\b|data\b|body\b|get_data\(|stream\b|post\(\))",
    "javascript": r"\b{R}\.(?:body|payload|rawBody)\b(?!\s*=[^=])|\.json\(\s*\)|\.formData\(\s*\)|\.text\(\s*\)",
    "go": r"\b(?:ShouldBind\w*|Bind\w*|BodyParser|MustBind\w*)\(|\.Body\b",
    "java": r"\.getInputStream\(|\.getReader\(", "kotlin": r"\.getInputStream\(|\.getReader\(|\.inputStream\b",
    "csharp": r"\bRequest\.Body\b|\bReadFromJsonAsync|\bReadFormAsync",
    "php": r"php://input|->getContent\(|->(?:all|validated|only|except|post)\(\s*[\[)]|->json\(\s*\)|\$_POST\b(?!\s*\[)",
    "ruby": r"\brequest\.(?:body|raw_post)\b",
}
_BODY_ALIAS = {
    "python": r"\b(\w+)\s*=\s*(?:await\s+)?request\.(?:get_json\([^)]*\)|json\(\)|json\b|data\b)",
    "javascript": r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?{R}\.(?:body\b|json\(\))",
}
_INLINE_AUTH = {
    "python": r"current_user\.is_authenticated|request\.user\.(?:is_authenticated|is_staff|is_superuser|has_perms?)|"
              r"['\"]user(?:_id|name)?['\"]\s+(?:not\s+)?in\s+session|session\.get\(\s*['\"]user|verify_jwt_in_request|"
              r"\bget_current_user\(|\bjwt\.decode\(|\brequire_auth\(|\bcheck_auth\(",
    "javascript": r"\b{R}\.(?:user|auth|isAuthenticated\(\))|\.session\.(?:user\w*|uid|account)|\bjwt\.verify\(|"
                  r"\bgetServerSession\(|\bgetToken\(|\bauth\(\s*\)|\bcurrentUser\(|\bctx\.state\.user|\bverifyToken\(|"
                  r"\bgetSession\(|\bwithApiAuthRequired\b|\bwithAuth\b|\bisAuthenticated\(",
    "java": r"\.isUserInRole\(|\.getUserPrincipal\(|\.getRemoteUser\(|getSession\([^)]*\)\.getAttribute\(\s*\"(?:user|login|auth)"
            r"|SecurityContextHolder|\.getAuthentication\(",
    "csharp": r"User\.Identity\??\.IsAuthenticated|\bUser\.IsInRole\(|\bAuthorizeAsync\(|\bUser\.FindFirst\(|\bUser\.Claims\b",
    "go": r"\.BasicAuth\(\)|\bjwt\.Parse\w*\(|Header\.Get\(\s*\"Authorization\"|GetHeader\(\s*\"Authorization\"|"
          r"\bsessions?\.(?:Get|Default)\(|\b(?:checkAuth|requireAuth|isAuthenticated|authenticate|currentUser)\(",
    "php": r"\$_SESSION\[\s*['\"](?:user|uid|logged|auth|admin|login)\w*|\bAuth::(?:check|user|id|guard)\(|"
           r"\bauth\(\)->(?:check|user|id)|->authorize\(|\bGate::(?:allows|denies|authorize)|denyAccessUnlessGranted\(|"
           r"->isGranted\(|\bcurrent_user_can\(|\bis_user_logged_in\(|PHP_AUTH_USER|HTTP_AUTHORIZATION|"
           r"\b(?:require|include)(?:_once)?\b[^;\n]*\b(?:auth|login|session)[\w./-]*\.php|\bcheck_?(?:login|auth)\w*\(|"
           r"\bis_?logged_?in\w*\(|\brequire_?login\w*\(",
    "ruby": r"\bcurrent_user\b|\bauthenticate\w*!|\bauthorize!?\s|\bsigned_in\?|\blogged_in\?|\bsession\[\s*:user\w*|"
            r"\bprotected!|\bdoorkeeper_authorize!|\bauthenticate_or_request_with_http_\w+",
}
_INLINE_AUTH["kotlin"] = _INLINE_AUTH["java"]


_ENFORCING_RE = re.compile(r"verify_jwt_in_request|authenticate\w*!|authorize!|doorkeeper_authorize!|protected!|"
                           r"denyAccessUnlessGranted|->authorize|Gate::authorize|jwt\.verify|jwt\.decode|jwt\.Parse|"
                           r"require_?auth|require_?login|check_?auth|check_?login|requireAuth|checkAuth|"
                           r"authenticate_or_request_with_http|withApiAuthRequired|withAuth|(?:require|include)(?:_once)?\b")
_DENY_RE = re.compile(r"\b40[13]\b|(?i:unauthori[sz]ed|forbidden|access.?denied|not.?authenticated|permission.?denied|"
                      r"not.?logged.?in|login.?required)|\babort\(|\bredirect\w*\b|\braise\b|\bthrow\b|\bhalt\b|\bexit\b|"
                      r"\bdie\b|\bsendError\(|\bChallenge\(|\bForbid\(|\bpanic\(|Location:|\bnotFound\(|\bNotFound\(|\b404\b")


def _req_names(names) -> str:
    base = ["req", "request", r"ctx(?:\.request|\.req)?", r"c\.req", "event"]
    base += [re.escape(n) for n in names if n and re.fullmatch(r"[A-Za-z_$][\w$]*", n) and n not in ("req", "request", "ctx")]
    return "(?:" + "|".join(base) + ")"


def _header_name(raw: str) -> str:
    if raw.startswith("HTTP_"):
        return "-".join(w.capitalize() for w in raw[5:].split("_"))
    return raw


def _scan_params(lang: str, code: str, req_names=()) -> list:
    """Untrusted inputs read in a piece of handler code (comments already blanked)."""
    out: list = []
    seen = set()
    R = _req_names(req_names)

    def add(name, loc):
        if loc == "header":
            name = _header_name(name)
        key = (name.lower() if loc == "header" else name, loc)
        if name and key not in seen and re.fullmatch(r"[\w.\-\[\]:$*()]{1,64}", name):
            seen.add(key)
            out.append(Param(name, loc))

    for rx, loc in _PARAM_PATTERNS.get(lang, ()):
        for m in re.finditer(rx.replace("{R}", R), code):
            add(m.group(1), loc)
    if lang == "javascript":
        for m in re.finditer(r"\{([^{}=]{1,300})\}\s*=\s*(?:await\s+)?" + R + r"\.(query|body|params|headers|cookies)\b", code):
            loc = {"query": "query", "body": "body", "params": "path", "headers": "header", "cookies": "cookie"}[m.group(2)]
            for piece in m.group(1).split(","):
                name = piece.split(":")[0].strip()
                if re.fullmatch(r"[A-Za-z_$][\w$]*", name):
                    add(name, loc)
    if lang == "php":
        for m in re.finditer(r"->validate\(\s*\[", code):
            end = _close(code, m.end() - 1)
            for k in re.finditer(r"['\"]([\w.*-]+)['\"]\s*=>", code[m.end():end if end > 0 else m.end() + 600]):
                add(k.group(1), "any")
    if lang == "ruby":
        for m in re.finditer(r"\.permit\(([^)]{0,400})\)", code):
            for k in re.finditer(r":(\w+)", m.group(1)):
                add(k.group(1), "body")
    alias_rx = _BODY_ALIAS.get(lang)
    if alias_rx:
        for m in re.finditer(alias_rx.replace("{R}", R), code):
            for k in re.finditer(r"\b" + re.escape(m.group(1)) + r"(?:\.get\(|\[)" + _Q, code):
                add(k.group(1), "body")
            if lang == "javascript":
                for k in re.finditer(r"\b" + re.escape(m.group(1)) + r"\.([A-Za-z_$][\w$]*)\b(?!\s*\()", code):
                    add(k.group(1), "body")
    marker = _BODY_MARKERS.get(lang)
    if marker and not any(p.location in ("body", "form") for p in out) and re.search(marker.replace("{R}", R), code):
        add("(body)", "body")
    if lang == "javascript" and re.search(r"\b" + R + r"\.files?\b", code):
        add("(upload)", "file")
    return out


def _inline_guards(lang: str, code: str, req_names=()) -> list:
    """An authentication check written inside the handler. Reading the identity is not a check: ``req.user``,
    ``current_user`` or ``$_SESSION['user']`` only count when the same handler also rejects somebody (401/403, abort,
    redirect, raise/throw ...), unless the call enforces by itself (``authenticate_user!``, ``jwt.verify(`` ...).
    Otherwise an open handler that merely greets the logged-in user would be reported as protected."""
    rx = _INLINE_AUTH.get(lang)
    if not rx:
        return []
    denies = None
    for m in re.finditer(rx.replace("{R}", _req_names(req_names)), code):
        hit = re.sub(r"\s+", " ", m.group(0)).strip(" (")
        if not _ENFORCING_RE.search(hit):
            if denies is None:
                denies = _DENY_RE.search(code) is not None
            if not denies:
                continue
        return [("inline: " + hit, "inline", False)]
    return []


# ------------------------------------------------------------------------------------------------ project context
class _File:
    __slots__ = ("rel", "text", "lang", "code", "bare", "lines", "tree")

    def __init__(self, rel: str, text: str, lang: str):
        self.rel, self.text, self.lang = rel, text, lang
        self.tree = None
        if lang == "python":
            self.code = self.bare = text
        else:
            self.code, self.bare = _mask(text, lang)
        self.lines = _Lines(text)

    def segment(self, start_line: int, end_line: int) -> str:
        return self.code[self.lines.start(start_line):self.lines.start(end_line + 1) if end_line < len(self.lines.starts)
                         else len(self.code)]


class _Limit(Exception):
    """Raised by ``_Ctx.add`` when ``MAX_ENTRIES`` is reached."""


class _Ctx:
    def __init__(self, files: dict, config: dict | None = None):
        self.unparsed: list = []
        self.exhausted = False
        # Handler text that may still be scanned for parameters / sinks / stores. An ordinary project never gets
        # near it (a byte belongs to few handlers); thousands of handlers nested in each other would otherwise
        # make every scan quadratic.
        self.budget = max(16 * 1024 * 1024, 4 * sum(len(v) for v in files.values() if isinstance(v, str)))
        self.files: dict = {}
        for rel, text in files.items():
            lang = _language(rel)
            if lang and len(text) <= MAX_SOURCE_BYTES:
                self.files[rel] = _File(rel, text, lang)
        self.config = config or {}
        self.entries: list = []
        self._defs: dict = {}

    def lang(self, *langs):
        return [f for f in self.files.values() if f.lang in langs]

    def take(self, n: int) -> bool:
        """Spend ``n`` characters of the scan budget; False (and ``exhausted``) when it is used up."""
        if self.budget < n:
            self.exhausted = True
            return False
        self.budget -= n
        return True

    def add(self, f: _File, kind: str, methods, path: str, handler: str, line: int, framework: str, spans=None,
            params=None, guards=None, module_level: bool = False, req_names=(), scan: bool = True) -> EntryPoint:
        """Register an entry point; parameters and inline guards found in the handler body are appended."""
        if len(self.entries) >= MAX_ENTRIES:
            raise _Limit()
        methods = [m.upper() for m in (methods or [])] or (["ANY"] if kind == "http" else [])
        spans = [s for s in (spans or []) if s]
        params = list(params or [])
        guards = list(guards or [])
        if kind == "http":
            have = {p.name for p in params if p.location == "path"}
            params = [Param(v, "path") for v in _path_vars(path) if v not in have and v != "wildcard"] + params
        if scan:
            for rel, a, b in spans:
                sf = self.files.get(rel)
                if not sf:
                    continue
                seg = sf.segment(a, b)
                if not self.take(len(seg)):
                    continue
                for p in _scan_params(sf.lang, seg, req_names):
                    if not any(q.name == p.name and (q.location == p.location or q.location == "path") for q in params):
                        params.append(p)
                guards.extend(_inline_guards(sf.lang, seg, req_names))
        e = EntryPoint(kind=kind, methods=methods, path=path, handler=handler, file=f.rel, line=line,
                       framework=framework, language=f.lang, params=params, spans=spans, module_level=module_level,
                       guards=guards)
        self.entries.append(e)
        return e

    # -- definitions index for the brace / `end` languages (handler lookup by name)
    def defs(self, f: _File) -> list:
        """[(name, class name, first line, last line, params text)] for the functions defined in a file."""
        hit = self._defs.get(f.rel)
        if hit is None:
            hit = self._defs[f.rel] = _index_defs(f)
        return hit

    def find_def(self, name: str, lang_group: tuple, prefer: _File | None = None, cls: str | None = None,
                 hint: str | None = None):
        """Locate a function by name: the preferred file first, then files matching ``hint`` (a path fragment), then
        anywhere in the project. Returns (file, def tuple) or None."""
        if not name:
            return None
        order = []
        if prefer is not None:
            order.append(prefer)
        others = [x for x in self.files.values() if x.lang in lang_group and x is not prefer]
        if hint:
            h = hint.lower().strip("./")
            others.sort(key=lambda x: 0 if h and h in x.rel.lower() else 1)
        elif prefer is not None:
            d = posixpath.dirname(prefer.rel)
            others.sort(key=lambda x: 0 if posixpath.dirname(x.rel) == d else 1)
        for x in order + others:
            for d in self.defs(x):
                if d[0] == name and (cls is None or d[1] == cls):
                    return x, d
        return None


_JS_KEYWORDS = {"if", "for", "while", "switch", "catch", "function", "return", "else", "do", "try", "with", "super",
                "constructor", "typeof", "await", "new", "throw", "delete", "void", "yield"}


def _index_defs(f: _File) -> list:
    bare, lines = f.bare, f.lines
    out = []

    def block(pos, name, cls="", params=""):
        blk = _block_after(bare, pos)
        if blk:
            out.append((name, cls, lines.of(pos), lines.of(blk[1]), params))
            return blk
        out.append((name, cls, lines.of(pos), lines.of(bare.find("\n", pos) if bare.find("\n", pos) > 0 else len(bare)), params))
        return None

    def params_at(open_idx):
        k = _close(bare, open_idx)
        return f.code[open_idx + 1:k] if k > 0 else ""

    if f.lang == "javascript":
        classes = []
        for m in re.finditer(r"\bclass\s+([\w$]+)[^{;]*\{", bare):
            k = _close(bare, m.end() - 1)
            if k > 0:
                classes.append((m.start(), k, m.group(1)))

        def cls_of(pos):
            return next((c for a, b, c in classes if a <= pos <= b), "")

        for m in re.finditer(r"\b(?:async\s+)?function\s*\*?\s*([\w$]+)\s*\(", bare):
            block(m.start(), m.group(1), "", params_at(m.end() - 1))
        for m in re.finditer(r"\b(?:const|let|var)\s+([\w$]+)\s*(?::[^=\n]+)?=\s*(?:async\s*)?(?=function\b|\(|[\w$]+\s*=>)", bare):
            rest = bare[m.end():m.end() + 400]
            if rest.startswith("function") or re.match(r"(?:\((?:[^()]|\([^()]*\))*\)|[\w$]+)\s*(?::[^=]{1,80})?=>", rest):
                p = bare.find("(", m.end(), m.end() + 12)
                block(m.start(), m.group(1), "", params_at(p) if p >= 0 else rest.split("=>")[0])
        for m in re.finditer(r"\b(?:module\.)?exports\.([\w$]+)\s*=\s*(?:async\s*)?(?=function\b|\(|[\w$]+\s*=>)", bare):
            p = bare.find("(", m.end(), m.end() + 20)
            block(m.start(), m.group(1), "", params_at(p) if p >= 0 else "")
        for m in re.finditer(r"(?m)^[ \t]*(?:(?:public|private|protected|static|async|override|readonly)\s+)*([\w$]+)\s*\(", bare):
            if m.group(1) in _JS_KEYWORDS:
                continue
            k = _close(bare, m.end() - 1)
            if k > 0 and re.match(r"\s*(?::\s*[^{;=]{1,120})?\{", bare[k + 1:k + 140]):
                block(m.start(1), m.group(1), cls_of(m.start()), params_at(m.end() - 1))
        for m in re.finditer(r"\b([\w$]+)\s*:\s*(?:async\s*)?(?:function\b[^(]*\(|\((?=[^()]*\)\s*=>))", bare):
            block(m.start(), m.group(1), "", params_at(m.end() - 1))
    elif f.lang == "go":
        for m in re.finditer(r"(?m)^func\s+(?:\(\s*\w*\s*\*?\s*(\w+)[^)]*\)\s*)?(\w+)\s*(?:\[[^\]]*\]\s*)?\(", bare):
            block(m.start(), m.group(2), m.group(1) or "", params_at(m.end() - 1))
    elif f.lang == "php":
        classes = []
        for m in re.finditer(r"\b(?:class|trait)\s+(\w+)[^{;]*\{", bare):
            k = _close(bare, m.end() - 1)
            if k > 0:
                classes.append((m.start(), k, m.group(1)))
        for m in re.finditer(r"\bfunction\s+&?(\w+)\s*\(", bare):
            cls = next((c for a, b, c in classes if a <= m.start() <= b), "")
            block(m.start(), m.group(1), cls, params_at(m.end() - 1))
    elif f.lang == "ruby":
        cls_stack = []
        text_lines = f.code.split("\n")
        for i, line in enumerate(text_lines):
            mc = re.match(r"^(\s*)(?:class|module)\s+([\w:]+)", line)
            if mc:
                cls_stack = [c for c in cls_stack if c[0] < len(mc.group(1))] + [(len(mc.group(1)), mc.group(2))]
                continue
            md = re.match(r"^(\s*)def\s+(?:self\.)?([\w?!]+)\s*(\(([^)]*)\))?", line)
            if md:
                ind = len(md.group(1))
                cls_stack = [c for c in cls_stack if c[0] < ind]
                out.append((md.group(2), "::".join(c[1] for c in cls_stack), i + 1, _ruby_end(text_lines, i), md.group(4) or ""))
    elif f.lang in ("java", "kotlin", "csharp"):
        classes = []
        for m in re.finditer(r"\b(?:class|interface|record|object)\s+(\w+)[^{;]*\{", bare):
            k = _close(bare, m.end() - 1)
            if k > 0:
                classes.append((m.start(), k, m.group(1)))
        rx = (r"\bfun\s+(?:<[^>]+>\s*)?(?:[\w.]+\.)?(\w+)\s*\(" if f.lang == "kotlin" else
              r"(?m)^[ \t]*(?:(?:public|private|protected|internal|static|final|abstract|async|virtual|override|synchronized|"
              r"sealed|partial|default)\s+)+[\w<>\[\],.? ]+?\s+(\w+)\s*\(")
        for m in re.finditer(rx, bare):
            cands = [c for c in classes if c[0] <= m.start() <= c[1]]
            cls = max(cands, key=lambda c: c[0])[2] if cands else ""
            block(m.start(1), m.group(1), cls, params_at(m.end() - 1))
    return out


def _ruby_end(text_lines: list, i: int) -> int:
    """1-based line of the ``end`` that closes the block opened on line index ``i`` (by indentation)."""
    ind = len(text_lines[i]) - len(text_lines[i].lstrip())
    if re.search(r"\bend\s*$", text_lines[i]) and re.search(r"\b(?:def|do)\b", text_lines[i]) and ";" in text_lines[i]:
        return i + 1
    for j in range(i + 1, len(text_lines)):
        line = text_lines[j]
        if line.strip() and len(line) - len(line.lstrip()) <= ind:
            return j + 1 if re.match(r"\s*(?:end\b|\})", line) else j
    return len(text_lines)


# ================================================================================================= Python extractor
_PY_ROUTE_ATTRS = {"route", "get", "post", "put", "delete", "patch", "head", "options", "websocket", "api_route",
                   "websocket_route"}
_PY_HTTP_NAMES = ("get", "post", "put", "patch", "delete", "head", "options")
_PY_FRAMEWORKS = ("fastapi", "flask", "quart", "sanic", "bottle", "starlette", "aiohttp", "falcon")
_PY_SKIP_TYPES = {"Request", "Response", "WebSocket", "BackgroundTasks", "Session", "AsyncSession", "HTTPConnection",
                  "SecurityScopes", "HttpRequest", "HttpResponse"}
_PY_SIMPLE_TYPES = {"str", "int", "float", "bool", "bytes", "UUID", "date", "datetime", "Decimal", "Optional", "List",
                    "list", "Union", "None", "Literal", "Any", "set", "Set", "tuple", "Tuple", "EmailStr"}
_DJ_GENERIC = {
    "CreateView": ["GET", "POST"], "UpdateView": ["GET", "POST"], "FormView": ["GET", "POST"], "DeleteView": ["GET", "POST"],
    "LoginView": ["GET", "POST"], "ListView": ["GET"], "DetailView": ["GET"], "TemplateView": ["GET"], "RedirectView": ["GET"],
    "ListAPIView": ["GET"], "CreateAPIView": ["POST"], "RetrieveAPIView": ["GET"], "UpdateAPIView": ["PUT", "PATCH"],
    "DestroyAPIView": ["DELETE"], "ListCreateAPIView": ["GET", "POST"], "RetrieveUpdateAPIView": ["GET", "PUT", "PATCH"],
    "RetrieveDestroyAPIView": ["GET", "DELETE"], "RetrieveUpdateDestroyAPIView": ["GET", "PUT", "PATCH", "DELETE"],
}
_VIEWSET_ACTIONS = (("list", "GET", False), ("create", "POST", False), ("retrieve", "GET", True), ("update", "PUT", True),
                    ("partial_update", "PATCH", True), ("destroy", "DELETE", True))
_VIEWSET_BASES = {"ModelViewSet": {"list", "create", "retrieve", "update", "partial_update", "destroy"},
                  "ReadOnlyModelViewSet": {"list", "retrieve"}, "ListModelMixin": {"list"}, "CreateModelMixin": {"create"},
                  "RetrieveModelMixin": {"retrieve"}, "UpdateModelMixin": {"update", "partial_update"},
                  "DestroyModelMixin": {"destroy"}}


def _pd(node) -> str:
    """Dotted name of an expression (``a.b.c``); a call yields the name of what is called."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _pd(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _pd(node.func)
    if isinstance(node, ast.Subscript):
        return _pd(node.value)
    return ""


def _ps(node) -> str | None:
    """String value of a literal (f-strings keep their constant parts, ``{}`` for the dynamic ones)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(v.value if isinstance(v, ast.Constant) and isinstance(v.value, str) else "{}" for v in node.values)
    return None


def _pkw(call: ast.Call, *names):
    for k in call.keywords:
        if k.arg in names:
            return k.value
    return None


def _pstrs(node) -> list:
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return [s for s in (_ps(e) for e in node.elts) if s is not None]
    s = _ps(node)
    return [s] if s is not None else []


def _pspan(f: _File, node) -> tuple:
    first = min([node.lineno] + [d.lineno for d in getattr(node, "decorator_list", [])])
    return (f.rel, first, getattr(node, "end_lineno", None) or node.lineno)


def _py_perm_guard(node, kind="permission_classes"):
    """``permission_classes = [IsAuthenticated]`` / ``@permission_classes([AllowAny])``."""
    names = [_pd(e).split(".")[-1] for e in node.elts] if isinstance(node, (ast.List, ast.Tuple)) else []
    names = [n for n in names if n]
    if not names:
        return None
    if all(n == "AllowAny" for n in names):
        return ("permission_classes=[AllowAny]", kind, True)
    return ("permission_classes=[" + ", ".join(names) + "]", kind, False)


def _py_dep_guards(node) -> list:
    """Guards in a FastAPI ``dependencies=[Depends(x)]`` list or a single ``Depends(x)`` / ``Security(x)`` call."""
    out = []
    calls = node.elts if isinstance(node, (ast.List, ast.Tuple)) else [node]
    for c in calls:
        if isinstance(c, ast.Call) and _pd(c.func).split(".")[-1] in ("Depends", "Security") and c.args:
            g = _guard(_pd(c.args[0]), "dependency")
            if g:
                out.append(g)
    return out


def _py_decorator_guards(decs: list) -> list:
    out = []
    for d in decs:
        name = _pd(d)
        tail = name.split(".")[-1]
        if tail in _PY_ROUTE_ATTRS or tail in ("command", "task", "shared_task", "api_view", "action"):
            continue
        if tail == "permission_classes" and isinstance(d, ast.Call) and d.args:
            g = _py_perm_guard(d.args[0], "decorator")
            if g:
                out.append(g)
            continue
        if tail == "method_decorator" and isinstance(d, ast.Call) and d.args:
            inner = d.args[0].elts if isinstance(d.args[0], (ast.List, ast.Tuple)) else [d.args[0]]
            for x in inner:
                g = _guard(_pd(x), "decorator")
                if g:
                    out.append(g)
            continue
        if tail == "login_not_required":
            out.append((name, "decorator", True))
            continue
        if isinstance(d, ast.Call) and _is_auth_name(name) and any(
                k.arg == "optional" and isinstance(k.value, ast.Constant) and k.value.value is True for k in d.keywords):
            out.append((name + "(optional=True)", "decorator", True))      # identity is read, anonymous is accepted
            continue
        g = _guard(name, "decorator")
        if g:
            out.append(g)
    return out


class _Py:
    """Entry-point discovery for the Python files of a project (uses the real ``ast``)."""

    def __init__(self, ctx: _Ctx):
        self.ctx = ctx
        self.files = []
        self.funcs: dict = {}      # name -> [(file, node)]  (module-level functions)
        self.classes: dict = {}    # name -> [(file, node)]
        self.imports: dict = {}    # rel -> {local name: (module, original name)}
        self.tops: dict = {}       # rel -> set of top-level imported packages
        self.global_guards: list = []
        self.drf_default = None
        self.routed: set = set()   # ids of function/class nodes that got a route
        for f in ctx.lang("python"):
            try:
                f.tree = ast.parse(f.text)
            except (SyntaxError, ValueError, MemoryError, RecursionError):
                ctx.unparsed.append(f.rel)
                continue
            self.files.append(f)
            imp, tops = {}, set()
            for node in ast.walk(f.tree):
                if isinstance(node, ast.ImportFrom):
                    tops.add((node.module or "").split(".")[0])
                    for a in node.names:
                        imp[a.asname or a.name] = (("." * node.level) + (node.module or ""), a.name)
                elif isinstance(node, ast.Import):
                    for a in node.names:
                        tops.add(a.name.split(".")[0])
                        imp[a.asname or a.name.split(".")[0]] = (a.name, "")
            self.imports[f.rel], self.tops[f.rel] = imp, tops
            for st in f.tree.body:
                if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.funcs.setdefault(st.name, []).append((f, st))
                elif isinstance(st, ast.ClassDef):
                    self.classes.setdefault(st.name, []).append((f, st))
            m = re.search(r"DEFAULT_PERMISSION_CLASSES['\"]?\s*[:=]\s*[\[(]([^\])]*)", f.text)
            if m:
                names = [n.split(".")[-1] for n in re.findall(r"[\w.]+", m.group(1))]
                if names and not all(n == "AllowAny" for n in names):
                    self.drf_default = ("settings: DEFAULT_PERMISSION_CLASSES=" + ",".join(names), "config", False)
            if re.search(r"MIDDLEWARE\s*=\s*[\[(][^\])]*LoginRequiredMiddleware", f.text, re.S):
                self.global_guards.append(("settings: LoginRequiredMiddleware", "config", False))

    # ------------------------------------------------------------------ lookup
    def find(self, table: dict, expr, f: _File):
        """Resolve ``views.detail`` / ``detail`` written in file ``f`` to (file, node)."""
        dotted = _pd(expr) if not isinstance(expr, str) else expr
        if not dotted:
            return None
        parts = dotted.split(".")
        name = parts[-1]
        cands = table.get(name) or []
        if not cands:
            return None
        hint = ""
        imp = self.imports.get(f.rel, {})
        if len(parts) > 1 and parts[0] in imp:
            mod, orig = imp[parts[0]]
            hint = (mod + "." + orig if orig else mod)
            hint = ".".join([hint] + parts[1:-1])
        elif name in imp:
            hint = imp[name][0]
        hint = hint.strip(".").replace(".", "/")
        for x, node in cands:
            if x is f and len(parts) == 1 and name not in imp:
                return x, node
        if hint:
            for x, node in cands:
                stem = x.rel[:-3]
                if stem.endswith(hint) or stem.endswith(hint + "/__init__") or (posixpath.dirname(f.rel) + "/" + hint).lstrip("/") == stem:
                    return x, node
            tail = hint.split("/")[-1]
            for x, node in cands:
                if posixpath.basename(x.rel)[:-3] == tail:
                    return x, node
        d = posixpath.dirname(f.rel)
        cands = sorted(cands, key=lambda c: (0 if c[0] is f else 1 if posixpath.dirname(c[0].rel) == d else 2))
        return cands[0]

    def module_file(self, module: str, f: _File):
        rel_mod = module.lstrip(".")
        base = posixpath.dirname(f.rel) if module.startswith(".") else ""
        path = rel_mod.replace(".", "/")
        wanted = [posixpath.join(base, path + ".py"), posixpath.join(base, path, "__init__.py")] if base or module.startswith(".") \
            else [path + ".py", path + "/__init__.py"]
        for x in self.files:
            if x.rel in wanted:
                return x
        for x in self.files:                      # project root below the scan root (src/, backend/ ...)
            if x.rel.endswith("/" + path + ".py") or x.rel.endswith("/" + path + "/__init__.py"):
                return x
        return None

    def framework(self, f: _File, attr: str = "") -> str:
        tops = self.tops.get(f.rel, set())
        for name in _PY_FRAMEWORKS:
            if name in tops:
                return name
        return "flask" if attr in ("route", "") else "fastapi"

    def bases(self, cls: ast.ClassDef, f: _File, depth: int = 0) -> list:
        """Base-class simple names, following bases defined in the project."""
        out = []
        for b in cls.bases:
            name = _pd(b).split(".")[-1]
            if not name:
                continue
            out.append(name)
            hit = self.find(self.classes, b, f) if depth < 6 else None
            if hit and hit[1] is not cls:
                out.extend(self.bases(hit[1], hit[0], depth + 1))
        return out

    def class_chain(self, cls: ast.ClassDef, f: _File, depth: int = 0) -> list:
        out = [(f, cls)]
        for b in cls.bases:
            hit = self.find(self.classes, b, f) if depth < 6 else None
            if hit and hit[1] is not cls:
                out.extend(self.class_chain(hit[1], hit[0], depth + 1))
        return out

    # ------------------------------------------------------------------ run
    def run(self):
        for f in self.files:
            self.prefixes(f)
        for f in self.files:
            self.decorated(f)
            self.calls(f)
        self.django()
        for f in self.files:
            self.unrouted(f)
            self.scripts(f)

    # -- Blueprint / APIRouter prefixes and mounts
    def prefixes(self, f: _File):
        loc = self.__dict__.setdefault("local", {})        # (rel, var) -> (prefix, guards)
        mounts = self.__dict__.setdefault("mounts", [])    # (target stem or rel, var, prefix, guards, by_stem)
        hooks = self.__dict__.setdefault("hooks", {})      # (rel, receiver) -> guards from before_request
        for node in ast.walk(f.tree):
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) \
                    and isinstance(node.value, ast.Call):
                tail = _pd(node.value.func).split(".")[-1]
                if tail in ("Blueprint", "APIRouter", "Router", "Bottle"):
                    pre = _ps(_pkw(node.value, "url_prefix", "prefix")) or ""
                    deps = _pkw(node.value, "dependencies")
                    loc[(f.rel, node.targets[0].id)] = (pre, _py_dep_guards(deps) if deps is not None else [])
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                    and node.func.attr in ("register_blueprint", "include_router", "mount") and node.args:
                pre = _ps(_pkw(node, "url_prefix", "prefix")) or ""
                deps = _pkw(node, "dependencies")
                guards = _py_dep_guards(deps) if deps is not None else []
                target = node.args[0]
                if node.func.attr == "mount":
                    pre = _ps(node.args[0]) or ""
                    target = node.args[1] if len(node.args) > 1 else None
                    if target is None:
                        continue
                dotted = _pd(target)
                parts = dotted.split(".")
                imp = self.imports.get(f.rel, {})
                if len(parts) > 1:
                    mounts.append((parts[-2], parts[-1], pre, guards, True))
                elif parts[0] in imp:
                    mod, orig = imp[parts[0]]
                    mounts.append((mod.strip(".").split(".")[-1], orig or parts[0], pre, guards, True))
                elif dotted:
                    mounts.append((f.rel, dotted, pre, guards, False))
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for d in node.decorator_list:
                    name = _pd(d)
                    if name.split(".")[-1] in ("before_request", "before_app_request") and "." in name:
                        body = ast.get_source_segment(f.text, node) or ""
                        if (_is_auth_name(node.name) or _inline_guards("python", body)) \
                                and re.search(r"\babort\(|\bredirect\(|\b40[13]\b|Unauthorized|Forbidden|\braise\b", body):
                            hooks.setdefault((f.rel, name.split(".")[0]), []).append((f"before_request: {node.name}", "middleware", False))

    def mount_of(self, f: _File, var: str) -> tuple:
        pre, guards = self.local.get((f.rel, var), ("", []))
        guards = list(guards)
        stem = posixpath.basename(f.rel)[:-3]
        if stem == "__init__":
            stem = posixpath.basename(posixpath.dirname(f.rel))
        idx = self.__dict__.get("_mount_idx")
        if idx is None or self.__dict__.get("_mount_n") != len(self.mounts):
            idx = self._mount_idx = {}
            for mount in self.mounts:
                idx.setdefault(mount[1], []).append(mount)
            self._mount_n = len(self.mounts)
        for target, mvar, mpre, mguards, by_stem in idx.get(var, ()):
            if mvar == var and ((by_stem and target == stem) or (not by_stem and target == f.rel)):
                pre = _join_path(mpre, pre) if (mpre or pre) else ""
                guards += mguards
                break
        guards += self.hooks.get((f.rel, var), [])
        if var != "app":
            for (rel, recv), g in self.hooks.items():
                if recv == "app":
                    guards += g                    # app.before_request also runs for blueprint routes
        return pre, guards

    # -- decorators: Flask / FastAPI / ... routes, CLI commands, tasks, consumers
    def decorated(self, f: _File):
        def visit(body, cls):
            for node in body:
                if isinstance(node, ast.ClassDef):
                    visit(node.body, node)
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.function(f, node, cls)
                    visit(node.body, cls)
                elif isinstance(node, (ast.If, ast.Try, ast.With)):
                    visit([n for n in ast.iter_child_nodes(node) if isinstance(n, ast.stmt)], cls)
        visit(f.tree.body, None)

    def function(self, f: _File, fn, cls):
        ctx = self.ctx
        name = f"{cls.name}.{fn.name}" if cls else fn.name
        span = _pspan(f, fn)
        args = [a for a in fn.args.posonlyargs + fn.args.args + fn.args.kwonlyargs if a.arg not in ("self", "cls")]
        dec_guards = _py_decorator_guards(fn.decorator_list)
        if cls:
            dec_guards += _py_decorator_guards(cls.decorator_list)
        for d in fn.decorator_list:
            call = d if isinstance(d, ast.Call) else None
            dotted = _pd(d)
            tail = dotted.split(".")[-1]
            recv = dotted.split(".")[0] if "." in dotted else ""
            if tail in _PY_ROUTE_ATTRS and call is not None and recv and recv not in ("click", "pytest", "typer"):
                path = _ps(call.args[0]) if call.args else _ps(_pkw(call, "path", "rule", "uri"))
                if path is None:
                    continue
                fw = self.framework(f, tail)
                methods = _pstrs(_pkw(call, "methods")) if _pkw(call, "methods") is not None else \
                    (["GET"] if tail in ("route", "api_route") else ["WEBSOCKET"] if tail.startswith("websocket") else [tail])
                pre, mguards = self.mount_of(f, recv)
                full = _join_path(pre, path)
                params, guards = [], list(dec_guards)
                deps = _pkw(call, "dependencies")
                if deps is not None:
                    guards += _py_dep_guards(deps)
                if fw in ("fastapi", "starlette"):
                    p2, g2 = self.fastapi_params(fn, full)
                    params, guards = p2, guards + g2
                self.routed.add(id(fn))
                ctx.add(f, "http", methods, full, name, fn.lineno, fw, [span], params, guards + mguards + self.global_guards)
            elif tail == "command" and (call is not None or recv):
                fw = "typer" if "typer" in self.tops.get(f.rel, ()) else "click"
                cmd = (_ps(call.args[0]) if call is not None and call.args else None) or \
                    (_ps(_pkw(call, "name")) if call is not None else None) or fn.name.replace("_", "-")
                params = [Param(a.arg, "arg") for a in args]
                for d2 in fn.decorator_list:
                    if isinstance(d2, ast.Call) and _pd(d2).split(".")[-1] in ("option", "argument") and d2.args:
                        opt = (_ps(d2.args[-1] if len(d2.args) > 1 and _ps(d2.args[-1]) else d2.args[0]) or "").lstrip("-")
                        if opt and not any(p.name == opt.replace("-", "_") for p in params):
                            params.append(Param(opt, "arg"))
                self.routed.add(id(fn))
                ctx.add(f, "cli", [], cmd, name, fn.lineno, fw, [span], params, scan=False)
            elif tail in ("task", "shared_task", "periodic_task", "actor", "job", "scheduled_job", "repeat_every", "cron",
                          "interval") and (recv or tail in ("shared_task", "periodic_task", "job", "repeat_every")) \
                    and recv not in ("pytest", "click"):
                fw = "celery" if "celery" in self.tops.get(f.rel, ()) or tail in ("shared_task", "periodic_task") else \
                    "dramatiq" if tail == "actor" else "rq" if tail == "job" else "scheduler"
                self.routed.add(id(fn))
                ctx.add(f, "job", [], fn.name, name, fn.lineno, fw, [span], [Param(a.arg, "message") for a in args], scan=False)
            elif tail in ("agent", "subscriber", "on", "event", "consumer", "subscribe", "kafka_listener", "handle") \
                    and recv and recv not in {"pytest", "click", "app"} | ({"router"} if tail == "on" else set()) \
                    and (tail != "on" or re.search(r"(?i)sio|socket|bot|client|bus|emitter", recv)):
                topic = (_ps(call.args[0]) if call is not None and call.args else None) or \
                    (_pd(call.args[0]) if call is not None and call.args else "") or fn.name
                fw = "socketio" if re.search(r"(?i)sio|socket", recv) else "faust" if tail == "agent" else "messaging"
                self.routed.add(id(fn))
                ctx.add(f, "consumer", [], topic, name, fn.lineno, fw, [span], [Param(a.arg, "message") for a in args], scan=False)
        if not cls and fn.name in ("lambda_handler", "handler") and [a.arg for a in fn.args.args] == ["event", "context"] \
                and fn in f.tree.body:
            self.routed.add(id(fn))
            ctx.add(f, "consumer", [], fn.name, fn.name, fn.lineno, "aws-lambda", [span], [Param("event", "message")],
                    req_names=("event",))

    def fastapi_params(self, fn, path: str) -> tuple:
        params, guards = [], []
        path_vars = set(_path_vars(path))
        a = fn.args
        pos = a.posonlyargs + a.args
        defaults = [None] * (len(pos) - len(a.defaults)) + list(a.defaults)
        pairs = list(zip(pos, defaults)) + list(zip(a.kwonlyargs, a.kw_defaults))
        for arg, default in pairs:
            if arg.arg in ("self", "cls"):
                continue
            ann = arg.annotation
            meta = [default] if isinstance(default, ast.Call) else []
            tname = ""
            if isinstance(ann, ast.Subscript) and _pd(ann.value).split(".")[-1] == "Annotated" and isinstance(ann.slice, ast.Tuple):
                meta += [e for e in ann.slice.elts[1:] if isinstance(e, ast.Call)]
                ann = ann.slice.elts[0]
            if ann is not None:
                try:
                    tname = ast.unparse(ann)
                except Exception:      # noqa: BLE001 - odd annotation nodes: the type is only informative
                    tname = ""
            kind = None
            name = arg.arg
            for c in meta:
                tail = _pd(c.func).split(".")[-1]
                if tail in ("Depends", "Security"):
                    dep = _pd(c.args[0]) if c.args else tname
                    g = _guard(dep, "dependency")
                    if g:
                        guards.append(g)
                    kind = "skip"
                elif tail in ("Query", "Path", "Header", "Cookie", "Body", "Form", "File", "UploadFile"):
                    kind = {"Query": "query", "Path": "path", "Header": "header", "Cookie": "cookie", "Body": "body",
                            "Form": "form", "File": "file", "UploadFile": "file"}[tail]
                    alias = _ps(_pkw(c, "alias"))
                    if alias:
                        name = alias
                    elif kind == "header":
                        name = name.replace("_", "-")
            if kind == "skip":
                continue
            idents = set(re.findall(r"[A-Za-z_]\w*", tname))
            if kind is None:
                if idents & _PY_SKIP_TYPES or (not idents and arg.arg in ("request", "websocket", "ws", "response", "req",
                                                                             "background_tasks")):
                    continue
                if arg.arg in path_vars:
                    kind = "path"
                elif "UploadFile" in idents:
                    kind = "file"
                elif not idents or idents <= _PY_SIMPLE_TYPES:
                    kind = "query"
                else:
                    kind = "body"
            params.append(Param(name, kind, tname if kind == "body" else ""))
        return params, guards

    # -- imperative registration: add_url_rule, aiohttp add_get / web.get, Starlette Route, schedulers
    def calls(self, f: _File):
        ctx = self.ctx
        for node in ast.walk(f.tree):
            if not isinstance(node, ast.Call):
                continue
            dotted = _pd(node.func)
            tail = dotted.split(".")[-1]
            if tail == "add_url_rule" and node.args:
                view = _pkw(node, "view_func") or (node.args[2] if len(node.args) > 2 else None)
                path = _ps(node.args[0])
                if view is None or path is None:
                    continue
                pre, mguards = self.mount_of(f, dotted.split(".")[0])
                methods = _pstrs(_pkw(node, "methods")) if _pkw(node, "methods") is not None else None
                self.view(f, view, _join_path(pre, path), methods, "flask", node.lineno, mguards)
            elif (tail in ("add_get", "add_post", "add_put", "add_delete", "add_patch", "add_route") or
                  (tail in _PY_HTTP_NAMES and dotted.split(".")[0] == "web")) and len(node.args) >= 2 \
                    and "aiohttp" in self.tops.get(f.rel, ()):
                if tail == "add_route" and len(node.args) >= 3:
                    methods, path, view = _pstrs(node.args[0]), _ps(node.args[1]), node.args[2]
                else:
                    methods, path, view = [tail.replace("add_", "")], _ps(node.args[0]), node.args[1]
                if path is not None:
                    self.view(f, view, path, methods, "aiohttp", node.lineno, [])
            elif tail in ("Route", "WebSocketRoute") and node.args and len(node.args) + len(node.keywords) >= 2 \
                    and "starlette" in self.tops.get(f.rel, ()):
                view = node.args[1] if len(node.args) > 1 else _pkw(node, "endpoint")
                path = _ps(node.args[0])
                if view is not None and path is not None:
                    self.view(f, view, path, _pstrs(_pkw(node, "methods")) if _pkw(node, "methods") is not None else ["GET"],
                              "starlette", node.lineno, [])
            elif tail == "add_job" and node.args and isinstance(node.args[0], (ast.Name, ast.Attribute)):
                hit = self.find(self.funcs, node.args[0], f)
                if hit and id(hit[1]) not in self.routed:
                    self.routed.add(id(hit[1]))
                    ctx.add(hit[0], "job", [], hit[1].name, hit[1].name, hit[1].lineno, "apscheduler", [_pspan(*hit)], scan=False)
            elif tail == "basic_consume":
                cb = _pkw(node, "on_message_callback") or (node.args[1] if len(node.args) > 1 else None)
                hit = self.find(self.funcs, cb, f) if cb is not None else None
                if hit:
                    queue = _ps(_pkw(node, "queue") or (node.args[0] if node.args else None)) or hit[1].name
                    self.routed.add(id(hit[1]))
                    ctx.add(hit[0], "consumer", [], queue, hit[1].name, hit[1].lineno, "amqp", [_pspan(*hit)],
                            [Param("body", "message")], scan=False)

    # -- a view expression (function, Class.as_view(), wrapper(view)) -> entry point
    def view(self, f: _File, expr, path: str, methods, framework: str, line: int, extra_guards: list):
        guards = []
        for _ in range(6):                                   # unwrap login_required(view), cache_page(60)(view) ...
            if isinstance(expr, ast.Call) and not (isinstance(expr.func, ast.Attribute) and expr.func.attr == "as_view"):
                names = [_pd(expr.func)] + ([_pd(expr.func.func)] if isinstance(expr.func, ast.Call) else [])
                for n in names:
                    g = _guard(n, "wrapper")
                    if g:
                        guards.append(g)
                inner = next((a for a in expr.args if isinstance(a, (ast.Name, ast.Attribute, ast.Call))), None)
                if inner is None:
                    break
                expr = inner
            else:
                break
        ctx = self.ctx
        if isinstance(expr, ast.Call):                        # Class.as_view()
            hit = self.find(self.classes, expr.func.value, f)
            if not hit:
                ctx.add(f, "http", methods, path, _pd(expr.func.value), line, framework, [], guards=guards + extra_guards + self.global_guards)
                return
            self.class_view(hit[0], hit[1], path, methods, framework, guards + extra_guards)
            return
        hit = self.find(self.funcs, expr, f)
        if hit:
            xf, fn = hit
            self.routed.add(id(fn))
            m2 = methods
            g2 = _py_decorator_guards(fn.decorator_list)
            drf = False
            for d in fn.decorator_list:
                tail = _pd(d).split(".")[-1]
                if tail in ("api_view", "require_http_methods") and isinstance(d, ast.Call) and d.args:
                    m2 = m2 or _pstrs(d.args[0])
                    drf = drf or tail == "api_view"
                elif tail in ("require_GET", "require_safe"):
                    m2 = m2 or ["GET"]
                elif tail == "require_POST":
                    m2 = m2 or ["POST"]
            if drf and self.drf_default:
                g2.append(self.drf_default)
            ctx.add(xf, "http", m2, path, fn.name, fn.lineno, framework, [_pspan(xf, fn)],
                    guards=g2 + guards + extra_guards + self.global_guards)
            return
        hit = self.find(self.classes, expr, f)
        if hit:
            self.class_view(hit[0], hit[1], path, methods, framework, guards + extra_guards)
            return
        ctx.add(f, "http", methods, path, _pd(expr) or "?", line, framework, [], guards=guards + extra_guards + self.global_guards)

    def class_guards(self, f: _File, cls: ast.ClassDef) -> tuple:
        guards, drf = [], False
        for xf, c in self.class_chain(cls, f):
            guards += _py_decorator_guards(c.decorator_list)
            for st in c.body:
                if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name):
                    if st.targets[0].id == "permission_classes":
                        g = _py_perm_guard(st.value)
                        if g:
                            guards.append(g)
                    elif st.targets[0].id == "decorators":
                        for e in getattr(st.value, "elts", []):
                            g = _guard(_pd(e), "decorator")
                            if g:
                                guards.append(g)
                elif isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)) and st.name == "dispatch":
                    guards += _py_decorator_guards(st.decorator_list)
        for b in self.bases(cls, f):
            if re.search(r"APIView|ViewSet|GenericAPIView|ModelMixin$", b):
                drf = True
            if b.endswith("Mixin") or b in ("LoginRequiredMixin",):
                g = _guard(b, "mixin")
                if g:
                    guards.append(g)
        if drf and self.drf_default and not any(g[0].startswith("permission_classes") for g in guards):
            guards.append(self.drf_default)
        return guards, drf

    def class_view(self, f: _File, cls: ast.ClassDef, path: str, methods, framework: str, extra_guards: list):
        self.routed.add(id(cls))
        guards, drf = self.class_guards(f, cls)
        chain = self.class_chain(cls, f)
        defined = [(xf, st) for xf, c in chain for st in c.body
                   if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)) and st.name in _PY_HTTP_NAMES]
        if not methods:
            methods = [st.name for _, st in defined]
            if not methods:
                for b in self.bases(cls, f):
                    if b in _DJ_GENERIC:
                        methods = _DJ_GENERIC[b]
                        break
        for _, st in defined:
            guards += _py_decorator_guards(st.decorator_list)
        spans = [_pspan(f, cls)] + [_pspan(xf, c) for xf, c in chain[1:]]
        self.ctx.add(f, "http", methods, path, cls.name, cls.lineno, "drf" if drf else framework, spans,
                     guards=guards + extra_guards + self.global_guards)

    def viewset(self, f: _File, cls: ast.ClassDef, prefix: str, base: str):
        self.routed.add(id(cls))
        guards, _ = self.class_guards(f, cls)
        chain = self.class_chain(cls, f)
        methods = {st.name: (xf, st) for xf, c in reversed(chain) for st in c.body
                   if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef))}
        implied = set()
        for b in self.bases(cls, f):
            implied |= _VIEWSET_BASES.get(b, set())
        helper_spans = [_pspan(xf, st) for n, (xf, st) in methods.items()
                        if n in ("get_queryset", "get_object", "perform_create", "perform_update", "perform_destroy",
                                 "filter_queryset", "get_serializer_class")]
        coll, detail = _join_path(base, prefix) + "/", _join_path(base, prefix, "{pk}") + "/"
        for action, verb, is_detail in _VIEWSET_ACTIONS:
            if action in methods or action in implied:
                xf, st = methods.get(action, (f, cls))
                span = _pspan(xf, st) if action in methods else (f.rel, cls.lineno, cls.lineno)
                self.ctx.add(f, "http", [verb], detail if is_detail else coll, f"{cls.name}.{action}", st.lineno, "drf",
                             [span] + helper_spans, guards=list(guards) + self.global_guards)
        for n, (xf, st) in methods.items():
            for d in st.decorator_list:
                if isinstance(d, ast.Call) and _pd(d).split(".")[-1] == "action":
                    det = _pkw(d, "detail")
                    is_detail = isinstance(det, ast.Constant) and det.value is True
                    url = _ps(_pkw(d, "url_path")) or n
                    verbs = _pstrs(_pkw(d, "methods")) if _pkw(d, "methods") is not None else ["GET"]
                    own = []
                    pc = _pkw(d, "permission_classes")
                    if pc is not None:
                        g = _py_perm_guard(pc)
                        own = [g] if g else []
                    self.ctx.add(xf, "http", verbs, (detail if is_detail else coll) + url + "/", f"{cls.name}.{n}", st.lineno,
                                 "drf", [_pspan(xf, st)], guards=own + _py_decorator_guards(st.decorator_list) + list(guards) + self.global_guards)

    # -- Django URL configuration
    def django(self):
        urlfiles = {}
        for f in self.files:
            pats, routers = [], {}
            for node in ast.walk(f.tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "register" \
                        and len(node.args) >= 2 and _ps(node.args[0]) is not None and isinstance(node.func.value, ast.Name):
                    routers.setdefault(node.func.value.id, []).append((_ps(node.args[0]), node.args[1]))
            for st in f.tree.body:
                target = st.targets[0] if isinstance(st, ast.Assign) and len(st.targets) == 1 else \
                    st.target if isinstance(st, (ast.AugAssign, ast.AnnAssign)) else None
                if isinstance(target, ast.Name) and target.id == "urlpatterns" and getattr(st, "value", None) is not None:
                    pats.extend(self.url_items(st.value))
            if pats:
                urlfiles[f.rel] = (f, pats, routers)
        included = set()
        resolved: dict = {}
        for rel, (f, pats, routers) in urlfiles.items():
            for kind, _route, target in pats:
                if kind == "include" and isinstance(target, str):
                    x = self.module_file(target, f)
                    resolved[(rel, target)] = x.rel if x else None
                    if x:
                        included.add(x.rel)

        def walk(rel, prefix, guards, stack):
            f, pats, routers = urlfiles[rel]
            for kind, route, target in pats:
                full = _join_path(prefix, route) if (prefix or route) else "/"
                if route.endswith("/") and not full.endswith("/"):
                    full += "/"
                if kind == "include":
                    if isinstance(target, str):
                        nxt = resolved.get((rel, target))
                        if nxt and nxt in urlfiles and nxt not in stack:
                            walk(nxt, full, guards, stack + [nxt])
                    else:                                      # include(router.urls) / *router.urls
                        for rprefix, vs in routers.get(target[1], []):
                            hit = self.find(self.classes, vs, f)
                            if hit:
                                self.viewset(hit[0], hit[1], rprefix, full)
                elif kind == "view":
                    self.view(f, target[0], full, None, "django", target[1], guards)

        for rel in urlfiles:
            if rel not in included:
                walk(rel, "", [], [rel])

    def url_items(self, value) -> list:
        """[(kind, route, target)] with kind ``view`` (target = (expr, line)), ``include`` (module name or
        ("router", var))."""
        out = []
        elts = value.elts if isinstance(value, (ast.List, ast.Tuple)) else [value]
        for e in elts:
            if isinstance(e, ast.Starred):
                e = e.value
            if isinstance(e, ast.BinOp):
                out.extend(self.url_items(e.left) + self.url_items(e.right))
                continue
            if isinstance(e, ast.Attribute) and e.attr == "urls" and isinstance(e.value, ast.Name):
                out.append(("include", "", ("router", e.value.id)))
                continue
            if not isinstance(e, ast.Call):
                continue
            tail = _pd(e.func).split(".")[-1]
            if tail not in ("path", "re_path", "url") or len(e.args) < 2:
                continue
            route = _ps(e.args[0]) or ""
            if tail != "path":
                route = re.sub(r"^\^|\$$", "", route)
            view = e.args[1]
            if isinstance(view, ast.Call) and _pd(view.func).split(".")[-1] == "include" and view.args:
                inc = view.args[0]
                if isinstance(inc, ast.Tuple) and inc.elts:
                    inc = inc.elts[0]
                if _ps(inc) is not None:
                    out.append(("include", route, _ps(inc)))
                elif isinstance(inc, ast.Attribute) and inc.attr == "urls" and isinstance(inc.value, ast.Name):
                    out.append(("include", route, ("router", inc.value.id)))
                continue
            out.append(("view", route, (view, e.lineno)))
        return out

    # -- DRF views that no URL configuration references (still worth a look), argparse / sys.argv scripts
    def unrouted(self, f: _File):
        for st in f.tree.body:
            if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)) and id(st) not in self.routed:
                for d in st.decorator_list:
                    if _pd(d).split(".")[-1] == "api_view":
                        guards = _py_decorator_guards(st.decorator_list) + ([self.drf_default] if self.drf_default else [])
                        self.ctx.add(f, "http", _pstrs(d.args[0]) if isinstance(d, ast.Call) and d.args else ["GET"],
                                     "(unrouted) " + st.name, st.name, st.lineno, "drf", [_pspan(f, st)], guards=guards)

    def scripts(self, f: _File):
        has_main = bool(re.search(r"(?m)^if\s+__name__\s*==\s*['\"]__main__['\"]", f.text))
        parser_fn, params = None, []
        seen_parser = False
        parents = {}
        for node in ast.walk(f.tree):
            for ch in ast.iter_child_nodes(node):
                parents[id(ch)] = node
        for node in ast.walk(f.tree):
            if isinstance(node, ast.Call):
                tail = _pd(node.func).split(".")[-1]
                if tail == "ArgumentParser":
                    seen_parser = True
                    p = parents.get(id(node))
                    while p is not None and not isinstance(p, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        p = parents.get(id(p))
                    parser_fn = p
                elif tail == "add_argument" and node.args and _ps(node.args[0]):
                    name = _ps(node.args[-1] if _ps(node.args[-1]) else node.args[0]).lstrip("-")
                    if name and not any(p.name == name for p in params):
                        params.append(Param(name, "arg"))
        if seen_parser:
            spans = [_pspan(f, parser_fn)] if parser_fn is not None else []
            main = next((n for x, n in self.funcs.get("main", []) if x is f), None)
            if main is not None and main is not parser_fn:
                spans.append(_pspan(f, main))
            self.ctx.add(f, "cli", [], posixpath.basename(f.rel), parser_fn.name if parser_fn is not None else "<module>",
                         parser_fn.lineno if parser_fn is not None else 1, "argparse", spans, params,
                         module_level=has_main or parser_fn is None, scan=False)
        elif has_main and re.search(r"\bsys\.argv\b", f.text) and not any(e.file == f.rel and e.kind == "cli" for e in self.ctx.entries):
            self.ctx.add(f, "cli", [], posixpath.basename(f.rel), "<module>", 1, "script", [], [Param("argv", "arg")],
                         module_level=True, scan=False)


# ============================================================================== shared helpers for the textual extractors
_TEST_PATH_RE = re.compile(r"(?i)(^|/)(tests?|__tests__|specs?|testdata|mocks?|node_modules|e2e|cypress)(/|$)|"
                           r"[._](test|spec)\.\w+$|(^|/)test_[^/]*\.py$|_test\.go$|(^|/)conftest\.py$")
_FUNC_EXPR = re.compile(r"(?:async\s+)?(?:function\b|\((?:[^()]|\([^()]*\))*\)\s*(?::[^=>]{1,80})?=>|[\w$]+\s*=>|func\s*\(|"
                        r"(?:static\s+)?fn\s*\(|static\s+function\b|delegate\b)")
_TYPE_KW = re.compile(r"\b(class|interface|record|object|enum|struct|trait|namespace)\b")


def _call_args(f: _File, open_idx: int) -> tuple:
    """Top-level argument pieces [(start, end)] of the call whose ``(`` is at ``open_idx`` and the offset of ``)``."""
    k = _close(f.bare, open_idx)
    if k < 0:
        return [], -1
    return _split_top(f.bare, open_idx + 1, k), k


def _lit(f: _File, s: int, e: int) -> str | None:
    """The value of the piece when it is a single string literal."""
    m = _STR_RE.fullmatch(f.code[s:e].strip())
    return m.group(2) if m else None


def _strip_parens(text: str) -> str:
    prev = None
    while prev != text:
        prev = text
        text = re.sub(r"\([^()]*\)", "", text)
    return text


def _handler(ctx: _Ctx, f: _File, s: int, e: int, group: tuple, hint: str | None = None, cls: str | None = None) -> dict:
    """Resolve a handler argument (inline function, identifier, ``pkg.Func``, ``wrap(handler)``) to
    ``{"name", "spans", "params", "line", "wrappers"}``."""
    raw = f.bare[s:e]
    off = s + (len(raw) - len(raw.lstrip()))
    ts = raw.strip()
    line = f.lines.of(off)
    wrappers = []
    toff = off                         # offset of `ts` in the file: brackets are matched with the file's table
    for _ in range(4):
        if _FUNC_EXPR.match(ts):
            m = re.match(r"(?:async\s+)?(?:function\s*[\w$]*\s*|func\s*|(?:static\s+)?fn\s*|static\s+function\s*)?\(", ts)
            params = ""
            if m:
                k = _close(f.bare, toff + m.end() - 1) - toff
                k = k if 0 < k < len(ts) else -1
                params = f.code[off + m.end():off + k] if k > 0 and not wrappers else (ts[m.end():k] if k > 0 else "")
            else:
                params = ts.split("=>")[0]
            return {"name": "<anonymous>", "spans": [(f.rel, line, f.lines.of(max(e - 1, s)))], "params": params, "line": line,
                    "wrappers": wrappers, "file": f}
        m = re.match(r"(?:new\s+)?([\w$.:\\]+)\s*\(", ts)
        if m and ts.endswith(")"):
            inner = [(a - toff, b - toff) for a, b in _split_top(f.bare, toff + m.end(), toff + len(ts) - 1)]
            if not inner:
                wrappers.append(m.group(1))          # factory call: handlers.List() -> look the factory up
                ts = m.group(1)
                break
            wrappers.append(m.group(1))
            pick = next((p for p in inner if _FUNC_EXPR.match(ts[p[0]:p[1]].strip())), None) or \
                next((p for p in reversed(inner) if re.match(r"\s*[A-Za-z_$][\w$.]*\s*(\(|$)", ts[p[0]:p[1]])), inner[-1])
            piece = ts[pick[0]:pick[1]]
            toff += pick[0] + (len(piece) - len(piece.lstrip()))
            ts = piece.strip()
            continue
        break
    m = re.match(r"&?\*?([A-Za-z_$][\w$.]*)", ts)
    name = m.group(1) if m else ts[:60]
    parts = name.split(".")
    hit = None
    if m:
        hit = ctx.find_def(parts[-1], group, prefer=f, cls=cls, hint=hint if hint else (parts[-2] if len(parts) > 1 else None))
    if hit:
        xf, d = hit
        return {"name": name, "spans": [(xf.rel, d[2], d[3])], "params": d[4], "line": line, "wrappers": wrappers, "file": xf}
    return {"name": name, "spans": [], "params": "", "line": line, "wrappers": wrappers, "file": f}


def _guards_from(names, kind: str) -> list:
    out = []
    for n in names:
        g = _guard(n, kind) if n else None
        if g:
            out.append(g)
    return out


def _members(f: _File, style: str, start: int = 0, end: int | None = None, cls: dict | None = None, out: list | None = None,
             depth: int = 0) -> list:
    """Annotated declarations of a brace language, in source order. ``style`` is the annotation syntax: ``@`` (Java,
    Kotlin, TypeScript decorators), ``[`` (C# attributes) or ``#[`` (PHP attributes). Each item is a dict:
    ``kind`` (class | member), ``name``, ``annos`` [(name, args text, offset)], ``header`` (text up to the body),
    ``pos`` / ``end`` (offsets), ``params`` ((open, close) offsets of the parameter list or None) and ``cls`` (the
    enclosing class item)."""
    bare = f.bare
    end = len(bare) if end is None else end
    out = [] if out is None else out
    kotlin = f.lang == "kotlin"
    anno_rx = re.compile(r"@([\w.$]+)")
    p, annos = start, []
    while p < end and depth < 8:
        ch = bare[p]
        if ch.isspace():
            p += 1
            continue
        if style == "@" and ch == "@":
            m = anno_rx.match(bare, p)
            if m:
                q, args = m.end(), ""
                r = q
                while r < end and bare[r] in " \t":
                    r += 1
                if r < end and bare[r] == "(":
                    k = _close(bare, r)
                    if k < 0:
                        break
                    args, q = f.code[r + 1:k], k + 1
                if m.group(1) != "interface":
                    annos.append((m.group(1).split(".")[-1], args, p))
                    p = q
                    continue
        if style in ("[", "#[") and bare.startswith(style, p):
            o = p + len(style) - 1
            k = _close(bare, o)
            if k < 0:
                break
            for s, e in _split_top(bare, o + 1, k):
                m = re.match(r"(?:\w+\s*:\s*)?([\w.\\]+)\s*(?:\((.*)\))?\s*$", f.code[s:e].strip(), re.S)
                if m:
                    annos.append((re.split(r"[.\\]", m.group(1))[-1], m.group(2) or "", s))
            p = k + 1
            continue
        h0, q, blk, params = p, p, None, None
        while q < end:
            c = bare[q]
            if c in "([":
                k = _close(bare, q)
                if k < 0:
                    q = end
                    break
                if c == "(" and params is None:
                    params = (q, k)
                q = k + 1
                continue
            if c == "{":
                k = _close(bare, q)
                blk = (q, k if k > 0 else end)
                break
            if c in ";}":
                break
            if kotlin and c == "\n" and bare[h0:q].strip() and bare[h0:q].rstrip()[-1] not in ",=:(<+&|" \
                    and not re.match(r"\s*(?:[{.:=?]|where\b|by\b)", bare[q:q + 80]):
                break
            q += 1
        header = f.code[h0:q]
        flat = _strip_parens(bare[h0:q])
        tm = _TYPE_KW.search(flat)
        item = {"kind": "member", "name": "", "annos": annos, "header": header, "pos": h0, "end": blk[1] if blk else q,
                "params": params, "cls": cls, "block": blk}
        annos = []
        if tm and blk and not re.search(r"\bnew\b|=", flat[:tm.start()]):
            nm = re.search(r"\b(?:class|interface|record|object|struct|trait|enum)\s+([\w$]+)", flat)
            if tm.group(1) == "namespace" or not nm:
                _members(f, style, blk[0] + 1, blk[1], cls, out, depth + 1)
            else:
                item["kind"], item["name"] = "class", nm.group(1)
                out.append(item)
                _members(f, style, blk[0] + 1, blk[1], item, out, depth + 1)
        elif header.strip():
            if params:
                nm = re.search(r"([\w$]+)\s*(?:<[^<>()]*>\s*)?$", bare[h0:params[0]])
                item["name"] = nm.group(1) if nm else ""
            out.append(item)
        p = (blk[1] + 1) if blk else q + 1
    return out


def _anno(annos: list, *names) -> tuple | None:
    for a in annos:
        if a[0] in names:
            return a
    return None


def _anno_path(args: str, keys=("value", "path")) -> str:
    """The route string of an annotation: the positional literal or ``value = "..."`` / ``path = {"..."}``."""
    for k in keys:
        m = re.search(r"\b" + k + r"\s*[=:]\s*[\[{(]?\s*(['\"])(.*?)\1", args)
        if m:
            return m.group(2)
    m = re.match(r"\s*[\[{(]?\s*(?:arrayOf\(\s*)?(['\"])(.*?)\1", args)
    return m.group(2) if m else ""


def _anno_paths(args: str, keys=("value", "path")) -> list:
    """Every route string of a mapping annotation: ``@GetMapping({"/a", "/b"})`` and ``path = ["/a", "/b"]`` declare
    one route per string (``[""]`` when the annotation carries no path)."""
    rest = None
    for k in keys:
        m = re.search(r"\b" + k + r"\s*[=:]\s*", args)
        if m:
            rest = args[m.end():]
            break
    if rest is None:
        rest = args.lstrip()
        if not re.match(r"[\[{]|arrayOf\(|['\"]", rest):
            return [""]
    rest = rest.lstrip()
    am = re.match(r"(?:arrayOf\s*)?[\[{(]", rest)
    if am:
        k = _close(rest, am.end() - 1)
        return _all_strs(rest[am.end():k if k > 0 else len(rest)])[:32] or [""]
    one = _STR_RE.match(rest)
    return [one.group(2)] if one else [""]


def _span_of(f: _File, item: dict) -> tuple:
    first = min([item["pos"]] + [a[2] for a in item["annos"]])
    return (f.rel, f.lines.of(first), f.lines.of(item["end"]))


def _decl_params(f: _File, span: tuple | None, lang: str) -> list:
    """Declared parameters of a method: [(annotations [(name, args)], type text, name)]."""
    if not span:
        return []
    out = []
    for s, e in _split_top(f.bare, span[0] + 1, span[1]):
        piece = f.code[s:e]
        annos = []
        if lang in ("csharp", "php"):
            for m in re.finditer(r"#?\[\s*([\w.\\]+)\s*(?:\(((?:[^()]|\([^()]*\))*)\))?[^\]]*\]", piece):
                annos.append((re.split(r"[.\\]", m.group(1))[-1], m.group(2) or ""))
            piece = re.sub(r"#?\[[^\]]*\]", " ", piece)
        else:
            for m in re.finditer(r"@([\w.]+)\s*(?:\(((?:[^()]|\([^()]*\))*)\))?", piece):
                annos.append((m.group(1).split(".")[-1], m.group(2) or ""))
            piece = re.sub(r"@[\w.]+\s*(?:\((?:[^()]|\([^()]*\))*\))?", " ", piece)
        piece = re.split(r"(?<![=!<>])=(?!=|>)", piece)[0].strip()
        if not piece:
            continue
        if lang in ("kotlin", "javascript"):
            m = re.match(r"(?:(?:public|private|protected|readonly|vararg|val|var)\s+)*([\w$]+)\??\s*(?::\s*(.+))?$", piece, re.S)
            name, typ = (m.group(1), (m.group(2) or "").strip()) if m else (piece, "")
        else:
            m = re.search(r"(\$?[\w]+)\s*$", piece)
            name = m.group(1).lstrip("$") if m else piece
            typ = piece[:m.start()].strip() if m else ""
            typ = re.sub(r"\b(final|this|params|ref|out|in)\b", "", typ).strip()
        out.append((annos, typ, name))
    return out


# ======================================================================================= JavaScript / TypeScript extractor
_JS_VERBS = ("get", "post", "put", "delete", "patch", "all", "head", "options", "del")
_JS_DENY = re.compile(r"(?i)^(axios|https?|got|request|superagent|\w*client|\$|jquery|agent|supertest|fetch|map|cache|store|"
                      r"params|headers|query|cookies|session|config|localstorage|formdata|searchparams|url|res|response|req|"
                      r"ctx|instance|redis|db|knex|storage|i18n|_|lodash|chai|nock|page|cy|browser|\$http|http\w+)$")
_JS_ROUTE_RE = re.compile(r"(?:\b([\w$.]+)|\))\s*\.\s*(get|post|put|delete|patch|all|head|options|del|use|register|route)\s*\(")
_NEST_HTTP = {"Get": "GET", "Post": "POST", "Put": "PUT", "Delete": "DELETE", "Patch": "PATCH", "All": "ANY", "Head": "HEAD",
              "Options": "OPTIONS"}
_NEST_PARAM = {"Param": "path", "Query": "query", "Body": "body", "Headers": "header", "UploadedFile": "file",
               "UploadedFiles": "file", "Payload": "message", "MessageBody": "message"}
_JS_EXTS = (".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", ".mts", ".cts")


class _Js:
    """Express / Koa / Fastify (and look-alikes), NestJS controllers, Next.js API routes."""

    def __init__(self, ctx: _Ctx):
        self.ctx = ctx
        self.files = ctx.lang("javascript")
        self.imports: dict = {}        # rel -> {local name: resolved rel or module spec}
        self.local_prefix: dict = {}   # (rel, var) -> prefix (koa `new Router({prefix})`)
        self.routers: dict = {}        # rel -> set of router variables
        self.var_mounts: dict = {}     # (rel, var) -> (parent receiver, prefix, guards, offset)
        self.file_mounts: dict = {}    # target rel -> (rel, parent receiver, prefix, guards, offset)
        self.uses: dict = {}           # (rel, receiver) -> [(offset, prefix, guards)]
        self.routes: list = []
        self.fw: dict = {}
        self.default_fw = "express"

    # ------------------------------------------------------------------ helpers
    def resolve(self, f: _File, spec: str):
        if spec.startswith("."):
            base = posixpath.normpath(posixpath.join(posixpath.dirname(f.rel), spec))
            for cand in [base] + [base + x for x in _JS_EXTS] + [base + "/index" + x for x in _JS_EXTS]:
                if cand in self.ctx.files:
                    return cand
        elif spec.startswith(("@/", "~/", "src/")):
            tail = spec.split("/", 1)[1]
            for rel in self.ctx.files:
                if any(rel.endswith(tail + x) or rel.endswith(tail + "/index" + x) for x in _JS_EXTS):
                    return rel
        return None

    def scan_imports(self, f: _File):
        imp = {}
        code = f.code
        for m in re.finditer(r"\b(?:const|let|var)\s+(\{[^}]*\}|[\w$]+)\s*=\s*require\(\s*['\"]([^'\"]+)['\"]\s*\)", code):
            self._bind(imp, f, m.group(1), m.group(2))
        for m in re.finditer(r"\bimport\s+(?:type\s+)?([\w$]+)?\s*,?\s*(\{[^}]*\}|\*\s+as\s+[\w$]+)?\s*from\s*['\"]([^'\"]+)['\"]", code):
            for part in (m.group(1), m.group(2)):
                if part:
                    self._bind(imp, f, part, m.group(3))
        self.imports[f.rel] = imp
        specs = " ".join(v[1] for v in imp.values()) + " " + " ".join(re.findall(r"require\(\s*['\"]([^'\"]+)", code))
        for name in ("fastify", "koa", "express", "hono", "restify", "@hapi/hapi", "polka"):
            if re.search(r"(^|[\s/@])" + re.escape(name) + r"($|[\s/-])", specs):
                self.fw[f.rel] = name.replace("@hapi/", "")
                break
        routers = set()
        for m in re.finditer(r"\b(?:const|let|var)\s+([\w$]+)\s*(?::[^=]+)?=\s*(?:await\s+)?(?:new\s+)?([\w$.]*)\s*\(", f.bare):
            callee = m.group(2)
            if re.search(r"(?:^|\.)(Router|express|fastify|Fastify|Koa|Hono|createServer|restify)$", callee) or callee in ("polka",):
                routers.add(m.group(1))
                if callee.endswith("Router"):
                    args, _k = _call_args(f, m.end() - 1)
                    if args:
                        pm = re.search(r"\bprefix\s*:\s*(['\"`])(.*?)\1", f.code[args[0][0]:args[0][1]])
                        if pm:
                            self.local_prefix[(f.rel, m.group(1))] = pm.group(2)
        self.routers[f.rel] = routers

    def _bind(self, imp: dict, f: _File, names: str, spec: str):
        target = self.resolve(f, spec)
        names = names.strip()
        if names.startswith("{"):
            for piece in names.strip("{}").split(","):
                nm = re.split(r"\s+as\s+|\s*:\s*", piece.strip())[-1].strip()
                if nm:
                    imp[nm] = (target, spec)
        else:
            imp[names.split()[-1]] = (target, spec)

    # ------------------------------------------------------------------ run
    def run(self):
        for f in self.files:
            self.scan_imports(f)
        counts: dict = {}
        for v in self.fw.values():
            counts[v] = counts.get(v, 0) + 1
        if counts:
            self.default_fw = max(counts.items(), key=lambda kv: kv[1])[0]
        for f in self.files:
            self.collect(f)
        for r in self.routes:
            self.emit(*r)
        for f in self.files:
            if "@Controller" in f.text or "@Resolver" in f.text or "@WebSocketGateway" in f.text or "@Injectable" in f.text:
                self.nest(f)
            self.next(f)

    def mw_guards(self, f: _File, pieces: list) -> list:
        out = []
        for s, e in pieces:
            text = f.code[s:e].strip()
            if text.startswith("{"):
                for m in re.finditer(r"\b(?:preHandler|onRequest|preValidation|preParsing|beforeHandler)\s*:\s*(\[[^\]]*\]|[^,}\n]+)", text):
                    out += _guards_from(re.findall(r"[A-Za-z_$][\w$.]*(?:\([^)]*\))?", m.group(1)), "hook")
                if re.search(r"\bconfig\s*:\s*\{[^}]*\b(?:public|auth)\s*:\s*(true|false)", text):
                    pub = re.search(r"\bpublic\s*:\s*true|\bauth\s*:\s*false", text)
                    out.append(("route config", "config", bool(pub)))
                continue
            names = [text] if not text.startswith("[") else [x.strip() for x in text.strip("[]").split(",")]
            out += _guards_from([re.sub(r"\s+", " ", n)[:80] for n in names if n and not _FUNC_EXPR.match(n)], "middleware")
            if _FUNC_EXPR.match(text):
                out += _inline_guards("javascript", text)[:1]
        return out

    def collect(self, f: _File):
        bare = f.bare
        fw = self.fw.get(f.rel, self.default_fw)
        routers = self.routers.get(f.rel, set())
        imp = self.imports.get(f.rel, {})
        chain_path = {}                       # offset of `)` closing X.route('/p') -> (receiver, path)
        for m in _JS_ROUTE_RE.finditer(bare):
            recv, verb = m.group(1), m.group(2)
            open_idx = m.end() - 1
            args, close = _call_args(f, open_idx)
            if close < 0:
                continue
            if recv is None:                  # ).get(...) : continuation of X.route('/p') or of a previous chained verb
                prev = bare.rfind(")", 0, m.start() + 1)
                hit = chain_path.get(prev)
                if not hit or verb not in _JS_VERBS or not args:
                    continue
                recv, path = hit
                chain_path[close] = hit
                self.routes.append((f, recv, verb, path, args[-1], args[:-1], m.start(), fw))
                continue
            tail = recv.split(".")[-1]
            if _JS_DENY.match(tail) or _JS_DENY.match(recv) or recv.startswith(("res.", "req.", "ctx.", "window.", "document.")):
                continue
            if verb in ("use", "register"):
                if not args:
                    continue
                prefix = _lit(f, *args[0]) if verb == "use" else None
                rest = args[1:] if prefix is not None else args
                if verb == "register":
                    for s, e in args[1:]:
                        pm = re.search(r"\bprefix\s*:\s*(['\"`])(.*?)\1", f.code[s:e])
                        if pm:
                            prefix = pm.group(2)
                    rest = args[:1]
                guards, targets = [], []
                for s, e in rest:
                    text = f.code[s:e].strip()
                    rq = re.match(r"require\(\s*['\"]([^'\"]+)['\"]\s*\)", text)
                    name = re.match(r"[\w$]+", text)
                    if rq:
                        t = self.resolve(f, rq.group(1))
                        if t:
                            targets.append(("file", t))
                    elif name and name.group(0) == text and text in routers:
                        targets.append(("var", text))
                    elif name and name.group(0) == text and text in imp and imp[text][0] and not _guard(text, "middleware"):
                        targets.append(("file", imp[text][0]))
                    elif name and name.group(0) == text and verb == "register" and self.ctx.find_def(text, ("javascript",), prefer=f):
                        targets.append(("func", text))
                    else:
                        guards += self.mw_guards(f, [(s, e)])
                for kind, t in targets:
                    if kind == "var":
                        self.var_mounts[(f.rel, t)] = (recv, prefix or "", guards, m.start())
                    elif kind == "file":
                        self.file_mounts.setdefault(t, (f.rel, recv, prefix or "", guards, m.start()))
                    else:
                        self.var_mounts[(f.rel, "fn:" + t)] = (recv, prefix or "", guards, m.start())
                if not targets and guards:
                    self.uses.setdefault((f.rel, recv), []).append((m.start(), prefix or "", guards))
                continue
            if verb == "route":
                if not args:
                    continue
                path = _lit(f, *args[0])
                if path is not None:
                    chain_path[close] = (recv, path)
                    continue
                text = f.code[args[0][0]:args[0][1]]
                if text.lstrip().startswith("{"):       # fastify.route({method, url, handler})
                    um = re.search(r"\b(?:url|path)\s*:\s*(['\"`])(.*?)\1", text)
                    mm = re.search(r"\bmethod\s*:\s*(\[[^\]]*\]|['\"`]\w+['\"`])", text)
                    hm = re.search(r"\bhandler\s*(?::|\()", f.bare[args[0][0]:args[0][1]])
                    if um:
                        methods = re.findall(r"\w+", mm.group(1)) if mm else ["ANY"]
                        hs = args[0][0] + (hm.end() if hm else 0)
                        he = args[0][1]
                        if hm:
                            inner = _split_top(bare, hs, _close(bare, args[0][0]) if _close(bare, args[0][0]) > 0 else he)
                            he = inner[0][1] if inner else he
                            if bare[hm.end() + args[0][0] - 1] == "(":
                                hs, he = args[0][0] + hm.start(), args[0][1] - 1
                        for mt in methods:
                            self.routes.append((f, recv, mt.lower(), um.group(2), (hs, he), [args[0]], m.start(), fw))
                continue
            if len(args) < 2:
                continue
            path = _lit(f, *args[0])
            if path is None:
                arr = f.code[args[0][0]:args[0][1]].strip()
                if arr.startswith("["):
                    path = _first_str(arr)
                elif re.match(r"/\^?\\?/", arr):
                    path = "/" + re.sub(r"^/\^?\\?/|/[a-z]*$|\\", "", arr)
            if path is None or not (path.startswith(("/", "*", ":")) or path == ""):
                continue
            last = f.code[args[-1][0]:args[-1][1]].strip()
            if last.startswith(("{", "'", '"', "`")) or re.match(r"[\d\[]", last) or last in ("true", "false", "null", "undefined"):
                continue
            if not (tail in routers or recv in routers or re.search(r"(?i)(app|router|routes?|server|api|fastify|srv|web|v\d+)$", tail)):
                continue
            self.routes.append((f, recv, verb, path, args[-1], args[1:-1], m.start(), fw))

    @staticmethod
    def under(prefix: str, path: str) -> bool:
        """Does ``app.use(prefix, middleware)`` apply to a route at ``path`` (both relative to the same router)?"""
        stem = re.split(r"[:*(?+\[{]", prefix or "")[0]
        if stem != (prefix or ""):
            stem = stem[:stem.rfind("/") + 1]              # a pattern: compare the literal directories before it
        stem = stem.rstrip("/").lower()
        path = _join_path(path or "/").lower()
        return not stem or path == stem or path.startswith(stem + "/")

    def chain(self, rel: str, recv: str, pos: int, depth: int = 0, path: str = "") -> tuple:
        """(prefix parts, guards) contributed by the mounts above ``recv`` in file ``rel``. ``path`` is the route
        path relative to ``recv``: a middleware registered with a path prefix (``app.use('/admin', auth)``) only
        guards the routes under that prefix."""
        parts = [self.local_prefix.get((rel, recv), "")]
        guards = [g for (p, pre, gs) in self.uses.get((rel, recv), []) if p < pos and self.under(pre, path) for g in gs]
        if depth > 6:
            return parts, guards
        m = self.var_mounts.get((rel, recv))
        if m:
            up, ug = self.chain(rel, m[0], m[3], depth + 1, _join_path(m[1], parts[0], path))
            return up + [m[1]] + parts, guards + m[2] + ug
        fm = self.file_mounts.get(rel)
        if fm and (recv in self.routers.get(rel, set()) or not re.fullmatch(r"app|server", recv) or depth):
            up, ug = self.chain(fm[0], fm[1], fm[4], depth + 1, _join_path(fm[2], parts[0], path))
            return up + [fm[2]] + parts, guards + fm[3] + ug
        return parts, guards

    def emit(self, f, recv, verb, path, hpiece, middle, pos, fw):
        ctx = self.ctx
        imp = self.imports.get(f.rel, {})
        first = re.match(r"\s*([\w$]+)\.", f.bare[hpiece[0]:hpiece[1]])
        hint = None
        if first and first.group(1) in imp:
            hint = imp[first.group(1)][0] or imp[first.group(1)][1]
        else:
            nm = re.match(r"\s*([\w$]+)\s*$", f.bare[hpiece[0]:hpiece[1]])
            if nm and nm.group(1) in imp:
                hint = imp[nm.group(1)][0] or imp[nm.group(1)][1]
        h = _handler(ctx, f, hpiece[0], hpiece[1], ("javascript",), hint=hint)
        parts, guards = self.chain(f.rel, recv, pos, 0, path or "")
        fn = next((d for d in ctx.defs(f) if d[2] <= f.lines.of(pos) <= d[3] and (f.rel, "fn:" + d[0]) in self.var_mounts), None)
        if fn:                                             # routes declared inside a registered plugin function
            m = self.var_mounts[(f.rel, "fn:" + fn[0])]
            up, ug = self.chain(f.rel, m[0], m[3], 1, _join_path(m[1], *parts, path or ""))
            parts, guards = up + [m[1]] + parts, guards + m[2] + ug
        full = _join_path(*parts, path)
        own = self.mw_guards(f, middle) + _guards_from(h["wrappers"], "wrapper")
        req = [x.strip().split(":")[0].strip() for x in h["params"].split(",")[:2]] if h["params"] else []
        ctx.add(f, "http", ["ANY"] if verb in ("all", "use") else ["DELETE" if verb == "del" else verb], full, h["name"],
                f.lines.of(pos), fw, h["spans"], guards=own + guards, req_names=req)

    # ------------------------------------------------------------------ NestJS
    def nest(self, f: _File):
        ctx = self.ctx
        glob = getattr(self, "_nest_global", None)
        if glob is None:
            pre, guards = "", []
            for x in self.files:
                m = re.search(r"\.setGlobalPrefix\(\s*(['\"`])(.*?)\1", x.code)
                if m:
                    pre = m.group(2)
                m = re.search(r"\.useGlobalGuards\(\s*(?:new\s+)?([\w$]+)|provide\s*:\s*APP_GUARD\s*,\s*use(?:Class|Existing)\s*:\s*([\w$]+)", x.code)
                if m:
                    guards += _guards_from([(m.group(1) or m.group(2))], "global guard")
            glob = self._nest_global = (pre, guards)
        for it in _members(f, "@"):
            if it["kind"] != "member" or not it["cls"] or not it["params"]:
                continue
            cls = it["cls"]
            ctrl = _anno(cls["annos"], "Controller")
            route = next((a for a in it["annos"] if a[0] in _NEST_HTTP), None)
            guards = []
            for annos in (it["annos"], cls["annos"]):
                for name, args, _p in annos:
                    if name == "UseGuards":
                        guards += _guards_from(re.findall(r"[A-Za-z_$][\w$]*(?:\([^)]*\))?", args), "guard")
                    elif name in ("Roles", "Permissions", "RequirePermissions", "Scopes", "ApiBearerAuth", "Auth", "Authorized"):
                        if name != "ApiBearerAuth":
                            guards.append((f"@{name}({args.strip()[:40]})", "decorator", False))
                    elif name in ("Public", "SkipAuth", "AllowAnonymous", "IsPublic", "NoAuth"):
                        guards.append((f"@{name}()", "decorator", True))
            guards += glob[1]
            handler = f"{cls['name']}.{it['name']}"
            params = []
            for annos, typ, name in _decl_params(f, it["params"], "javascript"):
                for an, aargs in annos:
                    loc = _NEST_PARAM.get(an)
                    if loc:
                        key = _first_str(aargs)
                        params.append(Param(key or name, loc, typ if loc == "body" and not key else ""))
            span = _span_of(f, it)
            line = f.lines.of(it["pos"])
            if route and ctrl is not None:
                base = _anno_path(ctrl[1]) if "{" in ctrl[1] else (_first_str(ctrl[1]) or "")
                full = _join_path(glob[0], base, _first_str(route[1]) or "")
                ctx.add(f, "http", [_NEST_HTTP[route[0]]], full, handler, line, "nestjs", [span], params, guards)
                continue
            a = _anno(it["annos"], "MessagePattern", "EventPattern", "SubscribeMessage", "OnEvent", "Process", "RabbitSubscribe")
            if a:
                topic = _first_str(a[1]) or re.sub(r"\s+", " ", a[1]).strip()[:60] or it["name"]
                ctx.add(f, "consumer", [], topic, handler, line, "nestjs", [span], params or [Param("payload", "message")],
                        guards, scan=False)
                continue
            a = _anno(it["annos"], "Cron", "Interval", "Timeout")
            if a:
                ctx.add(f, "job", [], _first_str(a[1]) or re.sub(r"\s+", " ", a[1]).strip()[:60] or it["name"], handler, line, "nestjs", [span],
                        scan=False)
                continue
            a = _anno(it["annos"], "Query", "Mutation", "Subscription")
            if a and _anno(cls["annos"], "Resolver") is not None:
                args = [Param(_first_str(aargs) or name, "body") for annos, _t, name in _decl_params(f, it["params"], "javascript")
                        for an, aargs in annos if an == "Args"]
                ctx.add(f, "http", ["POST"], f"/graphql#{a[0].lower()}.{it['name']}", handler, line, "nestjs-graphql", [span], args,
                        guards)

    # ------------------------------------------------------------------ Next.js
    def next(self, f: _File):
        ctx = self.ctx
        rel = f.rel
        m = re.search(r"(?:^|/)pages(/api/.+|/api)\.(?:[jt]sx?|mjs)$", rel)
        guards = self.next_middleware()
        if m:
            path = re.sub(r"/index$", "", m.group(1)) or "/"
            methods = sorted(set(re.findall(r"\bmethod\s*(?:===?|!==?)\s*['\"](GET|POST|PUT|PATCH|DELETE)['\"]", f.code)) |
                             set(re.findall(r"\bcase\s+['\"](GET|POST|PUT|PATCH|DELETE)['\"]", f.code)))
            dm = re.search(r"\bexport\s+default\s+(?:async\s+)?(?:function\s*([\w$]*)|([\w$]+)\s*\(|([\w$]+))", f.bare)
            name = next((g for g in (dm.groups() if dm else ()) if g), "handler")
            wrap = _guards_from([dm.group(2)] if dm and dm.group(2) else [], "wrapper")
            ctx.add(f, "http", methods or ["ANY"], path, name, f.lines.of(dm.start()) if dm else 1, "nextjs",
                    [(rel, 1, len(f.lines.starts))], guards=wrap + [g for g in guards if self.next_match(g, path)])
            return
        m = re.search(r"(?:^|/)app((?:/[^/]+)*)/route\.(?:[jt]s|mjs)$", rel)
        if m:
            path = re.sub(r"/\([^/]*\)|/@[^/]+", "", m.group(1)) or "/"
            for d in re.finditer(r"\bexport\s+(?:async\s+)?(?:function\s+|const\s+)(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b", f.bare):
                blk = _block_after(f.bare, d.end(), 4000)
                end = f.lines.of(blk[1]) if blk else f.lines.of(d.end())
                line = f.lines.of(d.start())
                ctx.add(f, "http", [d.group(1)], path, d.group(1), line, "nextjs", [(rel, line, end)],
                        guards=[g for g in guards if self.next_match(g, path)], req_names=("request", "req"))

    def next_middleware(self) -> list:
        hit = getattr(self, "_next_mw", None)
        if hit is None:
            hit = []
            for x in self.files:
                if re.search(r"(?:^|/)(?:src/)?middleware\.[jt]s$", x.rel) and (_inline_guards("javascript", x.code) or
                                                                                 re.search(r"withAuth|authMiddleware|clerkMiddleware", x.code)):
                    mm = re.search(r"\bmatcher\s*:\s*(\[[^\]]*\]|['\"][^'\"]*['\"])", x.code)
                    hit.append((f"{x.rel}", "middleware", False, _all_strs(mm.group(1)) if mm else []))
            self._next_mw = hit
        return hit

    @staticmethod
    def next_match(g: tuple, path: str) -> bool:
        pats = g[3] if len(g) > 3 else []
        if not pats:
            return True
        for p in pats:
            stem = re.split(r"[:(*]", p)[0].rstrip("/")
            if "(?!" in p:
                neg = re.search(r"\(\?!([^)]*)\)", p)
                if not any(path.lstrip("/").startswith(n) for n in (neg.group(1).split("|") if neg else []) if n):
                    return True
            elif path.startswith(stem or "/"):
                return True
        return False


# ================================================================================================ Java / Kotlin extractor
_SPRING_MAP = {"GetMapping": "GET", "PostMapping": "POST", "PutMapping": "PUT", "DeleteMapping": "DELETE",
               "PatchMapping": "PATCH", "RequestMapping": None}
_SPRING_PARAM = {"RequestParam": "query", "PathVariable": "path", "RequestHeader": "header", "CookieValue": "cookie",
                 "RequestBody": "body", "RequestPart": "file", "ModelAttribute": "form", "MatrixVariable": "path"}
_JAXRS_PARAM = {"QueryParam": "query", "PathParam": "path", "HeaderParam": "header", "CookieParam": "cookie",
                "FormParam": "form", "FormDataParam": "form", "BeanParam": "query", "MatrixParam": "path"}
_JAXRS_VERBS = ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")
_JVM_AUTH_ANNOS = ("PreAuthorize", "PostAuthorize", "Secured", "RolesAllowed", "DenyAll", "RequiresRoles", "RequiresPermissions",
                   "RequiresAuthentication", "RequiresUser", "Authenticated", "SecurityRequirement")
_JVM_SKIP_TYPES = re.compile(r"\b(HttpServletRequest|HttpServletResponse|ServletRequest|ServletResponse|Model|ModelMap|"
                             r"ModelAndView|Principal|Authentication|HttpSession|BindingResult|Errors|RedirectAttributes|Locale|"
                             r"WebRequest|NativeWebRequest|UriComponentsBuilder|ServerWebExchange|ServerHttpRequest|"
                             r"ServerHttpResponse|Pageable|SecurityContext|UriInfo|HttpHeaders|Request|AsyncResponse|"
                             r"Continuation|SessionStatus|OAuth2AuthenticationToken|Jwt|UserDetails|HttpContext|"
                             r"CancellationToken|ILogger\w*|ClaimsPrincipal|IFormCollection)\b")
_SIMPLE_TYPE = re.compile(r"^(?:final\s+)?(?:java\.lang\.)?(?:String|string|int|Int|Integer|long|Long|short|Short|double|Double|"
                          r"float|Float|decimal|bool|boolean|Boolean|char|Char|byte|Guid|UUID|DateTime|DateOnly|LocalDate|"
                          r"LocalDateTime|Instant|BigDecimal|BigInteger|uint|ulong)\??(?:\[\])?$|^(?:Optional|List|Set|"
                          r"IEnumerable|Collection)<\s*(?:String|string|Integer|int|Long|long|UUID|Guid)\s*>\??$")


def _between(text: str, opener: str, closer: str):
    """The texts between each ``opener`` ... ``closer`` pair, in order (linear time; an unclosed opener ends it)."""
    pos = 0
    while True:
        a = text.find(opener, pos)
        if a < 0:
            return
        b = text.find(closer, a + len(opener))
        if b < 0:
            return
        yield text[a + len(opener):b]
        pos = b + len(closer)


def _outside(text: str, opener: str, closer: str):
    """The pieces of ``text`` that are NOT between ``opener`` and ``closer`` (an unclosed opener hides the rest)."""
    pos = 0
    while True:
        a = text.find(opener, pos)
        if a < 0:
            yield text[pos:]
            return
        yield text[pos:a]
        b = text.find(closer, a + len(opener))
        if b < 0:
            return
        pos = b + len(closer)


def _ant_segment(pat: str, seg: str) -> bool:
    if pat == seg or pat == "*":
        return True
    if not re.search(r"[*?{]", pat):
        return False
    if len(pat) > 200 or len(seg) > 200 or len(re.findall(r"\*+|\{", pat)) > 3:
        return False                                   # not a pattern a person writes: never spend time on it
    rx = re.sub(r"(?:\\\*)+", "[^/]*", re.escape(pat)).replace(r"\?", "[^/]")
    rx = re.sub(r"\\\{[^/]*?\\\}", "[^/]+", rx)
    return re.fullmatch(rx, seg) is not None


def _ant_match(pattern: str, path: str) -> bool:
    """Ant-style path match as used by Spring Security matchers and (with ``/*`` -> ``/**``) servlet url-patterns:
    ``?`` one character, ``*`` within a segment, ``**`` any number of segments, ``{var}`` one segment. Matching is
    done segment by segment (the patterns and the paths both come from the scanned project: no regular expression
    over the whole path, so no catastrophic backtracking)."""
    pats, segs = pattern.split("/")[:64], path.split("/")[:64]
    reach = {0}                                         # indexes in `segs` reachable after the patterns consumed so far
    for pat in pats:
        if not reach:
            return False
        if pat == "**":
            reach = set(range(min(reach), len(segs) + 1))
        else:
            reach = {i + 1 for i in reach if i < len(segs) and _ant_segment(pat, segs[i])}
    return len(segs) in reach


def _safe_regex(rx: str) -> bool:
    """True when a regular expression taken from the scanned project (Symfony ``access_control`` paths) is cheap
    to evaluate: short, no quantified group, no back-reference, at most three unbounded quantifiers."""
    if len(rx) > 200 or re.search(r"\)\s*(?:[*+]|\{\d*,)|\\[1-9]|\(\?P=|\(\?\(", rx):
        return False
    return len(re.findall(r"(?<!\\)[*+]|\{\d*,\d*\}", rx)) <= 3


class _Jvm:
    """Spring MVC / WebFlux annotations, JAX-RS resources, servlets, message listeners, scheduled methods."""

    def __init__(self, ctx: _Ctx):
        self.ctx = ctx
        self.files = ctx.lang("java", "kotlin")
        self.rules: list = []       # Spring Security matcher rules [(patterns, action text, is_public)]
        self.default = None         # anyRequest() rule
        self.web_xml: dict = {}     # servlet class simple name -> [url patterns]
        self.xml_guards: list = []  # [(patterns, guard)]
        self.context_path = ""

    def run(self):
        for f in self.files:
            self.security(f)
        for rel, text in self.ctx.config.items():
            if rel.endswith("web.xml"):
                self.parse_web_xml(text)
        for f in self.files:
            self.scan(f)

    def security(self, f: _File):
        if "anyRequest" not in f.text and "Matchers" not in f.text and "authorizeExchange" not in f.text:
            return
        for m in re.finditer(r"\.(?:requestMatchers|antMatchers|mvcMatchers|regexMatchers|pathMatchers)\s*\(", f.bare):
            args, close = _call_args(f, m.end() - 1)
            if close < 0:
                continue
            pats = _all_strs(f.code[m.end():close])
            am = re.match(r"\s*\.\s*(\w+)\s*\(([^)]*)\)", f.code[close + 1:close + 200])
            if pats and am:
                act = am.group(1)
                self.rules.append((pats, f"{act}({am.group(2).strip()})", act in ("permitAll", "anonymous")))
        m = re.search(r"\.(?:anyRequest|anyExchange)\s*\(\s*\)\s*\.\s*(\w+)\s*\(([^)]*)\)", f.code)
        if m:
            self.default = (f"anyRequest().{m.group(1)}({m.group(2).strip()})", m.group(1) in ("permitAll", "anonymous"))

    def parse_web_xml(self, text: str):
        # Textual on purpose (no XML parser: no entity expansion, no external entity); `_between` is linear even
        # when thousands of elements are left unclosed.
        text = "".join(_outside(text, "<!--", "-->"))
        classes = {}
        for block in _between(text, "<servlet>", "</servlet>"):
            n = re.search(r"<servlet-name>\s*([^<\s]+)", block)
            c = re.search(r"<servlet-class>\s*([^<\s]+)", block)
            if n and c:
                classes[n.group(1)] = c.group(1).split(".")[-1]
        for block in _between(text, "<servlet-mapping>", "</servlet-mapping>"):
            n = re.search(r"<servlet-name>\s*([^<\s]+)", block)
            if n and n.group(1) in classes:
                self.web_xml.setdefault(classes[n.group(1)], []).extend(re.findall(r"<url-pattern>\s*([^<\s]+)", block))
        for block in _between(text, "<security-constraint>", "</security-constraint>"):
            pats = re.findall(r"<url-pattern>\s*([^<\s]+)", block)
            roles = re.findall(r"<role-name>\s*([^<\s]+)", block)
            if pats and "<auth-constraint" in block:
                self.xml_guards.append((pats, ("web.xml security-constraint: " + (",".join(roles) or "no access"), "config", False)))

    def config_guards(self, path: str) -> list:
        p = openapi_path(path)
        out = []
        for pats, guard in self.xml_guards:
            if any(_ant_match(x.replace("/*", "/**") if x.endswith("/*") else x, p) for x in pats):
                out.append(guard)
        for pats, action, public in self.rules:
            if any(_ant_match(x, p) for x in pats):
                out.append((f"security config: {' '.join(pats)[:60]} -> {action}", "config", public))
                return out
        if self.default:
            out.append(("security config: " + self.default[0], "config", self.default[1]))
        return out

    @staticmethod
    def anno_guards(annos: list) -> list:
        out = []
        for name, args, _p in annos:
            if name in ("PermitAll", "AllowAnonymous", "Anonymous", "PublicEndpoint"):
                out.append(("@" + name, "annotation", True))
            elif name in _JVM_AUTH_ANNOS or re.search(r"(?i)^(require|has|check|verify)\w*(auth|role|permission|login|admin|scope)|"
                                                       r"^(admin|auth\w*|login|secured?)(only|required)?$", name):
                text = re.sub(r"\s+", " ", args).strip()
                public = name in ("PreAuthorize", "PostAuthorize") and _PUBLIC_ARGS_RE.search(text) is not None
                out.append((f"@{name}({text[:50]})" if text else "@" + name, "annotation", public))
        return out

    def params(self, f: _File, item: dict, table: dict, path: str, default_body: bool) -> tuple:
        params, guards = [], []
        pv = set(_path_vars(path))
        for annos, typ, name in _decl_params(f, item["params"], f.lang):
            loc = None
            pname = name
            for an, aargs in annos:
                if an in table:
                    loc = table[an]
                    key = _first_str(aargs)
                    if key and not re.search(r"\b(defaultValue|required)\s*=\s*['\"]" + re.escape(key), aargs):
                        pname = key
                    else:
                        km = re.search(r"\b(?:name|value)\s*=\s*['\"]([^'\"]+)", aargs)
                        pname = km.group(1) if km else name
                elif an in ("AuthenticationPrincipal", "CurrentUser", "CurrentSecurityContext", "RegisteredOAuth2AuthorizedClient"):
                    guards.append(("@" + an, "parameter", False))
                    loc = "skip"
                elif an in ("Context", "Suspended", "Valid", "Validated", "NotNull", "Nullable"):
                    loc = loc or ("skip" if an in ("Context", "Suspended") else None)
            if loc == "skip":
                continue
            if loc is None:
                if _JVM_SKIP_TYPES.search(typ):
                    if re.search(r"\b(Principal|Authentication|Jwt|UserDetails|OAuth2AuthenticationToken|ClaimsPrincipal)\b", typ):
                        guards.append((f"parameter: {typ.strip()}", "parameter", False))
                    continue
                if name in pv:
                    loc = "path"
                elif "MultipartFile" in typ or "IFormFile" in typ or "Part" == typ.strip():
                    loc = "file"
                elif default_body or not _SIMPLE_TYPE.match(typ.strip() or "String"):
                    loc = "body" if default_body or item.get("post") else "query"
                else:
                    loc = "query"
            params.append(Param(pname, loc, typ.strip() if loc == "body" else ""))
        return params, guards

    def scan(self, f: _File):
        ctx = self.ctx
        text = f.text
        if "@" not in text and "Servlet" not in text and " main" not in text:
            return
        fw_spring = bool(re.search(r"org\.springframework|@(?:Rest)?Controller\b|@RequestMapping\b", text))
        fw_jaxrs = bool(re.search(r"\b(?:javax|jakarta)\.ws\.rs\b|@Path\s*\(", text))
        for it in _members(f, "@"):
            cls = it["cls"]
            if it["kind"] == "class":
                self.servlet(f, it)
                continue
            if not it["params"] or not it["name"]:
                continue
            annos = it["annos"]
            cannos = cls["annos"] if cls else []
            handler = f"{cls['name']}.{it['name']}" if cls else it["name"]
            span = _span_of(f, it)
            line = f.lines.of(it["pos"])
            route = next((a for a in annos if a[0] in _SPRING_MAP), None) if fw_spring else None
            if route and cls:
                base = _anno(cannos, "RequestMapping")
                method = _SPRING_MAP[route[0]]
                methods = [method] if method else re.findall(r"RequestMethod\.(\w+)", route[1]) or \
                    (re.findall(r"RequestMethod\.(\w+)", base[1]) if base else []) or ["ANY"]
                it["post"] = bool(set(methods) & {"POST", "PUT", "PATCH"})
                for bpath in (_anno_paths(base[1]) if base else [""]):
                    for rpath in _anno_paths(route[1]):
                        full = _join_path(self.context_path, bpath, rpath)
                        params, pguards = self.params(f, it, _SPRING_PARAM, full, False)
                        guards = self.anno_guards(annos) + pguards + self.anno_guards(cannos) + self.config_guards(full)
                        ctx.add(f, "http", methods, full, handler, line, "spring", [span], params, guards)
                continue
            verbs = [a[0] for a in annos if a[0] in _JAXRS_VERBS]
            if verbs and (fw_jaxrs or _anno(cannos, "Path")):
                base = _anno(cannos, "Path")
                sub = _anno(annos, "Path")
                full = _join_path(self.context_path, _first_str(base[1]) if base else "", _first_str(sub[1]) if sub else "")
                params, pguards = self.params(f, it, _JAXRS_PARAM, full, True)
                guards = self.anno_guards(annos) + pguards + self.anno_guards(cannos) + self.config_guards(full)
                ctx.add(f, "http", verbs, full, handler, line, "jax-rs", [span], params, guards)
                continue
            a = _anno(annos, "KafkaListener", "RabbitListener", "JmsListener", "SqsListener", "StreamListener", "ServiceActivator",
                      "PulsarListener", "NatsListener", "Incoming")
            if a:
                topic = _anno_path(a[1], ("topics", "queues", "destination", "value", "topicPattern", "inputChannel")) or it["name"]
                ps = [Param(n, "message") for _an, _t, n in _decl_params(f, it["params"], f.lang)] or [Param("message", "message")]
                ctx.add(f, "consumer", [], topic, handler, line, {"KafkaListener": "kafka", "RabbitListener": "rabbitmq",
                                                                   "JmsListener": "jms", "SqsListener": "sqs"}.get(a[0], "messaging"),
                        [span], ps, scan=False)
                continue
            a = _anno(annos, "Scheduled", "Schedule", "Schedules")
            if a:
                name = _anno_path(a[1], ("cron", "fixedRateString", "fixedDelayString")) or re.sub(r"\s+", " ", a[1]).strip()[:40]
                ctx.add(f, "job", [], name or it["name"], handler, line, "spring-scheduling", [span], scan=False)
                continue
            a = _anno(annos, "MessageMapping", "SubscribeMapping")
            if a:
                ctx.add(f, "consumer", [], _anno_path(a[1]) or it["name"], handler, line, "spring-websocket", [span],
                        [Param(n, "message") for _an, _t, n in _decl_params(f, it["params"], f.lang)],
                        self.anno_guards(annos) + self.anno_guards(cannos), scan=False)
                continue
            if it["name"] == "main" and re.search(r"\bstatic\b|^\s*fun\s+main", it["header"]) and it["block"]:
                body = f.code[it["block"][0]:it["block"][1]]
                arg = next((n for _an, _t, n in _decl_params(f, it["params"], f.lang)), "args")
                rest = re.sub(r"\b(?:SpringApplication\.run|runApplication\s*<[^>]*>)\s*\([^;\n]*", "", body)
                if re.search(r"\b" + re.escape(arg) + r"\b", rest) or "System.in" in rest or "readLine" in rest:
                    ctx.add(f, "cli", [], cls["name"] if cls else posixpath.basename(f.rel), handler, line, "main", [span],
                            [Param(arg, "arg")], scan=False)

    def servlet(self, f: _File, cls: dict):
        a = _anno(cls["annos"], "WebServlet")
        pats = []
        if a:
            pats = _all_strs(re.sub(r"\b(?:name|description|displayName)\s*=\s*(['\"]).*?\1", "", a[1]))
            pats = [p for p in pats if p.startswith(("/", "*"))]
        pats = pats or self.web_xml.get(cls["name"], [])
        if not pats and not re.search(r"\bextends\s+(?:Http|Generic)Servlet\b|:\s*HttpServlet\s*\(", cls["header"]):
            return
        blk = cls["block"]
        guards = self.anno_guards(cls["annos"])
        sec = _anno(cls["annos"], "ServletSecurity")
        if sec:
            guards.append(("@ServletSecurity(" + re.sub(r"\s+", " ", sec[1])[:50] + ")", "annotation", False))
        for d in self.ctx.defs(f):
            if d[1] != cls["name"] or d[0] not in ("doGet", "doPost", "doPut", "doDelete", "doPatch", "service", "doHead", "doOptions"):
                continue
            if blk and not (f.lines.of(blk[0]) <= d[2] <= f.lines.of(blk[1])):
                continue
            verb = "ANY" if d[0] == "service" else d[0][2:].upper()
            for p in pats or ["(unmapped) /" + cls["name"]]:
                self.ctx.add(f, "http", [verb], p, f"{cls['name']}.{d[0]}", d[2], "servlet", [(f.rel, d[2], d[3])],
                             guards=guards + self.config_guards(p))


# ============================================================================================================ C# extractor
_CS_HTTP = {"HttpGet": "GET", "HttpPost": "POST", "HttpPut": "PUT", "HttpDelete": "DELETE", "HttpPatch": "PATCH",
            "HttpHead": "HEAD", "HttpOptions": "OPTIONS"}
_CS_FROM = {"FromQuery": "query", "FromRoute": "path", "FromBody": "body", "FromHeader": "header", "FromForm": "form",
            "FromServices": "skip", "FromKeyedServices": "skip", "AsParameters": "query"}
_CS_MAP_RE = re.compile(r"\b([\w.]+)\s*\.\s*Map(Get|Post|Put|Delete|Patch|Methods|Group)\s*\(")


class _Cs:
    """ASP.NET Core controllers (attribute and conventional routing), minimal APIs, Azure Functions."""

    def __init__(self, ctx: _Ctx):
        self.ctx = ctx
        self.files = ctx.lang("csharp")
        self.global_guards: list = []

    def run(self):
        for f in self.files:
            if re.search(r"\bFallbackPolicy\s*=|MapControllers\s*\(\s*\)\s*\.\s*RequireAuthorization|"
                         r"AuthorizeFilter\s*\(|RequireAuthenticatedUser\(\)\s*\.Build\(\)\s*;\s*\w+\.Filters\.Add", f.code):
                self.global_guards = [("global authorization policy (" + posixpath.basename(f.rel) + ")", "config", False)]
        for f in self.files:
            self.controllers(f)
            self.minimal(f)

    @staticmethod
    def attr_guards(annos: list) -> list:
        out = []
        for name, args, _p in annos:
            name = re.sub(r"Attribute$", "", name)
            if name == "AllowAnonymous":
                out.append(("[AllowAnonymous]", "attribute", True))
            elif name in ("Authorize", "RequiredScope", "RequiresClaim", "ValidateAntiForgeryToken") or \
                    re.search(r"(?i)^(require|has)\w*(role|permission|scope|claim)|authoriz", name):
                if name != "ValidateAntiForgeryToken":
                    text = re.sub(r"\s+", " ", args).strip()
                    out.append((f"[{name}({text[:50]})]" if text else f"[{name}]", "attribute", False))
        return out

    def params(self, f: _File, span, path: str, methods: list) -> tuple:
        params, guards = [], []
        pv = {v.lower() for v in _path_vars(path)}
        for annos, typ, name in _decl_params(f, span, "csharp"):
            loc, pname = None, name
            for an, aargs in annos:
                an = re.sub(r"Attribute$", "", an)
                if an in _CS_FROM:
                    loc = _CS_FROM[an]
                    km = re.search(r"\bName\s*=\s*\"([^\"]+)", aargs)
                    pname = km.group(1) if km else name
            if loc == "skip":
                continue
            if loc is None:
                if _JVM_SKIP_TYPES.search(typ) or re.search(r"\b(I[A-Z]\w*(Service|Repository|Factory|Context|Sender|Mediator)|"
                                                            r"\w*(?:Db|DbContext|Service|Repository|Logger|Mediator)|HttpRequest|HttpResponse)\b", typ):
                    if "ClaimsPrincipal" in typ:
                        guards.append(("parameter: ClaimsPrincipal", "parameter", False))
                    continue
                if name.lower() in pv:
                    loc = "path"
                elif "IFormFile" in typ:
                    loc = "file"
                elif _SIMPLE_TYPE.match(typ.strip() or "string"):
                    loc = "query"
                else:
                    loc = "body" if set(methods) & {"POST", "PUT", "PATCH", "ANY"} else "query"
            params.append(Param(pname, loc, typ.strip() if loc == "body" else ""))
        return params, guards

    def controllers(self, f: _File):
        ctx = self.ctx
        if "Controller" not in f.text and "[Function" not in f.text and "Main" not in f.text and "Hub" not in f.text:
            return
        for it in _members(f, "["):
            cls = it["cls"]
            if it["kind"] != "member" or not cls or not it["params"] or not it["name"] or not it["block"] and "=>" not in it["header"]:
                continue
            annos, cannos = it["annos"], cls["annos"]
            handler = f"{cls['name']}.{it['name']}"
            span = _span_of(f, it)
            line = f.lines.of(it["pos"])
            fn = _anno(annos, "Function", "FunctionName")
            if fn:
                self.function(f, it, fn, handler, span, line)
                continue
            is_ctrl = cls["name"].endswith("Controller") or _anno(cannos, "ApiController", "Controller") is not None or \
                re.search(r":\s*(?:\w+\.)*(?:Controller|ControllerBase|ApiController|ODataController)\b", cls["header"]) is not None
            http = [a for a in annos if re.sub(r"Attribute$", "", a[0]) in _CS_HTTP]
            if is_ctrl and re.search(r"\bpublic\b", it["header"]) and not re.search(r"\bstatic\b", it["header"]) \
                    and it["name"] != cls["name"] and _anno(annos, "NonAction") is None:
                croute = _anno(cannos, "Route", "RoutePrefix")
                mroute = _anno(annos, "Route")
                if not http and not croute and not mroute and not re.search(r"\b(IActionResult|ActionResult|Task|JsonResult|"
                                                                               r"ViewResult|IResult|ContentResult|FileResult)\b", it["header"]):
                    continue
                ctrl_name = re.sub(r"Controller$", "", cls["name"])
                methods = [_CS_HTTP[re.sub(r"Attribute$", "", a[0])] for a in http] or \
                    [m.upper() for a in annos if a[0] == "AcceptVerbs" for m in _all_strs(a[1])] or ["ANY"]
                sub = next((_first_str(a[1]) for a in http if _first_str(a[1]) is not None), None)
                if sub is None and mroute:
                    sub = _first_str(mroute[1])
                base = _first_str(croute[1]) if croute else None
                if base is None and sub is None:
                    full = f"/{ctrl_name}/{it['name']}"                       # conventional {controller}/{action}
                    fw = "aspnet-mvc"
                else:
                    full = sub if (sub or "").startswith(("/", "~/")) else _join_path(base or "", sub or "")
                    full = full.lstrip("~")
                    fw = "aspnet"
                full = re.sub(r"(?i)\[controller\]", ctrl_name, full)
                full = re.sub(r"(?i)\[action\]", it["name"], full)
                full = re.sub(r"(?i)\{controller(=\w+)?\}", ctrl_name, full)
                params, pguards = self.params(f, it["params"], full, methods)
                guards = self.attr_guards(annos) + pguards + self.attr_guards(cannos) + self.global_guards
                ctx.add(f, "http", methods, full, handler, line, fw, [span], params, guards)
                continue
            if re.search(r":\s*(?:\w+\.)*Hub\b", cls["header"]) and re.search(r"\bpublic\b", it["header"]) and it["name"] != cls["name"] \
                    and not re.search(r"\boverride\b", it["header"]):
                ctx.add(f, "consumer", [], f"{cls['name']}/{it['name']}", handler, line, "signalr", [span],
                        [Param(n, "message") for _a, _t, n in _decl_params(f, it["params"], "csharp")],
                        self.attr_guards(annos) + self.attr_guards(cannos) + self.global_guards, scan=False)
                continue
            if it["name"] == "Main" and re.search(r"\bstatic\b", it["header"]) and it["block"]:
                arg = next((n for _a, _t, n in _decl_params(f, it["params"], "csharp")), "args")
                body = re.sub(r"\b(?:CreateBuilder|CreateHostBuilder|CreateDefaultBuilder)\s*\([^)]*\)", "", f.code[it["block"][0]:it["block"][1]])
                if re.search(r"\b" + re.escape(arg) + r"\b", body) or "Console.ReadLine" in body:
                    ctx.add(f, "cli", [], cls["name"], handler, line, "main", [span], [Param(arg, "arg")], scan=False)

    def function(self, f: _File, it: dict, fn: tuple, handler: str, span: tuple, line: int):
        name = _first_str(fn[1]) or it["name"]
        for annos, typ, pname in _decl_params(f, it["params"], "csharp"):
            for an, aargs in annos:
                if an == "HttpTrigger":
                    level = re.search(r"AuthorizationLevel\.(\w+)", aargs)
                    route = re.search(r"\bRoute\s*=\s*\"([^\"]*)\"", aargs)
                    methods = [s.upper() for s in _all_strs(re.sub(r"\bRoute\s*=\s*\"[^\"]*\"", "", aargs))] or ["ANY"]
                    lv = level.group(1) if level else "Function"
                    guards = [(f"AuthorizationLevel.{lv}", "function key", lv == "Anonymous")]
                    self.ctx.add(f, "http", methods, _join_path("api", route.group(1) if route else name), handler, line,
                                 "azure-functions", [span], guards=guards, req_names=(pname,))
                    return
                if an.endswith("Trigger"):
                    kind = "job" if an == "TimerTrigger" else "consumer"
                    self.ctx.add(f, kind, [], _first_str(aargs) or name, handler, line, "azure-functions", [span],
                                 [] if kind == "job" else [Param(pname, "message")], scan=False)
                    return

    def minimal(self, f: _File):
        ctx = self.ctx
        if ".Map" not in f.text:
            return
        groups: dict = {}            # variable -> (prefix parts, guards)
        for m in _CS_MAP_RE.finditer(f.bare):
            recv, verb = m.group(1), m.group(2)
            args, close = _call_args(f, m.end() - 1)
            if close < 0 or not args:
                continue
            path = _lit(f, *args[0])
            if path is None:
                continue
            stmt_end = f.bare.find(";", close)
            chain = f.code[close + 1:stmt_end if stmt_end > 0 else close + 400]
            guards = []
            if re.search(r"\.AllowAnonymous\s*\(", chain):
                guards.append(("AllowAnonymous()", "endpoint", True))
            am = re.search(r"\.RequireAuthorization\s*\(([^)]*)\)", chain)
            if am:
                guards.append((f"RequireAuthorization({am.group(1).strip()[:40]})", "endpoint", False))
            pparts, pguards = groups.get(recv, ([], []))
            if verb == "Group":
                var = re.search(r"\b(?:var|RouteGroupBuilder|\w+)\s+(\w+)\s*=\s*$", f.bare[max(0, m.start() - 80):m.start()])
                if var:
                    groups[var.group(1)] = (pparts + [path], guards + pguards)
                continue
            if len(args) < 2:
                continue
            methods = [verb.upper()]
            hpiece = args[-1]
            if verb == "Methods":
                methods = [s.upper() for s in _all_strs(f.code[args[1][0]:args[1][1]])] or ["ANY"]
            h = _handler(ctx, f, hpiece[0], hpiece[1], ("csharp",))
            full = _join_path(*pparts, path)
            ptext = f.bare[hpiece[0]:hpiece[1]]
            pm = re.match(r"\s*(?:async\s+)?(?:static\s+)?\(", ptext)
            params, g2 = [], []
            if pm:
                o = hpiece[0] + pm.end() - 1
                k = _close(f.bare, o)
                params, g2 = self.params(f, (o, k), full, methods) if k > 0 else ([], [])
                lam = re.search(r"\[\s*(Authorize|AllowAnonymous)[^\]]*\]\s*$", f.code[hpiece[0] - 0:hpiece[0] + pm.start() + 1])
            else:
                lam = None
                hit = ctx.find_def(h["name"].split(".")[-1], ("csharp",), prefer=f)
                if hit:
                    xf, d = hit
                    hm = re.search(r"\b" + re.escape(d[0]) + r"\s*\(", xf.bare[xf.lines.start(d[2]):])
                    if hm:
                        o = xf.lines.start(d[2]) + hm.end() - 1
                        k = _close(xf.bare, o)
                        params, g2 = self.params(xf, (o, k), full, methods) if k > 0 else ([], [])
            attr = re.match(r"\s*\[\s*(Authorize|AllowAnonymous)([^\]]*)\]", f.code[hpiece[0]:hpiece[1]])
            if attr or lam:
                a = attr or lam
                guards.insert(0, (f"[{a.group(1)}]", "attribute", a.group(1) == "AllowAnonymous"))
            ctx.add(f, "http", methods, full, h["name"], f.lines.of(m.start()), "aspnet-minimal", h["spans"], params,
                    guards + g2 + pguards + self.global_guards)


# ============================================================================================================ Go extractor
_GO_ROUTE_RE = re.compile(r"(?:\b([\w.]+)|\))\s*\.\s*(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|Any|Get|Post|Put|Delete|Patch|Head|"
                          r"Options|Handle|HandleFunc|Method|MethodFunc|All|Connect|Trace)\s*\(")
_GO_FW = (("github.com/gin-gonic/gin", "gin"), ("github.com/labstack/echo", "echo"), ("github.com/go-chi/chi", "chi"),
          ("github.com/gofiber/fiber", "fiber"), ("github.com/gorilla/mux", "gorilla"), ("github.com/julienschmidt/httprouter", "httprouter"))


class _Go:
    """net/http (incl. Go 1.22 method patterns), gin, echo, chi, fiber, gorilla/mux; cobra commands and ``flag``."""

    def __init__(self, ctx: _Ctx):
        self.ctx = ctx
        self.files = ctx.lang("go")

    def run(self):
        for f in self.files:
            self.scan(f)
            self.cli(f)

    def names(self, f: _File, pieces: list) -> list:
        out = []
        for s, e in pieces:
            text = re.sub(r"\s+", " ", f.code[s:e].strip())
            if text and not text.startswith(("func(", "func (")) and not _STR_RE.fullmatch(text):
                out.append(text[:80])
        return out

    def scan(self, f: _File):
        ctx, bare = self.ctx, f.bare
        fw = next((name for mod, name in _GO_FW if mod in f.text), "net/http")
        groups: dict = {}        # variable -> (prefix parts, guards)
        blocks: list = []        # (start, end, receiver var, prefix, guards) : chi Route / Group function blocks
        uses: list = []          # (offset, receiver, guards)
        for m in re.finditer(r"\b(\w+)\s*(?::=|=)\s*([\w.]+)\s*\.\s*(Group|PathPrefix|Route|With|Subrouter|NewRoute)\s*\(", bare):
            args, close = _call_args(f, m.end() - 1)
            if close < 0:
                continue
            pre = _lit(f, *args[0]) if args else None
            up = groups.get(m.group(2), ([], []))
            rest = args[1:] if pre is not None else args
            groups[m.group(1)] = (up[0] + [pre or ""], _guards_from(self.names(f, rest), "middleware") + up[1])
        for m in re.finditer(r"(?:\b([\w.]+)|\))\s*\.\s*(Route|Group)\s*\(", bare):
            args, close = _call_args(f, m.end() - 1)
            if close < 0 or not args:
                continue
            fpiece = args[-1]
            if not re.match(r"\s*func\s*\(", bare[fpiece[0]:fpiece[1]]):
                continue
            blk = _block_after(bare, fpiece[0], 400)
            pm = re.match(r"\s*func\s*\(\s*(\w+)", bare[fpiece[0]:fpiece[1]])
            pre = _lit(f, *args[0]) if len(args) > 1 else None
            guards = self.with_guards(f, m.start()) if m.group(1) is None else []
            if blk:
                blocks.append((blk[0], blk[1], pm.group(1) if pm else "", pre or "", guards, m.group(1) or ""))
        for m in re.finditer(r"\b([\w.]+)\s*\.\s*Use\s*\(", bare):
            args, close = _call_args(f, m.end() - 1)
            g = _guards_from(self.names(f, args), "middleware") if close > 0 else []
            for s, e in args if close > 0 else []:
                if re.match(r"\s*func\s*\(", bare[s:e]):
                    g += _inline_guards("go", f.code[s:e])
            if g:
                uses.append((m.start(), m.group(1), g))
        for m in _GO_ROUTE_RE.finditer(bare):
            recv, verb = m.group(1), m.group(2)
            args, close = _call_args(f, m.end() - 1)
            if close < 0 or len(args) < 2:
                continue
            methods = ["ANY"] if verb in ("Any", "All", "Handle", "HandleFunc") else [verb.upper()]
            pi = 0
            if verb in ("Method", "MethodFunc") or (verb == "Handle" and len(args) >= 3 and re.fullmatch(r"[A-Z]+", _lit(f, *args[0]) or "")):
                methods = [(_lit(f, *args[0]) or "ANY").upper()]
                pi = 1
            path = _lit(f, *args[pi]) if len(args) > pi else None
            if path is None:
                continue
            pm = re.match(r"([A-Z]+)\s+(\S+)$", path)               # Go 1.22: "POST /items/{id}"
            if pm:
                methods, path = [pm.group(1)], pm.group(2)
            if not (path.startswith(("/", "*")) or path == "" or re.match(r"[\w.-]+/", path)):
                continue
            if not path.startswith(("/", "*")) and path:
                path = "/" + path.split("/", 1)[1]                    # "host/path" patterns of net/http
            rest = args[pi + 1:]
            if recv is not None and (re.search(r"(?i)(client|resty|req|request|viper|cache|store|header|query|form|values|params|"
                                               r"cfg|config|env|redis|db|session|cookie)s?$", recv.split(".")[-1])
                                     or (recv == "http" and not verb.startswith("Handle"))):
                continue
            if re.fullmatch(r"\s*(nil|true|false|\d+|\"[^\"]*\")\s*", f.code[rest[-1][0]:rest[-1][1]]):
                continue
            hpiece = rest[0] if fw in ("echo", "fiber") and len(rest) > 1 and fw == "echo" else rest[-1]
            middle = [p for p in rest if p is not hpiece]
            h = _handler(ctx, f, hpiece[0], hpiece[1], ("go",))
            guards = _guards_from(self.names(f, middle), "middleware") + _guards_from(h["wrappers"], "wrapper")
            parts = []
            if recv is None:
                guards += self.with_guards(f, m.start())
            enclosing = sorted([b for b in blocks if b[0] < m.start() < b[1]], key=lambda b: b[0])
            if recv is not None and recv in groups and not any(b[2] == recv for b in enclosing):
                parts += groups[recv][0]
                guards += groups[recv][1]
            elif enclosing and enclosing[0][5] in groups:
                parts += groups[enclosing[0][5]][0]
                guards += groups[enclosing[0][5]][1]
            for b in enclosing:
                parts.append(b[3])
                guards += b[4]
            for pos, urecv, g in uses:
                if pos > m.start() and fw != "gorilla":          # gorilla applies a router's middleware to all its routes
                    continue
                inner = [b for b in blocks if b[0] < pos < b[1]]
                if inner:
                    if max(inner, key=lambda b: b[0]) in enclosing:
                        guards += g
                elif urecv == recv or (enclosing and (urecv == enclosing[0][5] or urecv in groups and recv is None)):
                    guards += g
                elif recv in groups and urecv == recv:
                    guards += g
            chain = bare[close + 1:close + 120]
            mm = re.match(r"\s*\.\s*Methods\s*\(", chain)
            if mm:
                k = _close(bare, close + mm.end())
                methods = [x.upper() for x in _all_strs(f.code[close + mm.end():k])] or \
                    re.findall(r"http\.Method(\w+)", f.code[close + mm.end():k]) or methods
                methods = [x.upper() for x in methods]
            ctx.add(f, "http", methods, _join_path(*parts, path), h["name"], f.lines.of(m.start()), fw, h["spans"], guards=guards)

    def with_guards(self, f: _File, pos: int) -> list:
        """Middlewares of a ``.With(a, b)`` call that ends right before offset ``pos`` (which is at ``)``)."""
        j = f.bare.rfind(")", 0, pos + 1)
        if j < 0:
            return []
        depth, i = 0, j
        while i >= 0:
            if f.bare[i] in ")]}":
                depth += 1
            elif f.bare[i] in "([{":
                depth -= 1
                if depth == 0:
                    break
            i -= 1
        if i > 5 and re.search(r"\.\s*(With|Use)\s*$", f.bare[max(0, i - 12):i]):
            return _guards_from(self.names(f, _split_top(f.bare, i + 1, j)), "middleware")
        return []

    def cli(self, f: _File):
        ctx = self.ctx
        for m in re.finditer(r"&?cobra\.Command\s*\{", f.bare):
            k = _close(f.bare, m.end() - 1)
            if k < 0:
                continue
            body = f.code[m.end():k]
            use = re.search(r"\bUse\s*:\s*\"([^\"]*)\"", body)
            run = re.search(r"\b(?:RunE?|PreRunE?)\s*:\s*([\w.]+)", f.bare[m.end():k])
            span = (f.rel, f.lines.of(m.start()), f.lines.of(k))
            spans = [span]
            if run and run.group(1) != "func":
                hit = ctx.find_def(run.group(1).split(".")[-1], ("go",), prefer=f)
                if hit:
                    spans.append((hit[0].rel, hit[1][2], hit[1][3]))
            name = (use.group(1).split() or ["command"])[0] if use else "command"
            ctx.add(f, "cli", [], name, run.group(1) if run and run.group(1) != "func" else "<anonymous>", span[1], "cobra",
                    spans, [Param("args", "arg")], scan=False)
        main = next((d for d in ctx.defs(f) if d[0] == "main" and not d[1]), None)
        if main and re.search(r"(?m)^package\s+main\b", f.text) and "cobra." not in f.text:
            flags = re.findall(r"\bflag\.(?:String|Int|Bool|Duration|Float64|Int64|Uint)(?:Var)?\(\s*(?:&?[\w.]+\s*,\s*)?\"([^\"]+)\"", f.code)
            if flags or re.search(r"\bos\.Args\b", f.code):
                ctx.add(f, "cli", [], posixpath.basename(posixpath.dirname(f.rel)) or "main", "main", main[2], "flag" if flags else "os.Args",
                        [] if any(e.file == f.rel and e.kind == "http" for e in ctx.entries) else [(f.rel, main[2], main[3])],
                        [Param(x, "arg") for x in flags] or [Param("os.Args", "arg")], scan=False)


# =========================================================================================================== PHP extractor
_LARAVEL_VERBS = ("get", "post", "put", "patch", "delete", "options", "any", "match", "resource", "apiResource", "view",
                  "redirect", "resources", "apiResources")
_RESOURCE_ACTIONS = (("index", "GET", ""), ("create", "GET", "/create"), ("store", "POST", ""), ("show", "GET", "/{id}"),
                     ("edit", "GET", "/{id}/edit"), ("update", "PUT", "/{id}"), ("destroy", "DELETE", "/{id}"))


def _php_strings(text: str) -> list:
    return [m.group(2) for m in _STR_RE.finditer(text)]


class _Php:
    """Laravel routes, Symfony attribute / annotation routes, plain PHP scripts, console commands."""

    def __init__(self, ctx: _Ctx):
        self.ctx = ctx
        self.files = ctx.lang("php")
        self.access: list = []      # Symfony security.yaml access_control [(path regex, roles text, is_public)]
        self.claimed: set = set()   # files that hold framework code (not plain scripts)

    def run(self):
        for rel, text in self.ctx.config.items():
            if posixpath.basename(rel) in ("security.yaml", "security.yml"):
                for m in re.finditer(r"-[ \t]*\{([^{}\n]{0,600})\}", text):      # bounded: no quadratic scan
                    pm = re.search(r"\bpath\s*:\s*['\"]?([^,'\"}]+)", m.group(1))
                    rm = re.search(r"\broles?\s*:\s*(\[[^\]]*\]|[^,}]+)", m.group(1))
                    if pm and rm:
                        roles = rm.group(1).strip()
                        self.access.append((pm.group(1).strip(), roles,
                                            bool(re.search(r"PUBLIC_ACCESS|IS_AUTHENTICATED_ANONYMOUSLY", roles))))
        for f in self.files:
            if "/vendor/" in "/" + f.rel:
                continue
            if "Route::" in f.text:
                self.laravel(f)
            if re.search(r"#\[\s*Route\b|@Route\s*\(", f.text):
                self.symfony(f)
            self.console(f)
        for f in self.files:
            if "/vendor/" not in "/" + f.rel:
                self.script(f)

    # ------------------------------------------------------------------ Laravel
    def laravel(self, f: _File):
        self.claimed.add(f.rel)
        bare = f.bare
        base = ["api"] if re.search(r"(?:^|/)routes/api\.php$", f.rel) else []
        groups: list = []            # (start, end, prefix, guards, controller)
        pos = 0
        while True:
            i = bare.find("Route::", pos)
            if i < 0:
                break
            pos = i + 7
            chain, p = [], i + 7
            while True:
                m = re.compile(r"\s*(\w+)\s*\(").match(bare, p)
                if not m:
                    break
                k = _close(bare, m.end() - 1)
                if k < 0:
                    break
                chain.append((m.group(1), m.end() - 1, k))
                nxt = re.compile(r"\s*->").match(bare, k + 1)
                if not nxt:
                    break
                p = nxt.end()
            if not chain:
                continue
            groups[:] = [g for g in groups if g[1] > i]     # calls are visited in order: closed groups are done
            enclosing = sorted([g for g in groups if g[0] < i < g[1]], key=lambda g: g[0])
            prefix = base + [g[2] for g in enclosing if g[2]]
            guards = []
            controller = next((g[4] for g in reversed(enclosing) if g[4]), None)
            mods = {"prefix": [], "mw": [], "without": [], "only": None, "except": None, "controller": None}
            route = None
            for name, o, k in chain:
                text = f.code[o + 1:k]
                if name == "prefix":
                    mods["prefix"].append(_first_str(text) or "")
                elif name in ("middleware", "can"):
                    mods["mw"] += [("can:" + s) if name == "can" else s for s in _php_strings(text)]
                    mods["mw"] += re.findall(r"([\w\\]+)::class", text)
                elif name == "withoutMiddleware":
                    mods["without"] += _php_strings(text)
                elif name == "controller":
                    cm = re.search(r"([\w\\]+)::class", text)
                    mods["controller"] = cm.group(1).split("\\")[-1] if cm else None
                elif name in ("only", "except"):
                    mods[name] = _php_strings(text)
                elif name == "group":
                    args = _split_top(bare, o + 1, k)
                    if args and f.code[args[0][0]:args[0][1]].lstrip().startswith("["):
                        arr = f.code[args[0][0]:args[0][1]]
                        pm = re.search(r"['\"]prefix['\"]\s*=>\s*(['\"])(.*?)\1", arr)
                        if pm:
                            mods["prefix"].append(pm.group(2))
                        mm = re.search(r"['\"]middleware['\"]\s*=>\s*(\[[^\]]*\]|['\"][^'\"]*['\"])", arr)
                        if mm:
                            mods["mw"] += _php_strings(mm.group(1))
                    blk = _block_after(bare, args[-1][0], 300) if args else None
                    if blk and len(groups) < _MAX_NESTING:
                        groups.append((blk[0], blk[1], _join_path(*mods["prefix"]).strip("/") if mods["prefix"] else "",
                                       _guards_from(mods["mw"], "middleware"), mods["controller"]))
                    route = None
                    break
                elif name in _LARAVEL_VERBS and route is None:
                    route = (name, o, k)
            for g in reversed(enclosing):
                guards += g[3]
            if route is None:
                continue
            own = _guards_from(mods["mw"], "middleware")
            if any(_guard(w, "middleware") for w in mods["without"]):
                own.insert(0, ("withoutMiddleware(" + ",".join(mods["without"]) + ")", "middleware", True))
            self.laravel_route(f, route, prefix + mods["prefix"], own + guards, mods, mods["controller"] or controller, i)

    def laravel_route(self, f: _File, route: tuple, prefix: list, guards: list, mods: dict, controller, pos: int):
        ctx = self.ctx
        verb, o, k = route
        args = _split_top(f.bare, o + 1, k)
        if not args:
            return
        line = f.lines.of(pos)
        if verb in ("resource", "apiResource"):
            name = _lit(f, *args[0])
            cm = re.search(r"([\w\\]+)::class|['\"]([\w\\]+)['\"]", f.code[args[1][0]:args[1][1]]) if len(args) > 1 else None
            if name is None or not cm:
                return
            cname = (cm.group(1) or cm.group(2)).split("\\")[-1]
            var = "{" + re.sub(r"s$", "", name.split("/")[-1].replace("-", "_")) + "}"
            for action, method, suffix in _RESOURCE_ACTIONS:
                if verb == "apiResource" and action in ("create", "edit"):
                    continue
                if mods["only"] is not None and action not in mods["only"] or mods["except"] and action in mods["except"]:
                    continue
                hit = ctx.find_def(action, ("php",), cls=cname)
                if not hit and ctx.find_def("__construct", ("php",), cls=cname) is None and not any(
                        d[1] == cname for x in self.files for d in ctx.defs(x)):
                    hit = None
                elif not hit:
                    continue
                self.action(f, [method], _join_path(*prefix, name) + suffix.replace("{id}", var), cname, action, hit, guards, line)
            return
        methods = ["ANY"] if verb == "any" else [verb.upper()]
        pi = 0
        if verb == "match":
            methods = [s.upper() for s in _php_strings(f.code[args[0][0]:args[0][1]])] or ["ANY"]
            pi = 1
        path = _lit(f, *args[pi]) if len(args) > pi else None
        if path is None:
            return
        full = _join_path(*prefix, path)
        if verb in ("view", "redirect") or len(args) <= pi + 1:
            ctx.add(f, "http", ["GET"], full, "Route::" + verb, line, "laravel", [], guards=guards)
            return
        apiece = args[pi + 1]
        atext = f.code[apiece[0]:apiece[1]].strip()
        cm = re.match(r"\[\s*([\w\\]+)::class\s*,\s*['\"](\w+)['\"]\s*\]$", atext) or re.match(r"['\"]([\w\\]+)@(\w+)['\"]$", atext)
        if cm:
            cname = cm.group(1).split("\\")[-1]
            self.action(f, methods, full, cname, cm.group(2), ctx.find_def(cm.group(2), ("php",), cls=cname), guards, line)
        elif re.match(r"([\w\\]+)::class$", atext):
            cname = atext[:-7].split("\\")[-1]
            self.action(f, methods, full, cname, "__invoke", ctx.find_def("__invoke", ("php",), cls=cname), guards, line)
        elif _STR_RE.fullmatch(atext) and controller:
            act = _STR_RE.fullmatch(atext).group(2)
            self.action(f, methods, full, controller, act, ctx.find_def(act, ("php",), cls=controller), guards, line)
        else:
            h = _handler(ctx, f, apiece[0], apiece[1], ("php",))
            ctx.add(f, "http", methods, full, h["name"] if h["name"] != "<anonymous>" else "<closure>", line, "laravel",
                    h["spans"], guards=guards)

    def action(self, f: _File, methods, path: str, cname: str, action: str, hit, guards: list, line: int):
        spans, own = [], []
        if hit:
            xf, d = hit
            self.claimed.add(xf.rel)
            spans = [(xf.rel, d[2], d[3])]
            for m in re.finditer(r"\$this->middleware\(([^)]*)\)((?:\s*->\s*(?:only|except)\([^)]*\))?)", xf.code):
                names = _php_strings(m.group(1))
                scope = re.search(r"(only|except)\(([^)]*)\)", m.group(2))
                if scope:
                    listed = action in _php_strings(scope.group(2))
                    if (scope.group(1) == "only") != listed:
                        continue
                own += _guards_from(names, "controller middleware")
            req = re.search(r"\b(\w+Request)\s+\$\w+", d[4] or "")
            if req and req.group(1) != "Request":
                rhit = self.ctx.find_def("rules", ("php",), cls=req.group(1))
                if rhit:
                    spans.append((rhit[0].rel, rhit[1][2], rhit[1][3]))
                    ahit = self.ctx.find_def("authorize", ("php",), cls=req.group(1))
                    if ahit and not re.search(r"return\s+true\s*;", ahit[0].segment(ahit[1][2], ahit[1][3])):
                        own.append((f"{req.group(1)}::authorize()", "form request", False))
        e = self.ctx.add(hit[0] if hit else f, "http", methods, path, f"{cname}@{action}", hit[1][2] if hit else line, "laravel",
                         spans, guards=own + guards)
        if len(spans) > 1:                       # FormRequest::rules() keys are the accepted body fields
            xf = self.ctx.files[spans[1][0]]
            for k in re.finditer(r"['\"]([\w.*-]+)['\"]\s*=>", xf.segment(spans[1][1], spans[1][2])):
                if not any(p.name == k.group(1) for p in e.params):
                    e.params.append(Param(k.group(1), "body"))
            e.params = [p for p in e.params if p.name != "(body)"]

    # ------------------------------------------------------------------ Symfony
    def symfony(self, f: _File):
        ctx = self.ctx
        self.claimed.add(f.rel)
        items = _members(f, "#[")
        doc = {}                                      # declaration line -> docblock text (annotation style)
        for m in re.finditer(r"(?s)/\*\*(.*?)\*/\s*(?:(?:public|final|abstract|static)\s+)*(function\s+\w+|class\s+\w+)", f.text):
            doc[f.lines.of(m.start(2))] = m.group(1)

        def annos_of(it):
            out = list(it["annos"])
            text = doc.get(f.lines.of(it["pos"] + (len(it["header"]) - len(it["header"].lstrip()))))
            if text is None:
                hm = re.search(r"function\s+\w+|class\s+\w+", it["header"])
                text = doc.get(f.lines.of(it["pos"] + hm.start())) if hm else None
            for m in re.finditer(r"@(Route|IsGranted|Security|Method)\s*\(((?:[^()]|\([^()]*\))*)\)", text or ""):
                out.append((m.group(1), m.group(2), it["pos"]))
            return out

        for it in items:
            if it["kind"] != "member" or not it["cls"] or not it["params"]:
                continue
            annos, cannos = annos_of(it), annos_of(it["cls"])
            route = _anno(annos, "Route")
            if not route:
                continue
            base = _anno(cannos, "Route")
            path = _anno_path(route[1])
            full = _join_path(_anno_path(base[1]) if base else "", path)
            mm = re.search(r"\bmethods\s*[:=]\s*[\[{]([^\]}]*)[\]}]|\bmethods\s*[:=]\s*(['\"]\w+['\"])", route[1])
            methods = [s.upper() for s in _php_strings(mm.group(1) or mm.group(2))] if mm else \
                [s.upper() for a in annos if a[0] == "Method" for s in _php_strings(a[1])] or ["ANY"]
            guards = []
            for src in (annos, cannos):
                for name, args, _p in src:
                    if name in ("IsGranted", "Security"):
                        public = bool(re.search(r"PUBLIC_ACCESS|IS_AUTHENTICATED_ANONYMOUSLY", args))
                        guards.append((f"#[{name}({re.sub(chr(92) + 's+', ' ', args).strip()[:50]})]", "attribute", public))
            op = openapi_path(full)
            for rx, roles, public in self.access:       # first matching rule wins, as in Symfony
                if not _safe_regex(rx):
                    continue
                try:
                    if re.search(rx, op[:256]):         # Symfony applies the path regex unanchored (preg_match)
                        guards.append((f"security.yaml: {rx} -> {roles}", "config", public))
                        break
                except re.error:
                    continue
            params = []
            pv = set(_path_vars(full))
            for pannos, typ, name in _decl_params(f, it["params"], "php"):
                loc = None
                for an, _aa in pannos:
                    loc = {"MapQueryParameter": "query", "MapQueryString": "query", "MapRequestPayload": "body",
                           "MapUploadedFile": "file", "CurrentUser": "skip"}.get(an, loc)
                    if an == "CurrentUser":
                        guards.append(("#[CurrentUser]", "parameter", False))
                if loc and loc != "skip":
                    params.append(Param(name, loc, typ if loc == "body" else ""))
                elif loc is None and name in pv:
                    params.append(Param(name, "path"))
            ctx.add(f, "http", methods, full, f"{it['cls']['name']}::{it['name']}", f.lines.of(it["pos"]), "symfony",
                    [_span_of(f, it)], params, guards)

    # ------------------------------------------------------------------ console commands, plain scripts
    def console(self, f: _File):
        m = re.search(r"\bprotected\s+(?:static\s+)?\$(?:signature|defaultName)\s*=\s*(['\"])(.*?)\1", f.code, re.S) or \
            re.search(r"#\[\s*AsCommand\s*\(\s*(?:name\s*:\s*)?(['\"])(.*?)\1", f.code)
        if not m or not re.search(r"\bextends\s+\w*Command\b", f.code):
            return
        self.claimed.add(f.rel)
        sig = m.group(2).split()
        hit = next((d for d in self.ctx.defs(f) if d[0] in ("handle", "execute", "__invoke")), None)
        params = [Param(re.sub(r"[{}?*=].*$|^--", "", x.strip("{}")).strip("-") or x, "arg") for x in sig[1:] if x.startswith("{")]
        self.ctx.add(f, "cli", [], sig[0] if sig else posixpath.basename(f.rel), hit[0] if hit else "handle", hit[2] if hit else 1,
                     "laravel-artisan" if "signature" in m.group(0) else "symfony-console",
                     [(f.rel, hit[2], hit[3])] if hit else [], params, scan=False)

    def script(self, f: _File):
        if f.rel in self.claimed or any(e.file == f.rel for e in self.ctx.entries):
            return
        code = f.code
        globs = set(re.findall(r"\$_(GET|POST|REQUEST|COOKIE|FILES)\b", code))
        if re.search(r"php://input|\$_SERVER\[\s*['\"](?:HTTP_\w+|REQUEST_URI|QUERY_STRING|PATH_INFO)['\"]", code):
            globs.add("SERVER")
        if not globs:
            if re.search(r"\$argv\b|\$_SERVER\[\s*['\"]argv['\"]\]|\bgetopt\s*\(", code):
                self.ctx.add(f, "cli", [], posixpath.basename(f.rel), "<script>", 1, "php-cli", [(f.rel, 1, len(f.lines.starts))],
                             [Param("argv", "arg")], module_level=True, scan=False)
            return
        if re.search(r"^\s*(?:namespace\s|(?:final\s+|abstract\s+)?class\s)", code, re.M) and not re.search(
                r"(?m)^\s*(?:echo|print|header|require|include|if|\$\w+\s*=)\b", _strip_blocks(f)):
            return                                      # a class file: reached through a framework, not directly
        methods = sorted({"GET"} & globs | ({"POST"} if globs & {"POST", "FILES"} else set()))
        if "REQUEST" in globs or not methods:
            methods = ["ANY"]
        self.ctx.add(f, "http", methods, "/" + f.rel, "<script>", 1, "php", [(f.rel, 1, len(f.lines.starts))], module_level=True)


def _strip_blocks(f: _File) -> str:
    """The file's top-level code: bodies of classes and functions removed."""
    out, pos = [], 0
    for m in re.finditer(r"\b(?:class|trait|interface|function)\b[^{;]*\{", f.bare):
        if m.start() < pos:
            continue
        k = _close(f.bare, m.end() - 1)
        if k < 0:
            break
        out.append(f.code[pos:m.start()])
        pos = k + 1
    out.append(f.code[pos:])
    return "".join(out)


# ========================================================================================================== Ruby extractor
_RAILS_ACTIONS = (("index", "GET", False, ""), ("new", "GET", False, "/new"), ("create", "POST", False, ""),
                  ("show", "GET", True, ""), ("edit", "GET", True, "/edit"), ("update", "PATCH", True, ""),
                  ("destroy", "DELETE", True, ""))
_RB_VERB = r"(get|post|put|patch|delete|match|root)"


def _rb_syms(text: str) -> list:
    return re.findall(r":(\w+[?!]?)|['\"]([\w/#-]+)['\"]", text)


def _rb_list(text: str, key: str):
    m = re.search(r"\b" + key + r":\s*(\[[^\]]*\]|%i\[[^\]]*\]|:\w+|['\"]\w+['\"])", text)
    if not m:
        return None
    if m.group(1).startswith("%i"):
        return m.group(1)[3:-1].split()
    return [a or b for a, b in _rb_syms(m.group(1))]


class _Rb:
    """Rails ``routes.rb`` + controllers, Sinatra, Sidekiq / ActiveJob workers, rake tasks."""

    def __init__(self, ctx: _Ctx):
        self.ctx = ctx
        self.files = ctx.lang("ruby")

    def run(self):
        for f in self.files:
            if re.search(r"(?:^|/)routes(?:\.rb|/[\w-]+\.rb)$", f.rel) and re.search(r"\.routes\.draw\b|^\s*(?:resources?|namespace|scope)\b", f.code, re.M):
                self.routes(f)
            elif re.search(r"\bsinatra\b|Sinatra::", f.text):
                self.sinatra(f)
            self.jobs(f)

    # ------------------------------------------------------------------ Rails
    def controller(self, modules: list, name: str):
        want = "/".join([m for m in modules if m] + [name + "_controller.rb"])
        best = None
        for x in self.files:
            if x.rel.endswith("/" + want) or x.rel == want:
                return x
            if x.rel.endswith("/" + name + "_controller.rb") or x.rel == name + "_controller.rb":
                best = best or x
        return best

    def filters(self, xf: _File, action: str, depth: int = 0) -> list:
        """Guards from ``before_action`` / ``skip_before_action`` of a controller and its ancestors (nearest first)."""
        out = []
        for m in re.finditer(r"(?m)^\s*(skip_)?(?:before_action|before_filter|prepend_before_action)\s+(.*)$", xf.code):
            rest = m.group(2)
            only, exc = _rb_list(rest, "only"), _rb_list(rest, "except")
            if only is not None and action not in only or exc is not None and action in exc:
                continue
            names = re.findall(r"(?<![\w:]):(\w+[?!]?)(?!\s*:)", re.split(r"\b(?:only|except|if|unless):", rest)[0])
            for n in names:
                g = _guard(n, "before_action")
                if g:
                    out.append((("skip_before_action :" if m.group(1) else "before_action :") + n, "before_action", bool(m.group(1))))
        for m in re.finditer(r"(?m)^\s*(http_basic_authenticate_with|authorize_resource|load_and_authorize_resource|"
                             r"doorkeeper_authorize!|authenticate_user!)\b(.*)$", xf.code):
            only, exc = _rb_list(m.group(2), "only"), _rb_list(m.group(2), "except")
            if not (only is not None and action not in only or exc is not None and action in exc):
                out.append((m.group(1), "controller", False))
        skips = [g for g in out if g[2]]
        out = skips + [g for g in out if not g[2]]
        pm = re.search(r"(?m)^\s*class\s+[\w:]+\s*<\s*([\w:]+)", xf.code)
        if pm and depth < 5:
            parent = pm.group(1).split("::")
            snake = re.sub(r"(?<!^)(?=[A-Z])", "_", re.sub(r"Controller$", "", parent[-1])).lower()
            pf = self.controller([re.sub(r"(?<!^)(?=[A-Z])", "_", p).lower() for p in parent[:-1]], snake)
            if pf and pf is not xf:
                out += self.filters(pf, action, depth + 1)
        return out

    def add_action(self, f: _File, methods, path: str, modules: list, ctrl: str, action: str, line: int, extra=()):
        ctx = self.ctx
        xf = self.controller(modules, ctrl)
        label = "/".join([m for m in modules if m] + [ctrl]) + "#" + action
        if not xf:
            ctx.add(f, "http", methods, path, label, line, "rails", [], guards=list(extra))
            return
        d = next((x for x in ctx.defs(xf) if x[0] == action), None)
        if not d:
            return                                   # the route points at an action the controller does not define
        spans = [(xf.rel, d[2], d[3])]
        body = xf.segment(d[2], d[3])
        for h in ctx.defs(xf):                        # one level of private helpers (strong parameters, finders)
            if h is not d and re.search(r"\b" + re.escape(h[0]) + r"\b", body) and len(spans) < 6:
                spans.append((xf.rel, h[2], h[3]))
        ctx.add(xf, "http", methods, path, label, d[2], "rails", spans, guards=self.filters(xf, action) + list(extra))

    def routes(self, f: _File):
        stack: list = []      # frames: {"path", "module", "ctrl", "kind", "guards"}
        overflow = 0
        lines = f.code.split("\n")

        def cur(key):
            return [fr[key] for fr in stack if fr.get(key)]

        def ctrl():
            return next((fr["ctrl"] for fr in reversed(stack) if fr.get("ctrl")), None)

        for i, raw in enumerate(lines):
            line = raw.strip()
            if not line:
                continue
            opens = bool(re.search(r"\bdo\s*(\|[^|]*\|)?\s*$", line))
            ln = i + 1
            guards = [g for fr in stack for g in fr.get("guards", [])]
            base = _join_path(*cur("path")) if cur("path") else ""
            frame = {"kind": "block"}
            if re.match(r"end\b", line):
                if overflow:
                    overflow -= 1
                elif stack:
                    stack.pop()
                continue
            m = re.match(r"namespace\s+:?['\"]?([\w/]+)", line)
            if m:
                frame = {"path": m.group(1), "module": m.group(1), "kind": "ns"}
            elif re.match(r"scope\b", line):
                pm = re.match(r"scope\s*\(?\s*(?:path:\s*)?['\"]([^'\"]*)['\"]", line) or re.match(r"scope\s*\(?\s*:(\w+)", line) or \
                    re.search(r"\bpath:\s*['\"]([^'\"]*)['\"]", line)
                mm = re.search(r"\bmodule:\s*[:'\"]([\w/]+)", line)
                frame = {"path": pm.group(1) if pm else "", "module": mm.group(1) if mm else "", "kind": "scope"}
            elif re.match(r"(?:authenticate|authenticated)\b", line):
                frame = {"kind": "auth", "guards": [("routes: " + line.split(" do")[0], "routes", False)]}
            elif re.match(r"constraints\b", line) and _is_auth_name(line):
                frame = {"kind": "auth", "guards": [("routes: " + line.split(" do")[0][:60], "routes", False)]}
            elif re.match(r"(member|collection)\b", line):
                frame = {"kind": line.split()[0]}
            elif re.match(r"resources?\b", line):
                rm = re.match(r"(resources?)\s+(.*?)(?:\s+do\b.*)?$", line)
                plural = rm.group(1) == "resources"
                head = re.split(r",\s*(?=\w+:)", rm.group(2), maxsplit=1)
                names = [a or b for a, b in _rb_syms(head[0])]
                opts = head[1] if len(head) > 1 else ""
                only, exc = _rb_list(opts, "only"), _rb_list(opts, "except")
                cm = re.search(r"\bcontroller:\s*[:'\"]([\w/]+)", opts)
                pm = re.search(r"\bpath:\s*['\"]([^'\"]*)", opts)
                parent_member = any(fr["kind"] in ("resources",) for fr in stack[-1:])
                for name in names:
                    c = cm.group(1) if cm else (name if plural else name + "s")
                    seg = pm.group(1) if pm else name
                    rbase = _join_path(base, stack[-1]["member"], seg) if parent_member and stack[-1].get("member") else _join_path(base, seg)
                    idv = ":id" if plural else ""
                    for action, verb, member, suffix in _RAILS_ACTIONS:
                        if not plural and action == "index":
                            continue
                        if only is not None and action not in only or exc is not None and action in exc:
                            continue
                        path = (rbase + ("/" + idv if member and idv else "") + suffix)
                        self.add_action(f, [verb], path, cur("module"), c, action, ln, guards)
                    single = re.sub(r"s$", "", name)
                    frame = {"kind": "resources", "ctrl": c, "base": rbase, "member": (":" + single + "_id") if plural else "",
                             "idpath": rbase + ("/:id" if plural else ""), "path": "", "module": ""}
                    if parent_member and stack[-1].get("member"):
                        frame["path"] = _join_path(stack[-1]["member"], seg)
                    else:
                        frame["path"] = seg
            elif re.match(r"mount\b", line):
                mm = re.match(r"mount\s+([\w:.]+)(?:\s*=>\s*|\s*,\s*at:\s*)['\"]([^'\"]+)", line)
                if mm:
                    self.ctx.add(f, "http", ["ANY"], _join_path(base, mm.group(2)), mm.group(1), ln, "rails-mount", [], guards=guards)
            else:
                vm = re.match(_RB_VERB + r"\b\s*\(?\s*(.*)$", line)
                if vm:
                    verb, rest = vm.group(1), vm.group(2)
                    rest = re.sub(r"\s+do\b.*$", "", rest)
                    to = re.search(r"(?:\bto:\s*|=>\s*)['\"]([\w/]+)#(\w+)['\"]", rest) or re.match(r"['\"]([\w/]+)#(\w+)['\"]", rest)
                    pm = re.match(r"['\"]([^'\"]*)['\"]|:(\w+)", rest)
                    path = "" if verb == "root" else ((pm.group(1) if pm.group(1) is not None else pm.group(2)) if pm else "")
                    if to and pm and pm.group(1) and "#" in pm.group(1) and verb != "root":
                        path = pm.group(1)
                    via = _rb_list(rest, "via")
                    methods = ["GET"] if verb == "root" else [v.upper() for v in via] if verb == "match" and via else \
                        ["ANY"] if verb == "match" else [verb.upper()]
                    kind = stack[-1]["kind"] if stack else ""
                    res = next((fr for fr in reversed(stack) if fr["kind"] == "resources"), None)
                    on = re.search(r"\bon:\s*:(\w+)", rest)
                    if res and (kind in ("member", "collection") or on or (kind == "resources" and not to)):
                        member = kind == "member" or (on and on.group(1) == "member")
                        outer = _join_path(*[fr["path"] for fr in stack[:stack.index(res)] if fr.get("path")]) if stack.index(res) else ""
                        rb = _join_path(outer, res["path"]) if outer else _join_path(res["path"])
                        full = _join_path(rb, ":id" if member and res["member"] else "", path)
                    else:
                        full = _join_path(base, path) if (base or path) else "/"
                    if to:
                        mods, c = cur("module") + to.group(1).split("/")[:-1], to.group(1).split("/")[-1]
                        self.add_action(f, methods, full, mods, c, to.group(2), ln, guards)
                    else:
                        cm = re.search(r"\bcontroller:\s*[:'\"]([\w/]+)", rest)
                        am = re.search(r"\baction:\s*[:'\"](\w+)", rest)
                        c = cm.group(1) if cm else ctrl()
                        act = am.group(1) if am else re.sub(r"\W", "_", path.strip("/").split("/")[-1]) if path else ""
                        if c and act:
                            self.add_action(f, methods, full, cur("module"), c, act, ln, guards)
            if opens and len(stack) >= _MAX_NESTING:
                overflow += 1                   # absurd nesting (hostile or generated): keep the block balance only
            elif opens:
                frame.setdefault("path", "")
                frame.setdefault("module", "")
                stack.append(frame)

    # ------------------------------------------------------------------ Sinatra
    def sinatra(self, f: _File):
        lines = f.code.split("\n")
        guards = []
        for i, line in enumerate(lines):
            if re.match(r"\s*before\b.*\bdo\b", line):
                body = "\n".join(lines[i:_ruby_end(lines, i)])
                g = _inline_guards("ruby", body)
                pm = re.match(r"\s*before\s+['\"]([^'\"]+)['\"]", line)
                if g and re.search(r"\bhalt\b|\bredirect\b|protected!|authenticate|authorize", body):
                    guards.append((g[0][0].replace("inline", "before filter"), "before", False, pm.group(1) if pm else None))
            if re.match(r"\s*use\s+Rack::Auth::\w+", line):
                guards.append((line.strip().split(" do")[0], "rack middleware", False, None))
        for i, line in enumerate(lines):
            m = re.match(r"\s*(get|post|put|patch|delete|options|head)\s+(['\"])(.+?)\2(.*?)\bdo\b", line)
            if not m:
                continue
            end = _ruby_end(lines, i)
            path = m.group(3)
            own = [g[:3] for g in guards if g[3] is None or re.match(re.escape(g[3]).replace(r"\*", ".*") + "$", path)]
            cond = _guards_from(re.findall(r":?(\w+)\s*=>", m.group(4)) + re.findall(r"(\w+):\s", m.group(4)), "condition")
            self.ctx.add(f, "http", [m.group(1)], path, f"{m.group(1).upper()} {path}", i + 1, "sinatra", [(f.rel, i + 1, end)],
                         guards=cond + own)

    # ------------------------------------------------------------------ jobs, rake
    def jobs(self, f: _File):
        ctx = self.ctx
        if re.search(r"include\s+Sidekiq::(?:Worker|Job)|<\s*(?:ApplicationJob|ActiveJob::Base)|include\s+Shoryuken::Worker|@queue\s*=", f.code):
            fw = "sidekiq" if "Sidekiq" in f.code else "activejob" if "Job" in f.code else "worker"
            for d in ctx.defs(f):
                if d[0] == "perform":
                    args = [a.strip().split("=")[0].strip(" *:") for a in (d[4] or "").split(",") if a.strip()]
                    ctx.add(f, "job", [], d[1] or posixpath.basename(f.rel), f"{d[1]}#perform" if d[1] else "perform", d[2], fw,
                            [(f.rel, d[2], d[3])], [Param(a, "message") for a in args], scan=False)
        if f.rel.endswith(".rake") or posixpath.basename(f.rel) == "Rakefile":
            lines = f.code.split("\n")
            ns = []
            for i, line in enumerate(lines):
                nm = re.match(r"(\s*)namespace\s+:?['\"]?(\w+)", line)
                if nm:
                    ns = [n for n in ns if n[0] < len(nm.group(1))] + [(len(nm.group(1)), nm.group(2))]
                    continue
                m = re.match(r"(\s*)task\s+:?['\"]?(\w+)['\"]?(.*?)\bdo\b\s*(\|[^|]*\|)?", line)
                if m:
                    ns = [n for n in ns if n[0] < len(m.group(1))]
                    args = re.findall(r":(\w+)", re.search(r"\[([^\]]*)\]", m.group(3)).group(1)) if re.search(r"^\s*,\s*\[", m.group(3)) else []
                    ctx.add(f, "cli", [], ":".join([n[1] for n in ns] + [m.group(2)]), "task " + m.group(2), i + 1, "rake",
                            [(f.rel, i + 1, _ruby_end(lines, i))], [Param(a, "arg") for a in args] +
                            ([Param("ENV", "arg")] if re.search(r"\bENV\[", "\n".join(lines[i:_ruby_end(lines, i)])) else []), scan=False)


# ==================================================================== reachability: call graph, sinks, findings, stores
_CWE_CATEGORY = {
    "CWE-89": "sql", "CWE-564": "sql", "CWE-78": "command", "CWE-77": "command", "CWE-88": "command", "CWE-94": "code",
    "CWE-95": "code", "CWE-470": "code", "CWE-98": "file", "CWE-502": "deserialization", "CWE-22": "file", "CWE-23": "file",
    "CWE-36": "file", "CWE-73": "file", "CWE-434": "file", "CWE-918": "ssrf", "CWE-1336": "template", "CWE-601": "redirect",
    "CWE-943": "nosql", "CWE-90": "ldap", "CWE-643": "xml", "CWE-611": "xml", "CWE-91": "xml", "CWE-79": "xss", "CWE-80": "xss",
}
_DYN = r"[A-Za-z_$#]"
_PATTERN_SINKS = (
    ("sql", r"\b(?:execute(?:Query|Update|Sql\w*)?|executemany|rawQuery|raw|query(?:ForObject|ForList|Row)?|createQuery|"
            r"createNativeQuery|prepareStatement|FromSqlRaw|ExecuteSqlRaw|ExecuteReader|mysqli_query|pg_query|find_by_sql|"
            r"whereRaw|selectRaw|select|where|QueryRow|Query|Exec)\s*\(", True),
    ("command", r"(?:\b(?:os\.system|os\.popen|subprocess\.\w+|child_process\.\w+|execSync|spawnSync|execFile|spawn|"
                r"exec\.Command(?:Context)?|Runtime\.getRuntime\(\)\.exec|Process\.Start|shell_exec|passthru|proc_open|popen|"
                r"Open3\.\w+|IO\.popen)|(?<![.\w>])(?:exec|system))\s*\(|\bnew\s+ProcessBuilder\s*\(", False),
    ("file", r"\b(?:open|readFile(?:Sync)?|writeFile(?:Sync)?|createReadStream|sendFile|send_file|readfile|file_get_contents|"
             r"file_put_contents|fopen|unlink|ReadFile|WriteFile|os\.Open|File\.(?:read|open|write|new|delete|Delete|Open\w*|"
             r"ReadAll\w+|WriteAll\w+)|Files\.(?:read\w+|write\w+|newInputStream|newOutputStream|delete\w*|copy)|FileInputStream|FileReader|"
             r"readAllBytes|ReadAllBytes|ReadAllText)\s*\(", False),
    ("ssrf", r"\b(?:requests\.\w+|urlopen|axios(?:\.\w+)?|fetch|http\.(?:Get|Post|Head)|httpx\.\w+|curl_init|URI\.open|"
             r"Net::HTTP\.\w+|got|GetAsync|PostAsync|GetStringAsync|getForObject|postForObject|openConnection|openStream)\s*\(|"
             r"\bnew\s+URL\s*\(", False),
    ("deserialization", r"\b(?:pickle\.loads?|yaml\.(?:unsafe_)?load|unserialize|readObject|Marshal\.load|jsonpickle\.decode|"
                        r"YAML\.load|BinaryFormatter|readUnshared)\s*\(", False),
    ("template", r"\b(?:render_template_string|createTemplate|ERB\.new|from_string|renderString|Template)\s*\(", False),
    ("code", r"(?<![.\w])eval\s*\(|\bnew\s+Function\s*\(|\binstance_eval\s*\(|\bScriptEngine\b[^;\n]*\.eval\s*\(", False),
    ("redirect", r"\b(?:redirect|sendRedirect|Redirect|redirect_to|RedirectPermanent|LocalRedirect)\s*\(", False),
)
_STORE_PATTERNS = (
    (r"(?i)\b(?:from|insert\s+into|delete\s+from|join)\s+[`\"\[]?([A-Za-z_][\w.]{1,40})\b(?!\s*\()", "table:{0}"),
    (r"(?i)\bupdate\s+[`\"\[]?([A-Za-z_][\w.]{1,40})[`\"\]]?\s+set\b", "table:{0}"),
    (r"\b([A-Z]\w+)\.objects\b", "model:{0}"), (r"\bsession\.query\(\s*([A-Z]\w+)", "model:{0}"),
    (r"\b([A-Z]\w+)\.query\.(?:filter|get|all|first)", "model:{0}"),
    (r"\b([A-Z]\w+)(?:::|\.)(?:where|find|find_by\w*|findOrFail|create|all|first|firstOrCreate|destroy|joins|order|findAll|"
     r"findOne|findByPk|findById|updateOne|deleteOne|insertMany|aggregate)\b\s*\(?", "model:{0}"),
    (r"\bDB::table\(\s*['\"](\w+)", "table:{0}"), (r"\.(?:Table|collection|Collection|getCollection)\(\s*['\"](\w+)", "collection:{0}"),
    (r"\b_?(?:db|context|ctx)\w*\.([A-Z]\w+)\.(?:Where|Find\w*|Add\w*|Remove\w*|First\w*|Single\w*|ToList\w*|FromSql\w*|Any\w*)\(", "dbset:{0}"),
    (r"\b(\w+)Repo(?:sitory)?\.(?:find\w*|save\w*|delete\w*|get\w*|exists\w*)\(", "repository:{0}"),
    (r"(?i)\bredis\w*\.(?:get|set|hget|hset|setex|lpush|rpush|publish|incr|del)\b", "redis"),
    (r"\b(?:s3|S3)\w*\.(?:get_object|put_object|upload\w*|download\w*|getObject|putObject)\b", "s3"),
)
_STORE_STOP = {"select", "where", "set", "values", "the", "a", "an", "and", "or", "dual", "this", "that", "it", "here", "there",
               "File", "Files", "Path", "String", "Math", "JSON", "Object", "Array", "Promise", "Date", "Results", "Response",
               "Request", "Rails", "Route", "Process", "System", "Console", "Optional", "List", "Auth", "Gate", "Log", "Cache",
               "Storage", "Str", "Arr", "Http", "URI", "Time", "Integer", "Collections", "Arrays", "Objects", "NextResponse"}


_GENERIC_METHODS = frozenset("""get post put delete patch head options set add update save find run execute read write open
close send create load init handle process call apply start stop list query exec render index show destroy store edit
remove push pop keys values items format join split encode decode json text status end then catch map filter each
forEach next first last all count size length contains exists has put_all append insert clear copy to_s to_string
toString equals hash parse build validate check test main""".split())


def _fn_label(qual: str) -> str:
    return qual.split("::", 1)[1] if "::" in qual else qual


class _Engine:
    """Read-only view of the taint engine's program model: per-file call index, callee resolution and sink models."""

    def __init__(self, files: dict, models_dirs=None, max_depth: int = 6, projects=None):
        from . import taint
        self.taint = taint
        self.max_depth = max_depth
        if projects is not None:                 # models already built by a scan: do not analyse the project twice
            self.projects, self.flows = list(projects), [f for p in projects for f in getattr(p, "findings", [])]
        else:
            self.projects, self.flows = taint.analyze_project_full(files, models_dirs or None)
        self.calls: dict = {}       # rel -> [(line, call, proj, mod, class qual, function qual)]
        self.ranges: dict = {}      # (id(proj), qual) -> (rel, first line, last line)
        self.memo: dict = {}
        for proj in self.projects:
            for mod, file in proj.files.items():
                self.index(proj, mod, file)
        for rows in self.calls.values():
            rows.sort(key=lambda r: r[0])

    def index(self, proj, mod: str, file: dict):
        rel = file["path"]
        rows = self.calls.setdefault(rel, [])
        stack = [(file["tree"], None, None)]
        while stack:
            node, cls, fn = stack.pop()
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.ClassDef):
                    stack.append((child, f"{mod}::{child.name}", fn))
                elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    q = f"{cls}.{child.name}" if cls else f"{mod}::{child.name}"
                    first = getattr(child, "lineno", 0)
                    last = getattr(child, "end_lineno", None) or max([getattr(n, "lineno", 0) or 0 for n in ast.walk(child)] + [first])
                    self.ranges[(id(proj), q)] = (rel, first, last)
                    stack.append((child, None, q))
                else:
                    if isinstance(child, ast.Call):
                        rows.append((getattr(child, "lineno", 0) or 0, child, proj, mod, cls, fn))
                    stack.append((child, cls, fn))

    def covers(self, rel: str) -> bool:
        return rel in self.calls

    def sink(self, proj, mod: str, call: ast.Call):
        try:
            si = proj._sink_info(mod, call)
        except Exception:      # noqa: BLE001 - a model lookup must never break the map
            return None
        if not si:
            return None
        cat = _CWE_CATEGORY.get(si[5])
        if cat is None or cat == "xss":
            return None
        values = list(call.args) + [k.value for k in call.keywords]
        if not values or all(isinstance(v, ast.Constant) or (isinstance(v, (ast.List, ast.Tuple)) and
                                                             all(isinstance(x, ast.Constant) for x in v.elts)) for v in values):
            return None                                   # only literals: nothing an attacker can influence
        try:
            name = proj._canon(mod, call.func) or si[6]
        except Exception:      # noqa: BLE001
            name = si[6]
        return (cat, name, getattr(call, "lineno", 0) or 0, si[5], si[0])

    def callees(self, proj, mod: str, cls, call: ast.Call) -> list:
        out = []
        env = self.taint._Env()
        try:
            quals, _ctor = proj._callees(mod, cls, call, env)
            out = [q for q in quals if q in proj.gfuncs]
        except Exception:      # noqa: BLE001 - unresolved call: no edge
            out = []
        f = call.func
        if out and isinstance(f, ast.Attribute) and f.attr in _GENERIC_METHODS and not (
                isinstance(f.value, ast.Name) and f.value.id in ("self", "cls", "this")):
            # `request.GET.get(...)` must not resolve to the only project method that happens to be called `get`
            try:
                typed = proj._type_of(mod, cls, f.value, env) is not None
            except Exception:      # noqa: BLE001
                typed = False
            if not typed:
                out = [q for q in out if proj.gfuncs[q].get("cls") is None]
        for a in call.args:                                # function values passed as callbacks
            if isinstance(a, ast.Name):
                try:
                    q = proj._resolve_function(mod, a.id)
                except Exception:      # noqa: BLE001
                    q = None
                if q and q in proj.gfuncs and q not in out:
                    out.append(q)
        return out

    def info(self, proj, qual: str) -> tuple:
        key = (id(proj), qual)
        hit = self.memo.get(key)
        if hit is None:
            g = proj.gfuncs[qual]
            sinks, callees = [], []
            for n in ast.walk(g["node"]):
                if isinstance(n, ast.Call):
                    s = self.sink(proj, g["mod"], n)
                    if s:
                        sinks.append(s)
                    for q in self.callees(proj, g["mod"], g["cls"], n):
                        if q != qual and q not in callees:
                            callees.append(q)
            hit = self.memo[key] = (sinks, callees)
        return hit

    def reach(self, e: EntryPoint):
        """Fill ``e.sinks`` / ``e.reachable`` / ``e.edges`` from the call graph; returns the reached function ranges."""
        roots = []
        for rel, a, b in e.spans:
            rows = self.calls.get(rel, ())
            i = bisect.bisect_left(rows, a, key=lambda r: r[0])
            while i < len(rows) and rows[i][0] <= b:
                roots.append((rel, rows[i]))
                i += 1
        if e.module_level:
            roots += [(e.file, r) for r in self.calls.get(e.file, ()) if r[5] is None]
        seen_sink, queue, visited, order = set(), [], {}, []

        def add_sink(s, rel, fn_label, depth):
            key = (rel, s[2], s[0])
            if key not in seen_sink:
                seen_sink.add(key)
                e.sinks.append(Sink(s[0], s[1], rel, s[2], fn_label, depth, s[3], s[4]))

        done = set()
        for rel, (line, call, proj, mod, cls, fn) in roots:
            if id(call) in done:
                continue
            done.add(id(call))
            s = self.sink(proj, mod, call)
            if s:
                add_sink(s, rel, "", 0)
            for q in self.callees(proj, mod, cls, call):
                key = (id(proj), q)
                rng = self.ranges.get(key)
                if rng and any(rng[0] == r and a <= rng[1] <= b for r, a, b in e.spans):
                    continue                                # a closure defined inside the handler itself
                if key not in visited:
                    visited[key] = 1
                    queue.append((proj, q, 1))
                    e.edges.append(("", _fn_label(q)))
        while queue and len(visited) < 400:
            proj, q, depth = queue.pop(0)
            order.append((id(proj), q))
            sinks, callees = self.info(proj, q)
            rel = proj.gfuncs[q]["path"]
            for s in sinks:
                add_sink(s, rel, _fn_label(q), depth)
            if depth >= self.max_depth:
                continue
            for c in callees:
                key = (id(proj), c)
                if key not in visited:
                    visited[key] = depth + 1
                    queue.append((proj, c, depth + 1))
                if len(e.edges) < 400 and (_fn_label(q), _fn_label(c)) not in e.edges:
                    e.edges.append((_fn_label(q), _fn_label(c)))
        e.sinks.sort(key=lambda s: (s.depth, s.file, s.line))
        del e.sinks[60:]
        e.reachable = [_fn_label(q) for _pid, q in order][:60]
        return [self.ranges[k] for k in order if k in self.ranges]


def _pattern_sinks(ctx: _Ctx, e: EntryPoint):
    """Textual fallback (engine disabled or file not analysed): dangerous calls with a non-literal argument that
    appear in the handler body itself."""
    seen = set()
    for rel, a, b in e.spans:
        f = ctx.files.get(rel)
        if not f:
            continue
        seg = f.segment(a, b)
        if not ctx.take(len(seg)):
            continue
        code, bare = _mask(seg, f.lang)
        for cat, rx, need_concat in _PATTERN_SINKS:
            for m in re.finditer(rx, bare):
                o = bare.find("(", m.start(), m.end() + 1)
                k = _close(bare, o) if o >= 0 else -1
                args = bare[o + 1:k] if k > 0 else bare[m.end():m.end() + 200]
                plain = re.sub(r"(['\"`])\s*\1", "", args)
                dynamic = re.search(_DYN, plain) is not None or re.search(r"[#$]\{|\$\w", code[o + 1:k] if k > 0 else "") is not None
                if not dynamic:
                    continue
                if need_concat and not re.search(r"(?i)\b(select|insert|update|delete)\b", code[o + 1:k] if k > 0 else "") and \
                        m.group(0).rstrip("( ").split(".")[-1] in ("select", "where", "raw", "Query", "Exec", "query"):
                    continue
                line = a + bare.count("\n", 0, m.start())
                if (rel, line, cat) not in seen:
                    seen.add((rel, line, cat))
                    e.sinks.append(Sink(cat, re.sub(r"\s*\($", "", m.group(0)).strip(), rel, line, "", 0, "", "", "pattern"))


def _stores(ctx: _Ctx, e: EntryPoint, ranges: list):
    found = []
    for rel, a, b in list(e.spans) + list(ranges)[:30]:
        f = ctx.files.get(rel)
        if not f:
            continue
        seg = f.segment(a, b)
        if not ctx.take(len(seg)):
            continue
        for rx, fmt in _STORE_PATTERNS:
            for m in re.finditer(rx, seg):
                name = m.group(1) if m.groups() else ""
                if name in _STORE_STOP or name.lower() in _STORE_STOP or (name and len(name) < 2):
                    continue
                label = fmt.format(name)
                if label not in found:
                    found.append(label)
    e.stores = found[:12]


def _norm_findings(findings) -> list:
    """Findings (``model.Finding`` objects or their ``to_dict()`` form) reduced to what the map needs."""
    out = []
    findings = list(findings or [])
    objs = [f for f in findings if f is not None and not isinstance(f, dict)]
    if objs:
        from .model import ensure_fingerprints
        ensure_fingerprints(objs)

    def num(v) -> int:
        try:
            return int(v)
        except (TypeError, ValueError, OverflowError):
            return 0

    for f in findings:                 # the dict form may come from a saved (possibly hand-edited) report: trust no type
        if f is None:
            continue
        if isinstance(f, dict):
            extra = f.get("extra")
            d = {"fingerprint": f.get("fingerprint", ""), "rule": f.get("rule_id", ""), "severity": f.get("severity", ""),
                 "cwe": f.get("cwe", ""), "title": f.get("title", ""), "file": f.get("file", ""), "line": f.get("line", 0)}
        else:
            extra = getattr(f, "extra", None)
            d = {"fingerprint": f.fingerprint(), "rule": f.rule_id, "severity": f.severity, "cwe": f.cwe, "title": f.title,
                 "file": f.file, "line": f.line}
        extra = extra if isinstance(extra, dict) else {}
        d = {k: (num(v) if k == "line" else "" if v is None else str(v)) for k, v in d.items()}
        d["file"] = d["file"].replace("\\", "/")
        path = extra.get("path") if isinstance(extra.get("path"), list) else []
        if not path and extra.get("analysis") not in ("taint", "dataflow") and not d["rule"].startswith("DF"):
            continue                                       # only data-flow findings are linked to entry points
        locs = [(str(st.get("file") or d["file"]).replace("\\", "/"), num(st.get("line", 0))) for st in path
                if isinstance(st, dict)]
        d["_locs"] = locs + [(d["file"], d["line"])]
        d["_sink"] = locs[-1] if locs else (d["file"], d["line"])
        out.append(d)
    return out


def _link_findings(e: EntryPoint, findings: list, ranges: list):
    for d in findings:
        direct = any(rel == r and a <= line <= b for rel, line in d["_locs"] for r, a, b in e.spans)
        indirect = not direct and any(rel == r and a <= line <= b for rel, line in d["_locs"] for r, a, b in ranges)
        if not (direct or indirect):
            continue
        e.findings.append({k: v for k, v in d.items() if not k.startswith("_")} | {"direct": direct})
        hit = False
        for s in e.sinks:
            if (s.file, s.line) in (d["_sink"], (d["file"], d["line"])):
                s.proven = hit = True
        cat = _CWE_CATEGORY.get(d["cwe"])
        if direct and not hit and cat:
            e.sinks.append(Sink(cat, d["title"][:60], d["_sink"][0], d["_sink"][1], "", 0, d["cwe"], d["rule"], "finding", True))
    e.findings.sort(key=lambda d: (not d["direct"], d["file"], d["line"]))


_LEVELS = ("critical", "high", "medium", "low")


def _rank(e: EntryPoint):
    score, reasons = 0.0, []
    status = e.auth.get("status")
    unauth = status != "protected"
    direct = [d for d in e.findings if d["direct"]]
    strong = [d for d in direct if d.get("severity") in ("critical", "high")]
    indirect = [d for d in e.findings if not d["direct"]]
    cats = [c for c in e.sink_categories if c != "xss"]
    if direct:
        score += (45 if strong else 20) + min(15, 5 * (len(direct) - 1))
        reasons.append(("r_finding", {"n": len(direct)}))
    elif indirect:
        score += 12
        reasons.append(("r_finding_indirect", {"n": len(indirect)}))
    if cats:
        score += 25 + min(10, 3 * (len(cats) - 1))
        reasons.append(("r_sink", {"cats": ", ".join(cats)}))
    if e.kind == "http":
        if status == "none":
            score += 30
            reasons.append(("r_unauth", {}))
        elif status == "public":
            score += 28
            reasons.append(("r_public", {}))
        if unauth and set(e.methods) & {"POST", "PUT", "PATCH", "DELETE"}:
            score += 4
            reasons.append(("r_write", {}))
    if e.params:
        score += min(len(e.params), 5)
        reasons.append(("r_params", {"n": len(e.params)}))
    if e.kind in ("cli", "job"):
        score *= 0.5
        reasons.append(("r_local", {"kind": e.kind}))
        level = "medium" if direct or cats else "low"
    elif e.kind == "consumer":
        score *= 0.8
        level = "high" if strong else "medium" if cats or e.findings else "low"
    elif unauth and strong:
        level = "critical"
    elif (unauth and (cats or direct)) or strong:
        level = "high"
    elif cats or e.findings or (unauth and e.params):
        level = "medium"
    else:
        level = "low"
    e.risk = int(round(min(score, 130.0) / 130.0 * 100))
    e.risk_level = level
    e.reasons = reasons


# ============================================================================================================ public API
_EXTRACTORS = (("python", "_Py"), ("javascript", "_Js"), ("java/kotlin", "_Jvm"), ("csharp", "_Cs"), ("go", "_Go"),
               ("php", "_Php"), ("ruby", "_Rb"))


def build_surface_from_files(files: dict, findings=None, models_dirs=None, engine: bool = True, max_depth: int = 6,
                             include_tests: bool = False, root: str = "", projects=None, _skipped: int = 0) -> Surface:
    """Build the attack-surface map from in-memory sources.

    ``files`` maps a relative POSIX path to its text (source files plus, optionally, ``web.xml`` / ``security.yaml``).
    ``findings`` (optional) is the finding list of a scan that already ran (``model.Finding`` objects or their
    ``to_dict()`` form): passing it keeps the fingerprints identical to the report; without it the taint engine's
    own findings are used. ``engine=False`` skips the data-flow engine (fast; sinks then come from textual patterns
    in the handler body and nothing is "proven"). ``projects`` (optional) are the ``taint.Project`` models a scan
    already built (``taint.analyze_project_full(files)[0]``): they are reused instead of analysing the project a
    second time (pass ``findings`` too). Nothing is executed and no network access is made."""
    import hashlib
    files = {str(rel).replace("\\", "/"): text for rel, text in files.items() if isinstance(text, str)}
    config = {rel: text for rel, text in files.items()
              if posixpath.basename(rel) in CONFIG_NAMES and len(text) <= MAX_SOURCE_BYTES}
    wanted = {rel: text for rel, text in files.items() if _language(rel) and (include_tests or not _TEST_PATH_RE.search(rel))}
    sources = {rel: text for rel, text in wanted.items() if len(text) <= MAX_SOURCE_BYTES}
    ctx = _Ctx(sources, config)
    surface = Surface(root=root, files_read=len(sources))
    skipped = len(wanted) - len(sources) + max(0, int(_skipped))
    if skipped:
        surface.notes.append(("note_skipped", {"n": skipped, "mb": MAX_SOURCE_BYTES // (1024 * 1024)}))
    g = globals()
    for name, cls in _EXTRACTORS:
        try:
            g[cls](ctx).run()
        except _Limit:
            surface.notes.append(("note_limit", {"n": MAX_ENTRIES}))
            break
        except Exception as exc:      # noqa: BLE001 - one broken extractor must not hide the other languages
            surface.notes.append(("note_extractor", {"name": name, "err": f"{type(exc).__name__}: {exc}"[:120]}))
    _MATCH_CACHE.clear()
    if ctx.unparsed:
        surface.notes.append(("note_unparsed", {"n": len(ctx.unparsed), "file": ctx.unparsed[0][:120]}))
    entries, seen = [], set()
    for e in ctx.entries:
        key = (e.kind, tuple(e.methods), e.path, e.file, e.handler)
        if key in seen:
            continue
        seen.add(key)
        if e.kind == "http" and set(e.methods) & {"GET", "HEAD", "OPTIONS", "ANY"}:
            # DRF IsAuthenticatedOrReadOnly / DjangoModelPermissionsOrAnonReadOnly: safe methods are open to anyone
            e.guards = [(g[0], g[1], True) + tuple(g[3:]) if _READONLY_PUBLIC_RE.search(g[0]) else g for g in e.guards]
        e.auth = _auth_from_guards(e.guards)
        e.id = "EP" + hashlib.sha256("\x00".join([e.kind, e.method, e.path, e.file, e.handler]).encode("utf-8")).hexdigest()[:10]
        entries.append(e)
    eng = None
    if engine and entries:
        try:
            eng = _Engine(sources, models_dirs, max_depth, projects)
        except Exception as exc:      # noqa: BLE001 - the map is still useful without the call graph
            surface.notes.append(("note_engine_failed", {"err": f"{type(exc).__name__}: {exc}"[:120]}))
    elif not engine:
        surface.notes.append(("note_engine_off", {}))
    linked = _norm_findings(findings if findings is not None else (eng.flows if eng else []))
    for e in entries:
        ranges = []
        if eng is not None and any(eng.covers(rel) for rel, _a, _b in e.spans):
            try:
                ranges = eng.reach(e)
                if e.language not in ("python", "javascript") and not any(s.depth == 0 for s in e.sinks):
                    _pattern_sinks(ctx, e)                  # the lowering frontends miss some constructs (attributes, closures)
            except Exception:      # noqa: BLE001 - fall back to the textual patterns for this entry
                e.sinks, e.reachable, e.edges = [], [], []
                _pattern_sinks(ctx, e)
        else:
            _pattern_sinks(ctx, e)
        _link_findings(e, linked, ranges)
        _stores(ctx, e, ranges)
        _rank(e)
    if ctx.exhausted:
        surface.notes.append(("note_budget", {}))
    entries.sort(key=lambda e: (_LEVELS.index(e.risk_level), -e.risk, e.kind != "http", e.path, e.method, e.file, e.line))
    surface.entries = entries
    return surface


def build_surface(root, findings=None, excludes=(), models_dirs=None, engine: bool = True, max_depth: int = 6,
                  include_tests: bool = False) -> Surface:
    """Build the attack-surface map of a directory (or a single source file). See ``build_surface_from_files``.

    Files are enumerated like a normal scan (same skipped directories, ``excludes`` are glob patterns)."""
    from .scanner import iter_files
    root = pathlib.Path(root)
    files = {}
    skipped = 0
    for p, rel in iter_files(root, list(excludes or ())):
        low = p.name.lower()
        if not (low.endswith(SOURCE_EXTS) or p.name in CONFIG_NAMES) or low.endswith((".min.js", ".d.ts")):
            continue
        try:
            if p.stat().st_size > MAX_SOURCE_BYTES:
                skipped += low.endswith(SOURCE_EXTS)
                continue
            files[str(rel).replace("\\", "/")] = p.read_text("utf-8", errors="replace")
        except (OSError, ValueError):
            continue
    return build_surface_from_files(files, findings, models_dirs, engine, max_depth, include_tests, root=str(root),
                                    _skipped=skipped)


# ============================================================================================================== renderers
def _auth_text(e: EntryPoint, lang: str) -> str:
    status = e.auth.get("status", "none")
    if e.kind in ("cli", "job") and status == "none":
        return _t(lang, "none")
    names = ", ".join(g["name"] for g in e.auth.get("guards", [])[:3])
    label = _t(lang, "auth_" + status)
    return f"{label}: {names}" if names else label


def _params_text(e: EntryPoint, limit: int = 8) -> str:
    items = [f"{p.name} ({p.location})" for p in e.params[:limit]]
    if len(e.params) > limit:
        items.append(f"+{len(e.params) - limit}")
    return ", ".join(items)


def _sinks_text(e: EntryPoint) -> str:
    out = []
    for c in e.sink_categories:
        n = sum(1 for s in e.sinks if s.category == c)
        proven = any(s.proven for s in e.sinks if s.category == c)
        out.append(f"{c}{'*' if proven else ''}" + (f" x{n}" if n > 1 else ""))
    return ", ".join(out)


def render_json(surface: Surface, lang: str = "en") -> str:
    """The whole map as JSON (``Surface.to_dict``)."""
    return json.dumps(surface.to_dict(lang), ensure_ascii=False, indent=2) + "\n"


_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f\u2028\u2029\u202a-\u202e\u2066-\u2069]")


def _clean(text) -> str:
    """One line, without control or bidirectional-override characters (file and route names come from the scanned
    project, which may be hostile: no forged rows, no "Trojan Source" reordering in the report)."""
    return _CTRL_RE.sub(" ", str(text).replace("\r", " ").replace("\n", " ").replace("\t", " "))


def _md(text) -> str:
    """Text placed in a Markdown table cell or list item: nothing in it can start markup, HTML or a new cell."""
    out = _clean(text).replace("\\", "\\\\").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return re.sub(r"([|`*_\[\]!#~])", r"\\\1", out)


def _mdcode(text) -> str:
    """Text placed inside a `code span` of a table cell."""
    return _clean(text).replace("`", "'").replace("|", "\\|")


def render_markdown(surface: Surface, lang: str = "en", top: int = 10) -> str:
    """A Markdown report: summary, one table row per entry point (riskiest first), details of the ``top`` riskiest."""
    t = lambda k, **kw: _t(lang, k, **kw)      # noqa: E731
    s = surface.summary()
    out = [f"# {t('title')}", "", f"_{t('intro')}_", "", f"## {t('summary')}", ""]
    out.append(f"- {t('entries')}: **{s['entries']}** ({t('http')}: {s['by_kind']['http']}, {t('cli')}: {s['by_kind']['cli']}, "
               f"{t('consumer')}: {s['by_kind']['consumer']}, {t('job')}: {s['by_kind']['job']})")
    out.append(f"- {t('unauth_sink')}: **{s['unauthenticated_reaching_sink']}**")
    out.append(f"- {t('unauth')}: {s['unauthenticated']}")
    out.append(f"- {t('with_findings')}: {s['with_findings']}")
    if s["frameworks"]:
        out.append(f"- {t('frameworks')}: " + ", ".join(f"{_md(k)} ({v})" for k, v in s["frameworks"].items()))
    for n in surface.notes_text(lang):
        out.append(f"- {t('notes')}: {_md(n)}")
    out += ["", f"## {t('entries')}", ""]
    if not surface.entries:
        return "\n".join(out + [t("no_entries"), ""])
    cols = ("col_rank", "col_risk", "col_method", "col_path", "col_handler", "col_location", "col_framework", "col_auth",
            "col_params", "col_sinks", "col_findings", "col_stores")
    out.append("| " + " | ".join(t(c) for c in cols) + " |")
    out.append("|" + "|".join("---" for _ in cols) + "|")
    for i, e in enumerate(surface.entries, 1):
        fps = ", ".join(f"`{_mdcode(d['fingerprint'])}`" if d["direct"] else f"(`{_mdcode(d['fingerprint'])}`)"
                        for d in e.findings[:4])
        if len(e.findings) > 4:
            fps += f" +{len(e.findings) - 4}"
        row = [i, f"{t('risk_' + e.risk_level)} ({e.risk})", _md(e.method) or t("kind_" + e.kind), f"`{_mdcode(e.path)}`",
               _md(e.handler), f"{_md(e.file)}:{e.line}", _md(e.framework), _md(_auth_text(e, lang)),
               _md(_params_text(e)) or t("none"),
               _md(_sinks_text(e)) or t("none"), fps or t("none"), _md(", ".join(e.stores[:5])) or t("none")]
        out.append("| " + " | ".join(str(c) for c in row) + " |")
    detail = [e for e in surface.entries if e.sinks or e.findings][:max(0, top)]
    if detail:
        out += ["", f"## {t('details')}", ""]
    for e in detail:
        out.append(f"### {(_md(e.method) + ' ') if e.method else ''}`{_mdcode(e.path)}` — {_md(e.handler)} ({_md(e.file)}:{e.line})")
        out.append("")
        out.append(f"- {t('col_risk')}: **{t('risk_' + e.risk_level)}** ({e.risk}) — " + _md("; ".join(e.reasons_text(lang))))
        out.append(f"- {t('col_auth')}: {_md(_auth_text(e, lang))}")
        if e.params:
            out.append(f"- {t('col_params')}: {_md(_params_text(e, 30))}")
        for sk in e.sinks[:12]:
            via = f" ← {_md(sk.function)}" if sk.function else ""
            out.append(f"- {t('col_sinks')}: **{_md(sk.category)}** `{_mdcode(sk.name)}` {_md(sk.file)}:{sk.line}{via}"
                       + (" ✔" if sk.proven else ""))
        for d in e.findings[:12]:
            out.append(f"- {t('col_findings')}: `{_mdcode(d['fingerprint'])}` {_md(d['rule'])} {_md(d['cwe'])} "
                       f"{_md(d['file'])}:{d['line']} — {_md(d['title'])}")
        if e.reachable:
            out.append(f"- {t('reachable')}: " + ", ".join(f"`{_mdcode(r)}`" for r in e.reachable[:15]))
        if e.stores:
            out.append(f"- {t('col_stores')}: {_md(', '.join(e.stores))}")
        out.append("")
    return "\n".join(out).rstrip("\n") + "\n"


def _csv_cell(value) -> str:
    if isinstance(value, int):
        return str(value)
    text = _clean(value)
    # no spreadsheet formula injection (OWASP "CSV Injection"): a cell must not start with = + - @ (nor after blanks)
    return "'" + text if text.lstrip()[:1] in ("=", "+", "-", "@") or text[:1] in ("\t", "\r") else text


def render_csv(surface: Surface, lang: str = "en") -> str:
    """One CSV row per entry point (riskiest first); the header is language-neutral for scripts."""
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["rank", "id", "risk", "risk_level", "kind", "method", "path", "handler", "file", "line", "framework", "language",
                "auth_status", "auth_guards", "params", "sink_categories", "sinks", "findings", "stores", "reasons"])
    for i, e in enumerate(surface.entries, 1):
        w.writerow([_csv_cell(c) for c in (
            i, e.id, e.risk, e.risk_level, e.kind, e.method, e.path, e.handler, e.file, e.line, e.framework, e.language,
            e.auth.get("status", ""), "; ".join(g["name"] for g in e.auth.get("guards", [])),
            "; ".join(f"{p.location}:{p.name}" for p in e.params), "; ".join(e.sink_categories),
            "; ".join(f"{s.category}@{s.file}:{s.line}" for s in e.sinks[:20]),
            "; ".join(d["fingerprint"] for d in e.findings), "; ".join(e.stores), "; ".join(e.reasons_text(lang)))])
    return buf.getvalue()


def _graph(surface: Surface, top: int) -> tuple:
    """(nodes {id: (kind, label, flagged)}, edges [(src, dst)], truncated) for the ``top`` riskiest entries with sinks."""
    chosen = [e for e in surface.entries if e.sinks][:max(1, top)]
    truncated = sum(1 for e in surface.entries if e.sinks) > len(chosen)
    nodes, edges, fn_ids, sink_ids = {}, [], {}, {}

    def fn(label):
        if label not in fn_ids:
            fn_ids[label] = f"f{len(fn_ids) + 1}"
            nodes[fn_ids[label]] = ("function", label, False)
        return fn_ids[label]

    for i, e in enumerate(chosen, 1):
        eid = f"e{i}"
        nodes[eid] = ("entry", f"{e.method + ' ' if e.method else ''}{e.path}\n{e.handler}", e.kind == "http" and e.unauthenticated)
        on_path = set()
        parents: dict = {}
        for a, b in e.edges:
            parents.setdefault(b, []).append(a)
        for s in e.sinks:                                  # keep only the functions that lead to a sink
            stack = [s.function]
            while stack:
                x = stack.pop()
                if x in on_path:
                    continue
                on_path.add(x)
                stack.extend(parents.get(x, []))
        for a, b in e.edges:
            if b in on_path and (a in on_path or a == ""):
                edge = (eid if a == "" else fn(a), fn(b))
                if edge not in edges:
                    edges.append(edge)
        for s in e.sinks[:15]:
            key = (s.category, s.file, s.line)
            if key not in sink_ids:
                sink_ids[key] = f"s{len(sink_ids) + 1}"
                nodes[sink_ids[key]] = ("sink", f"{s.category}: {s.name}\n{s.file}:{s.line}", s.proven)
            edge = (fn(s.function) if s.function and s.function in fn_ids else eid, sink_ids[key])
            if edge not in edges:
                edges.append(edge)
    return nodes, edges, truncated


def render_mermaid(surface: Surface, lang: str = "en", top: int = 25) -> str:
    """A Mermaid flowchart: entry point -> functions -> sinks, for the ``top`` riskiest entries that reach a sink."""
    nodes, edges, truncated = _graph(surface, top)

    def lab(text):                     # Mermaid entity codes (#NN;) for everything that has a meaning in a label
        lines = [re.sub(r"[\"`]", "'", _clean(part)) for part in text.split("\n")]
        return "<br/>".join(re.sub(r"[^\w \-./:,'()=+*@$?!~^\u0600-\u06ff]", lambda m: "#" + str(ord(m.group(0))) + ";", part)[:300]
                            for part in lines)

    out = ["flowchart LR", f"  %% {_t(lang, 'title')} - {_t(lang, 'intro')}", f"  %% {_t(lang, 'legend_unauth')}"]
    if truncated:
        out.append(f"  %% {_t(lang, 'note_truncated', n=top)}")
    for nid, (kind, label, flag) in nodes.items():
        if kind == "entry":
            out.append(f'  {nid}(["{lab(label)}"]):::{"unauth" if flag else "entry"}')
        elif kind == "function":
            out.append(f'  {nid}["{lab(label)}"]')
        else:
            out.append(f'  {nid}{{{{"{lab(label)}"}}}}:::{"proven" if flag else "sink"}')
    for a, b in edges:
        out.append(f"  {a} --> {b}")
    out += ["  classDef entry fill:#e8f0fe,stroke:#1a56db", "  classDef unauth fill:#fde8e8,stroke:#c81e1e,stroke-width:2px",
            "  classDef sink fill:#fff8e1,stroke:#b45309", "  classDef proven fill:#fde8e8,stroke:#9b1c1c,stroke-width:2px"]
    return "\n".join(out) + "\n"


def render_dot(surface: Surface, lang: str = "en", top: int = 25) -> str:
    """The same graph as ``render_mermaid`` in Graphviz DOT."""
    nodes, edges, truncated = _graph(surface, top)

    def lab(text):
        return "\\n".join(_clean(part)[:300].replace("\\", "\\\\").replace('"', '\\"') for part in text.split("\n"))

    out = ["digraph attack_surface {", "  rankdir=LR;", f'  label="{lab(_t(lang, "title"))}"; labelloc=t;',
           '  node [fontname="Helvetica", fontsize=10];']
    if truncated:
        out.append(f"  // {_t(lang, 'note_truncated', n=top)}")
    for nid, (kind, label, flag) in nodes.items():
        if kind == "entry":
            style = 'shape=box, style="rounded,filled", fillcolor="%s", color="%s"' % (("#fde8e8", "#c81e1e") if flag else ("#e8f0fe", "#1a56db"))
        elif kind == "function":
            style = "shape=box"
        else:
            style = 'shape=hexagon, style=filled, fillcolor="%s", color="%s"' % (("#fde8e8", "#9b1c1c") if flag else ("#fff8e1", "#b45309"))
        out.append(f'  {nid} [label="{lab(label)}", {style}];')
    for a, b in edges:
        out.append(f"  {a} -> {b};")
    out.append("}")
    return "\n".join(out) + "\n"


def render_openapi(surface: Surface, lang: str = "en", server_url: str | None = None, title: str | None = None) -> str:
    """An OpenAPI 3.1 skeleton (JSON) of the discovered HTTP routes, to seed a DAST tool (ZAP, Burp, Schemathesis).
    Kashif-specific facts are attached as ``x-kashif-*`` extensions. No request is ever sent."""
    paths: dict = {}
    used_ids: dict = {}
    skipped: list = []
    any_protected = False
    for e in surface.entries:
        if e.kind != "http" or e.path.startswith("(") or "#" in e.path:
            continue
        path = openapi_path(e.path)
        if not _OPENAPI_PATH_OK.match(path):               # leftovers of a route regex: not a usable path template
            skipped.append(e.path)
            continue
        tpl = re.findall(r"\{(\w+)\}", path)
        methods = []
        for m in e.methods:
            methods += ["get", "post"] if m == "ANY" else ["get"] if m == "WEBSOCKET" else [m.lower()]
        for method in methods:
            if method not in ("get", "post", "put", "delete", "patch", "head", "options", "trace"):
                continue
            item = paths.setdefault(path, {})
            if method in item:
                item[method].setdefault("x-kashif-also", []).append(f"{e.handler} ({e.file}:{e.line})")
                continue
            base = op_id = re.sub(r"\W+", "_", f"{method}_{e.handler}", flags=re.A).strip("_") or method
            while op_id in used_ids:                       # operationId MUST be unique among all operations
                used_ids[base] += 1
                op_id = f"{base}_{used_ids[base]}"
            used_ids.setdefault(base, 1)
            used_ids.setdefault(op_id, 1)
            op = {"operationId": op_id, "summary": _clean(f"{e.handler} ({e.file}:{e.line})"), "tags": [e.framework]}
            if "ANY" in e.methods:
                op["x-kashif-any-method"] = True            # the framework does not restrict the method: GET and POST listed
            params, props, form, upload = [], {}, {}, {}
            declared = set()
            for p in e.params:
                loc = p.location
                if loc == "path" and p.name not in tpl:
                    loc = "query"
                if loc == "any":
                    loc = "query" if method in ("get", "delete", "head") else "form"
                if loc in ("path", "query", "header", "cookie"):
                    if (p.name, loc) in declared or (loc == "header" and p.name.lower() in ("accept", "content-type", "authorization")):
                        continue
                    declared.add((p.name, loc))
                    params.append({"name": p.name, "in": loc, "required": loc == "path", "schema": {"type": "string"}})
                elif loc == "body" and not p.name.startswith("("):
                    props[p.name] = {"type": "object", "description": p.type} if p.type else {}
                elif loc == "form":
                    form[p.name] = {"type": "string"}
                elif loc == "file":
                    upload[p.name.strip("()") or "file"] = {"type": "string", "format": "binary"}
            for v in tpl:
                if (v, "path") not in declared:
                    params.append({"name": v, "in": "path", "required": True, "schema": {"type": "string"}})
            if params:
                op["parameters"] = params
            has_body = any(p.location in ("body", "form", "file", "any") for p in e.params)
            if method in ("post", "put", "patch") and (has_body or props or form or upload):
                content = {}
                if upload:
                    content["multipart/form-data"] = {"schema": {"type": "object", "properties": {**form, **upload}}}
                elif form and not props:
                    content["application/x-www-form-urlencoded"] = {"schema": {"type": "object", "properties": form}}
                else:
                    content["application/json"] = {"schema": {"type": "object", "properties": {**props, **form}}}
                op["requestBody"] = {"content": content}
            op["responses"] = {"default": {"description": _t(lang, "openapi_resp")}}
            if e.unauthenticated:
                op["security"] = []
            else:
                any_protected = True
                op["security"] = [{"inferredAuth": []}]
            op["x-kashif-id"] = e.id
            op["x-kashif-risk"] = {"score": e.risk, "level": e.risk_level, "reasons": e.reasons_text(lang)}
            op["x-kashif-auth"] = e.auth
            if e.sinks:
                op["x-kashif-sinks"] = e.sink_categories
            if e.findings:
                op["x-kashif-findings"] = [d["fingerprint"] for d in e.findings]
            item[method] = op
    doc = {"openapi": "3.1.0",
           "info": {"title": title or (posixpath.basename(surface.root.replace("\\", "/").rstrip("/")) or "application") + " (inferred)",
                    "version": "0.0.0", "description": _t(lang, "openapi_desc")},
           "paths": dict(sorted(paths.items()))}
    if server_url:
        doc["servers"] = [{"url": server_url}]
    if skipped:
        doc["x-kashif-skipped-paths"] = sorted(set(skipped))[:200]      # routes that are not expressible as a template
    if any_protected:
        doc["components"] = {"securitySchemes": {"inferredAuth": {"type": "http", "scheme": "bearer",
                                                                 "description": _t(lang, "openapi_auth")}}}
    return json.dumps(doc, ensure_ascii=False, indent=2) + "\n"


def render(surface: Surface, fmt: str = "markdown", lang: str = "en", top: int | None = None, server_url: str | None = None) -> str:
    """Render ``surface`` in one of ``FORMATS`` (``md`` and ``graphviz`` are accepted aliases)."""
    fmt = {"md": "markdown", "graphviz": "dot", "gv": "dot"}.get(fmt, fmt)
    if fmt == "json":
        return render_json(surface, lang)
    if fmt == "markdown":
        return render_markdown(surface, lang, 10 if top is None else top)
    if fmt == "csv":
        return render_csv(surface, lang)
    if fmt == "mermaid":
        return render_mermaid(surface, lang, 25 if top is None else top)
    if fmt == "dot":
        return render_dot(surface, lang, 25 if top is None else top)
    if fmt == "openapi":
        return render_openapi(surface, lang, server_url)
    raise ValueError(f"unknown format: {fmt}")


def main(argv=None) -> int:
    """Command line: ``python3 -m vulnscan.surface PATH [-f markdown] [-o FILE] [--lang en|ar] ...``. Exit codes:
    0 ok, 2 usage / unreadable path, 1 with ``--fail-on-unauth-sink`` when an unauthenticated entry reaches a sink."""
    import argparse
    argv = list(sys.argv[1:] if argv is None else argv)
    lang = "ar" if any(a in ("--lang=ar",) for a in argv) or ("--lang" in argv and argv[argv.index("--lang") + 1:][:1] == ["ar"]) else "en"
    ap = argparse.ArgumentParser(prog="kashif surface", description=_t(lang, "cli_desc"))
    ap.add_argument("path")
    ap.add_argument("-f", "--format", default="markdown", choices=FORMATS + ("md", "graphviz"))
    ap.add_argument("-o", "--output")
    ap.add_argument("--lang", default="en", choices=("en", "ar"))
    ap.add_argument("--exclude", action="append", default=[], metavar="GLOB")
    ap.add_argument("--models", action="append", default=[], metavar="DIR")
    ap.add_argument("--no-engine", action="store_true")
    ap.add_argument("--include-tests", action="store_true")
    ap.add_argument("--max-depth", type=int, default=6)
    ap.add_argument("--top", type=int, default=None)
    ap.add_argument("--server-url")
    ap.add_argument("--fail-on-unauth-sink", action="store_true")
    try:
        args = ap.parse_args(argv)
    except SystemExit as exc:
        return 0 if exc.code in (0, None) else 2
    root = pathlib.Path(args.path)
    if not root.exists():
        sys.stderr.write(_t(args.lang, "err_path", path=args.path) + "\n")
        return 2
    surface = build_surface(root, excludes=args.exclude, models_dirs=args.models or None, engine=not args.no_engine,
                            max_depth=max(0, args.max_depth), include_tests=args.include_tests)
    text = render(surface, args.format, args.lang, args.top, args.server_url)
    if args.output:
        try:
            pathlib.Path(args.output).write_text(text, encoding="utf-8", newline="\n")
        except OSError as exc:
            sys.stderr.write(_t(args.lang, "err_write", path=args.output, err=exc.strerror or type(exc).__name__) + "\n")
            return 2
        sys.stderr.write(_t(args.lang, "written", path=args.output) + "\n")
    else:
        try:
            sys.stdout.write(text)
        except UnicodeEncodeError:
            sys.stdout.buffer.write(text.encode("utf-8", "replace"))
    if args.fail_on_unauth_sink and any(e.kind == "http" and e.unauthenticated and e.reaches_sink for e in surface.entries):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
