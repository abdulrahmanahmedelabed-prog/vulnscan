"""DOM analysis of the page's own JavaScript (spec §2.6 WEB520–WEB522), WP12.

Burp's DOM-based family done with Kashif's own JavaScript frontend and taint engine (``js_frontend``, ``taint`` and the
bundled ``models/javascript.json``), on the scripts the scan already fetched. Nothing is executed and nothing is fetched
here: the engine filled ``ctx.pages`` and ``ctx.subresources``.

What is analysed
* **Inline scripts** of every crawled document (live ``<script>`` elements whose ``type`` is JavaScript; ``<template>``
  and ``<noscript>`` content is not live). The inline scripts of one page share the page's global scope, so they are
  analysed together as one unit (``inline/<page-slug>-<n>.js``); pages with identical inline scripts share one analysis.
* **Same-site script files** (same registrable domain, PSL) among ``ctx.subresources``: at most 15 per scan
  (:data:`MAX_FILES`), each at most 1.5 MB (:data:`MAX_FILE_BYTES`), written as ``src/<host>/<path>``.
* Skipped: files identified as a known library (the libs.py inventory when it already ran, retire.js component
  names in the file name or in a version banner, UMD builds with a licence banner, ``vendor``/``lib`` directories):
  library code is not the site's code. Bundles over 1.5 MB, truncated bodies, bodies in an unsupported content-coding
  and anything past the time budget are skipped and recorded as ``not_tested`` with the reason (never half-analysed,
  never shown as passed). Third-party scripts are not the site's code and are not analysed.

How
1. The units are written into a fresh temporary directory, read back and parsed with the existing frontend. Minified
   files (long lines) are first re-flowed: a newline is inserted after ``;``, ``{`` and ``}`` outside strings, template
   literals, comments and regular expressions, with a map back to the served line and column (the engine skips files
   whose lines exceed 5000 characters).
2. Two lowering gaps of the frontend/model for browser code are closed on the syntax tree (never in
   ``vulnscan/models``): an assignment to the global ``location`` becomes ``window.location = …`` (an attribute sink
   the model already has) and ``el.innerHTML += x`` becomes ``el.innerHTML = el.innerHTML + x``.
3. ``taint.analyze_project_full`` runs once over all units (so a page's inline code can call a function defined in a
   script file it loads). Only findings whose source is a DOM source are kept (``location.*``, ``document.URL``,
   ``document.referrer``, ``document.cookie``, ``window.name``, URL search params, SPA router params, web storage);
   server-side sources (``req.body``, ``process.env``, …) are dropped. DF013/DF001/DF012 map to WEB520, DF008 to
   WEB521. A flow that crosses into another script file of the page is ``tentative`` (it depends on load order and on
   an unresolved global call); a flow inside one file is ``firm``; storage and cookie sources are ``tentative``.
4. WEB522 is a syntactic check on the same trees: ``addEventListener("message", h)`` / ``onmessage = h`` on the window
   (not on workers, ports, sockets or event sources) where ``h``'s body (and the functions it hands the event to)
   never reads ``.origin``. ``firm`` when the message data reaches an HTML, script or navigation sink in the handler.
5. The temporary directory is removed (also on errors). File and line in evidence are the served URL and line.
"""

from __future__ import annotations

import ast
import copy
import hashlib
import os
import re
import shutil
import sys
import tempfile
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Iterable

from . import psl
from .rules import checks_for_module
from .types import (
    Evidence,
    InlineScript,
    Issue,
    Page,
    Response,
    ScanContext,
    normalise_host,
    strip_controls,
)

CHECKS: tuple[str, ...] = checks_for_module("domxss")

MAX_FILES = 15                    # same-site script files per scan (§2.6)
MAX_FILE_BYTES = 1_500_000        # per file / per page of inline code (§2.6)
ENGINE_MAX_CHARS = 600_000        # taint._analyze_groups skips larger JavaScript files
LONG_LINE = 1000                  # lines longer than this are re-flowed (the engine skips files with > 5000)
TIME_BUDGET = 60.0                # seconds for parsing + analysis of all units
MAX_TOTAL_CHARS = 8_000_000       # total JavaScript analysed per scan
MAX_PAGE_ISSUES = 50              # issues emitted per inline flow shared by many pages (grouping collapses them)
REPO_FILE = "retire-jsrepository.json.gz"

RULE_MAP = {"DF013": "WEB520", "DF001": "WEB520", "DF012": "WEB520", "DF008": "WEB521"}

_JS_ESSENCES = frozenset({"application/javascript", "text/javascript", "application/x-javascript", "text/ecmascript",
                          "application/ecmascript", "application/x-ecmascript", "text/jscript", "module"})
_JS_PATH = re.compile(r"\.(?:m|c)?js$", re.I)
_OPAQUE_CODINGS = ("br", "zstd", "compress", "x-compress")

# ----------------------------------------------------------------------------------------------- user-facing text

STR: dict[str, tuple[str, str]] = {
    "flow": ("{source} (line {source_line}) reaches {sink} at {where}.",
             "يصل المصدر {source} (السطر {source_line}) إلى {sink} في {where}."),
    "path": ("Path: {steps}.", "المسار: {steps}."),
    "inline": ("Inline script on {page}.", "سكربت مضمّن في الصفحة {page}."),
    "loaded_by": ("Loaded by {pages}.", "تحمّله الصفحات: {pages}."),
    "cross_file": ("The flow crosses script files ({files}); it depends on their load order.",
                   "يعبر التدفق عدة ملفات سكربت ({files})؛ لذا يعتمد على ترتيب تحميلها."),
    "stored_source": ("The source is browser storage or a cookie: an attacker must be able to write it first.",
                      "المصدر هو تخزين المتصفح أو كوكي: يجب أن يتمكن المهاجم من كتابته أولًا."),
    "reflowed": ("The file is minified; the line and column point into the served file.",
                 "الملف مصغّر؛ يشير السطر والعمود إلى موضعهما في الملف المقدَّم."),
    "message_handler": ("The \"message\" handler registered at {where} never reads event.origin.",
                        "معالج الحدث \"message\" المسجّل في {where} لا يقرأ event.origin إطلاقًا."),
    "message_sink": ("The message data reaches {sink} (line {line}).", "تصل بيانات الرسالة إلى {sink} (السطر {line})."),
    "static": ("Found by static analysis of the served code; Kashif does not run JavaScript.",
               "اكتُشف بتحليل ثابت للشيفرة المقدَّمة؛ لا يشغّل كاشف شيفرة JavaScript."),
    # coverage details
    "skip_size": ("{url} is larger than 1.5 MB (minified bundle), not analysed",
                  "الملف {url} أكبر من 1.5 ميغابايت (حزمة مصغّرة)، لم يُحلَّل"),
    "skip_engine": ("{url} is too large for the JavaScript analyser", "الملف {url} أكبر مما يستطيع محلل JavaScript تحليله"),
    "skip_truncated": ("{url} was truncated at the download cap", "قُطع الملف {url} عند حد التنزيل"),
    "skip_coding": ("{url} uses the content-coding {coding}", "يستخدم الملف {url} ترميز المحتوى {coding}"),
    "skip_limit": ("{url}: more than 15 script files", "{url}: أكثر من 15 ملف سكربت"),
    "skip_time": ("{url}: time budget of the DOM analysis reached", "{url}: بلغ تحليل DOM حدّه الزمني"),
    "skip_total": ("{url}: total JavaScript size limit reached", "{url}: بلغ الحجم الكلي لشيفرة JavaScript حدّه"),
    "engine_error": ("the JavaScript analyser failed: {error}", "فشل محلل JavaScript: {error}"),
}

# friendly names of the engine's source labels (the model labels location.hash as req.hash)
SOURCE_NAMES = {
    "req.hash": "location.hash", "req.search": "location.search", "req.href": "location.href",
    "req.referrer": "document.referrer", "req.name": "window.name", "req.cookie": "document.cookie",
    "req.searchParams": "URL.searchParams", "req.data": "event.data",
}
_DOM_ATTR_LABELS = frozenset(SOURCE_NAMES)
_DOM_NAME_PREFIXES = ("location.", "window.location", "document.location", "document.URL", "document.documentURI",
                      "document.baseURI", "document.referrer", "document.cookie", "window.name", "router.query",
                      "router.asPath", "useRouter.", "$route.", "self.$route.", "route.", "self.route.",
                      "activatedRoute.", "self.activatedRoute.")
_DOM_CALL_LABELS = frozenset({"URLSearchParams.get()", "searchParams.get()", "localStorage.getItem()",
                              "sessionStorage.getItem()", "useSearchParams()", "useParams()", "paramMap.get()",
                              "queryParamMap.get()"})
_STORED_SOURCES = frozenset({"localStorage.getItem()", "sessionStorage.getItem()", "req.cookie", "document.cookie"})

# sink names found on the analysed line (first match wins); rule → generic name otherwise
_SINKS: tuple[tuple[str, re.Pattern], ...] = tuple((n, re.compile(p)) for n, p in (
    ("innerHTML", r"\.innerHTML\b"), ("outerHTML", r"\.outerHTML\b"), ("insertAdjacentHTML", r"\binsertAdjacentHTML\b"),
    ("srcdoc", r"\.srcdoc\b"), ("document.writeln", r"\bwriteln\s*\("), ("document.write", r"\bwrite\s*\("),
    ("eval", r"(?<![\w$.])eval\s*\("), ("Function", r"\bFunction\s*\("), ("setTimeout", r"\bsetTimeout\s*\("),
    ("setInterval", r"\bsetInterval\s*\("), ("createContextualFragment", r"\bcreateContextualFragment\b"),
    ("jQuery.html()", r"\.html\s*\("), ("jQuery.parseHTML()", r"\bparseHTML\s*\("),
    ("jQuery DOM insertion", r"\.(?:append|prepend|after|before|replaceWith|wrap|wrapAll|wrapInner)\s*\("),
    ("import()", r"(?<![\w$.])import\s*\("), ("location.assign()", r"\.assign\s*\("),
    ("location.replace()", r"\blocation\s*\.\s*replace\s*\("), ("window.open()", r"\bopen\s*\("),
    ("location.href", r"\.href\s*=(?!=)"), ("location", r"\blocation\s*=(?!=)"), ("jQuery $()", r"(?:\$|jQuery)\s*\("),
))
_NOT_REDIRECT = re.compile(r"\b(?:pushState|replaceState)\s*\(|\brouter\s*\.\s*(?:push|replace)\s*\(")
_GENERIC_SINK = {"WEB520": ("an HTML/script sink", "نقطة إدراج HTML أو تنفيذ شيفرة"),
                 "WEB521": ("a navigation sink", "نقطة توجيه")}


def _fill(text: str, values: dict, lang: str) -> str:
    def sub(m: re.Match) -> str:
        v = values.get(m.group(1), m.group(0))
        if isinstance(v, tuple):
            v = v[1] if lang == "ar" else v[0]
        return strip_controls(str(v))     # §0.6: values from the target are plain text, never a format string
    return re.sub(r"\{([a-z_]+)\}", sub, text)


def _note(key: str, **values) -> tuple[str, str]:
    en, ar = STR[key]
    return _fill(en, values, "en"), _fill(ar, values, "ar")


def _short(value: str, limit: int = 120) -> str:
    v = " ".join(str(value).split())
    return v if len(v) <= limit else v[: limit - 1] + "…"


def _url_list(urls: list[str], limit: int = 5) -> str:
    shown = [_short(u, 100) for u in urls[:limit]]
    more = len(urls) - len(shown)
    return ", ".join(shown) + (f" (+{more})" if more > 0 else "")


# ----------------------------------------------------------------------------------------------- source labels

def is_dom_source(label: str) -> bool:
    """True when an engine source label is a browser (DOM) source rather than a server-side one."""
    if not label:
        return False
    if label in _DOM_ATTR_LABELS or label in _DOM_CALL_LABELS:
        return True
    return label.startswith(_DOM_NAME_PREFIXES)


def source_name(label: str) -> str:
    return SOURCE_NAMES.get(label, label)


def sink_name(rule: str, line_text: str) -> tuple[str, str]:
    """``(en, ar)`` name of the sink on an analysed line."""
    for name, rx in _SINKS:
        if rx.search(line_text):
            return name, name
    return _GENERIC_SINK.get(rule, ("a sink", "نقطة خطر"))


# ----------------------------------------------------------------------------------------------- re-flowing minified code

_REGEX_PREV_WORDS = frozenset({"return", "typeof", "case", "in", "of", "new", "delete", "void", "throw", "do", "else",
                               "instanceof", "await", "yield"})


def reflow(text: str, long_line: int = LONG_LINE) -> tuple[str, list[tuple[int, int]] | None]:
    """Split long (minified) lines after ``;``, ``{`` and ``}`` outside strings, templates, comments and regular
    expressions. Returns the new text and, for each new line (index 0 = line 1), the ``(line, column)`` of its first
    character in ``text`` (column 0-based); ``None`` as map when nothing needed re-flowing."""
    if not any(len(ln) > long_line for ln in text.split("\n")):
        return text, None
    out: list[str] = []
    line_map: list[tuple[int, int]] = [(1, 0)]
    n = len(text)
    i = 0
    line, col = 1, 0
    tpl: list[int] = []               # brace depth stack for ${ } inside template literals
    depth = 0
    last_sig = ""                     # last significant code character
    last_word = ""
    cur_len = 0                       # length of the current output line

    def newline_at(next_line: int, next_col: int) -> None:
        nonlocal cur_len
        out.append("\n")
        line_map.append((next_line, next_col))
        cur_len = 0

    def advance(chunk: str) -> None:
        nonlocal line, col, cur_len
        out.append(chunk)
        nl = chunk.count("\n")
        if nl:
            for _ in range(nl):
                line += 1
                line_map.append((line, 0))
            col = len(chunk) - chunk.rfind("\n") - 1
            cur_len = col
        else:
            col += len(chunk)
            cur_len += len(chunk)

    while i < n:
        c = text[i]
        if c in "\"'":
            j = i + 1
            while j < n and text[j] != c and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            j = min(j + 1, n)
            advance(text[i:j])
            i = j
            last_sig, last_word = c, ""
            continue
        if c == "`":
            j = i + 1
            while j < n:
                ch = text[j]
                if ch == "\\":
                    j += 2
                    continue
                if ch == "`":
                    j += 1
                    break
                if ch == "$" and j + 1 < n and text[j + 1] == "{":
                    j += 2
                    tpl.append(depth)
                    depth += 1
                    break
                j += 1
            advance(text[i:j])
            i = j
            last_sig, last_word = ("{", "") if tpl and text[j - 2:j] == "${" else ("`", "")
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            j = n if j < 0 else j
            advance(text[i:j])
            i = j
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            advance(text[i:j])
            i = j
            continue
        if c == "/" and (last_sig in ("", "(", ",", "=", ":", "[", "!", "&", "|", "?", "{", "}", ";", "+", "-", "*", "%",
                                      "<", ">", "~", "^") or last_word in _REGEX_PREV_WORDS):
            j, in_cls = i + 1, False
            while j < n and text[j] != "\n" and (text[j] != "/" or in_cls):
                if text[j] == "\\":
                    j += 1
                elif text[j] == "[":
                    in_cls = True
                elif text[j] == "]":
                    in_cls = False
                j += 1
            j = min(j + 1, n)
            while j < n and text[j].isalpha():
                j += 1
            advance(text[i:j])
            i = j
            last_sig, last_word = "/", ""
            continue
        if c.isalnum() or c in "_$":
            j = i + 1
            while j < n and (text[j].isalnum() or text[j] in "_$"):
                j += 1
            word = text[i:j]
            advance(word)
            i = j
            last_sig, last_word = "a", word
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            if tpl and depth - 1 == tpl[-1]:
                # end of a ${ } expression: continue the template literal
                depth -= 1
                tpl.pop()
                j = i + 1
                while j < n:
                    ch = text[j]
                    if ch == "\\":
                        j += 2
                        continue
                    if ch == "`":
                        j += 1
                        break
                    if ch == "$" and j + 1 < n and text[j + 1] == "{":
                        j += 2
                        tpl.append(depth)
                        depth += 1
                        break
                    j += 1
                advance(text[i:j])
                i = j
                last_sig, last_word = ("{", "") if text[j - 2:j] == "${" else ("`", "")
                continue
            depth = max(0, depth - 1)
        advance(c)
        i += 1
        if not c.isspace():
            last_sig, last_word = c, ""
        if c in ";{}" and cur_len > 0 and i < n and text[i] != "\n":
            newline_at(line, col)
    return "".join(out), line_map


# ----------------------------------------------------------------------------------------------- libraries

_LIB_NAMES = ("jquery", "jquery-ui", "jquery-migrate", "jquery-mobile", "bootstrap", "materialize", "lodash", "underscore",
              "backbone", "angular", "angularjs", "react", "react-dom", "vue", "moment", "d3", "chart", "highcharts",
              "popper", "select2", "datatables", "modernizr", "require", "requirejs", "handlebars", "knockout", "ember",
              "prototype", "mootools", "three", "leaflet", "codemirror", "ace", "tinymce", "ckeditor", "swiper", "slick",
              "socket.io", "axios", "semantic", "foundation", "uikit", "zepto", "dompurify", "purify", "sizzle", "dojo",
              "yui", "ext-all", "swfobject", "mustache", "marked", "markdown-it", "highlight", "video", "pdf",
              "echarts", "alpine", "alpinejs", "svelte", "htmx", "polyfill", "core-js", "babel-polyfill", "regenerator",
              "gsap", "hammer", "lazysizes", "masonry", "isotope", "fancybox", "lightbox", "owl.carousel", "slick",
              "flickity", "photoswipe", "plupload", "dropzone", "clipboard", "sweetalert", "sweetalert2", "toastr",
              "jszip", "quill", "froala", "summernote", "fullcalendar", "flatpickr", "pikaday", "luxon", "dayjs",
              "fontawesome", "font-awesome", "webfont", "webfontloader", "recaptcha", "jquery.validate",
              "jquery.min", "jquery.slim", "preact", "mithril", "riot", "lit", "stimulus", "turbo", "turbolinks")
_LIB_SUFFIX = (r"(?:[.\-_@]v?\d[\w.\-]*|\.min|\.slim|\.umd|\.production|\.development|\.prod|\.dev|\.bundle|\.esm|"
               r"\.global|\.runtime|\.full|\.core|\.all|\.pack|\.packed|\.compressed|\.js)*")
_VENDOR_DIRS = frozenset({"vendor", "vendors", "lib", "libs", "third-party", "thirdparty", "3rdparty", "bower_components",
                          "node_modules", "web_modules", "jspm_packages", "external", "externals", "plugins"})
_BANNER = re.compile(r"^\s*(?:[\"']use strict[\"'];?\s*)?(/\*[!*@][\s\S]{0,600}?\*/|(?://[!@][^\n]*\n\s*){1,6})")
_BANNER_VERSION = re.compile(r"\bv?\d+\.\d+(?:\.\d+)?\b")
_BANNER_LICENSE = re.compile(r"licen[sc]e|\(c\)|copyright|@preserve", re.I)
_UMD = re.compile(r"typeof\s+exports\s*={2,3}\s*[\"']object[\"']\s*&&\s*typeof\s+module|define\.amd|"
                  r"typeof\s+define\s*={2,3}\s*[\"']function[\"']")


def _norm_lib(name: str) -> str:
    n = name.lower().strip()
    if "/" in n:
        n = n.rsplit("/", 1)[-1]
    for suf in (".js", "js"):
        if n.endswith(suf) and len(n) > len(suf) + 1:
            n = n[: -len(suf)].rstrip(".-")
            break
    return n


def library_names(ctx: ScanContext | None = None) -> frozenset[str]:
    """Known library names: a built-in list plus the retire.js component, bower and npm names (data file)."""
    names = {_norm_lib(n) for n in _LIB_NAMES}
    dm = getattr(ctx, "data", None) if ctx is not None else None
    if dm is None:
        from . import data as dm   # noqa: PLW0127 - lazy import of the shared loader
    try:
        repo = dm.load_json(REPO_FILE)
    except Exception:  # noqa: BLE001 - a missing or broken data file only weakens library detection
        repo = None
    if isinstance(repo, dict):
        comps = repo.get("repository", repo)
        if isinstance(comps, dict):
            for key, comp in comps.items():
                if key == "dont check":
                    continue
                names.add(_norm_lib(key))
                if isinstance(comp, dict):
                    for b in comp.get("bowername") or ():
                        if isinstance(b, str):
                            names.add(_norm_lib(b))
                    if isinstance(comp.get("npmname"), str):
                        names.add(_norm_lib(comp["npmname"]))
    names.discard("")
    return frozenset(names)


def _name_rx(names: Iterable[str]) -> re.Pattern:
    alts = "|".join(sorted((re.escape(n) for n in names), key=len, reverse=True))
    return re.compile(rf"(?i)^(?:{alts}){_LIB_SUFFIX}\.(?:m|c)?js$")


def library_name(url: str, text: str, names: frozenset[str], known_urls: Iterable[str] = ()) -> str | None:
    """The library a script is, or ``None`` when it looks like the site's own code."""
    if url and url in set(known_urls):
        return "retire"
    path = urllib.parse.urlsplit(url).path if url else ""
    segs = [urllib.parse.unquote(s) for s in path.split("/") if s]
    if segs:
        if any(s.lower() in _VENDOR_DIRS for s in segs[:-1]):
            return segs[-1]
        if _name_rx(names).match(segs[-1]):
            return segs[-1]
    m = _BANNER.match(text[:4000])
    if m:
        banner = m.group(1)
        if _BANNER_VERSION.search(banner):
            low = banner.lower()
            for n in names:
                if len(n) >= 3 and re.search(rf"(?<![\w-]){re.escape(n)}(?![\w-])", low):
                    return n
            if _BANNER_LICENSE.search(banner) and _UMD.search(text[:20000]):
                return "umd"
    return None


# ----------------------------------------------------------------------------------------------- units

@dataclass
class Segment:
    """A run of unit lines that comes from one served text (one inline script, or a whole file)."""
    unit_start: int           # first unit line (1-based) of this segment
    lines: int
    url: str                  # served URL
    response: Response
    base_line: int            # served line of the segment's first line
    base_col: int             # served column of the segment's first character (first line only)
    page: str = ""            # page URL for inline scripts


@dataclass
class Unit:
    rel: str
    kind: str                 # inline | file
    text: str                 # analysed text (re-flowed when minified)
    reflow_map: list[tuple[int, int]] | None
    # inline units shared by identical pages: one segment list per page
    page_segments: list[list[Segment]] = field(default_factory=list)
    url: str = ""             # file units: the served URL
    response: Response | None = None
    pages: list[str] = field(default_factory=list)   # pages that load this file / carry these inline scripts
    tree: Any = None
    lines: list[str] = field(default_factory=list)

    def served(self, unit_line: int, page_index: int = 0) -> tuple[str, Response | None, int, int, str]:
        """``(url, response, line, column, page)`` in the served text for an analysed line."""
        line, col = unit_line, 0
        if self.reflow_map and 1 <= unit_line <= len(self.reflow_map):
            line, col = self.reflow_map[unit_line - 1]
        if self.kind == "file":
            return self.url, self.response, line, col, ""
        segs = self.page_segments[min(page_index, len(self.page_segments) - 1)]
        for seg in segs:
            if seg.unit_start <= line < seg.unit_start + seg.lines:
                rel = line - seg.unit_start
                return seg.url, seg.response, seg.base_line + rel, (seg.base_col + col if rel == 0 else col), seg.page
        seg = segs[-1] if segs else None
        return (seg.url, seg.response, seg.base_line, 0, seg.page) if seg else ("", None, line, col, "")

    def line_text(self, unit_line: int) -> str:
        if 1 <= unit_line <= len(self.lines):
            return self.lines[unit_line - 1]
        return ""


_HTML_COMMENT_OPEN = re.compile(r"^(\s*)<!--")
_HTML_COMMENT_CLOSE = re.compile(r"-->(\s*)$")


def _clean_inline(text: str) -> str:
    """Legacy ``<!--``/``-->`` wrappers around inline code (same length, so columns stay put)."""
    text = _HTML_COMMENT_OPEN.sub(lambda m: m.group(1) + "    ", text, count=1)
    return _HTML_COMMENT_CLOSE.sub(lambda m: "   " + m.group(1), text, count=1)


def _slug(value: str, limit: int = 60) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._-")
    return (s or "root")[:limit]


def _rel_for_url(url: str, used: set[str]) -> str:
    parts = urllib.parse.urlsplit(url)
    host = _slug(normalise_host(parts.hostname or "") or "host", 80)
    segs = [_slug(urllib.parse.unquote(s), 80) for s in parts.path.split("/") if s and s not in (".", "..")]
    segs = [s for s in segs if s not in (".", "..")] or ["index"]
    name = segs[-1]
    if not name.lower().endswith(".js") or name.lower().endswith(".min.js"):
        name += ".js"                  # the engine ignores *.min.js and needs a JavaScript extension
    rel = "/".join(["src", host, *segs[:-1][:8], name])
    base, k = rel, 1
    while rel in used:
        k += 1
        rel = base[:-3] + f"-{k}.js"
    used.add(rel)
    return rel


def _is_document(page: Page) -> bool:
    r = page.response
    if page.doc is None or not r.is_2xx or r.error:
        return False
    if r.kind:
        return r.kind == "document"
    return r.essence in ("text/html", "application/xhtml+xml", "")


def _opaque(r: Response) -> str | None:
    enc = (r.encoding or "").lower()
    if "opaque-coding" in r.flags:
        return enc or "unknown"
    for c in (x.strip() for x in enc.split(",")):
        if c in _OPAQUE_CODINGS or (c and c not in ("gzip", "x-gzip", "deflate", "identity")):
            return c
    return None


def _script_srcs(page: Page) -> list[tuple[str, str]]:
    """``(resolved URL, type)`` of the page's live ``<script src>`` elements."""
    out = []
    doc = page.doc
    if doc is None:
        return out
    for el in doc.find_all("script"):
        src = el.get("src")
        if src is None or not src.strip():
            continue
        url = doc.resolve(src)
        out.append((urllib.parse.urldefrag(url)[0], (el.get("type") or "").strip().lower()))
    return out


def _js_type(t: str) -> bool:
    t = t.split(";", 1)[0].strip()
    return InlineScript(text="", element=0, line=1, col=0, offset=0, nonce=None, type=t).is_javascript


def _is_script_response(r: Response) -> bool:
    if r.kind:
        return r.kind == "script"
    ess = r.essence
    if ess in _JS_ESSENCES:
        return True
    return not ess.startswith(("text/css", "text/html", "image/", "font/")) and bool(_JS_PATH.search(r.parsed_url.path))


# ----------------------------------------------------------------------------------------------- AST adjustments

class _Lower(ast.NodeTransformer):
    """Close two browser-code gaps of the frontend/model without touching ``vulnscan/models``."""

    def __init__(self, location_bound: bool):
        self.location_bound = location_bound

    def visit_Assign(self, node: ast.Assign) -> ast.AST:
        self.generic_visit(node)
        if not self.location_bound:
            targets = []
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == "location":
                    t = ast.copy_location(ast.Attribute(value=ast.copy_location(ast.Name(id="window", ctx=ast.Load()), t),
                                                        attr="location", ctx=ast.Store()), t)
                targets.append(t)
            node.targets = targets
        return node

    def visit_AugAssign(self, node: ast.AugAssign) -> ast.AST:
        self.generic_visit(node)
        t = node.target
        if isinstance(node.op, ast.Add) and isinstance(t, ast.Attribute) and t.attr in ("innerHTML", "outerHTML", "srcdoc"):
            load = copy.deepcopy(t)
            load.ctx = ast.Load()
            new = ast.Assign(targets=[t], value=ast.BinOp(left=load, op=ast.Add(), right=node.value))
            return ast.copy_location(new, node)
        if isinstance(node.op, ast.Add) and isinstance(t, ast.Name) and t.id == "location" and not self.location_bound:
            target = ast.copy_location(ast.Attribute(value=ast.Name(id="window", ctx=ast.Load()), attr="location",
                                                     ctx=ast.Store()), t)
            return ast.copy_location(ast.Assign(targets=[target], value=node.value), node)
        return node


_LOCATION_BOUND = re.compile(r"\b(?:var|let|const)\s+location\b|\bfunction\b[^(){};]*\([^()]*\blocation\b[^()]*\)|"
                             r"\(\s*location\s*\)\s*=>|\blocation\s*=>")


def _lower(tree: ast.Module, text: str) -> ast.Module:
    try:
        tree = _Lower(bool(_LOCATION_BOUND.search(text))).visit(tree)
        return ast.fix_missing_locations(tree)
    except (RecursionError, ValueError, TypeError, AttributeError):
        return tree


# ----------------------------------------------------------------------------------------------- WEB522

_WINDOWISH = frozenset({"window", "self", "globalThis", "top", "parent", "frames"})
_MSG_SINK_ATTRS = frozenset({"innerHTML", "outerHTML", "srcdoc", "href", "location", "src"})
_MSG_SINK_CALLS = frozenset({"eval", "Function", "setTimeout", "setInterval", "write", "writeln", "insertAdjacentHTML",
                             "assign", "replace", "open", "html", "append", "prepend", "after", "before", "replaceWith",
                             "createContextualFragment", "parseHTML"})


@dataclass
class MessageHandler:
    rel: str
    line: int                 # registration line (unit line)
    func: ast.FunctionDef
    sink: str = ""            # sink reached by the message data ("" = none seen)
    sink_line: int = 0


def _func_index(trees: dict[str, ast.Module]) -> dict[str, list[tuple[str, ast.FunctionDef]]]:
    idx: dict[str, list[tuple[str, ast.FunctionDef]]] = {}
    for rel, tree in trees.items():
        try:
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    idx.setdefault(node.name, []).append((rel, node))
        except RecursionError:
            continue
    return idx


def _windowish(node: ast.AST | None) -> bool:
    """Is ``node`` the page's window (``window``, ``self``, ``$(window)``)? ``None`` = a bare ``addEventListener``."""
    if node is None:
        return True
    if isinstance(node, ast.Name):
        return node.id in _WINDOWISH
    if isinstance(node, ast.Attribute):
        return node.attr in ("window", "top", "parent") and isinstance(node.value, ast.Name) and node.value.id in _WINDOWISH
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ("$", "jQuery") and node.args:
        return _windowish(node.args[0])
    return False


def _uses_self(node: ast.AST) -> bool:
    """A registration on ``this``/``self`` (``self.addEventListener``, ``self.onmessage = h``)."""
    f = node.func if isinstance(node, ast.Call) else None
    if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id == "self":
        return True
    if isinstance(node, ast.Assign):
        return any(isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) and t.value.id == "self"
                   for t in node.targets)
    return False


def _handler_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "bind":
        return _handler_name(node.func.value)
    return None


def _resolve(name: str | None, rel: str, group: set[str],
             idx: dict[str, list[tuple[str, ast.FunctionDef]]]) -> tuple[str, ast.FunctionDef] | None:
    if not name:
        return None
    cands = idx.get(name) or []
    same = [c for c in cands if c[0] == rel]
    if len(same) >= 1:
        return same[-1]
    other = [c for c in cands if c[0] in group]
    return other[-1] if len(other) == 1 else None


def _reads_origin(func: ast.AST, group: set[str], idx, depth: int = 0, seen: set[int] | None = None) -> bool | None:
    """True when the handler (or a function it hands the event to) reads ``.origin``; None when it hands the event
    to a function that cannot be resolved (unknown: no finding)."""
    seen = seen if seen is not None else set()
    if id(func) in seen:
        return False
    seen.add(id(func))
    params = {a.arg for a in func.args.args} if isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)) else set()
    unknown = False
    for node in ast.walk(func):
        if isinstance(node, ast.Attribute) and node.attr == "origin":
            return True
        if isinstance(node, ast.Call) and any(isinstance(a, ast.Name) and a.id in params for a in node.args):
            callee = node.func
            name = _handler_name(callee)
            if name in ("log", "warn", "error", "info", "debug", "stringify", "push", "preventDefault",
                        "stopPropagation"):
                continue
            target = None
            for rel_, fn in idx.get(name or "", []):
                if rel_ in group:
                    target = fn
                    break
            if target is None:
                unknown = True
                continue
            if depth < 3:
                r = _reads_origin(target, group, idx, depth + 1, seen)
                if r:
                    return True
                if r is None:
                    unknown = True
    return None if unknown else False


def _message_sink(func: ast.FunctionDef) -> tuple[str, int]:
    """First sink in the handler that the message data (``param.data`` or names assigned from it) reaches."""
    params = [a.arg for a in func.args.args]
    if not params:
        return "", 0
    ev = params[0]
    tainted: set[str] = set()

    def carries(expr: ast.AST | None) -> bool:
        if expr is None:
            return False
        for n in ast.walk(expr):
            if isinstance(n, ast.Attribute) and n.attr == "data" and isinstance(n.value, ast.Name) and n.value.id == ev:
                return True
            if isinstance(n, ast.Attribute) and n.attr == "data" and isinstance(n.value, ast.Attribute) \
                    and n.value.attr == "originalEvent":
                return True
            if isinstance(n, ast.Name) and n.id in tainted:
                return True
        return False

    nodes = list(ast.walk(func))
    for _ in range(4):                    # names assigned from the message data, to a fixed point
        before = len(tainted)
        for node in nodes:
            if isinstance(node, ast.Assign) and carries(node.value):
                tainted.update(t.id for t in node.targets if isinstance(t, ast.Name) and t.id != "location")
        if len(tainted) == before:
            break
    for node in nodes:
        if isinstance(node, ast.Assign) and carries(node.value):
            for t in node.targets:
                if isinstance(t, ast.Attribute) and t.attr in _MSG_SINK_ATTRS:
                    return t.attr, node.lineno
                if isinstance(t, ast.Name) and t.id == "location":
                    return "location", node.lineno
        elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Attribute) \
                and node.target.attr in _MSG_SINK_ATTRS and carries(node.value):
            return node.target.attr, node.lineno
        elif isinstance(node, ast.Call):
            name = _handler_name(node.func)
            if name in _MSG_SINK_CALLS and any(carries(a) for a in node.args) and _sink_receiver_ok(name, node.func):
                return name, node.lineno
    return "", 0


_JQ_METHODS = frozenset({"html", "append", "prepend", "after", "before", "replaceWith", "parseHTML"})


def _sink_receiver_ok(name: str, func: ast.AST) -> bool:
    """Calls whose name alone is ambiguous need the right receiver (``Object.assign`` and ``formData.append`` are not
    sinks)."""
    recv = func.value if isinstance(func, ast.Attribute) else None
    if name in ("assign", "replace"):
        return recv is not None and _handler_name(recv) == "location"
    if name == "open":
        return recv is None or _windowish(recv)
    if name in ("write", "writeln"):
        return recv is not None and _handler_name(recv) == "document"
    if name in _JQ_METHODS:
        if recv is None:
            return False
        root = recv
        while isinstance(root, (ast.Attribute, ast.Call)):
            root = root.func if isinstance(root, ast.Call) else root.value
        return isinstance(root, ast.Name) and (root.id.startswith("$") or root.id == "jQuery")
    return True


def message_handlers(trees: dict[str, ast.Module], groups: dict[str, set[str]]) -> list[MessageHandler]:
    """Window ``message`` handlers that never read ``event.origin`` (WEB522)."""
    idx = _func_index(trees)
    found: list[MessageHandler] = []
    for rel, tree in trees.items():
        group = groups.get(rel, {rel})
        regs: list[tuple[int, ast.AST]] = []
        try:
            in_class: set[int] = set()    # inside a class, `this` (lowered to self) is not the window
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    in_class.update(id(n) for n in ast.walk(node))
            for node in ast.walk(tree):
                if id(node) in in_class and _uses_self(node):
                    continue
                if isinstance(node, ast.Call):
                    f = node.func
                    member = f.attr if isinstance(f, ast.Attribute) else (f.id if isinstance(f, ast.Name) else "")
                    recv = f.value if isinstance(f, ast.Attribute) else None
                    if member == "addEventListener" and len(node.args) >= 2 and _windowish(recv):
                        evt, handler = node.args[0], node.args[1]
                    elif member == "on" and isinstance(recv, ast.Call) and _windowish(recv) and len(node.args) >= 2:
                        evt, handler = node.args[0], node.args[-1]
                    else:
                        continue
                    if isinstance(evt, ast.Constant) and evt.value == "message":
                        regs.append((node.lineno, handler))
                elif isinstance(node, ast.Assign):
                    for t in node.targets:
                        if isinstance(t, ast.Attribute) and t.attr == "onmessage" and _windowish(t.value):
                            regs.append((node.lineno, node.value))
            for node in tree.body:
                if isinstance(node, ast.FunctionDef) and node.name == "onmessage":   # onmessage = function (e) {…}
                    regs.append((node.lineno, ast.Name(id="onmessage", ctx=ast.Load())))
        except RecursionError:
            continue
        done: set[int] = set()
        for line, handler in regs:
            res = _resolve(_handler_name(handler), rel, group, idx)
            if res is None:
                continue
            _hrel, func = res
            if id(func) in done:
                continue
            done.add(id(func))
            if not func.args.args and not any(isinstance(n, ast.Name) and n.id == "event" for n in ast.walk(func)):
                continue                  # the handler never looks at the message
            try:
                reads = _reads_origin(func, group, idx)
            except RecursionError:
                continue
            if reads is not False:
                continue                  # checks the origin, or delegates to code we cannot see
            sink, sink_line = _message_sink(func)
            found.append(MessageHandler(rel, line, func, sink, sink_line))
    return found


# ----------------------------------------------------------------------------------------------- the run

@dataclass
class _Skip:
    url: str
    reason: str               # coverage reason code
    note: str                 # STR key
    values: dict = field(default_factory=dict)
    limitation: bool = True   # False for library skips (by design)


class _Run:
    def __init__(self, ctx: ScanContext):
        self.ctx = ctx
        self.units: dict[str, Unit] = {}
        self.skips: list[_Skip] = []
        self.used: set[str] = set()
        self.total = 0
        self.t0 = time.monotonic()
        self.names = library_names(ctx)
        libs = ctx.inventory.get("libraries") if isinstance(ctx.inventory, dict) else None
        self.known_lib_urls = {str(e.get("url")) for e in (libs or []) if isinstance(e, dict) and e.get("url")
                               and e.get("detection") in ("hash", "filecontent", "filecontentreplace", "filename")}
        self.file_pages: dict[str, list[str]] = {}
        self.tmpdir = ""

    def _over_time(self) -> bool:
        return time.monotonic() - self.t0 > TIME_BUDGET

    # -- collection --------------------------------------------------------------------------------------------
    def collect(self) -> None:
        ctx = self.ctx
        docs = [p for p in ctx.pages if _is_document(p)]
        site_hosts = {normalise_host(p.response.host) for p in docs} | {ctx.target_host}
        if ctx.entry is not None:
            site_hosts.add(ctx.entry.host)
        site_hosts.discard("")
        js_typed: dict[str, bool] = {}
        for p in docs:
            for url, typ in _script_srcs(p):
                self.file_pages.setdefault(url, [])
                if p.response.url not in self.file_pages[url]:
                    self.file_pages[url].append(p.response.url)
                js_typed[url] = js_typed.get(url, False) or _js_type(typ)
        # inline units (one per distinct inline content)
        by_content: dict[str, Unit] = {}
        for pi, p in enumerate(docs):
            coding = _opaque(p.response)
            if coding:                    # the body was never decoded: there is no script text to read
                self.skips.append(_Skip(p.response.url, "unsupported_coding", "skip_coding",
                                        {"url": p.response.url, "coding": coding}))
                continue
            scripts = []
            for s in p.doc.inline_scripts:
                if not (s.live and s.is_javascript and s.text.strip()):
                    continue
                lib = library_name("", s.text, self.names)
                if lib:
                    self.skips.append(_Skip(p.response.url, "", "", {"library": lib}, limitation=False))
                    continue
                scripts.append(s)
            if not scripts:
                continue
            body, segs, start = [], [], 1
            for s in scripts:
                code = _clean_inline(s.text)
                if not code.endswith("\n"):
                    code += "\n"
                nlines = code.count("\n")
                segs.append(Segment(start, nlines, p.response.url, p.response, s.line, s.col, p.response.url))
                body.append(code + ";\n")
                start += nlines + 1
            text = "".join(body)
            key = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
            if key in by_content:
                u = by_content[key]
                u.page_segments.append(segs)
                u.pages.append(p.response.url)
                continue
            if len(text.encode("utf-8", "replace")) > MAX_FILE_BYTES:
                self.skips.append(_Skip(p.response.url, "truncated", "skip_size", {"url": p.response.url}))
                continue
            rel = f"inline/{_slug(urllib.parse.urlsplit(p.response.url).path.strip('/') or 'index', 50)}-{pi}.js"
            self.used.add(rel)
            u = Unit(rel, "inline", text, None, [segs], pages=[p.response.url])
            by_content[key] = u
            self.units[rel] = u
        # same-site script files
        seen: set[str] = set()
        candidates: list[Response] = []
        for r in ctx.subresources:
            url = urllib.parse.urldefrag(r.url)[0]
            if url in seen or not r.is_2xx or r.error or not _is_script_response(r):
                continue
            if not any(psl.same_site(r.host, h) for h in site_hosts):
                continue                  # third-party code is not the site's own code
            if url in js_typed and not js_typed[url]:
                continue                  # <script type="text/template" src> and similar
            seen.add(url)
            candidates.append(r)
        files = 0
        for r in sorted(candidates, key=lambda x: x.url):
            url = urllib.parse.urldefrag(r.url)[0]
            coding = _opaque(r)
            if coding:
                self.skips.append(_Skip(url, "unsupported_coding", "skip_coding", {"url": url, "coding": coding}))
                continue
            if r.truncated or "truncated-body" in r.flags:
                self.skips.append(_Skip(url, "truncated", "skip_truncated", {"url": url}))
                continue
            if len(r.body) > MAX_FILE_BYTES:
                self.skips.append(_Skip(url, "truncated", "skip_size", {"url": url}))
                continue
            text = r.text()
            lib = library_name(url, text, self.names, self.known_lib_urls)
            if lib:
                self.skips.append(_Skip(url, "", "", {"library": lib}, limitation=False))
                continue
            if files >= MAX_FILES:
                self.skips.append(_Skip(url, "budget", "skip_limit", {"url": url}))
                continue
            files += 1
            rel = _rel_for_url(url, self.used)
            self.units[rel] = Unit(rel, "file", text, None, url=url, response=r, pages=list(self.file_pages.get(url, [])))

    # -- preparation (temp dir, parse) ----------------------------------------------------------------------------
    def prepare(self, tmp: str) -> dict[str, str]:
        from .. import js_frontend
        files: dict[str, str] = {}
        for rel, u in list(self.units.items()):
            text, rmap = reflow(u.text)
            if len(text) > ENGINE_MAX_CHARS or any(len(ln) > 5000 for ln in text.splitlines()[:50]):
                self.skips.append(_Skip(u.url or (u.pages[0] if u.pages else rel), "truncated", "skip_engine",
                                        {"url": u.url or (u.pages[0] if u.pages else rel)}))
                del self.units[rel]
                continue
            if self.total + len(text) > MAX_TOTAL_CHARS:
                where = u.url or (u.pages[0] if u.pages else rel)
                self.skips.append(_Skip(where, "budget", "skip_total", {"url": where}))
                del self.units[rel]
                continue
            if self._over_time():
                where = u.url or (u.pages[0] if u.pages else rel)
                self.skips.append(_Skip(where, "time_budget", "skip_time", {"url": where}))
                del self.units[rel]
                continue
            self.total += len(text)
            path = os.path.join(tmp, *rel.split("/"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
            with open(path, encoding="utf-8", newline="") as fh:
                on_disk = fh.read()
            u.text, u.reflow_map = on_disk, rmap
            u.lines = on_disk.split("\n")
            u.tree = js_frontend.parse_js(on_disk, rel)
            files[rel] = on_disk
        return files

    def groups(self) -> dict[str, set[str]]:
        """For each unit: the units that can share a global scope with it (same page)."""
        page_units: dict[str, set[str]] = {}
        for rel, u in self.units.items():
            for p in u.pages:
                page_units.setdefault(p, set()).add(rel)
        out: dict[str, set[str]] = {}
        for rel, u in self.units.items():
            g = {rel}
            for p in u.pages:
                g |= page_units.get(p, set())
            out[rel] = g
        return out


def _offset(response: Response | None, line: int, col: int) -> int | None:
    if response is None:
        return None
    text = response.text()
    pos = 0
    for _ in range(max(0, line - 1)):
        nxt = text.find("\n", pos)
        if nxt < 0:
            return None
        pos = nxt + 1
    return pos + col


def _excerpt(response: Response | None, line: int, col: int, analysed: str) -> str:
    if analysed.strip():
        return _short(analysed.strip(), 200)
    if response is None:
        return ""
    lines = response.text().split("\n")
    if 1 <= line <= len(lines):
        ln = lines[line - 1]
        return _short(ln[max(0, col - 60): col + 140], 200)
    return ""


def _host_of(url: str, ctx: ScanContext) -> str:
    return normalise_host(urllib.parse.urlsplit(url).hostname or "") or ctx.target_host


def _flow_issues(run: _Run, findings: list, groups: dict[str, set[str]]) -> list[Issue]:
    ctx = run.ctx
    issues: list[Issue] = []
    seen: set[tuple] = set()
    for f in findings:
        rule = RULE_MAP.get(getattr(f, "rule_id", ""))
        extra = getattr(f, "extra", None) or {}
        label = str(extra.get("taint_source") or "")
        if rule is None or not is_dom_source(label):
            continue
        unit = run.units.get(f.file)
        if unit is None:
            continue
        steps = [s for s in (extra.get("path") or []) if isinstance(s, dict)]
        files = [s.get("file") for s in steps if s.get("file")] or [f.file]
        files.append(f.file)
        if any(x not in run.units for x in files):
            continue
        uniq_files = list(dict.fromkeys(files))
        if len(uniq_files) > 1 and not set(uniq_files) <= groups.get(uniq_files[0], {uniq_files[0]}):
            continue                      # a "flow" between scripts no page loads together
        line_text = unit.line_text(f.line)
        sink_text = line_text
        if steps:                         # the sink itself is the last step (inside a called function, maybe)
            last = steps[-1]
            sink_unit = run.units.get(last.get("file", ""), unit)
            sink_text = sink_unit.line_text(int(last.get("line") or 0)) or line_text
        if rule == "WEB521" and _NOT_REDIRECT.search(sink_text):
            continue                      # history.pushState / router.push: same-origin navigation, not a redirect
        sink = sink_name(rule, sink_text)
        src_file = steps[0].get("file", f.file) if steps else f.file
        src_line = int(steps[0].get("line") or f.line) if steps else f.line
        src_unit = run.units.get(src_file, unit)
        conf = "firm"
        if len(uniq_files) > 1:
            conf = "tentative"
        if label in _STORED_SOURCES:
            conf = "tentative"
        source = source_name(label)
        page_count = len(unit.page_segments) if unit.kind == "inline" else 1
        for pi in range(min(page_count, MAX_PAGE_ISSUES)):
            url, resp, line, col, page = unit.served(f.line, pi)
            key = (rule, url, line, col, source)
            if key in seen:
                continue
            seen.add(key)
            s_url, _s_resp, s_line, _s_col, _ = src_unit.served(src_line, pi if src_unit is unit else 0)
            where = f"{url}:{line}"
            nts: list[tuple[str, str]] = [_note("flow", source=source, source_line=s_line if s_url == url else f"{s_url}:{s_line}",
                         sink=sink, where=where)]
            if len(steps) > 1:
                trace = []
                for st in steps:
                    su = run.units.get(st.get("file", ""), unit)
                    t_url, _r, t_line, _c, _p = su.served(int(st.get("line") or 0), pi if su is unit else 0)
                    trace.append(f"{_short(t_url, 80)}:{t_line}")
                nts.append(_note("path", steps=" → ".join(dict.fromkeys(trace))))
            if unit.kind == "inline":
                nts.append(_note("inline", page=page))
            elif unit.pages:
                nts.append(_note("loaded_by", pages=_url_list(unit.pages)))
            if len(uniq_files) > 1:
                nts.append(_note("cross_file", files=_url_list([run.units[x].url or run.units[x].rel for x in uniq_files
                                                                if x in run.units])))
            if label in _STORED_SOURCES:
                nts.append(_note("stored_source"))
            if unit.reflow_map:
                nts.append(_note("reflowed"))
            nts.append(_note("static"))
            excerpt = _excerpt(resp, line, col, line_text)
            ev = Evidence.for_response(resp, where="body", name=url, value=excerpt, offset=_offset(resp, line, col),
                                       excerpt=excerpt, now=ctx.now)
            params = {"file": url, "line": line, "column": col + 1, "source": source, "sink": sink[0],
                      "page": page or (unit.pages[0] if unit.pages else url), "inline": unit.kind == "inline"}
            group_value = f"{source}>{sink[0]}|" + re.sub(r"\s+", "", line_text)[:160]
            issues.append(Issue(rule=rule, url=page or url, confidence=conf, evidence=ev, params=params,
                                group_value=group_value, notes=nts, host=_host_of(page or url, ctx)))
    return issues


def _message_issues(run: _Run, handlers: list[MessageHandler]) -> list[Issue]:
    ctx = run.ctx
    issues: list[Issue] = []
    for h in handlers:
        unit = run.units.get(h.rel)
        if unit is None:
            continue
        page_count = len(unit.page_segments) if unit.kind == "inline" else 1
        for pi in range(min(page_count, MAX_PAGE_ISSUES)):
            url, resp, line, col, page = unit.served(h.line, pi)
            notes = [_note("message_handler", where=f"{url}:{line}")]
            conf = "tentative"
            if h.sink:
                _u, _r, s_line, _c, _p = unit.served(h.sink_line, pi)
                notes.append(_note("message_sink", sink=h.sink, line=s_line))
                conf = "firm"
            if unit.kind == "inline":
                notes.append(_note("inline", page=page))
            elif unit.pages:
                notes.append(_note("loaded_by", pages=_url_list(unit.pages)))
            notes.append(_note("static"))
            line_text = unit.line_text(h.line)
            excerpt = _excerpt(resp, line, col, line_text)
            ev = Evidence.for_response(resp, where="body", name=url, value=excerpt, offset=_offset(resp, line, col),
                                       excerpt=excerpt, now=ctx.now)
            params = {"file": url, "line": line, "column": col + 1, "sink": h.sink,
                      "page": page or (unit.pages[0] if unit.pages else url), "inline": unit.kind == "inline"}
            issues.append(Issue(rule="WEB522", url=page or url, confidence=conf, evidence=ev, params=params,
                                group_value="message|" + re.sub(r"\s+", "", line_text)[:160], notes=notes,
                                host=_host_of(page or url, ctx)))
    return issues


def _remove_tree(path: str) -> None:
    """Remove the temporary directory, also when Windows marks a file read-only."""
    def retry(func, p, _exc):
        try:
            os.chmod(p, 0o700)
            func(p)
        except OSError:
            pass
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=retry)
    else:                                 # pragma: no cover - Python 3.10/3.11
        shutil.rmtree(path, onerror=retry)


def analyse(run: _Run) -> tuple[list[Issue], str]:
    """Write the units to a temp dir, run the engine, map the results. Returns ``(issues, error)``."""
    from .. import taint
    if not run.units:
        return [], ""
    tmp = tempfile.mkdtemp(prefix="kashif-dom-")
    run.tmpdir = tmp                      # for tests: the directory must be gone afterwards
    try:
        files = run.prepare(tmp)
        if not files:
            return [], ""
        groups = run.groups()
        trees = {rel: u.tree for rel, u in run.units.items() if u.tree is not None}
        handlers = message_handlers(trees, groups)
        lowered = {rel: _lower(tree, run.units[rel].text) for rel, tree in trees.items()}
        budget = max(5.0, TIME_BUDGET - (time.monotonic() - run.t0))
        try:
            _projects, findings = taint.analyze_project_full(files, None, {}, budget, lowered)
        finally:
            taint.release_caches()
        if time.monotonic() - run.t0 > TIME_BUDGET:   # the engine degraded: its results may be partial
            run.skips.append(_Skip(run.ctx.target, "time_budget", "skip_time", {"url": run.ctx.target}))
        return _flow_issues(run, findings, groups) + _message_issues(run, handlers), ""
    except Exception as exc:  # noqa: BLE001 - a crash in the analyser must never abort the scan
        return [], f"{type(exc).__name__}: {_short(str(exc), 120)}"
    finally:
        _remove_tree(tmp)


def _inventory(run: _Run) -> dict:
    analysed = [{"url": u.url or (u.pages[0] if u.pages else ""), "kind": u.kind, "pages": len(u.pages) or 1,
                 "reflowed": bool(u.reflow_map)} for u in run.units.values()]
    skipped = [{"url": s.url, "reason": "library" if not s.limitation else s.reason,
                **({"library": s.values["library"]} if not s.limitation and "library" in s.values else {})}
               for s in run.skips]
    return {"analysed": analysed, "skipped": skipped}


def run(ctx: ScanContext) -> list[Issue]:
    cov = ctx.coverage
    host = ctx.target_host
    entry = ctx.entry
    if entry is not None and entry.kind in ("waf_challenge", "rate_limited"):
        if cov is not None:
            for c in CHECKS:
                cov.inconclusive(c, "waf" if entry.kind == "waf_challenge" else "rate_limited", host=host)
        return []
    if not any(_is_document(p) for p in ctx.pages) and not any(_is_script_response(r) for r in ctx.subresources):
        if cov is not None:
            for c in CHECKS:
                cov.not_tested(c, "no_document", host=host)
        return []
    st = _Run(ctx)
    st.collect()
    issues, error = analyse(st)
    if isinstance(ctx.inventory, dict):
        ctx.inventory["dom_scripts"] = _inventory(st)
    if cov is None:
        return issues
    if error:
        en, ar = _note("engine_error", error=error)
        for c in CHECKS:
            cov.not_tested(c, "error", host=host, detail_en=en, detail_ar=ar)
        return issues
    limits = [s for s in st.skips if s.limitation]
    for c in CHECKS:
        for s in limits:
            en, ar = _note(s.note, **s.values)
            cov.not_tested(c, s.reason or "not_run", host=host, detail_en=en, detail_ar=ar)
        mine = [i for i in issues if i.rule == c]
        if any(ctx.options.reports(i.confidence) for i in mine):
            cov.failed(c, host)
        elif mine:
            cov.not_tested(c, "sensitivity", host=host)
        elif st.units:
            cov.passed(c, host)
        elif not limits:
            cov.not_applicable(c, host=host)
    return issues


# ----------------------------------------------------------------------------------------------- i18n

def i18n_catalog() -> tuple[dict[str, str], list[tuple[str, str]]]:
    """``(CATALOG, PATTERNS)`` for cat_web2: fixed Arabic notes → English, regex patterns for templated ones."""
    catalog: dict[str, str] = {}
    patterns: list[tuple[str, str]] = []
    for en, ar in STR.values():
        names = re.findall(r"\{([a-z_]+)\}", ar)
        if not names:
            catalog[ar] = en
            continue
        out, pos, seen = [], 0, []
        for m in re.finditer(r"\{([a-z_]+)\}", ar):
            out.append(re.escape(ar[pos:m.start()]))
            out.append(f"(?P={m.group(1)})" if m.group(1) in seen else f"(?P<{m.group(1)}>.+?)")
            seen.append(m.group(1))
            pos = m.end()
        out.append(re.escape(ar[pos:]))
        patterns.append(("^" + "".join(out) + "$", re.sub(r"\{([a-z_]+)\}", lambda m: f"\\g<{m.group(1)}>", en)))
    return catalog, patterns


__all__ = ["CHECKS", "run", "analyse", "reflow", "library_name", "library_names", "is_dom_source", "source_name",
           "sink_name", "message_handlers", "STR", "RULE_MAP", "MAX_FILES", "MAX_FILE_BYTES", "TIME_BUDGET",
           "i18n_catalog"]
