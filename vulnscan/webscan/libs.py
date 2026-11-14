"""Known-vulnerable and end-of-life JavaScript libraries (spec §2.9), WP9.

Rules: WEB054 (vulnerable library, retire.js data) and WEB803 (end-of-life front-end framework).

Detection is a port of retire.js (``node/lib/retire.js``, Apache-2.0) over the bundled ``jsrepository-v4.json``:

* ``uri`` extractors on every live ``<script src>`` (absolute URL) of every fetched document;
* ``filename`` extractors on the basename of that URL (``^…$`` on the last path segment);
* ``filecontent`` (then ``filecontentreplace``) on the first 2 MB of each fetched script (same-site, and third-party in
  deep mode: the engine fetches them; this module never touches the network) and of each live inline script;
* ``hashes``: SHA-1 of a fetched script's full body (CRLF/CR normalised to LF, as retire.js does), only when no content
  extractor matched and the body was not truncated.

``§§version§§`` becomes ``[0-9][0-9.a-z_\\-]+``; a trailing ``.min``/``-min`` is dropped from the version; dotless runs of
7+ hex characters are bundler hashes, not versions (retire's ``looksLikeHash``). Version comparison is retire's
``isAtOrAbove``. ``func`` and ``ast`` extractors need a JavaScript runtime and are skipped. URLs that match the
``dont check`` entry are skipped as retire does. Only script URLs and script bodies are read, never page prose (D15).

Hostile input (§0.6): JavaScript's ``(?:.|\\r|\\n)`` becomes ``[\\s\\S]``, unbounded quantifiers get generous upper
bounds (:func:`bound_quantifiers`), bodies are matched in chunks under a per-body and per-scan time budget, and a body
that runs out of time leaves WEB054/WEB803 ``inconclusive`` ("time budget") instead of "passed". Results on 1,995 real
JavaScript files are identical to the unguarded matcher.

retire.js marks end-of-life branches with CWE-1104 pseudo-vulnerabilities ("jQuery 1.x and 2.x are End-of-Life");
those feed WEB803, not WEB054. WEB803 also uses ``eol.json`` (endoflife.date) for the front-end products it lists and
a small built-in table when the snapshot lacks one.
"""

from __future__ import annotations

import hashlib
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Iterable

from . import data as _data
from .rules import RULES, checks_for_module
from .types import Evidence, Issue, Page, Response, ScanContext, essence, normalise_host, strip_controls

CHECKS: tuple[str, ...] = checks_for_module("libs")

REPO_FILE = "retire-jsrepository.json.gz"
EOL_FILE = "eol.json"
VERSION_RX = r"[0-9][0-9.a-z_\-]+"
CONTENT_CAP = 2 * 1024 * 1024
# Hostile-input guards (§0.6). retire.js patterns are written for a backtracking engine and several are quadratic
# (``@class easyXDM(?:.|\r|\n)+@version``, ``/\*[\s*!]+(?:@license)?[\s*]+…``): 80 KB of crafted text took 47 s.
# Unbounded quantifiers are therefore capped (generously: real matches span far less), each body is matched in
# chunks with a time budget checked between chunks, and an unfinished body leaves WEB054/WEB803 inconclusive.
REPEAT_ANY = 20_000            # cap for "+"/"*" on ".", [\s\S], negated classes and groups
REPEAT_CLASS = 2_000           # cap for "+"/"*" on specific classes (\s, [a-z], [\s*!] …)
CHUNK = 16_384                 # match starts examined between two budget checks
BODY_BUDGET = 3.0              # seconds of retire matching per script body
RUN_BUDGET = 20.0              # seconds of retire matching per scan
MAX_URL = 4096                 # script URLs longer than this are cut before the uri/filename extractors
MAX_NOTES = 12
MAX_VERSION_LEN = 64                      # a longer run of [0-9.a-z_-] is not a version (hostile bodies)

_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}
_HASHLIKE = re.compile(r"^[0-9a-f]{7,}$")
_MIN_SUFFIX = re.compile(r"(\.|-)min$")
_EOL_SUMMARY = re.compile(r"end[- ]of[- ]life|\bEOL\b|no longer (?:maintained|supported|receiving)|discontinued|"
                          r"support has (?:officially )?ended", re.I)
_JS_ESSENCES = frozenset({"application/javascript", "text/javascript", "application/x-javascript", "text/ecmascript",
                          "application/ecmascript", "module", "text/jscript", "application/x-ecmascript"})

# retire component → endoflife.date product (WEB803)
EOL_PRODUCTS = {"jquery": "jquery", "angularjs": "angularjs", "bootstrap": "bootstrap", "vue": "vue",
                "@angular/core": "angular", "react": "react", "react-dom": "react", "ember": "emberjs",
                "nextjs": "nextjs", "jquery-ui": "jquery-ui", "jquery-mobile": "jquery-mobile", "svelte": "svelte"}
# built-in fallback (spec §2.9 WEB803): component → [(major, EOL date or "")]
BUILTIN_EOL: dict[str, list[tuple[int, str]]] = {
    "jquery": [(1, ""), (2, "")],
    "angularjs": [(1, "2021-12-31")],
    "bootstrap": [(2, "2013-08-19"), (3, "2019-07-24"), (4, "2023-01-01")],
    "vue": [(1, ""), (2, "2023-12-31")],
}

STR: dict[str, tuple[str, str]] = {
    "vuln": ("{ids}: {summary} (fixed in {below})", "{ids}: {summary} (مُصحَّح في {below})"),
    "vuln_nofix": ("{ids}: {summary} (no fixed version listed)", "{ids}: {summary} (لا يوجد إصدار مُصحَّح معروف)"),
    "more": ("…and {count}.", "…و{count}."),
    "detected_by": ("Detected from {how}: {where}", "اكتُشفت من {how}: {where}"),
    "how_uri": ("the script URL", "رابط السكربت"),
    "how_filename": ("the script file name", "اسم ملف السكربت"),
    "how_filecontent": ("the script content", "محتوى السكربت"),
    "how_filecontentreplace": ("the script content", "محتوى السكربت"),
    "how_hash": ("the exact file hash (SHA-1)", "بصمة الملف الدقيقة (SHA-1)"),
    "inline": ("an inline script of {page}", "سكربت مضمَّن في الصفحة {page}"),
    "eol_date": ("The {branch} branch reached end of life on {date}.", "انتهى دعم الفرع {branch} في {date}."),
    "eol_nodate": ("The {branch} branch is end of life and receives no security fixes.",
                   "انتهى دعم الفرع {branch} ولم يعد يتلقى تصحيحات أمان."),
    "eol_retire": ("retire.js: {summary}", "retire.js: {summary}"),
}
_PLACEHOLDER = re.compile(r"\{([a-z_][a-z0-9_]*)\}")
# Arabic count phrases (one, two, few, many, other) for vulnscan.i18n.plural.ar_count
_MORE_VULNS = ("{n} more known vulnerability", "{n} more known vulnerabilities",
              ("ثغرة معروفة أخرى", "ثغرتان معروفتان أخريان", "{n} ثغرات معروفة أخرى", "{n} ثغرةً معروفةً أخرى", "{n} ثغرة معروفة أخرى"))


def _count(n: int, forms: tuple) -> tuple[str, str]:
    from ..i18n.plural import ar_count   # lazy: vulnscan.i18n imports webscan modules through cat_web2
    en = (forms[0] if n == 1 else forms[1]).replace("{n}", str(n))
    return en, ar_count(n, forms[2])


def _note(key: str, **values: Any) -> tuple[str, str]:
    en, ar = STR[key]

    def fill(text: str, lang: str) -> str:
        def sub(m: re.Match) -> str:
            v = values.get(m.group(1), m.group(0))
            if isinstance(v, tuple):
                v = v[1] if lang == "ar" else v[0]
            return strip_controls(str(v))
        return _PLACEHOLDER.sub(sub, text)
    return fill(en, "en"), fill(ar, "ar")


# ----------------------------------------------------------------------------------------------- versions

def _comparable(part: str | None) -> int | str:
    if not part:                          # retire: ``if (!n) return 0`` (missing or empty part, "1.0-")
        return 0
    if part.isdigit() and part.isascii():
        return int(part[:18])             # bounded: Python 3.11+ refuses int() of > 4300 digits (hostile input)
    return part


def is_at_or_above(version1: str, version2: str) -> bool:
    """retire.js ``isAtOrAbove``: split on ``.``/``-``; numbers compare as integers, other parts as strings; a number
    beats a string (``1.0.0`` > ``1.0.0-beta``); a missing part counts as 0."""
    v1 = re.split(r"[.\-]", version1)
    v2 = re.split(r"[.\-]", version2)
    for i in range(max(len(v1), len(v2))):
        a = _comparable(v1[i] if i < len(v1) else None)
        b = _comparable(v2[i] if i < len(v2) else None)
        if type(a) is not type(b):
            return isinstance(a, int)
        if a > b:   # type: ignore[operator]
            return True
        if a < b:   # type: ignore[operator]
            return False
    return True


def vulnerability_matches(version: str, vuln: dict) -> bool:
    """``atOrAbove ≤ version < below`` (either bound optional) and the version is not in ``excludes``."""
    below = vuln.get("below")
    if below is not None and is_at_or_above(version, str(below)):
        return False
    low = vuln.get("atOrAbove")
    if low is not None and not is_at_or_above(version, str(low)):
        return False
    return version not in (vuln.get("excludes") or ())


# ----------------------------------------------------------------------------------------------- repository

# JavaScript's "any character" idiom (?:.|\r|\n) in any order, escaped or with the raw characters JSON decoded:
# the same set as [\s\S] in Python, which backtracks per run instead of per character
_ANY_ALT = r"(?:\.|\\r|\\n|\r|\n)"
_ANY_GROUP = re.compile(r"\((\?:)?(" + _ANY_ALT + r"(?:\|" + _ANY_ALT + r"){2})\)")


def _any_group(m: re.Match) -> str:
    alts = {a.replace("\\", "").replace("\r", "r").replace("\n", "n") for a in m.group(2).split("|")}
    if alts != {".", "r", "n"}:
        return m.group(0)
    return "[\\s\\S]" if m.group(1) else "([\\s\\S])"


def compile_js_regex(pattern: str, *, anchor: bool = False) -> tuple[re.Pattern | None, tuple[re.Pattern, ...]]:
    """Compile a retire.js (JavaScript) regex for Python. Variable-width look-behinds, which Python rejects, are
    removed and returned as post-checks on the captured version (they always follow the version group in retire's
    data). ``(None, ())`` when the pattern cannot be used."""
    src = bound_quantifiers(_ANY_GROUP.sub(_any_group, pattern).replace("§§version§§", VERSION_RX))
    if anchor:
        src = f"^(?:{src})$"
    try:
        return re.compile(src), ()
    except re.error:
        pass
    checks: list[re.Pattern] = []
    out: list[str] = []
    i = 0
    while i < len(src):
        if src.startswith("(?<=", i) or src.startswith("(?<!", i):
            depth, j = 0, i
            while j < len(src):
                ch = src[j]
                if ch == "\\":
                    j += 2
                    continue
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            body = src[i + 4:j]
            if src[i + 3] == "=":
                try:
                    checks.append(re.compile(f"(?:{body})\\Z"))
                except re.error:
                    return None, ()
            i = j + 1
            continue
        if src[i] == "\\" and i + 1 < len(src):
            out.append(src[i:i + 2])
            i += 2
            continue
        out.append(src[i])
        i += 1
    try:
        return re.compile("".join(out)), tuple(checks)
    except re.error:
        return None, ()


_META_CHARS = set(".^$*+?{}[]\\|()")


def bound_quantifiers(src: str) -> str:
    """``src`` with every unbounded quantifier (``*``, ``+``, ``{n,}``, lazy forms included) given an upper bound:
    :data:`REPEAT_ANY` after ``.``, ``[\\s\\S]``-like and negated classes and groups, :data:`REPEAT_CLASS` after
    anything else. Bounded repetition keeps the cost of one match attempt bounded on hostile input."""
    out: list[str] = []
    i, n = 0, len(src)
    last_any = False                  # does the previous atom match (almost) anything?
    while i < n:
        c = src[i]
        if c == "\\" and i + 1 < n:
            out.append(src[i:i + 2])
            last_any = src[i + 1] in "SWD"
            i += 2
            continue
        if c == "[":
            j = i + 1
            if j < n and src[j] == "^":
                j += 1
            k = j + 1 if j < n and src[j] == "]" else j
            while k < n and src[k] != "]":
                k += 2 if src[k] == "\\" else 1
            cls = src[i:k + 1]
            out.append(cls)
            last_any = cls.startswith("[^") or any(p in cls for p in ("\\s\\S", "\\S\\s", "\\w\\W", "\\d\\D"))
            i = k + 1
            continue
        if c in "*+" and out:
            low = "0" if c == "*" else "1"
            out.append("{%s,%d}" % (low, REPEAT_ANY if last_any else REPEAT_CLASS))
            i += 1
            continue
        if c == "{":
            m = re.match(r"\{(\d+),\}", src[i:])
            if m:
                out.append("{%s,%d}" % (m.group(1), max(int(m.group(1)), REPEAT_ANY if last_any else REPEAT_CLASS)))
                i += m.end()
                continue
        if c == "(" and src.startswith("(?", i):
            # "(?:", "(?=", "(?<=", "(?P<name>" …: the "?" is not a quantifier
            m = re.match(r"\(\?(?:P<[^>]*>|<[=!]|[:=!]|[a-zA-Z]+[:)])?", src[i:])
            out.append(m.group(0) if m else "(")
            i += len(m.group(0)) if m else 1
            continue
        out.append(c)
        last_any = c in ".)"
        i += 1
    return "".join(out)


def required_literal(src: str) -> str:
    """A literal substring every match must contain (the longest plain run outside groups/classes), or ``""`` when the
    pattern has a top-level alternation or no run of 4+ plain characters. Used as a cheap prefilter."""
    if "(?i" in src or "(?x" in src:
        return ""
    if "|" in src:
        depth = 0
        k = 0
        while k < len(src):
            c = src[k]
            if c == "\\":
                k += 2
                continue
            if c == "[":
                k = src.find("]", k + 2) + 1 or len(src)
                continue
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            elif c == "|" and depth == 0:
                return ""
            k += 1
    best = cur = ""
    i = 0
    depth = 0
    while i < len(src):
        c = src[i]
        if c == "\\" and i + 1 < len(src):
            nxt = src[i + 1]
            if depth == 0 and (nxt in _META_CHARS or nxt in "/-<>!@#%&=:;,'\"`~ "):
                cur += nxt
            else:
                best, cur = max(best, cur, key=len), ""
            i += 2
            continue
        if c == "[":
            best, cur = max(best, cur, key=len), ""
            j = i + 1
            if j < len(src) and src[j] == "]":
                j += 1
            while j < len(src) and src[j] != "]":
                j += 2 if src[j] == "\\" else 1
            i = j + 1
            continue
        if c in "*?{":
            # the previous character is optional/repeated: it is not part of the required run
            cur = cur[:-1]
            best = max(best, cur, key=len)
            cur = ""
            if c == "{":
                i = src.find("}", i) + 1 or len(src)
                continue
            i += 1
            continue
        if c == "+":
            best, cur = max(best, cur, key=len), ""
            i += 1
            continue
        if c == "(":
            best, cur = max(best, cur, key=len), ""
            depth += 1
            i += 1
            if src.startswith("?:", i) or src.startswith("?=", i) or src.startswith("?!", i):
                i += 2
            continue
        if c == ")":
            best, cur = max(best, cur, key=len), ""
            depth = max(0, depth - 1)
            i += 1
            # a group followed by a quantifier may be absent: the run inside it was already discarded above
            continue
        if c in _META_CHARS:
            best, cur = max(best, cur, key=len), ""
            i += 1
            continue
        if depth == 0:
            cur += c
        else:
            best, cur = max(best, cur, key=len), ""
        i += 1
    lit = max(best, cur, key=len)
    return lit if len(lit) >= 4 else ""


_WORD_BYTES = frozenset(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$")
_TOKEN_TABLE = bytes(c if c in _WORD_BYTES else 32 for c in range(256))
_WORD_RUN = re.compile(r"[A-Za-z0-9_$]+")


def token_requirement(literal: str) -> str:
    """A necessary condition, checked against :func:`token_index`, for ``literal`` to occur in a text.

    Every maximal word (``[A-Za-z0-9_$]+``) of the literal is related to a whole token of the text: a word bounded by
    non-word characters inside the literal *is* a token (``"\\nW\\n"``); a word at the literal's start is the end of a
    token (``"W\\n"``), one at its end the start of a token (``"\\nW"``); a literal that is one word lies inside a token
    (``"W"``). The longest such condition is returned (``""`` when the literal has no word of 3+ characters)."""
    best = ""
    for m in _WORD_RUN.finditer(literal):
        w = m.group(0)
        if len(w) < 3:
            continue
        at_start, at_end = m.start() == 0, m.end() == len(literal)
        cond = w if at_start and at_end else (w + "\n" if at_start else ("\n" + w if at_end else "\n" + w + "\n"))
        if len(cond) > len(best):
            best = cond
    return best


def token_index(text: str) -> str:
    """Every distinct maximal word of ``text``, newline-separated with a leading and trailing newline: a small string
    (usually < 10 % of a script) on which :func:`token_requirement` conditions are cheap substring tests."""
    words = set(text.encode("utf-8", "replace").translate(_TOKEN_TABLE).split())
    return "\n" + b"\n".join(words).decode("ascii") + "\n"


def max_match_length(src: str) -> int | None:
    """An upper bound of the length of any match of ``src``, or None when it has an unbounded quantifier. The version
    sub-pattern counts as at most 64 characters (a longer run of ``[0-9.a-z_-]`` is not a version)."""
    src = src.replace(VERSION_RX, "V" * 64)
    total_bounds = 0
    i = 0
    in_class = False
    while i < len(src):
        c = src[i]
        if c == "\\":
            i += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
        elif c == "[":
            in_class = True
            if src.startswith("[]", i) or src.startswith("[^]", i):
                i += 2
        elif c in "*+":
            return None
        elif c == "{":
            m = re.match(r"\{(\d*)(,?)(\d*)\}", src[i:])
            if m:
                if m.group(2) and not m.group(3):
                    return None
                total_bounds += int(m.group(3) or m.group(1) or 0)
                i += m.end()
                continue
        i += 1
    return len(src) * (1 + total_bounds)


def pattern_width(rx: re.Pattern) -> int | None:
    """The maximum length of a match of ``rx`` (``None`` when unbounded or unknown). Uses the stdlib regex parser's
    own width computation (``re._parser`` on 3.11+, ``sre_parse`` on 3.10); falls back to :func:`max_match_length`."""
    try:
        try:
            from re import _parser as sre   # type: ignore[attr-defined]
        except ImportError:                  # Python 3.10
            import sre_parse as sre          # type: ignore[no-redef]
        hi = sre.parse(rx.pattern, rx.flags & ~re.UNICODE).getwidth()[1]
        return None if hi >= sre.MAXREPEAT else int(hi)
    except Exception:                        # noqa: BLE001 - private API: any change falls back to the estimate
        return max_match_length(rx.pattern)


class BudgetExceeded(Exception):
    """Raised inside a match loop when the matching budget of a body is used up."""


@dataclass
class _Extractor:
    rx: re.Pattern
    checks: tuple[re.Pattern, ...] = ()
    literal: str = ""
    replace: str | None = None        # filecontentreplace: Python replacement template
    need: str = ""                    # token_requirement(literal), checked on the token index first
    bound: int | None = None          # maximum match length: search only windows around the literal

    def __post_init__(self) -> None:
        self.bound = pattern_width(self.rx)
        if self.literal:
            self.need = token_requirement(self.literal)

    def candidate(self, text: str, index: str | None) -> bool:
        if not self.literal:
            return True
        if index is not None and self.need and self.need not in index:
            return False
        return self.literal in text

    def _intervals(self, text: str) -> list[tuple[int, int]]:
        """Where matches can be: the whole text, or (bounded pattern with a literal) the union of the windows
        ``[occurrence - bound, occurrence + len(literal) + bound]``, merged."""
        if not self.literal or self.bound is None:
            return [(0, len(text))]
        out: list[list[int]] = []
        size, bound = len(self.literal), self.bound
        pos = text.find(self.literal)
        seen = 0
        while pos >= 0:
            seen += 1
            if seen > 1000:                  # a literal repeated this often (hostile filler): scan everything in chunks
                return [(0, len(text))]
            lo, hi = max(0, pos - bound), min(len(text), pos + size + bound)
            if out and lo <= out[-1][1]:
                out[-1][1] = max(out[-1][1], hi)
            else:
                out.append([lo, hi])
            pos = text.find(self.literal, pos + 1)
        return [(a, b) for a, b in out]

    def finditer(self, text: str, deadline: float | None = None) -> Iterable[re.Match]:
        """retire's global match (leftmost, non-overlapping) restricted to the literal's windows, examined in chunks
        of :data:`CHUNK` match starts; :class:`BudgetExceeded` when ``deadline`` (``time.monotonic``) passes."""
        reach = self.bound if self.bound is not None else len(text)
        for lo, hi in self._intervals(text):
            start = lo
            while start < hi:
                if deadline is not None and time.monotonic() > deadline:
                    raise BudgetExceeded
                stop = min(hi, start + CHUNK)
                nxt = stop
                for m in self.rx.finditer(text, start, min(hi, stop + reach) if stop < hi else hi):
                    if m.start() >= stop:
                        break
                    yield m
                    nxt = max(stop, m.end()) if m.end() > stop else nxt
                start = nxt


@dataclass
class Library:
    component: str
    name: str
    vulnerabilities: list[dict]
    uri: list[_Extractor] = field(default_factory=list)
    filename: list[_Extractor] = field(default_factory=list)
    filecontent: list[_Extractor] = field(default_factory=list)
    filecontentreplace: list[_Extractor] = field(default_factory=list)
    hashes: dict[str, str] = field(default_factory=dict)


@dataclass
class Repository:
    libraries: dict[str, Library]
    dont_check: list[_Extractor]
    by_hash: dict[str, tuple[str, str]]
    skipped_patterns: int = 0
    date: str = ""


_REPLACEMENT = re.compile(r"^/(.*[^\\])/([^/]+)/$", re.S)


def build_repository(repo: dict, date_: str = "") -> Repository:
    libs: dict[str, Library] = {}
    dont: list[_Extractor] = []
    skipped = 0
    by_hash: dict[str, tuple[str, str]] = {}
    for component, entry in repo.items():
        if not isinstance(entry, dict):
            continue
        ext = entry.get("extractors") or {}
        if component == "dont check":
            for p in ext.get("uri", []) or []:
                rx, checks = compile_js_regex(p)
                if rx is not None:
                    dont.append(_Extractor(rx, checks))
            continue
        names = entry.get("bowername") or []
        lib = Library(component=component, name=str(names[0]) if names else component,
                      vulnerabilities=list(entry.get("vulnerabilities") or []))
        for kind in ("uri", "filename", "filecontent"):
            for p in ext.get(kind, []) or []:
                rx, checks = compile_js_regex(str(p), anchor=(kind == "filename"))
                if rx is None:
                    skipped += 1
                    continue
                lit = required_literal(rx.pattern) if kind == "filecontent" and not checks else ""
                getattr(lib, kind).append(_Extractor(rx, checks, lit))
        for p in ext.get("filecontentreplace", []) or []:
            m = _REPLACEMENT.match(str(p))
            if not m:
                skipped += 1
                continue
            rx, checks = compile_js_regex(m.group(1))
            if rx is None:
                skipped += 1
                continue
            repl = re.sub(r"\$(\d)", r"\\g<\1>", m.group(2))
            lib.filecontentreplace.append(_Extractor(rx, checks, required_literal(rx.pattern), repl))
        for h, v in (ext.get("hashes") or {}).items():
            lib.hashes[str(h).lower()] = str(v)
            by_hash.setdefault(str(h).lower(), (component, str(v)))
        libs[component] = lib
    return Repository(libs, dont, by_hash, skipped, date_)


_REPO_CACHE: dict[int, Repository] = {}


def load_repository(data_mod: Any = None) -> Repository | None:
    """The compiled bundled (or updated) retire.js repository; ``None`` when the data file is missing."""
    dm = data_mod or _data
    try:
        obj = dm.load_json(REPO_FILE)
    except (OSError, ValueError):
        return None
    key = id(obj)
    if key not in _REPO_CACHE:
        meta = obj.get("meta", {}) if isinstance(obj, dict) else {}
        _REPO_CACHE.clear()
        _REPO_CACHE[key] = build_repository(obj.get("repository", {}) if isinstance(obj, dict) else {},
                                            str(meta.get("date", "")))
    return _REPO_CACHE[key]


# ----------------------------------------------------------------------------------------------- scanning

@dataclass
class Detection:
    component: str
    version: str
    method: str                      # uri | filename | filecontent | filecontentreplace | hash
    match: str = ""
    offset: int | None = None


def _clean_version(v: str) -> str:
    return _MIN_SUFFIX.sub("", v)


def _plausible(v: str) -> bool:
    return 0 < len(v) <= MAX_VERSION_LEN and not _HASHLIKE.match(v)


def _matches(ex: _Extractor, text: str, *, anchored: bool = False,
             deadline: float | None = None) -> Iterable[tuple[str, str, int]]:
    """(version, matched text, offset) for every match of an extractor (retire's global ``simpleMatch``)."""
    if anchored:
        m = ex.rx.match(text)
        found: Iterable[re.Match] = [m] if m else []
    else:
        found = ex.finditer(text, deadline)
    for m in found:
        if m.lastindex is None or m.group(1) is None:
            continue
        ver = m.group(1)
        if ex.checks and not all(c.search(text, 0, m.end(1)) for c in ex.checks):
            continue
        yield ver, m.group(0), m.start()


def _dedupe(found: list[Detection]) -> list[Detection]:
    seen: set[tuple[str, str]] = set()
    out = []
    for d in found:
        key = (d.component, d.version)
        if key not in seen:
            seen.add(key)
            out.append(d)
    return out


def skipped_by_repo(url: str, repo: Repository) -> bool:
    return any(ex.rx.search(url) for ex in repo.dont_check)


def scan_uri(uri: str, repo: Repository) -> list[Detection]:
    uri = uri[:MAX_URL]
    out = []
    for lib in repo.libraries.values():
        for ex in lib.uri:
            for ver, text, off in _matches(ex, uri):
                ver = _clean_version(ver)
                if _plausible(ver):
                    out.append(Detection(lib.component, ver, "uri", text, off))
    return _dedupe(out)


def scan_filename(name: str, repo: Repository) -> list[Detection]:
    base = re.split(r"[/\\]", name[:MAX_URL])[-1]
    out = []
    for lib in repo.libraries.values():
        for ex in lib.filename:
            for ver, text, off in _matches(ex, base, anchored=True):
                ver = _clean_version(ver)
                if _plausible(ver):
                    out.append(Detection(lib.component, ver, "filename", text, off))
    return _dedupe(out)


def normalise_newlines(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def scan_content(text: str, repo: Repository) -> list[Detection]:
    """``filecontent`` extractors, then ``filecontentreplace`` when nothing matched (retire's order)."""
    return scan_content_checked(text, repo)[0]


def scan_content_checked(text: str, repo: Repository, deadline: float | None = None) -> tuple[list[Detection], bool]:
    """:func:`scan_content` with a ``time.monotonic()`` deadline: ``(detections found so far, complete)``."""
    text = normalise_newlines(text[:CONTENT_CAP])
    tokens = token_index(text) if len(text) > 4096 else None
    out: list[Detection] = []
    try:
        for lib in repo.libraries.values():
            for ex in lib.filecontent:
                if not ex.candidate(text, tokens):
                    continue
                for ver, mtext, off in _matches(ex, text, deadline=deadline):
                    ver = _clean_version(ver)
                    if 0 < len(ver) <= MAX_VERSION_LEN:
                        out.append(Detection(lib.component, ver, "filecontent", mtext, off))
        if not out:
            for lib in repo.libraries.values():
                for ex in lib.filecontentreplace:
                    if not ex.candidate(text, tokens):
                        continue
                    for m in ex.finditer(text, deadline):
                        ver = _clean_version(ex.rx.sub(ex.replace or "", m.group(0), count=1))
                        if 0 < len(ver) <= MAX_VERSION_LEN:
                            out.append(Detection(lib.component, ver, "filecontentreplace", m.group(0), m.start()))
    except BudgetExceeded:
        return _dedupe(out), False
    return _dedupe(out), True


def body_sha1(body: bytes) -> str:
    return hashlib.sha1(body.replace(b"\r\n", b"\n").replace(b"\r", b"\n"), usedforsecurity=False).hexdigest()


def scan_hash(body: bytes, repo: Repository) -> list[Detection]:
    hit = repo.by_hash.get(body_sha1(body))
    if hit is None:
        return []
    return [Detection(hit[0], hit[1], "hash", body_sha1(body), None)]


def check(detection: Detection, repo: Repository) -> list[dict]:
    lib = repo.libraries.get(detection.component)
    if lib is None:
        return []
    return [v for v in lib.vulnerabilities if vulnerability_matches(detection.version, v)]


def is_eol_marker(vuln: dict) -> bool:
    """retire's end-of-life pseudo-vulnerabilities (CWE-1104 with an EOL summary): WEB803, not WEB054."""
    cwe = vuln.get("cwe") or []
    summary = str((vuln.get("identifiers") or {}).get("summary", ""))
    return "CWE-1104" in cwe and bool(_EOL_SUMMARY.search(summary))


# ----------------------------------------------------------------------------------------------- EOL (WEB803)

def _cycle_matches(version: str, cycle: str) -> bool:
    vp = re.split(r"[.\-]", version)
    cp = re.split(r"[.\-]", cycle)
    return len(vp) >= len(cp) and vp[:len(cp)] == cp


def eol_cycle(product: dict, version: str) -> dict | None:
    """The endoflife.date cycle of ``version``: the most specific cycle whose parts prefix the version's."""
    best = None
    for c in product.get("cycles", []):
        cyc = str(c.get("cycle", ""))
        if cyc and _cycle_matches(version, cyc) and (best is None or len(cyc) > len(str(best["cycle"]))):
            best = c
    return best


def _past(value: Any, today: date) -> tuple[bool, str]:
    """(is past, ISO date) for an endoflife ``eol`` field: a date string or a boolean."""
    if value is True:
        return True, ""
    if isinstance(value, str):
        try:
            return date.fromisoformat(value) <= today, value
        except ValueError:
            return False, ""
    return False, ""


def eol_status(component: str, version: str, today: date, eol_data: dict | None,
               retire_markers: list[dict]) -> tuple[str, str, str] | None:
    """``(branch, date, source)`` when ``component@version`` is in an end-of-life branch, else None."""
    product_id = EOL_PRODUCTS.get(component)
    products = (eol_data or {}).get("products", {}) if isinstance(eol_data, dict) else {}
    product = products.get(product_id) if product_id else None
    if product:
        cyc = eol_cycle(product, version)
        if cyc is not None:
            past, when = _past(cyc.get("eol"), today)
            if past:
                return str(cyc["cycle"]), when, "eol.json"
            return None          # a known supported cycle: the snapshot decides, not the fallbacks
    major_s = re.split(r"[.\-]", version)[0]
    if major_s.isdigit():
        for major, when in BUILTIN_EOL.get(component, ()):
            if int(major_s) == major and (not when or date.fromisoformat(when) <= today):
                return f"{major}.x", when, "builtin"
    if retire_markers:
        return f"{major_s}.x" if major_s.isdigit() else version, "", "retire"
    return None


# ----------------------------------------------------------------------------------------------- the run

@dataclass
class _Hit:
    detection: Detection
    page: Page | None
    response: Response | None         # the script response for content/hash hits
    script_url: str
    inline_page: str = ""


def _is_script_response(r: Response) -> bool:
    if r.status is None or r.error or not (200 <= r.status < 300):
        return False
    if r.kind == "script":
        return True
    ess = essence(r.content_type)
    if ess in _JS_ESSENCES:
        return True
    if r.kind and r.kind not in ("text", "other", "download"):
        return False                 # an HTML catch-all page, an image, a stylesheet …: no script runs
    # A browser runs a <script src> served as text/plain or application/octet-stream (a common S3 default) unless
    # nosniff is set or the type is one it always blocks (Fetch "should response to request be blocked due to MIME").
    if ess.startswith(("audio/", "image/", "video/")) or ess == "text/csv":
        return False
    if (r.headers.first("x-content-type-options") or "").strip().lower().startswith("nosniff"):
        return False
    head = r.body[:256].lstrip().lower()
    return not head.startswith((b"<!doctype", b"<html", b"<head", b"<body", b"<?xml", b"{", b"["))


def _script_srcs(page: Page) -> list[str]:
    doc = page.doc
    if doc is None:
        return []
    out: list[str] = []
    for el in doc.find_all("script"):
        src = el.get("src")
        if not src or not src.strip():
            continue
        url = doc.resolve(src.strip())
        if url.startswith(("http://", "https://")) and url not in out:
            out.append(url)
    return out


def _requested_urls(r: Response) -> list[str]:
    urls = [r.url]
    if r.chain:
        urls.insert(0, r.chain[0].url)
    return urls


class _Run:
    def __init__(self, ctx: ScanContext, repo: Repository):
        self.ctx = ctx
        self.repo = repo
        self.hits: dict[tuple[str, str], list[_Hit]] = {}
        self.order: list[tuple[str, str]] = []
        self.run_deadline = time.monotonic() + RUN_BUDGET
        self.incomplete: list[str] = []      # bodies whose matching ran out of time (§0.6 hostile input)

    def content(self, text: str, where: str) -> list[Detection]:
        """retire content extractors on one body, within the per-body and per-scan time budgets."""
        now = time.monotonic()
        if now >= self.run_deadline:
            self.incomplete.append(where)
            return []
        found, complete = scan_content_checked(text, self.repo, min(now + BODY_BUDGET, self.run_deadline))
        if not complete:
            self.incomplete.append(where)
        return found

    def add(self, hit: _Hit) -> None:
        key = (hit.detection.component, hit.detection.version)
        if key not in self.hits:
            self.hits[key] = []
            self.order.append(key)
        self.hits[key].append(hit)

    def collect(self) -> int:
        ctx, repo = self.ctx, self.repo
        scripts: dict[str, Response] = {}
        for r in ctx.subresources:
            if _is_script_response(r):
                for u in _requested_urls(r):
                    scripts.setdefault(u, r)
        referenced: dict[str, Page] = {}
        units = 0
        for page in ctx.pages:
            for url in _script_srcs(page):
                referenced.setdefault(url, page)
            if page.doc is not None:
                for s in page.doc.inline_scripts:
                    if not s.live or not s.is_javascript or not s.text.strip():
                        continue
                    units += 1
                    for d in self.content(s.text, page.response.url):
                        d.offset = (s.offset + d.offset) if d.offset is not None else s.offset
                        self.add(_Hit(d, page, page.response, page.response.url, inline_page=page.response.url))
        # URL-based detection on every referenced script, content/hash on the fetched ones
        done: set[int] = set()
        for url, page in referenced.items():
            units += 1
            if skipped_by_repo(url, repo):
                continue
            resp = scripts.get(url)
            fetched_bad = resp is None and self._fetched_but_not_script(url)
            if fetched_bad:
                continue          # the browser gets no script there (404, catch-all HTML): nothing is loaded
            for d in scan_uri(url, repo) + scan_filename(url.split("?", 1)[0].split("#", 1)[0], repo):
                self.add(_Hit(d, page, page.response, url))
            if resp is not None and id(resp) not in done:
                done.add(id(resp))
                self._scan_body(resp, page)
        for r in ctx.subresources:           # fetched scripts no parsed page references (e.g. from a crawl hop)
            if id(r) in done or not _is_script_response(r):
                continue
            done.add(id(r))
            units += 1
            if skipped_by_repo(r.url, repo):
                continue
            self._scan_body(r, None)
        return units

    def _fetched_but_not_script(self, url: str) -> bool:
        for r in self.ctx.subresources:
            if url in _requested_urls(r):
                if r.status is None:
                    return False      # no answer (DNS, proxy, timeout): unknown, so the URL evidence still counts
                return not _is_script_response(r)
        return False

    def _scan_body(self, resp: Response, page: Page | None) -> None:
        try:
            text = resp.text()
        except (LookupError, ValueError):
            text = resp.body.decode("utf-8", "replace")
        found = self.content(text, resp.url)
        if not found and not resp.truncated:
            found = scan_hash(resp.body, self.repo)
        for d in found:
            self.add(_Hit(d, page, resp, resp.url))


def _site_url(ctx: ScanContext, hit: _Hit) -> str:
    if hit.page is not None:
        return hit.page.response.url
    if ctx.entry is not None:
        return ctx.entry.url
    return hit.script_url


def _max_version(versions: list[str]) -> str:
    best = ""
    for v in versions:
        if not best or not is_at_or_above(best, v):
            best = v
    return best


def _ids(vuln: dict) -> str:
    ident = vuln.get("identifiers") or {}
    ids: list[str] = []
    for key in ("CVE",):
        for c in ident.get(key) or []:
            ids.append(str(c))
    if ident.get("githubID"):
        ids.append(str(ident["githubID"]))
    if not ids:
        for key in ("issue", "bug", "PR", "pr", "retid"):
            if ident.get(key):
                ids.append(f"{key} {ident[key]}")
                break
    return ", ".join(ids) or "retire.js"


def _evidence(ctx: ScanContext, hit: _Hit) -> Evidence:
    d = hit.detection
    if d.method in ("uri", "filename"):
        return Evidence.for_response(hit.response, where="body", name="script src", value=hit.script_url,
                                     excerpt=d.match, now=ctx.now)
    if d.method == "hash":
        return Evidence.for_response(hit.response, where="body", name="sha1", value=d.match, now=ctx.now)
    return Evidence.for_response(hit.response, where="body", name="script" if not hit.inline_page else "inline script",
                                 value=d.match[:300], offset=d.offset, excerpt=d.match, now=ctx.now)


def _how(method: str) -> tuple[str, str]:
    return STR.get(f"how_{method}", STR["how_filecontent"])


def run(ctx: ScanContext) -> list[Issue]:
    cov = ctx.coverage
    dm = ctx.data or _data
    repo = load_repository(dm)
    host = ctx.target_host
    if repo is None:
        if cov is not None:
            for c in CHECKS:
                cov.not_tested(c, "data_missing", host=host)
        return []
    if not ctx.pages and not any(_is_script_response(r) for r in ctx.subresources):
        if cov is not None:
            for c in CHECKS:
                cov.not_tested(c, "no_document", host=host)
        return []
    st = _Run(ctx, repo)
    st.collect()
    try:
        eol_data = dm.load_json(EOL_FILE)
    except (OSError, ValueError):
        eol_data = None
    today = ctx.now.date()
    issues: list[Issue] = []
    inventory: list[dict] = []
    failed: set[str] = set()
    for key in st.order:
        hits = st.hits[key]
        component, version = key
        lib = repo.libraries.get(component)
        if lib is None:
            continue
        # strongest evidence first: hash, content, filename, uri
        rank = {"hash": 0, "filecontent": 1, "filecontentreplace": 1, "filename": 2, "uri": 3}
        hits.sort(key=lambda h: rank.get(h.detection.method, 9))
        best = hits[0]
        vulns = check(best.detection, repo)
        markers = [v for v in vulns if is_eol_marker(v)]
        real = [v for v in vulns if not is_eol_marker(v)]
        site_url = _site_url(ctx, best)
        site_host = normalise_host(urllib.parse.urlsplit(site_url).hostname or "") or host
        where = _note("inline", page=best.inline_page) if best.inline_page else best.script_url
        detected = _note("detected_by", how=_how(best.detection.method), where=where)
        eol = eol_status(component, version, today, eol_data, markers)
        inventory.append({"name": lib.name, "component": component, "version": version,
                          "detection": best.detection.method, "url": best.script_url, "vulnerable": bool(real),
                          "eol": bool(eol)})
        if real:
            sev = max((str(v.get("severity", "medium")).lower() for v in real), key=lambda s: _SEV_ORDER.get(s, 2))
            if sev not in RULES["WEB054"].allowed_severities:
                sev = "medium"
            fixes = [str(v["below"]) for v in real if v.get("below")]
            fixed = _max_version(fixes) if fixes else ""
            notes = [detected]
            ordered = sorted(real, key=lambda v: -_SEV_ORDER.get(str(v.get("severity", "")).lower(), 0))
            for v in ordered[:MAX_NOTES]:
                summary = str((v.get("identifiers") or {}).get("summary") or "").strip()
                summary = " ".join(summary.split())[:160] or str(v.get("severity", ""))
                if v.get("below"):
                    notes.append(_note("vuln", ids=_ids(v), summary=summary, below=v["below"]))
                else:
                    notes.append(_note("vuln_nofix", ids=_ids(v), summary=summary))
            if len(ordered) > MAX_NOTES:
                notes.append(_note("more", count=_count(len(ordered) - MAX_NOTES, _MORE_VULNS)))
            conf = "certain" if best.detection.method == "hash" else "firm"
            params = {"library": lib.name, "version": version, "fixed": fixed or "latest",
                      "cves": [i for v in ordered for i in ((v.get("identifiers") or {}).get("CVE") or [])][:50],
                      "detection": best.detection.method, "script": best.script_url}
            issues.append(Issue(rule="WEB054", url=site_url, confidence=conf, evidence=_evidence(ctx, best),
                                params=params, severity=sev, group_value=f"{component}@{version}", notes=notes,
                                host=site_host))
            if ctx.options.reports(conf):
                failed.add("WEB054")
        if eol is not None:
            branch, when, source = eol
            notes = [detected, _note("eol_date", branch=branch, date=when) if when else _note("eol_nodate", branch=branch)]
            for m in markers[:1]:
                summary = " ".join(str((m.get("identifiers") or {}).get("summary") or "").split())[:160]
                if summary:
                    notes.append(_note("eol_retire", summary=summary))
            params = {"library": lib.name, "version": version, "branch": branch, "date": when, "source": source}
            issues.append(Issue(rule="WEB803", url=site_url, confidence="firm", evidence=_evidence(ctx, best),
                                params=params, group_value=f"{component}@{branch}", notes=notes, host=site_host))
            if ctx.options.reports("firm"):
                failed.add("WEB803")
    ctx.inventory.setdefault("libraries", []).extend(inventory)
    if cov is not None:
        for c in CHECKS:
            if c in failed:
                cov.failed(c, host)
            elif st.incomplete:
                # a body could not be matched completely in time: "no vulnerable library" would be a guess
                shown = ", ".join(strip_controls(u)[:120] for u in st.incomplete[:3])
                cov.inconclusive(c, "time_budget", host=host, detail_en=f"library matching stopped on {shown}",
                                 detail_ar=f"توقّفت مطابقة المكتبات عند {shown}")
            else:
                cov.passed(c, host)
    return issues


def i18n_catalog() -> tuple[dict[str, str], list[tuple[str, str]]]:
    """``(CATALOG, PATTERNS)`` for cat_web2: fixed Arabic notes → English, and patterns for templated ones."""
    from .rules import template_patterns
    catalog: dict[str, str] = {}
    patterns: list[tuple[str, str]] = []
    for en, ar in STR.values():
        if "{" in ar:
            patterns.extend(template_patterns(ar, en))
        else:
            catalog[ar] = en
    return catalog, patterns


__all__ = ["CHECKS", "run", "is_at_or_above", "vulnerability_matches", "compile_js_regex", "required_literal",
           "build_repository", "load_repository", "scan_uri", "scan_filename", "scan_content", "scan_hash", "check",
           "is_eol_marker", "eol_status", "eol_cycle", "body_sha1", "Detection", "Repository", "i18n_catalog", "STR"]
