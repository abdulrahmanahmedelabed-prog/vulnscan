"""English catalog: the 1.1.0 passive web scanner (``vulnscan/webscan``), built from its sources on first use.

Nothing here is hand-written: the rule registry (``webscan.rules``: names, titles, advice and their variants, families,
grade families) and every webscan module that emits Arabic text (notes, reasons, coverage states, remediation
snippets) provide ``i18n_catalog() -> (CATALOG, PATTERNS)``; a module's ``STR`` table of ``key → (en, ar)`` pairs is
read as well (each templated pair becomes one anchored pattern, :func:`plain_pattern`), so a module without its own
``i18n_catalog`` is still covered. The Arabic titles and advice of the data files (``exposed-paths.json``, the deep
paths of ``tech.json``, ``secret-rules.json``) are included too, so a data refresh cannot add an untranslated string.

**Lazy.** Building this catalogue imports every webscan module and compiles about 700 regular expressions (≈ 0.35 s),
which every ``kashif`` command would otherwise pay at start-up (``vulnscan.model`` imports ``vulnscan.i18n``). So
``CATALOG`` and ``PATTERNS`` start empty and :func:`load` builds them once, on the first of:

* an explicit :func:`ensure_loaded` (the web engine calls it before rendering English), or
* a ``vulnscan.i18n.to_en`` call whose text no other catalogue translates: while ``vulnscan.i18n`` loads its modules,
  ``CATALOG.items()`` appends a loader entry to the end of ``vulnscan.i18n.PATTERNS``; when the lookup reaches it, the
  web catalogue is installed into ``vulnscan.i18n`` (exact strings into its ``CATALOG``, patterns right after the
  loader) and the same lookup continues through them. Code scans never reach the loader for their own strings.

The 1.0.1 strings of ``vulnscan/web.py`` stay in ``cat_web`` (earlier in ``vulnscan.i18n``, so their English is
unchanged for 1.x reports). A source that fails to import is skipped and named in ``FAILED`` (an i18n problem must never
stop the scanner); ``tests/web/test_remediation.py`` asserts ``FAILED`` is empty.
"""

from __future__ import annotations

import importlib
import json
import re
import sys
import threading

FAILED: list[tuple[str, str]] = []
_COMPILED: dict[str, re.Pattern] = {}
_LOCK = threading.RLock()
_STATE = {"built": False, "installed": False, "hooked": False}


class _Catalog(dict):
    """The exact-string catalogue. Reading it through ``items()`` (what ``vulnscan.i18n`` does at import) hooks the
    lazy loader into ``vulnscan.i18n``; it stays empty until :func:`load`."""

    def items(self):
        _hook()
        return super().items()


CATALOG: dict[str, str] = _Catalog()
PATTERNS: list[tuple[str, str]] = []

# webscan modules with user-facing Arabic text, in priority order (the registry first; the first English wins)
SOURCES = ("rules", "remediation", "coverage", "data", "http", "robots", "classify", "transport", "headers", "csp",
           "cors", "cookies", "content", "domxss", "disclosure", "libs", "tech", "exposure", "sectxt", "group", "grade",
           "diff", "engine", "tls.assess", "tls.probe")

# data files whose records carry title_ar/advice_ar next to title_en/advice_en
DATA_FILES = ("exposed-paths.json", "tech.json", "secret-rules.json")

_ARABIC = re.compile(r"[؀-ۿݐ-ݿﭐ-﷿ﹰ-﻿]")
_PLACEHOLDER = re.compile(r"\{[a-z_][a-z0-9_]*\}")


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _add(ar: str, en: str) -> None:
    if isinstance(ar, str) and isinstance(en, str) and _ARABIC.search(ar) and en:
        CATALOG.setdefault(_norm(ar), en)


_GROUP = re.compile(r"\(\?P<([A-Za-z_][A-Za-z0-9_]*)>\.\+\?\)")


def _dedupe_groups(rx: str) -> str:
    """A placeholder used twice in one template becomes a back-reference the second time (``(?P=name)``), because a
    regular expression cannot define the same group name twice."""
    seen: set[str] = set()

    def sub(m: re.Match) -> str:
        if m.group(1) in seen:
            return f"(?P={m.group(1)})"
        seen.add(m.group(1))
        return m.group(0)

    return _GROUP.sub(sub, rx)


def _add_pattern(rx: str, en: str, seen: set[str], source: str = "") -> None:
    rx = _dedupe_groups(rx)
    if rx in seen:
        return
    try:
        _COMPILED[rx] = re.compile(rx, re.S)
    except re.error as exc:
        FAILED.append((source or "pattern", f"{exc}: {rx[:80]}"))
        return
    seen.add(rx)
    PATTERNS.append((rx, en))


def plain_pattern(ar: str, en: str) -> tuple[str, str]:
    """A pattern for a template as written: every ``{name}`` matches whatever the module substituted (a module that
    formats a count phrase itself, through ``plural.py``, provides those forms in its own ``i18n_catalog``)."""
    out, pos = [], 0
    for m in _PLACEHOLDER.finditer(ar):
        out.append(re.escape(ar[pos:m.start()]))
        out.append(f"(?P<{m.group(0)[1:-1]}>.+?)")
        pos = m.end()
    out.append(re.escape(ar[pos:]))
    return "".join(out), _PLACEHOLDER.sub(lambda m: f"\\g<{m.group(0)[1:-1]}>", en)


def _from_str_table(table: dict, seen: set[str], source: str) -> None:
    for pair in table.values():
        if not (isinstance(pair, tuple) and len(pair) == 2):
            continue
        en, ar = pair
        if not isinstance(ar, str) or not isinstance(en, str):
            continue
        if _PLACEHOLDER.search(ar):
            rx, repl = plain_pattern(ar, en)
            _add_pattern(rx, repl, seen, source)
        else:
            _add(ar, en)


def _walk_records(node, out: list[tuple[str, str]]) -> None:
    if isinstance(node, dict):
        for what in ("title", "advice", "name", "note", "reason"):
            ar, en = node.get(f"{what}_ar"), node.get(f"{what}_en")
            if isinstance(ar, str) and isinstance(en, str):
                out.append((ar, en))
        for v in node.values():
            _walk_records(v, out)
    elif isinstance(node, list):
        for v in node:
            _walk_records(v, out)


def _from_data_files(template_patterns, seen: set[str]) -> None:
    try:
        from ..webscan import data as wdata
    except Exception as exc:   # pragma: no cover - reported through FAILED
        FAILED.append(("data files", repr(exc)))
        return
    for name in DATA_FILES:
        try:
            blob = wdata.load_json(name)
        except Exception:
            try:
                from importlib import resources
                blob = json.loads(resources.files("vulnscan").joinpath("data", "web", name).read_text(encoding="utf-8"))
            except Exception as exc:
                FAILED.append((name, repr(exc)))
                continue
        pairs: list[tuple[str, str]] = []
        _walk_records(blob, pairs)
        for ar, en in pairs:
            if _PLACEHOLDER.search(ar):
                for rx, repl in template_patterns(ar, en):
                    _add_pattern(rx, repl, seen, name)
            else:
                _add(ar, en)


def _build() -> None:
    from ..webscan.rules import template_patterns
    seen: set[str] = set()
    for name in SOURCES:
        try:
            mod = importlib.import_module(f"vulnscan.webscan.{name}")
        except ModuleNotFoundError as exc:
            if exc.name == f"vulnscan.webscan.{name}":
                continue   # module not part of this build (e.g. not assembled yet)
            FAILED.append((name, repr(exc)))
            continue
        except Exception as exc:
            FAILED.append((name, repr(exc)))
            continue
        try:
            fn = getattr(mod, "i18n_catalog", None)
            if callable(fn):
                catalog, patterns = fn()
                for ar, en in catalog.items():
                    _add(ar, en)
                for rx, en in patterns:
                    _add_pattern(rx, en, seen, name)
            table = getattr(mod, "STR", None)
            if isinstance(table, dict):
                _from_str_table(table, seen, name)
        except Exception as exc:
            FAILED.append((name, repr(exc)))
    _from_data_files(template_patterns, seen)
    # most specific first: "X {a} allows {b} without a nonce." must be tried before "X {a} allows {b}", whose lazy last
    # group would otherwise swallow the rest of the sentence (stable, so equal lengths keep their source order)
    PATTERNS.sort(key=lambda p: -len(_ANY_GROUP.sub("", p[0])))


_ANY_GROUP = re.compile(r"\(\?P<[A-Za-z_][A-Za-z0-9_]*>\.\+\?\)|\(\?P=[A-Za-z_][A-Za-z0-9_]*\)")


def load() -> tuple[dict[str, str], list[tuple[str, str]]]:
    """Build the catalogue once (thread-safe) and return ``(CATALOG, PATTERNS)``: Arabic → English exact strings and
    ``(regular expression, English replacement)`` pairs, as the other ``cat_*`` modules define them."""
    with _LOCK:
        if not _STATE["built"]:
            _STATE["built"] = True
            try:
                _build()
            except Exception as exc:   # never let a broken source break translation of everything else
                FAILED.append(("build", repr(exc)))
    return CATALOG, PATTERNS


# ----------------------------------------------------------------------------------------------- lazy install

class _Hit:
    """A match-like result for an exact catalogue hit (``vulnscan.i18n.to_en`` reads ``groupdict()``)."""

    __slots__ = ("_en",)

    def __init__(self, en: str):
        self._en = en

    def groupdict(self) -> dict[str, str]:
        return {"t": self._en}


class _Exact:
    """Pattern-like lookup of the exact strings, for the one ``to_en`` call that triggered the install (later calls
    find them in ``vulnscan.i18n.CATALOG`` directly)."""

    pattern = "<kashif web catalogue: exact strings>"

    def fullmatch(self, text, *args):
        en = dict.get(CATALOG, text)
        return _Hit(en) if en is not None else None


class _Loader:
    """Pattern-like entry at the end of ``vulnscan.i18n.PATTERNS``; reaching it means no other catalogue knew the text."""

    pattern = "<kashif web catalogue: loader>"

    def fullmatch(self, text, *args):
        ensure_loaded()
        return None


_LOADER = _Loader()


def _i18n():
    return sys.modules.get("vulnscan.i18n")


def _hook() -> None:
    mod = _i18n()
    pats = getattr(mod, "PATTERNS", None)
    with _LOCK:
        if _STATE["hooked"] or _STATE["installed"] or not isinstance(pats, list):
            return
        _STATE["hooked"] = True
        if not any(p is _LOADER for p, _ in pats):
            pats.append((_LOADER, ""))


def ensure_loaded() -> None:
    """Build the catalogue and install it into ``vulnscan.i18n`` (idempotent, thread-safe)."""
    with _LOCK:
        if _STATE["installed"]:
            return
        _STATE["installed"] = True
        load()
        mod = _i18n()
        if mod is None or not isinstance(getattr(mod, "PATTERNS", None), list):
            return
        norm = getattr(mod, "_norm", lambda t: re.sub(r"\s+", " ", t).strip())
        target = mod.CATALOG
        for ar, en in dict.items(CATALOG):
            target.setdefault(norm(ar), en)
        compiled = [(_Exact(), "\\g<t>")]
        compiled += [(_COMPILED.get(rx) or re.compile(rx, re.S), en) for rx, en in PATTERNS]
        pats = mod.PATTERNS
        at = next((i for i, (p, _) in enumerate(pats) if p is _LOADER), len(pats) - 1)
        pats[at + 1:at + 1] = compiled
