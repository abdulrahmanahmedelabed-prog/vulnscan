"""English for the engine's user-facing text.

The engine writes its remediation advice, data-flow trail steps and scan notes in Arabic (the project's first
language). This package gives every such string an English counterpart so that the web UI, the reports, SARIF
(GitHub Code Scanning) and the command line can speak either language.

Two kinds of entries:

* ``CATALOG`` (exact text): static strings such as rule advice. The key is the Arabic text exactly as the engine
  emits it at run time; the value is the English text.
* ``PATTERNS`` (templates): dynamic strings built with f-strings, e.g. ``"يمرّ عبر run() ويُعاد"``. Each entry is a
  regular expression that must match the WHOLE Arabic string, and an English replacement that may use the
  expression's groups (``\\g<name>``). Groups hold code identifiers, numbers or paths, never prose.

Catalog modules live next to this file (``cat_*.py``), one per area of the engine, each defining ``CATALOG``
and optionally ``PATTERNS``. ``tests/test_i18n.py`` checks that every user-facing Arabic string the engine can
emit has an English translation, so a new rule without English fails CI.
"""

from __future__ import annotations

import re

# one module per area of the engine; explicit imports so frozen builds (PyInstaller) include them
from . import (cat_apex, cat_cli, cat_dynamic, cat_integrations, cat_misc, cat_models, cat_models_js, cat_models_jvm,
               cat_models_other, cat_models_python, cat_rules, cat_rules_extra, cat_updater, cat_web)

_MODULES = (cat_rules, cat_models, cat_web, cat_apex, cat_misc, cat_cli, cat_dynamic, cat_models_python, cat_models_jvm,
            cat_models_js, cat_models_other, cat_rules_extra, cat_integrations, cat_updater)

_ARABIC = re.compile(r"[\u0600-\u06FF\u0750-\u077F\uFB50-\uFDFF\uFE70-\uFEFF]")

CATALOG: dict[str, str] = {}
PATTERNS: list[tuple[re.Pattern, str]] = []


def _load() -> None:
    for m in _MODULES:
        for ar, en in getattr(m, "CATALOG", {}).items():
            CATALOG.setdefault(_norm(ar), en)
        for rx, en in getattr(m, "PATTERNS", []):
            PATTERNS.append((re.compile(rx, re.S), en))


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def has_arabic(text) -> bool:
    return isinstance(text, str) and bool(_ARABIC.search(text))


def to_en(text):
    """The English for an engine string; the text itself when it has no Arabic or no translation is known."""
    if not has_arabic(text):
        return text
    key = _norm(text)
    hit = CATALOG.get(key)
    if hit is not None:
        return hit
    for rx, en in PATTERNS:
        m = rx.fullmatch(key)
        if m:
            # groups may themselves be translatable phrases (a label inside a step), never prose to drop
            groups = {k: to_en(v) if v is not None else "" for k, v in m.groupdict().items()}
            return re.sub(r"\\g<(\w+)>", lambda g: groups.get(g.group(1), ""), en)
    return text


def translated(text) -> bool:
    """True when `text` needs no translation or has one."""
    return not has_arabic(to_en(text))


def localize(text, lang: str):
    return to_en(text) if lang == "en" else text


_load()
