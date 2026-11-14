"""Bidirectional text helpers: Latin runs inside Arabic text (console, JSON, the HTML report and the web UI).

Arabic engine text often carries code, header values, URLs, versions and dates: ``اضبط SameSite=Lax صراحةً``,
``أرسل Strict-Transport-Security: max-age=63072000; includeSubDomains``, ``انتهى الدعم في 2026-11-12``. Left to the
Unicode bidirectional algorithm, the punctuation inside such a run (``= ; ' " ( )``, spaces between tokens) takes the
paragraph's right-to-left direction and the run is displayed in the wrong order (``max-age=63072000; includeSubDomains``
becomes ``includeSubDomains ;max-age=63072000``, a date ``2026-11-12`` becomes ``12-11-2026``). Isolating every run as
left-to-right fixes that.

* :func:`iso` wraps a text in LEFT-TO-RIGHT ISOLATE … POP DIRECTIONAL ISOLATE (U+2066 … U+2069), for console and JSON
  text; :func:`isolate` does it for every Latin run of an Arabic text.
* :data:`LTR_RUN_PATTERN` is the one regular expression of a Latin run, shared by ``report._bidi_html`` (through
  :func:`html_runs`) and ``ui/app.js`` ``bidi()`` (through :data:`JS_BIDI`, the same pattern and trimming in
  JavaScript). The pattern is written so that Python ``re`` and a JavaScript ``RegExp`` read it identically.

A run starts at a Latin letter, a digit or code punctuation (``_ $ . / ~ ' " < # @ [ { \\``, and ``- * +`` directly
followed by a non-space) and continues through anything except Arabic letters, the Arabic comma and semicolon (``،؛``
are in the Arabic block), the Arabic quotation marks ``« »``, list separators (``·`` ``•``) and directional marks;
so ``= ' " < > ; , ( ) *`` and the spaces between Latin tokens stay in one run. It is then trimmed (:func:`trim_run`): trailing spaces, trailing ASCII
``.`` and ``:`` (sentence punctuation of the Arabic text), a trailing closing bracket without its opening one (the
``)`` of an Arabic parenthesis), a dangling opening bracket and a trailing token made only of brackets, dashes or
arrows. A trailing ``-`` attached to a token (``__Host-``) and a leading ``/`` or ``.`` (``/.well-known/``, ``.map``)
stay. A run is kept when it has a Latin letter, or when it is digits joined by ``- / : .`` (dates, versions, IP
addresses, ports, times); a bare number needs no isolation.
"""

from __future__ import annotations

import html as _html
import json
import re

LRI = "\u2066"     # LEFT-TO-RIGHT ISOLATE
FSI = "\u2068"     # FIRST STRONG ISOLATE
PDI = "\u2069"     # POP DIRECTIONAL ISOLATE
LRM = "\u200E"     # LEFT-TO-RIGHT MARK
RLM = "\u200F"     # RIGHT-TO-LEFT MARK

# Arabic, Arabic Supplement, Arabic Extended-A, presentation forms A and B (the Arabic block holds ، ؛ ؟ too)
ARABIC_RANGES = r"\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF\uFB50-\uFDFF\uFE70-\uFEFF"
# characters that end a run although they are not Arabic: Arabic quotation marks « », list separators and directional
# formatting characters
BREAK_CHARS = r"\u00AB\u00BB\u00B7\u2022\u200E\u200F\u202A-\u202E\u2066-\u2069"
_TOKEN_CHAR = rf"[^\s{ARABIC_RANGES}{BREAK_CHARS}]"
_START = r"(?:[A-Za-z0-9_$./~'\x22<#@\[{\\]|[-*+](?=[^\s]))"
_SPACE = r"[ \t\u00A0\u202F]"

#: The Latin-run regular expression (Python ``re`` and JavaScript ``RegExp`` syntax alike; use it with the ``g`` flag
#: in JavaScript). Matches are raw runs: pass each through :func:`trim_run` (``trimRun`` in :data:`JS_BIDI`).
LTR_RUN_PATTERN = rf"{_START}{_TOKEN_CHAR}*(?:{_SPACE}+{_TOKEN_CHAR}+)*"
LTR_RUN = re.compile(LTR_RUN_PATTERN)

_ARABIC = re.compile(rf"[{ARABIC_RANGES}]")
_LATIN = re.compile(r"[A-Za-z]")
_DIGIT_RUN = re.compile(r"[0-9]+(?:[-/:.][0-9]+)+")
_TAIL_SPACE = re.compile(rf"{_SPACE}+$")
_TAIL_TOKEN = re.compile(rf"{_SPACE}+[(\[{{<\u2014\u2013\u2192\u2190\u21D2|-]+$")
_PAIRS = {")": "(", "]": "[", "}": "{"}


def iso(text: str) -> str:
    """``text`` as a left-to-right isolate (U+2066 … U+2069): it keeps its own order inside Arabic text."""
    text = "" if text is None else str(text)
    return f"{LRI}{text}{PDI}" if text else text


def has_arabic(text) -> bool:
    return isinstance(text, str) and bool(_ARABIC.search(text))


def trim_run(run: str) -> str:
    """A raw :data:`LTR_RUN` match without what belongs to the surrounding Arabic text (see the module docstring)."""
    while True:
        prev = run
        run = _TAIL_SPACE.sub("", run)
        run = run.rstrip(".:")
        if _TAIL_TOKEN.search(run):
            run = _TAIL_TOKEN.sub("", run)
        elif run and run[-1] in _PAIRS and run.count(run[-1]) > run.count(_PAIRS[run[-1]]):
            run = run[:-1]
        elif run and run[-1] in "([{<":
            run = run[:-1]
        if run == prev:
            return run


def keep_run(run: str) -> bool:
    """Whether a trimmed run needs isolating: it has a Latin letter, or it is digits joined by ``- / : .``."""
    return bool(_LATIN.search(run)) or bool(_DIGIT_RUN.fullmatch(run))


def ltr_runs(text: str) -> list[tuple[int, int]]:
    """``(start, end)`` of every Latin run of ``text`` that needs isolating, in order."""
    text = "" if text is None else str(text)
    out = []
    for m in LTR_RUN.finditer(text):
        run = trim_run(m.group())
        if run and keep_run(run):
            out.append((m.start(), m.start() + len(run)))
    return out


def wrap_runs(text: str, wrap, escape=lambda s: s) -> str:
    """``text`` with ``escape`` applied to every piece and ``wrap(escaped_run)`` around every Latin run; unchanged
    (only escaped) when the text has no Arabic letter."""
    text = "" if text is None else str(text)
    if not has_arabic(text):
        return escape(text)
    out, last = [], 0
    for start, end in ltr_runs(text):
        out.append(escape(text[last:start]))
        out.append(wrap(escape(text[start:end])))
        last = end
    out.append(escape(text[last:]))
    return "".join(out)


def isolate(text: str) -> str:
    """Console / JSON text: every Latin run of an Arabic text wrapped in :func:`iso`."""
    return wrap_runs(text, iso)


def html_runs(text: str) -> str:
    """HTML-escaped text for an Arabic page with every Latin run in ``<bdi dir="ltr">`` (``report._bidi_html``)."""
    return wrap_runs(text, lambda s: f'<bdi dir="ltr">{s}</bdi>', lambda s: _html.escape(s))


#: The same pattern and trimming for ``ui/app.js`` (``ltrRuns(str)`` returns ``[start, end]`` pairs, ``bidiHtml(str,
#: esc)`` the escaped HTML with ``<bdi dir="ltr">`` runs). tests/web/test_rules_texts.py runs it under Node and checks
#: that it finds exactly the runs :func:`ltr_runs` finds.
JS_BIDI = """\
/* Generated from vulnscan/i18n/bidi.py (JS_BIDI): keep in sync with LTR_RUN_PATTERN and trim_run there. */
const LTR_RUN_SRC = %(pattern)s;
const LTR_TAIL_SPACE = new RegExp(%(tail_space)s);
const LTR_TAIL_TOKEN = new RegExp(%(tail_token)s);
const LTR_PAIRS = {')': '(', ']': '[', '}': '{'};
const ARABIC_RX = new RegExp('[' + %(arabic)s + ']');
const trimRun = (run) => {
  for (;;) {
    const prev = run;
    run = run.replace(LTR_TAIL_SPACE, '').replace(/[.:]+$/, '');
    const last = run.slice(-1);
    const count = (ch) => run.split(ch).length - 1;
    if (LTR_TAIL_TOKEN.test(run)) run = run.replace(LTR_TAIL_TOKEN, '');
    else if (last && LTR_PAIRS[last] && count(last) > count(LTR_PAIRS[last])) run = run.slice(0, -1);
    else if (last && '([{<'.includes(last)) run = run.slice(0, -1);
    if (run === prev) return run;
  }
};
const keepRun = (run) => /[A-Za-z]/.test(run) || /^[0-9]+(?:[-\\/:.][0-9]+)+$/.test(run);
const ltrRuns = (text) => {
  const str = String(text ?? ''), rx = new RegExp(LTR_RUN_SRC, 'g'), out = [];
  let m;
  while ((m = rx.exec(str))) {
    const run = trimRun(m[0]);
    if (run && keepRun(run)) out.push([m.index, m.index + run.length]);
  }
  return out;
};
const bidiHtml = (text, esc) => {
  const str = String(text ?? '');
  if (!ARABIC_RX.test(str)) return esc(str);
  let out = '', last = 0;
  for (const [a, b] of ltrRuns(str)) { out += esc(str.slice(last, a)) + `<bdi dir="ltr">${esc(str.slice(a, b))}</bdi>`; last = b; }
  return out + esc(str.slice(last));
};
""" % {"pattern": json.dumps(LTR_RUN_PATTERN), "tail_space": json.dumps(_TAIL_SPACE.pattern),
       "tail_token": json.dumps(_TAIL_TOKEN.pattern), "arabic": json.dumps(ARABIC_RANGES)}


__all__ = ["LRI", "FSI", "PDI", "LRM", "RLM", "ARABIC_RANGES", "BREAK_CHARS", "LTR_RUN_PATTERN", "LTR_RUN", "iso",
           "has_arabic", "trim_run", "keep_run", "ltr_runs", "wrap_runs", "isolate", "html_runs", "JS_BIDI"]
