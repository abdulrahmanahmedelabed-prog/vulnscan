"""PHP value semantics the taint engine needs beyond a sanitizer's name.

* **What a PHP escaper leaves out of its output.** ``htmlspecialchars($x, ENT_QUOTES)`` leaves no ``< > " '``,
  ``addslashes`` escapes quotes with a backslash, ``filter_var($x, FILTER_SANITIZE_NUMBER_INT)`` leaves digits, ``+``
  and ``-``, ``preg_replace('/[^a-z0-9]/', '', $x)`` leaves letters and digits. These facts travel with the taint as
  markers in its "escaped for" set (``php:no:<c>``: the value holds no ``<c>``; ``php:esc``: quotes and backslashes
  are backslash-escaped; ``php:shq``: one single-quoted shell word, as escapeshellarg makes it).
* **Where a tainted piece sits in the string the program builds.** The same value is harmless inside a quoted SQL
  literal it cannot close and dangerous as a bare number: ``"WHERE id='" . addslashes($x) . "'"`` is safe,
  ``"WHERE id=" . addslashes($x)`` is SQL injection. :func:`piece_safe` decides per sink kind from the quote state
  before the piece and the markers of its value.
* **Where an ``echo`` writes in the page.** The HTML around a ``<?php … ?>`` block (inside ``<script>``, a quoted or
  unquoted attribute, an event handler, a comment, a tag name …) decides what an escaped value may still do there:
  ``htmlspecialchars`` protects text and quoted attributes, not a ``<script>`` block or an ``onclick`` handler (the
  browser decodes ``&#039;`` back to ``'`` before it runs the handler).

Only values that went through one of the PHP functions modelled here carry markers; everything else keeps the
engine's name-based sanitizer model.
"""

from __future__ import annotations

import ast
import re
import string

MARK = "php:no:"           # php:no:<c> -- the value holds no <c>
ESC = "php:esc"            # ' " and \ are backslash-escaped (addslashes, mysql_real_escape_string, pg_escape_string)
SHQ = "php:shq"            # one single-quoted shell word (escapeshellarg)
BSESC = "php:bsesc"        # a backslash only starts an escape the sanitizer wrote (LDAP \2a style)

# the characters whose presence decides whether a value can change the meaning of what it is put into
SIG = frozenset("'\"\\<>&;|`$()= \t\r\n*:#/{}[]!?~^@\0.+-,%")
_WORD = frozenset(string.ascii_letters + string.digits + "_")
_XSS = frozenset({"CWE-79", "CWE-80", "CWE-116"})
_SQL = frozenset({"CWE-89", "CWE-564"})
_SHELL = frozenset({"CWE-78", "CWE-88"})
_CODE = frozenset({"CWE-94", "CWE-95"})
_PATHISH = frozenset({"CWE-98", "CWE-22", "CWE-23", "CWE-36", "CWE-73"})
_LDAP = frozenset({"CWE-90"})
_XPATH = frozenset({"CWE-643"})
_REDIRECT = frozenset({"CWE-601"})
# the sink kinds whose safety a built string's quoting decides (XSS is decided at the echo, see html_safe)
ADJUSTED = _SQL | _SHELL | _CODE | _PATHISH | _LDAP | _XPATH | _REDIRECT

# outside any quote a value may only be a number or a word: no operator, separator, quote, bracket or space
_BARE = frozenset("'\"\\<>&;|`$()= \t\r\n*:#/{}[]!?~^@\0")
_BARE_DASH = _BARE | {"-"}          # SQL `--` starts a comment; a shell word starting with `-` is an option


def no(chars) -> frozenset:
    return frozenset(MARK + c for c in chars if c in SIG)


def only(chars) -> frozenset:
    """Markers for a value made only of `chars`."""
    return frozenset(MARK + c for c in SIG if c not in chars)


def is_marked(safe) -> bool:
    return any(isinstance(m, str) and m.startswith("php:") for m in safe)


def _absent(safe) -> frozenset:
    return frozenset(m[len(MARK):] for m in safe if isinstance(m, str) and m.startswith(MARK))


# ---------------------------------------------------------------------------------------------- escaper calls
_HTML_ESCAPERS = {"htmlspecialchars", "htmlentities"}
_SQL_ESCAPERS = {"addslashes", "mysql_real_escape_string", "mysqli_real_escape_string", "real_escape_string",
                 "mysql_escape_string", "pg_escape_string", "sqlite_escape_string", "escapestring"}
_EMAIL_CHARS = frozenset(string.ascii_letters + string.digits + "!#$%&'*+-=?^_`{|}~@.[]")
_FILTERS = {   # filter_var() filter -> what is left of the value ("all": a number or a boolean)
    "FILTER_VALIDATE_INT": "all", "FILTER_VALIDATE_FLOAT": "all", "FILTER_VALIDATE_BOOLEAN": "all",
    "FILTER_VALIDATE_BOOL": "all",
    "FILTER_VALIDATE_IP": only(string.hexdigits + ".:"),
    "FILTER_VALIDATE_MAC": only(string.hexdigits + ".:-"),
    "FILTER_SANITIZE_NUMBER_INT": only(string.digits + "+-"),
    "FILTER_SANITIZE_NUMBER_FLOAT": only(string.digits + "+-.,eE"),
    "FILTER_SANITIZE_EMAIL": only(_EMAIL_CHARS),
    "FILTER_SANITIZE_SPECIAL_CHARS": _XSS | no("<>\"'&\t\r\n\0"),
    "FILTER_SANITIZE_FULL_SPECIAL_CHARS": _XSS | no("<>\"'"),
    "FILTER_SANITIZE_STRING": _XSS | no("<>\"'"),
    "FILTER_SANITIZE_STRIPPED": _XSS | no("<>\"'"),
    "FILTER_SANITIZE_MAGIC_QUOTES": _SQL | {ESC},
    "FILTER_SANITIZE_ADD_SLASHES": _SQL | {ESC},
    "FILTER_SANITIZE_ENCODED": only(string.ascii_letters + string.digits + "-_.%"),
}


def _bare_name(e) -> str:
    return e.id if isinstance(e, ast.Name) else ""


def _flag_names(e) -> set:
    """`ENT_QUOTES | ENT_HTML5` -> {"ENT_QUOTES", "ENT_HTML5"}; None-safe."""
    out: set = set()
    stack = [e]
    while stack:
        x = stack.pop()
        if isinstance(x, ast.BinOp):
            stack += [x.left, x.right]
        elif isinstance(x, ast.Name):
            out.add(x.id)
    return out


def _const(e, resolve):
    e = resolve(e) if resolve and isinstance(e, ast.Name) else e
    return e.value if isinstance(e, ast.Constant) else None


def call_kind(call: ast.Call, name: str, base, resolve=None):
    """What a PHP library call leaves of its argument: "all" (inert), a frozenset (the CWEs it is escaped for plus
    php: markers), "none" (not a sanitizer: the value passes through) or `base` (no PHP-specific opinion)."""
    n = name.split(".")[-1].split("::")[-1].lower()
    args = call.args
    if n in _HTML_ESCAPERS:
        flags = _flag_names(args[1]) if len(args) > 1 else set()
        if "ENT_QUOTES" in flags:
            quotes = "\"'"
        elif "ENT_NOQUOTES" in flags:
            quotes = ""
        else:
            quotes = '"'                   # ENT_COMPAT, the default before PHP 8.1: single quotes stay
        return _XSS | no("<>" + quotes)
    if n in ("filter_var",):
        if len(args) < 2:
            return "none"                  # FILTER_DEFAULT: the value unchanged
        k = _FILTERS.get(_bare_name(args[1]))
        if k is None:
            return "none"                  # FILTER_UNSAFE_RAW, VALIDATE_URL / EMAIL / REGEXP, a computed filter …
        return k
    if n in _SQL_ESCAPERS:
        return _SQL | {ESC}
    if n == "escapeshellarg":
        return _SHELL | {SHQ}
    if n == "escapeshellcmd":
        # escapes metacharacters but lets a value add arguments and options (`--output=/x`): not a sanitizer
        return "none"
    if n == "urlencode":
        return (base if isinstance(base, frozenset) else frozenset()) | only(_WORD | set("-.+%"))
    if n == "rawurlencode":
        return (base if isinstance(base, frozenset) else frozenset()) | only(_WORD | set("-.~%"))
    if n == "http_build_query":
        return (base if isinstance(base, frozenset) else frozenset()) | only(_WORD | set("-.+%=&"))
    if n == "preg_replace" and len(args) >= 3:
        return _preg_replace_kind(_const(args[0], resolve), _const(args[1], resolve)) or base
    if n in ("str_replace", "str_ireplace") and len(args) >= 3:
        return _str_replace_kind(args[0], args[1], resolve, n == "str_ireplace") or base
    return base


def _class_chars(body: str, icase: bool):
    """The characters of a regex character class body (without the brackets), or None when it cannot be read."""
    out: set = set()
    i = 0
    prev = None
    while i < len(body):
        c = body[i]
        if c == "\\" and i + 1 < len(body):
            nx = body[i + 1]
            i += 2
            if nx == "d":
                out |= set(string.digits)
                prev = None
                continue
            if nx == "w":
                out |= _WORD
                prev = None
                continue
            if nx == "s":
                out |= set(" \t\r\n\f\v")
                prev = None
                continue
            if nx in "DWSpPx":
                return None
            c = {"n": "\n", "r": "\r", "t": "\t", "0": "\0"}.get(nx, nx)
            out.add(c)
            prev = c
            continue
        if c == "-" and prev is not None and i + 1 < len(body) and body[i + 1] != "]":
            hi = body[i + 1]
            if hi == "\\":
                return None
            if ord(hi) < ord(prev) or ord(hi) - ord(prev) > 400:
                return None
            out |= {chr(k) for k in range(ord(prev), ord(hi) + 1)}
            prev = None
            i += 2
            continue
        if c == "[":
            return None                    # POSIX classes / nesting: not read
        out.add(c)
        prev = c
        i += 1
    if icase:
        out |= {x.swapcase() for x in out if x.isalpha()}
    return out


def _split_regex(p):
    """`/body/flags` -> (body, flags) or None."""
    if not isinstance(p, str) or len(p) < 2:
        return None
    d = p[0]
    close = {"(": ")", "{": "}", "[": "]", "<": ">"}.get(d, d)
    if d.isalnum() or d == "\\" or d.isspace():
        return None
    j = p.rfind(close)
    if j <= 0:
        return None
    flags = p[j + 1:]
    if not re.fullmatch(r"[imsxuADSUXJn]*", flags):
        return None
    return p[1:j], flags


def _preg_replace_kind(pattern, repl):
    """preg_replace with a constant pattern that removes characters: `/[^a-z0-9]/i` + "" leaves only letters and
    digits; `/'/` + "" leaves no quote; `/\\W/` + "" leaves word characters."""
    if not isinstance(repl, str):
        return None
    sp = _split_regex(pattern)
    if sp is None:
        return None
    body, flags = sp
    icase = "i" in flags
    m = re.fullmatch(r"\[(\^?)((?:\\.|[^\]\\])+)\]([+*]|\{\d+,?\d*\})?", body)
    if m:
        chars = _class_chars(m.group(2), icase)
        if chars is None:
            return None
        if m.group(1):                    # [^allowed]: only `allowed` (and the replacement) is left
            left = chars | set(repl)
            return "all" if left <= _WORD else only(left)
        return no(set(chars) - set(repl))
    if re.fullmatch(r"\\W[+*]?", body):
        left = _WORD | set(repl)
        return "all" if left <= _WORD else only(left)
    m = re.fullmatch(r"(\\.|[^\\.\[\]()*+?{}|^$])([+*])?", body)
    if m:                                  # one character: `/'/`, `/\\'/`, `/</`
        c = m.group(1)[-1]
        if m.group(1).startswith("\\") and c in "dwsDWSnrt0pPx":
            return None
        cs = {c, c.swapcase()} if icase and c.isalpha() else {c}
        return no(cs - set(repl))
    return None


def _str_list(e, resolve):
    """A literal PHP array of strings (also `array_keys($t)` / `array_values($t)` of a literal map), else None."""
    e = resolve(e) if resolve and isinstance(e, ast.Name) else e
    if isinstance(e, ast.Constant) and isinstance(e.value, str):
        return [e.value]
    if isinstance(e, ast.Call) and isinstance(e.func, ast.Name) and e.func.id in ("array_keys", "array_values") \
            and len(e.args) == 1:
        d = resolve(e.args[0]) if resolve and isinstance(e.args[0], ast.Name) else e.args[0]
        if isinstance(d, ast.Dict) and all(k is not None for k in d.keys):
            e = ast.List(elts=list(d.keys if e.func.id == "array_keys" else d.values))
    if isinstance(e, (ast.List, ast.Tuple)) and all(isinstance(x, ast.Constant) and isinstance(x.value, str) for x in e.elts):
        return [x.value for x in e.elts]
    return None


def _str_replace_kind(search, replace, resolve, icase: bool):
    """str_replace(SEARCH, REPLACE, $x) with literal lists: the single characters it replaces (in order, each
    replacement may bring characters back) are absent from the result; a backslash replaced first by an escape
    sequence only appears in escapes the call wrote (LDAP-style \\2a)."""
    s = _str_list(search, resolve)
    if s is None:
        return None
    r = _str_list(replace, resolve)
    if r is None:
        return None
    if len(r) == 1 and len(s) > 1:
        r = r * len(s)
    if len(r) < len(s):
        r = r + [""] * (len(s) - len(r))
    absent: set = set()
    bsesc = False
    for k, (a, b) in enumerate(zip(s, r)):
        if len(a) == 1:
            cs = {a, a.swapcase()} if icase and a.isalpha() else {a}
            absent |= cs
            if a == "\\" and k == 0 and b.startswith("\\") and len(b) > 1:
                bsesc = True
        absent -= set(b)
    if bsesc and "\\" not in absent:
        return no(absent) | {BSESC}
    return no(absent) or None


def sprintf_pieces(fmt: str, args: list):
    """sprintf("…'%s'…", $a) -> [("lit", "…'"), ("val", a), ("lit", "'…")]; %d / %u / %f / %x … print a number
    whatever the argument is. None for a format this does not read."""
    out, pos, k = [], 0, 0
    for m in re.finditer(r"%(?:(\d+)\$)?[-+ 0]*(?:'.)?\d*(?:\.\d+)?([bcdeEfFgGosuxX%])", fmt):
        if m.start() > pos:
            out.append(("lit", fmt[pos:m.start()]))
        pos = m.end()
        conv = m.group(2)
        if conv == "%":
            out.append(("lit", "%"))
            continue
        idx = int(m.group(1)) - 1 if m.group(1) else k
        if not m.group(1):
            k += 1
        if idx >= len(args):
            return None
        out.append(("val", args[idx]) if conv == "s" else ("lit", "0"))
    if "%" in fmt[pos:]:
        return None
    if pos < len(fmt):
        out.append(("lit", fmt[pos:]))
    return out


# ---------------------------------------------------------------------------------------- built-string quoting
def quote_states(pieces, known):
    """For each piece of a built string, the quote state before it: None (outside any quote), "'" or '"' (inside
    that literal) or "?" (unknown: an earlier piece of unknown text). `known(i)` is the constant text of piece i
    or None."""
    out = []
    st = None
    for i, (kind, e) in enumerate(pieces):
        out.append(st)
        if st == "?":
            continue
        text = e if kind == "lit" else known(i)
        if text is None:
            st = "?"
            continue
        j = 0
        while j < len(text):
            c = text[j]
            if st is None and c in "'\"":
                st = c
            elif st in ("'", '"') and c == "\\":
                j += 1
            elif st == c:
                st = None
            j += 1
    return out


def piece_safe(cwe: str, state, safe: frozenset, single: bool):
    """Is a tainted piece whose value carries `safe` harmless for a sink of kind `cwe` at quote `state`?
    None when this module has no rule for the CWE."""
    a = _absent(safe)

    def ok(chars):
        return set(chars) <= a
    if cwe in _SQL:
        if state in ("'", '"'):
            return ESC in safe or (ok(state) and (single or ok("\\")))
        return state is None and ok(_BARE_DASH)
    if cwe in _XPATH:
        if state in ("'", '"'):
            return ok(state)               # an XPath literal has no escapes: only its quote ends it
        return state is None and ok(_BARE)
    if cwe in _SHELL:
        if state == "'":
            return ok("'")                 # nothing is special inside '…' but the quote itself
        if state == '"':
            return ok('"$`\\')
        return state is None and (SHQ in safe or ok(_BARE_DASH))
    if cwe in _CODE:
        if state == "'":
            return ESC in safe or (ok("'") and (single or ok("\\")))
        if state == '"':
            return ok('"$\\')
        return state is None and ok(_BARE)
    if cwe in _PATHISH:
        return ok("/\\\0")                 # no directory separator: it cannot climb out or name a stream wrapper
    if cwe in _LDAP:
        return ok("*()\0") and (ok("\\") or BSESC in safe)
    if cwe in _REDIRECT:
        return ok("/\\:")                  # no scheme, no //host: a relative location on this site
    return None


def whole_value_safe(cwe: str, safe: frozenset):
    """A marked value passed to a sink as it is (not built into a larger string)."""
    return piece_safe(cwe, None, safe, True)


def adjust(safe: frozenset, state, single: bool) -> frozenset:
    """The CWEs a marked piece is safe for at quote `state`: the context decides every CWE it has a rule for."""
    if state == "?":
        return safe
    keep = frozenset(c for c in safe if c not in ADJUSTED)
    return keep | frozenset(c for c in ADJUSTED if piece_safe(c, state, safe, single))


# ---------------------------------------------------------------------------------------------- HTML contexts
_URL_ATTRS = {"href", "src", "action", "formaction", "background", "poster", "data", "codebase", "cite", "xlink:href",
              "srcset", "ping", "manifest", "longdesc", "lowsrc", "dynsrc", "icon"}
_RAW_TEXT = {"script": "script", "style": "style", "textarea": "rcdata", "title": "rcdata"}


class HtmlState(tuple):
    """(mode, tag, attr, attr_quote, inner_quote, value_so_far_empty)"""
    __slots__ = ()

    def __new__(cls, mode="text", tag="", attr="", aq="", jq="", fresh=True):
        return tuple.__new__(cls, (mode, tag, attr, aq, jq, fresh))

    mode = property(lambda s: s[0])
    tag = property(lambda s: s[1])
    attr = property(lambda s: s[2])
    aq = property(lambda s: s[3])
    jq = property(lambda s: s[4])
    fresh = property(lambda s: s[5])


TEXT = HtmlState()


def html_advance(st: HtmlState, text: str) -> HtmlState:
    """The HTML tokenizer state after `text` (a small subset of the HTML5 tokenizer: enough to tell text, tags,
    attribute values, comments and raw-text elements apart)."""
    mode, tag, attr, aq, jq, fresh = st
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if mode == "text" or mode == "rcdata":
            if text.startswith("<!--", i) and mode == "text":
                mode, i = "comment", i + 4
                continue
            if c == "<":
                m = re.match(r"</?([A-Za-z][A-Za-z0-9:-]*)", text[i:])
                if m and (mode == "text" or m.group(0)[1:2] == "/" and m.group(1).lower() == tag):
                    tag = m.group(1).lower() if not m.group(0).startswith("</") else ""
                    mode, attr, i = "tag", "", i + m.end()
                    continue
                if mode == "text" and text.startswith("<", i) and i + 1 == n:
                    mode, tag, i = "tagname", "", i + 1
                    continue
            i += 1
            continue
        if mode == "comment":
            j = text.find("-->", i)
            if j < 0:
                return HtmlState("comment")
            mode, i = "text", j + 3
            continue
        if mode == "tagname":
            m = re.match(r"[A-Za-z0-9:-]*", text[i:])
            tag = (tag + m.group(0)).lower()
            mode, i = "tag", i + m.end()
            continue
        if mode in ("script", "style"):
            close = "</" + mode
            if jq:
                if c == "\\":
                    i += 2
                    continue
                if c == jq or (c == "\n" and jq != "`"):
                    jq = ""
                i += 1
                continue
            if text[i:i + len(close)].lower() == close:
                mode, tag, i = "tag", "", i + len(close)
                continue
            if c == "\\":
                i += 2                     # an escaped character, not the start of a string
                continue
            if c in "'\"" or (c == "`" and mode == "script"):
                jq = c
            i += 1
            continue
        if mode == "tag":
            if c == ">":
                mode = _RAW_TEXT.get(tag, "text") if tag else "text"
                attr, i = "", i + 1
                continue
            if c == "/" and text.startswith("/>", i):
                mode, tag, attr, i = "text", "", "", i + 2
                continue
            if c.isspace() or c == "/":
                i += 1
                continue
            m = re.match(r"[^\s/>=\"'<]+", text[i:])
            if m:
                attr = m.group(0).lower()
                i += m.end()
                j = i
                while j < n and text[j].isspace():
                    j += 1
                if j < n and text[j] == "=":
                    mode, i = "beforeval", j + 1
                continue
            i += 1
            continue
        if mode == "beforeval":
            if c.isspace():
                i += 1
                continue
            if c in "\"'":
                mode, aq, jq, fresh, i = "attr", c, "", True, i + 1
                continue
            mode, aq, jq, fresh = "attr", "", "", True
            continue
        if mode == "attr":
            if (aq and c == aq) or (not aq and (c.isspace() or c == ">")):
                mode, aq, jq, fresh = "tag", "", "", True
                if c == aq:
                    i += 1
                continue
            fresh = False
            if attr.startswith("on") or attr == "style":
                if jq:
                    if c == "\\":
                        i += 2
                        continue
                    if c == jq:
                        jq = ""
                elif c in "'\"`":
                    jq = c
            i += 1
            continue
        i += 1
    return HtmlState(mode, tag, attr, aq, jq, fresh)


def html_required(st: HtmlState):
    """Characters a value must not hold to be inert where `st` puts it (None: no rule, keep the default)."""
    mode = st.mode
    if mode in ("text", "rcdata"):
        return frozenset("<")
    if mode == "comment":
        return frozenset(">")
    if mode in ("script", "style"):
        if st.jq:
            return frozenset(st.jq + "<\r\n")
        return _BARE
    if mode in ("tag", "tagname", "beforeval"):
        return _BARE
    if mode == "attr":
        q = st.aq
        if not q:
            return _BARE
        if st.attr.startswith("on") or st.attr == "style":
            # the browser decodes entities in the attribute before running it: &#39; is a quote again
            return frozenset(st.jq + q + "&\r\n") if st.jq else _BARE
        if st.attr in _URL_ATTRS and st.fresh:
            return frozenset(q + ":")      # no javascript: / data: scheme at the start of the URL
        return frozenset(q)
    return None


def html_needs_backslash(st: HtmlState) -> bool:
    """Inside a JavaScript / CSS string a trailing backslash escapes the closing quote."""
    return st.mode in ("script", "style", "attr") and bool(st.jq)


def html_safe(st: HtmlState, safe: frozenset, single: bool):
    """Is a piece escaped as `safe` harmless at HTML state `st`? None: no rule."""
    req = html_required(st)
    if req is None:
        return None
    a = _absent(safe)
    if is_marked(safe):
        return req <= a and (single or not html_needs_backslash(st) or "\\" in a)
    # escaped by a sanitizer of unknown output: safe in text and plain quoted attributes only
    if not (_XSS & safe):
        return False
    return st.mode in ("text", "rcdata") or (st.mode == "attr" and bool(st.aq) and not st.attr.startswith("on")
                                              and st.attr != "style" and not (st.attr in _URL_ATTRS and st.fresh))


def html_blocks(src: str) -> list:
    """[(first line, last line, HtmlState at the block's start)] for each <?php … ?> block of a PHP file; the HTML
    between blocks moves the state, PHP blocks are taken to leave it where it was."""
    out = []
    st = TEXT
    line = 1
    keep = False
    start = None
    for part in re.split(r"(<\?(?:php|=)?|\?>)", src):
        if part in ("<?php", "<?", "<?="):
            keep, start = True, line
            continue
        if part == "?>":
            if keep:
                out.append((start, line, st))
            keep = False
            continue
        if not keep:
            st = html_advance(st, part)
        line += part.count("\n")
    if keep:
        out.append((start, line, st))
    return out


def annotate_echoes(tree: ast.Module, src: str) -> None:
    """Mark the argument of each top-level `echo` / `print` with the HTML state it writes into (attribute
    `php_html`). A block's first echo starts at the block's state; a later echo of the same block continues from
    the earlier echoes' constant text (and is left unmarked when that text is unknown)."""
    blocks = html_blocks(src)
    if not blocks:
        return
    calls = []
    stack = list(tree.body)
    while stack:
        n = stack.pop()
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in ("echo", "print") and n.args:
            calls.append(n)
        stack.extend(ast.iter_child_nodes(n))
    calls.sort(key=lambda c: (c.lineno, getattr(c, "col_offset", 0)))
    state_of: dict = {}
    for c in calls:
        b = next((b for b in blocks if b[0] <= c.lineno <= b[1]), None)
        if b is None:
            continue
        st = state_of.get(b, b[2])
        for a in c.args:
            a.php_html = st
            # the constant text moves the state; a value printed in between is taken to be text that does not
            # (an unescaped one is reported where it is printed anyway)
            for k, e in pieces(a) or [("val", a)]:
                if k == "lit":
                    st = html_advance(st, e)
        state_of[b] = st


def pieces(node):
    """A PHP string built by `.` / interpolation as ("lit", text) / ("val", expr) pieces, or None."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [("lit", node.value)]
    if isinstance(node, ast.JoinedStr):
        out = []
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                out.append(("lit", v.value))
            elif isinstance(v, ast.FormattedValue):
                out.append(("val", v.value))
            else:
                return None
        return out
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add) and not getattr(node, "php_numeric", False):
        a = pieces(node.left) if isinstance(node.left, (ast.BinOp, ast.JoinedStr, ast.Constant)) else None
        b = pieces(node.right) if isinstance(node.right, (ast.BinOp, ast.JoinedStr, ast.Constant)) else None
        return (a if a is not None else [("val", node.left)]) + (b if b is not None else [("val", node.right)])
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id.lower() == "sprintf" \
            and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
        return sprintf_pieces(node.args[0].value, node.args[1:])
    return None
