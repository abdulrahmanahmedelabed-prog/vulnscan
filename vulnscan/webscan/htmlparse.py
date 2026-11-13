"""The light HTML model of spec §2.6, built with the stdlib ``html.parser`` (WP0).

``parse(text, url)`` returns a :class:`~vulnscan.webscan.types.ParsedHTML`: every start tag in document order with
its attributes, parent and position; the first ``<base href>``; inline scripts (with ``nonce``/``type`` and the line
and offset where their text starts, so script line N maps to page line ``line + N - 1``); inline styles; comments;
forms with their controls (the HTML form element pointer and the ``form="id"`` attribute, like a browser); the title
and the visible text (without script, style and template contents).

Elements inside ``<template>`` or ``<noscript>`` are kept but marked ``live=False``: they are not rendered or not
executed, so element rules must skip them (fixes D-cases where commented or templated markup was reported).
Comments are recorded separately and are never elements.

Malformed HTML is tolerated as browsers do: unclosed tags stay open until an ancestor closes, a stray end tag is
ignored, a ``<script>`` containing ``</div>`` keeps its text (raw text until ``</script``), a nested ``<form>`` start
tag does not create a second form. Nothing here fetches anything.
"""

from __future__ import annotations

import bisect
import re
from html.parser import HTMLParser
from urllib.parse import urljoin

from .types import Comment, Element, Form, InlineScript, InlineStyle, ParsedHTML, Response

VOID = frozenset({"area", "base", "basefont", "bgsound", "br", "col", "embed", "frame", "hr", "img", "input", "keygen",
                  "link", "meta", "param", "source", "track", "wbr"})
HEAD_TAGS = frozenset({"base", "basefont", "bgsound", "link", "meta", "title", "noscript", "noframes", "style", "script",
                       "template"})
FORM_ASSOCIATED = frozenset({"input", "button", "select", "textarea", "fieldset", "output", "object"})
_RAW = frozenset({"script", "style"})
_FOREIGN = frozenset({"svg", "math"})


class _Builder(HTMLParser):
    def __init__(self, text: str, url: str):
        super().__init__(convert_charrefs=True)
        self.url = url
        self.base_url = url
        self.base_href: str | None = None
        self.doctype: str | None = None
        self.elements: list[Element] = []
        self.scripts: list[InlineScript] = []
        self.styles: list[InlineStyle] = []
        self.comments: list[Comment] = []
        self.forms: list[Form] = []
        self.form_by_element: dict[int, Form] = {}
        self.ids: dict[str, int] = {}
        self.stack: list[int] = []
        self.inert = 0            # open <template>/<noscript> elements
        self.foreign = 0          # open <svg>/<math>
        self.phase = "initial"    # initial → in_head → in_body (only used for Element.in_head)
        self.form_pointer = -1
        self.pending_form_attr: list[tuple[int, str]] = []
        self.raw_tag: str | None = None
        self.raw_el = -1
        self.raw_parts: list[str] = []
        self.raw_pos: tuple[int, int] | None = None
        self.in_title = False
        self.title_parts: list[str] = []
        self.title_done = False
        self.text_parts: list[str] = []
        self.line_starts = [0] + [m.end() for m in re.finditer("\n", text)]

    # -- helpers -------------------------------------------------------------------------------------------
    def _offset(self, line: int, col: int) -> int:
        idx = line - 1
        if 0 <= idx < len(self.line_starts):
            return self.line_starts[idx] + col
        return 0

    def _resolve(self, value: str) -> str:
        v = re.sub(r"[\t\n\r]", "", value.strip(" \t\n\r\f"))
        try:
            return urljoin(self.base_url, v)
        except ValueError:
            return v

    def _add(self, tag: str, attrs: list[tuple[str, str | None]], push: bool) -> None:
        d: dict[str, str] = {}
        for k, v in attrs:
            if k not in d:
                d[k] = "" if v is None else v
        line, col = self.getpos()
        parent = self.stack[-1] if self.stack else -1
        live = self.inert == 0
        # head detection: an element is in <head> while the parser is in the (possibly implied) head
        if tag == "head":
            self.phase = "in_head"
            in_head = False
        elif tag in ("body", "frameset"):
            self.phase = "in_body"
            in_head = False
        elif tag == "html":
            in_head = False
        else:
            parent_in_head = parent >= 0 and self.elements[parent].in_head
            if parent_in_head:
                in_head = True
            elif self.phase in ("initial", "in_head") and tag in HEAD_TAGS:
                in_head = True
            else:
                if self.phase != "in_body":
                    self.phase = "in_body"
                in_head = False
        idx = len(self.elements)
        el = Element(tag, d, line, col, self._offset(line, col), parent, idx, live, in_head)
        self.elements.append(el)
        if "id" in d and d["id"] not in self.ids:
            self.ids[d["id"]] = idx
        if tag == "base" and self.base_href is None and live and "href" in d:
            self.base_href = d["href"]
            resolved = self._resolve(d["href"])
            if resolved.split(":", 1)[0].lower() in ("http", "https"):
                self.base_url = resolved
        if tag == "form":
            if self.form_pointer < 0 or not live:
                action_attr = d.get("action")
                form = Form(idx, self._resolve(action_attr) if action_attr else self.url, action_attr,
                            (d.get("method") or "").strip().lower(), [], live)
                self.forms.append(form)
                self.form_by_element[idx] = form
                if live:
                    self.form_pointer = idx
        elif tag in FORM_ASSOCIATED:
            if "form" in d:
                self.pending_form_attr.append((idx, d["form"]))
            elif self.form_pointer >= 0 and live:
                el.form = self.form_pointer
        if push:
            self.stack.append(idx)
            if tag in ("template", "noscript"):
                self.inert += 1
            elif tag in _FOREIGN:
                self.foreign += 1
            if tag in _RAW:
                self.raw_tag, self.raw_el, self.raw_parts, self.raw_pos = tag, idx, [], None
            elif tag == "title" and not self.title_done and live:
                self.in_title = True

    # -- HTMLParser callbacks ------------------------------------------------------------------------------
    def handle_starttag(self, tag, attrs):
        if self.raw_tag:                       # cannot happen in raw text mode, but stay safe
            self._finish_raw()
        self._add(tag, attrs, push=tag not in VOID)

    def handle_startendtag(self, tag, attrs):
        # "<div/>" opens a div in HTML (the slash is ignored); in SVG/MathML it closes the element
        push = tag not in VOID and self.foreign == 0
        if self.raw_tag:
            self._finish_raw()
        self._add(tag, attrs, push=push)

    def handle_endtag(self, tag):
        if self.raw_tag and tag == self.raw_tag:
            self._finish_raw()
        if tag == "title":
            if self.in_title:
                self.title_done = True
            self.in_title = False
        if tag == "form" and self.inert == 0:
            self.form_pointer = -1
        if tag == "head" and self.phase in ("initial", "in_head"):
            self.phase = "after_head"
        for pos in range(len(self.stack) - 1, -1, -1):
            if self.elements[self.stack[pos]].tag == tag:
                for i in self.stack[pos:]:
                    t = self.elements[i].tag
                    if t in ("template", "noscript"):
                        self.inert -= 1
                    elif t in _FOREIGN:
                        self.foreign -= 1
                del self.stack[pos:]
                break

    def handle_data(self, data):
        if self.raw_tag:
            if self.raw_pos is None:
                self.raw_pos = self.getpos()
            self.raw_parts.append(data)
            return
        if self.in_title:
            self.title_parts.append(data)
            return
        if self.inert == 0:
            self.text_parts.append(data)
        if self.phase != "in_body" and data.strip():
            self.phase = "in_body"

    def handle_comment(self, data):
        line, col = self.getpos()
        self.comments.append(Comment(data, line, self._offset(line, col), self.inert == 0))

    def handle_decl(self, decl):
        if decl[:7].lower() == "doctype" and self.doctype is None:
            self.doctype = decl[7:].strip().lower() or "html"

    def unknown_decl(self, data):   # <![CDATA[ … ]]> and friends: not HTML content
        pass

    def _finish_raw(self) -> None:
        tag, el_idx = self.raw_tag, self.raw_el
        text = "".join(self.raw_parts)
        el = self.elements[el_idx]
        if self.raw_pos is not None:
            line, col = self.raw_pos
        else:                                   # empty element: the text would start after the start tag
            line, col = el.line, el.col
        offset = self._offset(line, col)
        if tag == "script":
            if "src" not in el.attrs:
                self.scripts.append(InlineScript(text, el_idx, line, col, offset, el.attrs.get("nonce"),
                                                 (el.attrs.get("type") or "").strip().lower(), el.live))
        else:
            self.styles.append(InlineStyle(text, el_idx, line, offset, el.live))
        self.raw_tag, self.raw_el, self.raw_parts, self.raw_pos = None, -1, [], None

    def finish(self) -> None:
        if self.raw_tag:
            self._finish_raw()
        for idx, form_id in self.pending_form_attr:
            owner = self.ids.get(form_id)
            if owner is not None and self.elements[owner].tag == "form":
                self.elements[idx].form = owner
        for el in self.elements:
            if el.form >= 0 and el.form in self.form_by_element:
                self.form_by_element[el.form].inputs.append(el.index)


def parse(text: str, url: str) -> ParsedHTML:
    """Parse ``text`` (decoded HTML) of the document at ``url`` into the light DOM. Never raises on bad markup."""
    b = _Builder(text, url)
    error = ""
    try:
        b.feed(text)
        b.close()
    except (AssertionError, ValueError, IndexError, RecursionError) as e:   # very old html.parser edge cases
        error = f"{type(e).__name__}: {e}"
    b.finish()
    visible = " ".join(" ".join(b.text_parts).split())
    title = " ".join(" ".join(b.title_parts).split())
    return ParsedHTML(url=url, base_url=b.base_url, base_href=b.base_href, doctype=b.doctype, title=title,
                      elements=b.elements, inline_scripts=b.scripts, inline_styles=b.styles, comments=b.comments,
                      forms=b.forms, visible_text=visible, ids=b.ids, parse_error=error)


def parse_response(response: Response) -> ParsedHTML:
    """``parse`` over a response's decoded body (``Response.text()``) and final URL."""
    return parse(response.text(), response.url)


# ----------------------------------------------------------------------------------------------- shared helpers

def srcset_urls(value: str | None) -> list[str]:
    """The URLs of a ``srcset`` attribute (descriptors dropped), as written (resolve with ``ParsedHTML.resolve``)."""
    if not value:
        return []
    out = []
    pos, n = 0, len(value)
    while pos < n:
        while pos < n and (value[pos].isspace() or value[pos] == ","):
            pos += 1
        if pos >= n:
            break
        start = pos
        while pos < n and not value[pos].isspace():
            pos += 1
        url = value[start:pos]
        if url.endswith(","):
            url = url.rstrip(",")
        else:   # skip the descriptor up to the next comma outside parentheses
            depth = 0
            while pos < n:
                ch = value[pos]
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth = max(0, depth - 1)
                elif ch == "," and depth == 0:
                    break
                pos += 1
        if url:
            out.append(url)
    return out


_REFRESH = re.compile(r"""^\s*(\d*(?:\.\d*)?)\s*(?:[;,]\s*|\s+)?(?:(?:url\s*=\s*)?(.*))?$""", re.I | re.S)


def parse_meta_refresh(content: str | None) -> tuple[float, str | None] | None:
    """``(delay_seconds, url_or_None)`` of a ``<meta http-equiv=refresh content=…>`` value (HTML "shared declarative
    refresh steps", simplified), or ``None`` when the value is not a valid refresh."""
    if content is None:
        return None
    m = _REFRESH.match(content)
    if not m or m.group(1) in ("", "."):
        return None
    try:
        delay = float(m.group(1))
    except ValueError:
        return None
    url = (m.group(2) or "").strip()
    if url[:1] in ("'", '"'):
        q = url[0]
        url = url[1:]
        end = url.find(q)
        if end >= 0:
            url = url[:end]
    return delay, (url or None)


def line_of(text: str, offset: int) -> int:
    """1-based line number of a character offset in ``text`` (for evidence of body matches)."""
    starts = [0] + [m.end() for m in re.finditer("\n", text)]
    return bisect.bisect_right(starts, offset)


__all__ = ["parse", "parse_response", "srcset_urls", "parse_meta_refresh", "line_of", "VOID", "HEAD_TAGS",
           "FORM_ASSOCIATED"]
