#!/usr/bin/env python3
"""Render the repository's documents as pages of the landing site.

Usage:
    python3 site/build_docs.py [--out DIR] [--version X.Y.Z]

Writes docs.html (README.md), changelog.html (CHANGELOG.md), security.html
(SECURITY.md) and license.html (LICENSE) next to index.html, and copies the
images the README uses (docs/...) into DIR/docs/. Run at deploy time
(.github/workflows/pages.yml) so the pages always match the repository; the
outputs are build products and are not committed.

Standard library only. The Markdown renderer covers what this repository's
documents use (GitHub-flavoured Markdown: ATX/setext headings, paragraphs,
emphasis, code spans, fenced code, tables, nested lists, task items,
blockquotes, links, images, autolinks, horizontal rules) plus a small
allow-list of inline HTML. All text is HTML-escaped. Links to repository files
become on-site pages or plain text; links to github.com are never emitted (the
only GitHub link on these pages is the header's "GitHub" button).
"""
from __future__ import annotations

import argparse
import html
import json
import pathlib
import re
import shutil
import struct
import sys
import urllib.parse
from html.parser import HTMLParser

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.dont_write_bytecode = True  # never leave __pycache__ in the published site
sys.path.insert(0, str(HERE))
from stamp_version import read_version  # noqa: E402

SITE = "https://abdulrahmanahmedelabed-prog.github.io/vulnscan/"
REPO = "abdulrahmanahmedelabed-prog/vulnscan"
REPO_URL = "https://github.com/" + REPO

# repository file -> on-site page
PAGES = {
    "README.md": "docs.html",
    "CHANGELOG.md": "changelog.html",
    "SECURITY.md": "security.html",
    "LICENSE": "license.html",
    "PRIVACY.md": "privacy.html",
}
# Stable ASCII ids for headings other pages link to (index.html footer links
# security.html#report). The build fails if a listed heading disappears, so a
# renamed heading cannot silently break the link.
HEADING_IDS = {
    "security.html": {"الإبلاغ عن ثغرة": "report"},
}
IMAGE_DIRS = ("docs",)  # repository folders whose images may be copied into the site

ARABIC = re.compile(r"[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF\uFB50-\uFDFF\uFE70-\uFEFF]")
PH_OPEN, PH_CLOSE = "\uE000", "\uE001"
PH_RE = re.compile(PH_OPEN + r"(\d+)" + PH_CLOSE)


def esc(s: str) -> str:
    return html.escape(s, quote=True)


def strip_tags(s: str) -> str:
    return html.unescape(re.sub(r"<[^>]*>", "", s))


# --------------------------------------------------------------------------- links


class Resolver:
    """Maps link targets and image sources found in a document to safe on-site URLs."""

    def __init__(self, out_dir: pathlib.Path, src_file: str):
        self.out_dir = out_dir
        self.src_dir = (ROOT / src_file).parent
        self.copied: set[str] = set()

    @staticmethod
    def _repo_file(rel: str, frag: str) -> str | None:
        while rel.startswith("./"):
            rel = rel[2:]
        page = PAGES.get(rel)
        if not page:
            return None
        return page + ("#" + frag if frag else "")

    def href(self, raw: str) -> str | None:
        """Return the href to emit, or None to render the link text without a link."""
        raw = raw.strip()
        if not raw:
            return None
        if raw.startswith("#"):
            return raw
        parts = urllib.parse.urlsplit(raw)
        scheme = parts.scheme.lower()
        if scheme == "mailto":
            return raw
        if scheme in ("http", "https"):
            host = (parts.hostname or "").lower()
            if raw.startswith(SITE) or raw.rstrip("/") + "/" == SITE:
                rest = raw[len(SITE):] if raw.startswith(SITE) else ""
                return rest or "index.html"
            if host in ("github.com", "www.github.com"):
                path = parts.path.rstrip("/")
                repo_path = "/" + REPO
                if path.lower().startswith(repo_path.lower()):
                    sub = path[len(repo_path):]
                    if re.fullmatch(r"/releases(/latest)?(/download/[^/]+)?|/releases/tag/[^/]+", sub):
                        return "index.html#download"
                    m = re.fullmatch(r"/(?:blob|tree)/[^/]+/(.+)", sub)
                    if m:
                        return self._repo_file(urllib.parse.unquote(m.group(1)), parts.fragment)
                    if sub in ("/security/advisories/new", "/security/policy", "/security"):
                        return "security.html#report"
                return None
            if host.endswith(".github.com") or host.endswith("githubusercontent.com") or host == "github.io":
                return None
            return raw
        if scheme:  # javascript:, data:, file:, ...
            return None
        path = urllib.parse.unquote(parts.path)
        target = (self.src_dir / path).resolve()
        try:
            rel = target.relative_to(ROOT).as_posix()
        except ValueError:
            return None
        return self._repo_file(rel, parts.fragment)

    def image(self, raw: str) -> tuple[str, int, int] | None:
        """Copy a repository image into the site and return (src, width, height)."""
        raw = raw.strip()
        parts = urllib.parse.urlsplit(raw)
        if parts.scheme or parts.netloc or not parts.path:
            if parts.scheme == "https" and self.href(raw) == raw:
                return raw, 0, 0  # external non-GitHub image (e.g. a badge)
            return None
        target = (self.src_dir / urllib.parse.unquote(parts.path)).resolve()
        try:
            rel = target.relative_to(ROOT)
        except ValueError:
            return None
        if rel.parts[0] not in IMAGE_DIRS or not target.is_file():
            return None
        if target.suffix.lower() not in (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp"):
            return None
        dest = self.out_dir / rel
        if rel.as_posix() not in self.copied:
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(target, dest)
            self.copied.add(rel.as_posix())
        w = h = 0
        if target.suffix.lower() == ".png":
            head = target.read_bytes()[:24]
            if head[:8] == b"\x89PNG\r\n\x1a\n":
                w, h = struct.unpack(">II", head[16:24])
        elif target.suffix.lower() == ".svg":
            # intrinsic size from the viewBox, so the page reserves the space before
            # the image loads (otherwise a late layout shift breaks #anchor jumps)
            m = re.search(r'viewBox="\s*[-\d.]+[\s,]+[-\d.]+[\s,]+([\d.]+)[\s,]+([\d.]+)\s*"',
                          target.read_text(encoding="utf-8", errors="replace")[:4096])
            if m:
                w, h = round(float(m.group(1))), round(float(m.group(2)))
        return urllib.parse.quote(rel.as_posix()), w, h


# --------------------------------------------------------------------------- inline HTML


class Sanitizer(HTMLParser):
    """Re-emits only an allow-list of tags and attributes; everything else is text or dropped."""

    TAGS = {"p", "div", "span", "a", "img", "b", "strong", "i", "em", "code", "br", "kbd",
            "sub", "sup", "details", "summary", "small"}
    VOID = {"img", "br"}
    DROP = {"script", "style", "iframe", "object", "embed", "template", "noscript"}

    def __init__(self, ctx: "Ctx"):
        super().__init__(convert_charrefs=True)
        self.ctx = ctx
        self.out: list[str] = []
        self.stack: list[str] = []
        self.skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in self.DROP:
            self.skip += 1
            return
        if self.skip or tag not in self.TAGS:
            return
        a = dict(attrs)
        keep: list[tuple[str, str]] = []
        if tag == "a":
            anchor = a.get("id") or a.get("name")
            if anchor:
                keep.append(("id", self.ctx.slugs.claim(anchor)))
            if a.get("href") is not None:
                href = self.ctx.resolver.href(a["href"] or "")
                if href is None:
                    tag = "span"
                else:
                    keep.append(("href", href))
        elif tag == "img":
            img = self.ctx.resolver.image(a.get("src") or "")
            if img is None:
                if a.get("alt"):
                    self.out.append(esc(a["alt"]))
                return
            keep += [("src", img[0]), ("alt", a.get("alt") or "")]
            size = {k: a[k] for k in ("width", "height") if (a.get(k) or "").isdigit()}
            if img[1] and img[2]:  # fill in the missing dimension from the intrinsic aspect ratio
                if "width" in size and "height" not in size:
                    size["height"] = str(max(1, round(int(size["width"]) * img[2] / img[1])))
                elif "height" in size and "width" not in size:
                    size["width"] = str(max(1, round(int(size["height"]) * img[1] / img[2])))
                elif not size:
                    size = {"width": str(img[1]), "height": str(img[2])}
            keep += [(k, size[k]) for k in ("width", "height") if k in size]
            keep.append(("loading", "lazy"))
        else:
            if (a.get("align") or "").lower() == "center":
                keep.append(("class", "center"))
            if (a.get("dir") or "").lower() in ("rtl", "ltr", "auto"):
                keep.append(("dir", a["dir"].lower()))
            if a.get("id"):
                keep.append(("id", self.ctx.slugs.claim(a["id"])))
        self.out.append("<" + tag + "".join(f' {k}="{esc(v)}"' for k, v in keep) + ">")
        if tag not in self.VOID:
            self.stack.append(tag)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in self.VOID and self.stack and tag in self.TAGS:
            self.handle_endtag(self.stack[-1])

    def handle_endtag(self, tag):
        if tag in self.DROP:
            self.skip = max(0, self.skip - 1)
            return
        if self.skip or tag not in self.TAGS or tag in self.VOID:
            return
        # close the innermost open element; a renamed <a> (now <span>) closes too
        if self.stack:
            if tag not in self.stack and not (tag == "a" and "span" in self.stack):
                return
            self.out.append("</" + self.stack.pop() + ">")

    def handle_data(self, data):
        if not self.skip:
            self.out.append(esc(data))

    def result(self) -> str:
        self.close()
        while self.stack:
            self.out.append("</" + self.stack.pop() + ">")
        return "".join(self.out)


# --------------------------------------------------------------------------- context


class Slugs:
    """GitHub-style heading ids, unique per page."""

    def __init__(self):
        self.used: set[str] = set()

    def claim(self, wanted: str) -> str:
        base = wanted or "section"
        slug, n = base, 1
        while slug in self.used:
            slug = f"{base}-{n}"
            n += 1
        self.used.add(slug)
        return slug

    def make(self, text: str) -> str:
        s = text.strip().lower()
        s = "".join(c for c in s if c.isalnum() or c in "-_ " or (0x064B <= ord(c) <= 0x065F))
        return self.claim(s.replace(" ", "-"))


class Ctx:
    def __init__(self, resolver: Resolver, slugs: Slugs, rtl: bool, page: str):
        self.resolver = resolver
        self.slugs = slugs
        self.rtl = rtl
        self.page = page
        self.toc: list[tuple[int, str, str]] = []
        self.forced_ids = dict(HEADING_IDS.get(page, {}))
        self.used_forced: set[str] = set()

    def dir_attr(self, inner_html: str) -> str:
        """In a right-to-left document, a block with no Arabic letters reads left to right."""
        text = strip_tags(inner_html)
        if self.rtl and not ARABIC.search(text) and re.search(r"[A-Za-z]{3,}", text):
            return ' dir="ltr"'
        return ""


# --------------------------------------------------------------------------- inline Markdown

PUNCT = set("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")
INLINE_TAG = re.compile(r"<(/?)(br|b|strong|i|em|kbd|sub|sup|small)\s*/?>", re.I)
INLINE_ANCHOR = re.compile(r'<a\s+(?:id|name)="([^"<>]+)"\s*>\s*</a>', re.I)
AUTOLINK = re.compile(r"<((?:https?|mailto):[^\s<>]+)>", re.I)
BARE_URL = re.compile(r"https?://[^\s<>\"'`]+", re.I)
ENTITY = re.compile(r"&(#\d{1,7}|#[xX][0-9a-fA-F]{1,6}|[A-Za-z][A-Za-z0-9]{1,31});")


def _trim_url(url: str) -> str:
    while url and url[-1] in ".,;:!?*_~'\"":
        url = url[:-1]
    while url.endswith(")") and url.count(")") > url.count("("):
        url = url[:-1]
    return url


def _find_close_bracket(s: str, i: int) -> int:
    """s[i] == '['; return the index of the matching ']' or -1."""
    depth, j = 0, i
    while j < len(s):
        c = s[j]
        if c == "\\":
            j += 2
            continue
        if c == "`":
            run = len(s[j:]) - len(s[j:].lstrip("`"))
            k = s.find("`" * run, j + run)
            if k != -1:
                j = k + run
                continue
        if c == "[":
            depth += 1
        elif c == "]":
            depth -= 1
            if depth == 0:
                return j
        j += 1
    return -1


def _parse_dest(s: str, i: int) -> tuple[str, int] | None:
    """s[i] == '('; return (destination, index after ')')."""
    j = i + 1
    while j < len(s) and s[j] in " \t\n":
        j += 1
    if j < len(s) and s[j] == "<":
        k = s.find(">", j)
        if k == -1:
            return None
        dest, j = s[j + 1:k], k + 1
    else:
        depth, start = 0, j
        while j < len(s):
            c = s[j]
            if c == "\\" and j + 1 < len(s):
                j += 2
                continue
            if c in " \t\n":
                break
            if c == "(":
                depth += 1
            elif c == ")":
                if depth == 0:
                    break
                depth -= 1
            j += 1
        dest = s[start:j]
    while j < len(s) and s[j] in " \t\n":
        j += 1
    if j < len(s) and s[j] in "\"'(":
        close = ")" if s[j] == "(" else s[j]
        k = s.find(close, j + 1)
        if k == -1:
            return None
        j = k + 1
        while j < len(s) and s[j] in " \t\n":
            j += 1
    if j >= len(s) or s[j] != ")":
        return None
    return re.sub(r"\\([^\w\s])", r"\1", dest), j + 1


EMPHASIS = [
    (re.compile(r"\*\*(?=[^\s*])(.+?)(?<=[^\s*])\*\*", re.S), "strong"),
    (re.compile(r"(?<![\w_])__(?=[^\s_])(.+?)(?<=[^\s_])__(?![\w_])", re.S), "strong"),
    (re.compile(r"(?<!\*)\*(?=[^\s*])(.+?)(?<=[^\s*])\*(?!\*)", re.S), "em"),
    (re.compile(r"(?<![\w_])_(?=[^\s_])(.+?)(?<=[^\s_])_(?![\w_])", re.S), "em"),
    (re.compile(r"~~(?=\S)(.+?)(?<=\S)~~", re.S), "del"),
]


def inline(s: str, ctx: Ctx) -> str:
    tokens: list[str] = []

    def ph(value: str) -> str:
        tokens.append(value)
        return f"{PH_OPEN}{len(tokens) - 1}{PH_CLOSE}"

    out: list[str] = []
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c == "\\" and i + 1 < n:
            nxt = s[i + 1]
            if nxt == "\n":
                out.append(ph("<br>\n"))
                i += 2
                continue
            if nxt in PUNCT:
                out.append(ph(esc(nxt)))
                i += 2
                continue
        if c == "`":
            run = len(s[i:]) - len(s[i:].lstrip("`"))
            k = i + run
            while True:
                k = s.find("`" * run, k)
                if k == -1 or (k + run >= n or s[k + run] != "`"):
                    break
                k += len(s[k:]) - len(s[k:].lstrip("`"))
            if k != -1:
                code = s[i + run:k].replace("\n", " ")
                if len(code) > 2 and code[0] == " " and code[-1] == " " and code.strip():
                    code = code[1:-1]
                out.append(ph("<code>" + esc(code) + "</code>"))
                i = k + run
                continue
            out.append(ph("`" * run))
            i += run
            continue
        if c == "!" and i + 1 < n and s[i + 1] == "[":
            close = _find_close_bracket(s, i + 1)
            if close != -1 and close + 1 < n and s[close + 1] == "(":
                dest = _parse_dest(s, close + 1)
                if dest:
                    alt = strip_tags(inline(s[i + 2:close], ctx))
                    img = ctx.resolver.image(dest[0])
                    if img is None:
                        out.append(ph(esc(alt)))
                    else:
                        size = f' width="{img[1]}" height="{img[2]}"' if img[1] else ""
                        out.append(ph(f'<img src="{esc(img[0])}" alt="{esc(alt)}"{size} loading="lazy">'))
                    i = dest[1]
                    continue
        if c == "[":
            close = _find_close_bracket(s, i)
            if close != -1 and close + 1 < n and s[close + 1] == "(":
                dest = _parse_dest(s, close + 1)
                if dest:
                    label = inline(s[i + 1:close], ctx)
                    href = ctx.resolver.href(dest[0])
                    if href is None:
                        out.append(ph(label))
                    else:
                        ext = ' rel="noopener"' if href.startswith(("http://", "https://")) else ""
                        out.append(ph(f'<a href="{esc(href)}"{ext}>{label}</a>'))
                    i = dest[1]
                    continue
        if c == "<":
            m = AUTOLINK.match(s, i) or None
            if m:
                href = ctx.resolver.href(m.group(1))
                text = esc(m.group(1).removeprefix("mailto:"))
                # a visible URL is linked only to itself, never to a substitute page
                out.append(ph(f'<a href="{esc(href)}" rel="noopener">{text}</a>' if href == m.group(1) else text))
                i = m.end()
                continue
            m = INLINE_ANCHOR.match(s, i)
            if m:
                out.append(ph(f'<a id="{esc(ctx.slugs.claim(m.group(1)))}"></a>'))
                i = m.end()
                continue
            m = INLINE_TAG.match(s, i)
            if m:
                tag = m.group(2).lower()
                out.append(ph("<br>" if tag == "br" else f"<{m.group(1)}{tag}>"))
                i = m.end()
                continue
        if c == "&":
            m = ENTITY.match(s, i)
            if m and html.unescape(m.group(0)) != m.group(0):
                out.append(ph(m.group(0)))
                i = m.end()
                continue
        if c in "hH" and (i == 0 or not (s[i - 1].isalnum() or s[i - 1] in "/_-")):
            m = BARE_URL.match(s, i)
            if m:
                url = _trim_url(m.group(0))
                href = ctx.resolver.href(url)
                out.append(ph(f'<a href="{esc(href)}" rel="noopener">{esc(url)}</a>' if href == url else esc(url)))
                i += len(url)
                continue
        if c == "\n":
            # two trailing spaces = hard break
            j = len(out)
            while j and out[j - 1] == " ":
                j -= 1
            if len(out) - j >= 2:
                del out[j:]
                out.append(ph("<br>\n"))
            else:
                out.append("\n")
            i += 1
            continue
        out.append(esc(c))
        i += 1
    text = "".join(out)
    for rx, tag in EMPHASIS:
        text = rx.sub(lambda m, t=tag: f"<{t}>{m.group(1)}</{t}>", text)
    while PH_OPEN in text:
        text = PH_RE.sub(lambda m: tokens[int(m.group(1))], text)
    return text.rstrip()


# --------------------------------------------------------------------------- blocks

FENCE = re.compile(r"^( {0,3})(`{3,}|~{3,})[ \t]*([^`\s]*)[^`]*$")
ATX = re.compile(r"^ {0,3}(#{1,6})(?:[ \t]+(.*?))?(?:[ \t]+#+)?[ \t]*$")
HR = re.compile(r"^ {0,3}(?:(?:\*[ \t]*){3,}|(?:-[ \t]*){3,}|(?:_[ \t]*){3,})$")
LIST = re.compile(r"^( {0,3})([-*+]|\d{1,9}[.)])([ \t]+|$)")
QUOTE = re.compile(r"^ {0,3}> ?")
HTML_BLOCK = re.compile(r"^ {0,3}(?:<!--|</?[a-zA-Z][a-zA-Z0-9-]*(?:[\s/>]|$))")
TABLE_DELIM = re.compile(r"^ {0,3}\|?[ \t]*:?-+:?[ \t]*(?:\|[ \t]*:?-+:?[ \t]*)*\|?[ \t]*$")
SETEXT = re.compile(r"^ {0,3}(=+|-+)[ \t]*$")


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _split_row(line: str) -> list[str]:
    line = line.strip()
    if line.startswith("|"):
        line = line[1:]
    if line.endswith("|") and not line.endswith("\\|"):
        line = line[:-1]
    cells, cur, i = [], [], 0
    while i < len(line):
        if line[i] == "\\" and i + 1 < len(line) and line[i + 1] == "|":
            cur.append("|")
            i += 2
            continue
        if line[i] == "|":
            cells.append("".join(cur).strip())
            cur = []
        else:
            cur.append(line[i])
        i += 1
    cells.append("".join(cur).strip())
    return cells


def _starts_block(line: str, in_paragraph: bool = True) -> bool:
    if not line.strip():
        return True
    if FENCE.match(line) or ATX.match(line) or HR.match(line) or QUOTE.match(line):
        return True
    if HTML_BLOCK.match(line) and not INLINE_ANCHOR.match(line.strip()):
        return line.lstrip().startswith(("<p", "<div", "<details", "<table", "<!--", "</p", "</div"))
    m = LIST.match(line)
    if m and m.group(3):  # an empty item cannot interrupt a paragraph
        marker = m.group(2)
        return not in_paragraph or not marker[0].isdigit() or marker[:-1] == "1"
    return False


def blocks(lines: list[str], ctx: Ctx, tight: bool = False) -> str:
    out: list[str] = []
    i, n = 0, len(lines)
    while i < n:
        line = lines[i]
        if not line.strip():
            i += 1
            continue

        m = FENCE.match(line)
        if m:
            indent, fence, lang = len(m.group(1)), m.group(2), m.group(3)
            body: list[str] = []
            i += 1
            while i < n:
                cl = lines[i]
                if re.match(r"^ {0,3}" + re.escape(fence[0]) + "{" + str(len(fence)) + r",}[ \t]*$", cl):
                    i += 1
                    break
                body.append(cl[min(indent, _indent(cl)):])
                i += 1
            cls = f' class="language-{esc(lang)}"' if lang else ""
            label = f' data-lang="{esc(lang)}"' if lang else ""
            out.append(f'<pre dir="ltr"{label}><code{cls}>' + esc("\n".join(body)) + "</code></pre>")
            continue

        m = ATX.match(line)
        if m:
            out.append(_heading(len(m.group(1)), m.group(2) or "", ctx))
            i += 1
            continue

        if HR.match(line):
            out.append("<hr>")
            i += 1
            continue

        if QUOTE.match(line):
            body = []
            while i < n and lines[i].strip() and (QUOTE.match(lines[i]) or not _starts_block(lines[i])):
                body.append(QUOTE.sub("", lines[i], count=1))
                i += 1
            inner = blocks(body, ctx)
            out.append(f"<blockquote{ctx.dir_attr(inner)}>{inner}</blockquote>")
            continue

        if HTML_BLOCK.match(line):
            if line.lstrip().startswith("<!--"):  # comments are dropped
                while i < n and "-->" not in lines[i]:
                    i += 1
                i += 1
                continue
            body = []
            while i < n and lines[i].strip():
                body.append(lines[i])
                i += 1
            raw = "\n".join(body)
            san = Sanitizer(ctx)
            san.feed(raw)
            out.append(san.result())
            continue

        m = LIST.match(line)
        if m:
            i = _list(lines, i, ctx, out)
            continue

        if "|" in line and i + 1 < n and TABLE_DELIM.match(lines[i + 1]) and "-" in lines[i + 1]:
            head = _split_row(line)
            aligns = []
            for cell in _split_row(lines[i + 1]):
                left, right = cell.startswith(":"), cell.endswith(":")
                aligns.append("center" if left and right else "right" if right else "left" if left else "")
            if len(aligns) == len(head):
                i += 2
                rows = []
                while i < n and lines[i].strip() and "|" in lines[i] and not _starts_block(lines[i]):
                    rows.append(_split_row(lines[i]))
                    i += 1
                out.append(_table(head, aligns, rows, ctx))
                continue

        # paragraph (possibly a setext heading)
        para = [line.lstrip()]
        i += 1
        level = 0
        while i < n:
            nl = lines[i]
            sm = SETEXT.match(nl)
            if sm and nl.strip():
                level = 1 if sm.group(1)[0] == "=" else 2
                i += 1
                break
            if _starts_block(nl):
                break
            if "|" in nl and i + 1 < n and TABLE_DELIM.match(lines[i + 1]) and "-" in lines[i + 1]:
                break
            para.append(nl.rstrip("\n") if nl.endswith("  ") else nl.strip())
            i += 1
        text = "\n".join(p.lstrip() for p in para)
        if level:
            out.append(_heading(level, text, ctx))
            continue
        inner = inline(text, ctx)
        out.append(inner if tight else f"<p{ctx.dir_attr(inner)}>{inner}</p>")
    return "\n".join(out)


def _heading(level: int, raw: str, ctx: Ctx) -> str:
    inner = inline(raw.strip(), ctx)
    text = strip_tags(inner).strip()
    forced = ctx.forced_ids.get(text)
    if forced:
        hid = ctx.slugs.claim(forced)
        ctx.used_forced.add(text)
    else:
        hid = ctx.slugs.make(text)
    if level in (2, 3):
        ctx.toc.append((level, hid, text))
    return (f'<h{level} id="{esc(hid)}"{ctx.dir_attr(inner)}>{inner}'
            f'<a class="hl" href="#{esc(hid)}" aria-hidden="true" tabindex="-1">#</a></h{level}>')


def _table(head: list[str], aligns: list[str], rows: list[list[str]], ctx: Ctx) -> str:
    def cell(tag: str, text: str, k: int) -> str:
        style = f' style="text-align:{aligns[k]}"' if k < len(aligns) and aligns[k] else ""
        return f"<{tag}{style}>{inline(text, ctx)}</{tag}>"

    th = "".join(cell("th", c, k) for k, c in enumerate(head))
    body = []
    for r in rows:
        r = (r + [""] * len(head))[:len(head)]
        body.append("<tr>" + "".join(cell("td", c, k) for k, c in enumerate(r)) + "</tr>")
    whole = th + "".join(body)
    return (f'<div class="tablewrap"{ctx.dir_attr(whole)}><table><thead><tr>{th}</tr></thead>'
            f"<tbody>{''.join(body)}</tbody></table></div>")


def _list(lines: list[str], i: int, ctx: Ctx, out: list[str]) -> int:
    n = len(lines)
    first = LIST.match(lines[i])
    ordered = first.group(2)[-1] in ".)"
    start = int(first.group(2)[:-1]) if ordered else 1
    items: list[list[str]] = []
    loose = False
    while i < n:
        m = LIST.match(lines[i])
        if not m or (m.group(2)[-1] in ".)") != ordered:
            break
        if HR.match(lines[i]):
            break
        base = len(m.group(1))
        spaces = len(m.group(3).expandtabs(4)) if m.group(3) else 1
        if spaces > 4:
            spaces = 1
        offset = base + len(m.group(2)) + spaces
        body = [lines[i][m.end():] if m.group(3) else ""]
        if spaces == 1 and m.group(3) and len(m.group(3)) > 1:
            body = [lines[i][base + len(m.group(2)) + 1:]]
        i += 1
        in_para = bool(body[0].strip())
        while i < n:
            ln = lines[i].expandtabs(4)
            if not ln.strip():
                k = i
                while k < n and not lines[k].strip():
                    k += 1
                if k < n and _indent(lines[k].expandtabs(4)) >= offset:
                    body.extend([""] * (k - i))
                    i = k
                    in_para = False
                    continue
                break
            if _indent(ln) >= offset:
                body.append(ln[offset:])
                content = ln[offset:]
                in_para = not (FENCE.match(content) or ATX.match(content) or HR.match(content))
                i += 1
                continue
            if LIST.match(ln) or _starts_block(ln):
                break
            if in_para:  # lazy continuation line
                body.append(ln.strip())
                i += 1
                continue
            break
        while body and not body[-1].strip():
            body.pop()
        if _has_direct_blank(body):  # a blank line between two blocks of the item
            loose = True
        items.append(body)
        # blank lines between items make the list loose
        k = i
        while k < n and not lines[k].strip():
            k += 1
        if k < n and k > i:
            m2 = LIST.match(lines[k])
            if m2 and (m2.group(2)[-1] in ".)") == ordered and not HR.match(lines[k]) and len(m2.group(1)) < offset:
                loose = True
                i = k
                continue
            break
    tag = "ol" if ordered else "ul"
    attr = f' start="{start}"' if ordered and start != 1 else ""
    lis = []
    for body in items:
        task = ""
        tm = re.match(r"^\[([ xX])\][ \t]+", body[0]) if body else None
        if tm:
            checked = " checked" if tm.group(1) != " " else ""
            task = f'<input type="checkbox" disabled{checked} aria-hidden="true"> '
            body = [body[0][tm.end():]] + body[1:]
        inner = blocks(body, ctx, tight=not loose)
        cls = ' class="task"' if task else ""
        lis.append(f"<li{cls}{ctx.dir_attr(inner)}>{task}{inner}</li>")
    out.append(f"<{tag}{attr}>" + "\n".join(lis) + f"</{tag}>")
    return i


def _has_direct_blank(body: list[str]) -> bool:
    """True if a blank line separates two top-level blocks of an item (not inside a nested list/fence)."""
    in_fence = False
    for k, b in enumerate(body):
        if FENCE.match(b):
            in_fence = not in_fence
        if in_fence or b.strip():
            continue
        nxt = next((x for x in body[k + 1:] if x.strip()), None)
        if nxt is not None and _indent(nxt) == 0 and not LIST.match(nxt):
            return True
    return False


# --------------------------------------------------------------------------- page shell

UI = {
    "en": {
        "skip": "Skip to content", "brand": "Kashif", "gh.sr": "Kashif on GitHub", "nav.label": "Primary",
        "nav.menu": "Menu", "lang.label": "Language", "theme.toLight": "Switch to light theme",
        "theme.toDark": "Switch to dark theme", "nav.home": "Home", "nav.docs": "Documentation",
        "nav.changelog": "Changelog", "nav.security": "Security", "nav.license": "License", "nav.privacy": "Privacy",
        "toc": "On this page", "foot.ver": "Version", "foot.legal": "Scan only systems you are authorized to test.",
        "foot.src": "Generated from the repository's", "top": "Back to top",
        "docs.title": "Documentation — Kashif (vulnscan)",
        "docs.desc": "Kashif (vulnscan) documentation: install, quick start, CI and GitHub Code Scanning, baselines, accuracy on the OWASP Benchmark, languages and limitations.",
        "changelog.title": "Changelog — Kashif (vulnscan)",
        "changelog.desc": "What changed in each Kashif (vulnscan) release: new detectors, languages, accuracy and fixes.",
        "security.title": "Security policy — Kashif (vulnscan)",
        "security.desc": "How to report a vulnerability in Kashif (vulnscan) privately, what counts as one, and how to verify release binaries.",
        "license.title": "MIT License — Kashif (vulnscan)",
        "license.desc": "Kashif (vulnscan) is free and open source under the MIT License.",
        "privacy.title": "Privacy — Kashif (vulnscan)",
        "privacy.desc": "Kashif sends nothing about you or your code; the website counts visits anonymously, without cookies.",
        "ar.note": "This document is written in Arabic.",
    },
    "ar": {
        "skip": "تخطَّ إلى المحتوى", "brand": "كاشِف", "gh.sr": "كاشِف على GitHub", "nav.label": "التنقّل الرئيسي",
        "nav.menu": "القائمة", "lang.label": "اللغة", "theme.toLight": "التبديل إلى الوضع الفاتح",
        "theme.toDark": "التبديل إلى الوضع الداكن", "nav.home": "الرئيسية", "nav.docs": "التوثيق",
        "nav.changelog": "سجل التغييرات", "nav.security": "الأمان", "nav.license": "الرخصة", "nav.privacy": "الخصوصية",
        "toc": "في هذه الصفحة", "foot.ver": "الإصدار", "foot.legal": "افحص فقط الأنظمة المصرَّح لك باختبارها.",
        "foot.src": "مولَّدة من ملف المستودع", "top": "إلى الأعلى",
        "docs.title": "التوثيق — كاشِف (vulnscan)",
        "docs.desc": "توثيق كاشِف (vulnscan): التثبيت والبدء السريع والتكامل مع CI وGitHub Code Scanning وخط الأساس والدقة على OWASP Benchmark واللغات والحدود.",
        "changelog.title": "سجل التغييرات — كاشِف (vulnscan)",
        "changelog.desc": "ما الذي تغيّر في كل إصدار من كاشِف (vulnscan): كواشف ولغات جديدة وتحسينات الدقة والإصلاحات.",
        "security.title": "سياسة الأمان — كاشِف (vulnscan)",
        "security.desc": "كيف تبلّغ عن ثغرة في كاشِف (vulnscan) بشكل خاص، وما الذي يُعدّ ثغرة، وكيف تتحقق من سلامة النسخ.",
        "license.title": "رخصة MIT — كاشِف (vulnscan)",
        "license.desc": "كاشِف (vulnscan) مجاني ومفتوح المصدر برخصة MIT.",
        "privacy.title": "الخصوصية — كاشِف (vulnscan)",
        "privacy.desc": "لا يرسل كاشِف أي شيء عنك أو عن الكود؛ والموقع يعدّ الزيارات عدًّا مجهول الهوية دون ملفات تعريف ارتباط.",
        "ar.note": "هذا المستند مكتوب بالعربية.",
    },
}

NAV = [("docs.html", "nav.docs"), ("changelog.html", "nav.changelog"),
       ("security.html", "nav.security"), ("license.html", "nav.license"), ("privacy.html", "nav.privacy")]

FALLBACK_TOKENS = """:root{--radius:14px;--wrap:1200px;--font:"Inter","IBM Plex Sans Arabic",system-ui,sans-serif;
--font-ar:"IBM Plex Sans Arabic","Inter",system-ui,sans-serif;--mono:"JetBrains Mono",ui-monospace,monospace;
--code:#0a0f1b;--code-line:#1c2740;--code-text:#c9d4e3;--code-dim:#7d8ba1}
:root,[data-theme="dark"]{color-scheme:dark;--bg:#070b14;--bg2:#0a101d;--panel:#0e1524;--panel2:#131c2f;--line:#1c2740;
--line2:#2a3956;--text:#e8eef6;--muted:#a3b1c4;--dim:#8291a7;--accent:#3fc07c;--accent-ink:#6ad69a;--head-bg:rgba(7,11,20,.8);
--chip-code:#141e33;--chip-code-fg:#bfeaf3;--tint:rgba(63,192,124,.1);--tint-bd:rgba(63,192,124,.22)}
[data-theme="light"]{color-scheme:light;--bg:#fff;--bg2:#f5f7fb;--panel:#fff;--panel2:#f1f4f9;--line:#e3e8f0;--line2:#d0d8e4;
--text:#0b1220;--muted:#3f4a5c;--dim:#556072;--accent:#087a3f;--accent-ink:#087a3f;--head-bg:rgba(255,255,255,.85);
--chip-code:#eef3f8;--chip-code-fg:#0b4a5c;--tint:rgba(8,122,63,.08);--tint-bd:rgba(8,122,63,.22)}"""


def landing_tokens() -> str:
    """The design tokens (colours, fonts) of site/index.html, so every page shares them."""
    try:
        text = (HERE / "index.html").read_text(encoding="utf-8")
    except OSError:
        return FALLBACK_TOKENS
    start = text.find(":root{")
    end = text.find("*{box-sizing", start)
    if start == -1 or end == -1:
        return FALLBACK_TOKENS
    return text[start:end].strip()


def landing_symbols() -> str:
    try:
        text = (HERE / "index.html").read_text(encoding="utf-8")
    except OSError:
        text = ""
    found = []
    for sid in ("i-gh", "i-sun", "i-moon", "i-menu"):
        m = re.search(r'<symbol id="' + sid + r'"[^>]*>.*?</symbol>', text, re.S)
        if not m:
            raise SystemExit(f"build_docs: icon {sid} not found in site/index.html")
        found.append(m.group(0))
    return "\n".join(found)


CSS = """
*{box-sizing:border-box}
html{scroll-behavior:smooth;-webkit-text-size-adjust:100%;scroll-padding-top:84px}
body{margin:0;background:var(--bg);color:var(--text);font-family:var(--font);font-size:16px;line-height:1.65;overflow-x:hidden;-webkit-font-smoothing:antialiased}
html[lang="ar"] body{font-family:var(--font-ar)}
:lang(ar){font-family:var(--font-ar)}
a{color:var(--accent-ink)}
a:hover{text-decoration-thickness:2px}
img{max-width:100%;height:auto}
code,pre,code:lang(ar),pre:lang(ar){font-family:var(--mono)}
.wrap{max-width:var(--wrap);margin:0 auto;padding:0 24px}
.sr{position:absolute!important;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:6px}
.ic{width:20px;height:20px;flex:none;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
.skip{position:absolute;inset-inline-start:12px;top:-60px;z-index:100;background:var(--text);color:var(--bg);padding:10px 16px;border-radius:10px;font-weight:600;text-decoration:none}
.skip:focus{top:12px}
.top{position:sticky;top:0;z-index:50;background:var(--head-bg);backdrop-filter:saturate(1.4) blur(14px);-webkit-backdrop-filter:saturate(1.4) blur(14px);border-bottom:1px solid var(--line)}
.nav{display:flex;align-items:center;gap:26px;height:64px}
.brand{display:flex;align-items:center;gap:10px;color:var(--text);font-weight:700;font-size:18px;letter-spacing:-.01em;text-decoration:none}
.brand img{width:30px;height:30px;display:block}
.brand small{font-weight:500;color:var(--dim);font-size:14px}
.links{display:flex;gap:20px;flex:1}
.links a{color:var(--muted);font-size:14.5px;font-weight:500;text-decoration:none;padding:6px 0}
.links a:hover,.links a[aria-current="page"]{color:var(--text)}
.links a[aria-current="page"]{box-shadow:inset 0 -2px 0 var(--accent)}
.tools{display:flex;align-items:center;gap:8px;margin-inline-start:auto}
.seg{display:inline-flex;border:1px solid var(--line2);border-radius:10px;padding:3px;background:var(--panel)}
.seg button{all:unset;cursor:pointer;padding:4px 10px;border-radius:7px;font-size:13px;font-weight:600;color:var(--muted);line-height:1.4;min-width:20px;text-align:center}
.seg button[aria-pressed="true"]{background:var(--panel2);color:var(--text);box-shadow:inset 0 0 0 1px var(--line2)}
.seg button:focus-visible{outline:2px solid var(--accent)}
.seg .ar{font-family:var(--font-ar);font-size:14px}
.iconbtn{all:unset;cursor:pointer;width:36px;height:36px;display:grid;place-items:center;border-radius:10px;border:1px solid var(--line2);background:var(--panel);color:var(--muted)}
.iconbtn:hover{color:var(--text)}
.iconbtn:focus-visible{outline:2px solid var(--accent)}
.iconbtn .ic{width:18px;height:18px}
[data-theme="dark"] .i-sun{display:block}[data-theme="dark"] .i-moon{display:none}
[data-theme="light"] .i-sun{display:none}[data-theme="light"] .i-moon{display:block}
.menu-btn{display:none}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;border:1px solid var(--line2);color:var(--text);background:var(--panel);font-weight:600;white-space:nowrap;text-decoration:none;padding:7px 12px;font-size:14px;border-radius:9px}
.btn:hover{border-color:var(--dim)}
.btn svg{width:18px;height:18px}
.page{display:grid;grid-template-columns:240px minmax(0,1fr);gap:48px;padding-top:40px;padding-bottom:72px}
.page.solo{grid-template-columns:minmax(0,1fr)}
.toc{position:sticky;top:88px;align-self:start;max-height:calc(100vh - 110px);overflow:auto;font-size:14px}
.toc summary{font-size:12.5px;letter-spacing:.06em;text-transform:uppercase;font-weight:700;color:var(--text);cursor:pointer;margin-bottom:10px;list-style:none}
.toc summary::-webkit-details-marker{display:none}
.toc ol{list-style:none;margin:0;padding:0;display:grid;gap:2px}
.toc a{display:block;color:var(--muted);text-decoration:none;padding:4px 10px;border-inline-start:2px solid var(--line);line-height:1.45}
.toc a:hover{color:var(--text);border-color:var(--dim)}
.toc a.on{color:var(--text);border-color:var(--accent)}
.toc .l3 a{padding-inline-start:24px;font-size:13.5px}
.meta{display:flex;flex-wrap:wrap;align-items:center;gap:10px;margin:0 0 22px;color:var(--dim);font-size:13.5px}
.pill{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--line2);border-radius:999px;background:var(--panel);padding:3px 11px;color:var(--muted);text-decoration:none}
.pill .ver{background:var(--tint);color:var(--accent-ink);border-radius:999px;padding:1px 8px;font-weight:600;font-family:var(--mono);font-size:12px}
.prose{min-width:0;max-width:860px;overflow-wrap:anywhere}
.prose h1{font-size:clamp(28px,4vw,38px);line-height:1.2;letter-spacing:-.02em;margin:0 0 18px}
.prose h2{font-size:24px;line-height:1.3;margin:48px 0 14px;padding-top:28px;border-top:1px solid var(--line)}
.prose h3{font-size:19px;line-height:1.35;margin:32px 0 10px}
.prose h4,.prose h5,.prose h6{font-size:16px;margin:24px 0 8px}
.prose .hl{margin-inline-start:8px;color:var(--dim);text-decoration:none;opacity:0;font-weight:500}
.prose h1:hover .hl,.prose h2:hover .hl,.prose h3:hover .hl,.prose h4:hover .hl,.prose .hl:focus{opacity:1}
.prose p,.prose ul,.prose ol,.prose blockquote,.prose pre,.prose .tablewrap{margin:0 0 16px}
.prose ul,.prose ol{padding-inline-start:26px}
.prose li{margin:4px 0}
.prose li>ul,.prose li>ol{margin:4px 0 0}
.prose li.task{list-style:none}
.prose li.task input{margin-inline:-22px 6px}
.prose code{background:var(--chip-code);color:var(--chip-code-fg);border-radius:6px;padding:.12em .4em;font-size:.88em;direction:ltr;unicode-bidi:isolate}
.prose pre{background:var(--code);color:var(--code-text);border:1px solid var(--code-line);border-radius:12px;padding:16px 18px;overflow-x:auto;font-size:13.5px;line-height:1.6;text-align:left;overflow-wrap:normal}
.prose pre code{background:none;color:inherit;padding:0;font-size:inherit;border-radius:0}
.prose blockquote{border-inline-start:3px solid var(--accent);background:var(--tint);border-radius:10px;padding:12px 16px;color:var(--text)}
.prose blockquote>:last-child{margin-bottom:0}
.prose hr{border:0;border-top:1px solid var(--line);margin:40px 0}
.prose .tablewrap{overflow-x:auto;border:1px solid var(--line);border-radius:12px}
.prose table{border-collapse:collapse;width:100%;font-size:14.5px;overflow-wrap:normal}
.prose th,.prose td{padding:9px 14px;border-bottom:1px solid var(--line);text-align:start;vertical-align:top}
.prose th{background:var(--panel2);font-weight:600}
.prose tr:last-child td{border-bottom:0}
.prose td img{display:block;border-radius:8px;border:1px solid var(--line)}
.prose img{border-radius:6px}
.prose .center{text-align:center}
.prose .lic{white-space:pre-wrap;font-family:var(--mono);font-size:14px;line-height:1.7;background:var(--panel2);border:1px solid var(--line);border-radius:12px;padding:20px 22px;color:var(--text);overflow-wrap:anywhere}
html:not(.js) .half.sw+.half.sw{margin-top:56px;padding-top:8px;border-top:1px solid var(--line)}
html.js[lang="en"] .sw[lang="ar"],html.js[lang="ar"] .sw[lang="en"]{display:none}
.half>hr:last-child{display:none}
footer{border-top:1px solid var(--line);padding:28px 0 36px;color:var(--dim);font-size:14px;background:var(--bg2)}
.foot{display:flex;flex-wrap:wrap;gap:12px 24px;justify-content:space-between;align-items:center}
.foot a{color:var(--muted)}
.foot nav{display:flex;flex-wrap:wrap;gap:8px 18px}
@media(max-width:1080px){
  .links{display:none}
  .menu-btn{display:grid}
  .links.open{display:flex;position:absolute;top:64px;inset-inline:0;flex-direction:column;gap:0;background:var(--bg);border-bottom:1px solid var(--line);padding:8px 24px 16px}
  .links.open a{padding:12px 0;border-bottom:1px solid var(--line);font-size:16px;box-shadow:none}
}
@media(max-width:900px){
  .page{grid-template-columns:minmax(0,1fr);gap:20px;padding-top:24px}
  .toc{position:static;max-height:none;border:1px solid var(--line);border-radius:12px;padding:12px 14px;background:var(--panel)}
  .toc summary{margin:0}
  .toc[open] summary{margin-bottom:10px}
  .toc summary{display:flex;justify-content:space-between;align-items:center}
  .toc summary::after{content:"+";font-size:18px;line-height:1;color:var(--dim)}
  .toc[open] summary::after{content:"\2212"}
}
@media(max-width:560px){
  .wrap{padding:0 16px}
  .nav{gap:10px}
  .brand small,.tools .gh-txt{display:none}
  .tools{gap:6px}
  .iconbtn{width:34px;height:34px}
  .prose pre{font-size:12.5px;padding:14px}
  .prose .lic{font-size:12.5px;padding:16px}
  .prose h2{font-size:21px}
}
@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}}
"""

EARLY_JS = """(function () {
  var d = document.documentElement, lang = "en", theme = null;
  d.className = "js";
  try { var q = new URLSearchParams(location.search).get("lang"); if (q === "en" || q === "ar") lang = q; else { var s = localStorage.getItem("kashif-lang"); if (s === "en" || s === "ar") lang = s; else lang = /^ar\\b/i.test((navigator.languages && navigator.languages[0]) || navigator.language || "") ? "ar" : "en"; } } catch (e) {}
  try { theme = localStorage.getItem("kashif-theme"); } catch (e) {}
  if (theme !== "light" && theme !== "dark") theme = (window.matchMedia && matchMedia("(prefers-color-scheme: light)").matches) ? "light" : "dark";
  d.lang = lang; d.dir = lang === "ar" ? "rtl" : "ltr"; d.setAttribute("data-theme", theme);
})();"""

PAGE_JS = """(function () {
  "use strict";
  var root = document.documentElement, I18N = __I18N__, PAGE = "__PAGE__";
  var state = { lang: root.lang === "ar" ? "ar" : "en", theme: root.getAttribute("data-theme") === "light" ? "light" : "dark" };
  var themeStored = false;
  try { themeStored = !!localStorage.getItem("kashif-theme"); } catch (e) {}
  function t(k) { return (I18N[state.lang] && I18N[state.lang][k]) || I18N.en[k] || k; }
  function renderTheme() {
    root.setAttribute("data-theme", state.theme);
    var b = document.getElementById("theme-btn");
    b.setAttribute("aria-label", t(state.theme === "dark" ? "theme.toLight" : "theme.toDark"));
    b.title = b.getAttribute("aria-label");
  }
  function apply(lang) {
    state.lang = I18N[lang] ? lang : "en";
    root.lang = state.lang;
    root.dir = state.lang === "ar" ? "rtl" : "ltr";
    document.querySelectorAll("[data-i18n]").forEach(function (el) { el.textContent = t(el.getAttribute("data-i18n")); });
    document.querySelectorAll("[data-i18n-attr]").forEach(function (el) {
      el.getAttribute("data-i18n-attr").split(";").forEach(function (pair) {
        var p = pair.split(":"); if (p.length === 2) el.setAttribute(p[0].trim(), t(p[1].trim()));
      });
    });
    document.querySelectorAll(".seg [data-lang]").forEach(function (b) { b.setAttribute("aria-pressed", String(b.dataset.lang === state.lang)); });
    document.title = t(PAGE + ".title");
    var md = document.querySelector('meta[name="description"]'); if (md) md.setAttribute("content", t(PAGE + ".desc"));
    renderTheme();
    spy();
  }
  document.querySelectorAll(".seg [data-lang]").forEach(function (b) {
    b.addEventListener("click", function () {
      apply(b.dataset.lang);
      try { localStorage.setItem("kashif-lang", state.lang); } catch (e) {}
      try { var u = new URL(location.href); u.searchParams.set("lang", state.lang); history.replaceState(null, "", u.pathname + u.search + u.hash); } catch (e) {}
    });
  });
  document.getElementById("theme-btn").addEventListener("click", function () {
    state.theme = state.theme === "dark" ? "light" : "dark"; themeStored = true;
    try { localStorage.setItem("kashif-theme", state.theme); } catch (e) {}
    renderTheme();
  });
  if (window.matchMedia) {
    var mq = matchMedia("(prefers-color-scheme: light)");
    var onMq = function () { if (!themeStored) { state.theme = mq.matches ? "light" : "dark"; renderTheme(); } };
    if (mq.addEventListener) mq.addEventListener("change", onMq); else if (mq.addListener) mq.addListener(onMq);
  }
  var menuBtn = document.getElementById("menu-btn"), links = document.getElementById("nav-links");
  menuBtn.addEventListener("click", function () {
    var open = !links.classList.contains("open");
    links.classList.toggle("open", open); menuBtn.setAttribute("aria-expanded", String(open));
  });
  document.addEventListener("keydown", function (e) { if (e.key === "Escape" && links.classList.contains("open")) { links.classList.remove("open"); menuBtn.setAttribute("aria-expanded", "false"); menuBtn.focus(); } });

  /* the README has an English and an Arabic half: a link into the hidden half switches language */
  function reveal(hash) {
    if (!hash || hash.length < 2) return;
    var id; try { id = decodeURIComponent(hash.slice(1)); } catch (e) { id = hash.slice(1); }
    var el = document.getElementById(id); if (!el) return;
    var half = el.closest(".half.sw");
    if (half && half.getAttribute("lang") !== state.lang) { apply(half.getAttribute("lang")); el.scrollIntoView(); }
  }
  document.addEventListener("click", function (e) {
    var a = e.target.closest && e.target.closest('a[href^="#"]');
    if (!a) return;
    var h = a.getAttribute("href"), id; try { id = decodeURIComponent(h.slice(1)); } catch (x) { id = h.slice(1); }
    var el = document.getElementById(id), half = el && el.closest(".half.sw");
    if (half && half.getAttribute("lang") !== state.lang) { e.preventDefault(); apply(half.getAttribute("lang")); history.pushState(null, "", h); el.scrollIntoView(); }
  });

  /* table of contents: collapsed on small screens, highlights the current section */
  var toc = document.querySelector(".toc");
  if (toc && window.matchMedia && matchMedia("(max-width: 900px)").matches) toc.open = false;
  var spyLinks = [];
  function spy() {
    spyLinks = Array.prototype.slice.call(document.querySelectorAll(".toc a")).filter(function (a) { return a.offsetParent !== null; });
    onScroll();
  }
  function onScroll() {
    var cur = null;
    for (var i = 0; i < spyLinks.length; i++) {
      var id; try { id = decodeURIComponent(spyLinks[i].getAttribute("href").slice(1)); } catch (e) { continue; }
      var h = document.getElementById(id);
      if (h && h.getBoundingClientRect().top < 120) cur = spyLinks[i];
    }
    spyLinks.forEach(function (a) { a.classList.toggle("on", a === cur); if (a === cur) a.setAttribute("aria-current", "location"); else a.removeAttribute("aria-current"); });
  }
  window.addEventListener("scroll", onScroll, { passive: true });
  apply(state.lang);
  if (location.hash) reveal(location.hash);
})();"""


def page_html(*, page: str, version: str, body: str, toc: list[tuple[str, list[tuple[int, str, str]], bool]],
              source: str, alternates: bool) -> str:
    en = UI["en"]
    canonical = SITE + page
    head_alt = ""
    if alternates:
        head_alt = (f'<link rel="alternate" hreflang="en" href="{canonical}">\n'
                    f'<link rel="alternate" hreflang="ar" href="{canonical}?lang=ar">\n'
                    f'<link rel="alternate" hreflang="x-default" href="{canonical}">\n')
    current = ' aria-current="page"'
    nav = "\n".join(
        f'        <a href="{href}" data-i18n="{key}"{current if href == page else ""}>{esc(en[key])}</a>'
        for href, key in NAV)
    toc_html = ""
    if toc and any(entries for _, entries, _ in toc):
        parts = []
        for lang, entries, switch in toc:
            if switch:  # one half of the README: the list follows that half's direction
                lis = "".join(f'<li class="l{lv}"><a href="#{esc(urllib.parse.quote(hid))}">{esc(text)}</a></li>'
                              for lv, hid, text in entries)
                lang_attr = f' lang="{lang}" dir="{"rtl" if lang == "ar" else "ltr"}"'
            else:  # the list follows the page's direction; each entry keeps its own
                bdi = f'<bdi lang="{lang}">' if lang else "<bdi>"
                lis = "".join(f'<li class="l{lv}"><a href="#{esc(urllib.parse.quote(hid))}">{bdi}{esc(text)}</bdi></a></li>'
                              for lv, hid, text in entries)
                lang_attr = ""
            cls = "tochalf sw" if switch else "tochalf"
            parts.append(f'<ol class="{cls}"{lang_attr}>{lis}</ol>')
        toc_html = (f'<details class="toc" open><summary data-i18n="toc">{esc(en["toc"])}</summary>'
                    f'<nav aria-labelledby="toc-h"><span class="sr" id="toc-h" data-i18n="toc">{esc(en["toc"])}</span>'
                    + "".join(parts) + "</nav></details>")
    js = PAGE_JS.replace("__I18N__", json.dumps(UI, ensure_ascii=False)).replace("__PAGE__", page[:-5])
    title = en[page[:-5] + ".title"]
    desc = en[page[:-5] + ".desc"]
    fonts = ("https://fonts.googleapis.com/css2?family=IBM+Plex+Sans+Arabic:wght@400;500;600;700"
             "&family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap")
    return f"""<!doctype html>
<html lang="en" dir="ltr" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)}</title>
<meta name="description" content="{esc(desc)}">
<meta name="generator" content="site/build_docs.py from {esc(source)}">
<script>
{EARLY_JS}
</script>
<meta name="theme-color" content="#070b14" media="(prefers-color-scheme: dark)">
<meta name="theme-color" content="#ffffff" media="(prefers-color-scheme: light)">
<meta name="color-scheme" content="dark light">
<link rel="canonical" href="{canonical}">
{head_alt}<link rel="icon" type="image/svg+xml" href="favicon.svg">
<link rel="apple-touch-icon" href="logo.svg">
<link rel="manifest" href="manifest.webmanifest">
<meta property="og:type" content="article">
<meta property="og:site_name" content="Kashif">
<meta property="og:title" content="{esc(title)}">
<meta property="og:description" content="{esc(desc)}">
<meta property="og:url" content="{canonical}">
<meta property="og:image" content="{SITE}img/og-en.png">
<meta name="twitter:card" content="summary_large_image">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="preload" as="style" href="{fonts}" onload="this.onload=null;this.rel='stylesheet'">
<noscript><link rel="stylesheet" href="{fonts}"></noscript>
<style>
{landing_tokens()}
{CSS.strip()}
</style>
</head>
<body>
<a class="skip" href="#main" data-i18n="skip">{esc(en["skip"])}</a>
<svg width="0" height="0" style="position:absolute" aria-hidden="true">
{landing_symbols()}
</svg>
<header class="top">
  <div class="wrap nav">
    <a class="brand" href="index.html"><img src="logo.svg" alt="" width="30" height="30"><span data-i18n="brand">{esc(en["brand"])}</span><small>vulnscan</small></a>
    <nav aria-label="{esc(en["nav.label"])}" data-i18n-attr="aria-label:nav.label">
      <div class="links" id="nav-links">
        <a href="index.html" data-i18n="nav.home">{esc(en["nav.home"])}</a>
{nav}
      </div>
    </nav>
    <div class="tools">
      <div class="seg" role="group" aria-label="{esc(en["lang.label"])}" data-i18n-attr="aria-label:lang.label">
        <button type="button" data-lang="en" aria-pressed="true" lang="en">EN</button>
        <button type="button" data-lang="ar" aria-pressed="false" lang="ar" class="ar" aria-label="العربية">ع</button>
      </div>
      <button type="button" class="iconbtn" id="theme-btn" aria-label="{esc(en["theme.toLight"])}"><svg class="ic i-sun" aria-hidden="true"><use href="#i-sun"/></svg><svg class="ic i-moon" aria-hidden="true"><use href="#i-moon"/></svg></button>
      <a class="btn" href="{REPO_URL}"><svg class="ic" aria-hidden="true"><use href="#i-gh"/></svg><span class="gh-txt">GitHub</span><span class="sr" data-i18n="gh.sr">{esc(en["gh.sr"])}</span></a>
      <button type="button" class="iconbtn menu-btn" id="menu-btn" aria-expanded="false" aria-controls="nav-links" aria-label="{esc(en["nav.menu"])}" data-i18n-attr="aria-label:nav.menu"><svg class="ic" aria-hidden="true"><use href="#i-menu"/></svg></button>
    </div>
  </div>
</header>
<div class="wrap page{"" if toc_html else " solo"}">
{toc_html}
<main id="main" tabindex="-1" class="prose">
<div class="meta"><a class="pill" href="changelog.html"><span class="ver">v{esc(version)}</span><span data-i18n="nav.changelog">{esc(en["nav.changelog"])}</span></a><span><span data-i18n="foot.src">{esc(en["foot.src"])}</span> <code>{esc(source)}</code></span></div>
{body}
</main>
</div>
<footer>
  <div class="wrap foot">
    <span><span data-i18n="foot.ver">{esc(en["foot.ver"])}</span> <a href="changelog.html">v{esc(version)}</a> · <a href="license.html" data-i18n="nav.license">{esc(en["nav.license"])}</a> · <span data-i18n="foot.legal">{esc(en["foot.legal"])}</span></span>
    <nav aria-label="{esc(en["nav.label"])}" data-i18n-attr="aria-label:nav.label"><a href="index.html" data-i18n="nav.home">{esc(en["nav.home"])}</a><a href="docs.html" data-i18n="nav.docs">{esc(en["nav.docs"])}</a><a href="security.html" data-i18n="nav.security">{esc(en["nav.security"])}</a><a href="#main" data-i18n="top">{esc(en["top"])}</a></nav>
  </div>
</footer>
<script>
{js}
</script>
</body>
</html>
"""


# --------------------------------------------------------------------------- documents


def render_markdown(text: str, ctx: Ctx) -> str:
    return blocks(text.replace("\r\n", "\n").expandtabs(4).split("\n"), ctx)


def _check_forced(ctx: Ctx) -> None:
    missing = set(ctx.forced_ids) - ctx.used_forced
    if missing:
        raise SystemExit(f"build_docs: {ctx.page}: heading(s) {sorted(missing)} not found; "
                         "update HEADING_IDS and the links that use them (site/index.html)")


def build_readme(out: pathlib.Path, version: str) -> str:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    resolver, slugs = Resolver(out, "README.md"), Slugs()
    m = re.search(r'^<a id="arabic"></a>[ \t]*$', text, re.M)
    halves = [("en", text[:m.start()]), ("ar", text[m.start():])] if m else [("", text)]
    body, toc = [], []
    for lang, part in halves:
        ctx = Ctx(resolver, slugs, rtl=(lang == "ar"), page="docs.html")
        inner = render_markdown(part, ctx)
        if lang:
            body.append(f'<div class="half sw" lang="{lang}" dir="{"rtl" if lang == "ar" else "ltr"}">{inner}</div>')
        else:
            body.append(inner)
        toc.append((lang, ctx.toc, bool(lang)))
    return page_html(page="docs.html", version=version, body="\n".join(body), toc=toc,
                     source="README.md", alternates=True)


def build_arabic_doc(out: pathlib.Path, version: str, src: str, page: str) -> str:
    text = (ROOT / src).read_text(encoding="utf-8")
    ctx = Ctx(Resolver(out, src), Slugs(), rtl=True, page=page)
    inner = render_markdown(text, ctx)
    _check_forced(ctx)
    body = f'<div class="half" lang="ar" dir="rtl">{inner}</div>'
    return page_html(page=page, version=version, body=body, toc=[("ar", ctx.toc, False)], source=src, alternates=False)


def build_license(version: str) -> str:
    text = (ROOT / "LICENSE").read_text(encoding="utf-8").replace("\r\n", "\n").strip("\n")
    first, _, rest = text.partition("\n")
    body = (f'<div lang="en" dir="ltr"><h1 id="license">{esc(first.strip())}</h1>'
            f'<div class="lic">{esc(rest.strip())}</div></div>')
    return page_html(page="license.html", version=version, body=body, toc=[], source="LICENSE", alternates=False)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default=str(HERE), help="output directory (default: site/)")
    ap.add_argument("--version", help="version to stamp (default: vulnscan/__init__.py)")
    args = ap.parse_args(argv)
    version = (args.version or read_version()).strip().lstrip("vV")
    if not re.fullmatch(r"[0-9][0-9A-Za-z.+-]*", version):
        raise SystemExit(f"build_docs: refusing suspicious version {version!r}")
    out = pathlib.Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    pages = {
        "docs.html": build_readme(out, version),
        "changelog.html": build_arabic_doc(out, version, "CHANGELOG.md", "changelog.html"),
        "security.html": build_arabic_doc(out, version, "SECURITY.md", "security.html"),
        "license.html": build_license(version),
        "privacy.html": build_arabic_doc(out, version, "PRIVACY.md", "privacy.html"),
    }
    for name, content in pages.items():
        # the only github.com link these pages may carry is the header's "GitHub" button
        stray = [u for u in re.findall(r'href="(https?://[^"]*github\.com[^"]*)"', content) if u != REPO_URL]
        if stray or content.count(f'href="{REPO_URL}"') != 1:
            raise SystemExit(f"build_docs: {name}: unexpected GitHub link(s): {stray}")
        (out / name).write_text(content, encoding="utf-8")
        print(f"build_docs: wrote {out / name} ({len(content):,} bytes)")
    _check_landing_anchors(pages)
    return 0


def _check_landing_anchors(pages: dict[str, str]) -> None:
    """Fail the build when index.html links (in markup or in its i18n strings) to a heading
    of a generated page that no longer exists, e.g. after a README heading was renamed."""
    index = HERE / "index.html"
    if not index.is_file():
        return
    text = index.read_text(encoding="utf-8")
    names = "|".join(re.escape(n) for n in pages)
    missing = []
    for name, frag in set(re.findall(rf'(?<![\w/.-])({names})(?:\?[^"#\s]*)?#([^"\s<>]+)', text)):
        anchor = urllib.parse.unquote(frag)
        if f'id="{esc(anchor)}"' not in pages[name]:
            missing.append(f"{name}#{anchor}")
    if missing:
        raise SystemExit(f"build_docs: index.html links to missing heading(s): {sorted(missing)}")


if __name__ == "__main__":
    sys.exit(main())
