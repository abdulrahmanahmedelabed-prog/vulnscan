"""Structured Field Values for HTTP (RFC 8941), parsing only (WP0; used by Permissions-Policy, COOP/COEP report-to,
Integrity-Policy, Reporting-Endpoints, …).

``parse_item``, ``parse_list`` and ``parse_dictionary`` follow the RFC 8941 §4.2 algorithms exactly and raise
:class:`SFVError` on any failure (the caller then knows a browser ignores the whole field). Several field lines of
one header are combined with ``", "`` before parsing, as RFC 9110 and RFC 8941 §4.2 require (pass a list).

Bare item types: ``int``, ``float`` (Decimal), ``str`` (String), :class:`Token`, ``bytes`` (Byte Sequence), ``bool``.
With ``rfc9651=True`` the RFC 9651 additions are accepted too: :class:`Date` (``@1659578233``) and
:class:`DisplayString` (``%"…"``); browsers implementing RFC 8941 reject them, so the default is off.

Results: an Item is ``Item(value, params)``; an Inner List is ``InnerList(items, params)``; ``params`` is a ``dict``
(insertion-ordered, a repeated key keeps its first position and takes the last value); a List is a ``list`` of
members; a Dictionary is a ``dict`` key → member.
"""

from __future__ import annotations

import base64
import binascii
import string
from typing import NamedTuple, Union


class SFVError(ValueError):
    """The field value is not a valid structured field (browsers ignore the whole field)."""


class Token(str):
    """An sf-token (e.g. ``self``, ``*``, ``same-origin``), distinct from an sf-string."""

    def __repr__(self) -> str:
        return f"Token({str(self)!r})"


class Date(int):
    """RFC 9651 Date (seconds since the epoch)."""


class DisplayString(str):
    """RFC 9651 Display String."""


BareItem = Union[int, float, str, bytes, bool, Token, Date, DisplayString]


class Item(NamedTuple):
    value: BareItem
    params: dict


class InnerList(NamedTuple):
    items: list
    params: dict


Member = Union[Item, InnerList]

_DIGITS = frozenset(string.digits)
_LCALPHA = frozenset(string.ascii_lowercase)
_ALPHA = frozenset(string.ascii_letters)
_TCHAR = frozenset("!#$%&'*+-.^_`|~" + string.digits + string.ascii_letters)
_KEY_CHARS = _LCALPHA | _DIGITS | frozenset("_-.*")
_B64 = frozenset(string.ascii_letters + string.digits + "+/=")


class _Parser:
    def __init__(self, text: str, rfc9651: bool):
        if not isinstance(text, str):
            raise SFVError("field value must be text")
        try:
            text.encode("ascii")
        except UnicodeEncodeError:
            raise SFVError("non-ASCII character in a structured field") from None
        self.s = text
        self.i = 0
        self.rfc9651 = rfc9651

    # -- low level -----------------------------------------------------------------------------------------
    def peek(self) -> str:
        return self.s[self.i] if self.i < len(self.s) else ""

    def eof(self) -> bool:
        return self.i >= len(self.s)

    def skip_sp(self) -> None:
        while self.peek() == " ":
            self.i += 1

    def skip_ows(self) -> None:
        while self.peek() in (" ", "\t") and self.peek():
            self.i += 1

    def fail(self, why: str):
        raise SFVError(f"{why} at position {self.i}")

    # -- RFC 8941 §4.2 -------------------------------------------------------------------------------------
    def top(self, kind: str):
        self.skip_sp()
        if kind == "list":
            out = self.list_()
        elif kind == "dictionary":
            out = self.dictionary()
        else:
            out = self.item()
        self.skip_sp()
        if not self.eof():
            self.fail("unexpected trailing characters")
        return out

    def list_(self) -> list:
        members: list = []
        while not self.eof():
            members.append(self.item_or_inner_list())
            self.skip_ows()
            if self.eof():
                return members
            if self.peek() != ",":
                self.fail("expected ','")
            self.i += 1
            self.skip_ows()
            if self.eof():
                self.fail("trailing comma")
        return members

    def dictionary(self) -> dict:
        out: dict = {}
        while not self.eof():
            key = self.key()
            if self.peek() == "=":
                self.i += 1
                member = self.item_or_inner_list()
            else:
                member = Item(True, self.parameters())
            out[key] = member
            self.skip_ows()
            if self.eof():
                return out
            if self.peek() != ",":
                self.fail("expected ','")
            self.i += 1
            self.skip_ows()
            if self.eof():
                self.fail("trailing comma")
        return out

    def item_or_inner_list(self) -> Member:
        if self.peek() == "(":
            return self.inner_list()
        return self.item()

    def inner_list(self) -> InnerList:
        self.i += 1   # "("
        items: list = []
        while not self.eof():
            self.skip_sp()
            if self.peek() == ")":
                self.i += 1
                return InnerList(items, self.parameters())
            items.append(self.item())
            if self.peek() not in (" ", ")"):
                self.fail("expected ' ' or ')' in inner list")
        self.fail("unterminated inner list")

    def item(self) -> Item:
        value = self.bare_item()
        return Item(value, self.parameters())

    def bare_item(self) -> BareItem:
        c = self.peek()
        if c == "-" or c in _DIGITS:
            return self.number()
        if c == '"':
            return self.string()
        if c == "*" or c in _ALPHA:
            return self.token()
        if c == ":":
            return self.byte_sequence()
        if c == "?":
            return self.boolean()
        if self.rfc9651 and c == "@":
            self.i += 1
            n = self.number()
            if not isinstance(n, int):
                self.fail("date must be an integer")
            return Date(n)
        if self.rfc9651 and c == "%":
            return self.display_string()
        self.fail("unrecognised bare item")

    def parameters(self) -> dict:
        params: dict = {}
        while self.peek() == ";":
            self.i += 1
            self.skip_sp()
            key = self.key()
            value: BareItem = True
            if self.peek() == "=":
                self.i += 1
                value = self.bare_item()
            params[key] = value
        return params

    def key(self) -> str:
        c = self.peek()
        if not (c in _LCALPHA or c == "*"):
            self.fail("key must start with a lower-case letter or '*'")
        start = self.i
        while not self.eof() and self.peek() in _KEY_CHARS:
            self.i += 1
        return self.s[start:self.i]

    def number(self):
        sign = 1
        if self.peek() == "-":
            sign = -1
            self.i += 1
        if self.peek() not in _DIGITS or not self.peek():
            self.fail("expected a digit")
        start = self.i
        is_decimal = False
        while not self.eof():
            c = self.peek()
            if c in _DIGITS:
                self.i += 1
            elif c == "." and not is_decimal:
                if self.i - start > 12:
                    self.fail("decimal with more than 12 integer digits")
                is_decimal = True
                self.i += 1
            else:
                break
            if not is_decimal and self.i - start > 15:
                self.fail("integer with more than 15 digits")
            if is_decimal and self.i - start > 16:
                self.fail("decimal too long")
        num = self.s[start:self.i]
        if not is_decimal:
            return sign * int(num)
        if num.endswith("."):
            self.fail("decimal ends with '.'")
        if len(num.split(".", 1)[1]) > 3:
            self.fail("decimal with more than 3 fractional digits")
        return sign * float(num)

    def string(self) -> str:
        self.i += 1   # opening quote
        out = []
        while not self.eof():
            c = self.s[self.i]
            self.i += 1
            if c == "\\":
                if self.eof():
                    self.fail("backslash at end of string")
                nxt = self.s[self.i]
                self.i += 1
                if nxt not in ('"', "\\"):
                    self.fail("invalid escape in string")
                out.append(nxt)
            elif c == '"':
                return "".join(out)
            elif not (0x20 <= ord(c) <= 0x7E):
                self.fail("control character in string")
            else:
                out.append(c)
        self.fail("unterminated string")

    def token(self) -> Token:
        start = self.i
        self.i += 1
        while not self.eof() and (self.peek() in _TCHAR or self.peek() in ":/"):
            self.i += 1
        return Token(self.s[start:self.i])

    def byte_sequence(self) -> bytes:
        self.i += 1   # ":"
        end = self.s.find(":", self.i)
        if end < 0:
            self.fail("unterminated byte sequence")
        chunk = self.s[self.i:end]
        self.i = end + 1
        if any(ch not in _B64 for ch in chunk):
            self.fail("invalid base64 character in byte sequence")
        try:
            # RFC 8941 §4.2.7: parsers SHOULD NOT fail when "=" padding is missing
            return base64.b64decode(chunk + "=" * (-len(chunk) % 4), validate=True)
        except (binascii.Error, ValueError):
            self.fail("invalid base64 in byte sequence")

    def boolean(self) -> bool:
        self.i += 1   # "?"
        c = self.peek()
        if c == "1":
            self.i += 1
            return True
        if c == "0":
            self.i += 1
            return False
        self.fail("boolean must be ?0 or ?1")

    def display_string(self) -> DisplayString:
        self.i += 1   # "%"
        if self.peek() != '"':
            self.fail("display string must start with %\"")
        self.i += 1
        buf = bytearray()
        while not self.eof():
            c = self.s[self.i]
            self.i += 1
            if c == "%":
                hexpart = self.s[self.i:self.i + 2]
                if len(hexpart) != 2 or any(h not in "0123456789abcdef" for h in hexpart):
                    self.fail("invalid percent escape in display string")
                buf.append(int(hexpart, 16))
                self.i += 2
            elif c == '"':
                try:
                    return DisplayString(buf.decode("utf-8"))
                except UnicodeDecodeError:
                    self.fail("display string is not UTF-8")
            elif not (0x20 <= ord(c) <= 0x7E):
                self.fail("control character in display string")
            else:
                buf.append(ord(c))
        self.fail("unterminated display string")


def _join(value: str | list[str] | tuple[str, ...]) -> str:
    if isinstance(value, (list, tuple)):
        return ", ".join(value)
    return value


def parse_item(value: str | list[str] | tuple[str, ...], *, rfc9651: bool = False) -> Item:
    """Parse an Item field (several field lines are joined with ``", "`` first, which then fails as it should)."""
    return _Parser(_join(value), rfc9651).top("item")


def parse_list(value: str | list[str] | tuple[str, ...], *, rfc9651: bool = False) -> list:
    """Parse a List field; an empty value is an empty list (RFC 8941 §3.1)."""
    return _Parser(_join(value), rfc9651).top("list")


def parse_dictionary(value: str | list[str] | tuple[str, ...], *, rfc9651: bool = False) -> dict:
    """Parse a Dictionary field; an empty value is an empty dictionary (RFC 8941 §3.2)."""
    return _Parser(_join(value), rfc9651).top("dictionary")


def try_parse(kind: str, value, **kw):
    """``(result, None)`` or ``(None, error_text)`` for ``kind`` in item | list | dictionary."""
    fn = {"item": parse_item, "list": parse_list, "dictionary": parse_dictionary}[kind]
    try:
        return fn(value, **kw), None
    except SFVError as e:
        return None, str(e)


__all__ = ["SFVError", "Token", "Date", "DisplayString", "Item", "InnerList", "parse_item", "parse_list",
           "parse_dictionary", "try_parse"]
