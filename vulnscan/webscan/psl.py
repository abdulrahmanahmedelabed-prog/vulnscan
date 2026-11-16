"""Public Suffix List lookups (spec §0.5 same-site, §4.4), from the bundled unmodified list ``data/web/psl.dat.gz``.

The algorithm is the one at publicsuffix.org/list: the prevailing rule is an exception rule if one matches, else the
matching rule with the most labels, else the implicit ``*``; an exception rule's public suffix drops its leftmost
label. Both the ICANN and the PRIVATE sections are used by default, so ``a.github.io`` and ``b.github.io`` are
different sites (as browsers treat them).

Host input is normalised: lower-case, brackets and a trailing dot removed, Unicode labels converted to their ASCII
(punycode) form. IP literals are their own site.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from . import data
from .types import normalise_host

PSL_FILE = "psl.dat.gz"


@dataclass(frozen=True)
class _Rules:
    normal: dict[str, bool]        # rule → is_private
    wildcard: dict[str, bool]      # "ck" for "*.ck"
    exception: dict[str, bool]     # "www.ck" for "!www.ck"


_RULES: _Rules | None = None


def _to_ascii(name: str) -> str:
    labels = []
    for label in name.split("."):
        if label.isascii():
            labels.append(label.lower())
            continue
        try:
            labels.append(label.encode("idna").decode("ascii"))
        except UnicodeError:
            labels.append(label.lower())
    return ".".join(labels)


def parse_list(text: str) -> _Rules:
    """Parse the PSL text format (comments ``//``, one rule per line, first whitespace-separated token)."""
    normal: dict[str, bool] = {}
    wildcard: dict[str, bool] = {}
    exception: dict[str, bool] = {}
    private = False
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith("//"):
            if "===BEGIN PRIVATE DOMAINS===" in s:
                private = True
            elif "===END PRIVATE DOMAINS===" in s:
                private = False
            continue
        rule = s.split()[0]
        if rule.startswith("!"):
            exception[_to_ascii(rule[1:])] = private
        elif rule.startswith("*."):
            wildcard[_to_ascii(rule[2:])] = private
        else:
            normal[_to_ascii(rule)] = private
    return _Rules(normal, wildcard, exception)


def _rules() -> _Rules:
    global _RULES
    if _RULES is None:
        _RULES = parse_list(data.load_bytes(PSL_FILE).decode("utf-8"))
    return _RULES


def reset() -> None:
    """Forget the loaded list (tests, or after a data update)."""
    global _RULES
    _RULES = None


def _ip(host: str) -> str | None:
    try:
        return str(ipaddress.ip_address(host.split("%", 1)[0]))
    except ValueError:
        return None


def normalise(host: str) -> str:
    h = normalise_host(host)
    if not h:
        return ""
    if _ip(h):
        return h
    return _to_ascii(h)


def public_suffix(host: str, *, private: bool = True) -> str | None:
    """The public suffix of ``host`` (``co.uk`` for ``a.example.co.uk``); ``None`` for an IP literal or empty host."""
    h = normalise(host)
    if not h or _ip(h):
        return None
    rules = _rules()
    labels = h.split(".")
    n = len(labels)

    def ok(table: dict[str, bool], key: str) -> bool:
        return key in table and (private or not table[key])

    for i in range(n):                       # exception rules prevail over everything
        cand = ".".join(labels[i:])
        if ok(rules.exception, cand):
            return ".".join(labels[i + 1:])
    for i in range(n):                       # longest normal or wildcard match
        cand = ".".join(labels[i:])
        if ok(rules.normal, cand):
            return cand
        if i + 1 < n and ok(rules.wildcard, ".".join(labels[i + 1:])):
            return cand
    return labels[-1]                        # implicit "*" rule


def registrable_domain(host: str, *, private: bool = True) -> str | None:
    """eTLD+1 of ``host`` (``example.co.uk``, ``b.github.io`` for ``a.b.github.io``); an IP literal is returned as is;
    ``None`` when ``host`` is itself a public suffix or empty."""
    h = normalise(host)
    if not h:
        return None
    if _ip(h):
        return _ip(h)
    ps = public_suffix(h, private=private)
    if ps is None or ps == h:
        return None
    ps_labels = ps.count(".") + 1 if ps else 0
    labels = h.split(".")
    if len(labels) <= ps_labels:
        return None
    return ".".join(labels[-(ps_labels + 1):])


def is_public_suffix(name: str, *, private: bool = True) -> bool:
    h = normalise(name)
    if not h or _ip(h):
        return False
    return public_suffix(h, private=private) == h


def site(host: str) -> str:
    """The site key for same-site comparisons: the registrable domain, else the normalised host itself."""
    return registrable_domain(host) or normalise(host)


def same_site(a: str, b: str) -> bool:
    """Same registrable domain (§0.5). Hosts, not URLs."""
    return bool(a) and bool(b) and site(a) == site(b)


def is_subdomain(host: str) -> bool:
    """True when ``host`` is below its registrable domain (``www.example.com``)."""
    reg = registrable_domain(host)
    return reg is not None and normalise(host) != reg


__all__ = ["public_suffix", "registrable_domain", "is_public_suffix", "site", "same_site", "is_subdomain", "normalise",
           "parse_list", "reset"]
