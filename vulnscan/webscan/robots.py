"""robots.txt parser and matcher (RFC 9309), WP1.

* Groups start with one or more ``user-agent`` lines; the rules that follow belong to every agent of the group. Groups
  for the same agent are merged (RFC 9309 §2.2.1). A rule line before any ``user-agent`` line is ignored.
* The crawler's product token is ``Kashif`` (case-insensitive). A group naming it wins over ``*``; with no matching
  group and no ``*`` group, everything is allowed.
* Matching (§2.2.2): ``*`` matches any sequence, a trailing ``$`` anchors the end; the longest matching pattern wins,
  and ``Allow`` wins a tie. Patterns and paths are compared after percent-encoding normalisation (non-ASCII → UTF-8
  %XX, hex upper-cased, unreserved characters decoded). ``/robots.txt`` itself is always allowed.
* ``Crawl-delay`` (non-standard, widely used) is read from the group that applies; ``Sitemap`` lines are global.
* Availability (§2.3.1): 2xx → parsed; 4xx → "unavailable" (allow everything); 5xx, network errors and HTTP 429 →
  "unreachable" (disallow everything for the crawl). RFC 9309 lists 429 among the 4xx codes; Kashif treats it as
  unreachable like Google does, which is the polite choice.
* At most 500 KiB is parsed (§2.5).

Only the crawl obeys robots.txt; the well-known files and the deep probe's fixed list are exempt (spec §4.3). Pure: no
network, no file system.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

PRODUCT_TOKEN = "Kashif"
MAX_BYTES = 500 * 1024
_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
# accepted spellings of the record keys (RFC 9309 §2.2: crawlers MAY interpret common typos)
_KEYS = {
    "user-agent": "user-agent", "useragent": "user-agent", "user agent": "user-agent", "user_agent": "user-agent",
    "allow": "allow",
    "disallow": "disallow", "dissallow": "disallow", "dissalow": "disallow", "disalow": "disallow", "diasllow": "disallow",
    "disallaw": "disallow",
    "crawl-delay": "crawl-delay", "crawldelay": "crawl-delay", "crawl delay": "crawl-delay",
    "sitemap": "sitemap", "site-map": "sitemap",
}
_TOKEN = re.compile(r"[a-z_\-]+")


def normalise_path(value: str) -> str:
    """Percent-encoding normal form used for both patterns and paths (RFC 9309 §2.2.2, RFC 3986 §6.2.2)."""
    out: list[str] = []
    i = 0
    n = len(value)
    while i < n:
        ch = value[i]
        if ch == "%" and _is_hex(value[i + 1:i + 3]):
            byte = int(value[i + 1:i + 3], 16)
            c = chr(byte)
            out.append(c if byte < 0x80 and c in _UNRESERVED else "%" + value[i + 1:i + 3].upper())
            i += 3
            continue
        if ord(ch) >= 0x80 or ch in " \t\"<>\\^`{|}" or ord(ch) < 0x20:
            out.append("".join(f"%{b:02X}" for b in ch.encode("utf-8", "surrogatepass")))
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def _is_hex(s: str) -> bool:
    return len(s) == 2 and all(c in "0123456789abcdefABCDEF" for c in s)


@dataclass
class Rule:
    allow: bool
    pattern: str                # as written (trimmed)
    line: int = 0
    _norm: str = field(default="", repr=False)
    _rx: Any = field(default=None, repr=False)

    def __post_init__(self) -> None:
        self._norm = normalise_path(self.pattern)
        self._rx = _compile(self._norm)

    @property
    def length(self) -> int:
        """Pattern length in octets of the normalised pattern (the 'most specific' measure)."""
        return len(self._norm.encode("utf-8"))

    def matches(self, norm_path: str) -> bool:
        return self._rx.match(norm_path) is not None


def _compile(pattern: str) -> "re.Pattern[str]":
    anchored = pattern.endswith("$")
    body = pattern[:-1] if anchored else pattern
    rx = ".*".join(re.escape(part) for part in body.split("*"))
    return re.compile(rx + (r"\Z" if anchored else ""), re.S)


@dataclass
class Group:
    agents: list[str] = field(default_factory=list)      # lower-cased product tokens ("*" for the wildcard)
    rules: list[Rule] = field(default_factory=list)
    crawl_delay: float | None = None
    line: int = 0


@dataclass
class Robots:
    """A parsed robots.txt. ``status``: ok | unavailable (allow all) | unreachable (disallow all) | not_fetched."""
    groups: list[Group] = field(default_factory=list)
    sitemaps: list[str] = field(default_factory=list)
    status: str = "ok"
    url: str = ""
    truncated: bool = False
    invalid_lines: list[int] = field(default_factory=list)
    _cache: dict = field(default_factory=dict, repr=False)

    # -- construction -----------------------------------------------------------------------------------------
    @classmethod
    def allow_all(cls, url: str = "", status: str = "unavailable") -> "Robots":
        return cls(status=status, url=url)

    @classmethod
    def disallow_all(cls, url: str = "") -> "Robots":
        return cls(status="unreachable", url=url)

    # -- lookups ---------------------------------------------------------------------------------------------
    def group_for(self, agent: str = PRODUCT_TOKEN) -> Group | None:
        """The merged group that applies to ``agent`` (its own groups, else ``*``), or None when none applies."""
        token = _product(agent)
        key = ("group", token)
        if key in self._cache:
            return self._cache[key]
        own = [g for g in self.groups if token in g.agents]
        chosen = own or [g for g in self.groups if "*" in g.agents]
        merged: Group | None = None
        if chosen:
            merged = Group(agents=sorted({a for g in chosen for a in g.agents}), line=chosen[0].line)
            for g in chosen:
                merged.rules.extend(g.rules)
                if g.crawl_delay is not None and merged.crawl_delay is None:
                    merged.crawl_delay = g.crawl_delay
        self._cache[key] = merged
        return merged

    def decision(self, url_or_path: str, agent: str = PRODUCT_TOKEN) -> tuple[bool, Rule | None]:
        """``(allowed, deciding rule)``; the rule is None when no rule matched or the file decides globally."""
        if self.status == "unreachable":
            return False, None
        if self.status in ("unavailable", "not_fetched"):
            return True, None
        path = _path_of(url_or_path)
        if path == "/robots.txt":
            return True, None
        group = self.group_for(agent)
        if group is None:
            return True, None
        norm = normalise_path(path)
        best: Rule | None = None
        for r in group.rules:
            if not r.pattern or not r.matches(norm):
                continue
            if best is None or r.length > best.length or (r.length == best.length and r.allow and not best.allow):
                best = r
        return (True if best is None else best.allow), best

    def allowed(self, url_or_path: str, agent: str = PRODUCT_TOKEN) -> bool:
        return self.decision(url_or_path, agent)[0]

    def crawl_delay(self, agent: str = PRODUCT_TOKEN) -> float | None:
        g = self.group_for(agent)
        return g.crawl_delay if g else None

    def disallowed_paths(self) -> list[str]:
        """Every non-empty Disallow pattern of every group, in file order, without duplicates (WEB061 input)."""
        seen: dict[str, None] = {}
        for g in self.groups:
            for r in g.rules:
                if not r.allow and r.pattern:
                    seen.setdefault(r.pattern, None)
        return list(seen)

    def to_dict(self) -> dict:
        return {"status": self.status, "url": self.url, "sitemaps": list(self.sitemaps), "truncated": self.truncated,
                "groups": [{"agents": g.agents, "crawl_delay": g.crawl_delay,
                            "rules": [{"allow": r.allow, "pattern": r.pattern, "line": r.line} for r in g.rules]}
                           for g in self.groups]}


def _product(agent: str) -> str:
    m = _TOKEN.match(agent.strip().lower())
    return m.group(0) if m else agent.strip().lower()


def _path_of(url_or_path: str) -> str:
    """Path + query of a URL (``/`` when empty), as the matcher compares it."""
    s = url_or_path.strip()
    if "://" in s or s.startswith("//"):
        p = urllib.parse.urlsplit(s)
        path = p.path or "/"
        return path + ("?" + p.query if p.query else "")
    s = s.split("#", 1)[0]
    return s if s.startswith("/") else "/" + s


def parse(text: str | bytes, url: str = "") -> Robots:
    """Parse a robots.txt body (bytes are decoded as UTF-8 with replacement; a BOM is skipped)."""
    truncated = False
    if isinstance(text, bytes):
        if len(text) > MAX_BYTES:
            text, truncated = text[:MAX_BYTES], True
        text = text.decode("utf-8", "replace")
    elif len(text.encode("utf-8", "replace")) > MAX_BYTES:
        text, truncated = text.encode("utf-8", "replace")[:MAX_BYTES].decode("utf-8", "ignore"), True
    text = text.lstrip("﻿")
    robots = Robots(url=url, truncated=truncated)
    current: Group | None = None
    in_agents = False            # the previous record was a user-agent line (consecutive lines share a group)
    for lineno, raw in enumerate(re.split(r"\r\n|\r|\n", text), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        key, sep, value = line.partition(":")
        if not sep:
            robots.invalid_lines.append(lineno)
            continue
        key = _KEYS.get(re.sub(r"\s+", " ", key.strip().lower()))
        value = value.strip()
        if key is None:
            robots.invalid_lines.append(lineno)
            continue
        if key == "sitemap":
            if value:
                robots.sitemaps.append(urllib.parse.urljoin(url, value) if url else value)
            continue
        if key == "user-agent":
            if not in_agents or current is None:
                current = Group(line=lineno)
                robots.groups.append(current)
            current.agents.append("*" if value.startswith("*") else _product(value))
            in_agents = True
            continue
        in_agents = False
        if current is None:          # a rule before any user-agent line belongs to no group
            continue
        if key in ("allow", "disallow"):
            if not value:            # "Disallow:" with an empty value allows everything; "Allow:" is a no-op
                continue
            current.rules.append(Rule(allow=(key == "allow"), pattern=value, line=lineno))
        elif key == "crawl-delay":
            try:
                delay = float(value)
            except ValueError:
                robots.invalid_lines.append(lineno)
                continue
            if delay >= 0 and delay == delay and current.crawl_delay is None:
                current.crawl_delay = delay
    return robots


def from_response(response: Any) -> Robots:
    """Robots for a fetched ``/robots.txt`` response (follows RFC 9309 §2.3.1 availability rules)."""
    if response is None:
        return Robots(status="not_fetched")
    url = getattr(response, "url", "") or ""
    status = getattr(response, "status", None)
    if status is None or getattr(response, "error", None):
        return Robots.disallow_all(url)
    if status == 429 or status >= 500:
        return Robots.disallow_all(url)
    if 400 <= status < 500:
        return Robots.allow_all(url)
    if 200 <= status < 300:
        flags = getattr(response, "flags", frozenset())
        if any(f.startswith("opaque-coding") for f in flags):
            return Robots.allow_all(url, status="unavailable")
        return parse(response.body or b"", url)
    # 3xx that the fetcher did not follow (or 1xx): treated as unavailable
    return Robots.allow_all(url)


__all__ = ["PRODUCT_TOKEN", "MAX_BYTES", "Rule", "Group", "Robots", "normalise_path", "parse", "from_response"]
