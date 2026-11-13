"""robots.txt parser and matcher (RFC 9309), WP1."""

from __future__ import annotations

import pytest

from vulnscan.webscan import robots
from vulnscan.webscan.types import Response

# RFC 9309 §5.2 example file
RFC_EXAMPLE = """\
User-Agent: *
Disallow: *.gif$
Disallow: /example/
Allow: /publications/

User-Agent: foobot
Disallow:/
Allow:/example/page.html
Allow:/example/allowed.gif

User-Agent: barbot
User-Agent: bazbot
Disallow: /example/page.html

User-Agent: quxbot

EOF
"""


@pytest.mark.parametrize("agent, path, allowed", [
    ("foobot", "/example/page.html", True),
    ("foobot", "/example/allowed.gif", True),
    ("foobot", "/other", False),
    ("foobot", "/", False),
    ("barbot", "/example/page.html", False),
    ("bazbot", "/example/page.html", False),
    ("barbot", "/example/other.html", True),
    ("quxbot", "/example/page.html", True),         # a group without rules allows everything
    ("Kashif", "/picture.gif", False),              # falls back to *
    ("Kashif", "/picture.gif?x=1", True),           # $ anchors the end
    ("Kashif", "/example/a", False),
    ("Kashif", "/publications/x", True),
    ("Kashif", "/robots.txt", True),
])
def test_rfc9309_example(agent, path, allowed):
    r = robots.parse(RFC_EXAMPLE)
    assert r.allowed(path, agent) is allowed


@pytest.mark.parametrize("rules, path, allowed", [
    # RFC 9309 §2.2.2 / Google's longest-match examples
    ("Allow: /p\nDisallow: /", "/page", True),
    ("Allow: /folder\nDisallow: /folder", "/folder/page", True),          # tie → Allow
    ("Allow: /page\nDisallow: /*.htm", "/page.htm", False),               # longer pattern wins
    ("Allow: /page\nDisallow: /*.ph", "/page.php5", True),                # equal length (5) → Allow
    ("Allow: /$\nDisallow: /", "/", True),
    ("Allow: /$\nDisallow: /", "/page.htm", False),
    ("Disallow: /fish", "/fish", False),
    ("Disallow: /fish", "/fish.html", False),
    ("Disallow: /fish", "/fish/salmon.html", False),
    ("Disallow: /fish", "/fishheads", False),
    ("Disallow: /fish", "/Fish.asp", True),                               # paths are case-sensitive
    ("Disallow: /fish", "/catfish", True),
    ("Disallow: /fish*", "/fishheads/yummy.html", False),
    ("Disallow: /fish/", "/fish", True),
    ("Disallow: /fish/", "/fish/?id=anything", False),
    ("Disallow: /*.php", "/folder/filename.php?parameters", False),
    ("Disallow: /*.php$", "/filename.php?parameters", True),
    ("Disallow: /*.php$", "/filename.php", False),
    ("Disallow: /fish*.php", "/fishheads/catfish.php?parameters", False),
    ("Disallow: /fish*.php", "/Fish.PHP", True),
    ("Disallow:", "/anything", True),                                     # empty Disallow = allow
    ("Disallow: /", "/robots.txt", True),                                 # robots.txt is always allowed
    # percent-encoding normalisation
    ("Disallow: /foo/bar?baz=https://foo.bar", "/foo/bar?baz=https://foo.bar", False),
    ("Disallow: /foo/bar/ツ", "/foo/bar/%E3%83%84", False),
    ("Disallow: /foo/bar/%E3%83%84", "/foo/bar/ツ", False),
    ("Disallow: /foo/bar/%e3%83%84", "/foo/bar/%E3%83%84", False),
    ("Disallow: /%7Euser", "/~user/page", False),                         # unreserved %7E == ~
    ("Disallow: /a%2Fb", "/a/b", True),                                   # %2F is not the same as /
    ("Disallow: /path/file-with-a-%2A.html", "/path/file-with-a-*.html", True),
])
def test_matching_vectors(rules, path, allowed):
    r = robots.parse("User-agent: *\n" + rules + "\n")
    assert r.allowed(path) is allowed, (rules, path)


def test_specific_group_beats_wildcard_and_groups_merge():
    text = ("User-agent: *\nDisallow: /\n\nUser-agent: Kashif\nDisallow: /private\n\n"
            "User-agent: other\nDisallow: /x\n\nuser-agent: KASHIF/1.1\nDisallow: /tmp\n")
    r = robots.parse(text)
    assert r.allowed("/public") and not r.allowed("/private/a") and not r.allowed("/tmp/x")
    assert not r.allowed("/public", "SomeBot")


def test_product_token_and_full_url():
    r = robots.parse("User-agent: kashif\nDisallow: /admin\n")
    assert not r.allowed("https://example.test/admin/x?y=1", "Kashif/1.1.0 (+https://x)")
    assert r.allowed("https://example.test/", "Kashif")
    assert r.allowed("https://example.test", "Kashif")      # empty path → "/"


def test_crawl_delay_sitemap_comments_and_line_endings():
    text = ("﻿# comment\r\nSitemap: /sitemap.xml\r\nUser-agent: *\r\nCrawl-delay: 2.5 # slow\rDisallow: /a\n"
            "Crawl-delay: 9\nUser-agent: Kashif\nCrawl-delay: nonsense\n")
    r = robots.parse(text, "https://example.test/robots.txt")
    assert r.sitemaps == ["https://example.test/sitemap.xml"]
    assert r.crawl_delay("SomeBot") == 2.5
    assert r.crawl_delay("Kashif") is None            # the Kashif group has no valid Crawl-delay
    assert r.invalid_lines                            # "nonsense" recorded


def test_rules_before_any_user_agent_are_ignored_and_typos_are_accepted():
    r = robots.parse("Disallow: /\nuseragent: *\ndissallow: /x\nfoo: bar\nno colon here\n")
    assert r.allowed("/") and not r.allowed("/x/y")
    assert len(r.invalid_lines) == 2


def test_no_matching_group_allows_everything_and_disallowed_paths():
    r = robots.parse("User-agent: googlebot\nDisallow: /\nDisallow: /admin/\nAllow: /x\n")
    assert r.allowed("/anything")
    assert r.disallowed_paths() == ["/", "/admin/"]


def test_size_limit():
    big = b"User-agent: *\n" + b"Allow: /x\n" * 60000 + b"Disallow: /late\n"
    r = robots.parse(big)
    assert r.truncated and r.allowed("/late")


def _resp(status, body=b"", error=None, flags=frozenset()):
    return Response("https://example.test/robots.txt", status=status, body=body, error=error, flags=flags)


@pytest.mark.parametrize("status, error, allowed, state", [
    (200, None, False, "ok"),
    (404, None, True, "unavailable"),
    (410, None, True, "unavailable"),
    (401, None, True, "unavailable"),
    (429, None, False, "unreachable"),
    (500, None, False, "unreachable"),
    (503, None, False, "unreachable"),
    (None, "timed out", False, "unreachable"),
])
def test_availability_rules(status, error, allowed, state):
    r = robots.from_response(_resp(status, b"User-agent: *\nDisallow: /\n", error))
    assert r.status == state
    assert r.allowed("/page") is allowed
    assert r.allowed("/robots.txt") is (state != "unreachable")


def test_opaque_body_and_missing_response():
    assert robots.from_response(_resp(200, b"", flags=frozenset({"opaque-coding"}))).allowed("/x")
    assert robots.from_response(None).status == "not_fetched"
    assert robots.from_response(None).allowed("/x")


def test_to_dict_and_decision_rule():
    r = robots.parse("User-agent: *\nDisallow: /a\nAllow: /a/b\n")
    ok, rule = r.decision("/a/b/c")
    assert ok and rule.pattern == "/a/b" and rule.line == 3
    d = r.to_dict()
    assert d["groups"][0]["agents"] == ["*"] and len(d["groups"][0]["rules"]) == 2
