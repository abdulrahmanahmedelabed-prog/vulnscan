"""RFC 8941 structured fields (WP0): examples from the RFC, the httpwg test-suite rules, and the header shapes the
check modules parse (Permissions-Policy, COOP/COEP, Integrity-Policy, Reporting-Endpoints)."""

from __future__ import annotations

import pytest

from vulnscan.webscan.sfv import (Date, DisplayString, InnerList, Item, SFVError, Token, parse_dictionary, parse_item,
                                  parse_list, try_parse)


def test_rfc_examples_lists():
    assert parse_list("sugar, tea, rum") == [Item(Token("sugar"), {}), Item(Token("tea"), {}), Item(Token("rum"), {})]
    got = parse_list('("foo" "bar"), ("baz"), ("bat" "one"), ()')
    assert got[0] == InnerList([Item("foo", {}), Item("bar", {})], {})
    assert got[3] == InnerList([], {})
    got = parse_list('("foo"; a=1;b=2);lvl=5, ("bar" "baz");lvl=1')
    assert got[0].items[0].params == {"a": 1, "b": 2} and got[0].params == {"lvl": 5}
    got = parse_list("abc;a=1;b=2; cde_456, (ghi;jk=4 l);q=\"9\";r=w")
    assert got[0] == Item(Token("abc"), {"a": 1, "b": 2, "cde_456": True})
    assert got[1].params == {"q": "9", "r": Token("w")}
    assert parse_list("") == []


def test_rfc_examples_dictionaries():
    d = parse_dictionary('en="Applepie", da=:w4ZibGV0w6ZydGU=:')
    assert d == {"en": Item("Applepie", {}), "da": Item("Æbletærte".encode("utf-8"), {})}
    d = parse_dictionary("a=?0, b, c; foo=bar")
    assert d["a"].value is False and d["b"] == Item(True, {}) and d["c"] == Item(True, {"foo": Token("bar")})
    d = parse_dictionary("rating=1.5, feelings=(joy sadness)")
    assert d["rating"].value == 1.5 and [i.value for i in d["feelings"].items] == ["joy", "sadness"]
    assert parse_dictionary("a=(1 2), b=3, c=4;aa=bb, d=(5 6);valid")["d"].params == {"valid": True}
    assert parse_dictionary("") == {}


def test_items_numbers_strings_bytes_booleans():
    assert parse_item("5; foo=bar") == Item(5, {"foo": Token("bar")})
    assert parse_item("-999999999999999").value == -999999999999999
    assert parse_item("4.5").value == 4.5 and parse_item("-0.001").value == -0.001
    assert parse_item('"hello \\"world\\" \\\\"').value == 'hello "world" \\'
    assert parse_item(":cHJldGVuZCB0aGlzIGlzIGJpbmFyeSBjb250ZW50Lg==:").value == b"pretend this is binary content."
    assert parse_item(":cHJldGVuZA:").value == b"pretend"                       # missing padding is tolerated
    assert parse_item("?1").value is True
    assert parse_item("*foo/bar:baz").value == "*foo/bar:baz" and isinstance(parse_item("a").value, Token)
    assert parse_item("   sp-around   ").value == "sp-around"


@pytest.mark.parametrize("bad", [
    "1234567890123456",          # 16-digit integer
    "1234567890123.0",           # 13 integer digits in a decimal
    "1.2345",                    # 4 fractional digits
    "1.",                        # trailing dot
    '"unterminated',
    '"bad \\x escape"',
    '"ctl \x01"',
    ":not base64!:",
    "?2",
    "-",
    "a b",                       # trailing garbage
    "é",                         # non-ASCII
    "@1659578233",               # RFC 9651 date: rejected by RFC 8941 parsers
    '%"display"',
])
def test_invalid_items(bad):
    with pytest.raises(SFVError):
        parse_item(bad)


@pytest.mark.parametrize("bad", ["a=1,", "a=1, ,b=2", "A=1", "1a=1", "a=(1 2", "a=(1  2)x", "a=1;B=2", "a=1 b=2"])
def test_invalid_dictionaries(bad):
    with pytest.raises(SFVError):
        parse_dictionary(bad)


@pytest.mark.parametrize("bad", ["a,", "a, , b", "(a b", "(a b)c", "a b"])
def test_invalid_lists(bad):
    with pytest.raises(SFVError):
        parse_list(bad)


def test_duplicates_and_ows():
    d = parse_dictionary("a=1,\tb=2 ,  a=3")
    assert d == {"a": Item(3, {}), "b": Item(2, {})}         # last value wins
    assert parse_item("x;p=1;p=2").params == {"p": 2}
    assert parse_list("a,\tb") == [Item(Token("a"), {}), Item(Token("b"), {})]


def test_multiple_field_lines_are_combined():
    assert set(parse_dictionary(["camera=()", "geolocation=(self)"])) == {"camera", "geolocation"}
    with pytest.raises(SFVError):
        parse_item(["same-origin", "same-origin"])              # two COOP fields are not one Item


def test_permissions_policy_shapes():
    pp = parse_dictionary('camera=(), geolocation=(self "https://a.example"), fullscreen=*, microphone=self')
    assert pp["camera"] == InnerList([], {})
    assert [i.value for i in pp["geolocation"].items] == ["self", "https://a.example"]
    assert isinstance(pp["geolocation"].items[0].value, Token) and not isinstance(pp["geolocation"].items[1].value, Token)
    assert pp["fullscreen"].value == "*" and pp["microphone"].value == "self"
    assert parse_dictionary("camera=none")["camera"].value == "none"           # valid SF; WP3 decides its meaning
    for bad in ("camera 'none'", "camera=('self')", "camera=(self", "geolocation=self 'src'"):
        result, err = try_parse("dictionary", bad)
        assert result is None and err, bad


def test_coop_coep_integrity_policy_and_reporting_endpoints():
    assert parse_item('same-origin; report-to="coop"') == Item(Token("same-origin"), {"report-to": "coop"})
    assert parse_item("require-corp").value == "require-corp"
    ip = parse_dictionary("blocked-destinations=(script), endpoints=(integrity-endpoint)")
    assert [i.value for i in ip["blocked-destinations"].items] == ["script"]
    re_ = parse_dictionary('csp-endpoint="https://r.example/csp", default="/reports"')
    assert re_["csp-endpoint"].value == "https://r.example/csp"


def test_rfc9651_extensions_when_enabled():
    assert parse_item("@1659578233", rfc9651=True).value == Date(1659578233)
    v = parse_item('%"f%c3%bc%c3%bc"', rfc9651=True).value
    assert isinstance(v, DisplayString) and v == "füü"
    with pytest.raises(SFVError):
        parse_item('%"bad%zz"', rfc9651=True)


def test_try_parse():
    assert try_parse("item", "?0") == (Item(False, {}), None)
    res, err = try_parse("list", "a,")
    assert res is None and "trailing comma" in err
