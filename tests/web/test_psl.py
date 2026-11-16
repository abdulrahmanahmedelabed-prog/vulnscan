"""Public Suffix List lookups (WP0): spec acceptance vectors, the private section, wildcards/exceptions, IDN and the
official test vectors' core (publicsuffix.org/list ``tests/test_psl.txt``)."""

from __future__ import annotations

import gzip
import hashlib
import json

import pytest

from vulnscan.webscan import data, psl


def test_spec_acceptance_vectors():
    assert psl.registrable_domain("example.co.uk") == "example.co.uk"
    assert psl.registrable_domain("a.b.github.io") == "b.github.io"      # private section on by default
    assert psl.registrable_domain("192.0.2.7") == "192.0.2.7"            # IP literals are themselves
    assert psl.registrable_domain("[2001:db8::1]") == "2001:db8::1"
    assert psl.registrable_domain("2001:DB8::1") == "2001:db8::1"


def test_private_section_separates_sites():
    assert not psl.same_site("a.github.io", "b.github.io")
    assert psl.same_site("x.b.github.io", "b.github.io")
    assert psl.registrable_domain("a.b.github.io", private=False) == "github.io"
    assert psl.is_public_suffix("github.io") and not psl.is_public_suffix("github.io", private=False)


@pytest.mark.parametrize("host,expected", [
    # a subset of the official checkPublicSuffix() vectors (domain → registrable domain, None = not registrable)
    ("com", None), ("example.com", "example.com"), ("b.example.com", "example.com"), ("a.b.example.com", "example.com"),
    ("uk.com", None), ("example.uk.com", "example.uk.com"), ("b.example.uk.com", "example.uk.com"),
    ("a.b.example.uk.com", "example.uk.com"), ("test.ac", "test.ac"),
    ("mm", None), ("c.mm", None), ("b.c.mm", "b.c.mm"), ("a.b.c.mm", "b.c.mm"),
    ("jp", None), ("test.jp", "test.jp"), ("www.test.jp", "test.jp"), ("ac.jp", None), ("test.ac.jp", "test.ac.jp"),
    ("www.test.ac.jp", "test.ac.jp"), ("kyoto.jp", None), ("test.kyoto.jp", "test.kyoto.jp"),
    ("ide.kyoto.jp", None), ("b.ide.kyoto.jp", "b.ide.kyoto.jp"), ("a.b.ide.kyoto.jp", "b.ide.kyoto.jp"),
    ("c.kobe.jp", None), ("b.c.kobe.jp", "b.c.kobe.jp"), ("a.b.c.kobe.jp", "b.c.kobe.jp"),
    ("city.kobe.jp", "city.kobe.jp"), ("www.city.kobe.jp", "city.kobe.jp"),
    ("ck", None), ("test.ck", None), ("b.test.ck", "b.test.ck"), ("a.b.test.ck", "b.test.ck"),
    ("www.ck", "www.ck"), ("www.www.ck", "www.ck"),
    ("us", None), ("test.us", "test.us"), ("www.test.us", "test.us"), ("ak.us", None), ("test.ak.us", "test.ak.us"),
    ("www.test.ak.us", "test.ak.us"), ("k12.ak.us", None), ("test.k12.ak.us", "test.k12.ak.us"),
    ("www.test.k12.ak.us", "test.k12.ak.us"),
    ("食狮.com.cn", "食狮.com.cn"), ("食狮.公司.cn", "食狮.公司.cn"), ("www.食狮.公司.cn", "食狮.公司.cn"),
    ("shishi.公司.cn", "shishi.公司.cn"), ("公司.cn", None), ("食狮.中国", "食狮.中国"), ("www.食狮.中国", "食狮.中国"),
    ("中国", None),
    ("xn--85x722f.com.cn", "xn--85x722f.com.cn"), ("xn--85x722f.xn--55qx5d.cn", "xn--85x722f.xn--55qx5d.cn"),
    ("xn--55qx5d.cn", None),
    ("example", None), ("example.example", "example.example"), ("b.example.example", "example.example"),
    ("COM", None), ("example.COM", "example.com"), ("WwW.example.COM", "example.com"), ("example.com.", "example.com"),
])
def test_official_vectors(host, expected):
    got = psl.registrable_domain(host)
    want = None if expected is None else psl.normalise(expected)
    assert got == want, host


def test_public_suffix_and_helpers():
    assert psl.public_suffix("www.example.co.uk") == "co.uk"
    assert psl.public_suffix("unknown-tld-host.zzzz") == "zzzz"        # implicit "*" rule
    assert psl.is_public_suffix("co.uk") and not psl.is_public_suffix("example.co.uk")
    assert not psl.is_public_suffix("127.0.0.1")
    assert psl.is_subdomain("www.example.com") and not psl.is_subdomain("example.com")
    assert psl.site("localhost") == "localhost"
    assert psl.same_site("WWW.Example.com.", "api.example.com")
    assert not psl.same_site("example.com", "")
    assert psl.registrable_domain("") is None and psl.public_suffix("") is None


def test_parse_list_sections_and_rule_kinds():
    rules = psl.parse_list("// ===BEGIN ICANN DOMAINS===\ncom\n*.ck\n!www.ck\n// ===END ICANN DOMAINS===\n"
                           "// ===BEGIN PRIVATE DOMAINS===\ngithub.io extra-token\n// ===END PRIVATE DOMAINS===\n")
    assert rules.normal == {"com": False, "github.io": True}
    assert rules.wildcard == {"ck": False} and rules.exception == {"www.ck": False}


def test_bundled_snapshot_is_the_unmodified_list():
    side = data.load_json("psl.dat.meta.json")
    assert data.validate_data("psl.dat.meta.json", side) == []
    path, origin = data.path_for("psl.dat.gz")
    assert origin == "bundled"
    raw_gz = path.read_bytes()
    assert hashlib.sha256(raw_gz).hexdigest() == side["sha256"]
    text = gzip.decompress(raw_gz).decode("utf-8")
    assert "===BEGIN PRIVATE DOMAINS===" in text and "\ngithub.io\n" in text
    assert side["meta"]["license"] == "MPL-2.0" and side["meta"]["source"].startswith("https://publicsuffix.org/")
    assert side["rules"] > 5000
    json.dumps(side)


def test_refresh_script_is_deterministic(tmp_path):
    import importlib.util
    import pathlib
    spec = importlib.util.spec_from_file_location(
        "psl_refresh", pathlib.Path(__file__).resolve().parents[2] / "tools" / "webdata" / "psl.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    raw = gzip.decompress(data.path_for("psl.dat.gz")[0].read_bytes())
    a = mod.write(raw, "2026-11-13", out_dir=tmp_path / "a")
    b = mod.write(raw, "2026-11-13", out_dir=tmp_path / "b")
    assert a == b and (tmp_path / "a" / "psl.dat.gz").read_bytes() == (tmp_path / "b" / "psl.dat.gz").read_bytes()
    with pytest.raises(SystemExit):
        mod.check(b"com\nnet\n")
