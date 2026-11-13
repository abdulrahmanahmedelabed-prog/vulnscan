"""RFC 9116 security.txt validator vectors (webscan/sectxt.py, WP11, spec §2.10 WEB900). Pure; no network."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from vulnscan.webscan import sectxt

NOW = datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc)
FUTURE = "2027-05-13T00:00:00Z"
URL = "https://example.test/.well-known/security.txt"
CT = "text/plain; charset=utf-8"
VALID = f"Contact: mailto:security@example.test\nExpires: {FUTURE}\n"


def check(body, **kw):
    kw.setdefault("url", URL)
    kw.setdefault("content_type", CT)
    kw.setdefault("now", NOW)
    return sectxt.validate(body, **kw)


def codes(st) -> list[str]:
    return [p.code for p in st.problems]


# ----------------------------------------------------------------------------------------------- valid files

def test_minimal_valid_file_has_no_problem():
    st = check(VALID)
    assert st.problems == [] and st.severity is None
    assert st.contacts == ["mailto:security@example.test"]
    assert st.expires == datetime(2027, 5, 13, tzinfo=timezone.utc)


def test_full_valid_file_with_every_registered_field():
    body = (
        "# Our security policy\n"
        "Contact: mailto:security@example.test\n"
        "Contact: tel:+1-201-555-0123\n"
        "Contact: https://example.test/security-contact\n"
        f"Expires: {FUTURE}\n"
        "Encryption: https://example.test/pgp-key.txt\n"
        "Encryption: openpgp4fpr:5f2de5521c63a801ab59ccb603d49de44b29100f\n"
        "Acknowledgments: https://example.test/hall-of-fame.html\n"
        "Preferred-Languages: en, ar, fr-CA\n"
        f"Canonical: {URL}\n"
        "Policy: https://example.test/disclosure-policy.html\n"
        "Hiring: https://example.test/jobs.html\n"
        "CSAF: https://example.test/.well-known/csaf/provider-metadata.json\n"
    )
    st = check(body)
    assert st.problems == [], [p.text() for p in st.problems]
    assert st.languages == ["en", "ar", "fr-CA"]
    assert len(st.contacts) == 3


def test_offset_and_fractional_seconds_are_rfc3339():
    assert sectxt.parse_rfc3339("2027-01-01T05:30:00+05:30") == datetime(2027, 1, 1, tzinfo=timezone.utc)
    assert sectxt.parse_rfc3339("2027-01-01t00:00:00.250z") == datetime(2027, 1, 1, 0, 0, 0, 250000, tzinfo=timezone.utc)
    for bad in ("2027-01-01", "2027-01-01 00:00:00Z", "Tue, 01 Jan 2027 00:00:00 GMT", "2027-13-01T00:00:00Z",
                "2027-01-01T00:00:00", "2027-01-01T00:00:00+24:00"):
        assert sectxt.parse_rfc3339(bad) is None, bad


def test_crlf_line_endings_are_accepted():
    assert check(VALID.replace("\n", "\r\n")).problems == []


def test_comments_and_trailing_whitespace_are_fine():
    assert check("# hi\n\n" + VALID.replace("\n", "  \n", 1)).problems == []


# ----------------------------------------------------------------------------------------------- required fields (low)

def test_missing_contact_is_low():
    st = check(f"Expires: {FUTURE}\n")
    assert codes(st) == ["no_contact"] and st.severity == "low"


def test_missing_expires_is_low():
    st = check("Contact: mailto:security@example.test\n")
    assert codes(st) == ["no_expires"] and st.severity == "low"


def test_invalid_expires_is_low():
    st = check("Contact: mailto:security@example.test\nExpires: next year\n")
    assert codes(st) == ["invalid_expires"] and st.severity == "low"
    assert "next year" in st.problems[0].text("en") and "next year" in st.problems[0].text("ar")


def test_expired_is_low_with_arabic_day_count():
    past = (NOW - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    st = check(f"Contact: mailto:security@example.test\nExpires: {past}\n")
    assert codes(st) == ["expired"] and st.severity == "low"
    p = st.problems[0]
    assert "30 days ago" in p.text("en")
    assert "30 يومًا" in p.text("ar")
    assert p.line == 2


def test_expired_one_and_two_days_use_singular_and_dual():
    for days, en, ar in ((1, "1 day ago", "يوم واحد"), (2, "2 days ago", "يومين"), (5, "5 days ago", "5 أيام")):
        past = (NOW - timedelta(days=days, hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        p = check(f"Contact: mailto:a@example.test\nExpires: {past}\n").problems[0]
        assert en in p.text("en") and ar in p.text("ar"), (days, p.text("ar"))


def test_more_than_a_year_ahead_is_info():
    far = (NOW + timedelta(days=500)).strftime("%Y-%m-%dT%H:%M:%SZ")
    st = check(f"Contact: mailto:security@example.test\nExpires: {far}\n")
    assert codes(st) == ["long_expiry"] and st.severity == "info"


def test_multiple_expires_is_reported():
    st = check(VALID + "Expires: 2027-06-01T00:00:00Z\n")
    assert "multiple_expires" in codes(st)


def test_served_over_http_only_is_low():
    st = check(VALID, url="http://example.test/.well-known/security.txt")
    assert codes(st) == ["http_only"] and st.severity == "low"


# ----------------------------------------------------------------------------------------------- contact URIs

@pytest.mark.parametrize("value, ok", [
    ("mailto:security@example.test", True),
    ("mailto:security%2Bbugs@example.test?subject=Report", True),
    ("tel:+1-201-555-0123", True),
    ("https://example.test/contact", True),
    ("security@example.test", False),           # an e-mail address is not a URI
    ("mailto:not-an-address", False),
    ("tel:call-us", False),
    ("https:///nohost", False),
    ("just text", False),
])
def test_contact_values(value, ok):
    st = check(f"Contact: {value}\nExpires: {FUTURE}\n")
    if ok:
        assert st.problems == [], codes(st)
    else:
        assert sorted(codes(st)) == ["contact_invalid", "no_contact"]


def test_http_contact_is_info_and_still_a_contact():
    st = check(f"Contact: http://example.test/contact\nExpires: {FUTURE}\n")
    assert codes(st) == ["contact_http"] and st.severity == "info"


def test_http_web_uri_in_other_fields_is_info():
    st = check(VALID + "Policy: http://example.test/policy\n")
    assert codes(st) == ["uri_http"] and "Policy" in st.problems[0].text("en")


# ----------------------------------------------------------------------------------------------- other fields

def test_preferred_languages_more_than_once():
    st = check(VALID + "Preferred-Languages: en\nPreferred-Languages: ar\n")
    assert codes(st) == ["multiple_languages"]


def test_invalid_language_tag():
    st = check(VALID + "Preferred-Languages: en, english language\n")
    assert codes(st) == ["invalid_language"] and st.languages == ["en"]


def test_canonical_must_include_the_fetched_url():
    assert check(VALID + f"Canonical: {URL}\n").problems == []
    assert check(VALID + "Canonical: https://example.test:443/.well-known/security.txt\n").problems == []
    st = check(VALID + "Canonical: https://other.test/.well-known/security.txt\n")
    assert codes(st) == ["canonical_mismatch"]


def test_canonical_matches_the_requested_url_before_a_redirect():
    st = check(VALID + "Canonical: https://example.test/.well-known/security.txt\n",
               url="https://www.example.test/.well-known/security.txt", requested_url=URL)
    assert st.problems == []


def test_unknown_field_is_info_once_per_name():
    st = check(VALID + "Bounty: yes\nBounty: no\n")
    assert codes(st) == ["unknown_field"] and st.severity == "info"


def test_empty_value():
    st = check(VALID + "Policy: \n")
    assert "empty_value" in codes(st)


# ----------------------------------------------------------------------------------------------- syntax and encoding

def test_bom_and_missing_final_newline():
    st = check(b"\xef\xbb\xbf" + VALID.rstrip("\n").encode())
    assert sorted(codes(st)) == ["bom", "no_final_newline"]


def test_not_utf8():
    st = check(VALID.encode() + b"# caf\xe9\n")
    assert codes(st) == ["not_utf8"]


def test_line_without_space_after_colon_is_info_but_still_read():
    st = check(f"Contact:mailto:security@example.test\nExpires: {FUTURE}\n")
    assert codes(st) == ["bad_line"]           # not "no_contact": a lenient reader still finds the contact
    assert st.contacts == ["mailto:security@example.test"]


def test_free_text_line_is_info():
    st = check(VALID + "Please be nice to us\n")
    assert codes(st) == ["bad_line"]


def test_bad_lines_are_capped():
    st = check(VALID + "".join(f"junk line {i}\n" for i in range(20)))
    assert codes(st).count("bad_line") == 5


# ----------------------------------------------------------------------------------------------- media type

@pytest.mark.parametrize("ctype, want", [
    ("text/plain; charset=utf-8", []),
    ("text/plain;charset=\"UTF-8\"", []),
    ("text/plain", ["charset_missing"]),
    ("text/plain; charset=iso-8859-1", ["charset_wrong"]),
    ("text/html; charset=utf-8", ["content_type"]),
    ("", ["content_type"]),
])
def test_content_type(ctype, want):
    assert codes(check(VALID, content_type=ctype)) == want


def test_content_type_none_skips_media_checks():
    assert check(VALID, content_type=None).problems == []


def test_legacy_location_is_info():
    st = check(VALID, url="https://example.test/security.txt", legacy=True)
    assert codes(st) == ["legacy_location"] and st.severity == "info"


# ----------------------------------------------------------------------------------------------- OpenPGP structure

SIGNED = (
    "-----BEGIN PGP SIGNED MESSAGE-----\n"
    "Hash: SHA256\n"
    "\n"
    "Contact: mailto:security@example.test\n"
    f"Expires: {FUTURE}\n"
    "- -----not a header, dash-escaped\n"
    "-----BEGIN PGP SIGNATURE-----\n"
    "\n"
    "iHUEARYIAB0WIQTEST\n"
    "=abcd\n"
    "-----END PGP SIGNATURE-----\n"
)


def test_signed_file_structure_ok_and_not_verified():
    st = check(SIGNED)
    assert st.signed is True
    assert codes(st) == ["bad_line"]            # the dash-escaped line is free text inside the signed part
    assert st.contacts == ["mailto:security@example.test"] and st.expires is not None


def test_signed_without_signature_block():
    st = check(SIGNED.split("-----BEGIN PGP SIGNATURE-----")[0])
    assert "pgp_structure" in codes(st)
    assert any("BEGIN PGP SIGNATURE" in p.text("en") for p in st.problems)


def test_signed_without_end_line():
    st = check(SIGNED.replace("-----END PGP SIGNATURE-----\n", ""))
    assert "pgp_structure" in codes(st)


def test_signed_with_text_outside():
    st = check(SIGNED + "Contact: mailto:evil@example.test\n")
    assert "pgp_structure" in codes(st)
    assert st.contacts == ["mailto:security@example.test"]    # text outside the signed part is not read


def test_signed_without_blank_line_after_armor_headers():
    st = check(SIGNED.replace("Hash: SHA256\n\n", "Hash: SHA256\n"))
    assert "pgp_structure" in codes(st)


# ----------------------------------------------------------------------------------------------- order, notes, i18n

def test_low_problems_come_first_and_all_are_listed():
    st = check("Bounty: yes\nPreferred-Languages: en\n", content_type="text/plain")
    cs = codes(st)
    assert set(cs) == {"no_contact", "no_expires", "unknown_field", "charset_missing"}
    assert cs.index("no_contact") < cs.index("unknown_field")
    notes = st.notes()
    assert len(notes) == len(cs) and all(en and ar for en, ar in notes)


def test_every_problem_text_has_arabic_and_english():
    for code, (en, ar) in sectxt.STR.items():
        assert en and ar and en != ar, code
        assert any("؀" <= ch <= "ۿ" for ch in ar), code


def test_summary_is_json_safe():
    import json
    st = check(VALID + f"Canonical: {URL}\nPreferred-Languages: en\n")
    s = st.summary()
    json.dumps(s)
    assert s["expires"] == "2027-05-13T00:00:00Z" and s["problems"] == [] and "Contact" in s["fields"]


def test_looks_like_sectxt():
    assert sectxt.looks_like_sectxt(VALID)
    assert sectxt.looks_like_sectxt(SIGNED)
    assert sectxt.looks_like_sectxt("contact : mailto:x@example.test")
    assert not sectxt.looks_like_sectxt("<!doctype html><html><body>Contact us!</body></html>")
    assert not sectxt.looks_like_sectxt("OK\n")


def test_control_characters_never_reach_the_text():
    st = check("Contact: mailto:a@example.test\nExpires: \x1b[31mbad\x07\n")
    text = st.problems[0].text("en")
    assert "\x1b" not in text and "\x07" not in text


def test_i18n_catalog_covers_fixed_and_templated_texts():
    catalog, patterns = sectxt.i18n_catalog()
    assert catalog[sectxt.STR["no_contact"][1]] == sectxt.STR["no_contact"][0]
    assert patterns


def test_hostile_huge_file_is_fast():
    import time
    body = VALID + "x" * 200_000 + "\n" + "Contact: " + "a" * 100_000 + "\n"
    t = time.perf_counter()
    check(body)
    assert time.perf_counter() - t < 1.0


# ----------------------------------------------------------------------------------------------- adversarial review

def test_a_tab_after_the_colon_is_wsp_and_valid():
    # RFC 9116 §4: field-name ":" WSP value, and WSP is a space or a horizontal tab
    assert codes(check(f"Contact:\tmailto:security@example.test\nExpires:\t{FUTURE}\n")) == []


@pytest.mark.parametrize("value, problem", [("0001-01-01T00:00:00+01:00", "expired"),
                                            ("9999-12-31T23:59:59-23:59", "long_expiry")])
def test_expires_at_the_edge_of_the_calendar_never_crashes(value, problem):
    st = check(f"Contact: mailto:security@example.test\nExpires: {value}\n")
    assert problem in codes(st) and "invalid_expires" not in codes(st)
    for p in st.problems:
        assert p.text("en") and p.text("ar")
    assert sectxt.parse_rfc3339(value) is not None


def test_many_fraction_digits_are_truncated_not_rounded_into_an_error():
    dt = sectxt.parse_rfc3339("2027-05-13T00:00:00.99999999999999999999Z")
    assert dt is not None and dt.microsecond == 999999
    assert codes(check("Contact: mailto:security@example.test\nExpires: 2027-05-13T00:00:00.99999999999999999999Z\n")) \
        == []


def test_mailto_with_several_addresses_is_one_valid_contact():
    assert sectxt.uri_kind("mailto:security@example.test,cert@example.test") == "mailto"
    assert sectxt.uri_kind("mailto:security@example.test,not-an-address") == "invalid"
    assert codes(check(f"Contact: mailto:a@example.test,b@example.test\nExpires: {FUTURE}\n")) == []


def test_expired_date_is_an_iso_date_even_for_year_one():
    st = check("Contact: mailto:security@example.test\nExpires: 0001-01-01T00:00:00Z\n")
    (p,) = [p for p in st.problems if p.code == "expired"]
    assert "0001-01-01" in p.text("en") and "0001-01-01" in p.text("ar")


@pytest.mark.parametrize("body", [bytes(range(256)) * 50, "Contact: mailto:a@b.test\n".encode("utf-16"), b"\r" * 5000,
                                  b"-----BEGIN PGP SIGNED MESSAGE-----\n" * 3, b":" * 100_000, b"\x1b[31m" * 1000,
                                  ("Contact: " + "a" * 100_000 + "\n").encode() * 10])
def test_hostile_bodies_never_crash_and_stay_fast(body):
    import time
    t = time.perf_counter()
    st = check(body)
    assert time.perf_counter() - t < 2
    assert st.severity in ("low", "info")
    for p in st.problems:
        assert p.text("en") and p.text("ar")
        assert "\x1b" not in p.text("en")
