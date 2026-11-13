"""Content-Security-Policy (spec §2.2, WP4): parser, evaluator, Observatory slug and the C-CSP corpus group.

Vectors are ported from google/csp-evaluator's tests (Apache-2.0: parser_checks_test.ts, security_checks_test.ts,
strictcsp_checks_test.ts) and mdn-http-observatory 1.7.2 (MPL-2.0: test/csp.test.js, test/csp-parser.test.js),
mapped onto Kashif's rules. Everything is offline: corpus cases are rendered in-process without sockets.
"""

from __future__ import annotations

import importlib
import json
import pathlib
import re
import sys
import time
import urllib.parse

import pytest

from vulnscan.webscan import classify, csp, data, htmlparse, rules
from vulnscan.webscan.coverage import Coverage
from vulnscan.webscan.types import HeaderList, Page, Response

ROOT = pathlib.Path(__file__).resolve().parents[2]
OWN = set(csp.CHECKS)
SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


# ----------------------------------------------------------------------------------------------- helpers

def _pols(*values: str, origin: str = "header"):
    return csp.parse_header(list(values), origin)


def _eval(*values: str, url: str = "https://example.test/", forms: bool = False, password: bool = False,
          groups=None, paranoid: bool = False):
    info = csp.DocInfo(url=url, https=url.startswith("https:"), forms=forms, password=password,
                       reporting_groups=groups)
    return csp.evaluate(_pols(*values), info, csp.load_bypass(), paranoid)


def _rules(hits) -> set[str]:
    return {h.rule for h in hits}


def _hit(hits, rule):
    found = [h for h in hits if h.rule == rule]
    assert found, f"{rule} not in {_rules(hits)}"
    return found[0]


def _codes(policy: str) -> list[str]:
    return [e["code"] for p in _pols(policy) for e in p.errors]


def _run(ctx):
    issues = csp.run(ctx)
    for i in issues:
        assert rules.validate_issue(i) == [], i
        assert i.rule in OWN
        assert i.evidence.match is not None
        for en, ar in i.notes:
            assert en and ar and en != ar
    return issues


def _doc_ctx(make_page, make_ctx, headers, html="<html><head><title>x</title></head><body><script>1</script></body></html>",
             url="https://example.test/", **ctx_kw):
    page = make_page(html, url=url, headers=headers)
    ctx = make_ctx(target=url, entry=page, **ctx_kw)
    ctx.coverage = Coverage(csp.CHECKS)
    return ctx


# ======================================================================================== parsing (CSP3 §2.2)

def test_parse_first_occurrence_wins_and_duplicates_recorded():
    (p,) = _pols("script-src 'self'; SCRIPT-SRC 'unsafe-inline'; object-src 'none'")
    assert p.directives["script-src"] == ["'self'"]
    assert p.duplicates == [("script-src", "'unsafe-inline'")]


def test_parse_splits_header_on_commas_and_skips_empty_policies():
    pols = _pols("default-src 'none', script-src 'self'", "  ,  ")
    assert [list(p.directives) for p in pols] == [["default-src"], ["script-src"]]


def test_keywords_case_insensitive_nonce_values_case_sensitive():
    (p,) = _pols("script-src 'SELF' 'Nonce-AbCdEfGh12345678' HTTPS:")
    assert p.directives["script-src"] == ["'self'", "'nonce-AbCdEfGh12345678'", "https:"]
    assert csp.valid_nonces(p) == ["AbCdEfGh12345678"]


def test_non_ascii_directive_is_skipped():
    (p,) = _pols("script-src 'self'; img-src ’self’")
    assert "img-src" not in p.directives
    assert "non_ascii" in [e["code"] for e in p.errors]


def test_meta_policy_drops_header_only_directives():
    (p,) = _pols("default-src 'self'; frame-ancestors 'none'; report-uri /r; sandbox", origin="meta")
    assert p.dropped == ["frame-ancestors", "report-uri", "sandbox"]
    assert list(p.directives) == ["default-src"]


@pytest.mark.parametrize("policy,code", [
    # csp-evaluator parser_checks_test.ts
    ("foobar-src http:", "unknown"),
    ("default-src foo.bar script-src 'none'", "semicolon"),
    ("script-src strict-dynamic", "unquoted"),
    ("script-src nonce-test", "unquoted"),
    ("script-src sha256-asdf", "unquoted"),
    ("script-src 'foo-bar'", "bad_keyword"),
    ("script-src 'nonce-invalid$'", "bad_nonce"),
    ("script-src 'sha256-invalid$'", "bad_hash"),
    # spec §2.2 WEB201 list
    ("scritp-src 'self'", "unknown_typo"),
    ("script-src: 'self'", "colon"),
    ("script-src self", "unquoted"),
    ("script-src 'none' 'self'", "none_combined"),
    ("script-src 'https://cdn.example.com'", "quoted_host"),
    ("script-src 'sha256-AAAA'", "bad_hash"),
    ("script-src 8.8.8.8", "ip"),
    ("img-src ht!tp://x", "invalid_source"),
    ("sandbox allow-everything", "invalid_value"),
    ("require-trusted-types-for script", "unquoted"),
])
def test_syntax_errors(policy, code):
    assert code in _codes(policy)


@pytest.mark.parametrize("policy", [
    "require-trusted-types-for 'script'",                 # csp-evaluator CheckInvalidKeywordAllowsRequireTrustedTypesForScript
    "trusted-types 'allow-duplicates' policy1",           # ... AllowsTrustedTypesAllowDuplicateKeyword
    "script-src 'nonce-veryLongRandomNonce' 'strict-dynamic' https: 'unsafe-inline'; object-src 'none'; base-uri 'none'",
    "default-src 'none'; frame-ancestors 'none'",
    "script-src 'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='",   # padded base64
    "script-src 'sha256-47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU'",    # base64url, unpadded (43 chars)
    "upgrade-insecure-requests; report-to csp; report-uri https://r.example/csp",
    "img-src https://*.example.com:* data: blob:; connect-src wss://live.example.com",
    "sandbox allow-scripts allow-forms; webrtc 'block'",
])
def test_valid_policies_have_no_syntax_errors(policy):
    assert _codes(policy) == []


def test_typo_suggestion_and_ineffective_error_is_medium():
    (p,) = _pols("object-src 'none'; scirpt-src 'self'")
    (e,) = p.errors
    assert e["code"] == "unknown_typo" and e["suggest"] == "script-src" and e["severity"] == "medium"
    (p,) = _pols("default-src 'self'; scritp-src 'self'")          # default-src still restricts scripts → low
    assert p.errors[0]["severity"] == "low"
    (p,) = _pols("object-src 'none' script-src 'self'")           # missing ';' swallowed script-src
    assert any(e["code"] == "semicolon" and e["severity"] == "medium" for e in p.errors)


def test_ip_source_is_info():
    (p,) = _pols("script-src 8.8.8.8; font-src //127.0.0.1 not.an.ip")
    sev = {e["value"]: e["severity"] for e in p.errors}
    assert sev["8.8.8.8"] == "info"


@pytest.mark.parametrize("token,kind", [
    ("'self'", "keyword"), ("*", "host"), ("https:", "scheme"), ("https://*.example.com:443/path/", "host"),
    ("'nonce-abc_-+/='", "nonce"), ("'sha512-" + "A" * 86 + "=='", "hash"), ("data:", "scheme"),
    ("'nonce-'", "invalid"), ("//*", "invalid"), ("'unsafe-hashed-attributes'", "invalid"),
])
def test_classify_source(token, kind):
    assert csp.classify_source(token).kind == kind


# ======================================================================================== fallback and neutralisation

@pytest.mark.parametrize("policy,directive,used", [
    ("script-src 'self'; default-src 'none'", "script-src-elem", "script-src"),
    ("default-src 'none'", "script-src-attr", "default-src"),
    ("script-src 'self'", "worker-src", "script-src"),
    ("child-src 'self'; script-src 'none'", "worker-src", "child-src"),
    ("child-src 'self'; default-src 'none'", "frame-src", "child-src"),
    ("default-src 'none'", "img-src", "default-src"),
    ("style-src 'self'", "style-src-elem", "style-src"),
    ("default-src 'none'", "base-uri", None),       # no fallback for base-uri / form-action / frame-ancestors
    ("default-src 'none'", "form-action", None),
    ("default-src 'none'", "frame-ancestors", None),
])
def test_fallback_chains(policy, directive, used):
    (p,) = _pols(policy)
    assert csp.chain(p, directive)[0] == used


def test_neutralisation_nonce_and_strict_dynamic():
    (p,) = _pols("script-src 'nonce-abcdefgh12345678' 'strict-dynamic' 'unsafe-inline' https: 'self' https://a.example")
    assert [s.norm for s in csp.effective(p, "script-src-elem")] == ["'nonce-abcdefgh12345678'", "'strict-dynamic'"]
    (p,) = _pols("script-src 'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=' 'unsafe-inline' https://a.example")
    assert "'unsafe-inline'" not in {s.norm for s in csp.effective(p, "script-src-elem")}
    assert "https://a.example" in {s.norm for s in csp.effective(p, "script-src-elem")}
    # malformed nonce or hash does not neutralise (csp-evaluator CheckScriptUnsafeInlineWithMalformedNonce/Hash)
    for bad in ("'nonce-invalid$'", "'sha256-invalid$'"):
        assert "WEB040" in _rules(_eval(f"script-src 'unsafe-inline' {bad}; object-src 'none'"))


@pytest.mark.parametrize("value,anyof", [
    ("*", True), ("https:", True), ("http:", True), ("data:", True), ("blob:", True), ("http://*", True),
    ("https://*", True), ("https://*:443", True), ("https://*.example.com", False), ("https://cdn.example.com", False),
    ("'self'", False), ("'none'", False),
])
def test_any_definition_for_scripts(value, anyof):
    (p,) = _pols(f"script-src {value}")
    assert csp.is_any(csp.effective(p, "script-src-elem"), "script") is anyof
    assert csp.is_any(None, "script") is True          # missing effective directive


# ======================================================================================== value rules (csp-evaluator ports)

def test_web040_unsafe_inline():
    assert "WEB040" in _rules(_eval("default-src https:; script-src 'unsafe-inline'"))
    assert "WEB040" in _rules(_eval("default-src 'unsafe-inline'"))
    # default-src 'unsafe-inline' but script lists restricted: not reported
    assert "WEB040" not in _rules(_eval("default-src 'unsafe-inline'; script-src https:; script-src-attr https:; "
                                        "script-src-elem https:"))
    # D7: nonce / hash / strict-dynamic make 'unsafe-inline' ignored
    assert "WEB040" not in _rules(_eval("script-src 'unsafe-inline' 'nonce-foobar12'; script-src-elem 'unsafe-inline' "
                                        "'nonce-foobar12'"))
    assert "WEB040" not in _rules(_eval("script-src 'strict-dynamic' 'unsafe-inline'"))
    # D8: the weaker script-src is read even when default-src is strict
    assert "WEB040" in _rules(_eval("default-src 'self'; script-src 'unsafe-inline'"))
    # csp-evaluator checkScriptUnsafeInline_notOverriddenForScriptSrcElem
    assert "WEB040" in _rules(_eval("script-src 'nonce-aaaaaaaaaa' 'strict-dynamic'; script-src-elem 'unsafe-inline'"))
    # script-src-elem 'self' + script-src-attr 'none' override a weak script-src
    assert "WEB040" not in _rules(_eval("script-src 'unsafe-inline'; script-src-elem 'self'; script-src-attr 'none'"))


def test_inline_kept_for_old_browsers_inventory_note():
    notes = csp.policy_notes(_pols("script-src 'nonce-abcdefgh12345678' 'unsafe-inline'"))
    assert any("old browsers" in en for en, _ar in notes)


def test_web041_unsafe_eval():
    assert "WEB041" in _rules(_eval("default-src 'unsafe-eval'"))
    assert "WEB041" in _rules(_eval("default-src https:; script-src 'unsafe-eval'"))
    assert "WEB041" not in _rules(_eval("script-src 'wasm-unsafe-eval' 'self'"))
    assert "WEB041" in _rules(_eval("script-src 'self' 'trusted-types-eval'"))
    assert "WEB041" not in _rules(_eval("script-src 'self' 'trusted-types-eval'; require-trusted-types-for 'script'"))


@pytest.mark.parametrize("policy,fires", [
    ("script-src data: http: https: sthInvalid:", True),   # csp-evaluator CheckPlainUrlSchemesInScriptSrc
    ("script-src * http://* ", True),                      # CheckWildcardsInScriptSrc
    ("default-src *; object-src 'none'", True),
    ("script-src 'none'", False),
    ("script-src 'self' https://*.example.com", False),    # D9
    ("script-src 'nonce-abcdefgh12345678' 'strict-dynamic' https:", False),
    ("script-src 'strict-dynamic' https:", False),         # WEB203 instead
    ("default-src 'none'; script-src 'self'", False),
])
def test_web042_any_script_source(policy, fires):
    assert ("WEB042" in _rules(_eval(policy))) is fires


def test_web042_non_script_policy_replaces_restatements():
    hits = _eval("frame-ancestors 'none'; upgrade-insecure-requests")
    h = _hit(hits, "WEB042")
    assert h.params == {"variant": "non_script"}
    assert not _rules(hits) & {"WEB040", "WEB043", "WEB204", "WEB209", "WEB218"}
    assert rules.RULES["WEB042"].title("en", **h.params) == "CSP does not restrict scripts"


@pytest.mark.parametrize("policy,fires", [
    ("script-src 'none'", True),                    # CheckMissingDirectivesMissingObjectSrc
    ("script-src 'self'; object-src *", True),
    ("script-src 'self'; object-src data:", True),
    ("script-src 'none'; object-src 'none'", False),
    ("default-src https:; script-src 'self'", True),  # object falls back to default-src https: → ANY
    ("default-src 'none'; script-src 'self'", False),  # D10
    ("default-src 'self'", False),
    ("script-src 'self'; object-src 'self'", False),   # note only (inventory)
])
def test_web043_object_src(policy, fires):
    assert ("WEB043" in _rules(_eval(policy))) is fires


def test_web043_object_self_is_an_inventory_note():
    assert any("object-src 'self'" in en for en, _ar in csp.policy_notes(_pols("script-src 'self'; object-src 'self'")))
    notes = csp.policy_notes(_pols("script-src 'self'; object-src https://*.googleapis.com"), csp.load_bypass())
    assert any("Flash" in en for en, _ar in notes)        # csp-evaluator checkFlashObjectAllowlistBypassFlashBypass


def test_web203_strict_dynamic_without_nonce():
    assert "WEB203" in _rules(_eval("script-src 'strict-dynamic' https:"))
    assert "WEB203" not in _rules(_eval("script-src 'strict-dynamic' 'nonce-abcdefgh12345678'"))
    assert "WEB203" not in _rules(_eval("script-src 'strict-dynamic' 'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='"))


@pytest.mark.parametrize("policy,sev", [
    ("script-src 'nonce-123abcdefgh'; object-src 'none'", "medium"),     # CheckMissingDirectivesMissingBaseUriInNonceCsp
    ("script-src 'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=' 'strict-dynamic'; object-src 'none'", "medium"),
    ("script-src 'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='; object-src 'none'", "info"),
    ("script-src 'self'; object-src 'none'", "info"),
    ("script-src 'self'; object-src 'none'; base-uri *", "medium"),
    ("script-src 'self'; object-src 'none'; base-uri https:", "medium"),
    ("script-src 'nonce-123abcdefgh'; object-src 'none'; base-uri 'none'", None),
    ("script-src 'self'; object-src 'none'; base-uri 'self'", None),
])
def test_web204_base_uri(policy, sev):
    hits = _eval(policy)
    if sev is None:
        assert "WEB204" not in _rules(hits)
    else:
        assert _hit(hits, "WEB204").severity == sev


def test_web205_form_action():
    p = "script-src 'self'; object-src 'none'"
    assert "WEB205" not in _rules(_eval(p))                                       # no forms
    assert _hit(_eval(p, forms=True, password=True), "WEB205").severity == "medium"
    assert _hit(_eval(p, forms=True), "WEB205").severity == "info"
    assert _hit(_eval(p + "; form-action *", forms=True), "WEB205").severity == "info"
    assert "WEB205" not in _rules(_eval(p + "; form-action 'self'", forms=True, password=True))
    assert "WEB205" in _rules(_eval("default-src 'none'", forms=True, password=True))   # no fallback to default-src


@pytest.mark.parametrize("policy,fires", [
    ("frame-ancestors *", True), ("frame-ancestors https:", True), ("frame-ancestors http:", True),
    ("frame-ancestors 'none'", False), ("frame-ancestors 'self' https://a.example", False),
    ("default-src 'none'", False),    # no frame-ancestors at all: the missing-XFO rule (headers.py) covers it
])
def test_web206_frame_ancestors_any(policy, fires):
    assert ("WEB206" in _rules(_eval(policy))) is fires


def test_web206_intersection_one_restrictive_policy_protects():
    assert "WEB206" not in _rules(_eval("frame-ancestors *", "frame-ancestors 'self'"))


def test_web209_bypass_lists():
    # csp-evaluator checkScriptAllowlistBypassJSONPBypass: *.google.com → www.google.com JSONP
    h = _hit(_eval("script-src *.google.com; object-src 'none'"), "WEB209")
    assert h.severity == "medium" and "www.google.com" in h.notes[0][0] and h.value.startswith("https://")
    # AngularJS host (checkScriptAllowlistBypassAngularBypass)
    assert "Angular" in _hit(_eval("script-src gstatic.com; object-src 'none'"), "WEB209").notes[0][0]
    # needs eval: low without 'unsafe-eval', medium with it
    assert _hit(_eval("script-src https://googletagmanager.com"), "WEB209").severity == "low"
    assert _hit(_eval("script-src https://googletagmanager.com 'unsafe-eval'"), "WEB209").severity == "medium"
    # no bypass known / 'none' / strict-dynamic neutralises
    assert "WEB209" not in _rules(_eval("script-src foo.bar"))
    # csp-evaluator skips a list with 'none' in it; browsers ignore 'none' next to other sources (CSP3 §6.7.2.5), so
    # the bypass stays and the list also gets a WEB201 "none_combined" error
    assert "WEB209" in _rules(_eval("script-src *.google.com 'none'; script-src-elem *.google.com 'none'"))
    assert "none_combined" in _codes("script-src *.google.com 'none'")
    assert "WEB209" not in _rules(_eval("script-src 'none'"))
    assert "WEB209" not in _rules(_eval("script-src 'nonce-abcdefgh12345678' 'strict-dynamic' https://www.google.com"))
    # path-restricted source that excludes every listed endpoint
    assert "WEB209" not in _rules(_eval("script-src https://www.google.com/recaptcha/"))
    for host in ("ajax.googleapis.com", "cdnjs.cloudflare.com", "cdn.jsdelivr.net"):
        assert "WEB209" in _rules(_eval(f"script-src https://{host}")), host


def test_web209_intersection_requires_every_policy_to_allow_the_endpoint():
    assert "WEB209" not in _rules(_eval("script-src https://www.google.com", "script-src 'self'"))
    assert "WEB209" in _rules(_eval("script-src https://www.google.com", "script-src https:"))


def test_web210_unsafe_hashes():
    assert "WEB210" in _rules(_eval("script-src 'unsafe-hashes' 'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='"))
    assert "WEB210" not in _rules(_eval("script-src 'self'"))
    assert "WEB210" not in _rules(_eval("script-src 'unsafe-hashes'", "script-src-attr 'none'; script-src 'self'"))


def test_web211_insecure_sources():
    h = _hit(_eval("script-src http://foo.bar https://test.com"), "WEB211")      # csp-evaluator CheckSrcHttp
    assert h.severity == "medium"
    assert _hit(_eval("default-src 'self'; img-src http:"), "WEB211").severity == "low"
    assert _hit(_eval("default-src 'self'; script-src http://a.example; upgrade-insecure-requests"),
                "WEB211").severity == "low"
    assert "WEB211" not in _rules(_eval("script-src http://foo.bar", url="http://example.test/"))   # not secure context
    assert "WEB211" not in _rules(_eval("script-src http://foo.bar", "script-src 'self'"))           # intersection


@pytest.mark.parametrize("nonce,sev", [
    ("abc", "medium"), ("short", "medium"),             # csp-evaluator CheckNonceLengthWithShortNonce
    ("abcdefgh", "info"),                               # 8 chars → 6 bytes
    ("veryLongRandomNonce", "info"),                    # 19 chars → 14 bytes
    ("c3RhdGljLW5vbmNlLTEyMzQ1Ng==", None),            # 18 bytes
])
def test_web213_nonce_length(nonce, sev):
    hits = _eval(f"script-src 'nonce-{nonce}'; object-src 'none'; base-uri 'none'")
    if sev is None:
        assert "WEB213" not in _rules(hits)
    else:
        assert _hit(hits, "WEB213").severity == sev


def test_web214_inline_styles():
    assert "WEB214" in _rules(_eval("default-src 'self'; style-src 'self' 'unsafe-inline'"))
    assert "WEB214" not in _rules(_eval("default-src 'self'; style-src 'self' 'unsafe-inline' 'nonce-abcdefgh12345678'"))
    assert "WEB214" not in _rules(_eval("default-src 'self'"))


def test_web215_reporting():
    assert _hit(_eval("script-src 'nonce-aaaaaaaaaaaaaaaaaaaaaa'"), "WEB215").severity == "info"   # no reporting
    assert "WEB215" not in _rules(_eval("script-src 'self'; report-uri /r"))
    assert "WEB215" not in _rules(_eval("script-src 'self'; report-to csp", groups=frozenset({"csp"})))
    assert _hit(_eval("script-src 'self'; report-to csp", groups=frozenset({"other"})), "WEB215").severity == "low"
    assert _hit(_eval("script-src 'self'; report-to csp", groups=None), "WEB215").severity == "low"


@pytest.mark.parametrize("directive", ["block-all-mixed-content", "plugin-types application/pdf", "prefetch-src 'self'",
                                       "referrer origin", "reflected-xss block", "disown-opener", "navigate-to 'self'",
                                       "require-sri-for script"])
def test_web216_deprecated(directive):
    assert "WEB216" in _rules(_eval(f"default-src 'self'; {directive}"))


def test_web218_allowlist_only_and_web219_trusted_types():
    assert "WEB218" in _rules(_eval("default-src 'self'; script-src 'self' https://static.example"))
    assert "WEB218" not in _rules(_eval("script-src 'nonce-abcdefgh12345678' 'strict-dynamic'"))
    assert "WEB218" not in _rules(_eval("script-src *"))
    assert "WEB219" not in _rules(_eval("script-src 'self'"))                       # paranoid only
    assert "WEB219" in _rules(_eval("script-src 'self'", paranoid=True))
    assert "WEB219" not in _rules(_eval("script-src 'self'; require-trusted-types-for 'script'", paranoid=True))


def test_intersection_second_policy_fixes_the_first():
    hits = _eval("script-src 'self' 'unsafe-inline'; object-src 'none'", "script-src 'self'; object-src 'none'; base-uri 'none'")
    assert "WEB040" not in _rules(hits)
    assert "WEB204" not in _rules(hits)
    assert "WEB040" in _rules(_eval("script-src 'self' 'unsafe-inline'", "default-src 'unsafe-inline' 'self'"))


def test_severity_ceiling_of_the_family():
    for rid in csp.CHECKS:
        assert SEV_RANK[max(rules.RULES[rid].allowed_severities, key=SEV_RANK.__getitem__)] <= SEV_RANK["medium"], rid


# ======================================================================================== source matching

@pytest.mark.parametrize("src,url,ok", [
    ("'self'", "https://example.test/a.js", True),
    ("'self'", "https://other.test/a.js", False),
    ("https:", "https://x.test/", True),
    ("http:", "https://x.test/", True),             # http: also matches https (upgrade)
    ("https://*.example.com", "https://a.example.com/x", True),
    ("https://*.example.com", "https://example.com/x", False),
    ("https://cdn.example.com/lib/", "https://cdn.example.com/lib/a.js", True),
    ("https://cdn.example.com/lib/a.js", "https://cdn.example.com/lib/b.js", False),
    ("cdn.example.com", "https://cdn.example.com/a.js", True),
    ("http://cdn.example.com", "https://cdn.example.com/a.js", True),
    ("https://cdn.example.com:8443", "https://cdn.example.com/a.js", False),
    ("https://cdn.example.com:*", "https://cdn.example.com:8443/a.js", True),
])
def test_source_matches_url(src, url, ok):
    assert csp.source_matches_url(csp.classify_source(src), url, "https://example.test") is ok


# ======================================================================================== documents (run)

def test_missing_csp_and_static_document(make_page, make_ctx):
    ctx = _doc_ctx(make_page, make_ctx, [])
    issues = _run(ctx)
    (i,) = [i for i in issues if i.rule == "WEB-content-security-policy"]
    assert i.severity is None and i.confidence == "firm"
    ctx = _doc_ctx(make_page, make_ctx, [], html="<html><head><title>x</title></head><body><p>static</p></body></html>")
    (i,) = [i for i in _run(ctx) if i.rule == "WEB-content-security-policy"]
    assert i.severity == "low"
    ctx = _doc_ctx(make_page, make_ctx, [], html="<html><body><p onclick='x()'>x</p></body></html>")
    (i,) = [i for i in _run(ctx) if i.rule == "WEB-content-security-policy"]
    assert i.severity is None


def test_report_only_gives_web200_with_would_be_weak_notes(make_page, make_ctx):
    ctx = _doc_ctx(make_page, make_ctx, [("Content-Security-Policy-Report-Only", "script-src 'unsafe-inline' *")])
    issues = _run(ctx)
    rs = {i.rule for i in issues}
    assert "WEB200" in rs and "WEB-content-security-policy" not in rs and "WEB040" not in rs
    (i,) = [i for i in issues if i.rule == "WEB200"]
    assert any("WEB040" in en for en, _ar in i.notes)
    assert i.evidence.match["name"] == "Content-Security-Policy-Report-Only"
    assert "WEB040" in i.evidence.match["excerpt"]
    ctx = _doc_ctx(make_page, make_ctx, [("Content-Security-Policy-Report-Only", "default-src 'self'; scritp-src x")])
    issues = _run(ctx)
    assert {i.rule for i in issues} == {"WEB200"}
    assert any("WEB201" in en for en, _ar in issues[0].notes)


def test_meta_only_policy_counts_as_enforced(make_page, make_ctx):
    html = ("<html><head><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; object-src 'none'; "
            "base-uri 'none'\"><title>x</title></head><body><script>1</script></body></html>")
    issues = _run(_doc_ctx(make_page, make_ctx, [], html=html))
    assert "WEB-content-security-policy" not in {i.rule for i in issues}


def test_meta_outside_head_is_ignored(make_page, make_ctx):
    html = ("<html><head><title>x</title></head><body><p>x</p><meta http-equiv=\"Content-Security-Policy\" "
            "content=\"default-src 'self'\"><script>1</script></body></html>")
    issues = _run(_doc_ctx(make_page, make_ctx, [], html=html))
    (i,) = [i for i in issues if i.rule == "WEB-content-security-policy"]
    assert any("outside <head>" in en for en, _ar in i.notes)


def test_web207_meta_dropped_directives_and_severity(make_page, make_ctx):
    html = ("<html><head><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; frame-ancestors "
            "'none'\"><title>x</title></head><body></body></html>")
    (i,) = [i for i in _run(_doc_ctx(make_page, make_ctx, [], html=html)) if i.rule == "WEB207"]
    assert i.severity == "medium" and i.evidence.match["where"] == "body" and i.evidence.match["offset"] is not None
    (i,) = [i for i in _run(_doc_ctx(make_page, make_ctx, [("X-Frame-Options", "DENY")], html=html)) if i.rule == "WEB207"]
    assert i.severity == "low"


def test_web208_meta_after_script(make_page, make_ctx):
    meta = "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'\">"
    late = f"<html><head><link rel=stylesheet href=/a.css>{meta}<title>x</title></head><body></body></html>"
    assert "WEB208" in {i.rule for i in _run(_doc_ctx(make_page, make_ctx, [], html=late))}
    early = f"<html><head>{meta}<script src=/a.js></script><title>x</title></head><body></body></html>"
    assert "WEB208" not in {i.rule for i in _run(_doc_ctx(make_page, make_ctx, [], html=early))}
    noscript = f"<html><head><noscript><style>p{{}}</style></noscript>{meta}</head><body></body></html>"
    assert "WEB208" not in {i.rule for i in _run(_doc_ctx(make_page, make_ctx, [], html=noscript))}


def test_web217_legacy_header(make_page, make_ctx):
    issues = _run(_doc_ctx(make_page, make_ctx, [("X-WebKit-CSP", "default-src 'self'")]))
    (i,) = [i for i in issues if i.rule == "WEB217"]
    assert i.severity == "low" and "WEB-content-security-policy" in {x.rule for x in issues}
    issues = _run(_doc_ctx(make_page, make_ctx, [("X-Content-Security-Policy", "default-src 'self'"),
                                                 ("Content-Security-Policy", "default-src 'self'")]))
    (i,) = [i for i in issues if i.rule == "WEB217"]
    assert i.severity is None


def test_api_and_error_pages_are_not_judged(make_response, make_ctx):
    api = make_response("https://example.test/api", headers=[("Content-Security-Policy", "default-src 'none'; "
                                                               "frame-ancestors 'none'")],
                        body=b'{"a": 1}', content_type="application/json", kind="api_json")
    ctx = make_ctx(entry=api)
    assert _run(ctx) == []                                   # the recommended API policy is never flagged
    err = make_response("https://example.test/x", status=404, body="<html><body>nf</body></html>",
                        content_type="text/html", kind="error_page")
    assert _run(make_ctx(entry=err)) == []


def test_syntax_rules_on_non_html_and_once_per_policy(make_response, make_page, make_ctx):
    bad = [("Content-Security-Policy", "default-src 'none'; default-src *; scritp-src x")]
    page = make_page("<html><body><script>1</script></body></html>", headers=bad)
    js1 = make_response("https://example.test/a.js", headers=bad, body=b"1", content_type="text/javascript",
                        kind="script", source="subresource")
    js2 = make_response("https://example.test/b.js", headers=bad, body=b"1", content_type="text/javascript",
                        kind="script", source="subresource")
    ctx = make_ctx(entry=page, subresources=[js1, js2])
    issues = _run(ctx)
    assert [i.rule for i in issues].count("WEB201") == 1
    assert [i.rule for i in issues].count("WEB202") == 1
    api = make_response("https://example.test/api", headers=bad, body=b"{}", content_type="application/json",
                        kind="api_json")
    assert {i.rule for i in _run(make_ctx(entry=api))} == {"WEB201", "WEB202"}


def test_waf_entry_is_inconclusive(make_response, make_ctx):
    r = make_response("https://example.test/", status=403, body="<html>challenge</html>", content_type="text/html",
                      kind="waf_challenge")
    ctx = make_ctx(entry=r)
    ctx.coverage = Coverage(csp.CHECKS)
    assert _run(ctx) == []
    assert ctx.coverage.state("WEB-content-security-policy").state == "inconclusive"


def test_coverage_states(make_page, make_ctx):
    ctx = _doc_ctx(make_page, make_ctx, [("Content-Security-Policy", "script-src 'self' 'unsafe-inline'")])
    _run(ctx)
    cov = ctx.coverage
    assert cov.state("WEB040").state == "fail"
    assert cov.state("WEB041").state == "pass"
    assert cov.state("WEB219").state == "not_tested"          # paranoid only
    assert cov.state("WEB207").state == "not_applicable"      # no meta policy
    ctx = make_ctx(entry=None)
    ctx.coverage = Coverage(csp.CHECKS)
    _run(ctx)
    assert ctx.coverage.state("WEB-content-security-policy").state == "not_applicable"


# ======================================================================================== static nonce (WEB212)

def _nonce_doc(make_response, nonce, source="entry", url="https://example.test/", cache="no-store"):
    return make_response(url, headers=[("Content-Security-Policy", f"script-src 'nonce-{nonce}' 'strict-dynamic'"),
                                       ("Cache-Control", cache)],
                         body=f"<html><body><script nonce='{nonce}'>1</script></body></html>",
                         content_type="text/html; charset=utf-8", kind="document", source=source)


def test_compare_nonces_api(make_response):
    a = _nonce_doc(make_response, "c3RhdGljLW5vbmNlLTEyMzQ1Ng==")
    b = _nonce_doc(make_response, "c3RhdGljLW5vbmNlLTEyMzQ1Ng==", source="cors")
    c = _nonce_doc(make_response, "ZGlmZmVyZW50LW5vbmNlLTEyMw==", source="cors")
    assert csp.compare_nonces(a, b) == ["c3RhdGljLW5vbmNlLTEyMzQ1Ng=="]
    assert csp.compare_nonces(a, c) == []
    assert csp.compare_nonces(a, a) == []                    # the same response is not two fetches
    b.kind = "soft404"
    assert csp.compare_nonces(a, b) == []                    # differs in kind
    err = _nonce_doc(make_response, "c3RhdGljLW5vbmNlLTEyMzQ1Ng==", source="cors")
    err.status = 500
    assert csp.compare_nonces(a, err) == []


def test_web212_static_and_cached_nonce(make_response, make_ctx):
    a = _nonce_doc(make_response, "c3RhdGljLW5vbmNlLTEyMzQ1Ng==")
    b = _nonce_doc(make_response, "c3RhdGljLW5vbmNlLTEyMzQ1Ng==", source="cors")
    ctx = make_ctx(entry=Page(a, htmlparse.parse_response(a)), cors=b)
    (i,) = [i for i in _run(ctx) if i.rule == "WEB212"]
    assert i.confidence == "certain" and i.url == a.url
    c = _nonce_doc(make_response, "ZGlmZmVyZW50LW5vbmNlLTEyMw==", source="cors")
    ctx = make_ctx(entry=Page(a, htmlparse.parse_response(a)), cors=c)
    assert "WEB212" not in {i.rule for i in _run(ctx)}
    pub = _nonce_doc(make_response, "c3RhdGljLW5vbmNlLTEyMzQ1Ng==", cache="public, max-age=600")
    (i,) = [i for i in _run(make_ctx(entry=Page(pub, htmlparse.parse_response(pub)))) if i.rule == "WEB212"]
    assert i.confidence == "firm"
    sm = _nonce_doc(make_response, "c3RhdGljLW5vbmNlLTEyMzQ1Ng==", cache="max-age=0, s-maxage=60")
    assert "WEB212" in {i.rule for i in _run(make_ctx(entry=Page(sm, htmlparse.parse_response(sm))))}
    priv = _nonce_doc(make_response, "c3RhdGljLW5vbmNlLTEyMzQ1Ng==", cache="private, max-age=600")
    assert "WEB212" not in {i.rule for i in _run(make_ctx(entry=Page(priv, htmlparse.parse_response(priv))))}


@pytest.mark.parametrize("cache, reused", [
    ("public, max-age=0, must-revalidate", False),           # Netlify/Vercel/Cloudflare Pages default: revalidated each use
    ("public,max-age=0,must-revalidate", False),
    ("public, no-cache", False),
    ("public, max-age=600, no-cache", False),
    ("public, s-maxage=0, max-age=600", False),              # s-maxage overrides max-age for shared caches
    ("public", True),                                        # heuristic freshness: may be reused
    ("public, max-age=600, stale-while-revalidate=60", True),
    ("public, max-age=0, stale-while-revalidate=30", True),  # a stale copy (and its nonce) may still be served
    ("s-maxage=120", True),
    ("public, max-age=abc", False),                          # invalid delta-seconds = stale
])
def test_web212_cached_nonce_needs_shared_freshness(make_response, make_ctx, cache, reused):
    """1.1.0 accuracy: ``public`` alone is not reuse when every use is revalidated with the origin (which mints a new nonce)."""
    r = _nonce_doc(make_response, "ZnJlc2gtbm9uY2UtcGVyLXJlc3BvbnNl", cache=cache)
    got = {i.rule for i in _run(make_ctx(entry=Page(r, htmlparse.parse_response(r))))}
    assert ("WEB212" in got) is reused, cache
    assert bool(csp.cache_reuses_nonce(r)) is reused


def test_web212_cached_nonce_expires_header(make_response, make_ctx):
    def doc(*extra):
        return make_response("https://example.test/", headers=[("Content-Security-Policy", "script-src 'nonce-abcdefghijklmnopqrstuv'"),
                                                               ("Cache-Control", "public"), *extra],
                             body="<html><body>1</body></html>", content_type="text/html; charset=utf-8", kind="document")
    assert csp.cache_reuses_nonce(doc(("Expires", "0"))) == ""     # invalid Expires = already expired
    assert csp.cache_reuses_nonce(doc(("Expires", "-1"))) == ""
    assert csp.cache_reuses_nonce(doc(("Expires", "Fri, 13 Nov 2026 12:10:00 GMT"))) == "public"


# ======================================================================================== stage 1 facts

def test_parse_all_facts(make_page, make_ctx, make_response):
    html = ("<html><head><meta http-equiv=\"Content-Security-Policy\" content=\"img-src 'self'; frame-ancestors 'none'\">"
            "</head><body></body></html>")
    page = make_page(html, headers=[("Content-Security-Policy", "default-src 'self'; frame-ancestors *"),
                                    ("Content-Security-Policy", "frame-ancestors 'self'; upgrade-insecure-requests"),
                                    ("Content-Security-Policy-Report-Only", "script-src 'none'"),
                                    ("X-WebKit-CSP", "default-src 'self'")])
    js = make_response("https://example.test/a.js", body=b"1", content_type="text/javascript", kind="script")
    ctx = make_ctx(entry=page, subresources=[js])
    facts = csp.parse_all(ctx)
    f = facts[page.response]
    assert [p.origin for p in f.enforced] == ["header", "header", "meta"]
    assert f.frame_ancestors == ["'self'"] and f.frame_ancestors_protects is True
    assert f.upgrade_insecure_requests is True
    assert len(f.report_only) == 1 and f.legacy == [("X-WebKit-CSP", "default-src 'self'")]
    assert f.effective["policies"] == 3 and f.effective["restricts_scripts"] is True
    assert facts[js].enforced == [] and facts[js].frame_ancestors is None
    page2 = make_page("<html></html>", headers=[("Content-Security-Policy", "frame-ancestors *")])
    f2 = csp.facts_for(page2.response, page2.doc)
    assert f2.frame_ancestors == ["*"] and f2.frame_ancestors_protects is False


def test_run_fills_ctx_csp_and_inventory(make_page, make_ctx):
    ctx = _doc_ctx(make_page, make_ctx, [("Content-Security-Policy", "script-src 'self' https://cdn.example; "
                                          "style-src https://fonts.example")])
    _run(ctx)
    assert ctx.csp and ctx.inventory["csp"][0]["hosts"] == {"script": ["cdn.example"], "style": ["fonts.example"]}
    json.dumps(ctx.inventory["csp"])      # report data must be JSON-serialisable


# ======================================================================================== Observatory v6 slug

def _obs(header=None, html=None, url="https://mozilla.org/", ro=None):
    hs = [("Content-Type", "text/html")]
    if header is not None:
        hs.append(("Content-Security-Policy", header))
    if ro is not None:
        hs.append(("Content-Security-Policy-Report-Only", ro))
    r = Response(url=url, headers=HeaderList(tuple(hs)), body=(html or "").encode())
    doc = htmlparse.parse_response(r) if html else None
    return csp.observatory_slug(r, doc)


OBS_META1 = ("<!doctype html><html><head><meta charset=\"UTF-8\" /><meta http-equiv=\"Content-Security-Policy\" "
             "content=\"default-src 'none';\" /><title>Title</title></head><body></body></html>")
OBS_META2 = OBS_META1.replace("default-src 'none';", "default-src https:")
OBS_MULTI = ("<html><head><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; object-src 'none'; "
             "media-src 'none';\" /><meta http-equiv=\"Content-SECURITY-Policy\" content=\"connect-src 'self'; font-src "
             "'self'; child-src 'self'\" /><meta http-equiv=\" Content-Security-Policy \" content=\"img-src 'self'; "
             "style-src 'self' 'nonce-gAeQO8jI4VJCsrsXkcUVRCzQjiihKteQ\" /><meta http-equiv=\"Content-security-Policy\" "
             "content=\"script-src 'self' 'unsafe-inline' 'nonce-gAeQO8jI4VJCsrsXkcUVRCzQjiihKteQ'\" /></head><body>"
             "</body></html>")


@pytest.mark.parametrize("value", ["  ", "default-src 'none'; default-src 'none'",
                                   "default-src 'none'; img-src 'self'; default-src 'none'",
                                   "default-src 'none'; script-src 'strict-dynamic'", "defa"])
def test_observatory_header_invalid(value):
    assert _obs(value) == "csp-header-invalid"


@pytest.mark.parametrize("value,slug", [
    ("default-src 'none'; script-src https://*", "csp-implemented-with-unsafe-inline"),
    ("default-src 'none'; script-src 'unsafe-inline'", "csp-implemented-with-unsafe-inline"),
    ("default-src http://mozilla.org", "csp-implemented-with-insecure-scheme"),
    ("default-src 'none'; script-src ftp://mozilla.org", "csp-implemented-with-insecure-scheme"),
    ("default-src 'none'; img-src http://mozilla.org", "csp-implemented-with-insecure-scheme-in-passive-content-only"),
    ("default-src 'self'; img-src ftp:", "csp-implemented-with-insecure-scheme-in-passive-content-only"),
    ("default-src 'none'; img-src 'none'; media-src http:; script-src 'self'; style-src 'unsafe-inline'",
     "csp-implemented-with-insecure-scheme-in-passive-content-only"),
    ("script-src data:", "csp-implemented-with-unsafe-inline"),
    ("default-src 'UNSAFE-INLINE'", "csp-implemented-with-unsafe-inline"),
    ("upgrade-insecure-requests", "csp-implemented-with-unsafe-inline"),
    ("script-src 'none'", "csp-implemented-with-unsafe-inline"),
    ("default-src *; script-src *; object-src 'none'", "csp-implemented-with-unsafe-inline"),
    ("object-src https:; script-src 'none'", "csp-implemented-with-unsafe-inline"),
    ("default-src 'none'; script-src 'unsafe-eval'", "csp-implemented-with-unsafe-eval"),
    ("object-src 'none'; script-src 'none'; style-src 'unsafe-inline'",
     "csp-implemented-with-unsafe-inline-in-style-src-only"),
    ("default-src 'unsafe-inline'; script-src https://mozilla.org", "csp-implemented-with-unsafe-inline-in-style-src-only"),
    ("default-src 'none';;; ;;;style-src 'self' 'unsafe-inline'", "csp-implemented-with-unsafe-inline-in-style-src-only"),
    ("default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-hqBEA/HXB3aJU2FgOnYN8rkAgEVgyfi3Vs1j2/XMPBB=' "
     "'unsafe-inline'", "csp-implemented-with-unsafe-inline-in-style-src-only"),
    ("default-src https://mozilla.org", "csp-implemented-with-no-unsafe"),
    ("default-src https://mozilla.org;;; ;;;script-src 'none'", "csp-implemented-with-no-unsafe"),
    ("object-src 'none'; script-src 'strict-dynamic' 'nonce-abc' 'unsafe-inline'; style-src 'none'",
     "csp-implemented-with-no-unsafe"),
    ("object-src 'none'; script-src 'unsafe-inline' 'nonce-abc123' 'unsafe-inline'; style-src 'none'",
     "csp-implemented-with-no-unsafe"),
    ("default-src https://mozilla.org; style-src 'unsafe-inline' 'nonce-abc123' 'unsafe-inline'",
     "csp-implemented-with-no-unsafe"),
    ("default-src", "csp-implemented-with-no-unsafe-default-src-none"),
    ("default-src 'none'; script-src 'strict-dynamic' 'nonce-abc123' 'unsafe-inline'",
     "csp-implemented-with-no-unsafe-default-src-none"),
    ("default-src 'none'; object-src https://mozilla.org", "csp-implemented-with-no-unsafe-default-src-none"),
    ("default-src 'none'; script-src 'strict-dynamic' 'sha256-abc123' https://*",
     "csp-implemented-with-no-unsafe-default-src-none"),
    ("default-src 'none'; script-src 'self', default-src 'none'; script-src 'self'",
     "csp-implemented-with-no-unsafe-default-src-none"),
    ("default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline', default-src 'none'; style-src 'self', "
     "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'",
     "csp-implemented-with-no-unsafe-default-src-none"),
    ("frame-anchestors 'none'", "csp-implemented-with-unsafe-inline"),
    ("default-src 'none'; report-uri /a; report-uri /b", "csp-implemented-but-duplicate-directives"),
])
def test_observatory_slugs(value, slug):
    assert _obs(value) == slug


def test_observatory_meta_and_report_only():
    assert _obs(None) == "csp-not-implemented"
    assert _obs(None, ro="default-src 'none'; report-to /_/csp-reports") == "csp-not-implemented-but-reporting-enabled"
    assert _obs("default-src http:", OBS_META2) == "csp-implemented-with-no-unsafe-default-src-none"
    assert _obs(None, OBS_META1) == "csp-implemented-with-no-unsafe-default-src-none"
    assert _obs(None, OBS_MULTI) == "csp-implemented-with-no-unsafe-default-src-none"
    assert _obs("default-src 'none'", OBS_META2) == "csp-implemented-with-no-unsafe-default-src-none"
    assert _obs("img-src 'none'", OBS_META1) == "csp-implemented-with-no-unsafe-default-src-none"
    meta_fa = OBS_META1.replace("default-src 'none';", "frame-ancestors 'none'")
    assert _obs(None, meta_fa) == "csp-not-implemented"
    assert csp.observatory_slug(None) == "csp-not-implemented"


@pytest.mark.parametrize("policies,expected", [
    (["default-src 'none'; script-src 'self' https://mozilla.org",
      "default-src 'none'; script-src 'self' https://mozilla.org https://example.com"],
     {"default-src": {"'none'"}, "script-src": {"'self'", "https://mozilla.org"}}),
    (["default-src https://mozilla.org", "default-src https://mozilla.com"], {"default-src": {"'none'"}}),
    (["default-src https://mozilla.org https://mozilla.net https://mozilla.com https://mozilla.io",
      "default-src https://mozilla.pizza https://mozilla.ninja https://mozilla.net https://mozilla.org",
      "default-src https://mozilla.net https://mozilla.fox https://mozilla.fire https://mozilla.org",
      "default-src https://mozilla.browser https://mozilla.web https://mozilla.net https://mozilla.org"],
     {"default-src": {"https://mozilla.net", "https://mozilla.org"}}),
    (["default-src https://mozilla.org/fire", "default-src https://mozilla.org/firefox/"], {"default-src": {"'none'"}}),
    (["default-src https://mozilla.org/firefox/", "default-src https://mozilla.org/firefox/download/"],
     {"default-src": {"https://mozilla.org/firefox/download/"}}),
    (["default-src https://mozilla.org/firefox/download/", "default-src https://mozilla.org/firefox/"],
     {"default-src": {"https://mozilla.org/firefox/download/"}}),
    (["default-src http: http:", "default-src https: https:"], {"default-src": {"'none'"}}),
])
def test_observatory_parser_intersection(policies, expected):
    assert csp.obs_parse_csp(policies) == expected


def test_observatory_slug_written_by_run(make_page, make_ctx):
    ctx = _doc_ctx(make_page, make_ctx, [("Content-Security-Policy", "default-src 'none'")])
    _run(ctx)
    assert ctx.observatory["content-security-policy"] == "csp-implemented-with-no-unsafe-default-src-none"


# ======================================================================================== hostile input, speed

def test_hostile_policy_is_bounded_and_escaped(make_page, make_ctx):
    evil = "script-src " + " ".join(f"'x{i}\x1b[31m'" for i in range(5000)) + "; " + "; ".join(f"d{i}" for i in range(2000))
    t = time.perf_counter()
    issues = _run(_doc_ctx(make_page, make_ctx, [("Content-Security-Policy", evil)]))
    assert time.perf_counter() - t < 2.0
    for i in issues:
        for en, ar in i.notes:
            assert "\x1b" not in en and "\x1b" not in ar


def test_parse_and_evaluate_within_two_ms_per_policy():
    policies = [
        "default-src 'self'; script-src 'nonce-{n}abcdefghijkl' 'strict-dynamic' https: 'unsafe-inline'; object-src 'none'; "
        "base-uri 'none'; form-action 'self'; frame-ancestors 'none'; img-src 'self' data: https://cdn.example.com; "
        "style-src 'self' 'unsafe-inline'; report-to csp",
        "script-src 'self' https://a{n}.example.com https://cdn.jsdelivr.net https://ajax.googleapis.com; object-src 'none'",
    ]
    info = csp.DocInfo(url="https://example.test/", https=True, forms=True, password=True)
    bypass = csp.load_bypass()
    best = float("inf")
    for _round in range(3):
        t = time.perf_counter()
        n = 200
        for i in range(n):
            csp.classify_source.cache_clear()
            for p in policies:
                csp.evaluate(csp.parse_header([p.replace("{n}", str(i))]), info, bypass)
        best = min(best, (time.perf_counter() - t) / (n * len(policies)))
    assert best < 0.002, f"{best * 1000:.2f} ms per policy"


# ======================================================================================== data file and refresh tool

def test_bypass_data_file_validates_and_loads():
    assert data.validate_file(data.BUNDLED_DIR / "csp-bypass.json") == []
    b = csp.load_bypass()
    assert b.available and len(b.jsonp) >= 100 and len(b.angular) >= 30
    assert all(u.startswith("//") for u in b.jsonp + b.angular + b.flash)
    assert "googletagmanager.com" in b.needs_eval


def test_missing_bypass_data_is_not_tested(make_page, make_ctx):
    class NoData:
        @staticmethod
        def load_json(name):
            raise FileNotFoundError(name)
    ctx = _doc_ctx(make_page, make_ctx, [("Content-Security-Policy", "script-src https://www.google.com")])
    ctx.data = NoData()
    assert "WEB209" not in {i.rule for i in _run(ctx)}


def test_refresh_tool_normalises_offline(tmp_path):
    sys.path.insert(0, str(ROOT / "tools" / "webdata"))
    try:
        tool = importlib.import_module("csp_bypass")
    finally:
        sys.path.pop(0)
    raw = {"jsonp": {"needsEval": ["googletagmanager.com"],
                     "urls": [f"//h{i}.example.com/cb" for i in range(120)] + ["//H0.EXAMPLE.com/cb", "bad url"]},
           "angular": {"urls": [f"https://a{i}.example.org/angular.js" for i in range(40)]},
           "flash": {"urls": ["//vk.com/swf/video.swf"]}}
    obj = tool.build(raw, "2026-11-13", "abc123")
    assert len(obj["jsonp"]) == 120 and obj["angular"][0] == "//a0.example.org/angular.js"
    out = tool.write(obj, tmp_path)
    assert data.validate_file(out) == []
    with pytest.raises(SystemExit):
        tool.build({"jsonp": {"urls": ["//a.b/c"]}, "angular": {"urls": []}, "flash": {"urls": []}}, "2026-11-13")


# ======================================================================================== i18n

def test_every_note_has_both_languages_and_matching_placeholders():
    for key, (en, ar) in csp.STR.items():
        assert en and ar, key
        assert set(re.findall(r"\{([a-z_]+)\}", en)) == set(re.findall(r"\{([a-z_]+)\}", ar)), key
    catalog, patterns = csp.i18n_catalog()
    assert catalog and patterns
    en, ar = csp._note("short_nonce", nonce="abc", chars=csp._count(3, csp._CHARS))
    assert "3 characters" in en and "3 أحرف" in ar
    for rx, _repl in patterns:
        re.compile(rx)



# ======================================================================================== corpus cases (offline)

sys.path.insert(0, str(ROOT / "bench" / "web"))
corpus = importlib.import_module("corpus")
CORPUS_CASES = [c for c in corpus.CASES if set(c.labels) & OWN]


class _Sim:
    """Renders one corpus case in-process the way the engine would fetch it (entry chain with a cookie jar, the
    cookieless CORS GET) — no sockets."""

    def __init__(self, case):
        self.case = case
        self.srv = corpus.CorpusServer([case], mode="host", with_tls=False)
        self.srv.http_port, self.srv.https_port = 8080, 8443
        self.hosts = {h.lower(): a for h, a in case.all_hosts().items()}

    def url(self, path: str, scheme: str | None = None, alias: str = "") -> str:
        scheme = scheme or self.case.scheme
        host = self.case.alias_host(alias) if alias else self.case.host
        return f"{scheme}://{host}:{self.srv.port_for(self.case, scheme)}{path}"

    def get(self, url: str, *, jar: dict | None, origin: str | None = None, source: str = "entry") -> Response:
        hops: list[Response] = []
        for _ in range(10):
            p = urllib.parse.urlsplit(url)
            alias = self.hosts.get((p.hostname or "").lower())
            if alias is None:
                break
            req_headers = [("User-Agent", "Kashif-test"), ("Accept", "*/*")]
            if origin:
                req_headers.append(("Origin", origin))
            if jar:
                req_headers.append(("Cookie", "; ".join(f"{k}={v}" for k, v in jar.items())))
            hdrs = {k.lower(): [v] for k, v in req_headers}
            hits, case_hits = self.srv.count(self.case.id, alias, p.path or "/")
            req = corpus.Req(self.case, alias, p.path or "/", p.query, hdrs, p.scheme, hits, case_hits, self.srv,
                             p.netloc)
            r = self.srv.respond(req)
            per: dict = {}
            hl = []
            for name, value in r.headers:
                hl.append((name, corpus._render(value, req, per) if isinstance(value, str) else value.decode("latin-1")))
            body = r.body if isinstance(r.body, bytes) else corpus._render(r.body, req, per).encode("utf-8")
            resp = Response(url=url, status=r.status, headers=HeaderList(tuple(hl)), body=body,
                            request_headers=HeaderList(tuple(req_headers)), source=source)
            if jar is not None:
                for v in resp.headers.get_all("set-cookie"):
                    k, _, rest = v.partition("=")
                    jar[k.strip()] = rest.split(";", 1)[0]
            loc = resp.location
            if resp.status and 300 <= resp.status < 400 and loc:
                hops.append(resp)
                url = loc
                continue
            resp.chain = hops
            return resp
        last = hops.pop() if hops else Response(url=url, status=None, error="unroutable")
        last.chain = hops
        return last

    def context(self, make_ctx):
        c = self.case
        entry = self.get(self.url(c.path), jar={})
        kw: dict = {}
        if c.profile != "minimal":
            kw["cors"] = self.get(entry.url, jar=None, origin=corpus.CORS_PROBE_ORIGIN, source="cors")
        ctx = make_ctx(target=self.url(c.path), entry=None, profile=c.profile, sensitivity=c.sensitivity, **kw)
        ctx.entry = entry
        for r in ctx.all_responses():
            doc = htmlparse.parse_response(r) if r.essence in ("text/html", "") and r.body else None
            classify.classify(r, doc)
            if r is entry and r.kind == "document":
                ctx.pages.append(Page(r, doc, 0))
        ctx.csp = csp.parse_all(ctx)
        ctx.coverage = Coverage(csp.CHECKS)
        return ctx


@pytest.mark.parametrize("case", CORPUS_CASES, ids=[c.id for c in CORPUS_CASES])
def test_corpus_case_labels(case, make_ctx):
    ctx = _Sim(case).context(make_ctx)
    issues = _run(ctx)
    shown = [i for i in issues if ctx.options.reports(i.confidence)]
    for rule, want in case.labels.items():
        if rule not in OWN:
            continue
        got = [i for i in shown if i.rule == rule]
        assert bool(got) is want, f"{case.id}: {rule} expected {'to fire' if want else 'silent'}, got {got!r}"
    for key in ("severity", "max_severity", "confidence"):
        for rule, val in case.expect.get(key, {}).items():
            if rule not in OWN:
                continue
            got = [i for i in shown if i.rule == rule]
            assert got, f"{case.id}: {rule} did not fire"
            if key == "confidence":
                assert val in {i.confidence for i in got}
                continue
            sevs = [i.severity or rules.RULES[rule].severity for i in got]
            worst = max(sevs, key=SEV_RANK.__getitem__)
            assert (worst == val) if key == "severity" else SEV_RANK[worst] <= SEV_RANK[val], (case.id, rule, sevs)


def test_corpus_covers_the_c_csp_group():
    ids = {c.id for c in CORPUS_CASES}
    group = {c.id for c in corpus.CASES if c.group == "C-CSP"}
    assert group <= ids and len(group) >= 40
    fired = set()
    for c in corpus.CASES:
        fired |= {r for r, want in c.labels.items() if want and r in OWN}
    # every scored CSP rule that the corpus labels positively has a case here (WEB215/WEB219 are info/paranoid)
    assert fired >= OWN - {"WEB215", "WEB219"}


# ======================================================================================== adversarial review (WP4)

def test_hostile_report_to_nesting_does_not_crash(make_page, make_ctx):
    # json's C decoder raises RecursionError (not ValueError) on deep nesting; a header is up to 64 KB
    ctx = _doc_ctx(make_page, make_ctx, [("Content-Security-Policy", "default-src 'self'; report-to g"),
                                         ("Report-To", "[" * 60_000)])
    issues = _run(ctx)
    assert "WEB215" in {i.rule for i in issues}


@pytest.mark.parametrize("make_headers,html", [
    (lambda: [("Content-Security-Policy", ",".join("script-src 'self' https:" for _ in range(3000)))], None),
    (lambda: [], "<html><head>" + "<meta http-equiv='Content-Security-Policy' content=\"script-src 'self' https:\">"
     * 3000 + "</head><body></body></html>"),
])
def test_thousands_of_policies_stay_fast(make_page, make_ctx, make_headers, html):
    # Observatory's merge is quadratic: 400 <meta> policies took 6 s and 3000 never finished before the cap
    ctx = _doc_ctx(make_page, make_ctx, make_headers(), **({"html": html} if html else {}))
    t = time.perf_counter()
    issues = _run(ctx)
    assert time.perf_counter() - t < 3.0
    assert "WEB042" in {i.rule for i in issues}
    assert ctx.observatory["content-security-policy"] == "csp-implemented-with-unsafe-inline"


def test_observatory_parser_caps_hostile_sources():
    pols = ["script-src " + " ".join(f"https://h{j}.e{i}.com/p/" for j in range(2000)) for i in range(40)]
    t = time.perf_counter()
    csp.obs_parse_csp(pols)
    assert time.perf_counter() - t < 2.0


def test_long_directive_keeps_late_keywords():
    # real allowlists can run to hundreds of hosts; a keyword after the 400th source used to be dropped
    hosts = " ".join(f"https://h{i}.example.com" for i in range(600))
    hits = _eval(f"script-src {hosts} 'unsafe-inline'; object-src 'none'; base-uri 'none'")
    assert "WEB040" in _rules(hits)


def test_non_ascii_script_src_is_medium_when_it_disables_scripts():
    (p,) = _pols("script-src ’self’; object-src 'none'")      # curly quotes pasted from a word processor
    (e,) = [e for e in p.errors if e["code"] == "non_ascii"]
    assert e["severity"] == "medium" and e.get("ineffective")
    (p,) = _pols("default-src 'self'; script-src ’self’")    # default-src still restricts scripts
    (e,) = [e for e in p.errors if e["code"] == "non_ascii"]
    assert e["severity"] == "low"


@pytest.mark.parametrize("source,fires", [
    ("http://localhost:3000", False), ("http://127.0.0.1:8080", False), ("http://*.localhost", False),
    ("http://cdn.example.com", True), ("http:", True), ("http://127.example.com", True),
])
def test_web211_loopback_sources_are_not_insecure(source, fires):
    hits = _eval(f"default-src 'self'; connect-src 'self' {source}; object-src 'none'; base-uri 'none'")
    assert ("WEB211" in _rules(hits)) is fires


def test_web218_shows_the_restrictive_policy():
    hits = _eval("default-src *", "script-src 'self' https://cdn.example.com")
    assert _hit(hits, "WEB218").value == "'self' https://cdn.example.com"


@pytest.mark.parametrize("html", [
    "<html><head><title>x</title></head><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'\">"
    "<body><script>1</script></body></html>",
    "<html><head></head>\n<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'\"><body></body></html>",
])
def test_meta_between_head_and_body_is_enforced(make_page, make_ctx, html):
    # the HTML tree builder re-inserts a <meta> found "after head" into <head>, so browsers apply its policy
    issues = _run(_doc_ctx(make_page, make_ctx, [], html=html))
    assert "WEB-content-security-policy" not in {i.rule for i in issues}


def test_web208_ignores_data_blocks(make_page, make_ctx):
    meta = "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'\">"
    ld = f"<html><head><script type=\"application/ld+json\">{{}}</script>{meta}</head><body></body></html>"
    assert "WEB208" not in {i.rule for i in _run(_doc_ctx(make_page, make_ctx, [], html=ld))}
    mod = f"<html><head><script type=module src=/a.js></script>{meta}</head><body></body></html>"
    assert "WEB208" in {i.rule for i in _run(_doc_ctx(make_page, make_ctx, [], html=mod))}


def test_web217_meta_policy_counts_as_standard_csp(make_page, make_ctx):
    html = ("<html><head><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'\"></head>"
            "<body></body></html>")
    issues = _run(_doc_ctx(make_page, make_ctx, [("X-WebKit-CSP", "default-src 'self'")], html=html))
    (i,) = [i for i in issues if i.rule == "WEB217"]
    assert i.severity is None
    assert not any("no standard" in en for en, _ar in i.notes)


def test_paranoid_error_page_with_report_only_is_not_missing_csp(make_response, make_ctx):
    err = make_response("https://example.test/x", status=404, body="<html><body><script>1</script></body></html>",
                        headers=[("Content-Security-Policy-Report-Only", "default-src 'self'")],
                        content_type="text/html", kind="error_page")
    issues = _run(make_ctx(entry=err, sensitivity="paranoid"))
    assert "WEB-content-security-policy" not in {i.rule for i in issues}


def test_web212_evidence_names_the_targets_policy(make_response, make_ctx):
    nonce = "N" * 60                                   # longer than the 40-character display cut
    hdr = f"script-src 'nonce-{nonce}' 'strict-dynamic'; object-src 'none'; base-uri 'none'"
    a = make_response("https://example.test/", headers=[("Content-Security-Policy", "img-src 'self'"),
                                                        ("Content-Security-Policy", hdr), ("Cache-Control", "no-store")],
                      body="<html><body></body></html>", content_type="text/html", kind="document")
    b = make_response("https://example.test/", headers=[("Content-Security-Policy", hdr)],
                      body="<html><body></body></html>", content_type="text/html", kind="document", source="cors")
    ctx = make_ctx(entry=a, cors=b)
    (i,) = [i for i in _run(ctx) if i.rule == "WEB212"]
    assert nonce in i.evidence.match["value"]


def test_treat_as_public_address_is_a_known_directive():
    assert _codes("default-src 'self'; treat-as-public-address") == []
    assert _codes("default-src 'self'; treat-as-public-addres") == ["unknown_typo"]


def test_random_policies_never_crash_or_leak_controls(make_response, make_ctx):
    import random
    rnd = random.Random(1101)
    atoms = ["script-src", "default-src", "object-src", "base-uri", "form-action", "frame-ancestors", "report-to",
             "'self'", "'none'", "'unsafe-inline'", "'unsafe-eval'", "'strict-dynamic'", "'nonce-", "'sha256-", "https:",
             "http:", "*", "data:", "https://www.google.com", ";", ",", " ", "\r\n ", "'", "\x00", "\x1b[2J", "’",
             "%E0", "[::1]", "127.0.0.1", ":99999999999999999999", "/p/", "sandbox", "x" * 300, "SCRIPT-SRC",
             "script-src:", "plugin-types", "http://localhost:*"]
    for _ in range(150):
        pol = "".join(rnd.choice(atoms) + rnd.choice(["", " ", ";"]) for _ in range(rnd.randint(0, 25)))
        meta = pol.replace('"', "")
        body = (f"<html><head><script>1</script><meta http-equiv=Content-Security-Policy content=\"{meta}\"></head>"
                "<body><form><input type=password></form></body></html>")
        hdrs = [(rnd.choice(["Content-Security-Policy", "Content-Security-Policy-Report-Only", "X-WebKit-CSP",
                             "Report-To", "Reporting-Endpoints", "Cache-Control"]), pol) for _ in range(3)]
        r = make_response("https://example.test/", headers=hdrs, body=body, content_type="text/html", kind="document")
        c = make_response("https://example.test/", headers=hdrs, body=body, content_type="text/html", kind="document",
                          source="cors")
        for i in _run(make_ctx(entry=r, cors=c, sensitivity=rnd.choice(["default", "paranoid"]))):
            for en, ar in i.notes:
                assert "\x1b" not in en + ar and "\x00" not in en + ar


def test_folded_csp_header_is_an_info_syntax_note(make_page, make_ctx):
    page = make_page("<html><body><script>1</script></body></html>",
                     headers=[("Content-Security-Policy", "default-src 'self'; object-src 'none'; base-uri 'none'")],
                     flags={"obs-fold", "obs-fold:content-security-policy"})
    ctx = make_ctx(entry=page)
    (i,) = [i for i in _run(ctx) if i.rule == "WEB201"]
    assert i.severity == "info" and any("folded" in en for en, _ar in i.notes)


def test_huge_port_does_not_crash():
    # int() of more than 4300 digits raises ValueError on 3.11+; a port beyond 65535 is an invalid source
    hits = _eval("script-src https://www.google.com:" + "9" * 5000 + "; object-src 'none'; base-uri 'none'")
    assert "WEB209" not in _rules(hits)
    assert "invalid_source" in _codes("script-src a.example:65536")
    src = csp.classify_source("https://www.google.com:0443")
    assert src.port == "443" and csp.source_matches_url(src, "https://www.google.com/x", "https://e.test")
