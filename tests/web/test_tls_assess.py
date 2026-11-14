"""tls/assess.py: rules, tri-state coverage, verify-code mapping, SSL Labs-compatible grade, Mozilla 6.0 conformance
(spec §2.8, §3.4 c, WP10). Pure: synthetic ``ctx.tls`` reports built from the fixture certificates, no sockets."""

from __future__ import annotations

import base64
import copy
import dataclasses
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from vulnscan.webscan import coverage, rules, tls
from vulnscan.webscan.tls import assess, x509
from vulnscan.webscan.types import HstsVerdict, ScanContext, ScanOptions

CERTS = Path(__file__).resolve().parent.parent / "data" / "web" / "certs"
NOW = datetime(2026, 11, 13, 12, 0, 0, tzinfo=timezone.utc)


def b64(name: str) -> str:
    der = x509.pem_to_der_list((CERTS / name).read_text(encoding="ascii"))[0]
    return base64.b64encode(der).decode("ascii")


def chain(*names: str) -> list[str]:
    return [b64(n) for n in names]


GOOD_VERSIONS = {"TLSv1.3": "yes", "TLSv1.2": "yes", "TLSv1.1": "no", "TLSv1.0": "no", "SSLv3": "no", "SSLv2": "no"}
GOOD_CATS = {"null_anon": "no", "export_des": "no", "rc4": "no", "3des": "no", "krsa": "no", "cbc": "no", "aead": "yes"}


def ip_report(*, versions=None, cats=None, sent=("leaf.pem", "int.pem"), verified=True, code=None, message="",
              verified_chain=("leaf.pem", "int.pem", "root.pem"), ocsp=None, tls_scts=(), compression=False, reneg=True,
              higher=(), deep=None, chosen=None, legacy=None, ip="192.0.2.1", chain_source="ssl") -> dict:
    vs = {**GOOD_VERSIONS, **(versions or {})}
    cs = {**GOOD_CATS, **(cats or {})}
    cipher_for = {"null_anon": "TLS_RSA_WITH_NULL_SHA", "export_des": "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
                  "rc4": "TLS_RSA_WITH_RC4_128_SHA", "3des": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                  "krsa": "TLS_RSA_WITH_AES_128_GCM_SHA256", "cbc": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
                  "aead": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}
    ver = {"ok": verified, "verify_code": code, "verify_message": message, "version": "TLSv1.3",
           "cipher": "TLS_AES_128_GCM_SHA256", "alpn": "h2", "chain": chain(*sent), "chain_complete": True,
           "verified_chain": chain(*verified_chain) if verified is True else None, "error": None, "refused": None}
    if verified is None:
        ver["error"] = "SSLError: handshake failure"
    tls12 = vs.get("TLSv1.2") == "yes"
    cat_version = "TLSv1.2" if tls12 else ("TLSv1.0" if vs.get("TLSv1.0") == "yes" else None)
    return {
        "ip": ip, "status": "ok", "reason": "", "detail": "", "verified": ver, "unverified": None, "verified_legacy": legacy,
        "chain": chain(*sent), "chain_source": chain_source,
        "versions": {k: ({"state": v, "cipher": (chosen or {}).get(k)} if v != "inconclusive" else
                         {"state": v, "reason": "timeout"}) for k, v in vs.items()},
        "higher_version": list(higher), "downgrade_sentinel": None,
        "categories": ({k: ({"state": v, "cipher": cipher_for[k], "version": cat_version} if v == "yes" else
                            {"state": v, "reason": "timeout"} if v == "inconclusive" else {"state": v})
                        for k, v in cs.items()} if cat_version else
                       {k: {"state": "not_applicable", "reason": "tls13_only"} for k in cs}),
        "category_version": cat_version, "renegotiation_info": reneg if cat_version else None,
        "compression": compression if cat_version else None,
        "ocsp": ocsp or ({"state": "absent", "der": None, "reason": ""} if cat_version else
                         {"state": "not_tested", "der": None, "reason": "tls13_encrypted"}),
        "tls_scts": list(tls_scts), "chosen": dict(chosen or {}), "deep": dict(deep or {}), "handshakes": 14,
        "backoff": False, "notes": [],
    }


def host_report(*ips: dict, host="localhost", port=443, proxied=False, test_ca=None) -> dict:
    return {"kind": "kashif-tls-host", "host": host, "port": port, "proxied": proxied,
            "proxy": "http://proxy.example:3128" if proxied else None, "profile": "standard",
            "ips": {r["ip"] or "proxy": r for r in ips}, "not_sampled": [], "error": None, "leaf": {},
            "test_ca": test_ca}


class Data:
    """``ctx.data`` stub: the bundled TLS data files, with an optional fixed CT log list and date."""

    def __init__(self, logs=None, ct_date=None):
        from vulnscan.webscan import data
        self._real = data
        self.logs = logs
        self.ct_date = ct_date

    def load_json(self, name):
        if name == "ct-logs.json" and self.logs is not None:
            return {"meta": {}, "logs": self.logs}
        return self._real.load_json(name)

    def file_date(self, name):
        if name == "ct-logs.json" and self.ct_date is not None:
            return self.ct_date
        return self._real.file_date(name)


def run(*ips: dict, now=NOW, profile="standard", sensitivity="default", data=None, hsts=None, **host_kw):
    ctx = ScanContext(options=ScanOptions(profile=profile, sensitivity=sensitivity), target="https://localhost/",
                      now=now, coverage=coverage.Coverage(), data=data or Data())
    rep = host_report(*ips, **host_kw)
    ctx.tls[rep["host"]] = rep
    if hsts is not None:
        ctx.hsts[rep["host"]] = hsts
    issues = tls.run(ctx)
    for i in issues:
        assert rules.validate_issue(i) == [], (i.rule, rules.validate_issue(i))
        assert i.evidence.match["where"] == "tls" and i.evidence.curl.startswith("openssl s_client")
    return issues, ctx


def fired(issues, rule):
    return [i for i in issues if i.rule == rule]


def state(ctx, check):
    return ctx.coverage.state(check).state


# ----------------------------------------------------------------------------------------------- baseline

def test_good_server_has_no_findings_and_every_check_has_a_state():
    # the fixture leaf lives 20 years and names an OCSP responder: judged as a private test CA here
    issues, ctx = run(ip_report(), test_ca={"publicly_trusted": False, "ct_required": False})
    bad = [i.rule for i in issues if i.rule not in ("WEB714", "WEB718")]
    assert bad == []
    assert [i.severity for i in fired(issues, "WEB714")] == ["info"]
    states = {c: state(ctx, c) for c in tls.CHECKS}
    assert states["WEB030"] == states["WEB704"] == states["WEB705"] == states["WEB706"] == "pass"
    assert states["WEB070"] == states["WEB700"] == states["WEB701"] == states["WEB072"] == "pass"
    assert states["WEB710"] == "not_tested" and states["WEB719"] == "not_tested"     # deep / paranoid only
    assert states["WEB715"] == "not_applicable"                                       # one IP
    assert all(s in ("pass", "not_tested", "not_applicable", "fail") for s in states.values())


def test_no_tls_data():
    ctx = ScanContext(options=ScanOptions(), target="http://example.test/", coverage=coverage.Coverage())
    assert tls.run(ctx) == []
    assert state(ctx, "WEB030") == "not_applicable"
    ctx = ScanContext(options=ScanOptions(), target="https://example.test/", coverage=coverage.Coverage())
    assert tls.run(ctx) == []
    assert state(ctx, "WEB070") == "not_tested"


# ----------------------------------------------------------------------------------------------- verify-code mapping

def test_code_62_is_web700_with_san_evidence():
    issues, ctx = run(ip_report(verified=False, code=62, message="Hostname mismatch"), host="other.example")
    f = fired(issues, "WEB700")
    assert len(f) == 1 and f[0].severity == "high" and f[0].confidence == "certain"
    assert "localhost" in f[0].evidence.match["value"]
    assert not fired(issues, "WEB072") and state(ctx, "WEB701") == "pass"


def test_cn_only_certificate_is_web700_not_web717():
    issues, _ = run(ip_report(sent=("cnonly.pem", "int.pem"), verified=False, code=62))
    assert fired(issues, "WEB700") and not fired(issues, "WEB717")


def test_code_10_and_9_from_the_der():
    leaf = x509.parse_certificate(base64.b64decode(b64("leaf.pem")))
    issues, _ = run(ip_report(verified=False, code=10), now=leaf.not_after + timedelta(days=3))
    assert fired(issues, "WEB070") and not fired(issues, "WEB072") and not fired(issues, "WEB700")
    issues, ctx = run(ip_report(verified=False, code=9), now=leaf.not_before - timedelta(days=3))
    assert fired(issues, "WEB720") and not fired(issues, "WEB070") and state(ctx, "WEB071") == "not_applicable"
    issues, _ = run(ip_report(verified=False, code=9), now=leaf.not_before - timedelta(minutes=4))
    assert not fired(issues, "WEB720")                              # 5-minute clock-skew allowance


def test_expiry_is_reported_even_when_verification_fails_otherwise():
    leaf = x509.parse_certificate(base64.b64decode(b64("selfsigned.pem")))
    issues, _ = run(ip_report(sent=("selfsigned.pem",), verified=False, code=18), now=leaf.not_after + timedelta(days=1))
    assert fired(issues, "WEB070") and fired(issues, "WEB701")    # D21: expiry from the unverified chain


def test_self_signed_and_untrusted_chain():
    issues, _ = run(ip_report(sent=("selfsigned.pem",), verified=False, code=18))
    f = fired(issues, "WEB701")
    assert len(f) == 1 and f[0].confidence == "certain" and not fired(issues, "WEB072")
    issues, _ = run(ip_report(sent=("leaf.pem", "int.pem", "root.pem"), verified=False, code=19))
    assert fired(issues, "WEB701")[0].confidence == "certain"


def test_code_20_leaf_only_is_incomplete_chain():
    issues, ctx = run(ip_report(sent=("leaf.pem",), verified=False, code=20))
    f = fired(issues, "WEB702")
    assert len(f) == 1 and f[0].confidence == "firm" and f[0].severity == "medium"
    assert not fired(issues, "WEB701") and state(ctx, "WEB701") == "not_tested"


def test_code_20_with_intermediates_is_incomplete_chain_or_private_ca():
    issues, _ = run(ip_report(sent=("leaf.pem", "int.pem"), verified=False, code=20))
    f = fired(issues, "WEB701")
    assert len(f) == 1 and f[0].confidence == "tentative" and not fired(issues, "WEB702")


def test_store_supplied_intermediate_is_web702():
    issues, _ = run(ip_report(sent=("leaf.pem",), verified=True))     # verified chain had the intermediate
    f = fired(issues, "WEB702")
    assert len(f) == 1 and "Kashif Test Intermediate" in f[0].evidence.match["value"]


def test_other_codes_are_web072():
    issues, _ = run(ip_report(sent=("clientauth.pem", "int.pem"), verified=False, code=26,
                              message="unsuitable certificate purpose"))
    f = fired(issues, "WEB072")
    assert len(f) == 1 and "26" in f[0].evidence.match["value"]
    assert not fired(issues, "WEB700") and not fired(issues, "WEB701")


def test_strict_only_code_85_is_only_a_note():
    # D19: Python 3.13's VERIFY_X509_STRICT rejects a leaf without AKI (code 85); browsers accept it
    issues, ctx = run(ip_report(sent=("noaki.pem", "int.pem"), verified=False, code=85,
                                message="Missing Authority Key Identifier"))
    assert not fired(issues, "WEB072") and state(ctx, "WEB072") == "pass"
    assert any("strict" in n[0] for n in ctx.inventory["tls"]["localhost"]["notes"])


def test_weak_digest_code_68_is_judged_again_at_security_level_0():
    legacy = {"ok": True, "verify_code": None, "verify_message": "", "version": "TLSv1.3", "cipher": "x", "alpn": None,
              "chain": chain("sha1leaf.pem", "int.pem"), "chain_complete": True,
              "verified_chain": chain("sha1leaf.pem", "int.pem", "root.pem"), "error": None, "refused": None}
    issues, ctx = run(ip_report(sent=("sha1leaf.pem", "int.pem"), verified=False, code=68, legacy=legacy))
    # the security-level-0 retry judges only the rest of the chain (trusted, so no WEB701/WEB702); browsers still
    # reject the SHA-1 chain, so WEB072 is high with the reason, and the SSL Labs-compatible grade is T
    f = fired(issues, "WEB072")
    assert len(f) == 1 and f[0].severity == "high"
    assert f[0].evidence.match["value"].startswith("rejected by browsers: SHA-1 or weak key in chain")
    assert any("verify code 68" in n[0] and "ترفضها المتصفحات" in n[1] for n in f[0].notes)
    assert not fired(issues, "WEB701") and not fired(issues, "WEB702")
    f = fired(issues, "WEB708")
    assert len(f) == 1 and f[0].severity == "medium"
    g = ctx.inventory["tls"]["localhost"]["ips"]["192.0.2.1"]["ssllabs"]
    assert g["grade"] == "T" and g["caps"][0]["cap"] == "T" and "certificate not trusted" in g["caps"][0]["en"]


def test_verification_impossible_is_not_tested_never_pass():
    issues, ctx = run(ip_report(verified=None))
    assert not fired(issues, "WEB072")
    for c in ("WEB072", "WEB701", "WEB702", "WEB709", "WEB713"):
        assert state(ctx, c) == "not_tested", c
    assert state(ctx, "WEB700") == "pass"          # judged from the DER (RFC 6125 without CN fallback)


# ----------------------------------------------------------------------------------------------- dates

@pytest.mark.parametrize("lifetime,remaining,expect", [
    (398, 31, None), (398, 29, "low"), (398, 15, "low"), (398, 13, "medium"),
    (90, 25, None), (90, 16, None), (90, 14, "low"), (90, 9.5, "low"), (90, 8.9, "medium"),
    (47, 8, None), (47, 7.7, "low"), (47, 4.8, "low"), (47, 4.6, "medium"),
    (6, 1.1, None), (6, 0.9, "low"), (6, 0.61, "low"), (6, 0.59, "medium"),
])
def test_web071_thresholds_are_relative_to_the_lifetime(lifetime, remaining, expect):
    base = x509.parse_certificate(base64.b64decode(b64("leaf.pem")))
    start = NOW - timedelta(days=lifetime - remaining)
    cert = dataclasses.replace(base, not_before=start, not_after=start + timedelta(days=lifetime))
    out = assess._Ip("192.0.2.1")
    assess._dates(out, cert, NOW)
    got = [c["severity"] for (r, _g), c in out.cands.items() if r == "WEB071"]
    assert got == ([expect] if expect else [])
    if expect:
        assert out.cands[("WEB071", "expires_soon")]["params"]["days"] == int(remaining)


def test_web071_title_keeps_n_days():
    meta = rules.RULES["WEB071"]
    assert meta.title("en", days=9) == "TLS certificate expires in 9 days"
    assert "9" in meta.title("ar", days=9)


@pytest.mark.parametrize("issued,days,limit_hit", [
    ("2026-01-10", 398, False), ("2026-01-10", 399, True), ("2026-04-01", 200, False), ("2026-04-01", 201, True),
    ("2027-04-01", 100, False), ("2027-04-01", 101, True), ("2029-04-01", 47, False), ("2029-04-01", 48, True),
])
def test_web709_cab_forum_limits(issued, days, limit_hit):
    base = x509.parse_certificate(base64.b64decode(b64("leaf.pem")))
    nb = datetime.fromisoformat(issued).replace(tzinfo=timezone.utc)
    cert = dataclasses.replace(base, not_before=nb, not_after=nb + timedelta(days=days) - timedelta(seconds=1))
    out = assess._Ip("192.0.2.1")
    assess._lifetime(out, cert, True, True, True)
    assert (("WEB709", f"limit{assess._limit_for(nb)}") in out.cands) is limit_hit
    out = assess._Ip("192.0.2.1")
    assess._lifetime(out, cert, False, False, True)          # private CA: not judged
    assert not out.cands and out.states["WEB709"][0] == "not_applicable"


# ----------------------------------------------------------------------------------------------- chain order

@pytest.mark.parametrize("sent,sev,groups", [
    (("leaf.pem", "int.pem"), None, None),
    (("leaf.pem", "int.pem", "root.pem"), "info", "anchor"),
    (("leaf.pem", "root.pem", "int.pem"), "low", "anchor+order"),
    (("leaf.pem", "int.pem", "int.pem"), "info", "duplicate"),
    (("leaf.pem", "int.pem", "ecleaf.pem"), "info", "extra"),
])
def test_web703_chain_order(sent, sev, groups):
    issues, _ = run(ip_report(sent=sent))
    f = fired(issues, "WEB703")
    if sev is None:
        assert not f
    else:
        assert len(f) == 1 and f[0].severity == sev and f[0].group_value == groups


def test_web703_not_judged_with_leaf_only_chain_api():
    issues, ctx = run(ip_report(chain_source="ssl_leaf", sent=("leaf.pem",)))
    assert not fired(issues, "WEB703") and state(ctx, "WEB703") == "not_tested"
    assert state(ctx, "WEB702") == "not_tested"


# ----------------------------------------------------------------------------------------------- keys and signatures

@pytest.mark.parametrize("name,sev,group", [
    ("rsa1024leaf.pem", "high", "rsa_small"), ("roca-leaf.pem", "critical", "roca"),
    ("roca-sample-positive.pem", "critical", "roca"), ("fermat-leaf.pem", "critical", "fermat"),
    ("leaf.pem", None, None), ("ecleaf.pem", None, None),
])
def test_web707_keys(name, sev, group):
    issues, _ = run(ip_report(sent=(name,)))
    f = fired(issues, "WEB707")
    if sev is None:
        assert not f
    else:
        assert f[0].severity == sev and f[0].group_value == group


def test_web707_exponent_one_and_odd_size():
    base = x509.parse_certificate(base64.b64decode(b64("leaf.pem")))
    out = assess._Ip("x")
    assess._key(out, dataclasses.replace(base, rsa_exponent=1))
    assert out.cands[("WEB707", "exp1")]["severity"] == "critical"
    out = assess._Ip("x")
    assess._key(out, dataclasses.replace(base, key_bits=2049, rsa_modulus=(1 << 2048) + 3))
    assert out.cands[("WEB707", "odd_size")]["severity"] == "info"
    out = assess._Ip("x")
    assess._key(out, dataclasses.replace(base, key_type="EC", key_bits=192, curve="secp192r1", rsa_modulus=None))
    assert out.cands[("WEB707", "ec_small")]["severity"] == "high"


def test_web708_signatures():
    issues, _ = run(ip_report(sent=("sha1leaf.pem", "int.pem")))
    assert fired(issues, "WEB708")[0].severity == "medium"
    base = x509.parse_certificate(base64.b64decode(b64("leaf.pem")))
    out = assess._Ip("x")
    assess._signatures(out, [dataclasses.replace(base, sig_alg="md5WithRSAEncryption")])
    assert out.cands[("WEB708", "md5")]["severity"] == "high"
    root = x509.parse_certificate(base64.b64decode(b64("root.pem")))
    out = assess._Ip("x")
    assess._signatures(out, [base, dataclasses.replace(root, sig_alg="sha1WithRSAEncryption")])
    assert not out.cands                         # a root's self-signature is never checked by clients


# ----------------------------------------------------------------------------------------------- protocols

def test_web030_one_finding_per_version_like_1_0_1():
    issues, _ = run(ip_report(versions={"TLSv1.0": "yes", "TLSv1.1": "yes"},
                              chosen={"TLSv1.0": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"}))
    f = fired(issues, "WEB030")
    assert sorted(i.params["versions"] for i in f) == ["TLS 1.0", "TLS 1.1"]
    assert rules.RULES["WEB030"].title("en", **f[0].params).startswith("Server accepts TLS 1.")
    assert all(i.severity == "medium" for i in f)
    assert "-tls1" in f[0].evidence.curl or "-tls1_1" in f[0].evidence.curl
    assert fired(issues, "WEB706") and fired(issues, "WEB706")[0].group_value == "cbc_tls10"


def test_web030_inconclusive_is_not_tested_never_pass():
    issues, ctx = run(ip_report(versions={"TLSv1.0": "inconclusive", "TLSv1.1": "no"}))
    assert not fired(issues, "WEB030") and state(ctx, "WEB030") == "not_tested"
    reasons = ctx.coverage.state("WEB030").reasons
    assert reasons and reasons[0][0] == "timeout" and reasons[0][2]


def test_every_hello_refused_is_not_tested():
    vs = {k: "no" for k in GOOD_VERSIONS}
    issues, ctx = run(ip_report(versions=vs, verified=None))
    assert not fired(issues, "WEB705") and not fired(issues, "WEB718")
    assert state(ctx, "WEB705") == "not_tested" and state(ctx, "WEB030") == "not_tested"


@pytest.mark.parametrize("v12,v13,sev,versions", [
    ("no", "no", "high", ["TLS 1.2", "TLS 1.3"]), ("yes", "no", "low", ["TLS 1.3"]), ("no", "yes", None, None),
    ("yes", "yes", None, None),
])
def test_web705(v12, v13, sev, versions):
    extra = {"TLSv1.0": "yes"} if v12 == "no" and v13 == "no" else {}
    issues, _ = run(ip_report(versions={"TLSv1.2": v12, "TLSv1.3": v13, **extra}))
    f = fired(issues, "WEB705")
    if sev is None:
        assert not f
    else:
        assert f[0].severity == sev and f[0].params["versions"] == versions
        # a list parameter: each language joins it ("TLS 1.2 and TLS 1.3" / "TLS 1.2 ولا TLS 1.3")
        meta = rules.RULES["WEB705"]
        if len(versions) == 2:
            assert f[0].params["variant"] == "no12no13"
            assert meta.title("en", **f[0].params) == "TLS 1.2 and TLS 1.3 not supported"
            assert meta.title("ar", **f[0].params) == "لا دعم لـ TLS 1.2 ولا TLS 1.3"
        else:
            assert "variant" not in f[0].params and meta.title("en", **f[0].params) == "TLS 1.3 not supported"


def test_web704_sslv2_critical_sslv3_high():
    issues, _ = run(ip_report(versions={"SSLv2": "yes", "SSLv3": "yes"}))
    sev = {i.params["versions"]: i.severity for i in fired(issues, "WEB704")}
    assert sev == {"SSLv2": "critical", "SSLv3": "high"}


def test_web716_higher_version():
    issues, _ = run(ip_report(higher=[{"offered": "TLSv1.0", "answered": "TLSv1.2"}]))
    assert fired(issues, "WEB716")[0].severity == "low"


@pytest.mark.parametrize("cat,sev", [("rc4", "high"), ("3des", "medium"), ("krsa", "low"), ("null_anon", "high"),
                                     ("export_des", "high")])
def test_web706_categories(cat, sev):
    issues, _ = run(ip_report(cats={cat: "yes"}))
    f = fired(issues, "WEB706")
    assert len(f) == 1 and f[0].severity == sev


def test_web706_no_aead_and_server_preference_and_tls13_only():
    issues, _ = run(ip_report(versions={"TLSv1.3": "no"}, cats={"aead": "no", "cbc": "yes"}))
    assert [i.group_value for i in fired(issues, "WEB706")] == ["no_aead"]
    issues, _ = run(ip_report(cats={"krsa": "yes"}, deep={"server_preference": True,
                                                          "preferred": "TLS_RSA_WITH_AES_128_GCM_SHA256"}))
    assert {i.group_value for i in fired(issues, "WEB706")} == {"krsa", "prefers_krsa"}
    issues, ctx = run(ip_report(versions={"TLSv1.2": "no"}))
    assert not fired(issues, "WEB706") and state(ctx, "WEB706") == "pass"
    assert state(ctx, "WEB711") == "not_applicable" and state(ctx, "WEB712") == "not_applicable"


def test_web706_inconclusive_and_minimal_profile():
    issues, ctx = run(ip_report(cats={"rc4": "inconclusive"}))
    assert not fired(issues, "WEB706") and state(ctx, "WEB706") == "not_tested"
    issues, ctx = run(ip_report(), profile="minimal")
    assert state(ctx, "WEB706") == "not_tested" and ctx.coverage.state("WEB706").reasons[0][0] == "profile"


def test_web711_web712():
    issues, _ = run(ip_report(compression=True, reneg=False))
    assert fired(issues, "WEB711")[0].severity == "high"
    assert fired(issues, "WEB712")[0].severity == "low"
    issues, ctx = run(ip_report(compression=None, reneg=None))
    assert state(ctx, "WEB711") == "not_tested" and state(ctx, "WEB712") == "not_tested"


# ----------------------------------------------------------------------------------------------- OCSP and CT

def _ocsp(name):
    return {"state": "stapled", "der": base64.b64encode((CERTS / name).read_bytes()).decode(), "reason": ""}


def test_web714_variants():
    good = x509.parse_ocsp_response((CERTS / "ocsp-good.der").read_bytes())
    issues, _ = run(ip_report(ocsp=_ocsp("ocsp-revoked.der")), now=good.this_update)
    assert fired(issues, "WEB714")[0].severity == "high"
    issues, _ = run(ip_report(ocsp=_ocsp("ocsp-good.der")), now=good.next_update + timedelta(hours=1))
    assert fired(issues, "WEB714")[0].group_value == "expired"
    issues, _ = run(ip_report(ocsp=_ocsp("ocsp-good.der")), now=good.this_update)
    assert not fired(issues, "WEB714")
    issues, _ = run(ip_report(sent=("muststaple.pem", "int.pem")))
    assert fired(issues, "WEB714")[0].severity == "medium"
    issues, _ = run(ip_report())                     # OCSP URL, no staple: optional since CA/B SC-063
    assert fired(issues, "WEB714")[0].severity == "info"
    issues, ctx = run(ip_report(sent=("muststaple.pem", "int.pem"), versions={"TLSv1.2": "no"}))
    assert not fired(issues, "WEB714") and state(ctx, "WEB714") == "not_tested"
    assert ctx.coverage.state("WEB714").reasons[0][0] == "tls13_encrypted"


LOGS = {base64.b64encode(bytes(range(32))).decode(): {"operator": "Op A", "state": "usable"},
        base64.b64encode(bytes(range(32, 64))).decode(): {"operator": "Op B", "state": "qualified"}}


def test_web713_ct_policy():
    test_ca = {"publicly_trusted": True, "ct_required": True}
    sct_leaf = ("sctleaf.pem", "int.pem")
    issues, _ = run(ip_report(), test_ca=test_ca, data=Data(LOGS, NOW.date()))
    assert fired(issues, "WEB713")[0].severity == "medium"           # publicly trusted, no SCT anywhere
    lab = x509.parse_certificate(base64.b64decode(b64("sctleaf.pem")))
    now = lab.not_before + timedelta(days=2)
    issues, ctx = run(ip_report(sent=sct_leaf, verified_chain=sct_leaf + ("root.pem",)), test_ca=test_ca,
                      data=Data(LOGS, now.date()), now=now)
    assert not fired(issues, "WEB713") and state(ctx, "WEB713") == "pass"   # 2 SCTs, 2 operators, lifetime ≤ 180 d
    one_op = {k: {**v, "operator": "Op A"} for k, v in LOGS.items()}
    issues, _ = run(ip_report(sent=sct_leaf, verified_chain=sct_leaf + ("root.pem",)), test_ca=test_ca,
                    data=Data(one_op, now.date()), now=now)
    f = fired(issues, "WEB713")
    assert f[0].severity == "low" and f[0].confidence == "firm"
    issues, _ = run(ip_report(sent=sct_leaf, verified_chain=sct_leaf + ("root.pem",)), test_ca=test_ca,
                    data=Data(one_op, (now - timedelta(days=200)).date()), now=now)
    assert fired(issues, "WEB713")[0].confidence == "tentative"      # bundled log list older than 120 days


def test_web713_not_applicable_for_private_or_ct_exempt_test_ca():
    issues, ctx = run(ip_report(), test_ca={"publicly_trusted": True, "ct_required": False})
    assert not fired(issues, "WEB713") and state(ctx, "WEB713") == "not_applicable"
    issues, ctx = run(ip_report(), test_ca={"publicly_trusted": False, "ct_required": True})
    assert state(ctx, "WEB713") == "not_applicable" and state(ctx, "WEB709") == "not_applicable"
    assert state(ctx, "WEB702") == "not_applicable"


# ----------------------------------------------------------------------------------------------- names

def test_web717_wildcard_and_many_sans():
    issues, _ = run(ip_report(sent=("wildcard.pem", "int.pem")), host="a.kashif.test")
    f = fired(issues, "WEB717")
    assert f and f[0].group_value == "wildcard" and f[0].severity == "info"
    issues, _ = run(ip_report(sent=("manysan.pem", "int.pem")), host="h1.kashif.test")
    assert fired(issues, "WEB717")[0].group_value == "many_sans"


# ----------------------------------------------------------------------------------------------- deep / paranoid

def test_web710_dh_and_common_prime():
    import hashlib
    from vulnscan.webscan.tls.assess import COMMON_DH_PRIMES
    p = COMMON_DH_PRIMES["oakley-group-2"]
    sha = hashlib.sha256(p.to_bytes(128, "big")).hexdigest()
    issues, _ = run(ip_report(deep={"dh_bits": 1024, "dh_prime_sha256": sha}), profile="deep")
    f = fired(issues, "WEB710")
    assert f[0].severity == "medium" and any("Logjam" in n[0] for n in f[0].notes)
    issues, _ = run(ip_report(deep={"dh_bits": 768}), profile="deep")
    assert fired(issues, "WEB710")[0].severity == "high"
    issues, ctx = run(ip_report(deep={"dh_bits": None}), profile="deep")
    assert not fired(issues, "WEB710") and state(ctx, "WEB710") == "pass"
    issues, ctx = run(ip_report(deep={"dh_bits": 1024}))
    assert state(ctx, "WEB710") == "not_tested"                     # not in the standard profile


def test_oakley_prime_is_the_real_safe_prime():
    p = assess.COMMON_DH_PRIMES["oakley-group-2"]
    assert p.bit_length() == 1024
    for a in (2, 3, 5, 7, 11, 13):                                    # Fermat test: a typo would not pass
        assert pow(a, p - 1, p) == 1
        assert pow(a, (p - 1) // 2 - 1, (p - 1) // 2) == 1


def test_web719_paranoid_and_deep_only():
    rep = ip_report(deep={"groups": {"X25519MLKEM768": False, "x25519": True}})
    issues, ctx = run(copy.deepcopy(rep), profile="deep", sensitivity="paranoid")
    assert fired(issues, "WEB719")[0].severity == "info"
    issues, ctx = run(copy.deepcopy(rep), profile="deep")
    assert not fired(issues, "WEB719") and ctx.coverage.state("WEB719").reasons[0][0] == "sensitivity"
    rep["deep"]["groups"]["X25519MLKEM768"] = True
    issues, _ = run(rep, profile="deep", sensitivity="paranoid")
    assert not fired(issues, "WEB719")


# ----------------------------------------------------------------------------------------------- Mozilla 6.0

def test_web718_lists_deviations_and_inventory_has_modern_status():
    issues, ctx = run(ip_report(versions={"TLSv1.0": "yes"}, cats={"cbc": "yes"}))
    f = fired(issues, "WEB718")
    en = [n[0] for n in f[0].notes]
    assert "TLS 1.0 enabled" in en and "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA offered" in en
    assert all(any("؀" <= ch <= "ۿ" for ch in n[1]) for n in f[0].notes)
    moz = ctx.inventory["tls"]["localhost"]["ips"]["192.0.2.1"]["mozilla"]
    assert moz["intermediate"]["conformant"] is False and moz["modern"]["conformant"] is False


def test_mozilla_modern_conformance():
    from vulnscan.webscan import data
    prof = data.load_json("tls-profiles.json")["profiles"]
    rep = ip_report(versions={"TLSv1.2": "no"}, sent=("ecleaf.pem", "int.pem"))
    leaf = x509.parse_certificate(base64.b64decode(rep["chain"][0]))
    short = dataclasses.replace(leaf, sig_alg="ecdsa-with-SHA256", not_before=NOW, not_after=NOW + timedelta(days=60))
    devs, complete = assess.mozilla_deviations(rep, short, prof["modern"], deep=False)
    assert devs == [] and complete
    devs, _ = assess.mozilla_deviations(rep, short, prof["intermediate"], deep=False)
    assert ("TLS 1.2 disabled", "TLS 1.2 معطّل") not in devs     # stricter than intermediate is not a deviation (review)


# ----------------------------------------------------------------------------------------------- several IPs, proxy

def test_identical_findings_merge_and_list_ips():
    a = ip_report(ip="192.0.2.1", versions={"TLSv1.0": "yes"})
    b = ip_report(ip="192.0.2.2", versions={"TLSv1.0": "yes"})
    issues, ctx = run(a, b)
    f = fired(issues, "WEB030")
    assert len(f) == 1 and f[0].ips == ("192.0.2.1", "192.0.2.2")
    assert not fired(issues, "WEB715") and state(ctx, "WEB715") == "pass"


def test_web715_nodes_differ():
    a = ip_report(ip="192.0.2.1")
    b = ip_report(ip="192.0.2.2", versions={"TLSv1.3": "no"})
    issues, ctx = run(a, b)
    f = fired(issues, "WEB715")
    assert len(f) == 1 and f[0].severity == "low" and set(f[0].ips) == {"192.0.2.1", "192.0.2.2"}
    w705 = fired(issues, "WEB705")
    assert w705[0].ips == ("192.0.2.2",) and any("192.0.2.2" in n[0] for n in w705[0].notes)


def test_unreachable_ipv6_does_not_turn_checks_into_not_tested():
    a = ip_report(ip="192.0.2.1")
    b = {"ip": "2001:db8::1", "status": "unreachable", "reason": "ipv6_unreachable"}
    issues, ctx = run(a, b)
    assert state(ctx, "WEB030") == "pass"
    assert any("2001:db8::1" in n[0] for n in ctx.inventory["tls"]["localhost"]["notes"])


def test_proxied_scan_marks_trust_findings_tentative():
    rep = ip_report(ip=None, sent=("leaf.pem", "root.pem", "int.pem"), verified=False, code=19)
    issues, ctx = run(rep, proxied=True)
    f701 = fired(issues, "WEB701")
    assert f701[0].confidence == "tentative"
    assert fired(issues, "WEB703")[0].confidence == "tentative"
    for i in issues:
        assert any("proxy" in n[0] for n in i.notes), i.rule
        assert i.ips == ()
    assert state(ctx, "WEB715") == "not_tested"


def test_host_error_is_not_tested():
    ctx = ScanContext(options=ScanOptions(), target="https://localhost/", coverage=coverage.Coverage(), now=NOW)
    ctx.tls["localhost"] = {"kind": "kashif-tls-host", "host": "localhost", "port": 443, "ips": {}, "not_sampled": [],
                            "error": {"code": "network", "en": "no address", "ar": "لا يوجد عنوان"}}
    assert tls.run(ctx) == []
    assert all(state(ctx, c) == "not_tested" for c in tls.CHECKS)


# ----------------------------------------------------------------------------------------------- SSL Labs-compatible

def _grade(rep, **kw):
    return assess.ssllabs_ip(rep, kw.pop("now", NOW), host="localhost", **kw)


def test_ssllabs_grades():
    assert _grade(ip_report())["grade"] == "A"
    hsts = HstsVerdict(host="localhost", present=True, valid=True, max_age=63072000, effective=True)
    assert _grade(ip_report(), hsts=hsts)["grade"] == "A+"
    assert _grade(ip_report(versions={"TLSv1.3": "no"}))["grade"] == "A-"
    assert _grade(ip_report(versions={"TLSv1.0": "yes"}))["grade"] == "B"
    assert _grade(ip_report(compression=True))["grade"] == "C"
    assert _grade(ip_report(versions={"SSLv2": "yes"}))["grade"] == "F"
    assert _grade(ip_report(sent=("rsa1024leaf.pem", "int.pem")))["grade"] == "B"
    g = _grade(ip_report(sent=("sha1leaf.pem", "int.pem")))
    assert g["grade"] == "T" and g["grade_if_trusted"] == "A"
    assert _grade(ip_report(verified=False, code=62), now=NOW)["grade"] == "M"
    assert _grade(ip_report(versions={k: "no" for k in GOOD_VERSIONS}))["grade"] == "?"
    label = _grade(ip_report())["label"]
    assert "attack-only" in label[0] and any("؀" <= ch <= "ۿ" for ch in label[1])


def test_ssllabs_grade_of_the_scan_is_the_worst_ip():
    a = ip_report(ip="192.0.2.1")
    b = ip_report(ip="192.0.2.2", versions={"TLSv1.0": "yes"})
    _issues, ctx = run(a, b)
    g = tls.ssllabs_grade(ctx)
    assert g["grade"] == "B" and g["ip"] == "192.0.2.2"
    assert ctx.inventory["tls_grade"]["grade"] == "B"


# ----------------------------------------------------------------------------------------------- strings

def test_every_string_is_bilingual():
    for key, (en, ar) in assess.STR.items():
        assert en and ar, key
        assert any("؀" <= ch <= "ۿ" for ch in ar) or set(ar) <= set("{}_:/ abcdefghijklmnopqrstuvwxyz"), key
    exact, patterns = assess.i18n_catalog()
    assert exact and patterns
