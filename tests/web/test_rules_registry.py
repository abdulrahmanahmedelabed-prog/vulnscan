"""Registry acceptance tests (spec §6 WP0): every rule id of §2 exists exactly once with all fields filled, mappings are
real WSTG / ASVS 4.0.3 / ASVS 5.0.0 identifiers, severities are coherent, and titles/advice exist in both languages.

The id lists below are copied from the verified sources named in the spec: OWASP/wstg ``checklists/checklist.json``
and OWASP/ASVS ``4.0/en/*.md`` / ``5.0/en/*.md`` (requirements marked deleted or moved are excluded).
"""

from __future__ import annotations

import inspect
import json
import pathlib
import re

import pytest

from vulnscan import model
from vulnscan.i18n import plural
from vulnscan.webscan import rules as R
from vulnscan.webscan.types import CONFIDENCES, Evidence, Issue

# every rule id named in spec §2 (2.1 … 2.11), in catalogue order
SPEC_IDS = """
WEB000 WEB101 WEB102 WEB103 WEB104 WEB105 WEB106 WEB-strict-transport-security WEB110 WEB111 WEB112 WEB113 WEB114
WEB115 WEB116 WEB117 WEB118 WEB119 WEB-content-security-policy WEB040 WEB041 WEB042 WEB043 WEB200 WEB201 WEB202
WEB203 WEB204 WEB205 WEB206 WEB207 WEB208 WEB209 WEB210 WEB211 WEB212 WEB213 WEB214 WEB215 WEB216 WEB217 WEB218
WEB219 WEB-x-frame-options WEB300 WEB301 WEB302 WEB-x-content-type-options WEB303 WEB-referrer-policy WEB304
WEB-permissions-policy WEB305 WEB306 WEB307 WEB308 WEB309 WEB310 WEB311 WEB312 WEB313 WEB314 WEB315 WEB316 WEB317 WEB318
WEB320 WEB321 WEB322 WEB323 WEB324 WEB325 WEB326 WEB327 WEB020 WEB021 WEB022 WEB400 WEB401 WEB402 WEB403 WEB404
WEB405 WEB406 WEB407 WEB408 WEB409 WEB410 WEB411 WEB413 WEB412 WEB414 WEB050 WEB051 WEB052 WEB053 WEB500 WEB501
WEB502 WEB503 WEB504 WEB505 WEB506 WEB507 WEB508 WEB509 WEB510 WEB511 WEB512 WEB513 WEB514 WEB515 WEB517 WEB518
WEB519 WEB516 WEB520 WEB521 WEB522 WEB010 WEB011 WEB055 WEB056 WEB600 WEB601 WEB602 WEB603 WEB604 WEB605 WEB606
WEB607 WEB608 WEB609 WEB610 WEB611 WEB612 WEB613 WEB614 WEB615 WEB616 WEB617 WEB619 WEB030 WEB070 WEB071 WEB072
WEB700 WEB701 WEB702 WEB703 WEB704 WEB705 WEB706 WEB707 WEB708 WEB709 WEB710 WEB711 WEB712 WEB713 WEB714 WEB715
WEB716 WEB717 WEB718 WEB719 WEB720 WEB054 WEB080 WEB081 WEB800 WEB801 WEB802 WEB803 WEB060 WEB900 WEB061 WEB062
WEB082 WEB083 WEB901 WEB903 WEB990 WEB991
""".split()

WSTG_IDS = frozenset("""
WSTG-APIT-01 WSTG-APIT-02 WSTG-APIT-03 WSTG-APIT-04 WSTG-APIT-99 WSTG-ATHN-01 WSTG-ATHN-02 WSTG-ATHN-03 WSTG-ATHN-04
WSTG-ATHN-05 WSTG-ATHN-06 WSTG-ATHN-07 WSTG-ATHN-08 WSTG-ATHN-09 WSTG-ATHN-10 WSTG-ATHN-11 WSTG-ATHN-12 WSTG-ATHZ-01
WSTG-ATHZ-02 WSTG-ATHZ-03 WSTG-ATHZ-04 WSTG-ATHZ-05 WSTG-BUSL-01 WSTG-BUSL-02 WSTG-BUSL-03 WSTG-BUSL-04 WSTG-BUSL-05
WSTG-BUSL-06 WSTG-BUSL-07 WSTG-BUSL-08 WSTG-BUSL-09 WSTG-BUSL-10 WSTG-CLNT-01 WSTG-CLNT-02 WSTG-CLNT-03 WSTG-CLNT-04
WSTG-CLNT-05 WSTG-CLNT-06 WSTG-CLNT-07 WSTG-CLNT-09 WSTG-CLNT-10 WSTG-CLNT-11 WSTG-CLNT-12 WSTG-CLNT-13 WSTG-CLNT-14
WSTG-CLNT-15 WSTG-CLNT-16 WSTG-CONF-01 WSTG-CONF-02 WSTG-CONF-03 WSTG-CONF-04 WSTG-CONF-05 WSTG-CONF-06 WSTG-CONF-07
WSTG-CONF-09 WSTG-CONF-10 WSTG-CONF-11 WSTG-CONF-12 WSTG-CONF-13 WSTG-CONF-14 WSTG-CONF-15 WSTG-CRYP-01 WSTG-CRYP-02
WSTG-CRYP-03 WSTG-CRYP-04 WSTG-ERRH-01 WSTG-ERRH-02 WSTG-IDNT-01 WSTG-IDNT-02 WSTG-IDNT-03 WSTG-IDNT-04 WSTG-IDNT-05
WSTG-INFO-01 WSTG-INFO-02 WSTG-INFO-03 WSTG-INFO-04 WSTG-INFO-05 WSTG-INFO-06 WSTG-INFO-07 WSTG-INFO-08 WSTG-INFO-09
WSTG-INFO-10 WSTG-INJT-01 WSTG-INJT-02 WSTG-INJT-03 WSTG-INJT-04 WSTG-INJT-05 WSTG-INJT-06 WSTG-INJT-07 WSTG-INJT-08
WSTG-INJT-09 WSTG-INJT-10 WSTG-INJT-11 WSTG-INJT-12 WSTG-INJT-13 WSTG-INJT-14 WSTG-INJT-15 WSTG-INJT-16 WSTG-INJT-17
WSTG-INJT-18 WSTG-INJT-19 WSTG-INJT-20 WSTG-INJT-21 WSTG-INJT-22 WSTG-INJT-23 WSTG-SESS-01 WSTG-SESS-02 WSTG-SESS-03
WSTG-SESS-04 WSTG-SESS-05 WSTG-SESS-06 WSTG-SESS-07 WSTG-SESS-08 WSTG-SESS-09 WSTG-SESS-10 WSTG-SESS-11 WSTG-WASM-01
""".split())

ASVS4_IDS = frozenset("""
1.1.1 1.1.2 1.1.3 1.1.4 1.1.5 1.1.6 1.1.7 1.2.1 1.2.2 1.2.3 1.2.4 1.4.1 1.4.4 1.4.5 1.5.1 1.5.2 1.5.3 1.5.4 1.6.1
1.6.2 1.6.3 1.6.4 1.7.1 1.7.2 1.8.1 1.8.2 1.9.1 1.9.2 1.10.1 1.11.1 1.11.2 1.11.3 1.12.2 1.14.1 1.14.2 1.14.3 1.14.4
1.14.5 1.14.6 2.1.1 2.1.2 2.1.3 2.1.4 2.1.5 2.1.6 2.1.7 2.1.8 2.1.9 2.1.10 2.1.11 2.1.12 2.2.1 2.2.2 2.2.3 2.2.4
2.2.5 2.2.6 2.2.7 2.3.1 2.3.2 2.3.3 2.4.1 2.4.2 2.4.3 2.4.4 2.4.5 2.5.1 2.5.2 2.5.3 2.5.4 2.5.5 2.5.6 2.5.7 2.6.1
2.6.2 2.6.3 2.7.1 2.7.2 2.7.3 2.7.4 2.7.5 2.7.6 2.8.1 2.8.2 2.8.3 2.8.4 2.8.5 2.8.6 2.8.7 2.9.1 2.9.2 2.9.3 2.10.1
2.10.2 2.10.3 2.10.4 3.1.1 3.2.1 3.2.2 3.2.3 3.2.4 3.3.1 3.3.2 3.3.3 3.3.4 3.4.1 3.4.2 3.4.3 3.4.4 3.4.5 3.5.1 3.5.2
3.5.3 3.6.1 3.6.2 3.7.1 4.1.1 4.1.2 4.1.3 4.1.5 4.2.1 4.2.2 4.3.1 4.3.2 4.3.3 5.1.1 5.1.2 5.1.3 5.1.4 5.1.5 5.2.1
5.2.2 5.2.3 5.2.4 5.2.5 5.2.6 5.2.7 5.2.8 5.3.1 5.3.2 5.3.3 5.3.4 5.3.5 5.3.6 5.3.7 5.3.8 5.3.9 5.3.10 5.4.1 5.4.2
5.4.3 5.5.1 5.5.2 5.5.3 5.5.4 6.1.1 6.1.2 6.1.3 6.2.1 6.2.2 6.2.3 6.2.4 6.2.5 6.2.6 6.2.7 6.2.8 6.3.1 6.3.2 6.3.3
6.4.1 6.4.2 7.1.1 7.1.2 7.1.3 7.1.4 7.2.1 7.2.2 7.3.1 7.3.3 7.3.4 7.4.1 7.4.2 7.4.3 8.1.1 8.1.2 8.1.3 8.1.4 8.1.5
8.1.6 8.2.1 8.2.2 8.2.3 8.3.1 8.3.2 8.3.3 8.3.4 8.3.5 8.3.6 8.3.7 9.1.1 9.1.2 9.1.3 9.2.1 9.2.2 9.2.3 9.2.4 9.2.5
10.1.1 10.2.1 10.2.2 10.2.3 10.2.4 10.2.5 10.2.6 10.3.1 10.3.2 10.3.3 11.1.1 11.1.2 11.1.3 11.1.4 11.1.5 11.1.6
11.1.7 11.1.8 12.1.1 12.1.2 12.1.3 12.2.1 12.3.1 12.3.2 12.3.3 12.3.4 12.3.5 12.3.6 12.4.1 12.4.2 12.5.1 12.5.2
12.6.1 13.1.1 13.1.3 13.1.4 13.1.5 13.2.1 13.2.2 13.2.3 13.2.5 13.2.6 13.3.1 13.3.2 13.4.1 13.4.2 14.1.1 14.1.2
14.1.3 14.1.4 14.1.5 14.2.1 14.2.2 14.2.3 14.2.4 14.2.5 14.2.6 14.3.2 14.3.3 14.4.1 14.4.2 14.4.3 14.4.4 14.4.5
14.4.6 14.4.7 14.5.1 14.5.2 14.5.3 14.5.4
""".split())

ASVS5_IDS = frozenset("""
1.1.1 1.1.2 1.2.1 1.2.2 1.2.3 1.2.4 1.2.5 1.2.6 1.2.7 1.2.8 1.2.9 1.2.10 1.3.1 1.3.2 1.3.3 1.3.4 1.3.5 1.3.6 1.3.7
1.3.8 1.3.9 1.3.10 1.3.11 1.3.12 1.4.1 1.4.2 1.4.3 1.5.1 1.5.2 1.5.3 2.1.1 2.1.2 2.1.3 2.2.1 2.2.2 2.2.3 2.3.1 2.3.2
2.3.3 2.3.4 2.3.5 2.4.1 2.4.2 3.1.1 3.2.1 3.2.2 3.2.3 3.3.1 3.3.2 3.3.3 3.3.4 3.3.5 3.4.1 3.4.2 3.4.3 3.4.4 3.4.5
3.4.6 3.4.7 3.4.8 3.5.1 3.5.2 3.5.3 3.5.4 3.5.5 3.5.6 3.5.7 3.5.8 3.6.1 3.7.1 3.7.2 3.7.3 3.7.4 3.7.5 4.1.1 4.1.2
4.1.3 4.1.4 4.1.5 4.2.1 4.2.2 4.2.3 4.2.4 4.2.5 4.3.1 4.3.2 4.4.1 4.4.2 4.4.3 4.4.4 5.1.1 5.2.1 5.2.2 5.2.3 5.2.4
5.2.5 5.2.6 5.3.1 5.3.2 5.3.3 5.4.1 5.4.2 5.4.3 6.1.1 6.1.2 6.1.3 6.2.1 6.2.2 6.2.3 6.2.4 6.2.5 6.2.6 6.2.7 6.2.8
6.2.9 6.2.10 6.2.11 6.2.12 6.3.1 6.3.2 6.3.3 6.3.4 6.3.5 6.3.6 6.3.7 6.3.8 6.4.1 6.4.2 6.4.3 6.4.4 6.4.5 6.4.6 6.5.1
6.5.2 6.5.3 6.5.4 6.5.5 6.5.6 6.5.7 6.5.8 6.6.1 6.6.2 6.6.3 6.6.4 6.7.1 6.7.2 6.8.1 6.8.2 6.8.3 6.8.4 7.1.1 7.1.2
7.1.3 7.2.1 7.2.2 7.2.3 7.2.4 7.3.1 7.3.2 7.4.1 7.4.3 7.4.4 7.4.5 7.5.1 7.5.2 7.5.3 7.6.1 7.6.2 8.1.1 8.1.2 8.1.3
8.1.4 8.2.1 8.2.2 8.2.3 8.2.4 8.3.1 8.3.2 8.3.3 8.4.1 8.4.2 9.1.1 9.1.2 9.1.3 9.2.1 9.2.2 9.2.3 9.2.4 10.1.1 10.1.2
10.2.1 10.2.2 10.2.3 10.3.1 10.3.2 10.3.3 10.3.4 10.3.5 10.4.1 10.4.2 10.4.3 10.4.4 10.4.5 10.4.6 10.4.7 10.4.8
10.4.9 10.4.10 10.4.11 10.4.12 10.4.13 10.4.14 10.4.15 10.4.16 10.5.1 10.5.2 10.5.3 10.5.4 10.5.5 10.6.1 10.6.2
10.7.1 10.7.2 10.7.3 11.1.1 11.1.2 11.1.3 11.1.4 11.2.1 11.2.2 11.2.3 11.2.4 11.2.5 11.3.1 11.3.2 11.3.3 11.3.4
11.3.5 11.4.1 11.4.2 11.4.3 11.4.4 11.5.1 11.5.2 11.6.1 11.6.2 11.7.1 11.7.2 12.1.1 12.1.2 12.1.3 12.1.4 12.1.5
12.2.1 12.2.2 12.3.1 12.3.2 12.3.3 12.3.4 12.3.5 13.1.1 13.1.2 13.1.3 13.1.4 13.2.1 13.2.2 13.2.3 13.2.4 13.2.5
13.2.6 13.3.1 13.3.2 13.3.3 13.3.4 13.4.1 13.4.2 13.4.3 13.4.4 13.4.5 13.4.6 13.4.7 14.1.1 14.1.2 14.2.1 14.2.2
14.2.3 14.2.4 14.2.5 14.2.6 14.2.8 14.3.1 14.3.2 14.3.3 15.1.1 15.1.2 15.1.3 15.1.4 15.1.5 15.2.1 15.2.2 15.2.3
15.2.4 15.2.5 15.3.1 15.3.2 15.3.3 15.3.4 15.3.5 15.3.6 15.3.7 15.4.1 15.4.2 15.4.3 15.4.4 16.1.1 16.2.1 16.2.2
16.2.3 16.2.4 16.2.5 16.3.1 16.3.2 16.3.3 16.3.4 16.4.1 16.4.2 16.4.3 16.5.1 16.5.2 16.5.3 16.5.4 17.1.1 17.1.2
17.2.1 17.2.2 17.2.3 17.2.4 17.2.5 17.2.6 17.2.7 17.2.8 17.3.1 17.3.2
""".split())

EXISTING = frozenset("""
WEB000 WEB-strict-transport-security WEB-content-security-policy WEB-x-content-type-options WEB-x-frame-options
WEB-referrer-policy WEB-permissions-policy WEB010 WEB011 WEB020 WEB021 WEB022 WEB030 WEB040 WEB041 WEB042 WEB043 WEB050
WEB051 WEB052 WEB053 WEB054 WEB055 WEB056 WEB060 WEB061 WEB062 WEB070 WEB071 WEB072 WEB080 WEB081 WEB082 WEB083
""".split())
PARANOID_ONLY = {"WEB219", "WEB409", "WEB515", "WEB516", "WEB614", "WEB719"}
ARABIC = re.compile(r"[\u0600-\u06FF]")
PLACEHOLDER = re.compile(r"\{([a-z_]+)\}")


def _texts(meta):
    yield "name", meta.name_en, meta.name_ar
    yield "title", meta.title_en, meta.title_ar
    yield "advice", meta.advice_en, meta.advice_ar
    for vname, v in meta.variants.items():
        if "title_en" in v or "title_ar" in v:
            yield f"variant {vname} title", v.get("title_en", ""), v.get("title_ar", "")
        if "advice_en" in v or "advice_ar" in v:
            yield f"variant {vname} advice", v.get("advice_en", ""), v.get("advice_ar", "")


# ----------------------------------------------------------------------------------------------- ids

def test_every_spec_id_exists_exactly_once():
    assert len(SPEC_IDS) == 184 and len(set(SPEC_IDS)) == 184
    assert len(R.RULE_IDS) == len(set(R.RULE_IDS)) == 184
    assert set(R.RULES) == set(SPEC_IDS)
    for rid, meta in R.RULES.items():
        assert meta.id == rid


def test_family_sizes_and_existing_rules():
    sizes = {f: len(R.rules_for_family(f)) for f in R.FAMILIES}
    # §2 lists 150 new ids (§7's "147" predates WEB413/WEB516/WEB517 counting); 34 existing ids are kept
    assert sizes == {"A": 18, "B": 25, "C": 23, "D": 8, "E": 18, "F": 27, "G": 23, "H": 25, "I": 7, "J": 8, "K": 2}
    assert {r for r, m in R.RULES.items() if m.existing} == EXISTING
    assert len(R.RULES) - len(EXISTING) == 150


def test_every_1_0_rule_id_is_kept():
    """Every rule id 1.0.x emitted still exists with the same id (1.x stability). Since 1.1.0 ``web.py`` is a facade
    over the engine and emits no Finding itself, so the 1.0.x ids come from the recorded run of 1.0.2's ``web.py``
    on the corpus (bench/web/results/1.0.2-legacy.json) plus the list above."""
    assert len(EXISTING) == 34 and EXISTING <= set(R.RULES), sorted(EXISTING - set(R.RULES))
    legacy = pathlib.Path(__file__).resolve().parents[2] / "bench" / "web" / "results" / "1.0.2-legacy.json"
    if legacy.is_file():
        doc = json.loads(legacy.read_text(encoding="utf-8"))
        emitted = {f["rule"] for c in doc["cases"].values() for f in c.get("findings", [])}
        assert emitted and emitted <= EXISTING, sorted(emitted - EXISTING)


# ----------------------------------------------------------------------------------------------- fields

def test_all_fields_filled():
    for rid, m in R.RULES.items():
        for field_name in ("family", "module", "grade_family", "severity", "confidence", "name_en", "name_ar", "title_en",
                           "title_ar", "advice_en", "advice_ar", "check_id"):
            assert getattr(m, field_name), f"{rid}: empty {field_name}"
        assert m.allowed_severities and m.allowed_confidences, rid
        assert m.module in R.MODULES and m.family in R.FAMILIES and m.grade_family in R.GRADE_FAMILIES, rid
        for mapping in ("wstg", "asvs4", "asvs5", "fix", "cwe_variants"):
            assert isinstance(getattr(m, mapping), tuple), rid   # () is the spec's "—"
        if rid in R.META_RULES:                                  # scan-meta rules are not weaknesses
            assert m.family == "K" and not m.cwe and not m.fix
        else:
            assert m.cwe and m.fix, f"{rid}: CWE and fix ids are required"


def test_cwe_ids_are_valid_and_never_cwe16():
    for rid, m in R.RULES.items():
        for cwe in (m.cwe, *m.cwe_variants):
            if not cwe:
                continue
            assert re.fullmatch(r"CWE-[1-9]\d*", cwe), (rid, cwe)
            assert cwe != "CWE-16", rid
    assert R.RULES["WEB-permissions-policy"].cwe == "CWE-693"
    assert R.RULES["WEB-x-content-type-options"].cwe == "CWE-693"


def test_wstg_and_asvs_ids_exist_in_their_standards():
    for rid, m in R.RULES.items():
        for w in m.wstg:
            assert w in WSTG_IDS, (rid, w)
        for a in m.asvs4:
            assert a in ASVS4_IDS, (rid, a)
        for a in m.asvs5:
            assert a in ASVS5_IDS, (rid, a)
    # WSTG-CONF-08 and WSTG-CLNT-08 no longer exist (spec intro)
    assert "WSTG-CONF-08" not in WSTG_IDS and "WSTG-CLNT-08" not in WSTG_IDS


def test_severities_and_confidences_are_coherent():
    assert R.SEVERITIES == model.SEVERITIES
    for rid, m in R.RULES.items():
        assert m.severity in m.allowed_severities, rid
        assert set(m.allowed_severities) <= set(model.SEVERITIES), rid
        assert list(m.allowed_severities) == [s for s in model.SEVERITIES if s in m.allowed_severities], rid
        assert m.confidence in m.allowed_confidences, rid
        assert set(m.allowed_confidences) <= set(CONFIDENCES), rid


def test_csp_family_never_more_severe_than_missing_csp():
    ceiling = model.SEVERITY_RANK["medium"]
    assert R.RULES["WEB-content-security-policy"].severity == "medium"
    for rid in R.rules_for_family("B"):
        worst = min(model.SEVERITY_RANK[s] for s in R.RULES[rid].allowed_severities)
        assert worst >= ceiling, f"{rid} can exceed medium"


def test_paranoid_only_rules():
    assert {r for r, m in R.RULES.items() if m.paranoid_only} == PARANOID_ONLY
    for rid in PARANOID_ONLY:
        assert R.RULES[rid].severity == "info"


def test_fix_ids_are_known_snippets():
    used = {f for m in R.RULES.values() for f in m.fix}
    assert used <= set(R.FIX_IDS)
    assert used == set(R.FIX_IDS), sorted(set(R.FIX_IDS) - used)   # every snippet of §2.13 is used by some rule


# ----------------------------------------------------------------------------------------------- spot checks

@pytest.mark.parametrize("rid,sev,allowed,conf,cwe,wstg,asvs4,asvs5,fix", [
    ("WEB000", "high", ("high", "info"), "certain", "CWE-319", ("WSTG-CRYP-03",), ("9.1.1",), ("12.2.1",), ("S-REDIR", "S-TLS")),
    ("WEB-strict-transport-security", "medium", ("medium", "info"), "firm", "CWE-319", ("WSTG-CONF-07",), ("14.4.5",),
     ("3.4.1",), ("S-HSTS",)),
    ("WEB110", "medium", ("medium",), "certain", "CWE-319", ("WSTG-CONF-07",), ("14.4.5",), ("3.4.1",), ("S-HSTS",)),
    ("WEB111", "medium", ("medium", "low", "info"), "certain", "CWE-319", ("WSTG-CONF-07",), ("14.4.5",), ("3.4.1",),
     ("S-HSTS",)),
    ("WEB115", "low", ("low", "info"), "certain", "CWE-319", ("WSTG-CONF-07",), (), ("3.7.4",), ("S-HSTS",)),
    ("WEB119", "info", ("low", "info"), "tentative", "CWE-200", ("WSTG-CRYP-01",), (), (), ("S-BREACH",)),
    ("WEB204", "medium", ("medium", "info"), "certain", "CWE-693", ("WSTG-CONF-12",), ("14.4.3",), ("3.4.3",), ("S-CSP",)),
    ("WEB206", "medium", ("medium",), "certain", "CWE-1021", ("WSTG-CLNT-09",), ("14.4.7",), ("3.4.6",), ("S-FRAME",)),
    ("WEB212", "medium", ("medium",), "certain", "CWE-330", ("WSTG-CONF-12",), ("14.4.3",), ("3.4.3",), ("S-CSP",)),
    ("WEB215", "info", ("low", "info"), "certain", "CWE-778", ("WSTG-CONF-12",), (), ("3.4.7",), ("S-CSP",)),
    ("WEB219", "info", ("info",), "certain", "CWE-79", ("WSTG-CLNT-01",), (), (), ("S-CSP",)),
    ("WEB-x-frame-options", "medium", ("medium", "low"), "firm", "CWE-1021", ("WSTG-CLNT-09",), ("14.4.7",), ("3.4.6",),
     ("S-FRAME",)),
    ("WEB311", "info", ("info",), "certain", "CWE-693", ("WSTG-CONF-14",), (), (), ("S-DEPR",)),
    ("WEB312", "info", ("info",), "certain", "CWE-693", ("WSTG-CONF-14",), (), (), ("S-DEPR",)),
    ("WEB315", "medium", ("high", "medium", "low"), "firm", "CWE-525", ("WSTG-ATHN-06",), ("8.2.1",), ("14.3.2",),
     ("S-CACHE",)),
    ("WEB318", "info", ("info",), "certain", "CWE-693", ("WSTG-CONF-14",), ("14.4.1",), ("3.4.1",),
     ("S-HSTS", "S-CSP", "S-FRAME", "S-XCTO")),
    ("WEB320", "high", ("high",), "certain", "CWE-942", ("WSTG-CLNT-07",), ("14.5.3",), ("3.4.2",), ("S-CORS",)),
    ("WEB321", "low", ("medium", "low"), "certain", "CWE-942", ("WSTG-CLNT-07",), ("14.5.3",), ("3.4.2",), ("S-CORS",)),
    ("WEB020", "high", ("high", "medium", "low", "info"), "certain", "CWE-614", ("WSTG-SESS-02",), ("3.4.1",), ("3.3.1",),
     ("S-COOKIE",)),
    ("WEB021", "medium", ("medium", "info"), "firm", "CWE-1004", ("WSTG-SESS-02",), ("3.4.2",), ("3.3.4",), ("S-COOKIE",)),
    ("WEB403", "medium", ("medium",), "certain", "CWE-614", ("WSTG-SESS-02",), (), ("3.3.1",), ("S-COOKIE",)),
    ("WEB412", "medium", ("medium", "low"), "firm", "CWE-315", ("WSTG-SESS-02",), ("3.5.3",), ("14.3.3",), ("S-COOKIE",)),
    ("WEB050", "medium", ("medium", "low", "info"), "certain", "CWE-319", ("WSTG-CRYP-03",), ("9.1.1",), ("12.2.1",),
     ("S-MIXED",)),
    ("WEB501", "low", ("low",), "certain", "CWE-353", (), ("14.2.3",), ("3.6.1",), ("S-SRI",)),
    ("WEB503", "medium", ("medium",), "firm", "CWE-353", (), ("14.2.3",), ("3.6.1",), ("S-SRI",)),
    ("WEB517", "high", ("high", "medium", "low", "info"), "firm", "CWE-829", ("WSTG-CONF-10",), ("14.2.3",), ("15.2.4",),
     ("S-SRI",)),
    ("WEB522", "low", ("low",), "tentative", "CWE-346", ("WSTG-CLNT-11",), (), ("3.5.5",), ("S-HTML",)),
    ("WEB605", "high", ("critical", "high"), "certain", "CWE-489", ("WSTG-ERRH-02",), ("14.3.2",), ("13.4.2",), ("S-ERR",)),
    ("WEB609", "critical", ("critical", "high", "low"), "firm", "CWE-798", ("WSTG-INFO-05",), ("2.10.4",), ("13.3.1",),
     ("S-SECRET",)),
    ("WEB610", "medium", ("medium",), "firm", "CWE-502", (), ("1.5.2",), ("1.5.2",), ("S-SECRET",)),
    ("WEB030", "medium", ("medium",), "certain", "CWE-327", ("WSTG-CRYP-01",), ("9.1.3",), ("12.1.1",), ("S-TLS",)),
    ("WEB071", "medium", ("medium", "low"), "certain", "CWE-298", ("WSTG-CRYP-01",), (), ("12.2.2",), ("S-TLS",)),
    ("WEB704", "critical", ("critical", "high"), "certain", "CWE-327", ("WSTG-CRYP-01",), ("9.1.3",), ("12.1.1",), ("S-TLS",)),
    ("WEB714", "high", ("high", "medium", "info"), "certain", "CWE-299", ("WSTG-CRYP-01",), (), ("12.1.4",), ("S-TLS",)),
    ("WEB054", "high", ("critical", "high", "medium", "low"), "certain", "CWE-1395", ("WSTG-INFO-08",), ("14.2.1",),
     ("15.2.1",), ("S-LIBS",)),
    ("WEB080", "info", ("info",), "firm", "CWE-1395", ("WSTG-INFO-08", "WSTG-INFO-09"), (), (), ("S-LIBS",)),
    ("WEB802", "low", ("low",), "certain", "CWE-1104", (), ("1.14.6",), ("3.7.1",), ("S-HTML",)),
    ("WEB062", "high", ("critical", "high", "medium", "low", "info"), "certain", "CWE-538", ("WSTG-CONF-04",), ("12.5.1",),
     ("13.4.7", "13.4.1", "13.4.5"), ("S-DOTFILES",)),
    ("WEB901", "high", ("high",), "firm", "CWE-284", ("WSTG-CONF-10",), ("10.3.3",), (), ("S-TAKEOVER",)),
    ("WEB903", "medium", ("medium", "low"), "certain", "CWE-942", ("WSTG-CLNT-07",), ("14.5.3",), ("3.4.2",), ("S-CORS",)),
])
def test_spec_values(rid, sev, allowed, conf, cwe, wstg, asvs4, asvs5, fix):
    m = R.RULES[rid]
    assert (m.severity, set(m.allowed_severities), m.confidence, m.cwe, m.wstg, m.asvs4, m.asvs5, m.fix) == \
        (sev, set(allowed), conf, cwe, wstg, asvs4, asvs5, fix)


def test_module_ownership():
    assert set(R.checks_for_module("cors")) == {f"WEB{n}" for n in range(320, 328)}
    assert R.RULES["WEB520"].module == "domxss" and R.RULES["WEB054"].module == "libs"
    assert R.RULES["WEB802"].module == "tech" and R.RULES["WEB061"].module == "exposure"
    union = [c for mod in R.MODULES for c in R.checks_for_module(mod)]
    assert sorted(union) == sorted(R.all_check_ids())
    assert len(union) == len(set(union))


def test_sum_cap_controls():
    for control, (missing, weak) in R.CONTROLS.items():
        assert missing in R.RULES, control
        assert set(weak) <= set(R.RULES), control
        assert control in R.RULES[missing].controls
    assert R.RULES["WEB207"].controls == ("csp", "framing")
    assert "WEB206" not in R.CONTROLS["csp"][1]


# ----------------------------------------------------------------------------------------------- languages

def test_both_languages_everywhere():
    for rid, m in R.RULES.items():
        for what, en, ar in _texts(m):
            assert en and ar, f"{rid} {what}: missing language"
            assert ARABIC.search(ar), f"{rid} {what}: Arabic text has no Arabic"
            assert not ARABIC.search(en), f"{rid} {what}: English text contains Arabic"
            assert set(PLACEHOLDER.findall(en)) == set(PLACEHOLDER.findall(ar)), f"{rid} {what}: placeholders differ"
            assert en == en.strip() and ar == ar.strip() and "  " not in en, f"{rid} {what}: stray whitespace"


def test_plural_agreement_in_titles():
    m = R.RULES["WEB071"]
    assert m.title("en", days=1) == "TLS certificate expires in 1 day"
    assert m.title("en", days=9) == "TLS certificate expires in 9 days"
    assert m.title("ar", days=1).endswith("(تنتهي خلال يوم واحد)")
    assert m.title("ar", days=2).endswith("(تنتهي خلال يومين)")
    assert m.title("ar", days=5).endswith("(تنتهي خلال 5 أيام)")
    assert m.title("ar", days=11).endswith("(تنتهي خلال 11 يومًا)")
    assert m.title("ar", days=100).endswith("(تنتهي خلال 100 يوم)")
    for n in (1, 2, 3, 10, 11, 99, 100, 102, 111):
        cat = plural.ar_category(n)
        assert R.PLURAL_PARAMS["days"][2][plural.FORMS.index(cat)].replace("{n}", str(n)) in m.title("ar", days=n)


def test_formatting_params_variants_and_fallbacks():
    assert R.RULES["WEB020"].title("en", cookie="sid") == "Cookie without Secure flag: sid"
    assert R.RULES["WEB020"].title("ar", cookie="sid") == "كوكي بدون علامة Secure: sid"
    assert R.RULES["WEB020"].title("en") == "Cookie without Secure flag"          # missing parameter → plain name
    assert R.RULES["WEB054"].advice("ar", library="jquery", fixed="3.5.0") == "حدّث jquery إلى الإصدار 3.5.0 أو أحدث."
    assert R.RULES["WEB000"].advice("en", variant="api").startswith("Refuse plain HTTP")
    assert R.RULES["WEB800"].title("en", product="nginx", version="1.18.0", variant="tentative").startswith(
        "Server software version may be affected")
    assert R.RULES["WEB042"].title("ar", variant="non_script") == "سياسة CSP لا تقيّد السكربتات"
    assert R.RULES["WEB-x-frame-options"].title_1_0 == "Missing X-Frame-Options / frame-ancestors"
    assert R.RULES["WEB062"].params == ("path",)
    # a hostile value is inserted literally, never interpreted as a format string
    assert R.RULES["WEB010"].title("en", value="{0.__class__} %s {cookie}") == "Server header reveals version: {0.__class__} %s {cookie}"


def test_validate_issue():
    ev = Evidence()
    assert R.validate_issue(Issue("WEB020", "https://a.test/", "certain", ev, {"cookie": "sid"}, "high")) == []
    assert R.validate_issue(Issue("WEB999", "https://a.test/", "certain", ev))
    assert R.validate_issue(Issue("WEB040", "https://a.test/", "certain", ev, severity="high"))          # above ceiling
    assert R.validate_issue(Issue("WEB040", "https://a.test/", "tentative", ev))                         # confidence
    assert R.validate_issue(Issue("WEB020", "https://a.test/", "certain", ev))                           # no cookie name
    assert R.validate_issue(Issue("WEB000", "https://a.test/", "certain", ev, {"variant": "nope"}))


def _to_en(text, catalog, patterns):
    """The lookup of vulnscan.i18n.to_en over a given catalogue (cat_web2 is generated by WP14)."""
    key = re.sub(r"\s+", " ", text).strip()
    if key in catalog:
        return catalog[key]
    for rx, en in patterns:
        m = re.compile(rx, re.S).fullmatch(key)
        if m:
            return re.sub(r"\\g<(\w+)>", lambda g: m.groupdict().get(g.group(1)) or "", en)
    return None


def test_i18n_catalogue_translates_every_rendered_text():
    catalog, patterns = R.i18n_catalog()
    for rx, _en in patterns:
        re.compile(rx)
    samples = {"cookie": "sid", "value": "Apache/2.4.1", "versions": "TLS 1.0", "days": 7, "library": "jquery",
               "version": "1.8.3", "fixed": "3.5.0", "platform": "WordPress", "branch": "5.9", "date": "2024-01-01",
               "latest": "6.4.5", "product": "nginx", "path": "/.env", "header": "X-AspNet-Version"}
    for rid, m in R.RULES.items():
        variants = [None, *m.variants]
        for v in variants:
            params = dict(samples, variant=v)
            for days in (1, 2, 5, 11, 100):
                params["days"] = days
                for what in ("title", "advice"):
                    ar = getattr(m, what)("ar", **params)
                    en = getattr(m, what)("en", **params)
                    assert _to_en(ar, catalog, patterns) == en, (rid, v, what, ar)
        assert _to_en(m.name_ar, catalog, patterns) == m.name_en, rid


def test_i18n_catalogue_has_no_conflicts():
    pairs: dict[str, set[str]] = {}
    for m in R.RULES.values():
        for _what, en, ar in _texts(m):
            if not PLACEHOLDER.search(ar):
                pairs.setdefault(ar, set()).add(en)
    conflicts = {ar: en for ar, en in pairs.items() if len(en) > 1}
    assert not conflicts, conflicts


def test_rules_module_has_no_circular_imports():
    """vulnscan.i18n imports this module (cat_web2), so it must not import vulnscan.i18n or vulnscan.model at load."""
    src = inspect.getsource(R)
    assert not re.search(r"^from \.\.(i18n|model)\b|^import vulnscan\.(i18n|model)", src, re.M)
