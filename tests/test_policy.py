"""Policy-as-code (vulnscan/policy.py): the strict YAML subset, validation, inheritance, every gate condition, CLI."""

import datetime
import json
import re
import random

import pytest

from vulnscan import policy as P
from vulnscan.model import Finding

TODAY = datetime.date(2026, 6, 15)


def F(rule="PY001", sev="high", file="src/app.py", line=10, cwe="CWE-89", source="vulnscan", **extra):
    return {"rule_id": rule, "severity": sev, "title": f"{rule} title", "file": file, "line": line, "snippet": f"{rule}{line}",
            "cwe": cwe, "source": source, "fingerprint": f"{abs(hash((rule, file, line))) % 16 ** 16:016x}:0",
            "extra": dict(extra)}


def pol(text, **kw):
    return P.load_policy_text(text, **kw)


def run(text, findings, **ctx):
    ctx.setdefault("today", TODAY)
    return P.evaluate(findings, pol(text), ctx)


def codes(decision):
    return [v.code for v in decision.violations]


def err(text, fmt="yaml"):
    with pytest.raises(P.PolicyError) as e:
        P.load_policy_text(text, fmt)
    return e.value


def yerr(text):
    with pytest.raises(P.PolicyError) as e:
        P.parse_yaml(text, "k.yml")
    return e.value.problems[0]


# ------------------------------------------------------------------------------------------------------- YAML parser
def test_yaml_basic_structures():
    text = """\
# comment
---
name: demo   # trailing comment
count: 3
ratio: 1.5
neg: -2
on: yes
flag: true
off_flag: False
nothing: ~
empty:
date: 2027-01-31
zero_pad: 007
url: http://example.com/a#b
q1: 'it''s # not a comment'
q2: "tab\\there \\u0041 \\x42 \\"q\\""
"quoted key": v
flow: [a, "b, c", 'd', 1, true, null]
empty_list: []
empty_map: {}
flow_map: {a: 1, "b c": 'x, y', d: true,}   # comment
nested:
  inner:
    - x
    - y
  same_indent_list:
  - 1
  - 2
items:
  - id: A
    reason: first
  - id: B
    sub:
      k: v
  -
    id: C
  - - p
    - q
  - plain
"""
    marks = {}
    data = P.parse_yaml(text, "k.yml", marks)
    assert data["name"] == "demo" and data["count"] == 3 and data["ratio"] == 1.5 and data["neg"] == -2
    assert data["on"] == "yes"                      # the "Norway problem": yes/no/on/off stay strings
    assert data["flag"] is True and data["off_flag"] is False
    assert data["nothing"] is None and data["empty"] is None
    assert data["date"] == "2027-01-31" and data["zero_pad"] == "007"
    assert data["url"] == "http://example.com/a#b"
    assert data["q1"] == "it's # not a comment"
    assert data["q2"] == 'tab\there A B "q"'
    assert data["quoted key"] == "v"
    assert data["flow"] == ["a", "b, c", "d", 1, True, None]
    assert data["empty_list"] == [] and data["empty_map"] == {}
    assert data["flow_map"] == {"a": 1, "b c": "x, y", "d": True}
    assert data["nested"] == {"inner": ["x", "y"], "same_indent_list": [1, 2]}
    assert data["items"] == [{"id": "A", "reason": "first"}, {"id": "B", "sub": {"k": "v"}}, {"id": "C"}, ["p", "q"], "plain"]
    assert marks[("name",)] == 3 and marks[("items", 1)] == 32 and marks[("items", 1, "sub", "k")] == 34


def test_yaml_empty_scalar_and_crlf_and_bom():
    assert P.parse_yaml("") is None
    assert P.parse_yaml("# only a comment\n\n") is None
    assert P.parse_yaml("just a string") == "just a string"
    assert P.parse_yaml("\ufeffa: 1\r\nb:\r\n  - x\r\n") == {"a": 1, "b": ["x"]}
    assert P.parse_yaml("- a\n- b: 1\n  c: 2\n") == ["a", {"b": 1, "c": 2}]


@pytest.mark.parametrize("text, code, line", [
    ("a: &anchor 1\n", "e_anchor", 1),
    ("a: 1\nb: *anchor\n", "e_alias", 2),
    ("a: [*.py]\n", "e_alias", 1),
    ("base: &b\n  x: 1\n", "e_anchor", 1),
    ("a:\n  <<: other\n", "e_merge_key", 2),
    ("a: !!python/object/apply:os.system ['id']\n", "e_tag", 1),
    ("a: !!binary abc\n", "e_tag", 1),
    ("a: |\n  text\n", "e_block_scalar", 1),
    ("a: >-\n  text\n", "e_block_scalar", 1),
    ("a: {b: 1, c}\n", "e_flow_map", 1),
    ("a: {b: 1 c: 2}\n", "e_inline_map", 1),
    ("a: {: 1}\n", "e_flow_map", 1),
    ("a: {b: }\n", "e_flow_map", 1),
    ("a: {b: {c: 1}}\n", "e_flow_nested", 1),
    ("a: {b: [1]}\n", "e_flow_nested", 1),
    ("a: {b: 1,\n  c: 2}\n", "e_flow_unterminated", 1),
    ("a: {b: 1, b: 2}\n", "e_dup_key", 1),
    ("a: {b: &x 1}\n", "e_anchor", 1),
    ("a: {<<: *x}\n", "e_merge_key", 1),
    ("a: [1, [2]]\n", "e_flow_nested", 1),
    ("a: [1, {b: 2}]\n", "e_flow_nested", 1),
    ("a: [1,\n  2]\n", "e_flow_unterminated", 1),
    ("a: [1 2, ,]\n", "e_flow_syntax", 1),
    ("a: [1] x\n", "e_after_quote", 1),
    ("a: \"x\" y\n", "e_after_quote", 1),
    ("a: \"unterminated\n", "e_unterminated_quote", 1),
    ("a: 'unterminated\n", "e_unterminated_quote", 1),
    ("a: \"bad \\q escape\"\n", "e_bad_escape", 1),
    ("a: \"\\uD800\"\n", "e_bad_escape", 1),
    ("a: 1\na: 2\n", "e_dup_key", 2),
    ("\"a\": 1\na: 2\n", "e_dup_key", 2),
    ("a:\n\tb: 1\n", "e_tab", 2),
    ("a: 1\n---\nb: 2\n", "e_multi_doc", 2),
    ("a: 1\n...\n", "e_multi_doc", 2),
    ("%YAML 1.2\n---\na: 1\n", "e_directive", 1),
    ("? a\n: b\n", "e_complex_key", 1),
    ("a: b: c\n", "e_inline_map", 1),
    ("a: - b\n", "e_inline_seq", 1),
    ("a: text\n  continued\n", "e_multiline_scalar", 2),
    ("a:\n    b: 1\n  c: 2\n", "e_indent", 3),
    ("- a\n  - b\n", "e_indent", 2),
    ("a: 1\n  b: 2\n", "e_multiline_scalar", 2),
    ("a: 1\njust text\n", "e_expected_key", 2),
    ("a: 1\n- b\n", "e_expected_key", 2),
    (": v\n", "e_empty_key", 1),
    ("a: @reserved\n", "e_reserved", 1),
    ("a: `cmd`\n", "e_reserved", 1),
    ("a: x\x00y\n", "e_control_char", 1),
    ("a: x\n\x1b[31m: 1\n", "e_control_char", 2),
])
def test_yaml_rejects_everything_outside_the_subset(text, code, line):
    p = yerr(text)
    assert (p.code, p.line) == (code, line), p.format()
    assert p.format("en").startswith(f"k.yml:{line}")
    assert p.message("ar") != p.message("en")          # every message exists in Arabic too


def test_yaml_limits_on_hostile_input():
    assert yerr("a: " + "x" * (P.MAX_BYTES + 10)).code == "e_too_big"
    assert yerr("a: " + "x" * (P.MAX_LINE + 10)).code == "e_line_too_long"
    deep = "".join(" " * i + f"k{i}:\n" for i in range(P.MAX_DEPTH + 5)) + " " * (P.MAX_DEPTH + 5) + "v: 1\n"
    assert yerr(deep).code == "e_depth"
    assert yerr("- " * 200 + "x\n").code == "e_depth"
    many = "".join(f"- {i}\n" for i in range(P.MAX_NODES + 5))
    assert yerr(many).code == "e_nodes"
    assert yerr("a: [" + ", ".join("1" for _ in range(P.MAX_NODES + 5)) + "]\n").code in ("e_nodes", "e_line_too_long")
    # a "billion laughs" document is rejected at the first anchor instead of being expanded
    bomb = "a: &a [x, x]\nb: &b [*a, *a]\nc: &c [*b, *b]\n"
    assert yerr(bomb).code == "e_anchor"
    # huge numbers stay strings: no big-int parsing cost
    assert P.parse_yaml("n: " + "9" * 5000) == {"n": "9" * 5000}
    assert P.parse_yaml("f: 1e999") == {"f": "1e999"}


def test_yaml_parser_never_crashes_on_garbage():
    rng = random.Random(1234)
    alphabet = "abc:-#'\"[]{}&*!|>%@ \n\t,?~\\0123"
    for _ in range(3000):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 60)))
        try:
            P.parse_yaml(text)
        except P.PolicyError as e:
            assert e.problems and e.problems[0].code in P.STR["en"] and e.problems[0].code in P.STR["ar"]


def test_dump_yaml_round_trip():
    data = {"name": "x y", "tricky": ["true", "null", "1", "a: b", " lead", "#c", "*.py", "it's", 'q"q', "-", "",
                                      "كاشِف", "line\nbreak"],
            "n": 3, "b": False, "none": None, "empty": [], "emap": {}, "nested": [{"a": 1, "b": [1, 2]}, [["x"], "y"]],
            "key: odd": {"k k": "v"}}
    assert P.parse_yaml(P.dump_yaml(data)) == data
    for scalar in ("x", 5, None, True, [], {}):
        assert P.parse_yaml(P.dump_yaml(scalar)) == scalar


# -------------------------------------------------------------------------------------------------------- validation
def test_empty_or_non_mapping_policy_is_rejected():
    assert err("").problems[0].code == "e_top_mapping"
    assert err("- a\n").problems[0].code == "e_top_mapping"
    assert err("[]", "json").problems[0].code == "e_top_mapping"


def test_validation_reports_every_problem_with_line_and_path():
    e = err("""\
version: 2
gate:
  fail_on: severe
  fail_onn: high
  max:
    medium: -1
    huge: 3
  max_total: many
  new_only: yes
  fail_on_cwe: [CWE-89, sqli]
  fail_on_owasp: [A03, A11]
scopes:
  - name: tests
  - name: a
    paths: ["src/**"]
    skip: true
rules:
  disable:
    - id: PY001
  severity:
    - id: PY002
      severity: urgent
      reason: because
ignores:
  - reason: no selector
    approver: me
    expires: 2027-01-01
  - rule: PY003
    reason: no approver or expiry
  - rule: PY004
    reason: bad date
    approver: me
    expires: 31/12/2027
  - rule: PY005
    reason: impossible date
    approver: me
    expires: 2027-02-30
required_scanners: [deps, "Not Valid"]
sla:
  high: 0
reports:
  - format: sarif
    path: ../../etc/passwd
  - format: html
    path: /abs/report.html
unknown_top: 1
""")
    got = {(p.path, p.code, p.line) for p in e.problems}
    expected = {
        ("version", "e_version", 1), ("gate.fail_on", "e_severity", 3), ("gate.fail_onn", "e_unknown_key", 4),
        ("gate.max.medium", "e_int_min", 6), ("gate.max.huge", "e_severity", 7), ("gate.max_total", "e_type", 8),
        ("gate.new_only", "e_type", 9), ("gate.fail_on_cwe[1]", "e_cwe", 10), ("gate.fail_on_owasp[1]", "e_owasp", 11),
        ("scopes[0]", "e_required", 13), ("scopes[1]", "e_required", 14), ("rules.disable[0]", "e_required", 19),
        ("rules.severity[0].severity", "e_severity", 22), ("ignores[0]", "e_selector", 25),
        ("ignores[1]", "e_required", 28), ("ignores[2].expires", "e_date", 33), ("ignores[3].expires", "e_date", 37),
        ("required_scanners[1]", "e_identifier", 38), ("sla.high", "e_int_min", 40),
        ("reports[0].path", "e_report_path", 43), ("reports[1].path", "e_report_path", 45),
        ("unknown_top", "e_unknown_key", 46),
    }
    assert expected <= got, sorted(expected - got)
    text = e.format("en")
    assert "k.yml" not in text and "<policy>:4: [gate.fail_onn] unknown key 'fail_onn' (did you mean 'fail_on'?)" in text
    assert "هل تقصد 'fail_on'" in e.format("ar")
    assert all(p.to_dict()["message_ar"] for p in e.problems)


def test_mandatory_reason_approver_expiry():
    base = "ignores:\n  - rule: PY1\n"
    for missing in ("reason", "approver", "expires"):
        fields = {"reason": "r", "approver": "a", "expires": "2027-01-01"}
        del fields[missing]
        e = err(base + "".join(f"    {k}: {v}\n" for k, v in fields.items()))
        assert [(p.code, p.args["key"]) for p in e.problems] == [("e_required", missing)]
    assert err("rules:\n  disable:\n    - id: X\n      reason: ''\n").problems[0].path == "rules.disable[0].reason"
    assert err("rules:\n  severity:\n    - id: X\n      severity: low\n").problems[0].code == "e_required"
    assert err("rules:\n  disable:\n    - id: X\n      reason: r\n  enable: [X]\n").problems[0].code == "e_enable_conflict"
    assert err("scopes:\n  - name: default\n    paths: [a]\n").problems[0].code == "e_dup_name"
    assert err("ignores:\n  - fingerprint: xyz\n    reason: r\n    approver: a\n    expires: 2027-01-01\n") \
        .problems[0].code == "e_fingerprint"


def test_json_policy_and_json_hardening(tmp_path):
    good = {"version": 1, "name": "j", "gate": {"fail_on": "medium", "fail_on_cwe": ["CWE-79", 89]},
            "ignores": [{"rule": "PY1", "reason": "r", "approver": "a", "expires": "2027-01-01"}]}
    f = tmp_path / "kashif.json"
    f.write_text(json.dumps(good), encoding="utf-8")
    p = P.load_policy(f)
    assert p.name == "j" and p.gate["fail_on"] == "medium" and p.gate["fail_on_cwe"] == [79, 89]
    assert err('{"gate": {"fail_on": "high", "fail_on": "low"}}', "json").problems[0].code == "e_dup_key"
    assert err('{"gate": {"max_total": NaN}}', "json").problems[0].code == "e_json_const"
    e = err('{"gate": \n {"fail_on": }', "json").problems[0]
    assert e.code == "e_json" and e.line == 2
    assert err("[" * 100000 + "]" * 100000, "json").problems[0].code == "e_depth"
    assert err('{"a": "' + "x" * P.MAX_BYTES + '"}', "json").problems[0].code == "e_too_big"
    assert err('{"gate": {"fail_on": 5}}', "json").problems[0].path == "gate.fail_on"


def test_load_policy_file_errors(tmp_path):
    with pytest.raises(P.PolicyError) as e:
        P.load_policy(tmp_path / "missing.yml")
    assert e.value.problems[0].code == "e_not_file"
    (tmp_path / "p.toml").write_text("x = 1", encoding="utf-8")
    with pytest.raises(P.PolicyError) as e:
        P.load_policy(tmp_path / "p.toml")
    assert e.value.problems[0].code == "e_ext"
    (tmp_path / "bin.yml").write_bytes(b"name: \xff\xfe\n")
    with pytest.raises(P.PolicyError) as e:
        P.load_policy(tmp_path / "bin.yml")
    assert e.value.problems[0].code == "e_encoding"
    (tmp_path / "big.yml").write_bytes(b"# " + b"x" * (P.MAX_BYTES + 1))
    with pytest.raises(P.PolicyError) as e:
        P.load_policy(tmp_path / "big.yml")
    assert e.value.problems[0].code == "e_too_big"
    (tmp_path / "kashif.yml").write_text("name: here\n", encoding="utf-8")
    assert P.find_policy(tmp_path) == str(tmp_path / "kashif.yml")
    assert P.find_policy(tmp_path / "kashif.yml") == str(tmp_path / "kashif.yml")
    assert P.find_policy(tmp_path / "nope") is None


def test_defaults_and_to_dict_round_trip():
    p = pol("name: d\n")
    assert p.gate["fail_on"] == "high" and p.gate["fail_on_secrets"] and p.gate["fail_on_expired"]
    assert not p.gate["new_only"] and not p.gate["fail_on_sla_breach"]
    full = pol("""\
name: full
gate: {}
scopes:
  - name: t
    paths: tests
    fail_on: never
rules:
  disable:
    - id: A1
      reason: r
  enable: [B1]
  severity:
    - id: C1
      severity: low
      reason: r
ignores:
  - cwe: 79
    fingerprint: ABCDEF0123
    reason: r
    approver: a
    expires: "2027-01-01"
    ticket: T-1
required_scanners: deps
sla: {high: 30}
reports:
  - format: sarif
    path: out\\k.sarif
locked: [gate.fail_on]
""")
    assert full.scopes[0]["fail_on"] is None and full.scopes[0]["paths"] == ["tests"]
    assert full.ignores[0]["fingerprint"] == "abcdef0123" and full.reports[0]["path"] == "out/k.sarif"
    again = pol(P.dump_yaml(full.to_dict()))
    assert again.to_dict() == full.to_dict()
    assert P.load_policy_text(json.dumps(full.to_dict()), "json").to_dict() == full.to_dict()


def test_unknown_report_format_is_a_warning():
    p = pol("reports:\n  - format: junit\n    path: r.xml\n")
    assert [w.code for w in p.warnings] == ["w_report_format"]
    d = P.evaluate([], p, {"today": TODAY})
    assert d.passed and "junit" in d.warnings[0].message("en") and "junit" in d.warnings[0].message("ar")


# ------------------------------------------------------------------------------------------------------- inheritance
def test_presets_are_valid_and_listed():
    assert set(P.PRESETS) == {"owasp-asvs-l1", "pci-dss", "strict", "startup"}
    for name in P.PRESETS:
        p = P.builtin_policy(name)
        assert p.name == name and p.gate["fail_on_secrets"] and p.source == f"builtin:{name}"
        assert P.load_policy(name).to_dict() == p.to_dict()
        assert pol(P.init_template(name)).gate == p.gate
        assert pol(P.init_template(name, expand=True)).gate == p.gate
        assert f"p_{name}" in P.STR["en"] and f"p_{name}" in P.STR["ar"]
    assert P.builtin_policy("strict").gate["fail_on"] == "medium"
    assert P.builtin_policy("startup").gate["fail_on"] == "critical"
    assert 89 in P.builtin_policy("pci-dss").gate["fail_on_cwe"]
    with pytest.raises(KeyError):
        P.builtin_policy("nope")


def test_extends_builtin_merges():
    p = pol("""\
extends: pci-dss
gate:
  fail_on: medium
  max: {low: 5}
  fail_on_cwe: [1234]
required_scanners: [external]
sla: {critical: 2}
""")
    base = P.builtin_policy("pci-dss")
    assert p.gate["fail_on"] == "medium" and p.gate["max"] == {"low": 5}
    assert p.gate["fail_on_cwe"] == base.gate["fail_on_cwe"] + [1234]          # forbid lists are unions
    assert p.required_scanners == base.required_scanners + ["external"]
    assert p.sla == {**base.sla, "critical": 2}
    assert p.chain == ["<policy>", "builtin:pci-dss"]
    assert pol("extends: builtin:strict\n").gate["fail_on"] == "medium"


def test_extends_files_chain_scopes_rules_and_locks(tmp_path):
    (tmp_path / ".git").mkdir()                 # one repository: "extends" may cross its directories
    org = tmp_path / "org"
    org.mkdir()
    (org / "base.yml").write_text("""\
name: org-base
extends: startup
gate:
  fail_on: high
scopes:
  - name: tests
    paths: ["tests/**"]
    fail_on: critical
  - name: docs
    paths: ["docs/**"]
    skip: true
    reason: "no code"
rules:
  disable:
    - id: NOISY1
      reason: "org-wide false positives"
    - id: NOISY2
      reason: "org-wide false positives"
  severity:
    - id: SEC004
      severity: critical
      reason: "org rule"
ignores:
  - rule: ORG1
    reason: r
    approver: ciso
    expires: 2027-01-01
reports:
  - format: sarif
    path: a.sarif
locked: [gate.fail_on, gate.fail_on_secrets]
""", encoding="utf-8")
    (org / "team.json").write_text(json.dumps({"extends": "base.yml", "gate": {"max_total": 9}}), encoding="utf-8")
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "kashif.yml").write_text("""\
extends: ["../org/team.json"]
gate:
  fail_on: high          # same value as the locked one: allowed
scopes:
  - name: tests
    paths: ["spec/**"]
    max_total: 50          # (fail_on is locked by the organisation: a scope may not change it either)
rules:
  enable: [NOISY1]
  disable:
    - id: MINE
      reason: mine
  severity:
    - id: SEC004
      severity: high
      reason: "team override"
ignores:
  - rule: TEAM1
    reason: r
    approver: lead
    expires: 2027-01-01
reports:
  - format: html
    path: a.sarif
""", encoding="utf-8")
    p = P.load_policy(proj / "kashif.yml")
    assert p.name == "kashif" and p.gate["max_total"] == 9 and p.gate["fail_on"] == "high"
    assert [s["name"] for s in p.scopes] == ["tests", "docs"]            # child scope replaces and comes first
    assert p.scopes[0]["paths"] == ["spec/**"] and p.scopes[0]["max_total"] == 50
    assert [d["id"] for d in p.disabled] == ["NOISY2", "MINE"] and p.enabled == ["NOISY1"]
    assert [(s["id"], s["severity"]) for s in p.severity_overrides] == [("SEC004", "high")]
    assert [i["rule"] for i in p.ignores] == ["ORG1", "TEAM1"]
    assert p.reports == [{"format": "html", "path": "a.sarif"}]
    assert p.required_scanners == ["secrets"] and p.sla["critical"] == 14     # from "startup", two levels up
    assert [re.split(r"[\\/]", c)[-1] for c in p.chain] == ["kashif.yml", "team.json", "base.yml", "builtin:startup"]

    (proj / "weaker.yml").write_text("extends: ../org/team.json\ngate:\n  fail_on_secrets: false\n", encoding="utf-8")
    with pytest.raises(P.PolicyError) as e:
        P.load_policy(proj / "weaker.yml")
    prob = e.value.problems[0]
    assert (prob.code, prob.line, prob.path) == ("e_locked", 3, "gate.fail_on_secrets")
    assert "team.json" in prob.message("en") and "مقفل" in prob.message("ar")


def test_extends_errors(tmp_path):
    assert err("extends: nonsense\n").problems[0].code == "e_extends_unknown"
    assert err("extends: https://evil.example/p.yml\n").problems[0].code == "e_extends_unknown"
    assert err("extends: builtin:nope\n").problems[0].code == "e_extends_unknown"
    assert err("extends: /etc/passwd\n").problems[0].code == "e_extends_unknown"
    (tmp_path / "a.yml").write_text("extends: b.yml\n", encoding="utf-8")
    (tmp_path / "b.yml").write_text("extends: a.yml\n", encoding="utf-8")
    with pytest.raises(P.PolicyError) as e:
        P.load_policy(tmp_path / "a.yml")
    assert e.value.problems[0].code == "e_extends_cycle"
    (tmp_path / "self.yml").write_text("extends: self.yml\n", encoding="utf-8")
    with pytest.raises(P.PolicyError) as e:
        P.load_policy(tmp_path / "self.yml")
    assert e.value.problems[0].code == "e_extends_cycle"
    (tmp_path / "gone.yml").write_text("name: x\nextends: missing.yml\n", encoding="utf-8")
    with pytest.raises(P.PolicyError) as e:
        P.load_policy(tmp_path / "gone.yml")
    assert (e.value.problems[0].code, e.value.problems[0].line) == ("e_extends_missing", 2)
    for i in range(12):
        (tmp_path / f"d{i}.yml").write_text(f"extends: d{i + 1}.yml\n" if i < 11 else "name: end\n", encoding="utf-8")
    with pytest.raises(P.PolicyError) as e:
        P.load_policy(tmp_path / "d0.yml")
    assert e.value.problems[0].code == "e_extends_depth"
    (tmp_path / "bad_parent.yml").write_text("gate:\n  fail_on: nope\n", encoding="utf-8")
    (tmp_path / "child.yml").write_text("extends: bad_parent.yml\n", encoding="utf-8")
    with pytest.raises(P.PolicyError) as e:
        P.load_policy(tmp_path / "child.yml")
    assert e.value.problems[0].source.endswith("bad_parent.yml") and e.value.problems[0].line == 2


# -------------------------------------------------------------------------------------------------------- conditions
def test_path_patterns():
    m = P.path_matches
    assert m("tests/**", "tests/a/b.py") and m("tests/", "tests/a.py") and m("tests", "tests/a.py")
    assert not m("tests", "tests2/a.py") and not m("tests/**", "src/tests/a.py")
    assert m("**/tests/**", "src/tests/a.py") and m("**/tests/**", "tests/a.py")
    assert m("src/*.py", "src/a.py") and not m("src/*.py", "src/x/a.py")
    assert m("*.min.js", "static/js/app.min.js") and not m("*.min.js", "app.js")
    assert m("src/**/gen_?.py", "src/a/b/gen_1.py") and not m("src/**/gen_?.py", "src/gen_12.py")
    assert m("src/[ab]*.py", "src/b1.py") and not m("src/[!ab]*.py", "src/b1.py")
    assert m("./src/a.py", "src\\a.py") and m("src/a.py", "./src/a.py")
    assert not m("", "a")


def test_severity_threshold():
    fs = [F(sev="medium"), F(sev="low", line=2)]
    assert run("gate:\n  fail_on: high\n", fs).passed
    d = run("gate:\n  fail_on: medium\n", fs)
    assert not d.passed and d.exit_code == 1 and codes(d) == ["severity-threshold"]
    assert d.violations[0].args["count"] == 1 and d.violations[0].findings[0]["severity"] == "medium"
    assert not run("gate:\n  fail_on: info\n", fs).passed
    assert run("gate:\n  fail_on: never\n", [F(sev="critical")]).passed
    assert not run("name: defaults\n", [F(sev="high")]).passed           # default threshold is high


def test_max_counts_and_total():
    fs = [F(sev="medium", line=i) for i in range(3)] + [F(sev="low", line=9)]
    text = "gate:\n  fail_on: never\n  max:\n    medium: {m}\n    low: 1\n  max_total: {t}\n"
    assert run(text.format(m=3, t=4), fs).passed
    d = run(text.format(m=2, t=4), fs)
    assert codes(d) == ["max-count"] and d.violations[0].args == {"count": 3, "severity": "medium", "max": 2}
    d = run(text.format(m=3, t=3), fs)
    assert codes(d) == ["max-total"] and len(d.violations[0].findings) == 4
    assert codes(run("gate:\n  fail_on: never\n  max: {critical: 0}\n", [F(sev="critical")])) == ["max-count"]


def test_forbidden_cwe_rules_owasp():
    fs = [F("PY001", "low", cwe="CWE-89"), F("JS010", "low", cwe="CWE-79", line=2), F("SEC004", "info", cwe="", line=3),
          F("X1", "low", cwe="CWE-918", line=4)]
    base = "gate:\n  fail_on: never\n  fail_on_secrets: false\n"
    assert run(base, fs).passed
    d = run(base + "  fail_on_cwe: [CWE-89, 611]\n", fs)
    assert codes(d) == ["forbidden-cwe"] and d.violations[0].args["cwe"] == 89
    d = run(base + "  fail_on_rules: ['SEC*', JS010, NOPE]\n", fs)
    assert [(v.code, v.args["rule"]) for v in d.violations] == [("forbidden-rule", "SEC*"), ("forbidden-rule", "JS010")]
    d = run(base + "  fail_on_owasp: [a3, 'A10:2021', A06]\n", fs)
    assert [(v.code, v.args["category"], v.args["count"]) for v in d.violations] == \
        [("forbidden-owasp", "A03", 2), ("forbidden-owasp", "A10", 1)]


def test_owasp_fallback_table(monkeypatch):
    class Broken(P._Owasp):
        def __init__(self):
            self.cache, self.map, self.fallback = {}, None, True
    monkeypatch.setattr(P, "_Owasp", Broken)
    d = run("gate:\n  fail_on: never\n  fail_on_owasp: [A03]\n", [F(sev="low", cwe="CWE-89")])
    assert codes(d) == ["forbidden-owasp"] and [w.code for w in d.warnings] == ["owasp-fallback"]


def test_secrets_always_fail():
    secret = F("SEC004", "low", cwe="CWE-798")
    assert codes(run("gate:\n  fail_on: never\n", [secret])) == ["secret"]
    assert codes(run("gate:\n  fail_on: never\n", [F("X", "info", cwe="CWE-321")])) == ["secret"]
    assert codes(run("gate:\n  fail_on: never\n", [F("generic-api-key", "low", cwe="", source="gitleaks")])) == ["secret"]
    # even when the gate only looks at new findings and the secret is in the baseline
    d = run("gate:\n  fail_on: high\n  new_only: true\n", [secret, F(sev="critical", line=3)],
            baseline=[secret["fingerprint"], F(sev="critical", line=3)["fingerprint"]])
    assert codes(d) == ["secret"]
    assert run("gate:\n  fail_on: never\n  fail_on_secrets: false\n", [secret]).passed
    # an accountable, unexpired ignore does apply to a secret
    d = run("gate:\n  fail_on: never\nignores:\n  - rule: SEC004\n    path: src/app.py\n    reason: test fixture\n"
            "    approver: lead\n    expires: 2026-12-31\n", [secret])
    assert d.passed and d.stats["ignored"] == 1


def test_new_only_with_baseline_changed_files_and_flags(tmp_path):
    old, new = F(sev="critical", line=1), F(sev="critical", file="src/new.py", line=2)
    text = "gate:\n  new_only: true\n"
    d = run(text, [old, new], baseline={old["fingerprint"]})
    assert codes(d) == ["severity-threshold"] and [f["file"] for f in d.violations[0].findings] == ["src/new.py"]
    assert d.stats["not_new"] == 1
    assert run(text, [old], baseline={old["fingerprint"]}).passed
    # changed files / changed lines
    assert codes(run(text, [old, new], changed=["./src/new.py"])) == ["severity-threshold"]
    assert run(text, [old, new], changed=["README.md"]).passed
    assert run(text, [old, new], changed={"src/new.py": [40, 41]}).passed
    assert not run(text, [old, new], changed={"src/new.py": [2]}).passed
    assert not run(text, [old, new], changed_files={"src/new.py": None}).passed
    # extra["new"] flags written by the CLI's --baseline
    assert run(text, [F(sev="critical", new=False)]).passed
    assert not run(text, [F(sev="critical", new=True)]).passed
    # no reference at all: fail closed, with a warning
    d = run(text, [old])
    assert not d.passed and [w.code for w in d.warnings] == ["new-only-no-reference"]
    # baseline named in the policy, resolved against base_dir
    bl = tmp_path / "bl.json"
    bl.write_text(json.dumps({"schema": "vulnscan-baseline/1", "fingerprints": [{"fp": old["fingerprint"]}]}), "utf-8")
    text2 = "gate:\n  new_only: true\n  baseline: bl.json\n"
    assert run(text2, [old], base_dir=tmp_path).passed
    assert not run(text2, [old, new], base_dir=tmp_path).passed
    d = run("gate:\n  new_only: true\n  baseline: missing.json\n", [old], base_dir=tmp_path)
    assert not d.passed and [w.code for w in d.warnings] == ["baseline-unreadable"]
    assert run(text, [old], baseline=str(bl)).passed


def test_scopes_thresholds_and_skip():
    text = """\
gate:
  fail_on: high
  fail_on_cwe: [89]
scopes:
  - name: tests
    paths: ["tests/**", "**/test_*.py"]
    fail_on: never
    fail_on_cwe: []
    fail_on_secrets: false
  - name: vendored
    paths: ["third_party/**"]
    skip: true
    reason: "vendored"
  - name: legacy
    paths: ["src/legacy/**"]
    fail_on: critical
    max: {high: 1}
    new_only: true
"""
    relaxed = [F(sev="critical", file="tests/t.py"), F("SEC001", "critical", file="src/x/test_a.py", cwe="CWE-798"),
               F(sev="critical", file="third_party/lib/a.c"), F("Z", "high", file="src/legacy/a.py", cwe="")]
    d = run(text, relaxed, baseline=[])
    assert d.passed, P.explain(d)
    assert d.stats["skipped"] == 1 and d.stats["evaluated"] == 3
    assert d.stats["scopes"]["tests"]["total"] == 2 and d.stats["scopes"]["legacy"]["by_severity"]["high"] == 1
    d = run(text, relaxed + [F("Z", "high", file="src/legacy/b.py", cwe=""), F("Q", "medium", file="src/main.py")],
            baseline=[])
    assert [(v.code, v.scope) for v in d.violations] == [("forbidden-cwe", "default"), ("max-count", "legacy")]
    d = run(text, [F("Z", "critical", file="src/legacy/a.py", cwe="")], baseline=[])
    assert [(v.code, v.scope) for v in d.violations] == [("severity-threshold", "legacy")]
    assert "legacy" in d.violations[0].message("en") and "legacy" in d.violations[0].message("ar")
    # first matching scope wins
    first = "scopes:\n  - name: a\n    paths: [src]\n    fail_on: never\n  - name: b\n    paths: [src/x]\n    fail_on: info\n"
    assert run(first, [F(sev="critical", file="src/x/a.py", cwe="")]).passed


def test_rule_disable_enable_and_severity_override():
    text = """\
gate:
  fail_on: high
rules:
  disable:
    - id: "WEB*"
      reason: "not a web app"
  enable: [WEB999]
  severity:
    - id: PY050
      severity: info
      reason: "internal tool"
    - id: LOW1
      severity: critical
      reason: "release blocker here"
"""
    d = run(text, [F("WEB001", "critical"), F("PY050", "high", line=2)])
    assert d.passed and d.stats["disabled"] == 1 and d.stats["by_severity"]["info"] == 1
    d = run(text, [F("WEB999", "high")])
    assert codes(d) == ["severity-threshold"]
    d = run(text, [F("LOW1", "low")])
    assert codes(d) == ["severity-threshold"] and d.violations[0].findings[0]["severity"] == "critical"


IGN = """\
gate:
  fail_on: high
  {extra}
ignores:
  - rule: PY001
    path: "src/**"
    reason: "validated upstream"
    approver: "sec-lead"
    expires: {expires}
"""


def test_ignore_valid_expiring_expired_unused():
    f = F("PY001", "critical")
    d = run(IGN.format(extra="", expires="2026-12-31"), [f])
    assert d.passed and d.stats["ignored"] == 1 and not d.warnings
    assert run(IGN.format(extra="", expires="2026-06-15"), [f]).passed              # valid through the expiry day
    d = run(IGN.format(extra="", expires="2026-06-20"), [f])
    assert d.passed and [w.code for w in d.warnings] == ["ignore-expiring"] and d.warnings[0].args["days"] == 5
    d = run(IGN.format(extra="", expires="2026-06-14"), [f])
    assert codes(d) == ["expired-ignore", "severity-threshold"]
    v = d.violations[0]
    assert v.args["days"] == 1 and v.args["approver"] == "sec-lead" and v.args["count"] == 1
    assert "sec-lead" in v.message("en") and "2026-06-14" in v.message("ar")
    # other selectors do not match: the ignore is unused (warning), the finding still counts
    d = run(IGN.format(extra="", expires="2026-12-31"), [F("PY001", "critical", file="lib/a.py")])
    assert codes(d) == ["severity-threshold"] and [w.code for w in d.warnings] == ["ignore-unused"]
    d = run(IGN.format(extra="", expires="2020-01-01"), [])
    assert d.passed and [w.code for w in d.warnings] == ["ignore-expired-unused"]
    # fail_on_expired: false -> the expired ignore is a warning, the finding still fails on its own severity
    d = run(IGN.format(extra="fail_on_expired: false", expires="2026-06-14"), [f])
    assert codes(d) == ["severity-threshold"] and [w.code for w in d.warnings] == ["expired-not-enforced"]
    d = run(IGN.format(extra="fail_on_expired: false", expires="2026-06-14"), [F("PY001", "low")])
    assert d.passed
    # an expired ignore fails the gate even when the finding itself is below the threshold
    assert codes(run(IGN.format(extra="", expires="2026-06-14"), [F("PY001", "low")])) == ["expired-ignore"]


def test_ignore_selectors_cwe_and_fingerprint():
    f = F("PY001", "critical", cwe="CWE-89, CWE-564")
    tail = "    reason: r\n    approver: a\n    expires: 2026-12-31\n"
    assert run("ignores:\n  - cwe: CWE-564\n" + tail, [f]).passed
    assert not run("ignores:\n  - cwe: 79\n" + tail, [f]).passed
    assert run(f"ignores:\n  - fingerprint: \"{f['fingerprint']}\"\n" + tail, [f]).passed
    assert run(f"ignores:\n  - fingerprint: \"{f['fingerprint'][:10]}\"\n" + tail, [f]).passed
    assert not run("ignores:\n  - fingerprint: \"0123456789abcdef:7\"\n" + tail, [f]).passed
    assert not run(f"ignores:\n  - fingerprint: \"{f['fingerprint'][:10]}\"\n    rule: OTHER\n" + tail, [f]).passed


def test_max_acceptance_days():
    f = F("PY001", "critical")
    d = run(IGN.format(extra="max_acceptance_days: 90", expires="2027-06-15"), [f])
    assert codes(d) == ["acceptance-too-long", "severity-threshold"] and d.violations[0].args["days"] == 365
    assert run(IGN.format(extra="max_acceptance_days: 90", expires="2026-09-13"), [f]).passed


def test_triage_state_and_expired_risk_acceptance():
    accepted = F(sev="critical", triage={"status": "accepted_risk", "expires": "2026-12-01"})
    fp = F(sev="critical", line=2, triage={"status": "false_positive"})
    d = run("name: t\n", [accepted, fp])
    assert d.passed and d.stats["triaged"] == 2
    expired = F(sev="low", line=3, triage={"status": "open", "expired": True, "expires": "2026-01-01"})
    d = run("name: t\n", [expired])
    assert codes(d) == ["expired-acceptance"] and d.violations[0].args["count"] == 1
    d = run("gate:\n  fail_on_expired: false\n", [expired])
    assert d.passed and [w.code for w in d.warnings] == ["expired-not-enforced"]


def test_required_scanners():
    text = "gate:\n  fail_on: never\nrequired_scanners: [deps, secrets]\n"
    d = run(text, [])
    assert [(v.code, v.args["scanner"]) for v in d.violations] == [("required-scanner", "deps"), ("required-scanner", "secrets")]
    assert "deps" in d.violations[0].message("ar")
    assert run(text, [], scanners=["deps", "secrets", "sast"]).passed
    assert codes(run(text, [], scanners={"secrets"})) == ["required-scanner"]
    # inferred from a Kashif JSON report: source scan => sast + secrets; the dependency note or an OSV finding => deps
    meta = {"target": "/repo", "files_scanned": 12, "notes": []}
    assert codes(run(text, [], meta=meta)) == ["required-scanner"]
    assert run(text, [], meta={**meta, "notes": ["استعلام OSV.dev عن الاعتماديات: 0 ثغرة معروفة."]}).passed
    assert run(text, [F("GHSA-x", "low", file="requirements.txt", cwe="", source="osv")], meta=meta).passed
    assert not run(text, [], meta={**meta, "notes": ["OSV lookup failed: timeout"]}).passed
    assert run(text, [], meta={"scanners": ["deps", "secrets"]}).passed
    assert not run(text, [], meta={"target": "https://example.com", "files_scanned": 1}).passed
    # explicit context is authoritative
    assert not run(text, [], meta={"scanners": ["deps", "secrets"]}, scanners=[]).passed


def test_sla():
    old = F(sev="high", line=1)
    fresh = F(sev="high", line=2)
    undated = F(sev="high", line=3)
    tri = F(sev="critical", line=4, triage={"status": "open", "first_seen": "2026-06-01T10:00:00Z"})
    seen = {old["fingerprint"]: "2026-05-01", fresh["fingerprint"]: datetime.date(2026, 6, 10)}
    text = "gate:\n  fail_on: never\n  fail_on_sla_breach: {b}\nsla:\n  critical: 7\n  high: 30\n"
    d = run(text.format(b="true"), [old, fresh, undated, tri], first_seen=seen)
    assert [(v.code, v.args["severity"], v.args["count"], v.args["oldest"]) for v in d.violations] == \
        [("sla-breach", "critical", 1, 14), ("sla-breach", "high", 1, 45)]
    assert [w.code for w in d.warnings] == ["sla-no-dates"]
    assert "30" in d.violations[1].message("en") and "30" in d.violations[1].message("ar")
    d = run(text.format(b="false"), [old, fresh], first_seen=seen)
    assert d.passed and [w.code for w in d.warnings] == ["sla-breach"]
    assert run(text.format(b="true"), [fresh], first_seen=seen).passed
    assert run(text.format(b="true"), [old], first_seen=seen, today="2026-05-31").passed       # day 30 is still in time


def test_warnings_as_errors_and_unknown_severity():
    d = P.evaluate([F(sev="weird")], pol("gate:\n  fail_on: high\n"), {"today": TODAY})
    assert d.passed and [w.code for w in d.warnings] == ["unknown-severity"] and d.stats["by_severity"]["medium"] == 1
    d = P.evaluate([F(sev="weird")], pol("gate:\n  fail_on: high\n"), {"today": TODAY}, warnings_as_errors=True)
    assert codes(d) == ["warnings-as-errors"]


def test_evaluate_accepts_finding_objects_and_does_not_mutate():
    f = Finding("PY001", "high", "SQL injection", "حقن SQL", "src/a.py", 5, "cur.execute(q)", "نصيحة", "CWE-89")
    before = json.dumps(f.to_dict(), sort_keys=True)
    d = P.evaluate([f], pol("rules:\n  severity:\n    - id: PY001\n      severity: critical\n      reason: r\n"),
                   P.Context(today=TODAY))
    assert not d.passed and d.violations[0].findings[0]["fingerprint"] == f.fingerprint()
    assert json.dumps(f.to_dict(), sort_keys=True) == before and f.severity == "high"
    with pytest.raises(TypeError):
        P.evaluate(["nope"], pol("name: x\n"))
    with pytest.raises(TypeError):
        P.evaluate([], pol("name: x\n"), context=3)
    with pytest.raises(ValueError):
        P.evaluate([], pol("name: x\n"), {"today": "yesterday"})


# ----------------------------------------------------------------------------------------------------------- explain
def test_explain_text_markdown_json_in_both_languages():
    fs = [F(sev="critical", line=i, file="src/we|ird.py") for i in range(15)]
    d = run("name: demo\ngate:\n  fail_on: high\nrequired_scanners: [deps]\n", fs)
    text = P.explain(d)
    assert "Kashif security gate: FAILED" in text and "[severity-threshold]" in text and "... and 5 more" in text
    assert "Exit code: 1" in text and "demo" in text and "2026-06-15" in text
    ar = P.explain(d, "text", "ar")
    assert "فشلت" in ar and "المخالفات (2)" in ar and "FAILED" not in ar
    md = P.explain(d, "markdown", "en", limit=3)
    assert md.startswith("## Kashif security gate: FAILED") and "src/we\\|ird.py:0" in md and "... and 12 more" in md
    data = json.loads(P.explain(d, "json", "ar"))
    assert data["passed"] is False and data["exit_code"] == 1 and data["lang"] == "ar"
    assert data["violations"][0]["message"] == data["violations"][0]["message_ar"] != data["violations"][0]["message_en"]
    assert len(data["violations"][0]["findings"]) == 15 and data["stats"]["total"] == 15
    ok = P.evaluate([], pol("name: ok\n"), {"today": TODAY})
    assert "PASSED" in P.explain(ok) and "نجحت" in P.explain(ok, "md", "ar") and ok.exit_code == 0
    with pytest.raises(ValueError):
        P.explain(ok, "xml")


def test_every_string_exists_in_both_languages():
    assert set(P.STR["en"]) == set(P.STR["ar"])
    for key, text in P.STR["en"].items():
        import string
        fields_en = {f for _, f, _, _ in string.Formatter().parse(text) if f}
        fields_ar = {f for _, f, _, _ in string.Formatter().parse(P.STR["ar"][key]) if f}
        assert fields_en == fields_ar, key


# --------------------------------------------------------------------------------------------------------------- CLI
def _report(tmp_path, findings, **meta):
    path = tmp_path / "report.json"
    path.write_text(json.dumps({"target": "/repo", "files_scanned": 3, "notes": [], **meta, "findings": findings}), "utf-8")
    return str(path)


def test_cli_check(tmp_path, capsys, monkeypatch):
    policy_file = tmp_path / "kashif.yml"
    policy_file.write_text("name: cli\ngate:\n  fail_on: high\n  new_only: true\n", encoding="utf-8")
    old, new = F(sev="critical"), F(sev="critical", file="src/new.py")
    report = _report(tmp_path, [old, new])
    assert P.main(["check", report, "--policy", str(policy_file), "--today", "2026-06-15", "--lang", "en"]) == 1
    out = capsys.readouterr().out
    assert "FAILED" in out and "new_only is set but there is no baseline" in out
    baseline = tmp_path / "bl.json"
    baseline.write_text(json.dumps({"fingerprints": [{"fp": old["fingerprint"]}, {"fp": new["fingerprint"]}]}), "utf-8")
    assert P.main(["check", report, "--policy", str(policy_file), "--baseline", str(baseline), "--lang", "ar"]) == 0
    assert "نجحت" in capsys.readouterr().out
    changed = tmp_path / "changed.txt"
    changed.write_text("src/new.py\n", encoding="utf-8")
    out_file = tmp_path / "gate.json"
    assert P.main(["check", report, "--policy", str(policy_file), "--changed-files", str(changed), "-f", "json",
                   "-o", str(out_file)]) == 1
    data = json.loads(out_file.read_text("utf-8"))
    assert [f["file"] for f in data["violations"][0]["findings"]] == ["src/new.py"]
    # builtin preset as the policy, scanners asserted on the command line; a bare JSON list is accepted too
    bare = tmp_path / "list.json"
    bare.write_text(json.dumps([F(sev="low")]), encoding="utf-8")
    assert P.main(["check", str(bare), "--policy", "startup"]) == 1                 # required scanner "secrets" unverified
    assert "required-scanner" in capsys.readouterr().out
    assert P.main(["check", str(bare), "--policy", "startup", "--scanners", "secrets", "-f", "markdown"]) == 0
    assert capsys.readouterr().out.startswith("## ")
    # policy discovered in the current directory
    monkeypatch.chdir(tmp_path)
    assert P.main(["check", report, "--baseline", str(baseline)]) == 0
    capsys.readouterr()


def test_cli_errors_return_2(tmp_path, capsys, monkeypatch):
    report = _report(tmp_path, [])
    bad = tmp_path / "bad.yml"
    bad.write_text("gate:\n  fail_on: &x high\n", encoding="utf-8")
    assert P.main(["check", report, "--policy", str(bad), "--lang", "en"]) == 2
    assert f"{bad}:2:" in capsys.readouterr().err
    assert P.main(["check", report, "--policy", str(bad), "--lang", "ar"]) == 2
    assert "مراسي" in capsys.readouterr().err
    assert P.main(["check", str(tmp_path / "none.json"), "--policy", "strict"]) == 2
    (tmp_path / "broken.json").write_text("{", encoding="utf-8")
    assert P.main(["check", str(tmp_path / "broken.json"), "--policy", "strict"]) == 2
    (tmp_path / "shape.json").write_text('{"x": 1}', encoding="utf-8")
    assert P.main(["check", str(tmp_path / "shape.json"), "--policy", "strict"]) == 2
    assert P.main(["check", report, "--policy", "strict", "--today", "soon"]) == 2
    assert P.main(["check", report, "--policy", "strict", "--baseline", str(tmp_path / "nope")]) == 2
    assert P.main(["check"]) == 2 and P.main([]) == 2 and P.main(["--help"]) == 0
    monkeypatch.chdir(tmp_path / ".." if False else tmp_path)
    (tmp_path / "empty").mkdir()
    monkeypatch.chdir(tmp_path / "empty")
    assert P.main(["check", report]) == 2
    assert "kashif.yml" in capsys.readouterr().err


def test_cli_init_validate_presets(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert P.main(["init", "--preset", "strict", "--lang", "en"]) == 0
    assert (tmp_path / "kashif.yml").is_file() and "wrote kashif.yml" in capsys.readouterr().out
    assert P.load_policy("kashif.yml").gate["fail_on"] == "medium"
    assert P.main(["init", "--preset", "startup"]) == 2                              # refuses to overwrite
    assert P.main(["init", "--preset", "startup", "--force"]) == 0
    assert P.load_policy("kashif.yml").gate["fail_on"] == "critical"
    capsys.readouterr()
    assert P.main(["init", "--preset", "pci-dss", "--expand", "-o", "-", "--name", "pay api"]) == 0
    expanded = capsys.readouterr().out
    assert "extends" not in expanded and P.load_policy_text(expanded).name == "pay api"
    assert P.main(["init", "--preset", "unknown"]) == 2
    capsys.readouterr()
    assert P.main(["validate", "kashif.yml", "--lang", "en"]) == 0
    assert "valid policy" in capsys.readouterr().out
    assert P.main(["validate", "kashif.yml", "--show"]) == 0
    shown = capsys.readouterr().out
    assert P.load_policy_text(shown).to_dict() == P.load_policy("kashif.yml").to_dict()
    (tmp_path / "bad.yml").write_text("gate:\n  fail_on: nope\nignores:\n  - rule: X\n", encoding="utf-8")
    assert P.main(["validate", "bad.yml", "--lang", "en"]) == 2
    errs = capsys.readouterr().err.splitlines()
    assert errs[0].startswith("bad.yml:2: [gate.fail_on]") and len(errs) == 4
    assert P.main(["validate", "missing.yml"]) == 2
    capsys.readouterr()
    assert P.main(["presets", "--lang", "ar"]) == 0
    listed = capsys.readouterr().out
    assert all(name in listed for name in P.PRESETS)


# ------------------------------------------------------------------------------------------------------------------
# Adversarial review: hostile policies and reports
# ------------------------------------------------------------------------------------------------------------------
def test_glob_is_linear_and_keeps_its_semantics():
    import time
    m = P.path_matches
    start = time.perf_counter()
    assert not m("a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*b", "a" * 5000)          # catastrophic with a backtracking regex
    assert not m("**a**a**a**a**a**a**a**b", "a/" * 2500)
    assert time.perf_counter() - start < 2
    cases = [("src/**", "src/a/b.py", True), ("**/x", "x", True), ("**/x", "a/b/x", True), ("**/x", "a/bx", False),
             ("*.min.js", "a/b/c.min.js", True), ("src/*.py", "src/a/b.py", False), ("src/**/t_*.py", "src/t_a.py", True),
             ("a/**b", "a/x/yb", True), ("[a-c]x", "bx", True), ("[!a-c]x", "bx", False), ("[!a-c]x", "dx", True),
             ("a?c", "a/c", False), ("a[!x]c", "a/c", False), ("a/**/b", "a/b", True), ("a/**/b", "a/x/y/b", True),
             ("a/**/b", "ab", False), ("d/*", "d/a/b", False), ("x[", "x[", True), ("a**", "a/b/c", True),
             ("**", "a/b", True), ("a/*/c", "a/b/c", True), ("a/*/c", "a/b/d/c", False), ("*a*b", "xaxb", True)]
    for pattern, path, expected in cases:
        assert m(pattern, path) is expected, (pattern, path)


def test_extends_stays_inside_the_policy_repository(tmp_path):
    outside = tmp_path / "outside"
    repo = tmp_path / "repo"
    (repo / "ci").mkdir(parents=True)
    outside.mkdir()
    (outside / "org.yml").write_text("gate:\n  fail_on: low\n", encoding="utf-8")
    (repo / "base.yml").write_text("gate:\n  fail_on: medium\n", encoding="utf-8")
    (repo / "kashif.yml").write_text("extends: ../outside/org.yml\n", encoding="utf-8")
    with pytest.raises(P.PolicyError) as e:
        P.load_policy(repo / "kashif.yml")
    assert e.value.problems[0].code == "e_extends_outside" and "outside" in e.value.format("ar")
    assert P.load_policy(repo / "kashif.yml", allow_outside=True).gate["fail_on"] == "low"
    # the refusal does not depend on whether the file exists (no existence oracle), absolute paths included
    for ref in ("../outside/none.yml", str(outside / "org.yml"), "/etc/kashif-nope.yml"):
        with pytest.raises(P.PolicyError) as e:
            P.load_policy_text(f"extends: {json.dumps(ref)}\n", base_dir=repo)
        assert e.value.problems[0].code == "e_extends_outside"
    # without .git the limit is the policy's own directory; with it, the whole repository
    (repo / "ci" / "kashif.yml").write_text("extends: ../base.yml\n", encoding="utf-8")
    with pytest.raises(P.PolicyError):
        P.load_policy(repo / "ci" / "kashif.yml")
    (repo / ".git").mkdir()
    assert P.load_policy(repo / "ci" / "kashif.yml").gate["fail_on"] == "medium"
    # a symbolic link inside the repository that points outside is followed, then refused
    try:
        (repo / "link.yml").symlink_to(outside / "org.yml")
    except (OSError, NotImplementedError):
        return
    with pytest.raises(P.PolicyError) as e:
        P.load_policy_text("extends: link.yml\n", base_dir=repo)
    assert e.value.problems[0].code == "e_extends_outside"
    # CLI flag
    assert P.main(["validate", str(repo / "kashif.yml")]) == 2
    assert P.main(["validate", str(repo / "kashif.yml"), "--allow-external-extends"]) == 0


def test_network_paths_are_refused_everywhere():
    for ref in ('"//evil/share/p.yml"', "'\\\\evil\\share\\p.yml'", "'\\\\?\\C:\\p.yml'"):
        with pytest.raises(P.PolicyError) as e:
            P.load_policy_text(f"extends: {ref}\n", allow_outside=True)
        assert e.value.problems[0].code == "e_path_unsafe", ref
    assert err("gate:\n  baseline: '//evil/share/b.json'\n").problems[0].code == "e_path_unsafe"
    assert err("gate:\n  baseline: 'https://evil.example/b.json'\n").problems[0].code == "e_path_unsafe"


def test_lock_cannot_be_bypassed_through_a_scope_or_a_sibling(tmp_path):
    (tmp_path / "org.yml").write_text(
        "locked: [gate.fail_on, gate.max.high, gate.fail_on_secrets]\ngate:\n  fail_on: high\n  max: {high: 0}\n",
        encoding="utf-8")
    load = lambda text: P.load_policy_text(text, base_dir=tmp_path)  # noqa: E731
    head = "extends: org.yml\nscopes:\n  - name: everything\n    paths: ['**']\n"
    for body, where in (("    fail_on: never\n", "scopes[0].fail_on"), ("    max: {high: 9}\n", "scopes[0].max"),
                        ("    fail_on_secrets: false\n", "scopes[0].fail_on_secrets")):
        with pytest.raises(P.PolicyError) as e:
            load(head + body)
        prob = e.value.problems[0]
        assert (prob.code, prob.path, prob.line) == ("e_locked", where, 5)
    # a scope that repeats the locked value, or changes a key that is not locked, is fine
    p = load(head + "    fail_on: high\n    max: {high: 0, low: 3}\n    max_total: 5\n")
    assert p.scopes[0]["max_total"] == 5
    # a later entry of "extends" may not undo what an earlier one locked
    (tmp_path / "weak.yml").write_text("gate:\n  fail_on: never\n", encoding="utf-8")
    with pytest.raises(P.PolicyError) as e:
        load("extends: [org.yml, weak.yml]\n")
    assert e.value.problems[0].code == "e_locked" and "org.yml" in e.value.format("en")
    assert load("extends: [weak.yml, org.yml]\n").gate["fail_on"] == "high"
    # locking a whole section forbids a child to define it differently
    (tmp_path / "hard.yml").write_text("locked: [gate, scopes, ignores, rules]\n", encoding="utf-8")
    for text in ("scopes:\n  - {name: t, paths: 'tests/**', skip: true, reason: r}\n",
                 "rules:\n  disable:\n    - {id: '*', reason: r}\n",
                 "ignores:\n  - {path: '**', reason: r, approver: a, expires: 2030-01-01}\n",
                 "gate:\n  fail_on: never\n"):
        with pytest.raises(P.PolicyError) as e:
            load("extends: hard.yml\n" + text)
        assert e.value.problems[0].code == "e_locked", text


def test_locked_names_are_validated():
    for name in ("gate.fial_on", "gate.max.huge", "extends", "name", "rules.nope", "sla.urgent", "gate.fail_on.x"):
        assert err(f"locked: ['{name}']\n").problems[0].code == "e_locked_unknown", name
    assert pol("locked: [gate, gate.fail_on, gate.max.high, rules.disable, sla.high, scopes, ignores]\n").locked


def test_owasp_edition_must_be_the_implemented_one():
    assert pol("gate:\n  fail_on_owasp: ['A03:2021', a3, 'API1:2023', api10]\n").gate["fail_on_owasp"] == \
        ["A03", "API1", "API10"]
    for value in ("A03:2025", "A05:2025", "A03:2017", "API1:2019", "A11", "API0"):
        e = err(f"gate:\n  fail_on_owasp: ['{value}']\n")
        assert e.problems[0].code == "e_owasp" and "2021" in e.format("en") and "2021" in e.format("ar")


def test_owasp_fallback_table_matches_the_2021_lists():
    # OWASP Top 10 2021 "List of Mapped CWEs": CWE-295 belongs to A07 (not A02); CWE-259 is in A02 and A07
    t = P._OWASP_FALLBACK
    assert 295 in t["A07"] and 295 not in t["A02"] and 259 in t["A02"] and 259 in t["A07"]
    assert 89 in t["A03"] and 918 in t["A10"] and 502 in t["A08"] and 611 in t["A05"]
    seen = [c for cwes in t.values() for c in cwes]
    assert sorted(set(seen)) == sorted(seen) or set(c for c in seen if seen.count(c) > 1) == {259}


def test_control_and_bidi_characters_cannot_enter_or_leave():
    esc = chr(27)
    for text, fmt in (('{"name": "x\\u001b[2J"}', "json"), ('name: "x\\x1b[2J"\n', "yaml"),
                      ('name: "a\\nKashif security gate: PASSED"\n', "yaml"),
                      ('{"scopes": [{"name": "s\\u202e", "paths": ["a"]}]}', "json"),
                      ('ignores:\n  - {rule: X, reason: "r\\u2066", approver: a, expires: 2030-01-01}\n', "yaml")):
        assert err(text, fmt).problems[0].code == "e_text_char", text
    assert pol('name: "سياسة الدفع"\n').name == "سياسة الدفع"                   # ordinary Arabic text is fine
    hostile = F(rule="X" + esc + "[2K\rKashif security gate: PASSED", file="a\nb" + chr(0x202e) + ".py")
    hostile["fingerprint"] = "ab`|cd\n# PASSED"
    d = run("gate:\n  fail_on: high\n", [hostile])
    for fmt in ("text", "markdown"):
        out = P.explain(d, fmt)
        assert esc not in out and "\r" not in out and chr(0x202e) not in out
        assert not any(line.startswith(("Kashif security gate: PASSED", "# PASSED")) for line in out.splitlines())
    json.loads(P.explain(d, "json"))


def test_markdown_is_inert():
    f = F(rule="R|x", file="node_modules/@evil/team/<img src=x>.js")
    f["fingerprint"] = "abc`|def"
    d = run("name: \"@org/everyone\"\ngate:\n  fail_on: high\n", [f])
    md = P.explain(d, "markdown")
    assert "@" not in md and "<img" not in md.replace("\\<img", "") and "&#64;evil" in md
    row = next(line for line in md.splitlines() if "node\\_modules" in line)
    assert row.replace("\\|", "").count("|") == 5                                 # the table row was not split


def test_malformed_numbers_do_not_crash(tmp_path, capsys):
    assert err('{"gate": {"max_total": ' + "9" * 5000 + "}}", "json").problems[0].code == "e_json_const"
    assert err('{"gate": {"max_total": 1.' + "9" * 5000 + "}}", "json").problems[0].code == "e_json_const"
    assert err('{"gate": {"max_total": 1e999}}', "json").problems[0].code == "e_type"
    p = P.builtin_policy("startup")
    weird = [dict(F(sev="critical"), line=float("inf")), dict(F(), line=float("nan")), dict(F(), line="x"),
             {"rule_id": ["x"], "severity": {}, "file": 3, "cwe": ["CWE-89"], "fingerprint": {}, "extra": {"triage": 1}}]
    d = P.evaluate(weird, p, {"today": TODAY, "changed": {"src/app.py": [1, "2", None]}})
    assert not d.passed and P.explain(d, "text")
    assert P.evaluate([F()], p, {"today": TODAY, "changed": "src/app.py"}).stats["total"] == 1
    # the CLI reports a broken report instead of a traceback
    (tmp_path / "kashif.yml").write_text("gate:\n  fail_on: high\n", encoding="utf-8")
    (tmp_path / "deep.json").write_text("[" * 200000 + "]" * 200000, encoding="utf-8")
    (tmp_path / "inf.json").write_text('{"findings": [{"rule_id": "X", "severity": "high", "line": 1e999}]}',
                                       encoding="utf-8")
    assert P.main(["check", str(tmp_path / "deep.json"), "--policy", str(tmp_path / "kashif.yml")]) == 2
    assert P.main(["check", str(tmp_path / "inf.json"), "--policy", str(tmp_path / "kashif.yml"), "--scanners", "x"]) == 1
    capsys.readouterr()


def test_report_paths_are_portable():
    bad = ("a.txt:stream", "CON", "out/nul.txt", "out//x.json", "./x.json", "a/../b.json", "C:/x.json", "~/x.json",
           "x?.json", "trailing./x.json", "com1.sarif", "\\\\srv\\share\\x.json")
    for path in bad:
        e = err("reports:\n  - format: json\n    path: " + json.dumps(path) + "\n")
        assert e.problems[0].code == "e_report_path", path
    assert pol("reports:\n  - {format: sarif, path: 'out\\kashif.sarif'}\n").reports[0]["path"] == "out/kashif.sarif"


def test_yaml_rejects_stray_flow_indicators():
    for text in ("a: ]x\n", "a: ,y\n", "a: }z\n"):
        assert err(text).problems[0].code == "e_reserved"


def test_scanner_inference_knows_every_builtin_source():
    p = pol("gate:\n  fail_on: never\nrequired_scanners: [sast]\n")
    for source in ("vulnscan", "taint", "vql", "web", "apex"):
        assert P.evaluate([F(sev="info", source=source)], p, {"today": TODAY}).passed, source
    assert not P.evaluate([F(sev="info", source="osv")], p, {"today": TODAY}).passed


def test_preset_descriptions_claim_only_what_the_standards_say():
    asvs = P.PRESETS["owasp-asvs-l1"]["description"]
    assert "Level 2" in asvs and "V2.10.4" in asvs                 # secrets in source are an L2 requirement in 4.0.3
    assert "certification" in P.PRESETS["pci-dss"]["description"]
