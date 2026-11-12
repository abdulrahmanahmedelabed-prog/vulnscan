"""Policy-as-code for security gates: one reviewable file (``kashif.yml``) decides whether a scan passes.

INTEGRATION NOTES
=================
(For the integration step. This module edits no existing file and is usable today as
``python3 -m vulnscan.policy ...``.)

CLI (vulnscan/cli.py)
---------------------
* New sub-command ``kashif policy ...`` that forwards to ``policy.main(argv)``::

      kashif policy check  REPORT [--policy FILE] [--baseline FILE] [--changed-files FILE] [--scanners a,b]
                                  [--today YYYY-MM-DD] [-f text|markdown|json] [-o FILE] [--lang en|ar]
                                  [--warnings-as-errors] [--allow-external-extends]
      kashif policy init   [--preset strict|startup|pci-dss|owasp-asvs-l1] [-o kashif.yml] [--force] [--expand]
      kashif policy validate FILE [--show] [--lang en|ar] [--allow-external-extends]
      kashif policy presets

  Exit codes of ``main``: 0 = gate passed / file valid, 1 = gate failed, 2 = usage, policy or input error.
* Scan flag ``--policy [FILE]`` (default: ``policy.find_policy(target)``; when a policy file exists in the scanned
  root it should apply automatically). After ``assign_fingerprints`` and before any filtering::

      pol = policy.load_policy(path)                       # PolicyError -> print e.format(lang), exit 2
      ctx = policy.Context(
          scanners={"sast", "secrets"} | ({"deps"} if not args.no_deps else set())
                   | ({"external"} if ran else set()),
          baseline=baseline.load_baseline(args.baseline) if args.baseline else None,
          changed=diffscope_result,                        # {file: {lines}} or a list of files, for --diff-base
          base_dir=target)
      decision = policy.evaluate(findings, pol, ctx)
      print(policy.explain(decision, "text", lang), file=sys.stderr)
      for out in pol.reports:                              # {"format": "sarif", "path": "out/kashif.sarif"}
          write report.render_<format>(...) to pathlib.Path(output_dir) / out["path"]
      return decision.exit_code                            # replaces --fail-on when a policy is given

  ``pol.reports`` paths are validated as relative, portable paths without ``..``, drive letters, ``:`` or Windows
  device names, so a policy from an untrusted repository cannot write outside the output directory (still join
  them to the output directory, never to the current directory, and do not follow an existing symbolic link).
  SECURITY: a policy found in the scanned tree is untrusted input. Load it with the default
  ``load_policy(path)``: ``extends`` then cannot leave the policy's repository and never opens a network path.
  Pass ``allow_outside=True`` only for a file the user named with an explicit ``--allow-external-extends``; never
  for an auto-discovered policy and never in the server. ``report.render_json`` should add ``"scanners": [...]`` to its
  metadata: ``policy check`` reads it to verify ``required_scanners`` (today it infers what it can, see LIMITS).
* ``--sla`` / ``--fail-on-sla`` of the triage integration can read ``pol.sla`` instead of a flag.
* GitHub Action (action.yml): input ``policy`` -> ``kashif policy check kashif-report.json --policy ... -f markdown
  >> "$GITHUB_STEP_SUMMARY"``.

Web UI / server (vulnscan/server.py, vulnscan/ui/*)
---------------------------------------------------
* ``GET /api/scans/<id>/gate?lang=`` -> ``policy.evaluate(scan["findings"], pol, ctx).to_dict()`` (``evaluate``
  accepts the saved-scan dict form). UI: a "Security gate" banner (passed / failed), one card per violation
  (``message_en`` / ``message_ar``, the listed findings link to the finding cards), and the warnings list.
* ``POST /api/policy/validate`` (body = policy text) -> ``policy.load_policy_text(text, "yaml", base_dir=<scan
  root>)``; show ``PolicyError.problems`` (``line``, ``col``, ``path``, ``message(lang)``) as editor diagnostics.
  Always pass ``base_dir`` there (the default is the server's working directory) and keep ``allow_outside`` off.
* A read-only "Policy" page can render ``pol.to_dict()``; ``policy.dump_yaml`` turns it back into YAML.
* Always escape policy strings (names, reasons, approvers) and everything in ``Decision.to_dict()`` / ``explain(...,
  "json")``: they come from the scanned repository and the report and are returned verbatim there. Only the
  ``text`` and ``markdown`` renderings neutralise control characters, Markdown, HTML and ``@mentions``.

LSP / PR integration
--------------------
* LSP: diagnostics for ``kashif.yml`` from ``PolicyError.problems`` (line / column are 1-based).
* PR comment: ``policy.explain(decision, "markdown", lang)`` is a ready-made comment body.

Packaging
---------
* vulnscan.spec: ``hiddenimports += ["vulnscan.policy"]`` (imported lazily by the CLI). No data files.

README suggestions
------------------
EN: "**Policy as code.** Put a `kashif.yml` next to your code and the gate is the same on every laptop and in
every pipeline: fail on a severity, cap the number of findings, fail only on new findings, forbid specific CWEs,
rules or OWASP categories, never let a secret through, use different thresholds for `src/`, `tests/` and
`third_party/`, and inherit an organisation baseline (`extends: pci-dss`). Every exception needs a reason, an
approver and an expiry date, and an expired exception fails the build. `kashif policy check report.json` explains
each decision in English or Arabic. No server, no account, no YAML library: the parser is a strict subset that
rejects anchors, tags and anything it does not understand."
AR: «**السياسة ككود.** ضع ملف `kashif.yml` بجوار الكود فتصبح بوابة الأمان واحدة على كل حاسوب وفي كل خط إنتاج:
افشل عند خطورة معيّنة، حدِّد أقصى عدد للنتائج، افشل عند النتائج الجديدة فقط، امنع ثغرات CWE أو قواعد أو فئات OWASP
بعينها، لا تسمح بمرور أي سرّ، استخدم حدودًا مختلفة لـ `src/` و`tests/` و`third_party/`، ورِث سياسة المؤسسة
(`extends: pci-dss`). كل استثناء يحتاج سببًا ومعتمِدًا وتاريخ انتهاء، والاستثناء المنتهي يُفشل البناء. يشرح الأمر
`kashif policy check report.json` كل قرار بالعربية أو الإنجليزية، دون خادم ودون حساب ودون مكتبة YAML.»

THE POLICY FILE
===============
::

    version: 1
    name: payments-api
    extends: pci-dss                  # builtin preset or a path (relative to this file); a list is allowed
    gate:
      fail_on: high                   # fail when a finding is at or above this severity ("never" disables)
      max: {medium: 10, low: 50}      # maximum number of findings per severity
      max_total: 100
      new_only: false                 # true: only findings that are new against the baseline / diff count
      baseline: .kashif-baseline.json
      fail_on_cwe: [CWE-89, 78]
      fail_on_rules: ["SEC*", PY001]
      fail_on_owasp: [A03, API1]      # OWASP Top 10 2021 and API Security Top 10 2023 numbering
      fail_on_secrets: true           # secrets fail the gate even when new_only is on
      fail_on_expired: true           # expired ignores / risk acceptances fail the gate
      fail_on_sla_breach: false
      max_acceptance_days: 180        # an ignore may not expire later than this many days from today
    scopes:                           # first matching scope wins; unset keys fall back to "gate"
      - name: tests
        paths: ["tests/**"]
        fail_on: never
        fail_on_cwe: []
        fail_on_secrets: false
      - name: vendored
        paths: ["third_party/**"]
        skip: true
        reason: "vendored code, tracked by the dependency scanner"
    rules:
      disable:
        - id: WEB020
          reason: "cookies are set by the gateway"
      enable: [PY001]                 # re-enable something an inherited policy disabled
      severity:
        - id: SEC004
          severity: critical
          reason: "hard-coded credentials are a release blocker here"
    ignores:
      - rule: PY014
        path: "src/legacy/**"
        reason: "input is validated upstream, see ticket"
        approver: "security-lead"
        expires: 2027-01-31
    required_scanners: [deps, secrets]
    sla: {critical: 7, high: 30, medium: 90}
    reports:
      - format: sarif
        path: out/kashif.sarif
    locked: [gate.fail_on, scopes]    # a policy that extends this one may not change these keys

The same structure is accepted as ``kashif.json``.

Semantics worth knowing
-----------------------
* Order of evaluation: disabled rules -> severity overrides -> triage state (``extra["triage"]`` when present) ->
  ignores -> scopes -> conditions. An ignore suppresses a finding only while it is valid (through its expiry day).
* An ignore, a disabled rule and a ``skip`` scope are accountable decisions (reason, and for ignores approver and
  expiry), so they also apply to secrets. ``new_only`` and severity thresholds never hide a secret.
* ``new_only`` needs a reference: a baseline, a changed-file set, or ``extra["new"]`` flags written by
  ``--baseline``. Without one every finding counts (the gate fails closed) and a warning says so.
* A required scanner that cannot be shown to have run fails the gate.
* ``fail_on_owasp`` uses the OWASP Top 10 **2021** (``A01``..``A10``, also ``A03:2021``) and the OWASP API Security
  Top 10 **2023** (``API1``..``API10``). The Top 10 2025 renumbered the categories (``A03`` became Software Supply
  Chain Failures, Injection moved to ``A05``), so any other edition suffix is rejected instead of being guessed.
* ``locked``: a section (``gate``, ``scopes``, ``rules``, ``ignores``, ``sla``, ``reports``, ``required_scanners``)
  or a key (``gate.<key>``, ``gate.max.<severity>``, ``rules.disable|enable|severity``, ``sla.<severity>``). A
  child may repeat the locked value but not change it; a locked gate key can also not be overridden in a child's
  scope, nor by a later entry of the same ``extends`` list. A lock on gate keys does not stop a child from adding
  ignores, disabled rules or ``skip`` scopes (each needs a written reason): an organisation that wants a hard
  floor locks ``scopes``, ``ignores`` and ``rules`` as well.
* ``extends`` with a file: only ``.yml`` / ``.yaml`` / ``.json`` inside the policy's repository (nearest ancestor
  with ``.git``, else the policy file's directory), symbolic links resolved; ``--allow-external-extends`` /
  ``allow_outside=True`` lifts this for a trusted policy. UNC paths and URLs are always refused.
* Inheritance: scalars are overridden by the child; ``gate.max`` and ``sla`` merge per key; forbid lists
  (``fail_on_cwe`` / ``fail_on_rules`` / ``fail_on_owasp``) and ``required_scanners`` are unions; ``ignores`` are
  concatenated; a child scope replaces the parent scope of the same name and is tried first.

YAML SUBSET
===========
Block mappings, block sequences, single-line flow sequences and flow mappings of scalars (``[a, "b"]``,
``{high: 30, low: 90}``), plain,
single-quoted and double-quoted scalars, comments, one optional leading ``---``. Plain scalars resolve to null
(``null`` / ``~`` / empty), booleans (``true`` / ``false`` only: ``yes`` / ``no`` / ``on`` / ``off`` stay strings),
integers and decimals; everything else, dates included, is a string. Rejected with a line number: tabs in
indentation, anchors, aliases, tags, merge keys, block scalars (``|`` ``>``), nested or multi-line flow
collections, multi-line scalars, complex keys, directives, multiple documents, duplicate keys, and inputs over
the size / depth / node limits.

LIMITS
======
* The parser is deliberately not YAML: a construct outside the subset is an error, never a guess.
* ``required_scanners`` is verified from ``Context.scanners`` (authoritative) or, for a report file, from a
  ``"scanners"`` list in the report, findings of that scanner, or the dependency-audit note of the CLI. A Kashif
  source report implies ``sast`` and ``secrets`` (built-in secret rules always run with the rules engine).
* OWASP categories come from ``vulnscan.compliance`` when it is importable, else from a small built-in CWE table.
* SLA ages need a first-seen date (``Context.first_seen`` or ``extra["triage"]["first_seen"]``).
* The presets are gates inspired by the named standard (PCI DSS v4.0 / v4.0.1 Req. 6.2.4, 6.3.1, 6.3.3, 8.6.2; OWASP
  ASVS 4.0.3 Level 1 chapters V4, V5, V14.2). They cover only what static analysis can observe; passing one is
  evidence for an assessor, not a certification. The requirement numbers were written from the published standards;
  the ASVS levels were checked against the 4.0.3 CSV, the PCI DSS wording could not be re-fetched during review.
* The report is trusted input: triage states (``extra["triage"]``), ``extra["new"]`` flags (set by ``--baseline``
  on every finding it keeps) and severities in it are taken as they are. Gate on a report your pipeline produced.
* Path patterns are matched by a small linear-time matcher (no regular expressions), so a hostile pattern cannot
  stall the gate. Rule-id patterns use ``fnmatch`` (at most 8 ``*``).
* Nothing is executed and no network is used. ``extends`` only reads local ``.yml`` / ``.yaml`` / ``.json`` files.
"""

from __future__ import annotations

import argparse
import copy
import datetime as _dt
import difflib
import fnmatch
import hashlib
import json
import os
import pathlib
import re
import sys
from dataclasses import dataclass, field

__all__ = [
    "PolicyError", "Problem", "Policy", "Context", "Decision", "Violation", "Warning_", "PRESETS", "POLICY_FILENAMES",
    "parse_yaml", "dump_yaml", "load_policy", "load_policy_text", "builtin_policy", "find_policy", "evaluate",
    "explain", "init_template", "path_matches", "main",
]

SEVERITIES = ("critical", "high", "medium", "low", "info")
_RANK = {s: i for i, s in enumerate(SEVERITIES)}
POLICY_FILENAMES = ("kashif.yml", "kashif.yaml", ".kashif.yml", ".kashif.yaml", "kashif.json")
REPORT_FORMATS = ("markdown", "json", "html", "sarif")
KNOWN_SCANNERS = ("sast", "secrets", "deps", "external")

MAX_BYTES = 1_000_000        # a policy file is small; anything larger is a mistake or an attack
MAX_REPORT_BYTES = 512_000_000
MAX_LINE = 8_192
MAX_DEPTH = 24
MAX_NODES = 50_000
MAX_EXTENDS_DEPTH = 8
MAX_STR = 2_000
MAX_LIST = 5_000
EXPIRY_WARN_DAYS = 14
_SECRET_CWES = frozenset({798, 259, 321})

# --------------------------------------------------------------------------------------------------------------
# Strings (English / Arabic). Kept here so the shared i18n catalogs are not touched.
# --------------------------------------------------------------------------------------------------------------
STR = {
    "en": {
        # parser
        "e_too_big": "the file is {size} bytes; the limit is {limit}",
        "e_encoding": "the file is not valid UTF-8",
        "e_control_char": "control character U+{code:04X} is not allowed",
        "e_tab": "tab in indentation; use spaces",
        "e_line_too_long": "line longer than {limit} characters",
        "e_multi_doc": "multiple YAML documents ('---') are not supported",
        "e_directive": "YAML directives ('%...') are not supported",
        "e_anchor": "YAML anchors ('&name') are not supported",
        "e_alias": "YAML aliases ('*name') are not supported; quote the value if it is a glob such as \"*.py\"",
        "e_tag": "YAML tags ('!tag') are not supported",
        "e_block_scalar": "block scalars ('|' and '>') are not supported; use a quoted string on one line",
        "e_flow_map": "invalid flow mapping; expected '{{key: value, key: value}}' on one line",
        "e_flow_nested": "nested flow collections are not supported; use indented block lists and mappings",
        "e_flow_unterminated": "'[...]' or '{{...}}' is not closed on the same line (multi-line flow is not supported)",
        "e_flow_syntax": "invalid flow sequence; expected ',' or ']'",
        "e_complex_key": "complex mapping keys ('? key') are not supported",
        "e_merge_key": "merge keys ('<<') are not supported; use 'extends' for inheritance",
        "e_reserved": "a plain value cannot start with '{char}'; quote it",
        "e_unterminated_quote": "quoted string is not closed on the same line",
        "e_bad_escape": "unsupported escape sequence '\\{esc}' in a double-quoted string",
        "e_after_quote": "unexpected text after a quoted string",
        "e_dup_key": "duplicate key '{key}'",
        "e_indent": "inconsistent indentation",
        "e_expected_key": "expected 'key: value'",
        "e_empty_key": "empty mapping key",
        "e_inline_map": "a value containing ': ' must be quoted (nested mappings go on their own indented lines)",
        "e_inline_seq": "a list cannot start on the same line as its key; put each '- item' on its own line",
        "e_multiline_scalar": "multi-line values are not supported; keep the value on one line",
        "e_depth": "nesting deeper than {limit} levels",
        "e_nodes": "more than {limit} values",
        "e_json": "invalid JSON: {msg}",
        "e_json_const": "NaN, Infinity and numbers longer than 40 characters are not allowed",
        "e_ext": "unsupported policy file type; use .yml, .yaml or .json",
        "e_not_file": "policy file not found or not a regular file",
        "e_read": "cannot read the file: {err}",
        # validation
        "e_top_mapping": "a policy must be a mapping of settings (key: value)",
        "e_unknown_key": "unknown key '{key}'{hint}",
        "hint_did_you_mean": " (did you mean '{name}'?)",
        "e_type": "expected {expected}",
        "t_map": "a mapping", "t_list": "a list", "t_str": "a non-empty string", "t_bool": "true or false",
        "t_int": "an integer", "t_str_list": "a string or a list of strings",
        "e_required": "missing required key '{key}'",
        "e_severity": "'{value}' is not a severity; use one of: {allowed}",
        "e_version": "unsupported policy version {value}; this release understands version 1",
        "e_int_min": "expected an integer >= {min}",
        "e_cwe": "'{value}' is not a CWE id; write CWE-89 or 89",
        "e_owasp": "'{value}' is not a supported OWASP category; write A01..A10 (OWASP Top 10 2021) or API1..API10 "
                   "(OWASP API Security Top 10 2023). Other editions, such as the Top 10 2025, number their "
                   "categories differently and are not supported",
        "e_date": "'{value}' is not a date; write YYYY-MM-DD",
        "e_glob": "invalid path pattern",
        "e_selector": "an ignore needs at least one of: rule, path, cwe, fingerprint",
        "e_fingerprint": "a fingerprint (or prefix) needs at least 8 hexadecimal characters",
        "e_dup_name": "duplicate name '{name}'",
        "e_enable_conflict": "rule '{name}' is both disabled and enabled in the same file",
        "e_identifier": "'{value}' is not a valid name (lowercase letters, digits, '-' and '_')",
        "e_extends_unknown": "'{name}' is neither a builtin preset ({presets}) nor a .yml/.yaml/.json path",
        "e_extends_cycle": "inheritance cycle: {chain}",
        "e_extends_depth": "more than {limit} levels of 'extends'",
        "e_extends_missing": "inherited policy '{path}' was not found",
        "e_locked": "'{key}' is locked by the inherited policy {parent} and cannot be changed here",
        "e_report_path": "a report path must be relative, may not contain '..' and must be a portable file name "
                         "(no ':' or other reserved characters, no Windows device names)",
        "e_path_unsafe": "network (UNC) paths and URLs are not allowed",
        "e_text_char": "character U+{code:04X} (control or bidirectional override) is not allowed in a value",
        "e_extends_outside": "inherited policy '{path}' is outside '{root}'; a policy may only inherit files below "
                             "its own directory or repository (trusted policy: --allow-external-extends)",
        "e_locked_unknown": "'{key}' cannot be locked; lock a section (gate, scopes, rules, ignores, sla, reports, "
                            "required_scanners) or a key such as gate.fail_on, gate.max.high, rules.disable, sla.high",
        "e_too_long": "longer than {limit} characters",
        "e_list_too_long": "more than {limit} entries",
        "w_report_format": "report format '{value}' is not one of the built-in formats ({allowed})",
        # violations
        "v_severity-threshold": "{count} finding(s) at or above severity {threshold} in scope '{scope}'",
        "v_max-count": "{count} {severity} finding(s) in scope '{scope}'; the policy allows at most {max}",
        "v_max-total": "{count} finding(s) in scope '{scope}'; the policy allows at most {max} in total",
        "v_forbidden-cwe": "{count} finding(s) of CWE-{cwe}, which the policy forbids (scope '{scope}')",
        "v_forbidden-rule": "{count} finding(s) of rule '{rule}', which the policy forbids (scope '{scope}')",
        "v_forbidden-owasp": "{count} finding(s) in OWASP category {category}, which the policy forbids (scope '{scope}')",
        "v_secret": "{count} secret(s) in the code (scope '{scope}'); secrets always fail the gate",
        "v_expired-ignore": "ignore #{index} ({selector}), approved by {approver}, expired on {date} ({days} day(s) ago): "
                            "{count} finding(s) are no longer accepted",
        "v_expired-acceptance": "{count} finding(s) whose risk acceptance has expired",
        "v_acceptance-too-long": "ignore #{index} ({selector}) expires on {date}, {days} day(s) from today; "
                                 "the policy allows at most {max}",
        "v_required-scanner": "required scanner '{scanner}' did not run, or there is no evidence that it ran",
        "v_sla-breach": "{count} {severity} finding(s) are older than the SLA of {days} day(s) (oldest: {oldest} day(s))",
        "v_warnings-as-errors": "{count} warning(s) and warnings are treated as errors",
        # warnings
        "w_new-only-no-reference": "new_only is set but there is no baseline, changed-file set or 'new' flag; "
                                   "every finding was evaluated",
        "w_baseline-unreadable": "baseline '{path}' could not be read; every finding was evaluated",
        "w_ignore-expiring": "ignore #{index} ({selector}) expires on {date} (in {days} day(s))",
        "w_ignore-unused": "ignore #{index} ({selector}) matches no finding; remove it",
        "w_ignore-expired-unused": "ignore #{index} ({selector}) expired on {date} and matches no finding; remove it",
        "w_expired-not-enforced": "{count} expired ignore(s) / risk acceptance(s); fail_on_expired is off",
        "w_sla-no-dates": "SLA not checked for {count} finding(s): no first-seen date (use triage or a first_seen map)",
        "w_sla-breach": "{count} {severity} finding(s) are older than the SLA of {days} day(s) (oldest: {oldest} day(s))",
        "w_unknown-severity": "{count} finding(s) with an unknown severity were treated as medium",
        "w_owasp-fallback": "vulnscan.compliance is unavailable; OWASP categories come from a small built-in table",
        # explain
        "x_title": "Kashif security gate",
        "x_passed": "PASSED", "x_failed": "FAILED",
        "x_policy": "Policy", "x_date": "Evaluated on", "x_exit": "Exit code",
        "x_summary": "{evaluated} of {total} finding(s) evaluated (ignored {ignored}, rule disabled {disabled}, "
                     "triaged {triaged}, out of scope {skipped})",
        "x_violations": "Violations", "x_warnings": "Warnings", "x_none": "none",
        "x_more": "... and {count} more",
        "x_col_rule": "Rule", "x_col_sev": "Severity", "x_col_loc": "Location", "x_col_fp": "Fingerprint",
        "x_scope_default": "default",
        "sev_critical": "critical", "sev_high": "high", "sev_medium": "medium", "sev_low": "low", "sev_info": "info",
        # cli
        "c_valid": "{path}: valid policy '{name}' ({rules} gate condition(s), {scopes} scope(s), {ignores} ignore(s))",
        "c_written": "wrote {path}",
        "c_exists": "{path} already exists; use --force to overwrite",
        "c_no_policy": "no policy file found (looked for {names}); pass --policy",
        "c_bad_report": "cannot read the report {path}: {err}",
        "c_bad_today": "--today must be YYYY-MM-DD",
        "p_startup": "small team: block critical findings and secrets, relax tests",
        "p_strict": "block medium and above, no exceptions longer than 90 days, SLA enforced",
        "p_pci-dss": "gate inspired by PCI DSS v4.0 / v4.0.1 Req. 6.2.4, 6.3.1, 6.3.3 and 8.6.2 (not a certification)",
        "p_owasp-asvs-l1": "gate inspired by OWASP ASVS 4.0.3 Level 1 (V4, V5, V14.2), plus no secrets in code",
    },
    "ar": {
        "e_too_big": "حجم الملف {size} بايت والحد الأقصى {limit}",
        "e_encoding": "ترميز الملف ليس UTF-8 صالحًا",
        "e_control_char": "محرف التحكم U+{code:04X} غير مسموح",
        "e_tab": "محرف Tab في الإزاحة؛ استخدم المسافات",
        "e_line_too_long": "سطر أطول من {limit} محرفًا",
        "e_multi_doc": "تعدد مستندات YAML ('---') غير مدعوم",
        "e_directive": "توجيهات YAML ('%...') غير مدعومة",
        "e_anchor": "مراسي YAML ('&name') غير مدعومة",
        "e_alias": "إحالات YAML ('*name') غير مدعومة؛ ضع القيمة بين علامتي اقتباس إن كانت نمطًا مثل \"*.py\"",
        "e_tag": "وسوم YAML ('!tag') غير مدعومة",
        "e_block_scalar": "النصوص متعددة الأسطر ('|' و'>') غير مدعومة؛ استخدم نصًا بين علامتي اقتباس في سطر واحد",
        "e_flow_map": "قاموس مضمّن غير صالح؛ المتوقع '{{مفتاح: قيمة, مفتاح: قيمة}}' في سطر واحد",
        "e_flow_nested": "القوائم المضمّنة المتداخلة غير مدعومة؛ استخدم قائمة بأسطر",
        "e_flow_unterminated": "'[...]' أو '{{...}}' غير مغلقة في السطر نفسه (الصيغة المضمّنة على عدة أسطر غير مدعومة)",
        "e_flow_syntax": "قائمة مضمّنة غير صالحة؛ المتوقع ',' أو ']'",
        "e_complex_key": "المفاتيح المركّبة ('? key') غير مدعومة",
        "e_merge_key": "مفاتيح الدمج ('<<') غير مدعومة؛ استخدم 'extends' للوراثة",
        "e_reserved": "لا يجوز أن تبدأ قيمة غير مقتبسة بالمحرف '{char}'؛ ضعها بين علامتي اقتباس",
        "e_unterminated_quote": "النص المقتبس غير مغلق في السطر نفسه",
        "e_bad_escape": "تسلسل الهروب '\\{esc}' غير مدعوم داخل نص بعلامتي اقتباس مزدوجتين",
        "e_after_quote": "نص غير متوقع بعد النص المقتبس",
        "e_dup_key": "المفتاح '{key}' مكرر",
        "e_indent": "إزاحة غير متسقة",
        "e_expected_key": "المتوقع 'مفتاح: قيمة'",
        "e_empty_key": "مفتاح فارغ",
        "e_inline_map": "القيمة التي تحوي ': ' يجب أن تُقتبس (القواميس المتداخلة تُكتب في أسطر مزاحة)",
        "e_inline_seq": "لا تبدأ القائمة في سطر مفتاحها؛ اكتب كل '- عنصر' في سطر مستقل",
        "e_multiline_scalar": "القيم متعددة الأسطر غير مدعومة؛ اكتب القيمة في سطر واحد",
        "e_depth": "تداخل أعمق من {limit} مستوى",
        "e_nodes": "أكثر من {limit} قيمة",
        "e_json": "JSON غير صالح: {msg}",
        "e_json_const": "القيم NaN و Infinity والأعداد الأطول من 40 محرفًا غير مسموحة",
        "e_ext": "نوع ملف السياسة غير مدعوم؛ استخدم .yml أو .yaml أو .json",
        "e_not_file": "ملف السياسة غير موجود أو ليس ملفًا عاديًا",
        "e_read": "تعذّرت قراءة الملف: {err}",
        "e_top_mapping": "يجب أن تكون السياسة قاموس إعدادات (مفتاح: قيمة)",
        "e_unknown_key": "مفتاح غير معروف '{key}'{hint}",
        "hint_did_you_mean": " (هل تقصد '{name}'؟)",
        "e_type": "المتوقع {expected}",
        "t_map": "قاموس", "t_list": "قائمة", "t_str": "نص غير فارغ", "t_bool": "true أو false",
        "t_int": "عدد صحيح", "t_str_list": "نص أو قائمة نصوص",
        "e_required": "المفتاح الإلزامي '{key}' مفقود",
        "e_severity": "'{value}' ليست درجة خطورة؛ استخدم إحدى: {allowed}",
        "e_version": "إصدار السياسة {value} غير مدعوم؛ هذا الإصدار يفهم النسخة 1",
        "e_int_min": "المتوقع عدد صحيح >= {min}",
        "e_cwe": "'{value}' ليس معرّف CWE؛ اكتب CWE-89 أو 89",
        "e_owasp": "'{value}' ليست فئة OWASP مدعومة؛ اكتب A01..A10 (OWASP Top 10 لعام 2021) أو API1..API10 "
                   "(OWASP API Security Top 10 لعام 2023). الإصدارات الأخرى مثل Top 10 لعام 2025 ترقّم فئاتها "
                   "بشكل مختلف وهي غير مدعومة",
        "e_date": "'{value}' ليس تاريخًا؛ اكتب YYYY-MM-DD",
        "e_glob": "نمط مسار غير صالح",
        "e_selector": "يحتاج الاستثناء إلى واحد على الأقل من: rule أو path أو cwe أو fingerprint",
        "e_fingerprint": "البصمة (أو بادئتها) تحتاج 8 محارف ست عشرية على الأقل",
        "e_dup_name": "الاسم '{name}' مكرر",
        "e_enable_conflict": "القاعدة '{name}' معطّلة ومفعّلة في الملف نفسه",
        "e_identifier": "'{value}' ليس اسمًا صالحًا (أحرف لاتينية صغيرة وأرقام و'-' و'_')",
        "e_extends_unknown": "'{name}' ليس قالبًا مدمجًا ({presets}) ولا مسار ملف .yml/.yaml/.json",
        "e_extends_cycle": "حلقة وراثة: {chain}",
        "e_extends_depth": "أكثر من {limit} مستويات من 'extends'",
        "e_extends_missing": "السياسة الموروثة '{path}' غير موجودة",
        "e_locked": "المفتاح '{key}' مقفل في السياسة الموروثة {parent} ولا يجوز تغييره هنا",
        "e_report_path": "مسار التقرير يجب أن يكون نسبيًا ولا يحوي '..' وأن يكون اسم ملف محمولًا "
                         "(دون ':' أو محارف محجوزة أخرى ودون أسماء أجهزة Windows)",
        "e_path_unsafe": "مسارات الشبكة (UNC) والعناوين URL غير مسموحة",
        "e_text_char": "المحرف U+{code:04X} (تحكّم أو تجاوز لاتجاه النص) غير مسموح داخل القيم",
        "e_extends_outside": "السياسة الموروثة '{path}' تقع خارج '{root}'؛ لا ترث السياسة إلا ملفات داخل مجلدها "
                             "أو مستودعها (لسياسة موثوقة: --allow-external-extends)",
        "e_locked_unknown": "لا يمكن قفل '{key}'؛ اقفل قسمًا (gate أو scopes أو rules أو ignores أو sla أو reports أو "
                            "required_scanners) أو مفتاحًا مثل gate.fail_on أو gate.max.high أو rules.disable أو sla.high",
        "e_too_long": "أطول من {limit} محرفًا",
        "e_list_too_long": "أكثر من {limit} عنصر",
        "w_report_format": "صيغة التقرير '{value}' ليست من الصيغ المدمجة ({allowed})",
        "v_severity-threshold": "{count} نتيجة بخطورة {threshold} أو أعلى في النطاق '{scope}'",
        "v_max-count": "{count} نتيجة بخطورة {severity} في النطاق '{scope}' والسياسة تسمح بـ {max} على الأكثر",
        "v_max-total": "{count} نتيجة في النطاق '{scope}' والسياسة تسمح بـ {max} إجمالًا على الأكثر",
        "v_forbidden-cwe": "{count} نتيجة من نوع CWE-{cwe} الذي تمنعه السياسة (النطاق '{scope}')",
        "v_forbidden-rule": "{count} نتيجة للقاعدة '{rule}' التي تمنعها السياسة (النطاق '{scope}')",
        "v_forbidden-owasp": "{count} نتيجة ضمن فئة OWASP {category} التي تمنعها السياسة (النطاق '{scope}')",
        "v_secret": "{count} سرّ مكتوب في الكود (النطاق '{scope}')؛ الأسرار تُفشل البوابة دائمًا",
        "v_expired-ignore": "الاستثناء رقم {index} ({selector}) الذي اعتمده {approver} انتهى في {date} (منذ {days} يومًا): "
                            "{count} نتيجة لم تعد مقبولة",
        "v_expired-acceptance": "{count} نتيجة انتهى قبول الخطر الخاص بها",
        "v_acceptance-too-long": "الاستثناء رقم {index} ({selector}) ينتهي في {date} أي بعد {days} يومًا؛ "
                                 "السياسة تسمح بـ {max} يومًا على الأكثر",
        "v_required-scanner": "الفاحص الإلزامي '{scanner}' لم يعمل أو لا دليل على أنه عمل",
        "v_sla-breach": "{count} نتيجة بخطورة {severity} تجاوزت مهلة الإصلاح {days} يومًا (الأقدم: {oldest} يومًا)",
        "v_warnings-as-errors": "{count} تحذير، والتحذيرات تُعامَل كأخطاء",
        "w_new-only-no-reference": "الخيار new_only مفعّل دون خط أساس أو قائمة ملفات متغيّرة أو علامة 'new'؛ "
                                   "قُيّمت كل النتائج",
        "w_baseline-unreadable": "تعذّرت قراءة خط الأساس '{path}'؛ قُيّمت كل النتائج",
        "w_ignore-expiring": "الاستثناء رقم {index} ({selector}) ينتهي في {date} (بعد {days} يومًا)",
        "w_ignore-unused": "الاستثناء رقم {index} ({selector}) لا يطابق أي نتيجة؛ احذفه",
        "w_ignore-expired-unused": "الاستثناء رقم {index} ({selector}) انتهى في {date} ولا يطابق أي نتيجة؛ احذفه",
        "w_expired-not-enforced": "{count} استثناء أو قبول خطر منتهٍ؛ الخيار fail_on_expired معطّل",
        "w_sla-no-dates": "لم تُفحص مهلة الإصلاح لـ {count} نتيجة: لا يوجد تاريخ أول ظهور (استخدم الفرز أو خريطة first_seen)",
        "w_sla-breach": "{count} نتيجة بخطورة {severity} تجاوزت مهلة الإصلاح {days} يومًا (الأقدم: {oldest} يومًا)",
        "w_unknown-severity": "{count} نتيجة بخطورة غير معروفة عوملت كمتوسطة",
        "w_owasp-fallback": "الوحدة vulnscan.compliance غير متاحة؛ فئات OWASP مأخوذة من جدول مدمج صغير",
        "x_title": "بوابة الأمان في كاشِف",
        "x_passed": "نجحت", "x_failed": "فشلت",
        "x_policy": "السياسة", "x_date": "تاريخ التقييم", "x_exit": "رمز الخروج",
        "x_summary": "قُيّمت {evaluated} من {total} نتيجة (مستثناة {ignored}، قاعدة معطّلة {disabled}، "
                     "مفروزة {triaged}، خارج النطاق {skipped})",
        "x_violations": "المخالفات", "x_warnings": "التحذيرات", "x_none": "لا شيء",
        "x_more": "... و{count} أخرى",
        "x_col_rule": "القاعدة", "x_col_sev": "الخطورة", "x_col_loc": "الموضع", "x_col_fp": "البصمة",
        "x_scope_default": "الافتراضي",
        "sev_critical": "حرجة", "sev_high": "عالية", "sev_medium": "متوسطة", "sev_low": "منخفضة", "sev_info": "معلوماتية",
        "c_valid": "{path}: سياسة صالحة '{name}' ({rules} شرط بوابة، {scopes} نطاق، {ignores} استثناء)",
        "c_written": "كُتب الملف {path}",
        "c_exists": "الملف {path} موجود؛ استخدم --force للكتابة فوقه",
        "c_no_policy": "لم يُعثر على ملف سياسة (بُحث عن {names})؛ مرّر --policy",
        "c_bad_report": "تعذّرت قراءة التقرير {path}: {err}",
        "c_bad_today": "قيمة --today يجب أن تكون YYYY-MM-DD",
        "p_startup": "فريق صغير: امنع النتائج الحرجة والأسرار وتساهل مع الاختبارات",
        "p_strict": "امنع المتوسطة فما فوق، لا استثناء أطول من 90 يومًا، مهلة الإصلاح مُلزِمة",
        "p_pci-dss": "بوابة مستوحاة من PCI DSS v4.0 / v4.0.1 المتطلبات 6.2.4 و6.3.1 و6.3.3 و8.6.2 (ليست شهادة امتثال)",
        "p_owasp-asvs-l1": "بوابة مستوحاة من OWASP ASVS 4.0.3 المستوى الأول (V4 وV5 وV14.2) مع منع الأسرار في الكود",
    },
}


def _lang(lang) -> str:
    return "ar" if str(lang or "").lower().startswith("ar") else "en"


def _t(lang, key: str, /, **kw) -> str:
    table = STR[_lang(lang)]
    text = table.get(key) or STR["en"].get(key) or key
    try:
        return text.format(**kw)
    except (KeyError, IndexError, ValueError):
        return text


# --------------------------------------------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------------------------------------------
@dataclass
class Problem:
    """One precise problem in a policy file: where it is and a message key with its arguments."""
    source: str
    line: int          # 1-based; 0 when unknown (JSON validation, builtin presets)
    col: int           # 1-based; 0 when unknown
    path: str          # dotted location such as "ignores[2].expires"; "" for syntax errors
    code: str          # key of STR, e.g. "e_severity"
    args: dict = field(default_factory=dict)

    def message(self, lang: str = "en") -> str:
        args = dict(self.args)
        if "expected" in args:
            args["expected"] = _t(lang, args["expected"])
        if self.code == "e_unknown_key":
            args["hint"] = _t(lang, "hint_did_you_mean", name=args["hint"]) if args.get("hint") else ""
        return _t(lang, self.code, **args)

    def format(self, lang: str = "en") -> str:
        loc = self.source
        if self.line:
            loc += f":{self.line}"
            if self.col:
                loc += f":{self.col}"
        where = f" [{self.path}]" if self.path else ""
        return f"{loc}:{where} {self.message(lang)}"

    def to_dict(self) -> dict:
        return {"source": self.source, "line": self.line, "col": self.col, "path": self.path, "code": self.code,
                "message_en": self.message("en"), "message_ar": self.message("ar")}


class PolicyError(ValueError):
    """A policy file could not be parsed or is invalid. ``problems`` lists every problem found."""

    def __init__(self, problems):
        self.problems: list[Problem] = list(problems)
        super().__init__(self.format("en"))

    def format(self, lang: str = "en") -> str:
        return "\n".join(p.format(lang) for p in self.problems)


def _fail(source, line, col, code, /, **args):
    raise PolicyError([Problem(source, line, col, "", code, args)])


# --------------------------------------------------------------------------------------------------------------
# Strict YAML subset
# --------------------------------------------------------------------------------------------------------------
_INT = re.compile(r"[-+]?(?:0|[1-9][0-9]{0,17})\Z")
_FLOAT = re.compile(r"[-+]?(?:0|[1-9][0-9]{0,17})\.[0-9]{1,18}\Z")
_NULLS = frozenset({"null", "Null", "NULL", "~"})
_TRUES = frozenset({"true", "True", "TRUE"})
_FALSES = frozenset({"false", "False", "FALSE"})
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "0": "\0", '"': '"', "\\": "\\", "/": "/", " ": " "}
_HEX = {"x": 2, "u": 4, "U": 8}


def _resolve(plain: str):
    if plain in _NULLS:
        return None
    if plain in _TRUES:
        return True
    if plain in _FALSES:
        return False
    if _INT.match(plain):
        return int(plain)
    if _FLOAT.match(plain):
        return float(plain)
    return plain


def _check_text(text: str, source: str) -> str:
    """Common pre-checks for YAML and JSON input: size and control characters. Returns the text without a BOM."""
    if len(text) > MAX_BYTES:
        _fail(source, 0, 0, "e_too_big", size=len(text), limit=MAX_BYTES)
    if text.startswith("﻿"):
        text = text[1:]
    m = re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\x85  ]", text)
    if m:
        line = text.count("\n", 0, m.start()) + 1
        _fail(source, line, m.start() - (text.rfind("\n", 0, m.start()) + 1) + 1, "e_control_char", code=ord(m.group()))
    return text


class _Yaml:
    def __init__(self, text: str, source: str):
        self.source = source
        self.marks: dict[tuple, int] = {}
        self.nodes = 0
        self.pos = 0
        self.lines: list[tuple[int, int, str]] = []          # (line number, indent, content)
        text = _check_text(text, source)
        started = False
        for no, raw in enumerate(text.split("\n"), 1):
            if raw.endswith("\r"):
                raw = raw[:-1]
            if "\r" in raw:
                _fail(source, no, raw.index("\r") + 1, "e_control_char", code=13)
            if len(raw) > MAX_LINE:
                _fail(source, no, 0, "e_line_too_long", limit=MAX_LINE)
            body = raw.lstrip(" ")
            indent = len(raw) - len(body)
            content = body.rstrip(" \t")
            if not content or content.startswith("#"):
                continue
            if body.startswith("\t"):
                _fail(source, no, indent + 1, "e_tab")
            if indent == 0:
                head = content.split(" #", 1)[0].rstrip()
                if head == "---" and not started:
                    started = True
                    continue
                if head in ("---", "...") or content.startswith("--- "):
                    _fail(source, no, 1, "e_multi_doc")
                if content.startswith("%"):
                    _fail(source, no, 1, "e_directive")
            started = True
            self.lines.append((no, indent, content))

    # ----------------------------------------------------------------------------------------------------- helpers
    def fail(self, line, col, code, /, **args):
        _fail(self.source, line, col, code, **args)

    def count(self, line):
        self.nodes += 1
        if self.nodes > MAX_NODES:
            self.fail(line, 0, "e_nodes", limit=MAX_NODES)

    @staticmethod
    def is_seq(content: str) -> bool:
        return content == "-" or content.startswith("- ")

    def quoted(self, text: str, start: int, line: int, col: int) -> tuple[str, int]:
        """Parse the quoted string that starts at ``text[start]``. Returns (value, index after the closing quote)."""
        quote = text[start]
        out = []
        i = start + 1
        n = len(text)
        while i < n:
            ch = text[i]
            if quote == "'":
                if ch == "'":
                    if text[i + 1:i + 2] == "'":
                        out.append("'")
                        i += 2
                        continue
                    return "".join(out), i + 1
            elif ch == '"':
                return "".join(out), i + 1
            elif ch == "\\":
                esc = text[i + 1:i + 2]
                if esc in _ESCAPES:
                    out.append(_ESCAPES[esc])
                    i += 2
                    continue
                if esc in _HEX:
                    digits = text[i + 2:i + 2 + _HEX[esc]]
                    if len(digits) == _HEX[esc] and re.fullmatch(r"[0-9A-Fa-f]+", digits):
                        code = int(digits, 16)
                        if code <= 0x10FFFF and not 0xD800 <= code <= 0xDFFF:
                            out.append(chr(code))
                            i += 2 + _HEX[esc]
                            continue
                self.fail(line, col + i, "e_bad_escape", esc=esc[:1])
            out.append(ch)
            i += 1
        self.fail(line, col + start, "e_unterminated_quote")
        raise AssertionError  # pragma: no cover

    def tail_ok(self, tail: str, line: int, col: int):
        """After a complete value only whitespace or a comment may follow."""
        rest = tail.strip()
        if rest and not (rest.startswith("#") and tail[:1] in (" ", "\t")):
            self.fail(line, col, "e_after_quote")

    def reject_indicator(self, text: str, line: int, col: int):
        c = text[0]
        if c == "&":
            self.fail(line, col, "e_anchor")
        if c == "*":
            self.fail(line, col, "e_alias")
        if c == "!":
            self.fail(line, col, "e_tag")
        if c in "|>":
            self.fail(line, col, "e_block_scalar")
        if c in "%@`,]}":
            self.fail(line, col, "e_reserved", char=c)
        if text == "?" or text.startswith("? "):
            self.fail(line, col, "e_complex_key")

    def plain(self, text: str, line: int, col: int, flow: bool = False):
        self.reject_indicator(text, line, col)
        if not flow and self.is_seq(text):
            self.fail(line, col, "e_inline_seq")
        if text.startswith("<<"):
            self.fail(line, col, "e_merge_key")
        if re.search(r":(?: |\Z)", text):
            self.fail(line, col, "e_inline_map")
        return _resolve(text)

    def flow_seq(self, text: str, line: int, col: int) -> tuple[list, int]:
        out: list = []
        i = 1
        n = len(text)
        expect_value = True
        while True:
            while i < n and text[i] == " ":
                i += 1
            if i >= n:
                self.fail(line, col, "e_flow_unterminated")
            ch = text[i]
            if ch == "]":
                return out, i + 1
            if not expect_value:
                if ch != ",":
                    self.fail(line, col + i, "e_flow_syntax")
                i += 1
                expect_value = True
                continue
            if ch == ",":
                self.fail(line, col + i, "e_flow_syntax")
            if ch in "[{":
                self.fail(line, col + i, "e_flow_nested")
            if ch in "\"'":
                value, i = self.quoted(text, i, line, col)
            else:
                j = i
                while j < n and text[j] not in ",]":
                    if text[j] in "[{}" or (text[j] == "#" and text[j - 1] == " "):
                        self.fail(line, col + j, "e_flow_syntax")
                    j += 1
                value = self.plain(text[i:j].strip(), line, col + i, flow=True)
                i = j
            self.count(line)
            out.append(value)
            expect_value = False

    def flow_map(self, text: str, line: int, col: int) -> tuple[dict, int]:
        """``{key: scalar, ...}`` on one line (no nesting)."""
        out: dict = {}
        i = 1
        n = len(text)
        expect_key = True
        while True:
            while i < n and text[i] == " ":
                i += 1
            if i >= n:
                self.fail(line, col, "e_flow_unterminated")
            ch = text[i]
            if ch == "}":
                return out, i + 1
            if not expect_key:
                if ch != ",":
                    self.fail(line, col + i, "e_flow_map")
                i += 1
                expect_key = True
                continue
            if ch in "\"'":
                key, i = self.quoted(text, i, line, col)
            else:
                j = i
                while j < n and text[j] not in ":,}{[]":
                    j += 1
                key = text[i:j].strip()
                if not key:
                    self.fail(line, col + i, "e_flow_map")
                if key == "<<":
                    self.fail(line, col + i, "e_merge_key")
                self.reject_indicator(key, line, col + i)
                i = j
            while i < n and text[i] == " ":
                i += 1
            if i >= n or text[i] != ":":
                self.fail(line, col + min(i, n - 1), "e_flow_map")
            i += 1
            while i < n and text[i] == " ":
                i += 1
            if i >= n:
                self.fail(line, col, "e_flow_unterminated")
            if text[i] in "[{":
                self.fail(line, col + i, "e_flow_nested")
            if text[i] in "\"'":
                value, i = self.quoted(text, i, line, col)
            else:
                j = i
                while j < n and text[j] not in ",}":
                    if text[j] in "[{]" or (text[j] == "#" and text[j - 1] == " "):
                        self.fail(line, col + j, "e_flow_map")
                    j += 1
                raw = text[i:j].strip()
                if not raw:
                    self.fail(line, col + i, "e_flow_map")
                value = self.plain(raw, line, col + i, flow=True)
                i = j
            if key in out:
                self.fail(line, col, "e_dup_key", key=key[:60])
            self.count(line)
            out[key] = value
            expect_key = False

    def scalar(self, text: str, line: int, col: int):
        """A complete value on one line: quoted, flow sequence, flow mapping or plain (with an optional comment)."""
        self.count(line)
        c = text[0]
        if c in "\"'":
            value, end = self.quoted(text, 0, line, col)
            self.tail_ok(text[end:], line, col + end)
            return value
        if c == "[":
            value, end = self.flow_seq(text, line, col)
            self.tail_ok(text[end:], line, col + end)
            return value
        if c == "{":
            value, end = self.flow_map(text, line, col)
            self.tail_ok(text[end:], line, col + end)
            return value
        cut = re.search(r"[ \t]#", text)
        if cut:
            text = text[:cut.start()].rstrip()
        return self.plain(text, line, col)

    def split_key(self, content: str, line: int, indent: int):
        """``(key, value_text, value_col)`` when the line is ``key: ...``, else None."""
        c = content[0]
        if c in "\"'":
            key, end = self.quoted(content, 0, line, indent + 1)
            rest = content[end:].lstrip(" ")
            if rest.startswith(":") and (len(rest) == 1 or rest[1] == " "):
                return key, rest[1:], indent + len(content) - len(rest) + 2
            return None
        if c in "[{":
            return None
        for i, ch in enumerate(content):
            if ch == "#" and i and content[i - 1] in " \t":
                return None
            if ch == ":" and (i + 1 == len(content) or content[i + 1] == " "):
                key = content[:i].rstrip()
                if not key:
                    self.fail(line, indent + 1, "e_empty_key")
                if key == "<<":
                    self.fail(line, indent + 1, "e_merge_key")
                self.reject_indicator(key, line, indent + 1)
                return key, content[i + 1:], indent + i + 2
        return None

    # ------------------------------------------------------------------------------------------------------ blocks
    def node(self, depth: int, path: tuple):
        line, indent, content = self.lines[self.pos]
        if depth > MAX_DEPTH:
            self.fail(line, indent + 1, "e_depth", limit=MAX_DEPTH)
        if self.is_seq(content):
            return self.seq(indent, depth, path)
        if self.split_key(content, line, indent) is not None:
            return self.mapping(indent, depth, path)
        self.pos += 1
        return self.scalar(content, line, indent + 1)

    def after_block(self, indent: int):
        if self.pos < len(self.lines) and self.lines[self.pos][1] > indent:
            line, ind, _ = self.lines[self.pos]
            self.fail(line, ind + 1, "e_indent")

    def seq(self, indent: int, depth: int, path: tuple) -> list:
        out: list = []
        self.count(self.lines[self.pos][0])
        while self.pos < len(self.lines) and self.lines[self.pos][1] == indent and self.is_seq(self.lines[self.pos][2]):
            line, _, content = self.lines[self.pos]
            item_path = path + (len(out),)
            self.marks[item_path] = line
            rest = content[1:]
            body = rest.lstrip(" ")
            if not body or body.startswith("#"):
                self.pos += 1
                if self.pos < len(self.lines) and self.lines[self.pos][1] > indent:
                    value = self.node(depth + 1, item_path)
                else:
                    self.count(line)
                    value = None
            else:
                inner = indent + 1 + len(rest) - len(body)
                self.lines[self.pos] = (line, inner, body)          # "- key: v" is a block that starts at "key"
                value = self.node(depth + 1, item_path)
            out.append(value)
        self.after_block(indent)
        return out

    def mapping(self, indent: int, depth: int, path: tuple) -> dict:
        out: dict = {}
        self.count(self.lines[self.pos][0])
        while self.pos < len(self.lines) and self.lines[self.pos][1] == indent:
            line, _, content = self.lines[self.pos]
            if self.is_seq(content):
                self.fail(line, indent + 1, "e_expected_key")
            kv = self.split_key(content, line, indent)
            if kv is None:
                self.fail(line, indent + 1, "e_expected_key")
            key, vtext, vcol = kv
            if key in out:
                self.fail(line, indent + 1, "e_dup_key", key=key[:60])
            key_path = path + (key,)
            self.marks[key_path] = line
            self.pos += 1
            v = vtext.strip()
            more = self.pos < len(self.lines)
            if not v or v.startswith("#"):
                if more and self.lines[self.pos][1] > indent:
                    value = self.node(depth + 1, key_path)
                elif more and self.lines[self.pos][1] == indent and self.is_seq(self.lines[self.pos][2]):
                    if depth + 1 > MAX_DEPTH:
                        self.fail(line, indent + 1, "e_depth", limit=MAX_DEPTH)
                    value = self.seq(indent, depth + 1, key_path)
                else:
                    self.count(line)
                    value = None
            else:
                value = self.scalar(v, line, vcol + len(vtext) - len(vtext.lstrip()))
                if more and self.lines[self.pos][1] > indent:
                    nline, nind, _ = self.lines[self.pos]
                    self.fail(nline, nind + 1, "e_multiline_scalar")
            out[key] = value
        self.after_block(indent)
        return out

    def document(self):
        if not self.lines:
            return None
        value = self.node(0, ())
        if self.pos < len(self.lines):
            line, indent, _ = self.lines[self.pos]
            self.fail(line, indent + 1, "e_indent")
        return value


def parse_yaml(text: str, source: str = "<policy>", marks: dict | None = None):
    """Parse the strict YAML subset described in the module docstring.

    Returns plain ``dict`` / ``list`` / ``str`` / ``int`` / ``float`` / ``bool`` / ``None`` (``None`` for an empty
    document). Raises :class:`PolicyError` with the line and column of the first construct outside the subset.
    ``marks``, when given, is filled with ``{path tuple: line}`` for every mapping key and list item."""
    if not isinstance(text, str):
        raise TypeError("parse_yaml expects str")
    try:
        parser = _Yaml(text, source)
        value = parser.document()
    except RecursionError:                                   # cannot happen with MAX_DEPTH; belt and braces
        _fail(source, 0, 0, "e_depth", limit=MAX_DEPTH)
    if marks is not None:
        marks.update(parser.marks)
    return value


_PLAIN_SAFE = re.compile(r"[A-Za-z0-9_./][A-Za-z0-9_./ +=@-]*\Z")


def _yaml_scalar(value) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return repr(value) if value == value and value not in (float("inf"), float("-inf")) else json.dumps(str(value))
    text = str(value)
    if _PLAIN_SAFE.match(text) and not text.endswith(" ") and isinstance(_resolve(text), str) and text != "-":
        return text
    return json.dumps(text, ensure_ascii=False)


def _inline(value) -> str:
    if isinstance(value, dict):
        return "{}"
    if isinstance(value, list):
        return "[]"
    return _yaml_scalar(value)


def _dump(value, indent: int, out: list[str]):
    pad = " " * indent
    if isinstance(value, dict):
        for key, val in value.items():
            k = _yaml_scalar(str(key))
            if isinstance(val, (dict, list)) and val:
                out.append(f"{pad}{k}:")
                _dump(val, indent + 2, out)
            else:
                out.append(f"{pad}{k}: {_inline(val)}")
    else:
        for item in value:
            if isinstance(item, (dict, list)) and item:
                sub: list[str] = []
                _dump(item, indent + 2, sub)
                sub[0] = f"{pad}- {sub[0][indent + 2:]}"
                out.extend(sub)
            else:
                out.append(f"{pad}- {_inline(item)}")


def dump_yaml(data) -> str:
    """Serialize plain data to the YAML subset that :func:`parse_yaml` reads (``parse_yaml(dump_yaml(x)) == x``)."""
    if isinstance(data, (dict, list)) and data:
        out: list[str] = []
        _dump(data, 0, out)
        return "\n".join(out) + "\n"
    if data == {} and isinstance(data, dict):
        return "{}\n"
    if data == []:
        return "[]\n"
    return _yaml_scalar(data) + "\n"


def _parse_json(text: str, source: str):
    text = _check_text(text, source)

    def pairs(items):
        out = {}
        for k, v in items:
            if k in out:
                raise _Dup(k)
            out[k] = v
        return out

    def const(_name):
        raise _Const()

    def number(kind):
        def parse(literal):
            if len(literal) > 40:                            # int() of a huge literal is slow (3.10) or raises (3.11+)
                raise _Const()
            return kind(literal)
        return parse

    try:
        data = json.loads(text, object_pairs_hook=pairs, parse_constant=const, parse_int=number(int),
                          parse_float=number(float))
    except _Dup as e:
        _fail(source, 0, 0, "e_dup_key", key=str(e.args[0])[:60])
    except _Const:
        _fail(source, 0, 0, "e_json_const")
    except json.JSONDecodeError as e:
        _fail(source, e.lineno, e.colno, "e_json", msg=e.msg)
    except RecursionError:
        _fail(source, 0, 0, "e_depth", limit=MAX_DEPTH)
    stack = [(data, 1)]
    nodes = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES:
            _fail(source, 0, 0, "e_nodes", limit=MAX_NODES)
        if isinstance(value, (dict, list)):
            if depth > MAX_DEPTH:
                _fail(source, 0, 0, "e_depth", limit=MAX_DEPTH)
            stack.extend((v, depth + 1) for v in (value.values() if isinstance(value, dict) else value))
    return data


class _Dup(Exception):
    pass


class _Const(Exception):
    pass


# --------------------------------------------------------------------------------------------------------------
# Path patterns
# --------------------------------------------------------------------------------------------------------------
_GLOB_CACHE: dict[str, tuple] = {}


def _norm_path(path) -> str:
    p = str(path or "").replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p


def _glob_compile(pattern: str) -> tuple:
    """Tokens of a path pattern: ``("lit", text)``, ``("one", None)`` (``?``), ``("cls", (negate, chars, ranges))``,
    ``("seg", None)`` (``*``), ``("any", None)`` (``**``) and ``("dirs", None)`` (``**/`` at a segment start)."""
    toks = _GLOB_CACHE.get(pattern)
    if toks is not None:
        return toks
    out: list = []
    lit: list[str] = []

    def flush():
        if lit:
            out.append(("lit", "".join(lit)))
            lit.clear()

    pat = pattern
    i, n = 0, len(pat)
    while i < n:
        c = pat[i]
        if c == "*":
            j = i
            while j < n and pat[j] == "*":
                j += 1
            kind = "seg"
            if j - i >= 2:
                kind = "any"
                if j < n and pat[j] == "/" and (i == 0 or pat[i - 1] == "/"):
                    kind = "dirs"
                    j += 1
            flush()
            if not out or out[-1][0] != kind or kind == "dirs":
                out.append((kind, None))
            i = j
            continue
        end = pat.find("]", i + 2) if c == "[" else -1
        if c == "?":
            flush()
            out.append(("one", None))
        elif end != -1:
            body = pat[i + 1:end]
            negate = body.startswith("!")
            if negate:
                body = body[1:]
            chars, ranges = set(), []
            k = 0
            while k < len(body):
                if k + 2 < len(body) and body[k + 1] == "-":
                    ranges.append((body[k], body[k + 2]))
                    k += 3
                else:
                    chars.add(body[k])
                    k += 1
            flush()
            out.append(("cls", (negate, frozenset(chars), tuple(ranges))))
            i = end
        else:
            lit.append(c)
        i += 1
    flush()
    toks = tuple(out)
    if len(_GLOB_CACHE) < 4096:
        _GLOB_CACHE[pattern] = toks
    return toks


def _glob_match(pattern: str, path: str) -> bool:
    """Match without a regex engine: the set of reachable positions is advanced token by token, so the cost is
    O(len(pattern) * len(path)) whatever the pattern (a hostile ``*a*a*a*...`` cannot cause backtracking)."""
    n = len(path)
    cur = [0]                                                # sorted, distinct positions in ``path``
    for kind, arg in _glob_compile(pattern):
        if kind == "lit":
            step = len(arg)
            nxt = [i + step for i in cur if path.startswith(arg, i)]
        elif kind == "one":
            nxt = [i + 1 for i in cur if i < n and path[i] != "/"]
        elif kind == "cls":
            negate, chars, ranges = arg
            nxt = []
            for i in cur:
                if i < n and path[i] != "/":
                    ch = path[i]
                    if (ch in chars or any(lo <= ch <= hi for lo, hi in ranges)) != negate:
                        nxt.append(i + 1)
        elif kind == "any":
            nxt = list(range(cur[0], n + 1))
        elif kind == "seg":
            nxt, reach = [], -1
            for i in cur:
                if i <= reach:
                    continue                                 # same segment as an earlier position: already covered
                end = path.find("/", i)
                reach = n if end == -1 else end
                nxt.extend(range(i, reach + 1))
        else:                                                # "dirs": nothing, or any number of whole directories
            seen = set(cur)
            k = path.find("/", cur[0])
            while k != -1:
                seen.add(k + 1)
                k = path.find("/", k + 1)
            nxt = sorted(seen)
        if not nxt:
            return False
        cur = nxt
    return cur[-1] == n


def path_matches(pattern: str, path: str) -> bool:
    """True when ``path`` (relative, ``/``-separated) matches a policy path pattern.

    ``*`` and ``?`` stay inside one path segment, ``**`` crosses directories (``**/x`` also matches ``x``), ``[abc]`` /
    ``[a-z]`` / ``[!abc]`` is a character class (it never matches ``/``). A pattern without wildcards names a file or a directory (``tests`` and ``tests/`` both
    match everything below ``tests/``). A pattern without ``/`` is also tried against the file name alone, so
    ``*.min.js`` matches at any depth."""
    pat = _norm_path(pattern)
    p = _norm_path(path)
    if not pat:
        return False
    if not any(ch in pat for ch in "*?["):
        base = pat.rstrip("/")
        return p == base or p.startswith(base + "/")
    if pat.endswith("/"):
        pat += "**"
    if _glob_match(pat, p):
        return True
    return "/" not in pat and _glob_match(pat, p.rsplit("/", 1)[-1])


# --------------------------------------------------------------------------------------------------------------
# Presets
# --------------------------------------------------------------------------------------------------------------
_INJECTION_CWES = [22, 78, 79, 89, 90, 94, 502, 611, 918]
PRESETS: dict[str, dict] = {
    "startup": {
        "name": "startup",
        "description": "Block critical findings and secrets; keep tests out of the way.",
        "gate": {"fail_on": "critical", "fail_on_secrets": True, "fail_on_expired": True},
        "scopes": [{"name": "tests", "paths": ["tests/**", "test/**", "**/*_test.*", "**/test_*.*"], "fail_on": "never",
                    "fail_on_secrets": False}],
        "required_scanners": ["secrets"],
        "sla": {"critical": 14, "high": 60},
    },
    "strict": {
        "name": "strict",
        "description": "Block medium and above, enforce SLAs, short-lived exceptions only.",
        "gate": {"fail_on": "medium", "max": {"low": 25}, "fail_on_secrets": True, "fail_on_expired": True,
                 "fail_on_sla_breach": True, "max_acceptance_days": 90},
        "required_scanners": ["deps", "sast", "secrets"],
        "sla": {"critical": 3, "high": 7, "medium": 30, "low": 90},
    },
    "pci-dss": {
        "name": "pci-dss",
        "description": "Inspired by PCI DSS v4.0 / v4.0.1: Req. 6.2.4 (prevent injection and other common software "
                       "attacks), 6.3.1 (identify and risk-rank vulnerabilities), 6.3.3 (install security patches "
                       "promptly; the 30-day SLA here is this preset's choice) and 8.6.2 (no hard-coded passwords "
                       "in scripts, configuration or source code). Evidence for an assessment, not a certification.",
        "gate": {"fail_on": "high", "fail_on_cwe": _INJECTION_CWES + [287, 306, 327, 352, 434, 798, 862],
                 "fail_on_secrets": True, "fail_on_expired": True, "fail_on_sla_breach": True,
                 "max_acceptance_days": 180},
        "required_scanners": ["deps", "sast", "secrets"],
        "sla": {"critical": 30, "high": 30, "medium": 90},
    },
    "owasp-asvs-l1": {
        "name": "owasp-asvs-l1",
        "description": "Inspired by OWASP ASVS 4.0.3 Level 1: injection and redirect defences (V5), access control "
                       "and CSRF (V4), up-to-date components (V14.2.1). Secrets in code are blocked as well, although "
                       "ASVS lists that at Level 2 (V2.10.4, V6.4.1). Covers only what static analysis can see.",
        "gate": {"fail_on": "high", "fail_on_cwe": _INJECTION_CWES + [352, 601, 798],
                 "fail_on_owasp": ["A01", "A03"], "fail_on_secrets": True, "fail_on_expired": True},
        "required_scanners": ["deps", "sast", "secrets"],
        "sla": {"critical": 14, "high": 30, "medium": 90},
    },
}

# --------------------------------------------------------------------------------------------------------------
# Validation (one file -> a normalized, partial layer)
# --------------------------------------------------------------------------------------------------------------
_TOP_KEYS = ("version", "name", "description", "extends", "locked", "gate", "scopes", "rules", "ignores",
             "required_scanners", "sla", "reports")
_GATE_LISTS = ("fail_on_cwe", "fail_on_rules", "fail_on_owasp")
_SCOPE_GATE_KEYS = ("fail_on", "max", "max_total", "new_only", "fail_on_secrets") + _GATE_LISTS
_GATE_KEYS = _SCOPE_GATE_KEYS + ("baseline", "fail_on_expired", "fail_on_sla_breach", "max_acceptance_days")
_SCOPE_KEYS = ("name", "paths", "skip", "reason") + _SCOPE_GATE_KEYS
_IGNORE_KEYS = ("rule", "path", "cwe", "fingerprint", "reason", "approver", "expires", "ticket")
_IDENT = re.compile(r"[a-z][a-z0-9_-]{0,39}\Z")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}\Z")
_NEVER = ("never", "none", "off")
# C0 / C1 controls, line / paragraph separators and the bidirectional embedding / override / isolate characters
# ("Trojan Source"): never valid in a policy value, and replaced when a report value is printed.
_BAD_TEXT = re.compile("[\x00-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069]")
_WIN_DEVICES = frozenset(["CON", "PRN", "AUX", "NUL"] + [f"{d}{i}" for d in ("COM", "LPT") for i in range(1, 10)])
_LOCKABLE_TOP = ("gate", "scopes", "rules", "ignores", "required_scanners", "sla", "reports")


def _unsafe_path(text: str) -> bool:
    """UNC / device paths and URLs: opening one can reach the network (and leak credentials on Windows)."""
    t = text.replace("\\", "/")
    return t.startswith("//") or "://" in t


def _lockable(name: str) -> bool:
    parts = name.split(".")
    if parts[0] not in _LOCKABLE_TOP:
        return False
    if len(parts) == 1:
        return True
    if parts[0] == "gate":
        return parts[1] in _GATE_KEYS and (len(parts) == 2 or (len(parts) == 3 and parts[1] == "max"
                                                               and parts[2] in SEVERITIES))
    if parts[0] == "rules":
        return len(parts) == 2 and parts[1] in ("disable", "enable", "severity")
    return parts[0] == "sla" and len(parts) == 2 and parts[1] in SEVERITIES


def _parse_date(value) -> _dt.date | None:
    if isinstance(value, _dt.datetime):
        return value.date()
    if isinstance(value, _dt.date):
        return value
    text = str(value or "")[:10]
    if not _DATE.match(text):
        return None
    try:
        return _dt.date.fromisoformat(text)
    except ValueError:
        return None


def _norm_cwe(value) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 0 < value < 100_000 else None
    m = re.fullmatch(r"(?i)\s*(?:cwe[-_ ]?)?([1-9][0-9]{0,4})\s*", str(value))
    return int(m.group(1)) if m else None


def _norm_owasp(value) -> str | None:
    m = re.fullmatch(r"(?i)\s*(a|api)0?([1-9]|10)(?::(20\d\d))?\s*", str(value))
    if not m:
        return None
    # The category numbers mean something else in other editions (A03 is Injection in the Top 10 2021 and
    # Software Supply Chain Failures in 2025), so an explicit year must be the edition that is implemented.
    if m.group(3) and m.group(3) != ("2021" if m.group(1).lower() == "a" else "2023"):
        return None
    return f"A{int(m.group(2)):02d}" if m.group(1).lower() == "a" else f"API{int(m.group(2))}"


def _dotted(path: tuple) -> str:
    out = ""
    for part in path:
        out += f"[{part}]" if isinstance(part, int) else (f".{part}" if out else str(part))
    return out


class _Validator:
    def __init__(self, source: str, marks: dict):
        self.source = source
        self.marks = marks
        self.problems: list[Problem] = []
        self.warnings: list[tuple[str, dict]] = []

    def line(self, path: tuple) -> int:
        p = tuple(path)
        while p and p not in self.marks:
            p = p[:-1]
        return self.marks.get(p, 0)

    def err(self, path, code, /, **args):
        self.problems.append(Problem(self.source, self.line(tuple(path)), 0, _dotted(tuple(path)), code, args))

    def keys(self, mapping: dict, path: tuple, allowed) -> None:
        for key in mapping:
            if key not in allowed:
                near = difflib.get_close_matches(str(key), allowed, 1, 0.6)
                self.err(path + (key,), "e_unknown_key", key=str(key)[:60], hint=near[0] if near else "")

    def mapping(self, value, path) -> dict | None:
        if isinstance(value, dict):
            return value
        self.err(path, "e_type", expected="t_map")
        return None

    def items(self, value, path) -> list | None:
        if isinstance(value, list):
            if len(value) > MAX_LIST:
                self.err(path, "e_list_too_long", limit=MAX_LIST)
                return None
            return value
        self.err(path, "e_type", expected="t_list")
        return None

    def text(self, value, path) -> str | None:
        if isinstance(value, str) and value.strip():
            if len(value) > MAX_STR:
                self.err(path, "e_too_long", limit=MAX_STR)
                return None
            bad = _BAD_TEXT.search(value.strip())
            if bad:                                          # reachable through "\x1b" / "\u202e" escapes
                self.err(path, "e_text_char", code=ord(bad.group()))
                return None
            return value.strip()
        self.err(path, "e_type", expected="t_str")
        return None

    def boolean(self, value, path) -> bool | None:
        if isinstance(value, bool):
            return value
        self.err(path, "e_type", expected="t_bool")
        return None

    def integer(self, value, path, minimum: int = 0) -> int | None:
        if isinstance(value, int) and not isinstance(value, bool):
            if minimum <= value <= 10 ** 9:
                return value
            self.err(path, "e_int_min", min=minimum)
            return None
        self.err(path, "e_type", expected="t_int")
        return None

    def severity(self, value, path, never: bool = False) -> str | None:
        text = str(value).strip().lower() if isinstance(value, str) else ""
        if text in SEVERITIES:
            return text
        if never and text in _NEVER:
            return "never"
        allowed = ", ".join(SEVERITIES + (("never",) if never else ()))
        self.err(path, "e_severity", value=str(value)[:40], allowed=allowed)
        return None

    def text_list(self, value, path) -> list[str] | None:
        """A string or a list of strings -> list of strings."""
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, list):
            self.err(path, "e_type", expected="t_str_list")
            return None
        if len(value) > MAX_LIST:
            self.err(path, "e_list_too_long", limit=MAX_LIST)
            return None
        out = []
        for i, item in enumerate(value):
            if isinstance(item, (int, float)) and not isinstance(item, bool):
                item = str(item)
            s = self.text(item, path + (i,))
            if s is not None and s not in out:
                out.append(s)
        return out

    def glob(self, value, path) -> str | None:
        s = self.text(value, path)
        if s is None:
            return None
        if len(s) > 300 or s.count("*") > 16 or _norm_path(s).startswith("/"):
            self.err(path, "e_glob")
            return None
        return _norm_path(s)

    def rule_pattern(self, value, path) -> str | None:
        s = self.text(value, path)
        if s is not None and (len(s) > 100 or s.count("*") > 8):
            self.err(path, "e_glob")
            return None
        return s

    # ------------------------------------------------------------------------------------------------- sections
    def gate(self, raw, path: tuple, allowed) -> dict:
        out: dict = {}
        g = self.mapping(raw, path)
        if g is None:
            return out
        self.keys(g, path, allowed)
        for key in allowed:
            if key not in g:
                continue
            value, p = g[key], path + (key,)
            res = None
            if key == "fail_on":
                res = self.severity(value, p, never=True)
            elif key == "max":
                m = self.mapping(value, p)
                if m is not None:
                    res = {}
                    for sev, n in m.items():
                        s = self.severity(sev, p + (sev,))
                        c = self.integer(n, p + (sev,))
                        if s is not None and c is not None:
                            res[s] = c
            elif key in ("max_total", "max_acceptance_days"):
                res = self.integer(value, p, 1 if key == "max_acceptance_days" else 0)
            elif key in ("new_only", "fail_on_secrets", "fail_on_expired", "fail_on_sla_breach"):
                res = self.boolean(value, p)
            elif key == "baseline":
                res = self.text(value, p)
                if res is not None and _unsafe_path(res):
                    self.err(p, "e_path_unsafe")
                    res = None
            elif key == "fail_on_cwe":
                lst = self.items([value] if isinstance(value, (str, int)) and not isinstance(value, bool) else value, p)
                if lst is not None:
                    res = []
                    for i, item in enumerate(lst):
                        c = _norm_cwe(item)
                        if c is None:
                            self.err(p + (i,), "e_cwe", value=str(item)[:40])
                        elif c not in res:
                            res.append(c)
            elif key == "fail_on_rules":
                lst = self.text_list(value, p)
                if lst is not None:
                    res = [r for i, r in enumerate(lst) if self.rule_pattern(r, p + (i,)) is not None]
            elif key == "fail_on_owasp":
                lst = self.text_list(value, p)
                if lst is not None:
                    res = []
                    for i, item in enumerate(lst):
                        c = _norm_owasp(item)
                        if c is None:
                            self.err(p + (i,), "e_owasp", value=item[:40])
                        elif c not in res:
                            res.append(c)
            if res is not None:
                out[key] = res
        return out

    def scopes(self, raw, path: tuple) -> list:
        out = []
        names = set()
        for i, item in enumerate(self.items(raw, path) or []):
            p = path + (i,)
            s = self.mapping(item, p)
            if s is None:
                continue
            scope = self.gate({k: v for k, v in s.items() if k in _SCOPE_GATE_KEYS}, p, _SCOPE_GATE_KEYS)
            self.keys(s, p, _SCOPE_KEYS)
            name = self.text(s["name"], p + ("name",)) if "name" in s else self.err(p, "e_required", key="name")
            if name is not None:
                if name in names or name == "default":
                    self.err(p + ("name",), "e_dup_name", name=name[:60])
                names.add(name)
            paths = None
            if "paths" not in s:
                self.err(p, "e_required", key="paths")
            else:
                lst = self.text_list(s["paths"], p + ("paths",))
                if lst is not None:
                    paths = [g for j, g in enumerate(lst) if self.glob(g, p + ("paths", j)) is not None]
                    paths = [_norm_path(g) for g in paths]
                    if not paths:
                        self.err(p + ("paths",), "e_type", expected="t_str_list")
            skip = self.boolean(s["skip"], p + ("skip",)) if "skip" in s else False
            reason = self.text(s["reason"], p + ("reason",)) if "reason" in s else None
            if skip and "reason" not in s:
                self.err(p, "e_required", key="reason")
            if name and paths:
                scope.update({"name": name, "paths": paths})
                if skip:
                    scope["skip"] = True
                if reason:
                    scope["reason"] = reason
                out.append(scope)
        return out

    def rules(self, raw, path: tuple) -> dict:
        out: dict = {}
        r = self.mapping(raw, path)
        if r is None:
            return out
        self.keys(r, path, ("disable", "enable", "severity"))
        for key in ("disable", "severity"):
            if key not in r:
                continue
            entries, seen = [], set()
            for i, item in enumerate(self.items(r[key], path + (key,)) or []):
                p = path + (key, i)
                e = self.mapping(item, p)
                if e is None:
                    continue
                self.keys(e, p, ("id", "reason") + (("severity",) if key == "severity" else ()))
                entry = {}
                for k in ("id", "severity", "reason") if key == "severity" else ("id", "reason"):
                    if k not in e:
                        self.err(p, "e_required", key=k)
                    elif k == "id":
                        entry[k] = self.rule_pattern(e[k], p + (k,))
                    elif k == "severity":
                        entry[k] = self.severity(e[k], p + (k,))
                    else:
                        entry[k] = self.text(e[k], p + (k,))
                if entry.get("id") is not None and entry["id"] in seen:
                    self.err(p + ("id",), "e_dup_name", name=entry["id"][:60])
                seen.add(entry.get("id"))
                if len(entry) == (3 if key == "severity" else 2) and None not in entry.values():
                    entries.append(entry)
            out[key] = entries
        if "enable" in r:
            lst = self.text_list(r["enable"], path + ("enable",))
            if lst is not None:
                out["enable"] = [x for i, x in enumerate(lst) if self.rule_pattern(x, path + ("enable", i)) is not None]
                for i, name in enumerate(out["enable"]):
                    if any(d["id"] == name for d in out.get("disable", [])):
                        self.err(path + ("enable", i), "e_enable_conflict", name=name[:60])
        return out

    def ignores(self, raw, path: tuple) -> list:
        out = []
        for i, item in enumerate(self.items(raw, path) or []):
            p = path + (i,)
            e = self.mapping(item, p)
            if e is None:
                continue
            self.keys(e, p, _IGNORE_KEYS)
            entry: dict = {}
            ok = True
            if "rule" in e:
                entry["rule"] = self.rule_pattern(e["rule"], p + ("rule",))
            if "path" in e:
                entry["path"] = self.glob(e["path"], p + ("path",))
            if "cwe" in e:
                entry["cwe"] = _norm_cwe(e["cwe"])
                if entry["cwe"] is None:
                    self.err(p + ("cwe",), "e_cwe", value=str(e["cwe"])[:40])
                    ok = False
            if "fingerprint" in e:
                fp = str(e["fingerprint"]).strip().lower() if isinstance(e["fingerprint"], (str, int)) else ""
                if not re.fullmatch(r"[0-9a-f]{8,64}(?::\d{1,6})?", fp):
                    self.err(p + ("fingerprint",), "e_fingerprint")
                    ok = False
                entry["fingerprint"] = fp
            if not any(k in e for k in ("rule", "path", "cwe", "fingerprint")):
                self.err(p, "e_selector")
                ok = False
            for k in ("reason", "approver", "expires"):
                if k not in e:
                    self.err(p, "e_required", key=k)
                    ok = False
                elif k == "expires":
                    d = _parse_date(e[k]) if isinstance(e[k], str) and _DATE.match(e[k].strip()) else None
                    if d is None:
                        self.err(p + (k,), "e_date", value=str(e[k])[:40])
                        ok = False
                    else:
                        entry[k] = d.isoformat()
                else:
                    entry[k] = self.text(e[k], p + (k,))
            if "ticket" in e:
                entry["ticket"] = self.text(e["ticket"], p + ("ticket",))
            if ok and None not in entry.values():
                out.append(entry)
        return out

    def reports(self, raw, path: tuple) -> list:
        out = []
        for i, item in enumerate(self.items(raw, path) or []):
            p = path + (i,)
            e = self.mapping(item, p)
            if e is None:
                continue
            self.keys(e, p, ("format", "path"))
            fmt = target = None
            if "format" not in e:
                self.err(p, "e_required", key="format")
            elif isinstance(e["format"], str) and _IDENT.match(e["format"].strip().lower()):
                fmt = e["format"].strip().lower()
                if fmt not in REPORT_FORMATS:
                    self.warnings.append(("w_report_format", {"value": fmt, "allowed": ", ".join(REPORT_FORMATS)}))
            else:
                self.err(p + ("format",), "e_identifier", value=str(e["format"])[:40])
            if "path" not in e:
                self.err(p, "e_required", key="path")
            else:
                target = self.text(e["path"], p + ("path",))
                if target is not None:
                    t = target.replace("\\", "/")
                    parts = t.split("/")
                    if t.startswith(("/", "~")) or any(
                            seg in ("", ".", "..") or re.search(r'[<>:"|?*]', seg) or seg.endswith((".", " "))
                            or seg.split(".")[0].strip().upper() in _WIN_DEVICES for seg in parts):
                        self.err(p + ("path",), "e_report_path")
                        target = None
                    else:
                        target = t
            if fmt and target:
                out.append({"format": fmt, "path": target})
        return out

    def policy(self, raw) -> dict:
        out: dict = {}
        if not isinstance(raw, dict):
            self.err((), "e_top_mapping")
            return out
        self.keys(raw, (), _TOP_KEYS)
        if "version" in raw and (raw["version"] != 1 or isinstance(raw["version"], bool)):
            self.err(("version",), "e_version", value=str(raw["version"])[:20])
        for key in ("name", "description"):
            if key in raw:
                s = self.text(raw[key], (key,))
                if s is not None:
                    out[key] = s
        if "extends" in raw and raw["extends"] is not None:
            lst = self.text_list(raw["extends"], ("extends",))
            if lst is not None:
                out["extends"] = lst
        if "locked" in raw:
            lst = self.text_list(raw["locked"], ("locked",))
            if lst is not None:
                out["locked"] = lst
                for i, name in enumerate(lst):
                    if not _lockable(name):                  # a typo would silently lock nothing
                        self.err(("locked", i), "e_locked_unknown", key=name[:60])
        if "gate" in raw:
            out["gate"] = self.gate(raw["gate"], ("gate",), _GATE_KEYS)
        if "scopes" in raw:
            out["scopes"] = self.scopes(raw["scopes"], ("scopes",))
        if "rules" in raw:
            out["rules"] = self.rules(raw["rules"], ("rules",))
        if "ignores" in raw:
            out["ignores"] = self.ignores(raw["ignores"], ("ignores",))
        if "required_scanners" in raw:
            lst = self.text_list(raw["required_scanners"], ("required_scanners",))
            if lst is not None:
                out["required_scanners"] = []
                for i, name in enumerate(lst):
                    if _IDENT.match(name.lower()):
                        out["required_scanners"].append(name.lower())
                    else:
                        self.err(("required_scanners", i), "e_identifier", value=name[:40])
        if "sla" in raw:
            m = self.mapping(raw["sla"], ("sla",))
            if m is not None:
                out["sla"] = {}
                for sev, days in m.items():
                    s = self.severity(sev, ("sla", sev))
                    d = self.integer(days, ("sla", sev), 1)
                    if s is not None and d is not None:
                        out["sla"][s] = d
        if "reports" in raw:
            out["reports"] = self.reports(raw["reports"], ("reports",))
        return out


# --------------------------------------------------------------------------------------------------------------
# Inheritance
# --------------------------------------------------------------------------------------------------------------
def _union(a: list, b: list) -> list:
    return list(a) + [x for x in b if x not in a]


def _merge(parent: dict, child: dict) -> dict:
    """Effective policy of ``child`` on top of ``parent`` (see "Semantics worth knowing" in the module docstring)."""
    out = copy.deepcopy(parent)
    for key, value in child.items():
        value = copy.deepcopy(value)
        if key == "extends":
            continue
        if key == "gate":
            gate = out.setdefault("gate", {})
            for gk, gv in value.items():
                if gk == "max":
                    gate.setdefault("max", {}).update(gv)
                elif gk in _GATE_LISTS:
                    gate[gk] = _union(gate.get(gk, []), gv)
                else:
                    gate[gk] = gv
        elif key == "scopes":
            names = {s["name"] for s in value}
            out[key] = value + [s for s in out.get(key, []) if s["name"] not in names]
        elif key == "rules":
            rules = out.setdefault("rules", {})
            c_dis = {d["id"] for d in value.get("disable", [])}
            c_en = value.get("enable", [])
            rules["disable"] = [d for d in rules.get("disable", []) if d["id"] not in c_dis and d["id"] not in c_en] \
                + value.get("disable", [])
            rules["enable"] = _union([e for e in rules.get("enable", []) if e not in c_dis], c_en)
            c_sev = {s["id"] for s in value.get("severity", [])}
            rules["severity"] = [s for s in rules.get("severity", []) if s["id"] not in c_sev] + value.get("severity", [])
        elif key == "ignores":
            out[key] = out.get(key, []) + value
        elif key in ("required_scanners", "locked"):
            out[key] = _union(out.get(key, []), value)
        elif key == "sla":
            out.setdefault("sla", {}).update(value)
        elif key == "reports":
            paths = {r["path"] for r in value}
            out[key] = [r for r in out.get(key, []) if r["path"] not in paths] + value
        else:
            out[key] = value
    return out


_MISSING = object()


def _dig(data: dict, dotted: str):
    cur = data
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return _MISSING
        cur = cur[part]
    return cur


def _read_file(path: pathlib.Path, source: str) -> str:
    try:
        if not path.is_file():
            _fail(source, 0, 0, "e_not_file")
        size = path.stat().st_size
        if size > MAX_BYTES:
            _fail(source, 0, 0, "e_too_big", size=size, limit=MAX_BYTES)
        data = path.read_bytes()
    except OSError as e:
        _fail(source, 0, 0, "e_read", err=type(e).__name__)
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        _fail(source, 0, 0, "e_encoding")
    raise AssertionError  # pragma: no cover


def _parse(text: str, fmt: str, source: str) -> tuple[object, dict]:
    marks: dict = {}
    if fmt == "json":
        return _parse_json(text, source), marks
    return parse_yaml(text, source, marks), marks


def _extends_root(directory) -> pathlib.Path:
    """Directory that file ``extends`` may not leave: the enclosing repository (nearest ancestor with ``.git``)
    or, without one, ``directory`` itself."""
    try:
        d = pathlib.Path(directory).resolve()
    except (OSError, RuntimeError):
        d = pathlib.Path(directory).absolute()
    for cand in (d, *d.parents):
        try:
            if (cand / ".git").exists():
                return cand
        except OSError:
            break
    return d


def _lock_conflict(layer: dict, parent: dict, locked: str) -> tuple | None:
    """Path of the setting in ``layer`` that changes the key ``locked`` by ``parent``, or None.

    Besides the key itself this catches a scope that overrides a locked gate key (``gate.fail_on`` locked, then
    ``scopes: [{paths: ["**"], fail_on: never}]``), which would otherwise defeat the lock."""
    mine = _dig(layer, locked)
    if mine is not _MISSING and mine != _dig(parent, locked):
        return tuple(locked.split("."))
    parts = locked.split(".")
    if parts[0] == "gate":
        pgate = parent.get("gate", {})
        keys = [parts[1]] if len(parts) > 1 else list(_SCOPE_GATE_KEYS)
        for i, scope in enumerate(layer.get("scopes", [])):
            for k in keys:
                if k not in scope:
                    continue
                theirs = pgate.get(k, _GATE_DEFAULTS.get(k))
                value = scope[k]
                if len(parts) == 3:
                    value, theirs = value.get(parts[2], _MISSING), (theirs or {}).get(parts[2], _MISSING)
                if value != theirs:
                    return ("scopes", i, k)
    return None


def _layer(raw, marks: dict, source: str, base_dir: pathlib.Path | None, stack: tuple, warnings: list,
           root: pathlib.Path | None = None, allow_outside: bool = False) -> tuple[dict, list]:
    """Validate one file and resolve its ``extends`` chain. Returns (effective mapping, sources, nearest first)."""
    v = _Validator(source, marks)
    layer = v.policy(raw)
    if v.problems:
        raise PolicyError(v.problems)
    warnings.extend(v.warnings)
    effective: dict = {}
    sources = [source]
    for i, ref in enumerate(layer.get("extends", [])):
        name = ref[8:] if ref.startswith("builtin:") else ref
        if len(stack) + 1 > MAX_EXTENDS_DEPTH:
            raise PolicyError([Problem(source, v.line(("extends",)), 0, "extends", "e_extends_depth",
                                       {"limit": MAX_EXTENDS_DEPTH})])
        if name in PRESETS:
            ident = f"builtin:{name}"
            parent, parent_sources = _layer(copy.deepcopy(PRESETS[name]), {}, ident, None, stack + (ident,), warnings,
                                            root, allow_outside)
        else:
            lower = name.lower()
            if ref.startswith("builtin:") or "://" in name or not lower.endswith((".yml", ".yaml", ".json")):
                raise PolicyError([Problem(source, v.line(("extends", i)), 0, "extends", "e_extends_unknown",
                                           {"name": name[:80], "presets": ", ".join(sorted(PRESETS))})])
            if _unsafe_path(name):
                raise PolicyError([Problem(source, v.line(("extends", i)), 0, "extends", "e_path_unsafe", {})])
            p = pathlib.Path(name)
            if not p.is_absolute():
                p = (base_dir or pathlib.Path.cwd()) / p
            try:
                resolved = p.resolve()
            except (OSError, RuntimeError):
                resolved = p.absolute()
            ident = str(resolved)
            if not allow_outside:                            # decided before opening anything: no existence oracle
                limit = root if root is not None else _extends_root(base_dir or pathlib.Path.cwd())
                if resolved != limit and limit not in resolved.parents:
                    raise PolicyError([Problem(source, v.line(("extends", i)), 0, "extends", "e_extends_outside",
                                               {"path": name[:200], "root": str(limit)[:200]})])
            if ident in stack:
                raise PolicyError([Problem(source, v.line(("extends", i)), 0, "extends", "e_extends_cycle",
                                           {"chain": " -> ".join(pathlib.PurePath(s).name for s in stack + (ident,))})])
            if not p.is_file():
                raise PolicyError([Problem(source, v.line(("extends", i)), 0, "extends", "e_extends_missing",
                                           {"path": name[:200]})])
            praw, pmarks = _parse(_read_file(p, str(p)), "json" if lower.endswith(".json") else "yaml", str(p))
            parent, parent_sources = _layer(praw, pmarks, str(p), p.parent, stack + (ident,), warnings,
                                            root, allow_outside)
        for locked in effective.get("locked", []):           # an earlier entry of "extends" locked it
            if _lock_conflict(parent, effective, locked) is not None:
                raise PolicyError([Problem(source, v.line(("extends", i)), 0, "extends", "e_locked",
                                           {"key": locked, "parent": pathlib.PurePath(sources[1]).name})])
        effective = _merge(effective, parent)
        sources.extend(s for s in parent_sources if s not in sources)
        for locked in parent.get("locked", []):
            path = _lock_conflict(layer, parent, locked)
            if path is not None:
                raise PolicyError([Problem(source, v.line(path), 0, _dotted(path), "e_locked",
                                           {"key": locked, "parent": pathlib.PurePath(parent_sources[0]).name})])
    result = _merge(effective, layer)
    for key in ("name", "description"):                      # identity of a file is not inherited
        if key not in layer:
            result.pop(key, None)
    return result, sources


# --------------------------------------------------------------------------------------------------------------
# Policy
# --------------------------------------------------------------------------------------------------------------
_GATE_DEFAULTS = {"fail_on": "high", "max": {}, "max_total": None, "new_only": False, "baseline": None,
                  "fail_on_cwe": [], "fail_on_rules": [], "fail_on_owasp": [], "fail_on_secrets": True,
                  "fail_on_expired": True, "fail_on_sla_breach": False, "max_acceptance_days": None}


@dataclass
class Policy:
    """A validated, effective policy (inheritance already resolved). Build one with :func:`load_policy`,
    :func:`load_policy_text` or :func:`builtin_policy`; the lists hold plain dicts in the documented shape."""
    name: str = "default"
    description: str = ""
    source: str = "<default>"
    chain: list = field(default_factory=list)                 # this file first, then the inherited ones
    gate: dict = field(default_factory=lambda: copy.deepcopy(_GATE_DEFAULTS))
    scopes: list = field(default_factory=list)                # [{"name", "paths", optional gate keys, "skip", "reason"}]
    disabled: list = field(default_factory=list)              # [{"id", "reason"}]
    enabled: list = field(default_factory=list)               # ["PY001", ...]
    severity_overrides: list = field(default_factory=list)    # [{"id", "severity", "reason"}]
    ignores: list = field(default_factory=list)               # [{"rule"?, "path"?, "cwe"?, "fingerprint"?, "reason", ...}]
    required_scanners: list = field(default_factory=list)
    sla: dict = field(default_factory=dict)                   # {"critical": 7, ...}
    reports: list = field(default_factory=list)               # [{"format", "path"}]
    locked: list = field(default_factory=list)
    base_dir: str = ""                                        # directory of the policy file ("" for text / builtin)
    warnings: list = field(default_factory=list)              # [Warning_] found while loading

    def to_dict(self) -> dict:
        """The effective policy as a plain mapping. It is itself a valid policy file (without ``extends``)."""
        gate = {k: copy.deepcopy(v) for k, v in self.gate.items() if v is not None and v != {} and v != []}
        gate["fail_on"] = self.gate["fail_on"] or "never"
        out: dict = {"version": 1, "name": self.name}
        if self.description:
            out["description"] = self.description
        out["gate"] = gate
        if self.scopes:
            out["scopes"] = copy.deepcopy(self.scopes)
            for s in out["scopes"]:
                if "fail_on" in s:
                    s["fail_on"] = s["fail_on"] or "never"
        rules = {k: copy.deepcopy(v) for k, v in (("disable", self.disabled), ("enable", self.enabled),
                                                  ("severity", self.severity_overrides)) if v}
        if rules:
            out["rules"] = rules
        for key in ("ignores", "required_scanners", "sla", "reports", "locked"):
            if getattr(self, key):
                out[key] = copy.deepcopy(getattr(self, key))
        return out

    def condition_count(self) -> int:
        g = self.gate
        return sum(bool(x) for x in (g["fail_on"], g["max"], g["max_total"] is not None, g["fail_on_cwe"],
                                     g["fail_on_rules"], g["fail_on_owasp"], g["fail_on_secrets"], g["fail_on_expired"],
                                     g["fail_on_sla_breach"] and self.sla, self.required_scanners))


def _finish(effective: dict, source: str, chain: list, base_dir: str, warnings: list) -> Policy:
    def never(d: dict) -> dict:
        if d.get("fail_on") == "never":
            d["fail_on"] = None
        return d

    gate = copy.deepcopy(_GATE_DEFAULTS)
    gate.update(never(copy.deepcopy(effective.get("gate", {}))))
    rules = effective.get("rules", {})
    default_name = pathlib.PurePath(source).stem if not source.startswith("<") else "policy"
    seen, uniq = set(), []
    for code, args in warnings:
        key = (code, tuple(sorted(args.items())))
        if key not in seen:
            seen.add(key)
            uniq.append(Warning_(code, args))
    return Policy(
        name=effective.get("name") or default_name, description=effective.get("description", ""), source=source,
        chain=chain, gate=gate, scopes=[never(copy.deepcopy(s)) for s in effective.get("scopes", [])],
        disabled=copy.deepcopy(rules.get("disable", [])), enabled=list(rules.get("enable", [])),
        severity_overrides=copy.deepcopy(rules.get("severity", [])), ignores=copy.deepcopy(effective.get("ignores", [])),
        required_scanners=list(effective.get("required_scanners", [])), sla=dict(effective.get("sla", {})),
        reports=copy.deepcopy(effective.get("reports", [])), locked=list(effective.get("locked", [])),
        base_dir=base_dir, warnings=uniq)


def load_policy_text(text: str, fmt: str = "yaml", source: str = "<policy>", base_dir=None, *,
                     allow_outside: bool = False) -> Policy:
    """Parse and validate policy text (``fmt``: ``"yaml"`` or ``"json"``). ``base_dir`` resolves relative
    ``extends`` paths (default: the current directory). ``allow_outside``: see :func:`load_policy`.
    Raises :class:`PolicyError`."""
    raw, marks = _parse(text, "json" if str(fmt).lower() == "json" else "yaml", source)
    warnings: list = []
    base = pathlib.Path(base_dir) if base_dir else None
    effective, chain = _layer(raw, marks, source, base, (source,), warnings,
                              _extends_root(base or pathlib.Path.cwd()), allow_outside)
    return _finish(effective, source, chain, str(base) if base else "", warnings)


def load_policy(path, *, allow_outside: bool = False) -> Policy:
    """Load ``kashif.yml`` / ``kashif.json`` (or a builtin preset name such as ``"strict"``), resolve ``extends`` and
    validate everything. Raises :class:`PolicyError` whose ``problems`` carry file, line, dotted key and a message
    available in English and Arabic (``error.format("ar")``).

    A policy usually comes from the repository being scanned, so by default ``extends`` may only name files inside
    the policy's own repository (nearest ancestor directory with ``.git``; else the policy file's directory),
    symbolic links resolved. ``allow_outside=True`` lifts that for a policy you trust (an organisation baseline
    kept elsewhere on disk). Network (UNC) paths and URLs are refused either way."""
    name = str(path)
    preset = name[8:] if name.startswith("builtin:") else name
    if preset in PRESETS and (name.startswith("builtin:") or not pathlib.Path(name).exists()):
        return builtin_policy(preset)
    p = pathlib.Path(path)
    lower = p.name.lower()
    if not lower.endswith((".yml", ".yaml", ".json")):
        _fail(name, 0, 0, "e_ext")
    text = _read_file(p, name)
    raw, marks = _parse(text, "json" if lower.endswith(".json") else "yaml", name)
    try:
        ident = str(p.resolve())
    except (OSError, RuntimeError):
        ident = name
    warnings: list = []
    effective, chain = _layer(raw, marks, name, p.parent, (ident,), warnings, _extends_root(p.parent), allow_outside)
    return _finish(effective, name, chain, str(p.parent), warnings)


def builtin_policy(name: str) -> Policy:
    """One of the builtin presets (``sorted(PRESETS)``) as a :class:`Policy`. Raises ``KeyError`` for another name."""
    ident = f"builtin:{name}"
    warnings: list = []
    effective, chain = _layer(copy.deepcopy(PRESETS[name]), {}, ident, None, (ident,), warnings)
    return _finish(effective, ident, chain, "", warnings)


def find_policy(directory=".") -> str | None:
    """Path of the policy file in ``directory`` (a file argument means its directory), or None."""
    d = pathlib.Path(directory)
    if d.is_file():
        d = d.parent
    for name in POLICY_FILENAMES:
        if (d / name).is_file():
            return str(d / name)
    return None


# --------------------------------------------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------------------------------------------
@dataclass
class Context:
    """Facts about the scan that the findings alone do not carry. Every field is optional.

    ``today``       evaluation date (default: today); a ``date`` or ``YYYY-MM-DD``.
    ``baseline``    fingerprints that already existed (set / list), for ``new_only``.
    ``changed``     files touched by the change: a list of paths, or ``{path: lines or None}``, for ``new_only``.
    ``scanners``    names of the scanners that ran (authoritative for ``required_scanners``).
    ``first_seen``  ``{fingerprint: date}`` for SLA ages.
    ``meta``        metadata of a JSON report (``notes``, ``scanners``, ``files_scanned`` ...), used to infer scanners.
    ``base_dir``    directory against which ``gate.baseline`` is resolved (default: the policy file's directory)."""
    today: object = None
    baseline: object = None
    changed: object = None
    scanners: object = None
    first_seen: dict | None = None
    meta: dict | None = None
    base_dir: object = None


@dataclass
class Warning_:
    """A non-blocking remark of the gate. ``message(lang)`` renders it."""
    code: str
    args: dict = field(default_factory=dict)

    def message(self, lang: str = "en") -> str:
        args = dict(self.args)
        if "severity" in args:
            args["severity"] = _t(lang, f"sev_{args['severity']}")
        return _t(lang, f"w_{self.code}" if not self.code.startswith("w_") else self.code, **args)

    def to_dict(self) -> dict:
        return {"code": self.code[2:] if self.code.startswith("w_") else self.code, "args": dict(self.args),
                "message_en": self.message("en"), "message_ar": self.message("ar")}


@dataclass
class Violation:
    """One failed gate condition. ``code`` is stable (``severity-threshold``, ``max-count``, ``max-total``,
    ``forbidden-cwe``, ``forbidden-rule``, ``forbidden-owasp``, ``secret``, ``expired-ignore``,
    ``expired-acceptance``, ``acceptance-too-long``, ``required-scanner``, ``sla-breach``, ``warnings-as-errors``)."""
    code: str
    scope: str = ""                    # "" = whole scan, "default" = findings outside every named scope
    args: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)       # brief dicts: rule_id, severity, file, line, fingerprint, title

    def message(self, lang: str = "en") -> str:
        args = dict(self.args)
        args["scope"] = _t(lang, "x_scope_default") if self.scope in ("", "default") else self.scope
        for key in ("severity", "threshold"):
            if key in args:
                args[key] = _t(lang, f"sev_{args[key]}")
        return _t(lang, f"v_{self.code}", **args)

    def to_dict(self) -> dict:
        return {"code": self.code, "scope": self.scope, "args": dict(self.args), "count": len(self.findings),
                "message_en": self.message("en"), "message_ar": self.message("ar"), "findings": list(self.findings)}


@dataclass
class Decision:
    """Result of :func:`evaluate`: ``passed``, ``exit_code`` (0 or 1), ``violations``, ``warnings`` and ``stats``."""
    passed: bool
    exit_code: int
    violations: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    policy_name: str = ""
    policy_source: str = ""
    evaluated_on: str = ""

    def to_dict(self) -> dict:
        return {"passed": self.passed, "exit_code": self.exit_code, "policy": self.policy_name,
                "policy_source": self.policy_source, "evaluated_on": self.evaluated_on, "stats": copy.deepcopy(self.stats),
                "violations": [v.to_dict() for v in self.violations], "warnings": [w.to_dict() for w in self.warnings]}


_OWASP_FALLBACK = {
    # subset of the "List of Mapped CWEs" of each OWASP Top 10 2021 category (checked against the OWASP/Top10 sources)
    "A01": {22, 23, 35, 200, 201, 284, 285, 352, 425, 601, 639, 862, 863},
    "A02": {259, 261, 319, 321, 326, 327, 328, 330, 331, 338, 916},
    "A03": {20, 74, 77, 78, 79, 88, 89, 90, 91, 94, 95, 643, 917}, "A04": {209, 256, 434, 501, 522},
    "A05": {16, 611, 614, 1004}, "A06": {937, 1035, 1104}, "A07": {259, 287, 290, 295, 306, 307, 384, 521, 798},
    "A08": {345, 494, 502, 829}, "A09": {117, 532, 778}, "A10": {918},
}


class _Owasp:
    def __init__(self):
        self.cache: dict = {}
        self.fallback = False
        try:
            from . import compliance
            self.map = compliance.map_finding
        except Exception:                                    # noqa: BLE001 - any import problem means "fallback"
            self.map = None
            self.fallback = True

    def categories(self, item: dict) -> frozenset:
        key = (item["rule_id"], item["cwe"])
        if key not in self.cache:
            cats: set = set()
            if self.map is not None:
                try:
                    res = self.map({"rule_id": item["rule_id"], "cwe": item["cwe_text"], "source": item["source"]},
                                   ["owasp-top10-2021", "owasp-api-2023"])
                    for controls in res.values():
                        cats.update(c for c in (_norm_owasp(x) for x in controls) if c)
                except Exception:                            # noqa: BLE001
                    self.map, self.fallback = None, True
            if self.map is None:
                cats = {cat for cat, cwes in _OWASP_FALLBACK.items() if cwes & item["cwe"]}
            self.cache[key] = frozenset(cats)
        return self.cache[key]


def _item(f) -> dict:
    """Normalize a ``Finding`` or its dict form to what the evaluator needs."""
    d = f.to_dict() if hasattr(f, "to_dict") else f
    if not isinstance(d, dict):
        raise TypeError(f"finding must be a Finding or a dict, got {type(f).__name__}")
    extra = d.get("extra") if isinstance(d.get("extra"), dict) else {}
    rule = str(d.get("rule_id") or "")
    file = _norm_path(d.get("file"))
    cwe_text = str(d.get("cwe") or "")
    cwes = frozenset(int(x) for x in re.findall(r"(?i)cwe[-_ ]?(\d{1,5})", cwe_text))
    if not cwes and cwe_text.strip().isdigit():
        cwes = frozenset({int(cwe_text)})
    fp = str(d.get("fingerprint") or "")
    if not fp:
        norm = re.sub(r"\s+", "", str(d.get("snippet") or "")).lower()
        fp = hashlib.sha256(f"{rule}\x00{file}\x00{norm}".encode("utf-8", "replace")).hexdigest()[:16] + ":0"
    try:
        line = int(d.get("line") or 0)
    except (TypeError, ValueError, OverflowError):           # OverflowError: a JSON report can hold 1e999
        line = 0
    source = str(d.get("source") or "")
    triage = extra.get("triage") if isinstance(extra.get("triage"), dict) else {}
    return {"rule_id": rule, "severity": str(d.get("severity") or "").lower(), "file": file, "line": line, "cwe": cwes,
            "cwe_text": cwe_text, "fingerprint": fp, "source": source, "title": str(d.get("title") or ""),
            "new_flag": extra.get("new") if "new" in extra else None, "triage": triage,
            "first_seen": triage.get("first_seen") or extra.get("first_seen") or d.get("first_seen"),
            "secret": bool(re.match(r"SEC\d", rule) or source == "gitleaks" or cwes & _SECRET_CWES)}


def _brief(item: dict) -> dict:
    return {"rule_id": item["rule_id"], "severity": item["severity"], "file": item["file"], "line": item["line"],
            "fingerprint": item["fingerprint"], "title": item["title"], "cwe": item["cwe_text"]}


def _rule_match(pattern: str, rule_id: str) -> bool:
    return pattern == rule_id or fnmatch.fnmatchcase(rule_id, pattern)


def _ignore_matches(ig: dict, item: dict) -> bool:
    if "rule" in ig and not _rule_match(ig["rule"], item["rule_id"]):
        return False
    if "path" in ig and not path_matches(ig["path"], item["file"]):
        return False
    if "cwe" in ig and ig["cwe"] not in item["cwe"]:
        return False
    if "fingerprint" in ig:
        want, fp = ig["fingerprint"], item["fingerprint"].lower()
        if not (fp == want or (":" not in want and fp.split(":")[0].startswith(want))):
            return False
    return True


def _selector(ig: dict) -> str:
    parts = []
    for key in ("rule", "path", "cwe", "fingerprint"):
        if key in ig:
            parts.append(f"{key}={'CWE-' + str(ig[key]) if key == 'cwe' else ig[key]}")
    return ", ".join(parts)


def _context(context) -> Context:
    if context is None:
        return Context()
    if isinstance(context, Context):
        return context
    if isinstance(context, dict):
        known = {k: v for k, v in context.items() if k in Context.__dataclass_fields__}
        if "changed_files" in context and "changed" not in known:
            known["changed"] = context["changed_files"]
        return Context(**known)
    raise TypeError("context must be a Context, a dict or None")


def _load_baseline_file(path: pathlib.Path) -> set | None:
    from .baseline import read_baseline_text
    try:
        # gate.baseline comes from the repository's kashif.yml: regular files only (not /dev/zero, a FIFO, ...)
        text = read_baseline_text(path)
        if text is None:
            return None
        data = json.loads(text)
    except (OSError, ValueError, RecursionError):
        return None
    if isinstance(data, dict) and isinstance(data.get("fingerprints"), list):
        return {str(e.get("fp")) for e in data["fingerprints"] if isinstance(e, dict) and e.get("fp")}
    if isinstance(data, list) and all(isinstance(x, str) for x in data):
        return set(data)
    return None


def _scanners_from(meta: dict | None, items: list) -> set | None:
    """Scanners that provably ran, inferred from a report. None when nothing is known about the scan."""
    meta = meta or {}
    if isinstance(meta.get("scanners"), (list, tuple, set)):
        return {str(s).lower() for s in meta["scanners"]}
    found: set = set()
    target = str(meta.get("target") or "")
    if "files_scanned" in meta and not re.match(r"https?://", target):
        found.update(("sast", "secrets"))                    # a Kashif source scan always runs rules + secret rules
    for note in list(meta.get("notes") or []) + list(meta.get("notes_en") or []):
        if isinstance(note, str) and re.search(r"OSV\.dev[^:]*:\s*\d+", note):
            found.add("deps")
    for it in items:
        if it["source"] == "osv":
            found.add("deps")
        elif it["source"] in ("bandit", "semgrep", "gitleaks", "npm"):
            found.add("external")
        elif it["source"] in ("vulnscan", "taint", "vql", "web", "apex"):
            found.add("sast")
        if re.match(r"SEC\d", it["rule_id"]):
            found.add("secrets")
    return found if (found or meta) else None


def evaluate(findings, policy: Policy, context=None, *, warnings_as_errors: bool = False) -> Decision:
    """Evaluate findings against a policy and return a :class:`Decision`.

    ``findings`` holds ``Finding`` objects or their ``to_dict()`` form (a JSON report / saved scan); they are not
    modified. ``context`` is a :class:`Context` (or a dict with the same keys). The decision passes when no
    condition is violated; warnings never fail it unless ``warnings_as_errors`` is set."""
    ctx = _context(context)
    today = _parse_date(ctx.today) if ctx.today is not None else _dt.date.today()
    if today is None:
        raise ValueError("context.today must be a date or YYYY-MM-DD")
    gate = policy.gate
    items = [_item(f) for f in findings]
    violations: list[Violation] = []
    warnings: list[Warning_] = list(policy.warnings)
    stats = {"total": len(items), "evaluated": 0, "disabled": 0, "ignored": 0, "triaged": 0, "skipped": 0, "not_new": 0,
             "by_severity": {s: 0 for s in SEVERITIES}, "scopes": {}}

    # 1. rules: disabled, severity overrides (a child policy's entry is later in the list and wins)
    active = []
    unknown = 0
    for it in items:
        rid = it["rule_id"]
        if any(_rule_match(d["id"], rid) for d in policy.disabled) and not any(_rule_match(e, rid) for e in policy.enabled):
            stats["disabled"] += 1
            continue
        for ov in reversed(policy.severity_overrides):
            if _rule_match(ov["id"], rid):
                it["severity"] = ov["severity"]
                break
        if it["severity"] not in _RANK:
            unknown += 1
            it["severity"] = "medium"
        active.append(it)
    if unknown:
        warnings.append(Warning_("unknown-severity", {"count": unknown}))

    # 2. triage decisions carried by the findings (vulnscan.triage.apply)
    expired_acceptances = []
    kept = []
    for it in active:
        tri = it["triage"]
        status = str(tri.get("status") or "")
        if tri.get("expired"):
            expired_acceptances.append(it)
        elif status in ("false_positive", "wont_fix", "fixed", "accepted_risk"):
            stats["triaged"] += 1
            continue
        kept.append(it)
    active = kept

    # 3. ignores: valid ones suppress, expired ones do not (and fail the gate)
    expired_count = len(expired_acceptances)
    suppressed: set[int] = set()
    for index, ig in enumerate(policy.ignores, 1):
        expires = _parse_date(ig["expires"])
        selector = _selector(ig)
        matched = [it for it in active if _ignore_matches(ig, it)]
        days_left = (expires - today).days
        if days_left < 0:
            if matched:
                expired_count += 1
                if gate["fail_on_expired"]:
                    violations.append(Violation("expired-ignore", "", {
                        "index": index, "selector": selector, "approver": ig["approver"], "date": ig["expires"],
                        "days": -days_left, "count": len(matched)}, [_brief(m) for m in matched]))
            else:
                warnings.append(Warning_("ignore-expired-unused", {"index": index, "selector": selector,
                                                                   "date": ig["expires"]}))
            continue
        if gate["max_acceptance_days"] is not None and days_left > gate["max_acceptance_days"]:
            violations.append(Violation("acceptance-too-long", "", {
                "index": index, "selector": selector, "date": ig["expires"], "days": days_left,
                "max": gate["max_acceptance_days"]}, [_brief(m) for m in matched]))
            continue                                         # an over-long acceptance is not honoured
        if not matched:
            warnings.append(Warning_("ignore-unused", {"index": index, "selector": selector}))
        elif days_left <= EXPIRY_WARN_DAYS:
            warnings.append(Warning_("ignore-expiring", {"index": index, "selector": selector, "date": ig["expires"],
                                                         "days": days_left}))
        suppressed.update(id(m) for m in matched)
    stats["ignored"] = sum(1 for it in active if id(it) in suppressed)
    active = [it for it in active if id(it) not in suppressed]
    if expired_acceptances and gate["fail_on_expired"]:
        violations.append(Violation("expired-acceptance", "", {"count": len(expired_acceptances)},
                                    [_brief(m) for m in expired_acceptances]))
    if expired_count and not gate["fail_on_expired"]:
        warnings.append(Warning_("expired-not-enforced", {"count": expired_count}))

    # 4. scopes (first match wins)
    groups: dict[str, list] = {"default": []}
    configs: dict[str, dict] = {"default": gate}
    for scope in policy.scopes:
        groups.setdefault(scope["name"], [])
        cfg = dict(gate)
        cfg.update({k: scope[k] for k in _SCOPE_GATE_KEYS if k in scope})
        configs[scope["name"]] = cfg
    in_gate = []
    for it in active:
        name = "default"
        for scope in policy.scopes:
            if any(path_matches(p, it["file"]) for p in scope["paths"]):
                name = scope["name"]
                break
        if name != "default" and next(s for s in policy.scopes if s["name"] == name).get("skip"):
            stats["skipped"] += 1
            continue
        it["scope"] = name
        groups[name].append(it)
        in_gate.append(it)
        stats["by_severity"][it["severity"]] += 1
    stats["evaluated"] = len(in_gate)

    # 5. what is "new"
    wants_new = any(cfg["new_only"] for cfg in configs.values())
    baseline = set(ctx.baseline) if ctx.baseline is not None and not isinstance(ctx.baseline, (str, os.PathLike)) else None
    baseline_path = ctx.baseline if isinstance(ctx.baseline, (str, os.PathLike)) else gate["baseline"]
    if wants_new and baseline is None and baseline_path:
        p = pathlib.Path(str(baseline_path))
        if not p.is_absolute():
            p = pathlib.Path(str(ctx.base_dir or policy.base_dir or ".")) / p
        baseline = _load_baseline_file(p)
        if baseline is None:
            warnings.append(Warning_("baseline-unreadable", {"path": str(baseline_path)}))
    changed = None
    if ctx.changed is not None:
        src = [ctx.changed] if isinstance(ctx.changed, (str, os.PathLike)) else ctx.changed
        changed = {_norm_path(k): (None if v is None else {x for x in v if isinstance(x, int)}) for k, v in src.items()} \
            if isinstance(src, dict) else {_norm_path(k): None for k in src}
    flags = any(it["new_flag"] is not None for it in in_gate)
    has_reference = baseline is not None or changed is not None or flags
    if wants_new and not has_reference and not any(w.code == "baseline-unreadable" for w in warnings):
        warnings.append(Warning_("new-only-no-reference"))
    for it in in_gate:
        new = True
        if baseline is not None and it["fingerprint"] in baseline:
            new = False
        if changed is not None:
            lines = changed.get(it["file"], _MISSING)
            if lines is _MISSING or (lines is not None and it["line"] and it["line"] not in lines):
                new = False
        if baseline is None and changed is None and flags:
            new = bool(it["new_flag"])
        it["new"] = new

    # 6. conditions, per scope
    owasp = _Owasp()
    for name, group in groups.items():
        cfg = configs[name]
        cand = [it for it in group if it["new"]] if cfg["new_only"] else group
        if cfg["new_only"]:
            stats["not_new"] += len(group) - len(cand)
        counts = {s: 0 for s in SEVERITIES}
        for it in cand:
            counts[it["severity"]] += 1
        stats["scopes"][name] = {"total": len(group), "counted": len(cand), "by_severity": counts}

        def add(code, hits, _name=name, **args):
            violations.append(Violation(code, _name, {"count": len(hits), **args}, [_brief(h) for h in hits]))

        if cfg["fail_on"]:
            hits = [it for it in cand if _RANK[it["severity"]] <= _RANK[cfg["fail_on"]]]
            if hits:
                add("severity-threshold", hits, threshold=cfg["fail_on"])
        for sev in SEVERITIES:
            if sev in cfg["max"] and counts[sev] > cfg["max"][sev]:
                add("max-count", [it for it in cand if it["severity"] == sev], severity=sev, max=cfg["max"][sev])
        if cfg["max_total"] is not None and len(cand) > cfg["max_total"]:
            add("max-total", cand, max=cfg["max_total"])
        for cwe in cfg["fail_on_cwe"]:
            hits = [it for it in cand if cwe in it["cwe"]]
            if hits:
                add("forbidden-cwe", hits, cwe=cwe)
        for pattern in cfg["fail_on_rules"]:
            hits = [it for it in cand if _rule_match(pattern, it["rule_id"])]
            if hits:
                add("forbidden-rule", hits, rule=pattern)
        for category in cfg["fail_on_owasp"]:
            hits = [it for it in cand if category in owasp.categories(it)]
            if hits:
                add("forbidden-owasp", hits, category=category)
        if cfg["fail_on_secrets"]:
            hits = [it for it in group if it["secret"]]      # "group", not "cand": new_only never hides a secret
            if hits:
                add("secret", hits)
    if owasp.fallback and any(cfg["fail_on_owasp"] for cfg in configs.values()):
        warnings.append(Warning_("owasp-fallback"))

    # 7. required scanners
    if policy.required_scanners:
        ran = {str(s).lower() for s in ctx.scanners} if ctx.scanners is not None else _scanners_from(ctx.meta, items)
        for scanner in policy.required_scanners:
            if ran is None or scanner not in ran:
                violations.append(Violation("required-scanner", "", {"scanner": scanner}))

    # 8. SLA
    if policy.sla:
        first_seen = ctx.first_seen or {}
        undated = 0
        for sev in SEVERITIES:
            if sev not in policy.sla:
                continue
            late = []
            for it in in_gate:
                if it["severity"] != sev:
                    continue
                seen = _parse_date(first_seen.get(it["fingerprint"]) or it["first_seen"])
                if seen is None:
                    undated += 1
                elif (today - seen).days > policy.sla[sev]:
                    late.append(((today - seen).days, it))
            if late:
                args = {"count": len(late), "severity": sev, "days": policy.sla[sev], "oldest": max(a for a, _ in late)}
                if gate["fail_on_sla_breach"]:
                    violations.append(Violation("sla-breach", "", args, [_brief(it) for _, it in late]))
                else:
                    warnings.append(Warning_("sla-breach", args))
        if undated:
            warnings.append(Warning_("sla-no-dates", {"count": undated}))

    if warnings_as_errors and warnings:
        violations.append(Violation("warnings-as-errors", "", {"count": len(warnings)}))
    passed = not violations
    return Decision(passed=passed, exit_code=0 if passed else 1, violations=violations, warnings=warnings, stats=stats,
                    policy_name=policy.name, policy_source=policy.source, evaluated_on=today.isoformat())


# --------------------------------------------------------------------------------------------------------------
# Explain
# --------------------------------------------------------------------------------------------------------------
def _clean(text) -> str:
    """Printable form of a value that came from a report or a policy: control characters (terminal escape
    sequences, line breaks) and bidirectional overrides become U+FFFD so they cannot forge or hide output."""
    return _BAD_TEXT.sub("\ufffd", str(text))


def _md(text) -> str:
    """Markdown-inert text: no formatting, no HTML, no table break and no ``@mention`` notification."""
    text = re.sub(r"([\\`*_{}\[\]<>|#~!])", r"\\\1", _clean(text).replace("&", "&amp;"))
    return text.replace("@", "&#64;")


def _code(text) -> str:
    """Content for a Markdown code span inside a table cell."""
    return _clean(text).replace("`", "'").replace("|", "\\|")


def explain(decision: Decision, fmt: str = "text", lang: str = "en", limit: int = 10) -> str:
    """Render a decision as ``"text"`` (console), ``"markdown"`` (PR comment / step summary) or ``"json"``.
    ``limit`` caps the findings listed per violation in text and markdown (JSON always lists all)."""
    lang = _lang(lang)
    fmt = {"md": "markdown", "txt": "text"}.get(str(fmt).lower(), str(fmt).lower())
    if fmt == "json":
        data = decision.to_dict()
        data["lang"] = lang
        for group in ("violations", "warnings"):
            for entry in data[group]:
                entry["message"] = entry[f"message_{lang}"]
        return json.dumps(data, ensure_ascii=False, indent=2)
    if fmt not in ("text", "markdown"):
        raise ValueError(f"unknown format {fmt!r}; use text, markdown or json")
    verdict = _t(lang, "x_passed" if decision.passed else "x_failed")
    s = decision.stats
    summary = _t(lang, "x_summary", **{k: s.get(k, 0) for k in ("evaluated", "total", "ignored", "disabled", "triaged",
                                                                "skipped")})
    out: list[str] = []
    if fmt == "markdown":
        out.append(f"## {_t(lang, 'x_title')}: {verdict}")
        out.append("")
        out.append(f"**{_t(lang, 'x_policy')}:** {_md(decision.policy_name)} (`{_code(decision.policy_source)}`)  ")
        out.append(f"**{_t(lang, 'x_date')}:** {decision.evaluated_on}  ")
        out.append(summary)
        out.append("")
        out.append(f"### {_t(lang, 'x_violations')} ({len(decision.violations)})")
        out.append("")
        if not decision.violations:
            out.append(f"_{_t(lang, 'x_none')}_")
        for i, v in enumerate(decision.violations, 1):
            out.append(f"{i}. **{_md(v.message(lang))}** `{v.code}`")
            if v.findings:
                out.append("")
                out.append(f"   | {_t(lang, 'x_col_rule')} | {_t(lang, 'x_col_sev')} | {_t(lang, 'x_col_loc')} | "
                           f"{_t(lang, 'x_col_fp')} |")
                out.append("   |---|---|---|---|")
                for f in v.findings[:limit]:
                    out.append(f"   | {_md(f['rule_id'])} | {_t(lang, 'sev_' + f['severity'])} | "
                               f"{_md(f['file'])}:{f['line']} | `{_code(f['fingerprint'])}` |")
                if len(v.findings) > limit:
                    out.append(f"   | {_t(lang, 'x_more', count=len(v.findings) - limit)} | | | |")
                out.append("")
        out.append("")
        out.append(f"### {_t(lang, 'x_warnings')} ({len(decision.warnings)})")
        out.append("")
        if not decision.warnings:
            out.append(f"_{_t(lang, 'x_none')}_")
        out.extend(f"- {_md(w.message(lang))}" for w in decision.warnings)
        out.append("")
        out.append(f"{_t(lang, 'x_exit')}: `{decision.exit_code}`")
        return "\n".join(out) + "\n"
    out.append(f"{_t(lang, 'x_title')}: {verdict}")
    out.append(f"{_t(lang, 'x_policy')}: {decision.policy_name} ({decision.policy_source})")
    out.append(f"{_t(lang, 'x_date')}: {decision.evaluated_on}")
    out.append(summary)
    out.append(f"{_t(lang, 'x_violations')} ({len(decision.violations)}):" + ("" if decision.violations
                                                                               else f" {_t(lang, 'x_none')}"))
    for i, v in enumerate(decision.violations, 1):
        out.append(f"  {i}. [{v.code}] {v.message(lang)}")
        for f in v.findings[:limit]:
            out.append(f"       - {f['rule_id']} {_t(lang, 'sev_' + f['severity'])} {f['file']}:{f['line']} "
                       f"({f['fingerprint']})")
        if len(v.findings) > limit:
            out.append(f"       {_t(lang, 'x_more', count=len(v.findings) - limit)}")
    out.append(f"{_t(lang, 'x_warnings')} ({len(decision.warnings)}):" + ("" if decision.warnings
                                                                           else f" {_t(lang, 'x_none')}"))
    out.extend(f"  - {w.message(lang)}" for w in decision.warnings)
    out.append(f"{_t(lang, 'x_exit')}: {decision.exit_code}")
    return "\n".join(_clean(line) for line in out) + "\n"


# --------------------------------------------------------------------------------------------------------------
# Template
# --------------------------------------------------------------------------------------------------------------
_TEMPLATE = """\
# Kashif security policy (policy as code)          سياسة الأمان في كاشِف
# Check a report:   python3 -m vulnscan.policy check report.json --policy kashif.yml
# Validate:         python3 -m vulnscan.policy validate kashif.yml --show
# {preset}: {summary}
version: 1
name: {name}
extends: {preset}

# Uncomment and adapt. Values set here override the preset.
# gate:
#   fail_on: high                  # critical | high | medium | low | info | never
#   max:
#     medium: 20                   # at most 20 medium findings
#   max_total: 200
#   new_only: true                 # only findings that are new against the baseline / diff count
#   baseline: .kashif-baseline.json
#   fail_on_cwe: [CWE-89, CWE-78]
#   fail_on_rules: ["SEC*"]
#   fail_on_owasp: [A03]
#   fail_on_secrets: true
#   fail_on_expired: true
#   fail_on_sla_breach: false
#   max_acceptance_days: 180

# scopes:                          # first matching scope wins; unset keys fall back to "gate"
#   - name: tests
#     paths: ["tests/**"]
#     fail_on: never
#     fail_on_cwe: []
#     fail_on_secrets: false
#   - name: third-party
#     paths: ["third_party/**", "vendor/**"]
#     skip: true
#     reason: "vendored code, covered by the dependency scanner"

# rules:
#   disable:
#     - id: WEB020
#       reason: "cookies are set by the gateway"
#   severity:
#     - id: SEC004
#       severity: critical
#       reason: "hard-coded credentials block a release here"

# ignores:                         # every exception needs a reason, an approver and an expiry date
#   - rule: PY014
#     path: "src/legacy/**"
#     reason: "validated upstream, tracked in the linked ticket"
#     approver: "security-lead"
#     expires: {expires}

# required_scanners: [deps, secrets]

# sla:                             # days allowed to fix, per severity
#   critical: 7
#   high: 30

# reports:
#   - format: sarif
#     path: kashif.sarif
"""


def init_template(preset: str = "startup", name: str = "my-project", expand: bool = False, today=None) -> str:
    """Text of a starter ``kashif.yml`` that extends ``preset``. With ``expand`` the preset's effective settings are
    written out instead of ``extends`` (a self-contained file)."""
    if preset not in PRESETS:
        raise KeyError(preset)
    if expand:
        data = builtin_policy(preset).to_dict()
        data["name"] = name
        return f"# Kashif security policy, expanded from the builtin preset '{preset}'.\n" + dump_yaml(data)
    day = (_parse_date(today) or _dt.date.today()) + _dt.timedelta(days=90)
    return _TEMPLATE.format(preset=preset, summary=_t("en", f"p_{preset}"), name=_yaml_scalar(name), expires=day.isoformat())


# --------------------------------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------------------------------
def _auto_lang() -> str:
    for var in ("KASHIF_LANG", "LC_ALL", "LC_MESSAGES", "LANG"):
        if os.environ.get(var):
            return _lang(os.environ[var])
    return "en"


def _read_report(path: str) -> tuple[list, dict]:
    """Findings and metadata of a Kashif JSON report, a JSON list of findings, or (through ``vulnscan.compliance``)
    a SARIF file. Raises ``ValueError`` / ``OSError``."""
    p = pathlib.Path(path)
    if p.stat().st_size > MAX_REPORT_BYTES:
        raise ValueError(f"larger than {MAX_REPORT_BYTES} bytes")
    try:
        doc = json.loads(p.read_text(encoding="utf-8-sig"))
    except RecursionError:
        raise ValueError("JSON nested too deeply") from None
    if isinstance(doc, dict) and isinstance(doc.get("runs"), list):
        from . import compliance
        findings, meta = compliance.load_findings(p)
        return list(findings), dict(meta or {})
    if isinstance(doc, list):
        doc = {"findings": doc}
    if isinstance(doc, dict) and isinstance(doc.get("findings"), list) and all(isinstance(f, dict) for f in doc["findings"]):
        return doc["findings"], {k: v for k, v in doc.items() if k != "findings"}
    raise ValueError('no "findings" list')


# --help in English and Arabic ("both": the Arabic line, then the English line; see vulnscan/i18n/cliargs.py)
_HELP = {
    "en": {
        "desc": "Kashif policy-as-code: security gates from kashif.yml / kashif.json.",
        "lang": "message language: en or ar (default: from KASHIF_LANG or the system locale)",
        "check": "evaluate a JSON/SARIF report against a policy",
        "report": "Kashif JSON report or SARIF file",
        "policy": "policy file or builtin preset (default: kashif.yml in the current directory)",
        "baseline": "baseline file (fingerprints) for new_only",
        "changed": "file with one changed path per line ('-' = stdin), for new_only",
        "scanners": "comma-separated scanners that ran (e.g. sast,secrets,deps)",
        "today": "evaluation date YYYY-MM-DD (default: today)",
        "format": "format of the explanation (default: text)",
        "output": "write the explanation to this file instead of standard output",
        "strict": "treat policy warnings as errors",
        "external": "let 'extends' name files outside the policy's repository (only for a policy you trust)",
        "init": "write a starter kashif.yml",
        "preset": "the preset to start from (default: startup)",
        "init_output": "target file ('-' = standard output)",
        "name": "policy name (default: the name of the current directory)",
        "expand": "write the preset's settings instead of 'extends'",
        "force": "overwrite an existing file",
        "validate": "validate a policy file",
        "file": "the policy file",
        "show": "print the effective policy (inheritance resolved) as YAML",
        "presets": "list the builtin presets",
    },
    "ar": {
        "desc": "السياسة ككود في كاشِف: بوابات أمان من kashif.yml أو kashif.json.",
        "lang": "لغة الرسائل: en أو ar (الافتراضي: من KASHIF_LANG أو لغة النظام)",
        "check": "قيّم تقرير JSON أو SARIF وفق سياسة",
        "report": "تقرير JSON من كاشِف أو ملف SARIF",
        "policy": "ملف السياسة أو قالب مدمج (الافتراضي: kashif.yml في المجلد الحالي)",
        "baseline": "ملف خط الأساس (البصمات) لشرط new_only",
        "changed": "ملف فيه مسار معدَّل في كل سطر ('-' = الدخل القياسي)، لشرط new_only",
        "scanners": "الفاحصات التي عملت مفصولة بفواصل (مثل sast,secrets,deps)",
        "today": "تاريخ التقييم YYYY-MM-DD (الافتراضي: اليوم)",
        "format": "صيغة الشرح (الافتراضي: text)",
        "output": "اكتب الشرح إلى هذا الملف بدلًا من الخرج القياسي",
        "strict": "عامِل تحذيرات السياسة كأخطاء",
        "external": "اسمح لـ extends بتسمية ملفات خارج مستودع السياسة (فقط لسياسة تثق بها)",
        "init": "اكتب ملف kashif.yml أوليًّا",
        "preset": "القالب الذي تبدأ منه (الافتراضي: startup)",
        "init_output": "الملف الهدف ('-' = الخرج القياسي)",
        "name": "اسم السياسة (الافتراضي: اسم المجلد الحالي)",
        "expand": "اكتب إعدادات القالب نفسها بدلًا من extends",
        "force": "اكتب فوق ملف موجود",
        "validate": "تحقّق من صحة ملف سياسة",
        "file": "ملف السياسة",
        "show": "اطبع السياسة الفعلية (بعد حلّ الوراثة) بصيغة YAML",
        "presets": "اعرض القوالب المدمجة",
    },
}


def _parser(lang: str = "en") -> argparse.ArgumentParser:
    from .i18n.cliargs import HelpFormatter, pick

    def h(key: str) -> str:
        return pick(lang, _HELP["ar"][key], _HELP["en"][key])

    langs = ("en", "ar", "auto", "both")
    p = argparse.ArgumentParser(prog="kashif policy", description=h("desc"), formatter_class=HelpFormatter)
    # --lang before or after the command word: the command's own option (no default) keeps the value given before it
    p.add_argument("--lang", choices=langs, default="auto", metavar="{en,ar}", help=h("lang"))
    sub = p.add_subparsers(dest="cmd", required=True)

    def command(name: str, key: str):
        return sub.add_parser(name, help=h(key), description=h(key), formatter_class=HelpFormatter)

    c = command("check", "check")
    c.add_argument("report", help=h("report"))
    c.add_argument("--policy", help=h("policy"))
    c.add_argument("--baseline", help=h("baseline"))
    c.add_argument("--changed-files", metavar="FILE", help=h("changed"))
    c.add_argument("--scanners", help=h("scanners"))
    c.add_argument("--today", help=h("today"))
    c.add_argument("-f", "--format", choices=("text", "markdown", "json"), default="text", help=h("format"))
    c.add_argument("-o", "--output", help=h("output"))
    c.add_argument("--warnings-as-errors", action="store_true", help=h("strict"))
    c.add_argument("--allow-external-extends", action="store_true", help=h("external"))
    i = command("init", "init")
    i.add_argument("--preset", choices=sorted(PRESETS), default="startup", help=h("preset"))
    i.add_argument("-o", "--output", default="kashif.yml", help=h("init_output"))
    i.add_argument("--name", default=None, help=h("name"))
    i.add_argument("--expand", action="store_true", help=h("expand"))
    i.add_argument("--force", action="store_true", help=h("force"))
    v = command("validate", "validate")
    v.add_argument("file", help=h("file"))
    v.add_argument("--show", action="store_true", help=h("show"))
    v.add_argument("--allow-external-extends", action="store_true", help=h("external"))
    pr = command("presets", "presets")
    for s in (c, i, v, pr):
        s.add_argument("--lang", choices=langs, default=argparse.SUPPRESS, metavar="{en,ar}", help=h("lang"))
    return p


def main(argv=None) -> int:
    """Command line entry point. Returns 0 (passed / valid), 1 (gate failed) or 2 (usage, policy or input error)."""
    from .i18n.cliargs import help_lang, localized_argparse
    argv = list(sys.argv[1:] if argv is None else argv)
    hlang = help_lang(argv, default=_auto_lang(), choices=("en", "ar", "both"))   # --help and usage errors
    try:
        with localized_argparse(hlang):
            args = _parser(hlang).parse_args(argv)
    except SystemExit as e:
        return 0 if e.code in (0, None) else 2
    lang = _auto_lang() if args.lang == "auto" else "ar" if args.lang == "ar" else "en"   # "both": English
    for stream in (sys.stdout, sys.stderr):                  # Arabic output crashes on a cp1252 Windows console
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    def err(text):
        print("\n".join(_clean(line) for line in str(text).split("\n")), file=sys.stderr)

    try:
        if args.cmd == "presets":
            for name in sorted(PRESETS):
                print(f"{name:15} {_t(lang, 'p_' + name)}")
            return 0
        if args.cmd == "init":
            name = args.name or pathlib.Path.cwd().name or "my-project"
            text = init_template(args.preset, name, args.expand)
            if args.output == "-":
                sys.stdout.write(text)
                return 0
            target = pathlib.Path(args.output)
            if target.exists() and not args.force:
                err(_t(lang, "c_exists", path=args.output))
                return 2
            target.write_text(text, encoding="utf-8")
            print(_t(lang, "c_written", path=args.output))
            return 0
        if args.cmd == "validate":
            pol = load_policy(args.file, allow_outside=args.allow_external_extends)
            for w in pol.warnings:
                err(f"warning: {w.message(lang)}")
            if args.show:
                sys.stdout.write(dump_yaml(pol.to_dict()))
            else:
                print(_t(lang, "c_valid", path=args.file, name=pol.name, rules=pol.condition_count(),
                         scopes=len(pol.scopes), ignores=len(pol.ignores)))
            return 0
        # check
        policy_path = args.policy or find_policy(".")
        if not policy_path:
            err(_t(lang, "c_no_policy", names=", ".join(POLICY_FILENAMES)))
            return 2
        pol = load_policy(policy_path, allow_outside=args.allow_external_extends)
        try:
            findings, meta = _read_report(args.report)
        except (OSError, ValueError, ImportError, RecursionError) as e:
            err(_t(lang, "c_bad_report", path=args.report, err=str(e)[:200] or type(e).__name__))
            return 2
        ctx = Context(meta=meta)
        if args.today:
            ctx.today = _parse_date(args.today)
            if ctx.today is None:
                err(_t(lang, "c_bad_today"))
                return 2
        if args.baseline:
            ctx.baseline = _load_baseline_file(pathlib.Path(args.baseline))
            if ctx.baseline is None:
                err(_t(lang, "c_bad_report", path=args.baseline, err="not a baseline file"))
                return 2
        if args.changed_files:
            try:
                raw = sys.stdin.read() if args.changed_files == "-" else \
                    pathlib.Path(args.changed_files).read_text(encoding="utf-8-sig")
            except (OSError, UnicodeDecodeError) as e:
                err(_t(lang, "c_bad_report", path=args.changed_files, err=type(e).__name__))
                return 2
            ctx.changed = [ln.strip() for ln in raw.splitlines() if ln.strip()]
        if args.scanners is not None:
            ctx.scanners = {s.strip().lower() for s in args.scanners.split(",") if s.strip()}
        try:
            decision = evaluate(findings, pol, ctx, warnings_as_errors=args.warnings_as_errors)
            text = explain(decision, args.format, lang)
        except (ValueError, TypeError, AttributeError, OverflowError, RecursionError) as e:   # a malformed report
            err(_t(lang, "c_bad_report", path=args.report, err=f"{type(e).__name__}: {str(e)[:200]}"))
            return 2
        if args.output:
            pathlib.Path(args.output).write_text(text, encoding="utf-8")
        else:
            sys.stdout.write(text)
        return decision.exit_code
    except PolicyError as e:
        err(e.format(lang))
        return 2
    except OSError as e:
        err(f"{type(e).__name__}: {e}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
