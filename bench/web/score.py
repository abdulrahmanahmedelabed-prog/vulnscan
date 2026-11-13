"""Score a corpus run against labels.json (spec §5.3) and gate it on min-score.json (spec §5.4).

    python bench/web/score.py RESULTS.json [--baseline results/1.0.2-legacy.json] [--zap results/zap-2.17.0.json]
                              [--min-score min-score.json] [--ratchet] [--diff PREVIOUS.json]
                              [--markdown OUT.md] [--json OUT.json]

Per rule: TP (fires on a must-fire label), FP (fires on a trap), FN (misses a must-fire label), TN (silent on a trap);
precision, recall, F1 and Youden J = TPR − FPR. The macro average over rules with at least one must-fire label is the
headline, the micro average is shown too. A label is *inconclusive* when the rule did not fire and the run's coverage marks
its check ``not_tested``/``inconclusive``; it is never counted as TN or TP. Skipped cases (a requirement such as the TLS
stub or 127.0.0.2 is missing on this machine) are listed and never counted as passed. A run that crashed counts its
must-fire labels as FN and its traps as errors (never TN).

Attribution: run_kashif.py runs one scan per case, each case on its own host, so every finding of a run belongs to that
case ("grouped findings count once per case they name"). Results with several cases in one scan (ZAP) carry the case id on
each finding, attributed by URL (``/_case/<id>/``).
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
CONF_ORDER = ("certain", "firm", "tentative")
GRADE_ORDER = ["F", "D-", "D", "D+", "C-", "C", "C+", "B-", "B", "B+", "A-", "A", "A+"]
# Kashif rules matching ZAP's crowd-sourced top-20 false-positive passive families (accuracy note §2.1).
ZAP_FP_FAMILY = {"WEB022", "WEB-x-content-type-options", "WEB-strict-transport-security", "WEB-content-security-policy",
                 "WEB010", "WEB040", "WEB041", "WEB042", "WEB043", "WEB053", "WEB510", "WEB320", "WEB321", "WEB323",
                 "WEB327", "WEB608", "WEB315", "WEB404", "WEB613", "WEB614", "WEB308", "WEB309"}
NOT_RUN_STATES = {"not_tested", "inconclusive"}


def load(path) -> dict:
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))


# ------------------------------------------------------------------------------------------- reading a run


def coverage_state(web: dict | None, rule: str) -> str | None:
    """The coverage state the run recorded for ``rule`` (several shapes are accepted, see README)."""
    cov = (web or {}).get("coverage")
    if isinstance(cov, dict):
        entry = cov.get(rule)
        if isinstance(entry, str):
            return entry
        if isinstance(entry, dict):
            return entry.get("state") or entry.get("status")
        for v in cov.values():
            if isinstance(v, dict) and rule in (v.get("rules") or []):
                return v.get("state") or v.get("status")
    if isinstance(cov, list):
        for v in cov:
            if isinstance(v, dict) and (v.get("rule") == rule or v.get("check") == rule or rule in (v.get("rules") or [])):
                return v.get("state") or v.get("status")
    return None


def kashif_grade(web: dict | None) -> str | None:
    g = (web or {}).get("grades")
    if not isinstance(g, dict):
        return None
    k = g.get("kashif", g.get("kashif_grade"))
    if isinstance(k, str):
        return k
    if isinstance(k, dict):
        letter = k.get("grade") or k.get("letter")
        if isinstance(letter, str):
            suffix = "*" if k.get("provisional") and not letter.endswith("*") else ""
            return letter + suffix
    return None


def observatory_score(web: dict | None):
    g = (web or {}).get("grades")
    if isinstance(g, dict) and isinstance(g.get("observatory"), dict):
        return g["observatory"].get("score")
    return None


def grade_rank(letter: str | None) -> int | None:
    if not letter:
        return None
    base = letter.rstrip("*")
    return GRADE_ORDER.index(base) if base in GRADE_ORDER else None


def fired(result: dict, rule: str) -> list[dict]:
    return [f for f in result.get("findings", []) if f.get("rule") == rule]


def ran_ok(label: dict, result: dict) -> bool:
    allowed = label.get("expect", {}).get("exit", [0, 1])
    return result.get("status") == "ran" and result.get("exit") in allowed and not result.get("traceback")


# ------------------------------------------------------------------------------------------- expectations


def expectations(cid: str, label: dict, result: dict, results: dict) -> list[tuple[str, bool | None, str]]:
    """[(key, ok, message)]; ok None = not evaluable here (pending, not measured on this platform)."""
    out: list[tuple[str, bool | None, str]] = []
    exp = label.get("expect", {})
    allowed = exp.get("exit", [0, 1])
    out.append(("exit", result.get("exit") in allowed, f"exit {result.get('exit')} (allowed {allowed})"))
    out.append(("no traceback", not result.get("traceback"), "Python traceback on stderr" if result.get("traceback") else ""))
    tr = result.get("traffic", {})
    web = result.get("web") or {}
    for key, want in exp.items():
        if key == "exit":
            continue
        if key in ("severity", "max_severity", "confidence"):
            for rule, val in want.items():
                fs = fired(result, rule)
                if not fs:
                    out.append((f"{key}:{rule}", None, f"{rule} did not fire"))
                    continue
                if key == "confidence":
                    got = sorted({f.get("confidence") for f in fs})
                    out.append((f"{key}:{rule}", val in got, f"{rule} confidence {got}, expected {val}"))
                    continue
                worst = max(fs, key=lambda f: SEV_RANK.get(f.get("severity"), -1)).get("severity")
                ok = worst == val if key == "severity" else SEV_RANK.get(worst, 9) <= SEV_RANK[val]
                out.append((f"{key}:{rule}", ok, f"{rule} severity {worst}, expected {'≤ ' if key != 'severity' else ''}{val}"))
        elif key in ("count", "min_count"):
            for rule, n in want.items():
                got = len(fired(result, rule))
                ok = got == n if key == "count" else got >= n
                out.append((f"{key}:{rule}", ok, f"{rule} reported {got} time(s), expected {'' if key == 'count' else '≥ '}{n}"))
        elif key == "grade":
            got = kashif_grade(web)
            out.append(("grade", got == want if got is not None else False, f"grade {got}, expected {want}"))
        elif key == "grade_suffix":
            got = kashif_grade(web)
            out.append(("grade_suffix", bool(got and got.endswith(want)), f"grade {got}, expected suffix {want}"))
        elif key == "grade_at_least_case":
            other = results.get(want, {})
            a, b = grade_rank(kashif_grade(web)), grade_rank(kashif_grade(other.get("web")))
            ok = None if other.get("status") != "ran" else (a is not None and b is not None and a >= b)
            out.append(("grade_at_least_case", ok, f"grade {kashif_grade(web)} vs {want}: {kashif_grade(other.get('web'))}"))
        elif key == "observatory":
            if want is None:
                out.append(("observatory", None, "expected number pending (official scorer)"))
            else:
                got = observatory_score(web)
                out.append(("observatory", got == want, f"observatory {got}, expected {want}"))
        elif key == "states":
            for rule, st in want.items():
                got = coverage_state(web, rule)
                out.append((f"state:{rule}", got == st, f"{rule} coverage state {got}, expected {st}"))
        elif key == "max_elapsed":
            out.append(("max_elapsed", (result.get("elapsed") or 1e9) <= want, f"{result.get('elapsed')} s, limit {want} s"))
        elif key == "stderr_absent":
            for n in want:
                out.append((f"stderr_absent:{n}", not result.get("stderr_has", {}).get(n, False), f"'{n}' on stderr"))
        elif key == "json_contains":
            for n in want:
                out.append((f"json_contains:{n}", bool(result.get("contains", {}).get(n)), f"'{n}' in the JSON report"))
        elif key == "server_never":
            hit = [p for p in tr.get("paths", []) if any(p.startswith(x) for x in want)]
            out.append(("server_never", not hit, f"requested {hit}" if hit else ""))
        elif key == "min_gap":
            g = tr.get("min_gap")
            out.append(("min_gap", None if g is None else g >= want, f"min gap {g} s, expected ≥ {want} s"))
        elif key == "entry_gap":
            g = tr.get("entry_gap")
            out.append(("entry_gap", g is not None and g >= want, f"entry retried after {g} s, expected ≥ {want} s"))
        elif key == "max_requests":
            out.append(("max_requests", tr.get("requests", 0) <= want, f"{tr.get('requests')} requests, limit {want}"))
        elif key == "min_requests":
            out.append(("min_requests", tr.get("requests", 0) >= want, f"{tr.get('requests')} requests, expected ≥ {want}"))
        elif key == "output_safe":
            o = result.get("output_safety")
            out.append(("output_safe", None if o is None else o.get("ok"), "; ".join((o or {}).get("problems", []))))
        elif key == "curl_quoted":
            n = result.get("curl_checked", 0)
            unsafe = result.get("curl_unsafe", [])
            out.append(("curl_quoted", n > 0 and not unsafe,
                        "no curl reproduction lines in the evidence (§3.6)" if n == 0 else f"unquoted: {unsafe}"))
        elif key == "no_requests_on_ip2":
            out.append(("no_requests_on_ip2", tr.get("ip2_requests", 0) == 0, f"{tr.get('ip2_requests')} request(s) "
                                                                                "reached 127.0.0.2"))
        elif key == "max_rss_mb":
            m = result.get("max_rss_mb")
            out.append(("max_rss_mb", None if m is None else m <= want, f"peak RSS {m} MB, limit {want} MB"))
    return out


# ------------------------------------------------------------------------------------------- scoring


def score(labels: dict, run: dict) -> dict:
    cases = labels["cases"]
    results = run.get("cases", {})
    covers = set(run["covers"]) if isinstance(run.get("covers"), list) else None
    only = set(run["case_filter"]) if isinstance(run.get("case_filter"), list) else None
    per_rule: dict[str, dict] = {}
    verdicts: dict[str, dict] = {}
    conf: dict[str, dict] = {c: {"tp": 0, "fp": 0} for c in CONF_ORDER + ("unknown",)}
    skipped, errors, exp_fail, exp_pending = {}, {}, [], []
    inconclusive = 0
    total_labels = 0
    raw_instances = grouped = 0
    for cid, lab in cases.items():
        if only is not None and cid not in only:
            continue
        res = results.get(cid)
        if res is None:
            continue
        verdicts[cid] = {}
        if res.get("status") == "skipped":
            skipped[cid] = res.get("reason", "")
            for rule in lab["labels"]:
                verdicts[cid][rule] = "skipped"
            continue
        ok_run = ran_ok(lab, res)
        if not ok_run:
            errors[cid] = res.get("reason") or f"exit {res.get('exit')}" + (" + traceback" if res.get("traceback") else "")
        for f in res.get("findings", []):
            raw_instances += f.get("instances", 1) or 1
            grouped += 1
        for rule, must in lab["labels"].items():
            if covers is not None and rule not in covers:
                continue
            total_labels += 1
            r = per_rule.setdefault(rule, {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "inconclusive": 0, "error": 0, "skipped": 0,
                                           "cases": []})
            fs = fired(res, rule)
            if not ok_run and not fs:
                v = "fn" if must else "error"
            elif fs:
                v = "tp" if must else "fp"
                best = min(fs, key=lambda f: CONF_ORDER.index(f["confidence"]) if f.get("confidence") in CONF_ORDER else 9)
                bucket = best.get("confidence") if best.get("confidence") in CONF_ORDER else "unknown"
                conf[bucket]["tp" if must else "fp"] += 1
            elif coverage_state(res.get("web"), rule) in NOT_RUN_STATES:
                v = "inconclusive"
                inconclusive += 1
            else:
                v = "fn" if must else "tn"
            r[v] += 1
            if v in ("fp", "fn", "error"):
                r["cases"].append(f"{cid}:{v}")
            verdicts[cid][rule] = v
        if run.get("tool") == "zap":          # case expectations (grades, traffic, output safety) are Kashif-specific
            continue
        for key, ok, msg in expectations(cid, lab, res, results):
            if ok is False:
                exp_fail.append({"case": cid, "check": key, "message": msg})
            elif ok is None and key not in ("exit", "no traceback"):
                exp_pending.append({"case": cid, "check": key, "message": msg})
    rules_out = {}
    f1s = []
    tot = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    for rule in sorted(per_rule):
        r = per_rule[rule]
        for k in tot:
            tot[k] += r[k]
        m = metrics(r["tp"], r["fp"], r["fn"], r["tn"])
        rules_out[rule] = {**{k: r[k] for k in ("tp", "fp", "fn", "tn", "inconclusive", "error")}, **m,
                           "wrong": r["cases"][:12], "zap_fp_family": rule in ZAP_FP_FAMILY}
        if r["tp"] + r["fn"] > 0 and m["f1"] is not None:
            f1s.append(m["f1"])
    micro = metrics(tot["tp"], tot["fp"], tot["fn"], tot["tn"])
    conf_prec = {c: (round(v["tp"] / (v["tp"] + v["fp"]), 4) if v["tp"] + v["fp"] else None) for c, v in conf.items()}
    order = [conf_prec[c] for c in CONF_ORDER if conf_prec[c] is not None]
    ran = [c for c, r in results.items() if r.get("status") == "ran" and (only is None or c in only)]
    traffic_viol = {c: r.get("traffic", {}).get("violations") for c, r in results.items()
                    if r.get("traffic", {}).get("violations")}
    return {
        "tool": run.get("tool"), "mode": run.get("mode"), "version": run.get("kashif_version") or run.get("version"),
        "cases_scored": len(verdicts), "cases_ran": len(ran), "skipped": skipped, "errors": errors,
        "labels_scored": total_labels, "inconclusive": inconclusive,
        "inconclusive_rate": round(inconclusive / total_labels, 4) if total_labels else 0.0,
        "macro_f1": round(sum(f1s) / len(f1s), 4) if f1s else None, "micro": micro,
        "precision_by_confidence": conf_prec, "confidence_monotone": all(a >= b for a, b in zip(order, order[1:])),
        "noise_ratio": round(raw_instances / grouped, 3) if grouped else None,
        "findings_per_case": round(grouped / len(ran), 2) if ran else None,
        "zap_fp_family_trap_failures": sum(rules_out[r]["fp"] for r in rules_out if r in ZAP_FP_FAMILY),
        "rules": rules_out, "verdicts": verdicts, "expectation_failures": exp_fail, "expectation_pending": exp_pending,
        "traffic_violations": traffic_viol, "server_violations": run.get("violations", []),
        "unavailable": run.get("unavailable", {}),
    }


def metrics(tp: int, fp: int, fn: int, tn: int) -> dict:
    p = tp / (tp + fp) if tp + fp else None
    r = tp / (tp + fn) if tp + fn else None
    f1 = 2 * tp / (2 * tp + fp + fn) if tp + fp + fn else None      # 0 when a rule never fires on its positives
    tpr = r if r is not None else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    rd = (lambda x: None if x is None else round(x, 4))
    return {"precision": rd(p), "recall": rd(r), "f1": rd(f1), "youden_j": round(tpr - fpr, 4)}


def defect_table(labels: dict, summary: dict, baseline: dict | None) -> list[dict]:
    rows = []
    for n in range(1, 26):
        d = f"D{n}"
        cids = [c for c, lab in labels["cases"].items() if d in lab.get("defect", [])]
        rows.append({"defect": d, "cases": cids, "now": _defect_verdict(cids, summary),
                     "baseline": _defect_verdict(cids, baseline) if baseline else "not recorded"})
    return rows


def _defect_verdict(cids: list[str], summary: dict) -> str:
    if not cids:
        return "no case"
    failing = {e["case"] for e in summary["expectation_failures"]} | set(summary["errors"])
    states = []
    for c in cids:
        v = summary["verdicts"].get(c)
        if v is None:
            states.append("not run")
        elif c in summary["skipped"]:
            states.append("skipped")
        elif c in failing or any(x in ("fp", "fn", "error") for x in v.values()):
            states.append("wrong")
        else:
            states.append("right")
    if "wrong" in states:
        return "wrong"
    if all(s == "right" for s in states):
        return "fixed"
    return "skipped" if "skipped" in states else "not run"


def zap_comparison(k: dict, z: dict) -> dict:
    shared = sorted(r for r in z["rules"] if r in k["rules"])
    rows, disagree = [], []
    for r in shared:
        rows.append({"rule": r, "kashif_f1": k["rules"][r]["f1"], "zap_f1": z["rules"][r]["f1"]})
    for cid, zv in z["verdicts"].items():
        kv = k["verdicts"].get(cid, {})
        for rule, v in zv.items():
            if rule in kv and kv[rule] != v and v not in ("skipped",) and kv[rule] not in ("skipped",):
                disagree.append({"case": cid, "rule": rule, "kashif": kv[rule], "zap": v})
    kf = [x["kashif_f1"] for x in rows if x["kashif_f1"] is not None]
    zf = [x["zap_f1"] for x in rows if x["zap_f1"] is not None]
    every = all((x["kashif_f1"] or 0) >= (x["zap_f1"] or 0) for x in rows)
    kmac = sum(kf) / len(kf) if kf else None
    zmac = sum(zf) / len(zf) if zf else None
    return {"shared_rules": rows, "disagreements": disagree[:200],
            "kashif_macro_f1_shared": None if kmac is None else round(kmac, 4),
            "zap_macro_f1_shared": None if zmac is None else round(zmac, 4),
            "kashif_only_rules": sorted(r for r in k["rules"] if r not in z["rules"]),
            "claim_allowed": bool(rows) and every and kmac is not None and zmac is not None and kmac > zmac}


# ------------------------------------------------------------------------------------------- gate


def gate(summary: dict, mins: dict, defects: list[dict]) -> list[str]:
    fails = []
    t = mins.get("targets", {})
    pc = summary["precision_by_confidence"]
    if "precision_certain" in t and pc.get("certain") is not None and pc["certain"] < t["precision_certain"]:
        fails.append(f"precision(certain) {pc['certain']} < {t['precision_certain']}")
    if "precision_firm" in t and pc.get("firm") is not None and pc["firm"] < t["precision_firm"]:
        fails.append(f"precision(firm) {pc['firm']} < {t['precision_firm']}")
    if "recall_per_rule" in t:
        for rule, r in summary["rules"].items():
            if r["recall"] is not None and r["recall"] < t["recall_per_rule"]:
                fails.append(f"{rule}: recall {r['recall']} < {t['recall_per_rule']} ({', '.join(r['wrong'][:4])})")
    if "macro_f1" in t and summary["macro_f1"] is not None and summary["macro_f1"] < t["macro_f1"]:
        fails.append(f"macro F1 {summary['macro_f1']} < {t['macro_f1']}")
    if "zap_fp_family_trap_failures" in t and summary["zap_fp_family_trap_failures"] > t["zap_fp_family_trap_failures"]:
        fails.append(f"{summary['zap_fp_family_trap_failures']} trap failure(s) in ZAP's top false-positive families")
    if t.get("defects_fixed"):
        for row in defects:
            if row["now"] == "wrong":
                fails.append(f"{row['defect']} not fixed ({', '.join(row['cases'])})")
    if t.get("confidence_monotone") and not summary["confidence_monotone"]:
        fails.append(f"precision by confidence is not monotone: {pc}")
    if t.get("expectations"):
        for e in summary["expectation_failures"]:
            fails.append(f"{e['case']}: {e['check']}: {e['message']}")
    if t.get("traffic"):
        for c, v in summary["traffic_violations"].items():
            fails.append(f"{c}: traffic: {'; '.join(v[:3])}")
        for v in summary["server_violations"][:10]:
            fails.append(f"server: {v}")
    if "max_errors" in t and len(summary["errors"]) > t["max_errors"]:
        fails.append(f"{len(summary['errors'])} case(s) crashed or failed: {sorted(summary['errors'])[:8]}")
    for rule, floor in mins.get("rules", {}).items():
        r = summary["rules"].get(rule)
        if r is None:
            fails.append(f"{rule}: no longer scored (was in min-score.json)")
            continue
        for k in ("precision", "recall"):
            if floor.get(k) is not None and (r[k] is None or r[k] < floor[k]):
                fails.append(f"{rule}: {k} {r[k]} < recorded {floor[k]}")
    return fails


def ratchet(mins: dict, summary: dict) -> dict:
    rules = dict(mins.get("rules", {}))
    for rule, r in summary["rules"].items():
        old = rules.get(rule, {})
        new = {}
        for k in ("precision", "recall"):
            vals = [v for v in (old.get(k), r[k]) if v is not None]
            if vals:
                new[k] = max(vals)
        if new:
            rules[rule] = new
    return {**mins, "rules": dict(sorted(rules.items()))}


# ------------------------------------------------------------------------------------------- report


def markdown(summary: dict, defects: list[dict], zap: dict | None, diff: list[str] | None) -> str:
    s = summary
    pc = s["precision_by_confidence"]
    lines = [f"# Kashif passive web corpus: {s['tool']} {s['version']} ({s['mode']})", "",
             f"Cases scored {s['cases_scored']} (ran {s['cases_ran']}, skipped {len(s['skipped'])}, "
             f"failed {len(s['errors'])}); labels {s['labels_scored']}; inconclusive {s['inconclusive']} "
             f"({s['inconclusive_rate']:.1%}).", "",
             f"**Macro F1 {s['macro_f1']}** · micro P {s['micro']['precision']} R {s['micro']['recall']} "
             f"F1 {s['micro']['f1']} · precision certain {pc.get('certain')} / firm {pc.get('firm')} / tentative "
             f"{pc.get('tentative')} · noise ratio {s['noise_ratio']} · findings per case {s['findings_per_case']} · "
             f"ZAP-FP-family trap failures {s['zap_fp_family_trap_failures']}", "",
             "| Rule | TP | FP | FN | TN | Inc. | Precision | Recall | F1 | J | Wrong cases |",
             "|---|---|---|---|---|---|---|---|---|---|---|"]
    for rule, r in s["rules"].items():
        lines.append(f"| {rule} | {r['tp']} | {r['fp']} | {r['fn']} | {r['tn']} | {r['inconclusive']} | {r['precision']} | "
                     f"{r['recall']} | {r['f1']} | {r['youden_j']} | {', '.join(r['wrong'][:4])} |")
    lines += ["", "## 1.0.1 defects (regression cases)", "", "| Defect | Cases | 1.0.x baseline | This run |", "|---|---|---|---|"]
    for row in defects:
        lines.append(f"| {row['defect']} | {', '.join(row['cases'])} | {row['baseline']} | {row['now']} |")
    if s["expectation_failures"]:
        lines += ["", "## Case expectations not met", ""]
        lines += [f"- `{e['case']}` {e['check']}: {e['message']}" for e in s["expectation_failures"][:150]]
    if s["expectation_pending"]:
        lines += ["", "## Expectations not evaluable in this run", ""]
        lines += [f"- `{e['case']}` {e['check']}: {e['message']}" for e in s["expectation_pending"][:60]]
    if s["traffic_violations"] or s["server_violations"]:
        lines += ["", "## Politeness / scope violations (§0.1, §5.7)", ""]
        lines += [f"- `{c}`: {'; '.join(v)}" for c, v in s["traffic_violations"].items()]
        lines += [f"- server: {v}" for v in s["server_violations"]]
    if s["skipped"]:
        lines += ["", "## Skipped cases (never counted as passed)", ""]
        lines += [f"- `{c}`: {why}" for c, why in s["skipped"].items()]
    if s["errors"]:
        lines += ["", "## Failed runs", ""] + [f"- `{c}`: {why}" for c, why in s["errors"].items()]
    if zap:
        lines += ["", "## ZAP comparison (passive only, same labels)", "",
                  f"Macro F1 on shared rules: Kashif {zap['kashif_macro_f1_shared']}, ZAP {zap['zap_macro_f1_shared']}; "
                  f"claim allowed: {'yes' if zap['claim_allowed'] else 'no'}.", "", "| Rule | Kashif F1 | ZAP F1 |", "|---|---|---|"]
        lines += [f"| {x['rule']} | {x['kashif_f1']} | {x['zap_f1']} |" for x in zap["shared_rules"]]
        lines += ["", f"Rules ZAP does not cover (scored separately, not used for any claim): "
                      f"{', '.join(zap['kashif_only_rules'])}", "", "Disagreements:", ""]
        lines += [f"- `{d['case']}` {d['rule']}: Kashif {d['kashif']}, ZAP {d['zap']}" for d in zap["disagreements"][:80]]
    if diff:
        lines += ["", "## Changes against the previous run", ""] + [f"- {x}" for x in diff]
    return "\n".join(lines) + "\n"


def compare(prev: dict, now: dict) -> list[str]:
    out = []
    for rule in sorted(set(prev["rules"]) | set(now["rules"])):
        a, b = prev["rules"].get(rule), now["rules"].get(rule)
        if a is None or b is None:
            out.append(f"{rule}: {'new' if a is None else 'no longer scored'}")
            continue
        for k in ("precision", "recall", "f1"):
            if a[k] != b[k] and a[k] is not None and b[k] is not None:
                tag = "REGRESSION" if b[k] < a[k] else "improved"
                out.append(f"{tag}: {rule} {k} {a[k]} → {b[k]}")
    return sorted(out, key=lambda x: not x.startswith("REGRESSION"))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Score a corpus run and gate it (spec §5.3, §5.4).")
    ap.add_argument("results")
    ap.add_argument("--labels", default=str(HERE / "labels.json"))
    ap.add_argument("--baseline", help="results of the 1.0.x baseline run (legacy mode) for the defect table")
    ap.add_argument("--zap", help="results of run_zap.py on the same corpus")
    ap.add_argument("--min-score", help="gate on this min-score.json (exit 1 on failure)")
    ap.add_argument("--ratchet", action="store_true", help="raise the per-rule floors in --min-score to this run's values")
    ap.add_argument("--diff", help="a previous score JSON (from --json) to compare with")
    ap.add_argument("--markdown", help="write the Markdown report here (default: stdout)")
    ap.add_argument("--json", help="write the score summary JSON here")
    a = ap.parse_args(argv)
    labels = load(a.labels)
    summary = score(labels, load(a.results))
    base = score(labels, load(a.baseline)) if a.baseline else None
    defects = defect_table(labels, summary, base)
    zsum = score(labels, load(a.zap)) if a.zap else None
    zap = zap_comparison(summary, zsum) if zsum else None
    diff = compare(load(a.diff), summary) if a.diff else None
    md = markdown(summary, defects, zap, diff)
    if a.markdown:
        pathlib.Path(a.markdown).write_text(md, encoding="utf-8", newline="\n")
    else:
        sys.stdout.write(md)
    if a.json:
        doc = {**summary, "defects": defects, "zap": zap}
        pathlib.Path(a.json).write_text(json.dumps(doc, ensure_ascii=False, indent=1) + "\n", encoding="utf-8", newline="\n")
    if a.min_score:
        mins = load(a.min_score)
        fails = gate(summary, mins, defects)
        if a.ratchet:
            if fails:
                print("not ratcheting: the gate fails", file=sys.stderr)
            else:
                pathlib.Path(a.min_score).write_text(json.dumps(ratchet(mins, summary), indent=1) + "\n", encoding="utf-8",
                                                     newline="\n")
        if fails:
            print(f"GATE FAILED ({len(fails)}):", file=sys.stderr)
            for f in fails[:200]:
                print(f"  - {f}", file=sys.stderr)
            return 1
        print("gate passed", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
