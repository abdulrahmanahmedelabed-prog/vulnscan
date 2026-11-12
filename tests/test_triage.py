"""Finding triage lifecycle (vulnscan/triage.py): decisions, expiry, auto-fixed/regression, statistics, merge,
atomic and diff-stable storage, import of old suppressions, CLI. No network, no scanned code is executed."""

from __future__ import annotations

import datetime as dt
import json
import os

import pytest

from vulnscan import baseline, triage
from vulnscan.model import Finding, assign_fingerprints

T0 = dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=dt.timezone.utc)


def day(n: float) -> dt.datetime:
    return T0 + dt.timedelta(days=n)


def mk(rule="PY001", sev="high", file="app.py", snippet="os.system(cmd)", line=3) -> Finding:
    return Finding(rule, sev, f"{rule} title", "عنوان", file, line, snippet, "نصيحة", "CWE-78")


def scan(*findings: Finding) -> list[Finding]:
    out = list(findings)
    assign_fingerprints(out)
    return out


@pytest.fixture
def three():
    return scan(mk(), mk("PY002", "medium", snippet="eval(x)"), mk("PY003", "low", "lib.py", "pickle.loads(b)"))


# ------------------------------------------------------------------------------------------------ decisions

def test_set_status_validation_and_audit_log(three):
    t = triage.new_triage()
    fp = three[0].fingerprint()
    for status in ("false_positive", "accepted_risk", "wont_fix"):
        with pytest.raises(triage.TriageError) as err:
            triage.set_status(t, fp, status, author="sara", now=T0)
        assert err.value.key == "e_justification"
    with pytest.raises(triage.TriageError):
        triage.set_status(t, fp, "bogus", author="sara", now=T0)
    with pytest.raises(triage.TriageError):
        triage.set_status(t, fp, "confirmed", author="  ", now=T0)
    with pytest.raises(triage.TriageError):                      # expiry is for accepted_risk only
        triage.set_status(t, fp, "false_positive", author="sara", justification="x", expires="+30d", now=T0)
    with pytest.raises(triage.TriageError):                      # not in the future
        triage.set_status(t, fp, "accepted_risk", author="sara", justification="x", expires="2026-01-01", now=T0)
    with pytest.raises(triage.TriageError):                      # policy ceiling
        triage.set_status(t, fp, "accepted_risk", author="sara", justification="x", expires="+400d", now=T0,
                          max_accept_days=365)
    with pytest.raises(triage.TriageError):                      # only http(s) links reach the UI
        triage.set_status(t, fp, "confirmed", author="sara", ticket="javascript:alert(1)", now=T0)
    assert t["findings"] == {}                                   # failed calls leave no trace

    triage.set_status(t, fp, "confirmed", author="sara", now=T0, finding=three[0], comment="reproduced")
    e = triage.set_status(t, fp, "accepted_risk", author="omar", justification="internal only", expires="+90d",
                          ticket="https://tracker.example/SEC-1", now=day(1))
    assert e["status"] == "accepted_risk" and e["expires"] == "2026-04-02" and e["author"] == "omar"
    assert (e["rule"], e["file"], e["severity"]) == ("PY001", "app.py", "high")
    assert [item["action"] for item in e["log"]] == ["status", "comment", "status"]
    assert e["log"][2]["from"] == "confirmed" and e["log"][2]["to"] == "accepted_risk"
    triage.add_comment(t, fp, "reviewed with the team", author="lina", now=day(2))
    assert e["log"][-1] == {"at": "2026-01-03T12:00:00Z", "author": "lina", "action": "comment",
                            "text": "reviewed with the team"}
    with pytest.raises(triage.TriageError):
        triage.add_comment(t, fp, "   ", author="lina")


def test_control_and_bidi_characters_are_stripped():
    t = triage.new_triage()
    e = triage.set_status(t, "a" * 16 + ":0", "wont_fix", author="eve\x1b[31m", justification="ok‮\x07 fine", now=T0)
    assert e["author"] == "eve[31m" and e["justification"] == "ok fine"


def test_severity_override_changes_reported_severity_not_identity(three):
    t = triage.new_triage()
    f = three[0]
    fp = f.fingerprint()
    with pytest.raises(triage.TriageError):
        triage.override_severity(t, fp, "low", author="sara", now=T0)                # reason required
    with pytest.raises(triage.TriageError):
        triage.override_severity(t, fp, "severe", reason="x", author="sara", now=T0)
    triage.override_severity(t, fp, "low", reason="behind auth, test-only endpoint", author="sara", now=T0, finding=f)
    res = triage.apply(three, t, T0)
    assert f.severity == "low" and f.fingerprint() == fp
    info = f.extra["triage"]
    assert info["severity_original"] == "high" and info["severity_reason"].startswith("behind auth")
    assert t["findings"][fp]["severity"] == "high"                                 # the scanner's own severity is kept
    assert res.visible == three
    triage.sync(three, t, T0)                                                       # sync after apply keeps the original
    assert t["findings"][fp]["severity"] == "high"
    triage.override_severity(t, fp, None, author="sara", now=day(1))
    assert "severity_override" not in t["findings"][fp]
    assert [i["action"] for i in t["findings"][fp]["log"]] == ["severity", "severity"]


# --------------------------------------------------------------------------------------------- apply / expiry

def test_apply_filters_and_annotates(three):
    t = triage.new_triage()
    a, b, c = three
    triage.set_status(t, b.fingerprint(), "false_positive", author="sara", justification="value is a constant", now=T0)
    triage.set_status(t, c.fingerprint(), "confirmed", author="sara", now=T0)
    res = triage.apply(three, t, day(3))
    assert res.findings == three and res.visible == [a, c] and res.hidden == [b]
    assert res.counts == {"open": 1, "false_positive": 1, "confirmed": 1}
    assert a.extra["triage"] == {"status": "open", "tracked": False}
    assert b.extra["triage"]["justification"] == "value is a constant" and b.extra["triage"]["age_days"] == 3
    assert triage.apply(three, t, day(3), show=triage.STATUSES).visible == three
    assert json.loads(triage.dumps(t)) == json.loads(triage.dumps(t))               # apply never mutates the triage
    assert "triage" in b.to_dict()["extra"]                                         # travels with the JSON report


def test_apply_accepts_saved_scan_dicts(three):
    t = triage.new_triage()
    dicts = [f.to_dict() for f in three]
    triage.set_status(t, dicts[0]["fingerprint"], "wont_fix", author="sara", justification="legacy module", now=T0)
    triage.override_severity(t, dicts[1]["fingerprint"], "critical", reason="internet facing", author="sara", now=T0)
    res = triage.apply(dicts, t, T0)
    assert [d["rule_id"] for d in res.visible] == ["PY002", "PY003"]
    assert dicts[1]["severity"] == "critical" and dicts[1]["extra"]["triage"]["severity_original"] == "medium"


def test_accepted_risk_expires_and_reopens(three):
    t = triage.new_triage()
    f = three[0]
    fp = f.fingerprint()
    triage.sync(three, t, T0)
    triage.set_status(t, fp, "accepted_risk", author="omar", justification="compensating control", expires="2026-01-31",
                      now=T0)
    on_last_day = triage.apply(three, t, dt.datetime(2026, 1, 31, 23, 0, tzinfo=dt.timezone.utc))
    assert f in on_last_day.hidden and not on_last_day.expired                      # valid through the expiry day
    after = triage.apply(three, t, dt.datetime(2026, 2, 1, 0, 0, 1, tzinfo=dt.timezone.utc))
    assert f in after.visible and after.expired == [f]
    assert f.extra["triage"]["status"] == "open" and f.extra["triage"]["expired"] is True
    assert f.extra["triage"]["flags"] == ["risk acceptance expired"]
    assert triage.apply(three, t, day(40), lang="ar").expired[0].extra["triage"]["flags"] == ["انتهى قبول الخطر"]
    assert t["findings"][fp]["status"] == "accepted_risk"                           # apply is read-only

    check = triage.expire_check(t, dt.date(2026, 1, 25), within_days=14)
    assert check["expired"] == [] and check["expiring"][0]["days"] == 6
    check = triage.expire_check(t, day(40))
    assert check["expired"][0]["fingerprint"] == fp and check["expired"][0]["days"] == 10

    res = triage.sync(three, t, day(40))                                            # persists the re-open
    e = t["findings"][fp]
    assert res.expired == [fp] and e["status"] == "open" and e["expired"] is True and "expires" not in e
    assert e["log"][-1]["action"] == "expired" and e["log"][-1]["author"] == "kashif"
    assert e["log"][-1]["justification"] == "compensating control"
    assert triage.sync(three, t, day(41)).expired == []                             # only once
    assert triage.apply(three, t, day(41)).expired == [f]                           # still flagged until re-triaged
    assert triage.expire_check(t, day(41))["expired"][0]["expires"] == "2026-01-31"
    triage.set_status(t, fp, "confirmed", author="omar", now=day(42))
    assert "expired" not in t["findings"][fp] and triage.apply(three, t, day(42)).expired == []


# ------------------------------------------------------------------------------ auto-fixed / regression / stale

def test_auto_fixed_then_regression(three):
    t = triage.new_triage()
    a, b, c = three
    first = triage.sync(three, t, T0)
    assert first.new == sorted(f.fingerprint() for f in three) and first.changed
    assert all(e["status"] == "open" and e["first_seen"] == "2026-01-01T12:00:00Z" for e in t["findings"].values())
    triage.set_status(t, c.fingerprint(), "false_positive", author="sara", justification="trusted input", now=day(1))

    second = triage.sync(scan(mk()), t, day(10))                                    # b and c are gone
    assert second.fixed == [b.fingerprint()] and second.stale == [c.fingerprint()] and not second.new
    e = t["findings"][b.fingerprint()]
    assert e["status"] == "fixed" and e["fixed_at"] == "2026-01-11T12:00:00Z" and e["auto"] is True
    assert e["log"][-1] == {"at": "2026-01-11T12:00:00Z", "author": "kashif", "action": "auto_fixed", "from": "open"}
    assert t["findings"][c.fingerprint()]["status"] == "false_positive"             # a decision is never auto-deleted

    back = scan(mk(), mk("PY002", "medium", snippet="eval(x)"))
    shown = triage.apply(back, t, day(20))                                          # flagged even before sync
    assert shown.regressions == [back[1]] and back[1] in shown.visible
    third = triage.sync(back, t, day(20))
    assert third.regressions == [b.fingerprint()]
    assert e["status"] == "open" and e["regression"] is True and e["regressions"] == 1 and "fixed_at" not in e
    assert e["log"][-1]["action"] == "regression" and e["log"][-1]["fixed_at"] == "2026-01-11T12:00:00Z"
    res = triage.apply(back, t, day(20))
    assert res.regressions == [back[1]] and back[1].extra["triage"]["flags"] == ["regression"]
    assert back[1].extra["triage"]["regressions"] == 1


def test_partial_scans_do_not_mark_fixed(three):
    t = triage.new_triage()
    triage.sync(three, t, T0)
    assert triage.sync([], t, day(1), complete=False).fixed == []
    res = triage.sync([], t, day(1), scanned_files=["lib.py"])                       # only lib.py was rescanned
    assert res.fixed == [three[2].fingerprint()]
    assert t["findings"][three[0].fingerprint()]["status"] == "open"


def test_track_new_false_keeps_only_decisions(three):
    t = triage.new_triage()
    res = triage.sync(three, t, T0, track_new=False)
    assert t["findings"] == {} and not res.changed


# ---------------------------------------------------------------------------------------------------- statistics

def test_stats_mttr_age_buckets_and_sla():
    t = triage.new_triage()
    crit, high, med, low = (mk("R1", "critical", snippet="a"), mk("R2", "high", snippet="b"),
                            mk("R3", "medium", snippet="c"), mk("R4", "low", snippet="d"))
    fixed_fast, fixed_slow = mk("R5", "high", snippet="e"), mk("R5", "high", snippet="f")
    triage.sync(scan(crit, fixed_fast, fixed_slow), t, T0)
    triage.sync(scan(crit, fixed_slow, high), t, day(4))                            # fixed_fast: 4 days
    triage.sync(scan(crit, high, med), t, day(10))                                  # fixed_slow: 10 days
    triage.sync(scan(crit, high, med, low), t, day(95))
    triage.set_status(t, med.fingerprint(), "false_positive", author="sara", justification="not reachable", now=day(95))
    s = triage.stats(t, day(100))
    assert s["total"] == 6
    assert s["by_status"] == {"open": 3, "confirmed": 0, "false_positive": 1, "accepted_risk": 0, "fixed": 2,
                              "wont_fix": 0}
    assert s["open_by_severity"] == {"critical": 1, "high": 1, "medium": 0, "low": 1, "info": 0}
    assert s["open_by_age"] == {"0-7": 1, "8-30": 0, "31-90": 0, "91+": 2}          # low 5d, high 96d, critical 100d
    assert s["mttr_days"] == {"high": {"count": 2, "mean": 7.0, "median": 7.0},
                              "all": {"count": 2, "mean": 7.0, "median": 7.0}}
    breaches = s["sla"]["breaches"]
    assert [(b["severity"], b["age_days"], b["sla_days"], b["overdue_days"]) for b in breaches] == [
        ("critical", 100, 7, 93), ("high", 96, 30, 66)]
    assert s["false_positive_rules"] == [{"rule": "R3", "total": 1, "false_positive": 1, "rate": 1.0}]
    assert triage.stats(t, day(100), sla_days={"low": 3})["sla"]["breaches"][0]["severity"] == "low"
    assert triage.stats(t, day(100), sla_days={})["sla"]["breaches"] == []
    json.dumps(s)                                                                   # JSON-serialisable for the UI

    triage.override_severity(t, crit.fingerprint(), "low", reason="dev tool only", author="sara", now=day(100))
    assert [b["severity"] for b in triage.stats(t, day(100))["sla"]["breaches"]] == ["high"]   # 100d < 180d for low


def test_stats_counts_expired_acceptance_as_open():
    t = triage.new_triage()
    f = scan(mk())[0]
    triage.sync([f], t, T0)
    triage.set_status(t, f.fingerprint(), "accepted_risk", author="omar", justification="j", expires="+10d", now=T0)
    assert triage.stats(t, day(5))["by_status"]["accepted_risk"] == 1
    assert triage.stats(t, day(5))["expiring"][0]["days"] == 5
    s = triage.stats(t, day(60))
    assert s["by_status"]["open"] == 1 and s["by_status"]["accepted_risk"] == 0 and len(s["expired"]) == 1
    assert s["sla"]["breaches"][0]["age_days"] == 60                                # the SLA clock never stopped


# ------------------------------------------------------------------------------------------------------- storage

def test_save_is_atomic_and_leaves_no_temp_files(tmp_path, three, monkeypatch):
    path = tmp_path / ".kashif" / "triage.json"
    t = triage.new_triage()
    triage.sync(three, t, T0)
    assert triage.save(t, path) is True and triage.load(path) == json.loads(path.read_text(encoding="utf-8"))
    original = path.read_bytes()

    def boom(src, dst):
        raise OSError("disk full")

    triage.set_status(t, three[0].fingerprint(), "confirmed", author="sara", now=day(1))
    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        triage.save(t, path)
    monkeypatch.undo()
    assert path.read_bytes() == original                                            # previous file intact
    assert [p.name for p in path.parent.iterdir()] == ["triage.json"]               # temp file cleaned up
    assert triage.save(t, path) is True
    assert [p.name for p in path.parent.iterdir()] == ["triage.json"]


def test_file_is_stable_for_clean_diffs(tmp_path, three):
    path = tmp_path / "triage.json"
    t = triage.new_triage()
    triage.sync(three, t, T0)
    triage.set_status(t, three[1].fingerprint(), "false_positive", author="سارة", justification="قيمة ثابتة", now=T0)
    triage.save(t, path)
    text = path.read_text(encoding="utf-8")
    assert text.endswith("}\n") and "\r" not in text and "سارة" in text            # readable UTF-8, one final newline
    assert list(json.loads(text)["findings"]) == sorted(json.loads(text)["findings"])
    stat = path.stat()

    assert triage.save(triage.load(path), path) is False                            # round trip: byte-identical
    again = triage.load(path)
    assert not triage.sync(three, again, day(30)).changed                           # rescanning the same code
    triage.apply(three, again, day(30))
    assert triage.save(again, path) is False
    assert path.read_text(encoding="utf-8") == text and path.stat().st_mtime_ns == stat.st_mtime_ns

    shuffled = {"findings": dict(reversed(list(again["findings"].items()))), "schema": triage.SCHEMA}
    assert triage.dumps(shuffled) == text                                           # insertion order is irrelevant

    before = text.splitlines()
    triage.add_comment(again, three[0].fingerprint(), "one more look", author="sara", now=day(31))
    after = triage.dumps(again).splitlines()
    changed = [line for line in after if line not in before]
    assert len(after) - len(before) == 8 and any("one more look" in line for line in changed)   # one log item, no churn


def test_missing_empty_and_malformed_files(tmp_path):
    assert triage.load(tmp_path / "absent.json") == triage.new_triage()
    empty = tmp_path / "empty.json"
    empty.write_text("", encoding="utf-8")
    assert triage.load(empty) == triage.new_triage()
    good = {"status": "open"}
    cases = {
        "not json": "{oops",
        "list": "[]",
        "no schema": json.dumps({"findings": {}}),
        "other tool": json.dumps({"schema": "vulnscan-baseline/1", "findings": {}}),
        "future": json.dumps({"schema": "kashif-triage/2", "findings": {}}),
        "findings list": json.dumps({"schema": triage.SCHEMA, "findings": []}),
        "entry not object": json.dumps({"schema": triage.SCHEMA, "findings": {"x": "open"}}),
        "bad status": json.dumps({"schema": triage.SCHEMA, "findings": {"x": {"status": "ignored"}}}),
        "no justification": json.dumps({"schema": triage.SCHEMA, "findings": {"x": {"status": "false_positive"}}}),
        "bad log": json.dumps({"schema": triage.SCHEMA, "findings": {"x": {**good, "log": ["x"]}}}),
        "bad override": json.dumps({"schema": triage.SCHEMA, "findings": {"x": {**good, "severity_override": {}}}}),
        "bad expiry": json.dumps({"schema": triage.SCHEMA, "findings": {"x": {**good, "expires": "soon"}}}),
        "bad ticket": json.dumps({"schema": triage.SCHEMA, "findings": {"x": {**good, "ticket": "javascript:x"}}}),
        "deep": "[" * 100000,
    }
    for name, text in cases.items():
        p = tmp_path / "bad.json"
        p.write_text(text, encoding="utf-8")
        with pytest.raises(triage.TriageError) as err:
            triage.load(p)
        assert err.value.key == "e_malformed", name
        assert "bad.json" in str(err.value) and "bad.json" in err.value.message("ar")
    p.write_bytes(b"\xff\xfe\x00bad")
    with pytest.raises(triage.TriageError):
        triage.load(p)
    assert triage.main(["--file", str(p), "list"]) == 2                             # the CLI reports, never crashes


# --------------------------------------------------------------------------------------------------------- merge

def _branches(three):
    base = triage.new_triage()
    triage.sync(three, base, T0)
    ours, theirs = json.loads(triage.dumps(base)), json.loads(triage.dumps(base))
    return base, ours, theirs


def test_merge_independent_edits_without_conflict(three):
    base, ours, theirs = _branches(three)
    a, b, c = (f.fingerprint() for f in three)
    triage.set_status(ours, a, "false_positive", author="sara", justification="sanitised upstream", now=day(1))
    triage.add_comment(ours, c, "ours comment", author="sara", now=day(1))
    triage.set_status(theirs, b, "confirmed", author="omar", now=day(2))
    triage.add_comment(theirs, c, "theirs comment", author="omar", now=day(2))
    for kwargs in ({"base": base}, {}):                                             # with and without an ancestor
        merged, conflicts = triage.merge(ours, theirs, **kwargs)
        assert conflicts == []
        assert merged["findings"][a]["status"] == "false_positive" and merged["findings"][b]["status"] == "confirmed"
        assert [i["text"] for i in merged["findings"][c]["log"]] == ["ours comment", "theirs comment"]
        assert triage.dumps(merged) == triage.dumps(triage.merge(theirs, ours, **kwargs)[0])   # symmetric
        assert triage.dumps(triage.merge(merged, theirs)[0]) == triage.dumps(merged)           # idempotent


def test_merge_conflicting_edits_latest_wins_and_is_reported(three):
    base, ours, theirs = _branches(three)
    a = three[0].fingerprint()
    triage.set_status(ours, a, "false_positive", author="sara", justification="looks safe", now=day(1))
    triage.set_status(theirs, a, "confirmed", author="omar", now=day(2), comment="exploited in staging")
    merged, conflicts = triage.merge(ours, theirs, base=base)
    assert merged["findings"][a]["status"] == "confirmed" and "justification" not in merged["findings"][a]
    assert conflicts == [{"fingerprint": a, "field": "status", "ours": "false_positive", "theirs": "confirmed",
                          "chosen": "confirmed"}]
    actions = [(i["author"], i["action"]) for i in merged["findings"][a]["log"]]
    assert actions == [("sara", "status"), ("omar", "comment"), ("omar", "status")]  # both audit trails survive
    assert triage.dumps(triage.merge(theirs, ours, base=base)[0]) == triage.dumps(merged)

    # same timestamp: the edit that keeps the finding visible wins
    base, ours, theirs = _branches(three)
    triage.set_status(ours, a, "false_positive", author="sara", justification="looks safe", now=day(1))
    triage.set_status(theirs, a, "confirmed", author="omar", now=day(1))
    for x, y in ((ours, theirs), (theirs, ours)):
        merged, conflicts = triage.merge(x, y)
        assert merged["findings"][a]["status"] == "confirmed" and len(conflicts) == 1

    base, ours, theirs = _branches(three)
    triage.override_severity(ours, a, "low", reason="r1", author="sara", now=day(1))
    triage.override_severity(theirs, a, "critical", reason="r2", author="omar", now=day(1))
    merged, conflicts = triage.merge(ours, theirs, base=base)
    assert merged["findings"][a]["severity_override"]["severity"] == "critical"
    assert [c["field"] for c in conflicts] == ["severity_override"]


def test_git_conflict_markers_are_resolved_on_load(tmp_path, three):
    base, ours, theirs = _branches(three)
    a, b = three[0].fingerprint(), three[1].fingerprint()
    triage.set_status(ours, a, "wont_fix", author="sara", justification="module is being removed", now=day(1))
    triage.set_status(theirs, b, "confirmed", author="omar", now=day(2))
    text = ("<<<<<<< HEAD\n" + triage.dumps(ours) + "||||||| base\n" + triage.dumps(base) + "=======\n"
            + triage.dumps(theirs) + ">>>>>>> feature\n")
    path = tmp_path / "triage.json"
    path.write_text(text, encoding="utf-8")
    info: dict = {}
    loaded = triage.load(path, info)
    assert info["conflict_markers"] is True and info["conflicts"] == []
    assert loaded["findings"][a]["status"] == "wont_fix" and loaded["findings"][b]["status"] == "confirmed"
    path.write_text("<<<<<<< HEAD\n{broken\n=======\n" + triage.dumps(theirs) + ">>>>>>> x\n", encoding="utf-8")
    with pytest.raises(triage.TriageError):
        triage.load(path)


def test_update_merges_a_concurrent_save(tmp_path, three):
    path = tmp_path / "triage.json"
    t = triage.new_triage()
    triage.sync(three, t, T0)
    triage.save(t, path)
    a, b = three[0].fingerprint(), three[1].fingerprint()

    def mine(tri):
        triage.set_status(tri, a, "confirmed", author="sara", now=day(1))
        other = triage.load(path)                                                   # someone else saves meanwhile
        triage.set_status(other, b, "wont_fix", author="omar", justification="deprecated", now=day(1))
        triage.save(other, path)

    triage.update(path, mine)
    final = triage.load(path)
    assert final["findings"][a]["status"] == "confirmed" and final["findings"][b]["status"] == "wont_fix"


# ----------------------------------------------------------------------------------------------- import / inline

def test_import_baseline(tmp_path, three):
    bl = tmp_path / "baseline.json"
    baseline.save_baseline(three, str(bl))
    t = triage.new_triage()
    triage.set_status(t, three[0].fingerprint(), "confirmed", author="sara", now=T0)
    assert triage.import_baseline(t, bl, author="sara", now=day(1)) == {"added": 2, "skipped": 1}
    e = t["findings"][three[1].fingerprint()]
    assert e["status"] == "open" and e["rule"] == "PY002" and e["severity"] == "medium"
    assert e["log"] == [{"at": "2026-01-02T12:00:00Z", "author": "sara", "action": "import", "source": "baseline.json",
                         "to": "open"}]
    assert t["findings"][three[0].fingerprint()]["status"] == "confirmed"           # existing decisions untouched
    assert triage.import_baseline(t, bl, author="sara") == {"added": 0, "skipped": 3}

    t2 = triage.new_triage()
    with pytest.raises(triage.TriageError):
        triage.import_baseline(t2, bl, author="sara", status="accepted_risk")
    triage.import_baseline(t2, bl, author="sara", status="accepted_risk", justification="pre-existing, tracked in SEC-9")
    assert {e["status"] for e in t2["findings"].values()} == {"accepted_risk"}
    triage.loads(triage.dumps(t2))                                                  # still a valid file
    with pytest.raises(triage.TriageError):
        triage.import_baseline(t2, tmp_path / "nope.json", author="sara")
    (tmp_path / "junk.json").write_text("[1]", encoding="utf-8")
    with pytest.raises(triage.TriageError):
        triage.import_baseline(t2, tmp_path / "junk.json", author="sara")


def test_inline_suppressions_are_listed_only(tmp_path):
    marker = "no" + "sec"                                   # built at run time: this test file is scanned too
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "a.py").write_text(f"import os\nos.system(cmd)  # {marker}: reviewed\nx = 1\n", encoding="utf-8")
    (tmp_path / "b.js").write_text("// vulnscan:" + " ignore-file\neval(x) // vulnscan:" + " ignore\n", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "c.js").write_text(f"// {marker}\n", encoding="utf-8")
    (tmp_path / "blob.bin").write_bytes(b"\0\0" + marker.encode())
    found = triage.find_inline_suppressions(tmp_path)
    assert [(i["file"], i["line"], i["kind"], i["marker"]) for i in found] == [
        ("b.js", 1, "file", "vulnscan: ignore-file"), ("b.js", 2, "line", "vulnscan: ignore"),
        ("pkg/a.py", 2, "line", marker)]
    assert len(triage.find_inline_suppressions(tmp_path, max_results=1)) == 1
    assert len(triage.find_inline_suppressions(tmp_path / "pkg" / "a.py")) == 1


# ----------------------------------------------------------------------------------------------------------- CLI

def _cli(capsys, *argv):
    code = triage.main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_cli_end_to_end(tmp_path, three, capsys):
    report = tmp_path / "scan.json"
    report.write_text(json.dumps({"findings": [f.to_dict() for f in three]}), encoding="utf-8")
    root = ["--root", str(tmp_path)]
    path = tmp_path / ".kashif" / "triage.json"
    a, b, c = (f.fingerprint() for f in three)

    code, out, _ = _cli(capsys, *root, "sync", "--report", str(report), "--now", "2026-01-01T12:00:00Z", "--json")
    assert code == 0 and json.loads(out)["new"] == sorted([a, b, c]) and path.exists()

    code, _, err = _cli(capsys, *root, "set", a, "false_positive", "--author", "sara")
    assert code == 2 and "justification" in err
    code, _, err = _cli(capsys, *root, "--lang", "ar", "set", a, "false_positive", "--author", "sara")
    assert code == 2 and "مبرّر" in err
    code, out, _ = _cli(capsys, *root, "set", a[:8], "accepted_risk", "--author", "omar", "-j", "WAF rule in place",
                        "--expires", "2026-02-15", "--ticket", "https://tracker.example/SEC-7",
                        "--now", "2026-01-02T12:00:00Z")
    assert code == 0 and "Accepted risk" in out
    code, _, err = _cli(capsys, *root, "set", "zzzz", "confirmed", "--author", "omar")
    assert code == 2 and "zzzz" in err
    assert _cli(capsys, *root, "comment", b, "needs a pentest", "--author", "lina")[0] == 0
    assert _cli(capsys, *root, "severity", c, "high", "--reason", "reachable pre-auth", "--author", "lina")[0] == 0

    entry = triage.load(path)["findings"][a]
    assert entry["author"] == "omar" and entry["expires"] == "2026-02-15" and entry["ticket"].endswith("SEC-7")

    code, out, _ = _cli(capsys, *root, "list", "--status", "accepted_risk", "--now", "2026-01-10T00:00:00Z")
    assert code == 0 and a in out and b not in out and "WAF rule in place" in out
    code, out, _ = _cli(capsys, *root, "list", "--json", "--severity", "high")
    assert set(json.loads(out)["findings"]) == {a, c}
    code, out, _ = _cli(capsys, *root, "show", b[:6])
    assert code == 0 and "needs a pentest" in out and "lina" in out

    code, out, _ = _cli(capsys, *root, "expire-check", "--now", "2026-02-10T00:00:00Z")
    assert code == 0 and a in out
    code, out, _ = _cli(capsys, *root, "expire-check", "--now", "2026-03-01T00:00:00Z", "--json", "--apply")
    assert code == 1 and json.loads(out)["expired"][0]["fingerprint"] == a
    assert triage.load(path)["findings"][a]["status"] == "open"
    code, out, _ = _cli(capsys, *root, "--lang", "ar", "list", "--now", "2026-03-02T00:00:00Z")
    assert "انتهى قبول الخطر" in out

    code, out, _ = _cli(capsys, *root, "stats", "--now", "2026-03-02T00:00:00Z", "--sla", "high=30,medium=20",
                        "--fail-on-breach")
    assert code == 1 and "SLA breaches: 3" in out
    code, out, _ = _cli(capsys, *root, "stats", "--json", "--now", "2026-01-03T00:00:00Z")
    assert code == 0 and json.loads(out)["total"] == 3
    assert _cli(capsys, *root, "stats", "--sla", "urgent=1")[0] == 2

    report.write_text(json.dumps({"findings": [three[0].to_dict()]}), encoding="utf-8")
    code, out, _ = _cli(capsys, *root, "sync", "--report", str(report), "--dry-run", "--json")
    assert sorted(json.loads(out)["fixed"]) == sorted([b, c]) and triage.load(path)["findings"][b]["status"] == "open"
    assert _cli(capsys, *root, "sync", "--report", str(tmp_path / "missing.json"))[0] == 2


def test_cli_import_and_merge(tmp_path, three, capsys):
    bl = tmp_path / "baseline.json"
    baseline.save_baseline(three, str(bl))
    (tmp_path / "x.py").write_text("eval(a)  # no" + "sec\n", encoding="utf-8")
    code, out, _ = _cli(capsys, "--root", str(tmp_path), "import", "--baseline", str(bl), "--inline", "--author", "sara")
    assert code == 0 and "3 imported" in out and "x.py:1" in out
    ours = tmp_path / ".kashif" / "triage.json"
    theirs = tmp_path / "theirs.json"
    other = triage.load(ours)
    triage.set_status(other, three[0].fingerprint(), "confirmed", author="omar", now=day(1))
    triage.save(other, theirs)
    code, out, err = _cli(capsys, "merge", str(ours), str(theirs))
    assert code == 0 and json.loads(out)["findings"][three[0].fingerprint()]["status"] == "confirmed"
    assert "0 conflicting" in err
    assert _cli(capsys, "merge", str(ours), str(theirs), "--base", str(ours), "-o", str(ours))[0] == 0   # merge driver
    assert triage.load(ours) == triage.load(theirs)


def test_strings_are_complete_in_both_languages():
    assert set(triage.STR["en"]) == set(triage.STR["ar"])
    assert all(triage.status_label(s, "ar") != triage.status_label(s, "en") for s in triage.STATUSES)


# ------------------------------------------------------------------------- hardening (adversarial review)

def _doc(entry: dict, fp: str = "0123456789abcdef:0") -> str:
    return json.dumps({"schema": triage.SCHEMA, "findings": {fp: entry}})


def test_hostile_file_values_are_rejected_not_crashed_on(tmp_path):
    good = {"status": "open"}
    cases = {
        "regressions text": _doc({**good, "regressions": "many"}),
        "regressions huge": _doc({**good, "regressions": 10 ** 400}),
        "regressions bool": _doc({**good, "regressions": True}),
        "regressions inf": '{"schema": "kashif-triage/1", "findings": {"0123456789abcdef:0": {"regressions": 1e999}}}',
        "nan": '{"schema": "kashif-triage/1", "x": NaN, "findings": {}}',
        "rule is a list": _doc({**good, "rule": ["R1"]}),
        "author is a dict": _doc({**good, "author": {}}),
        "status is a list": _doc({"status": ["open"]}),
        "flag is text": _doc({**good, "regression": "yes"}),
        "log at is a number": _doc({**good, "log": [{"at": 5}]}),
        "override reason": _doc({**good, "severity_override": {"severity": "low", "reason": 1}}),
        "override severity list": _doc({**good, "severity_override": {"severity": ["low"]}}),
        "key with newline": _doc(good, "abc\ndef"),
        "key with space": _doc(good, "abc def"),
        "empty key": _doc(good, ""),
        "nested entry": _doc({**good, "x": json.loads("[" * 40 + "]" * 40)}),
        "ticket escape": _doc({**good, "ticket": "https://t.example/\x1b[2J"}),
        "ticket credentials": _doc({**good, "ticket": "https://user:" + "pw" + "@t.example/1"}),
        "ticket no host": _doc({**good, "ticket": "https:///x"}),
    }
    p = tmp_path / "t.json"
    for name, text in cases.items():
        p.write_text(text, encoding="utf-8")
        with pytest.raises(triage.TriageError) as err:
            triage.load(p)
        assert err.value.key == "e_malformed", name
        assert triage.main(["--file", str(p), "stats"]) == 2, name

    # year-1 timestamps with an offset used to raise OverflowError out of stats()/merge()
    p.write_text(_doc({**good, "first_seen": "0001-01-01T00:00:00+05:00", "fixed_at": "9999-12-31T23:59:59-05:00",
                       "updated": "0001-01-01T00:00:00+05:00"}), encoding="utf-8")
    t = triage.load(p)
    triage.stats(t)
    triage.merge(t, t)
    assert triage.apply([{"fingerprint": "0123456789abcdef:0", "severity": "high"}], t).counts == {"open": 1}


def test_control_characters_in_a_hostile_file_never_reach_the_terminal(tmp_path, capsys):
    esc, rlo = "\x1b[31m", "‮"
    fp = "0123456789abcdef:0"
    entry = {"status": "false_positive", "justification": f"ok{esc}{rlo}", "author": f"eve{esc}", "rule": f"R{esc}",
             "file": f"a{rlo}.py", "title": f"t{esc}", "updated": f"2026-01-01T00:00:00Z{esc}",
             "log": [{"at": f"x{esc}", "author": f"eve{esc}", "action": f"status{esc}", f"k{esc}": f"v{rlo}"}]}
    p = tmp_path / "t.json"
    p.write_text(_doc(entry), encoding="utf-8")
    loaded = triage.load(p)
    assert "\x1b" not in triage.dumps(loaded) and rlo not in triage.dumps(loaded)
    for argv in (["list"], ["show", fp], ["stats"], ["list", "--json"], ["show", fp, "--json"]):
        assert triage.main(["--file", str(p), *argv]) == 0
        out = capsys.readouterr()
        assert "\x1b" not in out.out + out.err and rlo not in out.out + out.err, argv
    src = (tmp_path / "s").resolve()
    src.mkdir()
    (src / "a.py").write_text("x = 1  # no" + f"sec {esc}{rlo}\n", encoding="utf-8")
    found = triage.find_inline_suppressions(src)
    assert len(found) == 1 and "\x1b" not in found[0]["text"] and rlo not in found[0]["text"]
    # the module's own source carries no bidi-override characters (they are written as escapes)
    source = open(triage.__file__, encoding="utf-8").read()
    assert not triage._CONTROL.search(source)


def test_triage_file_must_be_a_regular_file(tmp_path):
    d = tmp_path / "triage.json"
    d.mkdir()
    with pytest.raises(triage.TriageError):
        triage.load(d)
    if os.path.exists("/dev/zero"):                              # symlink to an endless device: refused, not read
        link = tmp_path / "zero.json"
        try:
            os.symlink("/dev/zero", link)
        except OSError:
            return
        with pytest.raises(triage.TriageError):
            triage.load(link)
        assert triage.main(["--file", str(link), "list"]) == 2
        with pytest.raises(triage.TriageError):
            triage.import_baseline(triage.new_triage(), link, author="sara")
        assert triage.main(["--file", str(tmp_path / "ok.json"), "sync", "--report", str(link)]) == 2


def test_fingerprints_are_validated_everywhere(tmp_path, three):
    t = triage.new_triage()
    for bad in ("", "x y", "a\nb", "../../etc", "é", "a" * 200, None, 5):
        with pytest.raises(triage.TriageError) as err:
            triage.set_status(t, bad, "confirmed", author="sara", now=T0)
        assert err.value.key == "e_fp_invalid"
        with pytest.raises(triage.TriageError):
            triage.sync([{"fingerprint": bad or "x y"}], triage.new_triage(), T0)
    assert t["findings"] == {}
    bl = tmp_path / "bl.json"
    bl.write_text(json.dumps({"fingerprints": [{"fp": "bad key\n"}, {"fp": three[0].fingerprint()}, {"fp": 7}, "x"]}),
                  encoding="utf-8")
    assert triage.import_baseline(t, bl, author="sara", now=T0) == {"added": 1, "skipped": 0}
    triage.loads(triage.dumps(t))                                # what we write, we can read back
    report = tmp_path / "r.json"
    report.write_text(json.dumps([{"fingerprint": "bad key"}]), encoding="utf-8")
    assert triage.main(["--file", str(tmp_path / "t.json"), "sync", "--report", str(report)]) == 2
    assert not (tmp_path / "t.json").exists()


def test_ticket_urls():
    t = triage.new_triage()
    fp = "0123456789abcdef:0"
    for bad in ("javascript:alert(1)", "ftp://x/1", "https://", "https://a b", "https://x/\\y", "https://x/\x07",
                "https://u:" + "p" + "@x/1", "https://x/<script>", "HTTP://x", "https://x/" + "a" * 2000):
        with pytest.raises(triage.TriageError) as err:
            triage.set_status(t, fp, "confirmed", author="sara", ticket=bad, now=T0)
        assert err.value.key == "e_ticket", bad
    assert t["findings"] == {}
    for ok in ("https://tracker.example/SEC-7", "http://jira.local:8080/browse/A-1?x=1&y=@me#c"):
        assert triage.set_status(t, fp, "confirmed", author="sara", ticket=ok, now=T0)["ticket"] == ok


def test_policy_ceiling_cannot_be_bypassed_by_omitting_the_expiry():
    t = triage.new_triage()
    fp = "0123456789abcdef:0"
    with pytest.raises(triage.TriageError) as err:
        triage.set_status(t, fp, "accepted_risk", author="sara", justification="j", now=T0, max_accept_days=90)
    assert err.value.key == "e_expires_required" and "90" in err.value.message("ar")
    with pytest.raises(triage.TriageError):
        triage.set_status(t, fp, "accepted_risk", author="sara", justification="j", now=T0, max_accept_days=90,
                          expires="+91d")
    triage.set_status(t, fp, "accepted_risk", author="sara", justification="j", now=T0, max_accept_days=90,
                      expires="+90d")
    triage.set_status(t, fp, "confirmed", author="sara", now=T0, max_accept_days=90)       # other statuses: no expiry


def test_apply_is_idempotent_and_accepts_show_as_text(three):
    t = triage.new_triage()
    triage.sync(three, t, T0)
    a, b = three[0].fingerprint(), three[1].fingerprint()
    triage.override_severity(t, a, "low", reason="internal only", author="sara", now=T0)
    triage.set_status(t, b, "false_positive", author="sara", justification="constant", now=T0)
    dicts = [f.to_dict() for f in three]
    for _ in range(2):                                           # the second pass must not lose the original
        for items in (three, dicts):
            triage.apply(items, t, T0)
            first = items[0]
            info = first["extra"]["triage"] if isinstance(first, dict) else first.extra["triage"]
            assert info["severity_original"] == "high" and info["severity_reason"] == "internal only"
    assert three[0].severity == "low" and dicts[0]["severity"] == "low" and dicts[0]["severity_ar"] != "عالية"
    assert dicts[0]["severity_ar"] == three[0].to_dict()["severity_ar"]
    triage.sync(three, t, T0)
    assert t["findings"][a]["severity"] == "high"                # the scanner's severity stays on record
    triage.override_severity(t, a, None, author="sara", now=T0)
    triage.apply(three, t, T0)
    assert three[0].severity == "high" and "severity_original" not in three[0].extra["triage"]

    assert len(triage.apply(three, t, T0, show="all").visible) == 3
    assert len(triage.apply(three, t, T0, show="false_positive").visible) == 1
    assert len(triage.apply(three, t, T0, show="open, confirmed").visible) == 2


def test_sla_breach_is_counted_in_whole_days():
    t = triage.new_triage()
    f = scan(mk("R1", "critical"))
    triage.sync(f, t, T0)
    assert triage.stats(t, day(7.5))["sla"]["breaches"] == []    # day 7 of a 7-day SLA is not overdue yet
    assert triage.stats(t, day(8))["sla"]["breaches"][0]["overdue_days"] == 1


def test_save_keeps_permissions_and_update_takes_a_lock(tmp_path, three):
    path = tmp_path / ".kashif" / "triage.json"
    t = triage.new_triage()
    triage.sync(three, t, T0)
    triage.save(t, path)
    if os.name == "posix":
        umask = os.umask(0)
        os.umask(umask)
        assert path.stat().st_mode & 0o777 == 0o666 & ~umask     # not mkstemp's 0600: teammates / CI can read it
        os.chmod(path, 0o640)
        triage.update(path, lambda tri: triage.add_comment(tri, three[0].fingerprint(), "c", author="s", now=T0))
        assert path.stat().st_mode & 0o777 == 0o640
    lock = path.with_name("triage.json.lock")
    lock.write_text("", encoding="utf-8")                        # another process holds the lock
    real = triage._locked
    with pytest.raises(triage.TriageError) as err:
        with real(path, timeout=0.2):
            pass
    assert err.value.key == "e_locked" and lock.exists()
    os.utime(lock, (1, 1))                                       # a lock left by a crashed process is taken over
    triage.update(path, lambda tri: triage.add_comment(tri, three[0].fingerprint(), "d", author="s", now=T0))
    assert sorted(p.name for p in path.parent.iterdir()) == ["triage.json"]

    fresh = tmp_path / "new" / ".kashif" / "triage.json"         # a rejected first edit leaves no empty directory
    with pytest.raises(triage.TriageError):
        triage.update(fresh, lambda tri: triage.set_status(tri, "0123456789abcdef:0", "wont_fix", author="s"))
    assert not fresh.parent.exists()


def test_concurrent_updates_do_not_lose_edits(tmp_path, three):
    import threading
    path = tmp_path / "triage.json"
    fp = three[0].fingerprint()
    errors = []

    def work(n: int) -> None:
        try:
            for i in range(10):
                triage.update(path, lambda tri: triage.add_comment(tri, fp, f"w{n}-{i}", author=f"u{n}", now=T0))
        except Exception as exc:                                 # noqa: BLE001 - reported below
            errors.append(exc)

    threads = [threading.Thread(target=work, args=(n,)) for n in range(4)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert not errors
    assert len(triage.load(path)["findings"][fp]["log"]) == 40


def test_merge_is_symmetric_for_unknown_top_level_keys(three):
    a, b = triage.new_triage(), triage.new_triage()
    a["note"], b["note"], b["team"] = "ours", "theirs", "appsec"
    assert triage.dumps(triage.merge(a, b)[0]) == triage.dumps(triage.merge(b, a)[0])
    assert triage.merge(a, b)[0]["team"] == "appsec"


def test_decision_changes_flag_what_a_pull_request_could_hide(tmp_path, three, capsys):
    base = triage.new_triage()
    triage.sync(three, base, T0)
    a, b, c = (f.fingerprint() for f in three)
    triage.set_status(base, c, "accepted_risk", author="sara", justification="waf", expires="+30d", now=T0)
    triage.add_comment(base, b, "history", author="sara", now=T0)
    assert triage.decision_changes(base, json.loads(triage.dumps(base))) == []

    head = json.loads(triage.dumps(base))
    triage.set_status(head, a, "false_positive", author="mallory", justification="trust me", now=day(1))
    triage.override_severity(head, b, "info", reason="meh", author="mallory", now=day(1))
    triage.set_status(head, c, "accepted_risk", author="mallory", justification="waf", expires="+300d", now=day(1))
    head["findings"][b]["log"] = [i for i in head["findings"][b]["log"] if i.get("text") != "history"]
    head["findings"]["0123456789abcdef:0"] = {"status": "wont_fix", "justification": "new and already hidden"}
    kinds = {(ch["fingerprint"], ch["kind"]) for ch in triage.decision_changes(base, head)}
    assert kinds == {(a, "suppressed"), (b, "severity_lowered"), (b, "log_removed"), (c, "expiry_extended"),
                     ("0123456789abcdef:0", "suppressed")}
    del head["findings"][a]
    assert (a, "entry_removed") in {(ch["fingerprint"], ch["kind"]) for ch in triage.decision_changes(base, head)}

    benign = json.loads(triage.dumps(base))                      # confirming, commenting, raising severity: no alarm
    triage.set_status(benign, a, "confirmed", author="sara", now=day(1))
    triage.add_comment(benign, b, "more", author="sara", now=day(1))
    triage.override_severity(benign, b, "critical", reason="worse", author="sara", now=day(1))
    assert triage.decision_changes(base, benign) == []

    bp, hp = tmp_path / "base.json", tmp_path / "head.json"
    triage.save(base, bp)
    triage.save(head, hp)
    assert triage.main(["--file", str(hp), "diff", str(bp)]) == 0
    assert "mallory" in capsys.readouterr().out
    assert triage.main(["--file", str(hp), "diff", str(bp), "--fail-on-change", "--lang", "ar", "--json"]) == 1
    assert len(json.loads(capsys.readouterr().out)["changes"]) == 5
    assert triage.main(["--file", str(bp), "diff", str(bp), "--fail-on-change"]) == 0
    assert triage.main(["--file", str(hp), "diff", str(tmp_path / "absent.json"), "--fail-on-change"]) == 1


def test_cli_reports_io_errors_and_bad_dates_without_a_traceback(tmp_path, capsys):
    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    target = blocker / "sub" / "triage.json"                     # parent is a file: cannot be created
    assert triage.main(["--file", str(target), "set", "0123456789abcdef:0", "confirmed", "--author", "s"]) == 2
    assert triage.main(["--file", str(tmp_path / "t.json"), "list", "--now", "yesterday"]) == 2
    assert "Traceback" not in capsys.readouterr().err


# --------------------------------------------------------------------- second adversarial review pass

FP = "0123456789abcdef:0"


def test_unknown_status_in_show_fails_instead_of_hiding_everything(three):
    t = triage.new_triage()
    for bad in ("opn", "open,confirmd", ("open", "nope")):
        with pytest.raises(triage.TriageError) as err:
            triage.apply(three, t, T0, show=bad)
        assert err.value.key == "e_status"
    assert len(triage.apply(three, t, T0, show="all").visible) == 3


def test_new_severity_override_cannot_hide_behind_a_forged_context_severity():
    # A pull request adds a brand-new entry claiming the scanner said "info" and overrides it to "info".
    head = {"schema": triage.SCHEMA, "findings": {FP: {
        "status": "open", "severity": "info",
        "severity_override": {"severity": "info", "reason": "r", "author": "eve", "at": "2026-01-01T00:00:00Z"}}}}
    kinds = [c["kind"] for c in triage.decision_changes(triage.new_triage(), head)]
    assert kinds == ["severity_lowered"]
    # the base's recorded severity is trusted: raising it is not a finding to review
    base = {"schema": triage.SCHEMA, "findings": {FP: {"status": "open", "severity": "low"}}}
    head["findings"][FP]["severity_override"]["severity"] = "high"
    assert triage.decision_changes(base, head) == []
    # nothing known, override to the top severity: cannot be a lowering
    head["findings"][FP]["severity_override"]["severity"] = "critical"
    assert triage.decision_changes(triage.new_triage(), head) == []


def test_findings_with_a_malformed_extra_do_not_crash(three):
    t = triage.new_triage()
    hostile = [{"fingerprint": FP, "severity": "high", "extra": "text"},
               {"fingerprint": "fedcba9876543210:0", "severity": "low", "extra": {"triage": ["x"]}}]
    assert len(triage.sync(hostile, t, T0).new) == 2
    res = triage.apply(hostile, t, T0)
    assert len(res.visible) == 2 and all(f["extra"]["triage"]["tracked"] for f in hostile)


def test_fingerprint_keys_resolve_whatever_their_case():
    t = {"schema": triage.SCHEMA, "findings": {"ABCDEF-other-tool": {"status": "open"}}}
    assert triage.resolve_fingerprint(t, "ABCDEF-other-tool") == "ABCDEF-other-tool"
    assert triage.resolve_fingerprint(t, " " + FP.upper()) == FP


def test_show_keeps_hostile_log_fields_on_one_line(tmp_path, capsys):
    p = tmp_path / "t.json"
    p.write_text(json.dumps({"schema": triage.SCHEMA, "findings": {FP: {
        "status": "open", "log": [{"at": "2026\nFAKE fixed", "author": "a", "action": "x\ny"}]}}}), encoding="utf-8")
    assert triage.main(["--file", str(p), "show", FP]) == 0
    out = capsys.readouterr().out
    assert "2026 FAKE fixed" in out and "x y" in out and "\nFAKE" not in out


def test_inline_listing_masks_literals_and_knows_where_ignore_file_counts(tmp_path):
    value = "hunter" + "2" * 6                                   # built at run time (see test_no_secret_literals)
    (tmp_path / "a.py").write_text(f'pw = "{value}"  # nosec\nx = "ab"  # nosec\n', encoding="utf-8")
    (tmp_path / "b.py").write_text("# vulnscan: ignore-file\n" + "#\n" * 1500 + "# vulnscan: ignore-file\n",
                                   encoding="utf-8")
    found = triage.find_inline_suppressions(tmp_path)
    texts = [i["text"] for i in found if i["file"] == "a.py"]
    assert value not in " ".join(texts) and 'pw = "hu***"' in texts[0] and '"ab"' in texts[1]
    assert [i["kind"] for i in found if i["file"] == "b.py"] == ["file", "line"]
