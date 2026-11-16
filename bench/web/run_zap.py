"""Run OWASP ZAP's passive scanner on the Kashif corpus as a baseline (spec §5.5). PASSIVE ONLY.

    python bench/web/run_zap.py --zap /opt/ZAP_2.17.0 -o bench/web/results/zap-2.17.0.json
    python bench/web/score.py bench/web/results/1.1.0.json --zap bench/web/results/zap-2.17.0.json

ZAP cannot use Kashif's test-only resolver hook, so the corpus is served in *prefix* mode: every case is
``http(s)://127.0.0.1:<port>/_case/<id>/…`` and alerts are attributed to cases by that path. Cases that need real host
names (cookie Domain, cross-host redirects, DNS), TLS-only cases (ZAP has no passive TLS rules) and deep/third-party cases
are excluded from the ZAP column and marked as such (``zap: false`` in labels.json). The C-HOSTILE group tests Kashif's own
robustness (decompression bomb, slow drip, …) and is not sent to ZAP.

ZAP runs headless with ``-cmd -silent`` (no update checks or other unsolicited requests) and a throw-away home directory
(``-dir``). The plan (zap-plan.yaml) has only passiveScan-config, requestor, passiveScan-wait and report; this script refuses
to run a plan that contains an active-scan, spider or fuzz job.

When ZAP or Java is missing the script says so, writes a results file with ``"status": "skipped"`` and exits 0 (or 2 with
``--require``): a missing baseline is never reported as a result.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import corpus  # noqa: E402

HERE = pathlib.Path(__file__).resolve().parent
PLAN_TEMPLATE = HERE / "zap-plan.yaml"
ZAP_VERSION = "2.17.0"
FORBIDDEN_JOBS = ("activeScan", "activeScan-config", "activeScan-policy", "spider", "spiderAjax", "fuzz", "openapi",
                  "graphql", "soap", "postman")

# ZAP alert id (+ alertRef suffix) -> Kashif rules, verified against the ZAP pscanrules sources (zap-pscan-rules.md).
ZAP_MAP: dict[str, list[str]] = {
    "10035-1": ["WEB-strict-transport-security"], "10035-2": ["WEB110"], "10035-3": ["WEB113"], "10035-4": ["WEB116"],
    "10035-5": ["WEB112"], "10035-6": ["WEB116"], "10035-7": ["WEB112"], "10035-8": ["WEB112"],
    "10038-1": ["WEB-content-security-policy"], "10038-2": ["WEB217"], "10038-3": ["WEB200"],
    "10055-1": ["WEB217"], "10055-2": ["WEB217"], "10055-3": ["WEB201"], "10055-5": ["WEB040"], "10055-6": ["WEB214"],
    "10055-7": ["WEB210"], "10055-9": ["WEB201"], "10055-10": ["WEB041"], "10055-11": ["WEB207"],
    "10020-1": ["WEB-x-frame-options"], "10020-2": ["WEB301"], "10020-3": ["WEB302"], "10020-4": ["WEB300"],
    "10010": ["WEB021"], "10011": ["WEB020"], "10054-1": ["WEB022"], "10054-2": ["WEB407"], "10054-3": ["WEB402"],
    "90033": ["WEB404"], "10098": ["WEB323", "WEB327"], "90003": ["WEB053"], "10017": ["WEB053"], "10040": ["WEB050"],
    "10042": ["WEB051"], "10041": ["WEB504"], "10105-1": ["WEB118"], "10105-2": ["WEB118"], "10033": ["WEB055"],
    "90022": ["WEB056", "WEB605", "WEB606"], "10023": ["WEB056", "WEB605", "WEB606"], "10009": ["WEB616"],
    "10036-2": ["WEB010"], "10037": ["WEB011"], "10061": ["WEB600"], "10039": ["WEB600"], "10052": ["WEB601"],
    "10056": ["WEB601"], "10034": ["WEB615"], "20020": ["WEB800"], "2": ["WEB603"], "3": ["WEB510"], "10097": ["WEB612"],
    "10062": ["WEB613"], "10044": ["WEB106"], "10015": ["WEB315"], "10019": ["WEB313"], "90011": ["WEB314"],
    "10108": ["WEB505"], "10115": ["WEB506"], "10032": ["WEB611"], "90001": ["WEB611"], "90002": ["WEB610"],
    "10063-1": ["WEB-permissions-policy"], "10063-2": ["WEB307"], "90004-1": ["WEB310"], "90004-2": ["WEB309"],
    "90004-3": ["WEB308"], "10099": ["WEB608"], "110009": ["WEB607"], "10003": ["WEB054"],
}
# 10055-4 ("wildcard directive") names the directives in its text: map each to the Kashif rule for that directive.
WILDCARD_DIRECTIVES = {"script-src": "WEB042", "object-src": "WEB043", "frame-ancestors": "WEB206",
                       "form-action": "WEB205", "base-uri": "WEB204"}
COVERS = sorted({r for rules in ZAP_MAP.values() for r in rules} | set(WILDCARD_DIRECTIVES.values()))


def map_alert(alert: dict, instance: dict) -> list[str]:
    pid = str(alert.get("pluginid", ""))
    ref = str(alert.get("alertRef") or pid)
    if ref == "10055-4" or (pid == "10055" and ref == "10055-4"):
        text = " ".join(str(x) for x in (instance.get("otherinfo"), alert.get("otherinfo"), instance.get("evidence"),
                                         alert.get("desc")) if x)
        return sorted({rule for d, rule in WILDCARD_DIRECTIVES.items() if d in text}) or ["WEB042"]
    if pid == "10021":
        return ["WEB303"] if (instance.get("evidence") or "").strip() else ["WEB-x-content-type-options"]
    return ZAP_MAP.get(ref) or ZAP_MAP.get(pid) or []


def plan_problems(text: str) -> list[str]:
    """Jobs a passive-only plan must not contain."""
    jobs = re.findall(r"^\s*-\s*type:\s*([A-Za-z-]+)", text, re.M)
    return [j for j in jobs if j in FORBIDDEN_JOBS or j.lower().startswith(("active", "spider", "fuzz"))]


def find_zap(explicit: str | None) -> tuple[list[str] | None, str]:
    """The ZAP launcher command, or (None, reason)."""
    cands = [explicit, os.environ.get("ZAP_HOME"), shutil.which("zap.sh") and str(pathlib.Path(shutil.which("zap.sh")).parent)]
    for c in cands:
        if not c:
            continue
        d = pathlib.Path(c)
        launcher = d / ("zap.bat" if os.name == "nt" else "zap.sh")
        if d.is_file():
            launcher, d = d, d.parent
        if launcher.is_file():
            if not shutil.which("java"):
                return None, "Java (21+) not found on PATH; ZAP needs it"
            return ([str(launcher)] if os.name == "nt" else ["sh", str(launcher)]), str(d)
    return None, ("ZAP not found: pass --zap DIR (the unpacked ZAP_2.17.0_Crossplatform.zip) or set ZAP_HOME; "
                  "Docker (ghcr.io/zaproxy/zaproxy:2.17.0) works too, see bench/web/README.md")


def zap_cases(srv: corpus.CorpusServer) -> list[corpus.Case]:
    return [c for c in srv.cases if c.zap and c.group != "C-HOSTILE" and c.profile != "deep" and not c.use_proxy and not c.dns and not c.aliases
            and not c.extra_hosts and not c.url_host and not srv.missing(c)]


def request_urls(srv: corpus.CorpusServer, c: corpus.Case) -> list[str]:
    """The entry URL plus, like a browser, a same-case redirect target and (crawl cases) the linked pages."""
    urls = [srv.url(c)]
    entry = c.routes.get(c.path)
    if isinstance(entry, corpus.R):
        loc = dict((k.lower(), v) for k, v in entry.headers).get("location", "")
        if loc.startswith("/") and loc in c.routes:
            urls.append(srv.origin(c, c.scheme) + loc)
    if c.crawl:
        urls += [srv.origin(c, c.scheme) + p for p, r in c.routes.items() if p.startswith("/") and p != c.path
                 and isinstance(r, corpus.R)]
    return urls


def build_plan(srv: corpus.CorpusServer, cases: list[corpus.Case], report_dir: pathlib.Path) -> str:
    text = PLAN_TEMPLATE.read_text(encoding="utf-8")
    origins = sorted({f"http://127.0.0.1:{srv.http_port}"} | ({f"https://127.0.0.1:{srv.https_port}"} if srv.https_port
                                                               else set()))
    ctx = "\n".join(f"        - {o}/" for o in origins)
    inc = "\n".join(f'        - "{re.escape(o)}/.*"' for o in origins)
    reqs = []
    for c in cases:
        for u in request_urls(srv, c):
            reqs.append(f'      - url: "{u}"\n        method: GET\n        name: "{c.id}"')
    text = (text.replace("@CONTEXT_URLS@", ctx).replace("@INCLUDE_PATHS@", inc).replace("@REQUESTS@", "\n".join(reqs))
            .replace("@REPORT_DIR@", str(report_dir).replace("\\", "/")))
    return text


def parse_report(report: dict, case_ids: set[str]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {c: [] for c in case_ids}
    seen = set()
    for site in report.get("site", []) or []:
        for alert in site.get("alerts", []) or []:
            for inst in alert.get("instances", []) or [{}]:
                m = re.search(r"/_case/([a-z0-9-]+)(/|$)", inst.get("uri", ""))
                if not m or m.group(1) not in out:
                    continue
                for rule in map_alert(alert, inst):
                    key = (m.group(1), rule, alert.get("alertRef") or alert.get("pluginid"))
                    if key in seen:
                        continue
                    seen.add(key)
                    out[m.group(1)].append({"rule": rule, "severity": _risk(alert.get("riskcode")),
                                            "confidence": f"zap:{alert.get('confidence', '')}", "instances": 1,
                                            "urls": [inst.get("uri", "")], "curl": [],
                                            "title": f"{alert.get('alertRef') or alert.get('pluginid')} {alert.get('name', '')}"})
    return out


def _risk(code) -> str:
    return {"0": "info", "1": "low", "2": "medium", "3": "high"}.get(str(code), "info")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="ZAP passive baseline on the Kashif corpus (no active scan).")
    ap.add_argument("--zap", help="ZAP installation directory (contains zap.sh / zap.bat) or the launcher itself")
    ap.add_argument("-o", "--out", default=str(HERE / "results" / f"zap-{ZAP_VERSION}.json"))
    ap.add_argument("--require", action="store_true", help="exit 2 instead of 0 when ZAP cannot run here")
    ap.add_argument("--plan-only", help="write the generated plan to this file and exit (no ZAP needed)")
    ap.add_argument("--timeout", type=float, default=1800)
    ap.add_argument("--keep", help="keep ZAP's raw report and log in this directory")
    a = ap.parse_args(argv)
    launcher, where = (None, "") if a.plan_only else find_zap(a.zap)
    if not a.plan_only and launcher is None:
        doc = {"schema": 1, "tool": "zap", "status": "skipped", "reason": where, "cases": {}}
        pathlib.Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(a.out).write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8", newline="\n")
        print(f"ZAP comparison skipped: {where}", file=sys.stderr)
        return 2 if a.require else 0
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="kashif-zap-"))
    srv = corpus.CorpusServer(mode="prefix").start()
    try:
        cases = zap_cases(srv)
        plan = build_plan(srv, cases, tmp / "report")
        bad = plan_problems(plan)
        if bad:
            raise SystemExit(f"refusing to run a plan with non-passive jobs: {bad}")
        if a.plan_only:
            pathlib.Path(a.plan_only).write_text(plan, encoding="utf-8", newline="\n")
            print(f"wrote {a.plan_only} ({len(cases)} cases)", file=sys.stderr)
            return 0
        plan_file = tmp / "plan.yaml"
        plan_file.write_text(plan, encoding="utf-8", newline="\n")
        (tmp / "report").mkdir()
        env = {k: v for k, v in os.environ.items() if k.lower() not in ("http_proxy", "https_proxy", "all_proxy")}
        cmd = launcher + ["-cmd", "-silent", "-dir", str(tmp / "home"), "-autorun", str(plan_file)]
        t0 = time.monotonic()
        p = subprocess.run(cmd, cwd=where, env=env, capture_output=True, timeout=a.timeout, check=False,
                           encoding="utf-8", errors="replace")
        elapsed = round(time.monotonic() - t0, 1)
        report_path = tmp / "report" / "zap-report.json"
        if a.keep:
            k = pathlib.Path(a.keep)
            k.mkdir(parents=True, exist_ok=True)
            (k / "zap-stdout.txt").write_text(p.stdout + "\n" + p.stderr, encoding="utf-8")
            (k / "plan.yaml").write_text(plan, encoding="utf-8")
            if report_path.is_file():
                shutil.copy(report_path, k / "zap-report.json")
        if not report_path.is_file():
            raise SystemExit(f"ZAP produced no report (exit {p.returncode}): {(p.stdout + p.stderr)[-1500:]}")
        report = json.loads(report_path.read_text(encoding="utf-8"))
        ids = {c.id for c in cases}
        per_case = parse_report(report, ids)
        doc = {"schema": 1, "tool": "zap", "version": report.get("@version", ZAP_VERSION), "mode": "prefix",
               "elapsed": elapsed, "exit": p.returncode, "covers": COVERS, "case_filter": sorted(ids),
               "violations": srv.violations,
               "excluded": {c.id: (c.zap_note or "needs host names, TLS, DNS, a proxy or the deep profile")
                            for c in srv.cases if c.id not in ids},
               "cases": {cid: {"status": "ran", "exit": 0, "findings": per_case[cid]} for cid in sorted(ids)}}
        pathlib.Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(a.out).write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8", newline="\n")
        print(f"ZAP {doc['version']}: {len(ids)} cases, {sum(len(v) for v in per_case.values())} mapped alerts, "
              f"{elapsed} s; non-GET requests seen: {len(srv.violations)}", file=sys.stderr)
        return 0
    finally:
        srv.stop()
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
