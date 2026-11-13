"""Run Kashif on every corpus case through its command line and record what it reported (spec §5.2, §5.3, §5.7).

Kashif is driven only through the CLI JSON output (``kashif URL --authorized -f json``), one process per case, so the scan
is exactly what a user runs. The corpus servers record every request, which gives the politeness facts of §5.7 (request
counts per profile, gaps, headers, methods, the cookieless CORS GET, no random-path baseline in ``standard``).

Two modes:

* default (Kashif 1.1+): case host names through the test-only resolver hook (``KASHIF_TEST_RESOLVE=1``,
  ``KASHIF_TEST_RESOLVE_MAP=<json>``, ``KASHIF_TEST_CAFILE=<test root CA>``), the 1.1 options (``--web-profile``,
  ``--web-sensitivity``, ``--no-proxy``…), cases in parallel;
* ``--legacy`` (Kashif 1.0.x, e.g. the 1.0.2 baseline): no hook exists, so cases are served one at a time on
  ``127.0.0.1`` and the test root CA is trusted through ``SSL_CERT_FILE``; cases that need host names are skipped.

Usage::

    python bench/web/run_kashif.py -o bench/web/results/1.1.0.json
    python bench/web/run_kashif.py --legacy --root /path/to/kashif-1.0.2 -o bench/web/results/1.0.2-legacy.json
    python bench/web/score.py bench/web/results/1.1.0.json --min-score bench/web/min-score.json

No request leaves the machine: every name resolves to 127.0.0.1 through the hook (unknown names too), proxies are
removed from the environment, and a preflight case must reach the local server before any other case runs.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as _dt
import json
import os
import pathlib
import platform
import re
import shlex
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import corpus  # noqa: E402
import tls_servers  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
ALLOWED_REQUEST_HEADERS = {"host", "user-agent", "accept", "accept-encoding", "accept-language", "origin", "cookie",
                           "connection"}
PROFILE_CAPS = {"minimal": 10, "standard": 45, "deep": 150}          # spec §0.1 (crawl pages come on top)
PROXY_VARS = ("http_proxy", "https_proxy", "all_proxy", "no_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")
PREFLIGHT_CASE = "csp-strict-good"
_LAUNCHER = ("import atexit, runpy, sys\n"
             "def _rss():\n"
             "    try:\n"
             "        import resource\n"
             "        kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss\n"
             "        kb = kb // 1024 if sys.platform == 'darwin' else kb\n"
             "        sys.stderr.write(f'\\nKASHIF_CORPUS_MAXRSS_KB={kb}\\n')\n"
             "    except Exception:\n"
             "        pass\n"
             "atexit.register(_rss)\n"
             "sys.argv = ['vulnscan'] + sys.argv[1:]\n"
             "runpy.run_module('vulnscan', run_name='__main__', alter_sys=True)\n")


def _urls(obj, out: set) -> None:
    if isinstance(obj, str):
        if obj.startswith(("http://", "https://")):
            out.add(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _urls(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _urls(v, out)


def _curls(obj, out: list) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "curl" and isinstance(v, str):
                out.append(v)
            else:
                _curls(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _curls(v, out)


def shell_safe(cmd: str) -> bool:
    """True when no shell metacharacter of ``cmd`` is live: each sits inside single quotes, or is a quote inside double
    quotes (shlex.quote writes a literal ' as '"'"')."""
    try:
        shlex.split(cmd)
    except ValueError:
        return False
    state = ""                                   # "" outside, "'" in single quotes, '"' in double quotes
    for ch in cmd:
        if state == "'":
            state = "" if ch == "'" else state
        elif state == '"':
            if ch in "$`\\":
                return False
            state = "" if ch == '"' else state
        elif ch in "'\"":
            state = ch
        elif ch in "$`;|&<>()\n\\!*?{}[]#~":
            return False
    return state == ""


def summarize_findings(data: dict) -> list[dict]:
    out = []
    for f in data.get("findings", []):
        extra = f.get("extra") or {}
        urls: set = set()
        _urls(extra, urls)
        if isinstance(f.get("file"), str):
            _urls(f["file"], urls)
        curls: list = []
        _curls(extra, curls)
        out.append({"rule": f.get("rule_id", ""), "severity": f.get("severity", ""),
                    "confidence": extra.get("confidence", ""), "title": (f.get("title") or "")[:200],
                    "instances": extra.get("instances", 1) if isinstance(extra.get("instances", 1), int) else 1,
                    "urls": sorted(urls)[:20], "curl": curls[:10], "file": f.get("file", "")})
    return out


def compact(res: dict, c: corpus.Case) -> dict:
    """Keep committed result files small: stderr only when it matters, at most 60 request paths."""
    keep_stderr = res.get("status") != "ran" or res.get("traceback") or res.get("exit") not in (0, 1) \
        or c.expect.get("stderr_absent")
    if not keep_stderr:
        res.pop("stderr_tail", None)
    if "traffic" in res:
        res["traffic"]["paths"] = res["traffic"]["paths"][:60]
    return res


def traffic(srv: corpus.CorpusServer, c: corpus.Case, legacy: bool, delay: float = 0.2) -> dict:
    recs = sorted(srv.requests_for(c.id), key=lambda r: r.t)
    by_host: dict[str, list] = {}
    violations = []
    for r in recs:
        h = dict((k.lower(), v) for k, v in r.headers)
        by_host.setdefault(h.get("host", "?").lower(), []).append(r.t)
        if legacy:
            continue
        extra = sorted(set(h) - ALLOWED_REQUEST_HEADERS)
        if extra:
            violations.append(f"unexpected request headers {extra} on {r.path}")
        ua = h.get("user-agent", "")
        if not ua.startswith("Kashif/"):
            violations.append(f"User-Agent is not the honest Kashif UA: {ua[:80]!r}")
        if "origin" in h:
            if h["origin"] != corpus.CORS_PROBE_ORIGIN:
                violations.append(f"unexpected Origin {h['origin']!r}")
            if "cookie" in h:
                violations.append("the CORS GET carried the scan's cookies (§0.1)")
        if "/kashif-404-" in r.path and c.profile != "deep":
            violations.append(f"random-path baseline in profile {c.profile}: {r.path}")
    gaps = []
    for times in by_host.values():
        gaps += [b - a for a, b in zip(times, times[1:])]
    if not legacy and gaps and min(gaps) < 0.9 * delay:
        violations.append(f"two requests to one host {min(gaps):.3f} s apart (delay {delay} s, §4.3)")
    entry = [r.t for r in recs if r.path.split("?")[0] == c.path]
    cap = PROFILE_CAPS[c.profile] + (c.max_pages if c.crawl else 0)
    if not legacy and len(recs) > cap:
        violations.append(f"{len(recs)} requests > budget {cap} for profile {c.profile}")
    return {"requests": len(recs), "paths": [r.path for r in recs][:200],
            "listeners": sorted({r.listener for r in recs}),
            "min_gap": round(min(gaps), 3) if gaps else None,
            "entry_gap": round(entry[1] - entry[0], 3) if len(entry) > 1 else None,
            "ip2_requests": sum(1 for r in recs if r.listener.endswith("ip2")),
            "violations": sorted(set(violations))}


class Runner:
    def __init__(self, args: argparse.Namespace):
        self.a = args
        self.legacy = args.legacy
        self.root = pathlib.Path(args.root).resolve() if args.root else ROOT
        self.python = args.python or sys.executable
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="kashif-corpus-run-"))
        self.lock = threading.Lock()

    # -------------------------------------------------------------- environment
    def base_env(self) -> dict:
        env = {k: v for k, v in os.environ.items() if k not in PROXY_VARS and not k.startswith("KASHIF_TEST_")}
        home = self.tmp / "home"
        home.mkdir(exist_ok=True)
        env.update({"HOME": str(home), "USERPROFILE": str(home), "APPDATA": str(home), "LOCALAPPDATA": str(home),
                    "XDG_CONFIG_HOME": str(home), "XDG_CACHE_HOME": str(home), "XDG_DATA_HOME": str(home),
                    "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1", "NO_COLOR": "1",
                    "PYTHONPATH": str(self.root) + os.pathsep + env.get("PYTHONPATH", "")})
        return env

    def version(self) -> str:
        try:
            p = subprocess.run([self.python, "-m", "vulnscan", "--version"], cwd=self.root, env=self.base_env(),
                               capture_output=True, text=True, timeout=60, check=False, encoding="utf-8", errors="replace")
            return (p.stdout or p.stderr).strip().splitlines()[-1] if (p.stdout or p.stderr).strip() else "?"
        except (OSError, subprocess.SubprocessError):
            return "?"

    def supports_11(self) -> bool:
        try:
            p = subprocess.run([self.python, "-m", "vulnscan", "--help"], cwd=self.root, env=self.base_env(),
                               capture_output=True, text=True, timeout=60, check=False, encoding="utf-8", errors="replace")
        except (OSError, subprocess.SubprocessError):
            return False
        return "--web-profile" in p.stdout

    def command(self, srv: corpus.CorpusServer, c: corpus.Case, out: pathlib.Path, prefix: pathlib.Path | None) -> list[str]:
        url = srv.url(c)
        head = [self.python, "-W", "default::DeprecationWarning"]
        head += ["-c", _LAUNCHER] if "max_rss_mb" in c.expect else ["-m", "vulnscan"]
        cmd = head + [url, "--authorized", "--no-color", "--timeout", str(self.a.timeout)]
        cmd += ["--all-formats", str(prefix)] if prefix else ["-f", "json", "-o", str(out)]
        if self.legacy:
            cmd += ["--deep"] if c.profile == "deep" else []
            if c.crawl:
                cmd += ["--crawl", "--max-pages", str(c.max_pages), "--max-depth", str(c.max_depth), "--delay", "0.2"]
            return cmd
        cmd += ["--web-profile", c.profile, "--web-sensitivity", c.sensitivity, "--delay", str(self.a.delay)]
        if c.crawl:
            cmd += ["--crawl", "--max-pages", str(c.max_pages), "--max-depth", str(c.max_depth)]
        if not c.use_proxy:
            cmd += ["--no-proxy"]
        return cmd + list(c.extra_args)

    def env_for(self, srv: corpus.CorpusServer, c: corpus.Case, d: pathlib.Path) -> dict:
        env = self.base_env()
        ca = str(srv.material.root) if srv.material else ""
        if self.legacy:
            if ca:
                env["SSL_CERT_FILE"] = ca
            return env
        rmap = d / "resolve.json"
        rmap.write_text(json.dumps(srv.resolver_map(c, ca or None), indent=1), encoding="utf-8")
        env.update({"KASHIF_TEST_RESOLVE": "1", "KASHIF_TEST_RESOLVE_MAP": str(rmap)})
        if ca:
            env["KASHIF_TEST_CAFILE"] = ca
        if c.use_proxy and srv.proxy is not None:
            proxy = f"http://127.0.0.1:{srv.proxy.server_address[1]}"
            env.update({"HTTP_PROXY": proxy, "HTTPS_PROXY": proxy, "http_proxy": proxy, "https_proxy": proxy})
        for k, v in c.env.items():
            env[k] = v
        return env

    # -------------------------------------------------------------- one case
    def run_case(self, srv: corpus.CorpusServer, c: corpus.Case) -> dict:
        missing = srv.missing(c)
        if self.legacy and not c.legacy:
            missing.append("legacy: needs the 1.1 resolver hook (host names)")
        if missing:
            return {"status": "skipped", "reason": "; ".join(missing)}
        d = self.tmp / c.id
        d.mkdir(parents=True, exist_ok=True)
        out = d / "out.json"
        prefix = d / "report" if c.expect.get("output_safe") else None
        cmd = self.command(srv, c, out, prefix)
        env = self.env_for(srv, c, d)
        if self.legacy:
            srv.set_active(c)
        t0 = time.monotonic()
        timeout = self.a.case_timeout + (60 if c.profile == "deep" else 0) + (60 if "slow" in c.requires else 0)
        try:
            p = subprocess.run(cmd, cwd=self.root, env=env, capture_output=True, timeout=timeout, check=False)
            code, stdout, stderr = p.returncode, p.stdout, p.stderr
        except subprocess.TimeoutExpired as e:
            code, stdout, stderr = None, e.stdout or b"", (e.stderr or b"") + b"\n[corpus] case timed out"
        elapsed = round(time.monotonic() - t0, 2)
        if self.legacy:
            time.sleep(0.3)                      # let stray requests of this case land before switching cases
            srv.set_active(None)
        else:
            time.sleep(0.05)
        so = stdout.decode("utf-8", "replace")
        se = stderr.decode("utf-8", "replace")
        res: dict = {"status": "ran", "exit": code, "elapsed": elapsed, "url": srv.url(c),
                     "traceback": "Traceback (most recent call last)" in se, "stderr_tail": self.clean(se[-1500:])}
        m = re.search(r"KASHIF_CORPUS_MAXRSS_KB=(\d+)", se)
        if m:
            res["max_rss_mb"] = round(int(m.group(1)) / 1024, 1)
        jpath = pathlib.Path(f"{prefix}.json") if prefix else out
        raw = ""
        data = None
        if jpath.is_file():
            raw = jpath.read_text(encoding="utf-8", errors="replace")
            try:
                data = json.loads(raw)
            except ValueError:
                data = None
        if data is None:
            res["status"] = "error"
            res["reason"] = "no JSON report" if not raw else "unparsable JSON report"
            data = {}
        res["findings"] = summarize_findings(data)
        res["web"] = {k: data.get("web", {}).get(k) for k in ("grades", "coverage")} if isinstance(data.get("web"), dict) else {}
        res["notes"] = [self.clean(str(n)) for n in (data.get("notes_en") or data.get("notes") or [])[:20]]
        low = raw.lower()
        res["contains"] = {n: n.lower() in low for n in c.expect.get("json_contains", [])}
        res["stderr_has"] = {n: n in se for n in c.expect.get("stderr_absent", [])}
        curls = [u for f in res["findings"] for u in f["curl"]]
        if c.expect.get("curl_quoted"):
            res["curl_checked"] = len(curls)
            res["curl_unsafe"] = [u for u in curls if not shell_safe(u)][:5]
        if prefix:
            res["output_safety"] = self.output_safety(prefix, so)
        res["traffic"] = traffic(srv, c, self.legacy, self.a.delay)
        if self.a.keep:
            keep = pathlib.Path(self.a.keep) / c.id
            keep.mkdir(parents=True, exist_ok=True)
            (keep / "report.json").write_text(raw, encoding="utf-8")
            (keep / "stderr.txt").write_text(se, encoding="utf-8")
        return compact(res, c)

    def clean(self, text: str) -> str:
        """Results files are committed: replace local paths with placeholders."""
        for path, tag in ((self.tmp, "<tmp>"), (self.root, "<root>"), (pathlib.Path.home(), "<home>")):
            text = text.replace(str(path), tag)
        return text

    @staticmethod
    def output_safety(prefix: pathlib.Path, console: str) -> dict:
        problems = []
        for ext in ("html", "md"):
            p = pathlib.Path(f"{prefix}.{ext}")
            if not p.is_file():
                problems.append(f"{ext} report missing")
                continue
            t = p.read_text(encoding="utf-8", errors="replace")
            if '<script>alert("kashif-xss")' in t:
                problems.append(f"raw target markup in the {ext} report")
            if "\x1b" in t:
                problems.append(f"ANSI escape in the {ext} report")
        if "\x1b" in console:
            problems.append("ANSI escape from the target reached the terminal")
        return {"ok": not problems, "problems": problems}

    # -------------------------------------------------------------- all cases
    def run(self) -> dict:
        cases = select(self.a)
        mode = "active" if self.legacy else "host"
        srv = corpus.CorpusServer(mode=mode, with_tls=not self.a.no_tls).start()
        started = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
        t0 = time.monotonic()
        results: dict = {}
        try:
            if not self.legacy and not self.supports_11():
                raise SystemExit("this Kashif has no 1.1 web options (--web-profile): run with --legacy for 1.0.x")
            if not self.legacy:
                pre = srv.by_id[PREFLIGHT_CASE]
                r = self.run_case(srv, pre)
                if r.get("status") != "skipped" and not srv.requests_for(pre.id):
                    raise SystemExit("preflight failed: Kashif did not reach the local corpus server through the "
                                     "resolver hook (KASHIF_TEST_RESOLVE); refusing to run cases with real-looking host "
                                     f"names. stderr: {r.get('stderr_tail', '')[-400:]}")
                if pre in cases:
                    results[pre.id] = r
            todo = [c for c in cases if c.id not in results]
            jobs = 1 if self.legacy else max(1, self.a.jobs)
            with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as ex:
                futs = {ex.submit(self.run_case, srv, c): c for c in todo}
                for i, fut in enumerate(concurrent.futures.as_completed(futs), 1):
                    c = futs[fut]
                    try:
                        results[c.id] = fut.result()
                    except Exception as e:           # noqa: BLE001 - a harness bug must not lose the other results
                        results[c.id] = {"status": "error", "reason": f"harness: {type(e).__name__}: {e}"}
                    if not self.a.quiet:
                        r = results[c.id]
                        print(f"[{i}/{len(todo)}] {c.id}: {r['status']} exit={r.get('exit')} "
                              f"{len(r.get('findings', []))} findings {r.get('elapsed', '')}s", file=sys.stderr, flush=True)
        finally:
            srv.stop()
        doc = {"schema": 1, "tool": "kashif", "mode": "legacy" if self.legacy else "hook",
               "kashif_version": self.version(), "python": platform.python_version(), "platform": platform.platform(),
               "tls": tls_servers.describe(), "started": started, "elapsed": round(time.monotonic() - t0, 1),
               "unavailable": srv.unavailable, "violations": srv.violations,
               "cases": {k: results[k] for k in sorted(results)}}
        return doc


def select(a: argparse.Namespace) -> list[corpus.Case]:
    cases = list(corpus.CASES)
    if a.cases:
        want = set(a.cases.split(","))
        unknown = want - {c.id for c in cases}
        if unknown:
            raise SystemExit(f"unknown case ids: {sorted(unknown)}")
        cases = [c for c in cases if c.id in want]
    if a.groups:
        gs = set(a.groups.split(","))
        cases = [c for c in cases if c.group in gs]
    if a.defects:
        cases = [c for c in cases if c.defect]
    return cases


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Run Kashif on the passive web corpus (CLI JSON) and record the results.")
    ap.add_argument("-o", "--out", default=None, help="results JSON (default: stdout)")
    ap.add_argument("--legacy", action="store_true", help="Kashif 1.0.x: no resolver hook, one case at a time on 127.0.0.1")
    ap.add_argument("--root", help="directory that contains the vulnscan package to run (default: this checkout)")
    ap.add_argument("--python", help="Python interpreter (default: this one)")
    ap.add_argument("--cases", help="comma-separated case ids")
    ap.add_argument("--groups", help="comma-separated groups (C-CSP,…)")
    ap.add_argument("--defects", action="store_true", help="only the D1–D25 regression cases")
    ap.add_argument("--jobs", type=int, default=min(8, (os.cpu_count() or 2) * 2))
    ap.add_argument("--delay", type=float, default=0.2, help="Kashif --delay (the floor is 0.2 s)")
    ap.add_argument("--timeout", type=float, default=10.0, help="Kashif --timeout per request")
    ap.add_argument("--case-timeout", type=float, default=120.0, help="wall-clock limit per case")
    ap.add_argument("--keep", help="keep each case's raw JSON report and stderr in this directory")
    ap.add_argument("--no-tls", action="store_true", help="do not start TLS servers (https cases are skipped)")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args(argv)
    doc = Runner(a).run()
    text = json.dumps(doc, ensure_ascii=False, indent=1) + "\n"
    if a.out:
        pathlib.Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(a.out).write_text(text, encoding="utf-8", newline="\n")
    else:
        sys.stdout.write(text)
    ran = sum(1 for r in doc["cases"].values() if r["status"] == "ran")
    print(f"{ran} ran, {sum(1 for r in doc['cases'].values() if r['status'] == 'skipped')} skipped, "
          f"{sum(1 for r in doc['cases'].values() if r['status'] == 'error')} errors in {doc['elapsed']} s",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
