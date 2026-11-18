#!/usr/bin/env python3
"""Regenerate Kashif's product screenshots (landing page, README) and Open Graph cards from this checkout.

    python tools/screenshots/make.py                   # everything: 11 screens x en/ar x light/dark, OG cards
    python tools/screenshots/make.py --only trace,web  # just these screens (no OG cards unless trace is among them)
    python tools/screenshots/make.py --keep            # keep the temporary home and the raw captures (prints where)

What it does, in order:

1. Creates a throwaway HOME (``<tmp>/kashif-screenshots``); the real ``~/.vulnscan`` is never read or written.
   The demo project (tools/screenshots/acme-shop, intentionally vulnerable) is copied to ``<HOME>/demo/acme-shop``.
   When ``/home/demo/acme-shop`` (else ``/srv/demo/acme-shop``) does not exist and can be created, it is made a
   symbolic link to that copy, so the UI shows a neutral path; the link and any folder made for it are removed
   afterwards. Otherwise the UI shows the copy's own path. KASHIF_SHOTS_NO_LINK=1 skips the link.
2. Starts ``kashif ui`` from this checkout (``python -m vulnscan``, the real ``vulnscan.__version__``), with TZ=UTC,
   a C.UTF-8 locale and the triage author "lina".
3. Builds a believable history through the UI's own API: four states of the project scanned oldest first, three
   triage decisions and a reviewer comment, the attack-surface map, and a passive web scan of a tiny storefront served
   on ``http://localhost:<port>/`` by this script (loopback only; nothing leaves the machine).
4. Stops the UI, spreads the scans over the past four weeks relative to now (fixed UTC times of day), restarts it.
5. Captures every screen with Playwright (capture.js, 1440x900 at 2x, en/ar x light/dark, browser timezone UTC).
6. Installs the images: site/img/shots/<name>-<lang>-<theme>.{png,webp} (2880x1800, PNG palette-quantised) and the
   1440x900 README copies in docs/screenshots/, then renders site/img/og-en.png and og-ar.png (og.js).

Requirements: Node.js with the ``playwright`` package and its Chromium already installed (this script never runs
``playwright install``), and Pillow with WebP support. Run it before every release and commit the images.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import http.server
import json
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent
DEMO_SRC = HERE / "acme-shop"
# neutral paths the UI can show for the demo project (a symbolic link to the copy), first free one wins
NEUTRALS = [pathlib.Path("/home/demo/acme-shop"), pathlib.Path("/srv/demo/acme-shop")]
AUTHOR = "lina"

SCREENS = ["dashboard", "findings", "trace", "scan", "reports",          # the landing-page gallery since 0.8
           "autofix", "triage", "compliance", "surface", "export",       # 1.0 features
           "web"]                                                        # 1.1 passive web scanner
VARIANTS = [f"{lang}-{theme}" for lang in ("en", "ar") for theme in ("light", "dark")]
DOCS_FILES = ["dashboard-en-light", "trace-en-light", "dashboard-ar-light", "trace-ar-light", "scan-ar-light",
              "reports-ar-dark",                                                # referenced by README.md
              "autofix-en-light", "compliance-en-light", "surface-en-light", "triage-en-light", "export-en-light",
              "autofix-ar-light", "compliance-ar-light", "surface-ar-light", "triage-ar-light", "export-ar-light"]

# Scans are dated this many days before today, at these UTC times: a project checked roughly once a week.
SCHEDULE = [(27, "10:14"), (19, "15:02"), (12, "11:37"), (4, "09:48")]
WEB_SCHEDULE = (6, "14:21")          # older than the last project scan, so the default views show the project

LEGACY_PY = '''import pickle

from flask import Blueprint, request

legacy = Blueprint("legacy", __name__)


@legacy.route("/legacy/cart", methods=["POST"])
def restore_cart():
    return str(pickle.loads(request.data))


@legacy.route("/legacy/calc")
def calc():
    return str(eval(request.args["expr"]))
'''

# --------------------------------------------------------------------------------------------- the demo web site
JQUERY = ("/*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */\n"
          "!function(a,b){\"object\"==typeof module?module.exports=b(a):b(a)}(window,function(a){var jQuery={fn:{"
          "jquery:\"1.12.4\"}};a.jQuery=a.$=jQuery;return jQuery});\n")
SHOP_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Acme Shop</title>
<meta name="generator" content="WordPress 5.8.1">
<script src="/static/js/jquery-1.12.4.min.js"></script>
<script>var cart = JSON.parse(localStorage.getItem("cart") || "[]"); document.write("<p>" + location.hash.slice(1) + "</p>");</script>
</head><body>
<h1>Acme Shop</h1>
<form action="http://localhost:{port}/login" method="post"><input name="user"><input name="password" type="password">
<button>Sign in</button></form>
<a href="/catalog">Catalog</a> <a href="/contact">Contact</a>
<!-- TODO: remove staging link http://staging.acme.internal/admin before launch -->
</body></html>
"""


class ShopHandler(http.server.BaseHTTPRequestHandler):
    """A small, deliberately careless storefront for the web-scan screenshot (served on loopback only)."""
    server_version = "nginx/1.18.0"
    sys_version = ""

    def log_message(self, *args):  # quiet
        pass

    def _send(self, code: int, body: bytes, ctype: str, extra: list[tuple[str, str]] = ()):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Powered-By", "PHP/7.4.3")
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        port = self.server.server_address[1]
        if path in ("/", "/catalog", "/contact"):
            body = SHOP_HTML.replace("{port}", str(port)).encode()
            return self._send(200, body, "text/html; charset=utf-8",
                              [("Set-Cookie", "PHPSESSID=8f2c1d0a9b7e6f5a4c3b2a1d0e9f8a7b; path=/"),
                               ("Set-Cookie", "cart_id=31337; path=/; SameSite=None"),
                               ("Access-Control-Allow-Origin", "*")])
        if path == "/static/js/jquery-1.12.4.min.js":
            return self._send(200, JQUERY.encode(), "application/javascript")
        if path == "/robots.txt":
            return self._send(200, b"User-agent: *\nDisallow: /admin/\nDisallow: /backup/\n", "text/plain")
        return self._send(404, b"<h1>404 Not Found</h1>", "text/html")


# ------------------------------------------------------------------------------------------------------- helpers
NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def free_port(preferred: int) -> int:
    for port in (preferred, 0):
        with contextlib.closing(socket.socket()) as s:
            try:
                s.bind(("127.0.0.1", port))
            except OSError:
                continue
            return s.getsockname()[1]
    raise RuntimeError("no free port")


class UI:
    """``python -m vulnscan ui`` from this checkout, with the throwaway home."""

    def __init__(self, env: dict, port: int, log: pathlib.Path):
        self.env, self.port, self.log = env, port, log
        self.base = f"http://127.0.0.1:{port}"
        self.proc = None

    def __enter__(self):
        out = open(self.log, "ab")
        self.proc = subprocess.Popen([sys.executable, "-m", "vulnscan", "ui", "--no-browser", "--port", str(self.port)],
                                     cwd=REPO, env=self.env, stdout=out, stderr=subprocess.STDOUT)
        for _ in range(150):
            if self.proc.poll() is not None:
                raise RuntimeError(f"kashif ui exited ({self.proc.returncode}); see {self.log}")
            try:
                meta = self.get("/api/meta")
                break
            except OSError:
                time.sleep(0.2)
        else:
            raise RuntimeError(f"kashif ui did not start; see {self.log}")
        if meta.get("version") != version():
            raise RuntimeError(f"the UI reports {meta.get('version')}, this checkout is {version()}")
        return self

    def __exit__(self, *exc):
        self.proc.terminate()
        try:
            self.proc.wait(10)
        except subprocess.TimeoutExpired:
            self.proc.kill()

    def get(self, path: str):
        with NO_PROXY.open(self.base + path, timeout=30) as r:
            return json.load(r)

    def post(self, path: str, body: dict):
        req = urllib.request.Request(self.base + path, json.dumps(body).encode(),
                                     {"Content-Type": "application/json", "Origin": self.base})
        with NO_PROXY.open(req, timeout=60) as r:
            return json.load(r)

    def scan(self, target: str, **opts) -> dict:
        s = self.post("/api/scan", {"target": target, **opts})
        for _ in range(600):
            time.sleep(0.5)
            cur = self.get(f"/api/scans/{s['id']}")
            if cur.get("status") not in ("queued", "running"):
                if cur.get("status") != "done":
                    raise RuntimeError(f"scan of {target} ended {cur.get('status')}: {cur.get('error')}")
                print(f"  scan {cur['id']} {target}: {cur.get('summary')}")
                return cur
        raise RuntimeError(f"scan of {target} did not finish")


def version() -> str:
    ns: dict = {}
    text = (REPO / "vulnscan" / "__init__.py").read_text(encoding="utf-8")
    line = next(x for x in text.splitlines() if x.startswith("__version__"))
    exec(line, ns)  # noqa: S102 - one assignment line of our own package
    return ns["__version__"]


def finding(scan: dict, rule: str, file: str, line: int | None = None) -> dict:
    for d in scan.get("findings") or []:
        if d.get("rule_id") == rule and d.get("file", "").endswith(file) and (line is None or d.get("line") == line):
            return d
    raise RuntimeError(f"no {rule} finding in {file}:{line} (the demo project or the rules changed?)")


def line_of(text: str, needle: str) -> int:
    return next(i for i, x in enumerate(text.splitlines(), 1) if needle in x)


def stamp(days_ago: int, hhmm: str) -> float:
    today = dt.datetime.now(dt.timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    h, m = map(int, hhmm.split(":"))
    return (today - dt.timedelta(days=days_ago, hours=-h, minutes=-m)).timestamp()


def iso(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------------------------------------- steps
def neutral_project(real: pathlib.Path, made: list[pathlib.Path]) -> pathlib.Path:
    """The path the UI shows for the demo project: the first of NEUTRALS that is free and can be created, as a
    symbolic link to the copy, else the copy itself. Anything created here is listed in `made` (removed in reverse)."""
    if os.environ.get("KASHIF_SHOTS_NO_LINK") or os.name == "nt":
        return real
    for neutral in NEUTRALS:
        try:
            if neutral.is_symlink() and str(os.readlink(neutral)).endswith("kashif-screenshots/home/demo/acme-shop"):
                neutral.unlink()                  # a link left by an interrupted earlier run of this script
            if os.path.lexists(neutral):
                print(f"note: {neutral} exists, not used")
                continue
            missing = [p for p in reversed(neutral.parents) if not p.exists()]
            for p in missing:
                p.mkdir()
                made.append(p)
            neutral.symlink_to(real, target_is_directory=True)
            made.append(neutral)
            return neutral
        except OSError as e:
            print(f"note: cannot create {neutral} ({e.strerror}), not used")
    print(f"note: the UI will show {real}")
    return real


def build_history(ui: UI, proj: pathlib.Path, real: pathlib.Path, web_url: str) -> dict:
    app = real / "api" / "app.py"
    final = app.read_text(encoding="utf-8")
    no_import = final.split('\n\n@app.route("/import"')[0] + "\n"
    no_debug = final.replace('    app.run(host="0.0.0.0", debug=True)', "    app.run()")
    states = [(no_import, True), (no_import, False), (no_debug, False), (final, False)]
    scans = []
    try:
        for text, legacy in states:
            app.write_text(text, encoding="utf-8")
            lp = real / "api" / "legacy.py"
            if legacy:
                lp.write_text(LEGACY_PY, encoding="utf-8")
            elif lp.exists():
                lp.unlink()
            scans.append(ui.scan(str(proj)))
    finally:
        app.write_text(final, encoding="utf-8")
        (real / "api" / "legacy.py").unlink(missing_ok=True)
    last = scans[-1]
    sql_line = line_of(final, "db.execute(")
    sql = finding(last, "DF004", "api/app.py", sql_line)
    net = finding(last, "NET002", "api/app.py")
    health = finding(last, "vql/entry-point-without-auth", "api/app.py", line_of(final, '@app.route("/health")') + 1)
    for body in (
        {"fingerprint": sql["fingerprint"], "status": "confirmed",
         "comment": "Reproduced on staging with a quote in the customer parameter. Parameterising order_query() in "
                    "ACME-142.", "ticket": "https://tracker.example.com/browse/ACME-142"},
        {"fingerprint": net["fingerprint"], "status": "accepted_risk",
         "justification": "The API only runs inside the private container network behind the gateway.",
         "expires": (dt.date.today() + dt.timedelta(days=75)).isoformat()},
        {"fingerprint": health["fingerprint"], "status": "false_positive",
         "justification": "Public health check: returns a constant and reads no input."},
    ):
        ui.post("/api/triage/set", {"scan": last["id"], **body})
    ui.post("/api/triage/comment", {"scan": last["id"], "fingerprint": sql["fingerprint"], "author": "omar",
                                    "text": "Patch with a parameterised query is in review; will verify on the next scan."})
    # attack-surface map of the latest scan
    pid = next(p["id"] for p in ui.get("/api/projects") if p.get("target") == str(proj))
    ui.post(f"/api/scans/{last['id']}/surface", {"engine": True})
    for _ in range(240):
        time.sleep(0.5)
        sf = ui.get(f"/api/projects/{pid}/surface")
        if sf.get("status") == "done":
            break
        if sf.get("status") == "error":
            raise RuntimeError(f"surface map failed: {sf.get('error')}")
    else:
        raise RuntimeError("surface map did not finish")
    web = ui.scan(web_url, authorized=True, profile="standard", use_proxy=False, third_party_lookups=False,
                  compare_previous=False)
    return {"scans": [s["id"] for s in scans], "web": web["id"], "pid": pid, "sql_line": sql_line,
            "sql_fp": sql["fingerprint"]}


def retime(vhome: pathlib.Path, real: pathlib.Path, hist: dict) -> None:
    """Spread the scans over the past weeks (the UI must be stopped)."""
    plan = list(zip(hist["scans"], SCHEDULE)) + [(hist["web"], WEB_SCHEDULE)]
    for i, (sid, (days, hhmm)) in enumerate(plan):
        p = vhome / "scans" / f"{sid}.json"
        d = json.loads(p.read_text(encoding="utf-8"))
        dur = max((d.get("finished_at") or d["started_at"]) - d["started_at"], 2.4) + i * 0.3
        ts = stamp(days, hhmm)
        d["started_at"], d["finished_at"] = ts, ts + dur
        p.write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8")
    (vhome / "index.json").unlink(missing_ok=True)       # rebuilt from the scan files on the next start
    for sf in (vhome / "surface").glob("*.json"):      # the surface map: built a minute after the last scan
        d = json.loads(sf.read_text(encoding="utf-8"))
        d["built_at"] = stamp(*SCHEDULE[-1]) + 60
        sf.write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8")
    # triage: decided the morning after the last scan, the reviewer's comment a day later
    tp = real / ".kashif" / "triage.json"
    tri = json.loads(tp.read_text(encoding="utf-8"))
    decided, commented = iso(stamp(SCHEDULE[-1][0] - 1, "10:05")), iso(stamp(SCHEDULE[-1][0] - 2, "16:40"))
    for entry in tri.get("findings", {}).values():
        for key in ("first_seen", "updated"):
            if key in entry:
                entry[key] = decided
        for ev in entry.get("log") or []:
            ev["at"] = commented if ev.get("author") == "omar" else decided
    tp.write_text(json.dumps(tri, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def node(script: str, *args: str, env: dict) -> str:
    r = subprocess.run(["node", str(HERE / script), *args], cwd=HERE, env=env, capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError(f"{script} failed:\n{r.stdout}\n{r.stderr}")
    return r.stdout


def install(raw: pathlib.Path, only: set[str] | None) -> list[pathlib.Path]:
    from PIL import Image

    site, docs = REPO / "site" / "img" / "shots", REPO / "docs" / "screenshots"

    def png(im, path):
        im.convert("RGB").quantize(colors=256, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE).save(
            path, optimize=True)

    written = []
    for n in SCREENS:
        if only and n not in only:
            continue
        for v in VARIANTS:
            im = Image.open(raw / f"{n}-{v}.png").convert("RGB")
            if im.size != (2880, 1800):
                raise RuntimeError(f"{n}-{v}: unexpected size {im.size}")
            png(im, site / f"{n}-{v}.png")
            im.save(site / f"{n}-{v}.webp", quality=82, method=6)
            written += [site / f"{n}-{v}.png", site / f"{n}-{v}.webp"]
    for f in DOCS_FILES:
        if only and f.rsplit("-", 2)[0] not in only:
            continue
        png(Image.open(raw / f"{f}.png").convert("RGB").resize((1440, 900), Image.LANCZOS), docs / f"{f}.png")
        written.append(docs / f"{f}.png")
    return written


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--only", default="", help=f"comma-separated screens (default: all of {','.join(SCREENS)})")
    ap.add_argument("--port", type=int, default=8841, help="UI port (another free port is used if it is taken)")
    ap.add_argument("--keep", action="store_true", help="keep the temporary home and raw captures")
    ap.add_argument("--no-install", action="store_true", help="capture only; do not touch site/ or docs/")
    args = ap.parse_args(argv)
    only = {x for x in args.only.split(",") if x} or None
    if only and only - set(SCREENS):
        ap.error(f"unknown screens: {', '.join(sorted(only - set(SCREENS)))}")

    root = pathlib.Path(tempfile.gettempdir()) / "kashif-screenshots"
    if root.exists():                                  # left by an earlier --keep or interrupted run
        if not (root / ".kashif-screenshots").exists():
            raise SystemExit(f"{root} exists and was not made by this script; remove it first")
        shutil.rmtree(root)
    home = root / "home" / "demo"
    home.mkdir(parents=True)
    (root / ".kashif-screenshots").touch()
    vhome, raw = home / ".vulnscan", root / "raw"
    vhome.mkdir()
    raw.mkdir()
    real = home / "acme-shop"
    shutil.copytree(DEMO_SRC, real, ignore=shutil.ignore_patterns(".kashif", "__pycache__"))
    (vhome / "settings.json").write_text(json.dumps({
        "language": "en", "theme": "auto", "check_updates": False, "use_osv": False, "use_external": False,
        "keep_scans": 50, "web_use_proxy": False, "web_third_party_lookups": False}, indent=2), encoding="utf-8")

    env = {k: v for k, v in os.environ.items()
           if k.upper() not in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "VULNSCAN_HOME", "KASHIF_HOME", "PYTHONPATH")}
    env.update(HOME=str(home), USERPROFILE=str(home), VULNSCAN_HOME=str(vhome), KASHIF_HOME=str(vhome),
               KASHIF_AUTHOR=AUTHOR, TZ="UTC", LANG="C.UTF-8", LC_ALL="C.UTF-8", PYTHONHASHSEED="0",
               PYTHONDONTWRITEBYTECODE="1", NO_PROXY="localhost,127.0.0.1", no_proxy="localhost,127.0.0.1")
    node_env = {**os.environ, "TZ": "UTC", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}

    made: list[pathlib.Path] = []
    shop = None
    try:
        proj = neutral_project(real, made)
        port = free_port(args.port)
        shop = http.server.ThreadingHTTPServer(("127.0.0.1", free_port(8080)), ShopHandler)
        threading.Thread(target=shop.serve_forever, daemon=True).start()
        web_url = f"http://localhost:{shop.server_address[1]}/"
        print(f"Kashif {version()}: home {home}, project {proj}, demo site {web_url}")

        with UI(env, port, root / "ui.log") as ui:
            hist = build_history(ui, proj, real, web_url)
        retime(vhome, real, hist)
        cfg = {**hist, "base": f"http://127.0.0.1:{port}", "path": str(proj), "only": sorted(only or SCREENS)}
        (root / "capture.json").write_text(json.dumps(cfg, indent=1), encoding="utf-8")
        print("capturing ...")
        with UI(env, port, root / "ui.log"):
            out = node("capture.js", str(root / "capture.json"), str(raw), env=node_env)
        errs = json.loads(out[out.index("["):])
        if errs:
            raise RuntimeError("capture problems:\n" + "\n".join(errs))
        print(f"captured {len(list(raw.glob('*.png')))} images into {raw}")
        if args.no_install:
            return 0
        written = install(raw, only)
        if not only or "trace" in only:                  # the OG cards show the dark trace screenshot
            print(node("og.js", str(REPO / "site"), str(REPO / "site" / "img"), version(), env=node_env).strip())
            written += [REPO / "site" / "img" / "og-en.png", REPO / "site" / "img" / "og-ar.png"]
        size = sum(p.stat().st_size for p in written)
        print(f"installed {len(written)} files, {size / 1e6:.1f} MB")
        return 0
    finally:
        if shop:
            shop.shutdown()
        for p in reversed(made):
            with contextlib.suppress(OSError):
                p.unlink() if p.is_symlink() else p.rmdir()
        if args.keep:
            print(f"kept {root}")
        else:
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
