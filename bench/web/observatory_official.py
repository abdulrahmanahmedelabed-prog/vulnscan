"""Score the Observatory grade fixtures with the official MDN HTTP Observatory analyzer (spec §5.2 C-GRADE, §5.4).

    npm install --prefix /tmp/obs --ignore-scripts @mdn/mdn-http-observatory@1.7.2
    echo '{}' > /tmp/obs/node_modules/@mdn/mdn-http-observatory/conf/hsts-preload.json
    python bench/web/observatory_official.py --package /tmp/obs/node_modules/@mdn/mdn-http-observatory

The script starts the corpus servers on 127.0.0.1, records the exact responses each ``grade-obs-*`` case serves (the
entry document, robots.txt for cookies, and the GET with an ``Origin`` header that Kashif uses instead of Observatory's
OPTIONS preflight), and feeds them to the package's own ``analyzeScan()`` without any network access (Node 24+). The
other scheme is recorded as unreachable, which is what Observatory sees for a site whose port 80 or 443 is closed.
``--postinstall`` is skipped (it downloads the preload and TLD lists): the corpus hosts are under ``.kashif.test`` and
are in no preload list, so an empty list is exact.

It prints, per case, the official score and grade, Kashif's score from a corpus run (``--results``), and every test
where the two differ. The expected numbers in ``corpus.py`` (``expect={"observatory": N}``) were recorded with it.
"""

from __future__ import annotations

import argparse
import http.client
import json
import pathlib
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import corpus  # noqa: E402

PACKAGE_VERSION = "1.7.2"
CASES = ("grade-obs-165", "grade-obs-100", "grade-obs-0")

SCORER = r"""
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
const pkg = process.argv[2];
const imp = (p) => import(pathToFileURL(path.join(pkg, p)).href);
const { AxiosHeaders } = await import(pathToFileURL(path.join(pkg, "..", "..", "axios", "index.js")).href);
const { Session } = await imp("src/retriever/session.js");
const { parseHttpEquivHeaders } = await imp("src/retriever/utils.js");
const { analyzeScan } = await imp("src/scanner/index.js");
const { Site } = await imp("src/site.js");
const { Requests, HTML_TYPES } = await imp("src/types.js");
const fx = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));
const ORIGIN = "https://http-observatory.security.mozilla.org";
// Node's http client: set-cookie becomes a list, these keep the first value, every other duplicate is joined with ", ".
const FIRST_WINS = new Set(["age", "authorization", "content-length", "content-type", "etag", "expires", "from", "host",
  "if-modified-since", "if-unmodified-since", "last-modified", "location", "max-forwards", "proxy-authorization",
  "referer", "retry-after", "server", "user-agent"]);
function resp(r, requestHeaders = {}) {
  const merged = new Map();
  for (const [k, v] of r.headers) {
    const n = k.toLowerCase();
    if (n === "set-cookie") merged.set(n, [...(merged.get(n) || []), v]);
    else if (!merged.has(n)) merged.set(n, v);
    else if (!FIRST_WINS.has(n)) merged.set(n, merged.get(n) + ", " + v);
  }
  const h = new AxiosHeaders();
  for (const [k, v] of merged) h.set(k, v);
  return { headers: h, request: { headers: new AxiosHeaders(requestHeaders) }, status: r.status, statusText: "OK",
           verified: r.verified ?? true, data: r.body, config: { headers: new AxiosHeaders() } };
}
const out = {};
for (const [cid, f] of Object.entries(fx)) {
  const base = `${f.scheme}://${f.host}${f.path}`;
  const req = new Requests(Site.fromSiteString(f.host));
  const auto = resp(f.entry);
  req.responses.auto = auto;
  req.responses.cors = resp(f.cors, { Origin: ORIGIN });
  const hop = [{ url: new URL(base), status: f.entry.status }];
  if (f.scheme === "https") {
    req.responses.https = auto; req.responses.http = null; req.responses.httpRedirects = []; req.responses.httpsRedirects = hop;
  } else {
    req.responses.http = auto; req.responses.https = null; req.responses.httpRedirects = hop; req.responses.httpsRedirects = [];
  }
  req.session = new Session(new URL(base));
  for (const r of [f.entry, f.robots]) for (const [k, v] of r.headers)
    if (k.toLowerCase() === "set-cookie") req.session.jar.setCookieSync(v, base, { ignoreError: true });  // as http-cookie-agent
  req.resources.path = f.entry.body;
  const ct = (auto.headers.get("content-type") || "").split(";", 1)[0];
  auto.httpEquiv = HTML_TYPES.has(ct) ? parseHttpEquivHeaders(f.entry.body, base) : new Map();
  const res = analyzeScan(req);
  out[cid] = { score: res.scan.score, grade: res.scan.grade,
               tests: Object.fromEntries(Object.entries(res.tests).map(([k, t]) => [k, [t.result, t.scoreModifier]])) };
}
console.log(JSON.stringify(out));
"""


def _get(c: corpus.Case, port: int, path: str, extra: dict | None = None) -> dict:
    """One GET to the local corpus server (127.0.0.1 only), with the case's Host header and SNI."""
    raw = socket.create_connection(("127.0.0.1", port), timeout=10)
    if c.scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = ctx.wrap_socket(raw, server_hostname=c.host)
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.sock = raw
    conn.request("GET", path, headers={"Host": c.host, "Accept": "text/html,*/*;q=0.8", **(extra or {})})
    r = conn.getresponse()
    out = {"status": r.status, "headers": r.getheaders(), "body": r.read().decode("utf-8", "replace")}
    conn.close()
    return out


def record(ids: tuple[str, ...]) -> dict:
    srv = corpus.CorpusServer(mode="host").start()
    try:
        out = {}
        for cid in ids:
            c = srv.by_id[cid]
            port = srv.port_for(c, c.scheme)
            out[cid] = {"scheme": c.scheme, "host": c.host, "path": c.path, "entry": _get(c, port, c.path),
                        "robots": _get(c, port, "/robots.txt"),
                        "cors": _get(c, port, c.path, {"Origin": "https://http-observatory.security.mozilla.org"})}
        return out
    finally:
        srv.stop()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--package", required=True, help="the installed @mdn/mdn-http-observatory directory")
    ap.add_argument("--node", default=shutil.which("node") or "node", help="Node.js 24+ binary")
    ap.add_argument("--results", help="a run_kashif.py --keep directory to compare with")
    a = ap.parse_args(argv)
    pkg = pathlib.Path(a.package).resolve()
    version = json.loads((pkg / "package.json").read_text(encoding="utf-8")).get("version")
    if version != PACKAGE_VERSION:
        print(f"expected @mdn/mdn-http-observatory {PACKAGE_VERSION}, found {version}", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="kashif-obs-") as tmp:
        fx = pathlib.Path(tmp) / "fixtures.json"
        fx.write_text(json.dumps(record(CASES)), encoding="utf-8")
        script = pathlib.Path(tmp) / "score.mjs"
        script.write_text(SCORER, encoding="utf-8")
        proc = subprocess.run([a.node, str(script), str(pkg), str(fx)], capture_output=True, text=True, encoding="utf-8")
    if proc.returncode:
        print(proc.stderr, file=sys.stderr)
        return 2
    official = json.loads(proc.stdout)
    for cid, o in official.items():
        line = f"{cid}: official {o['score']} ({o['grade']})"
        if a.results:
            rep = pathlib.Path(a.results) / cid / "report.json"
            k = json.loads(rep.read_text(encoding="utf-8"))["web"]["grades"]["observatory"] if rep.is_file() else {}
            line += f", kashif {k.get('score')} ({k.get('grade')}), not computed by kashif: {k.get('missing_tests') or []}"
            for test, (slug, mod) in o["tests"].items():
                kt = (k.get("tests") or {}).get(test)
                if kt and (kt.get("slug") != slug or kt.get("modifier") != mod):
                    line += f"\n    {test}: official {slug} ({mod}), kashif {kt.get('slug')} ({kt.get('modifier')})"
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
