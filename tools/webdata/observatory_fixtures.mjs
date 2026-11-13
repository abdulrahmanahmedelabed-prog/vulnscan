// Record the expected Observatory numbers of tests/web/test_grade.py with the OFFICIAL scorer (maintainers only).
//
// The scorer is never re-implemented here: this script imports src/scanner/index.js (analyzeScan) and the analyzers
// of an unmodified mdn/mdn-http-observatory checkout (1.7.2, commit 11b909f) and feeds them the fixture responses
// the way its retriever records them: Node's header folding (duplicate fields joined with ", ", the documented
// single-value fields keep the first), a tough-cookie jar per session, the CORS preflight with Observatory's default
// Origin, and the HSTS preload entries the fixture names (written to conf/hsts-preload.json).
//
//   git clone https://github.com/mdn/mdn-http-observatory obs && cd obs && git checkout v1.7.2
//   npm install --ignore-scripts structured-headers@2.1.1 tldts@7.4.19 htmlparser2@12.0.0 axios@1.21.0 \
//       tough-cookie@5.1.2 convict@6.2.5 http-cookie-agent@8.0.0
//   PYTHONPATH=<kashif>:<kashif>/tests/web python -c "import json, sys, test_grade; \
//       json.dump(test_grade.FIXTURES, sys.stdout)" > fixtures.json
//   cp <kashif>/tools/webdata/observatory_fixtures.mjs . && node observatory_fixtures.mjs fixtures.json
//
// Paste the printed score, grade, testsPassed and per-test results into OFFICIAL in tests/web/test_grade.py.
import fs from "node:fs";
import { AxiosHeaders } from "axios";
import { CookieJar } from "tough-cookie";

const fixtures = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const preload = {};
for (const f of fixtures) Object.assign(preload, f.preload || {});
fs.writeFileSync(new URL("./conf/hsts-preload.json", import.meta.url), JSON.stringify(Object.fromEntries(
  Object.entries(preload).map(([h, e]) => [h, { includeSubDomains: !!e.include_subdomains,
    includeSubDomainsForPinning: false, mode: "force-https", pinned: false }]))));

const { analyzeScan } = await import("./src/scanner/index.js");
const { Requests } = await import("./src/types.js");
const { Site } = await import("./src/site.js");
const { parseHttpEquivHeaders } = await import("./src/retriever/utils.js");

// node:http (_http_incoming.js matchKnownFields): these keep the first value, set-cookie is an array, the rest join ", "
const DROP_DUP = new Set(["age", "authorization", "content-length", "content-type", "etag", "expires", "from", "host",
  "if-modified-since", "if-unmodified-since", "last-modified", "location", "max-forwards", "proxy-authorization",
  "referer", "retry-after", "server", "user-agent"]);

function nodeHeaders(lines) {
  const obj = {};
  for (const [k, v] of lines || []) {
    const n = k.toLowerCase();
    if (n === "set-cookie") (obj[n] ||= []).push(v);
    else if (!(n in obj)) obj[n] = v;
    else if (!DROP_DUP.has(n)) obj[n] = n === "cookie" ? obj[n] + "; " + v : obj[n] + ", " + v;
  }
  return new AxiosHeaders(obj);
}

function response(hop, verified) {
  return { headers: nodeHeaders(hop.headers), request: { headers: new AxiosHeaders() }, status: hop.status,
    statusText: "", verified, data: hop.body || "", config: { headers: new AxiosHeaders() } };
}

const out = [];
for (const f of fixtures) {
  const req = new Requests(Site.fromSiteString(f.host));
  const jars = {};
  for (const scheme of ["http", "https"]) {
    const chain = f[scheme + "_chain"];
    if (!chain) continue;
    const verified = scheme === "https" ? f.verified !== false : f.http_verified !== false;
    const jar = new CookieJar();
    for (const hop of chain) {
      for (const [k, v] of hop.headers || []) {
        if (k.toLowerCase() === "set-cookie") jar.setCookieSync(v, hop.url, { ignoreError: true });
      }
    }
    jars[scheme] = jar;
    req.responses[scheme] = response(chain.at(-1), verified);
    req.responses[scheme + "Redirects"] = chain.map((h) => ({ url: new URL(h.url), status: h.status }));
  }
  const autoScheme = req.responses.https ? "https" : "http";
  req.responses.auto = req.responses[autoScheme];
  req.session = { jar: jars[autoScheme], url: new URL(f[autoScheme + "_chain"][0].url) };
  req.resources.path = req.responses.auto ? req.responses.auto.data : null;
  if (f.cors) {
    const OBS_ORIGIN = "https://http-observatory.security.mozilla.org";   // CONFIG.retriever.corsOrigin default
    const lines = [...(f.cors.headers || [])];
    if (f.cors.reflect) lines.push(["Access-Control-Allow-Origin", OBS_ORIGIN]);
    if (f.cors.credentials) lines.push(["Access-Control-Allow-Credentials", "true"]);
    req.responses.cors = response({ ...f.cors, headers: lines }, true);
    req.responses.cors.request = { headers: new AxiosHeaders({ Origin: OBS_ORIGIN }) };
  } else {
    req.responses.cors = null;
  }
  if (req.responses.auto) {
    const ct = req.responses.auto.headers["content-type"]?.split(";", 1)[0];
    req.responses.auto.httpEquiv = ["text/html", "application/xhtml+xml"].includes(ct) && req.resources.path
      ? parseHttpEquivHeaders(req.resources.path, f[autoScheme + "_chain"][0].url) : new Map();
  }
  const r = analyzeScan(req);
  const tests = {};
  for (const [name, t] of Object.entries(r.tests)) tests[name] = { result: t.result, pass: t.pass, modifier: t.scoreModifier };
  out.push({ id: f.id, score: r.scan.score, grade: r.scan.grade, tests_passed: r.scan.testsPassed, tests });
}
console.log(JSON.stringify(out, null, 1));
