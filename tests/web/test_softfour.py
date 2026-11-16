"""Soft-404 engine and simhash (spec §3.2, WP2).

Covers: simhash/Hamming properties and stability; the signature normalisation; the ``similar`` rule; catch-all text,
SPA shell, URL-echoing 404 page, real 404 (not soft), per-directory baselines, natural baselines from the well-known
files (standard profile: no random path), the baseline planner's budgets and honest names, and the corpus' soft-404
cases. Offline: synthetic responses only.
"""

from __future__ import annotations

import base64
import pathlib
import random
import re
import sys

import pytest

from vulnscan.webscan import classify as C
from vulnscan.webscan import htmlparse
from vulnscan.webscan import simhash as S
from vulnscan.webscan.types import HeaderList, Page, Response, ResponseSignature

BENCH = pathlib.Path(__file__).resolve().parents[2] / "bench" / "web"
ORIGIN = "https://soft.example.test"
HTML = [("Content-Type", "text/html; charset=utf-8")]
TEXT = [("Content-Type", "text/plain; charset=utf-8")]


def R(path="/", status=200, headers=HTML, body=b"", source="probe", origin=ORIGIN) -> Response:
    if isinstance(body, str):
        body = body.encode("utf-8")
    return Response(url=origin + path, status=status, headers=HeaderList.of(*headers), body=body, source=source)


def page(body="", title="Page"):
    return (f"<!doctype html><html><head><meta charset='utf-8'><title>{title}</title></head><body>{body}</body>"
            "</html>")


LOREM = ("Kashif is a passive security scanner. It reads the responses a browser would receive and explains what they "
         "mean for the safety of the site and its visitors. ")
SITE_TEMPLATE = ("<header><nav><a href='/'>Home</a><a href='/products'>Products</a><a href='/about'>About</a>"
                 "<a href='/contact'>Contact</a></nav></header><main>{main}</main><footer><p>" + LOREM * 3 +
                 "</p></footer>")


def token(i=0):
    return f"{i:016x}"


# ----------------------------------------------------------------------------------------------- simhash

def words(n, seed):
    rnd = random.Random(seed)
    vocab = [f"w{i}" for i in range(5000)]
    return " ".join(rnd.choice(vocab) for _ in range(n))


def test_simhash_basic_properties():
    assert S.simhash64([]) == 0
    a = S.word_shingles(words(400, 1))
    assert S.simhash64(a) == S.simhash64(list(a))                  # deterministic
    assert 0 <= S.simhash64(a) <= S.MASK64
    assert S.simhash64(["x"]) == S.simhash64([b"x"])                # str and bytes features hash alike
    # a single feature's simhash is its own 64-bit digest (every bit votes alone)
    assert S.simhash64(["only"]) == int.from_bytes(S._feature_digest("only"), "big")


def test_simhash_is_stable_across_runs():
    # BLAKE2b features, not Python's salted hash(): this value must never change (it is stored in evidence)
    assert S.to_hex(S.simhash64(["kashif soft 404", "baseline"])) == S.to_hex(
        S.simhash64(["baseline", "kashif soft 404"]))
    assert S.simhash64(["a", "b", "c"]) == S.simhash64(["c", "b", "a"])   # order-independent
    assert len(S.to_hex(S.simhash64(["a"]))) == 16


def test_hamming():
    assert S.hamming(0, 0) == 0
    assert S.hamming(0b1011, 0b0001) == 2
    assert S.hamming(0, S.MASK64) == 64
    assert S.hamming(1 << 63, 0) == 1
    assert S.near_duplicate(0b111, 0) and not S.near_duplicate(0b1111, 0)


def test_simhash_near_duplicates_are_close_and_unrelated_texts_are_far():
    near, far = [], []
    for seed in range(40):
        base = words(600, seed).split()
        edited = list(base)
        edited[300] = "changed"                                     # one word of 600
        a = S.simhash64(S.word_shingles(" ".join(base)))
        near.append(S.hamming(a, S.simhash64(S.word_shingles(" ".join(edited)))))
        far.append(S.hamming(a, S.simhash64(S.word_shingles(words(600, seed + 1000)))))
    assert sum(near) / len(near) <= S.SIMILAR_DISTANCE             # typical one-word edit: within the threshold
    assert sum(d <= S.SIMILAR_DISTANCE for d in near) >= 30
    assert min(far) > 12 and sum(far) / len(far) > 24              # unrelated texts: about 32 bits apart


def test_shingles():
    assert S.word_shingles("a b c d") == ["a b c", "b c d"]
    assert S.word_shingles("a b") == ["a", "b"]
    assert S.byte_shingles(b"abcdef") == [b"abcd", b"bcde", b"cdef"]
    assert S.byte_shingles(b"ab") == [b"ab"] and S.byte_shingles(b"") == []


def test_normalise_removes_volatile_parts():
    url = "https://x.test/files/kashif-404-0123456789abcdef.php?ref=campaign-42&q=hello"
    text = ("The requested URL /files/kashif-404-0123456789abcdef.php?ref=campaign-42&q=hello was not found. "
            "kashif-404-0123456789abcdef.php does not exist. Searched for hello. "
            "Request 9f8e7d6c-5b4a-3928-1706-f5e4d3c2b1a0 at 2026-11-12T10:00:01Z (Thu, 12 Nov 2026 10:00:01 GMT); "
            "server time 10:00 PM, 12/11/2026, ray 8f00aa11bb22cc33, order 123456, nonce dGhpcyBpcyBhIG5vbmNlMTIz")
    norm = S.normalise_text(text, url)
    for gone in ("kashif-404", "campaign-42", "hello", "9f8e7d6c", "2026", "10:00", "8f00aa11bb22cc33", "123456",
                 "dghpcyb"):
        assert gone not in norm, gone
    assert "the requested url # was not found" in norm
    # short numbers and ordinary words stay
    assert S.normalise_text("Error 404 on page 12 of 300", None) == "error 404 on page 12 of 300"


def test_visible_text_ignores_scripts_styles_and_comments():
    html_ = ("<html><head><title>T &amp; C</title><style>p{color:red}</style><script>var secret=1;</script></head>"
             "<body><!-- hidden --><p>Hello <b>world</b></p><template><p>tpl</p></template></body></html>")
    assert S.visible_text(html_) == "T & C Hello world"
    assert S.title_of(html_) == "T & C"


# ----------------------------------------------------------------------------------------------- signature / similar

def sig(status=200, essence="text/html", length=1000, sha="a", simhash=0) -> ResponseSignature:
    return ResponseSignature(status=status, essence=essence, length=length, sha256=sha, simhash=simhash)


def test_similar_rule():
    assert C.similar(sig(sha="x"), sig(sha="x"))                                      # equal SHA-256
    assert C.similar(sig(simhash=0b111), sig(sha="b", simhash=0))                     # Hamming 3
    assert not C.similar(sig(simhash=0b1111), sig(sha="b", simhash=0))                # Hamming 4
    assert C.similar(sig(length=100), sig(sha="b", length=160, simhash=S.MASK64))    # short bodies, Δlen 60
    assert not C.similar(sig(length=100), sig(sha="b", length=200, simhash=S.MASK64))  # Δlen 100 > 64
    assert not C.similar(sig(length=1000), sig(sha="b", length=1010, simhash=S.MASK64))  # long: length rule off
    # status class and essence must agree
    assert not C.similar(sig(sha="x"), sig(status=404, sha="x"))
    assert C.similar(sig(status=200, sha="x"), sig(status=203, sha="x"))
    assert not C.similar(sig(sha="x"), sig(essence="text/plain", sha="x"))


def test_signature_fields_and_cache():
    r = R("/a", body=page("<p>hello</p>"))
    s = C.signature(r)
    assert (s.status, s.essence, s.length, s.url) == (200, "text/html", len(r.body), r.url)
    assert s.sha256 == r.body_sha256() and s.simhash != 0
    assert C.signature(r) is s                                                         # cached per response
    r.body = page("<p>something else entirely, a different page body</p>").encode()
    assert C.signature(r) is not s                                                     # cache follows the body
    assert C.signature(R("/e", body=b"")).simhash == 0


def test_signature_ignores_the_echoed_path():
    a = R("/kashif-404-" + token(1), body=page(f"<h1>Not here</h1><p>/kashif-404-{token(1)} was not found</p>" + LOREM))
    b = R("/backup.sql", body=page("<h1>Not here</h1><p>/backup.sql was not found</p>" + LOREM))
    assert C.signature(a).simhash == C.signature(b).simhash
    assert C.similar(C.signature(a), C.signature(b))


# ----------------------------------------------------------------------------------------------- helpers

def test_ext_class_and_directory():
    assert [C.ext_class(p) for p in ("/", "/a/", "/server-status", "/index.html", "/.git/HEAD")] == ["none"] * 5
    assert [C.ext_class(p) for p in ("/phpinfo.php", "/x.aspx", "/a.jsp")] == ["php"] * 3
    assert [C.ext_class(p) for p in ("/.env", "/backup.sql", "/laravel.log", "/.DS_Store", "/a.tar.gz")] == ["text"] * 5
    assert [C.ext_class(p) for p in ("/crossdomain.xml", "/composer.json", "/a.yml")] == ["data"] * 3
    assert C.directory_of("/a/b/c.txt") == "/a/b/" and C.directory_of("/x") == "/" and C.directory_of("/a/") == "/a/"
    assert C._parents("/a/b/") == ["/a/b/", "/a/", "/"]


def test_baseline_path_is_honest():
    p = C.baseline_path("/app", "php", token(255))
    assert p == "/app/kashif-404-00000000000000ff.php"
    assert C.is_baseline_url("https://x.test" + p)
    assert re.fullmatch(r"/kashif-404-[0-9a-f]{16}", C.baseline_path())
    assert not C.is_baseline_url("https://x.test/kashif-404-short")
    with pytest.raises(ValueError):
        C.baseline_path("/", "exe")
    with pytest.raises(ValueError):
        C.baseline_path("/", "none", "NOT-HEX")


def test_plan_baselines_budgets():
    counter = iter(range(1000))
    probes = [f"{ORIGIN}{p}" for p in ("/.env", "/backup.sql", "/.git/HEAD", "/.git/config", "/phpinfo.php",
                                       "/server-status", "/actuator/env", "/actuator/health", "/actuator/info",
                                       "/crossdomain.xml", "/storage/logs/laravel.log")]
    plan = C.plan_baselines(probes, token=lambda: token(next(counter)))
    assert len(plan) == 5                                                              # 1 root + 4 per host
    assert plan[0] == ORIGIN + "/kashif-404-0000000000000000"                          # root first
    assert all(C.is_baseline_url(u) for u in plan)
    keys = [(C.directory_of(u.split(ORIGIN)[1]), C.ext_class(u.split(ORIGIN)[1])) for u in plan]
    assert len(set(keys)) == 5
    assert ("/actuator/", "none") in keys and ("/", "text") in keys                    # the most-covering pairs
    # already-fetched baselines count; the scan-wide cap is 10
    assert C.plan_baselines(probes, have=plan) == []
    other = [f"https://h{i}.test/.env" for i in range(8)]
    big = C.plan_baselines(probes + other)
    assert len(big) == 10
    assert len(C.plan_baselines(probes + other, have=["https://z.test/kashif-404-" + token()])) == 9
    assert C.plan_baselines([]) == []


# ----------------------------------------------------------------------------------------------- the engine

def catch_all_text_index():
    idx = C.Soft404Index()
    idx.add_baseline(R("/kashif-404-" + token(), headers=TEXT, body="OK\n", source="baseline"))
    return idx


def test_catch_all_text():
    idx = catch_all_text_index()
    probe = R("/.git/HEAD", headers=TEXT, body="OK\n")
    m = idx.match(probe)
    assert m and m.reason == "sha256" and not m.baseline.natural
    ev = m.evidence()
    assert ev["url"].endswith("/kashif-404-" + token()) and ev["status"] == 200 and len(ev["simhash"]) == 16
    assert idx.hosts["soft.example.test"].is_catch_all and idx.hosts["soft.example.test"].real_404s is False
    # a real file of another type or a 404 is not the catch-all page
    assert idx.match(R("/robots.txt", headers=[("Content-Type", "application/json")], body="{}")) is None
    assert idx.match(R("/x", status=404, headers=TEXT, body="OK\n")) is None


def test_catch_all_octet_stream_corpus_d13():
    idx = C.Soft404Index()
    blob = b"\x00\x01kashif-catch-all\x00"
    octet = [("Content-Type", "application/octet-stream")]
    idx.add_baseline(R("/kashif-404-" + token(), headers=octet, body=blob, source="baseline"))
    assert idx.match(R("/.DS_Store", headers=octet, body=blob))
    assert idx.match(R("/.svn/entries", headers=octet, body=blob))


SPA = page('<div id="root"></div><noscript>Login to continue</noscript><script src="/static/app.js"></script>',
           title="Corpus App")


def test_spa_shell():
    idx = C.Soft404Index()
    idx.add_baseline(R("/kashif-404-" + token(), body=SPA, source="baseline"))
    for path in ("/wp-admin/", "/admin/login", "/.env", "/phpinfo.php", "/swagger-ui/index.html"):
        assert idx.match(R(path, body=SPA)), path
    # the real swagger page differs from the shell
    swagger = page('<div id="swagger-ui"></div><script src="./swagger-ui-bundle.js"></script>' + LOREM * 4,
                   title="Swagger UI")
    assert idx.match(R("/swagger-ui/index.html", body=swagger)) is None
    # another SPA shell with a different structure is not the same page
    other = page('<app-root></app-root><script src="/main.js"></script><script src="/polyfills.js"></script>'
                 '<script src="/runtime.js"></script><link rel="stylesheet" href="/styles.css">', title="Other")
    assert len(other + " " * 300) >= C.SHORT_BODY and idx.match(R("/x", body=other + " " * 300)) is None


def url_echo_404(path, ts="10:00:01", rid="9f8e7d6c5b4a39281706f5e4d3c2b1a0"):
    return page(SITE_TEMPLATE.format(main=f"<h1>Sorry</h1><p>The page {path} could not be found on this server. "
                                          f"Request id {rid}, generated 2026-11-12 {ts}.</p>"), title="Sorry")


def test_url_echoing_404_page():
    idx = C.Soft404Index()
    base_path = "/kashif-404-" + token(7)
    idx.add_baseline(R(base_path, body=url_echo_404(base_path), source="baseline"))
    probe = R("/backup.sql", body=url_echo_404("/backup.sql", ts="10:00:07", rid="0" * 31 + "1"))
    m = idx.match(probe)
    assert m and m.reason in ("sha256", "simhash")
    # a real page of the same site template is not the 404 page
    real = page(SITE_TEMPLATE.format(main="<h1>Products</h1>" + "<p>Our bread is baked fresh every morning with "
                                          "flour from local farms, water and salt.</p>" * 6), title="Products")
    assert idx.match(R("/products", body=real)) is None


def test_real_404_means_no_soft_404():
    idx = C.Soft404Index()
    idx.add_baseline(R("/kashif-404-" + token(), status=404, body=page("<h1>Not found</h1>"), source="baseline"))
    hs = idx.hosts["soft.example.test"]
    assert hs.real_404s is True and not hs.is_catch_all
    # any 200 is not soft by this test, even one that looks like an error page
    assert idx.match(R("/.env", headers=TEXT, body="APP_KEY=x\n")) is None
    assert idx.match(R("/admin/", body=page("<h1>Not found</h1>"))) is None
    # a 404 probe matches the 404 baseline (same page; kind stays error_page)
    assert idx.match(R("/nope", status=404, body=page("<h1>Not found</h1>")))


def test_per_directory_baseline():
    """A framework that only catches everything under /app/: root 404s are real, /app/* answers 200 with a shell."""
    idx = C.Soft404Index()
    idx.add_baseline(R("/kashif-404-" + token(1), status=404, body=page("Not found"), source="baseline"))
    shell = page("<div id='app'></div><script src='/app/main.js'></script>", title="App")
    idx.add_baseline(R("/app/kashif-404-" + token(2), body=shell, source="baseline"))
    assert idx.match(R("/app/.env", body=shell))                      # fallback: /app/ none-class baseline
    assert idx.match(R("/app/deep/er/config.php", body=shell))        # parent directory baseline
    m = idx.match(R("/app/x", body=shell))
    assert m and m.baseline.directory == "/app/"
    assert idx.match(R("/.env", body=shell)) is None                  # root: real 404s
    cands = idx.candidates(R("/app/sub/x.php", body=shell))
    assert [(b.directory, b.cls) for b in cands] == [("/app/", "none"), ("/", "none")]


def test_extension_class_baseline_preferred():
    idx = C.Soft404Index()
    idx.add_baseline(R("/kashif-404-" + token(1), body=page("home " + LOREM * 3), source="baseline"))
    idx.add_baseline(R("/kashif-404-" + token(2) + ".php", status=404, body=page("No such script"), source="baseline"))
    # .php probes: the php baseline (real 404) decides first
    assert idx.match(R("/phpinfo.php", body=page("home " + LOREM * 3))) is None
    assert idx.match(R("/admin", body=page("home " + LOREM * 3)))


# ----------------------------------------------------------------------------------------------- natural baselines

def wellknown(robots, sectxt, legacy=None, favicon=None):
    out = {"/robots.txt": robots, "/.well-known/security.txt": sectxt}
    if legacy is not None:
        out["/security.txt"] = legacy
    if favicon is not None:
        out["/favicon.ico"] = favicon
    for k, v in out.items():
        v.source = "wellknown"
        assert v.url.endswith(k)
    return out


def test_natural_two_html_wellknowns_prove_catch_all():
    shell = SPA
    wk = wellknown(R("/robots.txt", body=shell), R("/.well-known/security.txt", body=shell))
    idx = C.Soft404Index()
    proven = idx.add_natural(wk)
    assert set(map(id, proven)) == set(map(id, wk.values()))
    hs = idx.hosts["soft.example.test"]
    assert hs.is_catch_all and hs.real_404s is False and len(hs.catch_all) == 2
    # crawl pages similar to them are soft
    assert idx.match(R("/blog/2026/hello", body=shell, source="crawl"))
    assert idx.match(R("/products", body=page("Real products page " + LOREM * 5), source="crawl")) is None


def test_natural_one_wellknown_similar_to_entry():
    entry = R("/", body=SPA, source="entry")
    wk = wellknown(R("/robots.txt", headers=TEXT, body="User-agent: *\nAllow: /\n"),
                   R("/.well-known/security.txt", body=SPA))
    idx = C.Soft404Index()
    proven = idx.add_natural(wk, entry)
    assert [r.url for r in proven] == [ORIGIN + "/.well-known/security.txt"]


def test_natural_valid_files_are_not_catch_all():
    """corpus exp-sectxt-valid: two short legitimate text files must not look like a catch-all."""
    wk = wellknown(R("/robots.txt", headers=TEXT, body="User-agent: *\nDisallow:\n"),
                   R("/.well-known/security.txt", headers=TEXT,
                     body="Contact: mailto:security@example.test\nExpires: 2027-05-01T00:00:00Z\n"),
                   favicon=R("/favicon.ico", status=404, headers=TEXT, body="not found\n"))
    idx = C.Soft404Index()
    assert idx.add_natural(wk, R("/", body=page(LOREM), source="entry")) == []
    hs = idx.hosts["soft.example.test"]
    assert not hs.is_catch_all and hs.real_404s is True and hs.real_404_paths == ["/favicon.ico"]
    assert idx.match(R("/about", body=page("About " + LOREM), source="crawl")) is None


def test_natural_identical_non_html_bodies_prove_catch_all():
    """corpus exp-catchall-text-ok: every path answers 200 text/plain 'OK'."""
    wk = wellknown(R("/robots.txt", headers=TEXT, body="OK\n"), R("/.well-known/security.txt", headers=TEXT, body="OK\n"),
                   favicon=R("/favicon.ico", headers=TEXT, body="OK\n"))
    idx = C.Soft404Index()
    assert len(idx.add_natural(wk)) == 3
    assert idx.hosts["soft.example.test"].is_catch_all


def test_natural_entry_alone_or_single_html_proves_nothing():
    wk = wellknown(R("/robots.txt", headers=TEXT, body="User-agent: *\n"),
                   R("/.well-known/security.txt", body=page("Our security policy " + LOREM)))
    idx = C.Soft404Index()
    assert idx.add_natural(wk, R("/", body=page("Welcome " + LOREM * 4), source="entry")) == []
    assert not idx.hosts["soft.example.test"].is_catch_all


# ----------------------------------------------------------------------------------------------- whole context

def test_classify_context_standard_profile_uses_no_random_path(make_ctx):
    """Standard profile: the soft-404 verdict comes from the well-known files only; no baseline is planned or needed."""
    entry = R("/", body=SPA, source="entry")
    crawl = R("/pricing", body=SPA, source="crawl")
    real = R("/docs", body=page("<h1>Docs</h1>" + LOREM * 6), source="crawl")
    wk = wellknown(R("/robots.txt", body=SPA), R("/.well-known/security.txt", body=SPA),
                   favicon=R("/favicon.ico", headers=[("Content-Type", "image/x-icon")], body=b"\0\0\1\0" + b"\0" * 60))
    cors = R("/", body=SPA, source="cors")
    ctx = make_ctx(target=ORIGIN + "/", entry=Page(entry, htmlparse.parse_response(entry)), cors=cors,
                   pages=[Page(crawl, None), Page(real, None)], wellknown=wk)
    idx = C.classify_context(ctx)
    assert ctx.baselines == []
    assert entry.kind == "document" and "app" in entry.roles             # the entry is always judged
    assert cors.kind == "document"
    assert crawl.kind == "soft404" and "soft404" in crawl.flags
    assert real.kind == "document"
    assert wk["/robots.txt"].kind == "soft404" and "catch-all" in wk["/robots.txt"].flags
    assert wk["/.well-known/security.txt"].kind == "soft404"
    assert wk["/favicon.ico"].kind == "image"
    inv = ctx.inventory["soft404"]["soft.example.test"]
    assert inv["catch_all"] is True and len(inv["natural_catch_all"]) == 2
    assert idx.hosts["soft.example.test"].is_catch_all


def test_classify_context_deep_marks_probes_and_baselines(make_ctx):
    entry = R("/", body=page("<h1>Home</h1>" + LOREM * 4), source="entry")
    base = R("/kashif-404-" + token(), headers=TEXT, body="Nothing to see here :)\n", source="baseline")
    probe_soft = R("/backup.sql", headers=TEXT, body="Nothing to see here :)\n")
    probe_real = R("/.git/HEAD", headers=TEXT, body="ref: refs/heads/main\n")
    probe_404 = R("/server-status", status=404, headers=TEXT, body="Nothing to see here :)\n")
    ctx = make_ctx(target=ORIGIN + "/", entry=Page(entry, None), profile="deep", baselines=[base],
                   probes=[probe_soft, probe_real, probe_404])
    idx = C.classify_context(ctx)
    assert base.kind == "soft404"
    assert probe_soft.kind == "soft404"
    # corpus rev-git-head-catchall: similar length, so the soft-404 test alone matches; exposure.py's strong
    # signature decides against it (§2.10) - the match carries the reason so the caller can tell
    m = idx.match(probe_real)
    assert m and m.reason == "length"
    assert probe_404.kind == "error_page"
    assert entry.kind == "document"


def test_entry_chain_is_never_soft404(make_ctx):
    hop = R("/", status=301, headers=[("Location", ORIGIN + "/home")], source="entry")
    entry = R("/home", headers=TEXT, body="OK\n", source="entry")
    entry.chain = [hop]
    base = R("/kashif-404-" + token(), headers=TEXT, body="OK\n", source="baseline")
    ctx = make_ctx(target=ORIGIN + "/", entry=entry, baselines=[base], profile="deep")
    C.classify_context(ctx)
    assert entry.kind == "text" and hop.kind == "redirect" and base.kind == "soft404"


# ----------------------------------------------------------------------------------------------- corpus cases

def _corpus():
    if str(BENCH) not in sys.path:
        sys.path.insert(0, str(BENCH))
    try:
        import corpus  # type: ignore
    except Exception as e:   # pragma: no cover - bench/ is not shipped in the sdist
        pytest.skip(f"corpus not importable: {e}")
    return corpus


def _render(text: str, host: str) -> str:
    def sub(m):
        return {"NONCE": base64.b64encode(random.randbytes(18)).decode(), "RAND": random.randbytes(16).hex(),
                "HOST": host}.get(m.group(1), "https://" + host)
    return re.sub(r"\{(HOST|SELF|HTTPS|HTTP|THIRD|NONCE|RAND|EXPIRES|PAST|HTTP_PORT|HTTPS_PORT|CASE)(?::[a-z0-9-]+)?\}",
                  sub, text)


def serve(case, path: str, source="probe") -> Response:
    """What the corpus server answers for ``path`` of ``case`` (static routes only)."""
    host = f"{case.id}.kashif.test"
    r = case.routes.get(path, case.routes.get("*"))
    assert r is not None and not callable(r), (case.id, path)
    body = _render(r.body, host).encode("utf-8") if isinstance(r.body, str) else r.body
    return Response(url=f"https://{host}{path}", status=r.status, headers=HeaderList.of(*[tuple(h) for h in r.headers]),
                    body=body, source=source)


@pytest.mark.parametrize("cid,probes", [
    ("exp-catchall-octet", ["/.DS_Store", "/.svn/entries", "/.git/HEAD", "/core/CHANGELOG.txt"]),
    ("exp-catchall-text-ok", ["/.git/HEAD", "/.env", "/crossdomain.xml"]),
    ("exp-spa-catchall", ["/wp-admin/", "/wp-login.php", "/.env", "/phpinfo.php"]),
    ("disc-error-in-soft404", ["/.env", "/server-status", "/backup.sql"]),
])
def test_corpus_catch_all_cases(cid, probes):
    corpus = _corpus()
    case = {c.id: c for c in corpus.CASES}[cid]
    idx = C.Soft404Index()
    idx.add_baseline(serve(case, "/kashif-404-" + token(), source="baseline"))
    for p in probes:
        resp = serve(case, p)
        C.classify(resp)
        assert idx.match(resp), (cid, p)


def test_corpus_real_files_are_not_soft():
    corpus = _corpus()
    cases = {c.id: c for c in corpus.CASES}
    for cid, path in (("exp-git-head", "/.git/HEAD"), ("exp-env", "/.env"), ("exp-phpinfo", "/phpinfo.php"),
                      ("exp-swagger", "/swagger-ui/index.html"), ("exp-wp-login", "/wp-login.php")):
        case = cases[cid]
        # these sites answer unknown paths with the corpus' default 404
        base = Response(url=f"https://{cid}.kashif.test/kashif-404-{token()}", status=404,
                        headers=HeaderList.of(*corpus.NOT_FOUND.headers), body=_render(corpus.NOT_FOUND.body, "h").encode(),
                        source="baseline")
        idx = C.Soft404Index()
        idx.add_baseline(base)
        assert idx.match(serve(case, path)) is None, cid


def test_corpus_spa_natural_baselines():
    """exp-spa-catchall under the standard profile: robots.txt and security.txt both return the shell."""
    corpus = _corpus()
    case = {c.id: c for c in corpus.CASES}["exp-spa-catchall"]
    wk = {p: serve(case, p, source="wellknown") for p in ("/robots.txt", "/.well-known/security.txt")}
    entry = serve(case, "/", source="entry")
    idx = C.Soft404Index()
    assert len(idx.add_natural(wk, entry)) == 2
    assert idx.match(serve(case, "/wp-admin/", source="crawl"))


def test_signature_is_fast_on_a_large_tag_dense_page():
    import time
    body = "<!doctype html><html><body>" + "".join(f"<div class='c{i % 50}'><span>item {i} text</span></div>"
                                                    for i in range(40000)) + "</body></html>"
    assert len(body) > 1_500_000
    resp = R("/big", body=body)
    t = time.perf_counter()
    C.signature(resp)
    assert time.perf_counter() - t < 1.5


def test_waf_and_error_probes_are_not_marked_soft(make_ctx):
    cf = [("Content-Type", "text/html"), ("cf-mitigated", "challenge")]
    base = R("/kashif-404-" + token(), status=403, headers=cf, body=page("challenge"), source="baseline")
    probe = R("/.env", status=403, headers=cf, body=page("challenge"))
    ctx = make_ctx(target=ORIGIN + "/", entry=R("/", body=page(LOREM), source="entry"), baselines=[base],
                   probes=[probe], profile="deep")
    C.classify_context(ctx)
    assert probe.kind == "waf_challenge" and base.kind == "waf_challenge"
    assert "soft404" not in probe.flags


# ----------------------------------------------------------------------------------------------- adversarial review

@pytest.mark.parametrize("markup", ["<script>" * 32768, "<style a>x" * 26000, "<" * 262144, "<a" * 131072,
                                    "<!--" * 65536, "<nav>" * 52000, "<template>" * 26000])
def test_visible_text_is_linear_on_hostile_markup(markup):
    """§0.6: the regex version took ≈ 40 s on 256 KB of unclosed <script> tags (quadratic backtracking)."""
    import time
    t = time.perf_counter()
    S.visible_text(markup)
    S.visible_text(markup, boilerplate=False)
    S.tag_features(markup)
    S.title_of(markup)
    S.html_features(markup)
    assert time.perf_counter() - t < 2.0          # the quadratic regex version took 3–40 s


def test_tag_features_and_title_on_unclosed_markup():
    assert S.tag_features("<a " * 50000) == []                   # no start tag is ever closed
    assert S.tag_features("<div id=root><p>x</p>") == ["t:div#root", "t:p"]
    assert S.title_of("<title>never closed" + "x" * 100) == ""
    assert S.title_of("<TITLE lang=en>A &amp; B</title >") == "A & B"
    assert S.element_inner("<h1 class=x>Hi <b>there</b></h1>", "h1") == "Hi <b>there</b>"


def test_unclosed_block_semantics():
    # an unclosed <script> runs to the end (as in a browser); an unclosed layout block keeps the page text
    assert S.visible_text("<p>before</p><script>var x = 1; <p>after") == "before"
    assert S.visible_text("<nav><a>Home</a><main>Body text</main>", boilerplate=False) == "Home Body text"
    assert S.visible_text("<nav><a>Home</a></nav><main>Body</main><footer>(c)</footer>", boilerplate=False) == "Body"


def test_template_heavy_site_real_pages_are_not_its_404_page():
    """A large site template (mega menu, footer) must not make every page a near-duplicate of the not-found page.
    Before the fix a real page with up to 300 words of its own was within Hamming 2 of the 404 page."""
    rnd = random.Random(5)
    vocab = [f"w{i}" for i in range(3000)]

    def words_(n):
        return " ".join(rnd.choice(vocab) for _ in range(n))

    head = "<header><nav>" + words_(1500) + "</nav></header><main>"
    foot = "</main><footer>" + words_(1500) + "</footer>"
    nf_a = page(head + "<h1>Page not found</h1><p>Sorry, /a/b.php does not exist.</p>" + foot)
    nf_b = page(head + "<h1>Page not found</h1><p>Sorry, /x.env does not exist.</p>" + foot)
    idx = C.Soft404Index()
    idx.add_baseline(R("/kashif-404-" + token(), body=nf_a.replace("/a/b.php", "/kashif-404-" + token()),
                       source="baseline"))
    assert idx.match(R("/x.env", body=nf_b))
    for n in (20, 50, 100, 300):
        real = page(head + "<h1>Article</h1><p>" + words_(n) + "</p>" + foot)
        assert idx.match(R("/blog/post", body=real, source="crawl")) is None, n


def test_redirected_baseline_is_keyed_by_the_requested_path():
    """/app/kashif-404-… redirected to /login is the /app/ baseline; it must not replace the root's real 404."""
    idx = C.Soft404Index()
    idx.add_baseline(R("/kashif-404-" + token(1), status=404, body=page("Not found"), source="baseline"))
    hop = R("/app/kashif-404-" + token(2), status=302, headers=[("Location", ORIGIN + "/login")], source="baseline")
    login = R("/login", body=page(LOGIN := "<form action=/login method=post><input type=password name=p></form>",
                                  title="Sign in"), source="baseline")
    login.chain = [hop]
    b = idx.add_baseline(login)
    assert (b.directory, b.cls, b.path, b.final_path) == ("/app/", "none", hop.parsed_url.path, "/login")
    hs = idx.hosts["soft.example.test"]
    assert hs.real_404s is True and not hs.is_catch_all
    # a probe under /app/ that lands on the same login page is soft; the real /login page itself is not
    probe_hop = R("/app/.env", status=302, headers=[("Location", ORIGIN + "/login")])
    probe = R("/login", body=page(LOGIN, title="Sign in"))
    probe.chain = [probe_hop]
    assert idx.match(probe)
    assert idx.match(R("/login", body=page(LOGIN, title="Sign in"), source="crawl")) is None


def test_deeper_directory_baseline_wins_over_root_extension_baseline():
    idx = C.Soft404Index()
    idx.add_baseline(R("/kashif-404-" + token(1) + ".php", status=404, body=page("No such script"), source="baseline"))
    shell = page("<div id='app'></div><script src='/app/main.js'></script>", title="App")
    idx.add_baseline(R("/app/kashif-404-" + token(2), body=shell, source="baseline"))
    assert [(b.directory, b.cls) for b in idx.candidates(R("/app/x.php", body=shell))] == [("/app/", "none"),
                                                                                          ("/", "php")]
    assert idx.match(R("/app/x.php", body=shell))
    assert idx.match(R("/phpinfo.php", body=page("<h1>PHP Version 8.2</h1>"))) is None


def test_same_security_txt_at_both_locations_is_not_a_catch_all():
    """RFC 9116 sites often publish one file at /.well-known/security.txt and /security.txt (byte-identical)."""
    body = "Contact: mailto:security@example.test\nExpires: 2027-05-01T00:00:00Z\n"
    wk = wellknown(R("/robots.txt", headers=TEXT, body="User-agent: *\nDisallow:\n"),
                   R("/.well-known/security.txt", headers=TEXT, body=body),
                   legacy=R("/security.txt", headers=TEXT, body=body))
    idx = C.Soft404Index()
    assert idx.add_natural(wk) == []
    assert not idx.hosts["soft.example.test"].is_catch_all
    # but a catch-all that answers both with the same non-security.txt page is still caught
    wk2 = wellknown(R("/robots.txt", status=404, headers=TEXT, body="nf"),
                    R("/.well-known/security.txt", headers=TEXT, body="OK\n"),
                    legacy=R("/security.txt", headers=TEXT, body="OK\n"))
    idx2 = C.Soft404Index()
    assert len(idx2.add_natural(wk2)) == 2


def test_one_resource_fetched_twice_proves_nothing():
    """/security.txt redirected to /.well-known/security.txt: two responses for one resource are not a catch-all."""
    html_page = page("<h1>Security</h1><p>Report issues to our team.</p>")
    a = R("/.well-known/security.txt", body=html_page, source="wellknown")
    b = R("/.well-known/security.txt", body=html_page, source="wellknown")
    idx = C.Soft404Index()
    assert idx.add_natural({"/.well-known/security.txt": a, "/security.txt": b}) == []
