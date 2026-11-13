"""Refresh every web data snapshot in one go (spec §4.4 step 1; maintainers only, needs the network unless --sources).

    python tools/webdata/refresh.py                              # download every upstream, rebuild, validate, install
    python tools/webdata/refresh.py --record mirror/             # the same, keeping the downloaded upstream files
    python tools/webdata/refresh.py --sources mirror/            # offline: rebuild from a recorded mirror
    python tools/webdata/refresh.py --sources mirror/ --check    # CI: fail when the bundled files differ from a rebuild
    python tools/webdata/refresh.py --only psl,retire            # some steps only (the other files are kept)
    python tools/webdata/refresh.py --pack out/                  # also write the release asset kashif-webdata-<date>.tar.gz
    python tools/webdata/refresh.py --list                       # the steps, their files and upstream URLs

How it works. Each data file has one generator in ``tools/webdata/`` (owned by the WP that owns the file); this script
only orchestrates them:

1. **Download** (upstream steps): every upstream file is fetched by this script (HTTPS only, from a fixed host
   allowlist, honest ``Kashif/<version> webdata-refresh`` User-Agent, size cap, redirects checked) into a mirror
   directory laid out the way each generator's ``--from`` option reads it, plus ``sources.json`` (date, URL, sha256
   and size of every input). Nothing about any scan target is ever sent: these are whole public lists.
2. **Build**: each generator runs on the mirror (``--from``) with the same ``--date`` into a staging directory that
   starts as a copy of the current snapshot. Seed generators (Kashif's own tables) run offline; hand-curated files
   without a generator (``exposed-paths.json``) are copied with only their ``meta.date`` restamped, because a refresh
   is also the release review of those lists (``--keep-curated-dates`` turns that off).
3. **Validate**: ``validate.py`` checks every file of the staged snapshot and writes its ``MANIFEST.json``.
4. **Install**: changed files are moved into place one by one (temp file + ``os.replace``), the manifest last. A
   failure in any earlier step leaves the bundled snapshot untouched.

Determinism: the same mirror and the same ``--date`` give byte-identical files and manifest (generators sort their
output and write gzip without a timestamp; ``--sources`` defaults the date to the mirror's recording date). The test
suite rebuilds twice from one mirror and compares every byte.

Generators are loaded fresh for every run (no state leaks between two runs in one process).
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import re
import shutil
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from vulnscan import __version__  # noqa: E402  (after the path tweak: the worktree's own package)
from vulnscan.webscan import data  # noqa: E402


def _sibling(name: str):
    """tools/webdata/<name>.py by file path (a plain ``import validate`` could pick up an unrelated package)."""
    key = f"_kashif_webdata_{name}"
    if key not in sys.modules:
        spec = importlib.util.spec_from_file_location(key, HERE / f"{name}.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[key] = mod
        spec.loader.exec_module(mod)
    return sys.modules[key]


validate = _sibling("validate")

DATA_DIR = data.BUNDLED_DIR
SOURCES_INDEX = "sources.json"
ALLOWED_HOSTS = frozenset({"raw.githubusercontent.com", "publicsuffix.org"})
MAX_DOWNLOAD = 64 * 1024 * 1024
TIMEOUT = 120.0
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

# Upstream branches. csp-evaluator's default branch is "master" (its generator's default "main" answers 404).
REFS = {"retire": "master", "csp_bypass": "master", "tech": "main", "favicons": "main", "eol": "master",
        "tls_profiles": "6.0"}


class RefreshError(Exception):
    """A step failed; nothing was installed."""


@dataclass(frozen=True)
class Input:
    rel: str                       # path inside the step's mirror directory
    urls: tuple[str, ...]          # tried in order; the first answer wins
    optional: bool = False         # a 404 is allowed (the generator copes with the file missing)


@dataclass
class Ctx:
    """What a step's build function gets."""
    date: str
    src: Path                      # this step's mirror directory
    out: Path                      # the staging directory
    base: Path                     # the snapshot being refreshed (curated files are read from here)
    used: dict[str, str]           # rel -> URL actually used (from sources.json)
    digest: str = ""               # short sha256 over this step's recorded inputs (provenance in meta)
    keep_curated_dates: bool = False

    def upstream(self, ref: str) -> list[str]:
        """``--upstream-version <ref>@<inputs digest>``: the branch name alone would not say which content was used."""
        return ["--upstream-version", f"{ref}@{self.digest}" if self.digest else ref]


@dataclass(frozen=True)
class Step:
    name: str                                   # tools/webdata/<module>.py, or a curated file's name
    outputs: tuple[str, ...]
    kind: str                                   # upstream | seed | curated
    module: str | None
    inputs: Callable[[object], list[Input]] = field(default=lambda m: [])
    build: Callable[[object, Ctx], None] = field(default=lambda m, c: None)


# ------------------------------------------------------------------------------------------------- steps

def _main(m, argv: list[str]) -> None:
    code = m.main(argv)
    if code not in (0, None):
        raise RefreshError(f"exited with {code}")


def _common(c: Ctx, src: Path, *extra: str) -> list[str]:
    return ["--from", str(src), "--date", c.date, "--out", str(c.out), *extra]


def _note(c: Ctx, inputs: list[Input]) -> list[str]:
    """``--notes`` naming a fallback mirror when the first URL was not the one used (provenance)."""
    fallbacks = sorted({c.used[i.rel] for i in inputs if i.rel in c.used and c.used[i.rel] != i.urls[0]})
    return ["--notes", "downloaded from " + ", ".join(fallbacks)] if fallbacks else []


def _psl_inputs(m) -> list[Input]:
    return [Input("public_suffix_list.dat",
                  (m.SOURCE, "https://raw.githubusercontent.com/publicsuffix/list/main/public_suffix_list.dat"))]


def _observatory_rels(m) -> list[str]:
    # the files observatory.py's main() reads with --from (kept in step with it; a missing file fails the build)
    return ["src/types.js", "src/grader/charts.js", "src/constants.js"] + \
        [f"src/analyzer/tests/{t.split(':')[1]}.js" for t in m.TEST_FILES]


def _server_cve_inputs(m) -> list[Input]:
    files = [("php-known-vulnerabilities.json", m.ZAP.format(name="php-known-vulnerabilities.json")),
             ("apache-known-vulnerabilities.json", m.ZAP.format(name="apache-known-vulnerabilities.json")),
             ("security_advisories.xml", m.NGINX)]
    files += [(f"security-{mj}.xml", m.TOMCAT.format(major=mj)) for mj in m.TOMCAT_MAJORS]
    return [Input(rel, (url,)) for rel, url in files]


def _write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="\n")


def restamp(text: str, day: str) -> str:
    """``text`` (a JSON data file) with only ``meta.date`` replaced: every other byte stays as it is."""
    obj = json.loads(text)
    old = (obj.get("meta") or {}).get("date")
    if not isinstance(old, str):
        raise RefreshError("no meta.date to restamp")
    if old == day:
        return text
    want = json.loads(text)
    want["meta"]["date"] = day
    for m in re.finditer(r'"date"\s*:\s*"' + re.escape(old) + '"', text):
        cand = text[:m.start()] + '"date": "' + day + '"' + text[m.end():]
        if json.loads(cand) == want:
            return cand
    raise RefreshError("cannot locate meta.date in the file text")


def _curated(name: str) -> Callable[[object, Ctx], None]:
    def build(_m, c: Ctx) -> None:
        text = (c.base / name).read_text(encoding="utf-8")
        _write_text(c.out / name, text if c.keep_curated_dates else restamp(text, c.date))
    return build


STEPS: tuple[Step, ...] = (
    Step("psl", ("psl.dat.gz", "psl.dat.meta.json"), "upstream", "psl", _psl_inputs,
         lambda m, c: _main(m, _common(c, c.src / "public_suffix_list.dat") + _note(c, _psl_inputs(m)))),
    Step("hsts_preload", ("hsts-preload.json.gz",), "upstream", "hsts_preload",
         lambda m: [Input("transport_security_state_static.json", (m.MIRROR,))],
         lambda m, c: _main(m, _common(c, c.src / "transport_security_state_static.json"))),
    Step("retire", ("retire-jsrepository.json.gz",), "upstream", "retire",
         lambda m: [Input("jsrepository-v4.json", (m.RAW.format(ref=REFS["retire"]),))],
         lambda m, c: _main(m, _common(c, c.src / "jsrepository-v4.json", *c.upstream(REFS["retire"])))),
    Step("csp_bypass", ("csp-bypass.json",), "upstream", "csp_bypass",
         lambda m: [Input(f"allowlist_bypasses/json/{n}.json", (m.RAW.format(ref=REFS["csp_bypass"], name=n),))
                    for n in m.FILES],
         lambda m, c: _main(m, _common(c, c.src, *c.upstream(REFS["csp_bypass"])))),
    Step("cookies", ("cookies.json",), "upstream", "cookies",
         lambda m: [Input("open-cookie-database.csv", (m.OCD_URL,))],
         lambda m, c: _main(m, ["--ocd", str(c.src / "open-cookie-database.csv"), "--date", c.date,
                                "--out", str(c.out / "cookies.json")])),
    Step("tech", ("tech.json",), "upstream", "tech",
         lambda m: [Input("tech-detect.yaml", (m.RAW.format(ref=REFS["tech"]),))],
         lambda m, c: _main(m, _common(c, c.src / "tech-detect.yaml", *c.upstream(REFS["tech"])))),
    Step("favicons", ("favicons.json",), "upstream", "favicons",
         lambda m: [Input("favicon-detect.yaml", (m.RAW.format(ref=REFS["favicons"]),))],
         lambda m, c: _main(m, _common(c, c.src / "favicon-detect.yaml", *c.upstream(REFS["favicons"])))),
    Step("eol", ("eol.json",), "upstream", "eol",
         lambda m: [Input(f"{s}.md", (m.RAW.format(ref=REFS["eol"], slug=s),), optional=True) for s in m.PRODUCTS],
         lambda m, c: _main(m, _common(c, c.src, *c.upstream(REFS["eol"])))),
    Step("server_cve", ("server-cve.json",), "upstream", "server_cve", _server_cve_inputs,
         lambda m, c: _main(m, _common(c, c.src))),
    Step("ct_logs", ("ct-logs.json",), "upstream", "ct_logs",          # meta.date is the list's own timestamp
         lambda m: [Input("log_list.json", (m.SOURCE,))],
         lambda m, c: _main(m, ["--from", str(c.src / "log_list.json"), "--out", str(c.out)])),
    Step("tls_profiles", ("tls-profiles.json",), "upstream", "tls_profiles",
         lambda m: [Input(f"{REFS['tls_profiles']}.json", (m.SOURCE.format(version=REFS["tls_profiles"]),))],
         lambda m, c: _main(m, _common(c, c.src / f"{REFS['tls_profiles']}.json", "--guidelines", REFS["tls_profiles"]))),
    Step("observatory", ("observatory-v6.json",), "upstream", "observatory",
         lambda m: [Input(rel, (m.RAW.format(tag=m.TAG, path=rel),)) for rel in _observatory_rels(m)],
         lambda m, c: _main(m, _common(c, c.src, "--tag", m.TAG))),
    Step("errors", ("error-signatures.json", "leak-headers.json", "secret-rules.json"), "seed", "errors",
         build=lambda m, c: _main(m, ["--date", c.date, "--out", str(c.out)])),
    Step("malicious_hosts", ("malicious-hosts.json",), "seed", "malicious_hosts",
         build=lambda m, c: _write_text(c.out / "malicious-hosts.json", m.render(m.build(c.date)))),
    Step("takeover", ("takeover.json",), "seed", "takeover",
         build=lambda m, c: _write_text(c.out / "takeover.json", m.render(m.build(c.date)))),
    Step("exposed-paths.json", ("exposed-paths.json",), "curated", None, build=_curated("exposed-paths.json")),
)
BY_NAME = {s.name: s for s in STEPS}


def load_module(name: str):
    """A fresh instance of ``tools/webdata/<name>.py`` (never shared with an earlier run)."""
    unique = f"_kashif_webdata_{name}_{id(object())}"
    spec = importlib.util.spec_from_file_location(unique, HERE / f"{name}.py")
    if spec is None or spec.loader is None:
        raise RefreshError(f"{name}: generator not found")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[unique] = mod                    # dataclasses and pickling look the module up by name
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.modules.pop(unique, None)
    return mod


# ---------------------------------------------------------------------------------------------- download

class _CheckedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def check_url(url: str) -> None:
    u = urllib.parse.urlparse(url)
    if u.scheme != "https" or (u.hostname or "") not in ALLOWED_HOSTS or u.username or u.password \
            or u.port not in (None, 443):
        raise RefreshError(f"refusing to download from {url!r} (https on an allowlisted host only)")


def http_get(url: str, timeout: float = TIMEOUT) -> bytes | None:
    """The body of ``url``, or None for a 404. Honest UA, HTTPS + host allowlist on every hop, size cap."""
    check_url(url)
    opener = urllib.request.build_opener(_CheckedRedirect())       # ProxyHandler included: HTTPS_PROXY works
    req = urllib.request.Request(url, headers={"User-Agent": f"Kashif/{__version__} webdata-refresh",
                                               "Accept": "*/*"})
    try:
        with opener.open(req, timeout=timeout) as resp:              # nosec B310 - https + allowlisted host
            body = resp.read(MAX_DOWNLOAD + 1)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise RefreshError(f"{url}: HTTP {e.code}") from e
    except (urllib.error.URLError, OSError) as e:
        raise RefreshError(f"{url}: {getattr(e, 'reason', e)}") from e
    if len(body) > MAX_DOWNLOAD:
        raise RefreshError(f"{url}: larger than {MAX_DOWNLOAD} bytes")
    return body


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _safe_rel(rel: str) -> Path:
    p = Path(rel)
    if p.is_absolute() or ".." in p.parts:
        raise RefreshError(f"bad mirror path {rel!r}")
    return p


def record(steps, mirror: Path, day: str, fetch: Callable[[str], bytes | None] = http_get, log=print) -> dict:
    """Download the inputs of ``steps`` into ``mirror`` and write its ``sources.json``; returns the index."""
    index = {"date": day, "kashif": __version__, "inputs": {}}
    for step in steps:
        if step.kind != "upstream":
            continue
        m = load_module(step.module)
        entries: dict[str, dict] = {}
        for inp in step.inputs(m):
            body, used, failures = None, inp.urls[0], []
            for url in inp.urls:                       # a mirror is tried when the first host fails or 404s
                try:
                    body, used = fetch(url), url
                except RefreshError as e:
                    failures.append(str(e))
                    continue
                if body is not None:
                    break
            if body is None and failures and len(failures) == len(inp.urls):
                raise RefreshError(f"{step.name}: {inp.rel}: " + "; ".join(failures))
            if body is None:
                if not inp.optional:
                    raise RefreshError(f"{step.name}: {inp.rel} not found upstream ({', '.join(inp.urls)})")
                entries[inp.rel] = {"url": inp.urls[0], "missing": True}
                continue
            dest = mirror / step.name / _safe_rel(inp.rel)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(body)
            entries[inp.rel] = {"url": used, "sha256": _sha(body), "size": len(body)}
        index["inputs"][step.name] = entries
        log(f"downloaded {step.name}: {sum(1 for e in entries.values() if not e.get('missing'))} file(s)")
    mirror.mkdir(parents=True, exist_ok=True)
    (mirror / SOURCES_INDEX).write_text(json.dumps(index, indent=1, sort_keys=True) + "\n", encoding="utf-8",
                                        newline="\n")
    return index


def read_index(mirror: Path) -> dict:
    try:
        index = json.loads((mirror / SOURCES_INDEX).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise RefreshError(f"{mirror}: no readable {SOURCES_INDEX} (record a mirror with --record)") from e
    if not isinstance(index, dict) or not _DATE.match(str(index.get("date", ""))):
        raise RefreshError(f"{mirror / SOURCES_INDEX}: no recording date")
    return index


def verify_mirror(steps, mirror: Path, index: dict) -> None:
    """Every input a step needs is in the mirror with the recorded sha256 (a tampered mirror never builds)."""
    for step in steps:
        if step.kind != "upstream":
            continue
        entries = index.get("inputs", {}).get(step.name)
        if not isinstance(entries, dict):
            raise RefreshError(f"{step.name}: not recorded in {mirror / SOURCES_INDEX}")
        for inp in step.inputs(load_module(step.module)):
            e = entries.get(inp.rel)
            if e is None:
                raise RefreshError(f"{step.name}: {inp.rel} not recorded in the mirror")
            if e.get("missing"):
                continue
            try:
                raw = (mirror / step.name / _safe_rel(inp.rel)).read_bytes()
            except OSError as err:
                raise RefreshError(f"{step.name}: {inp.rel} missing from the mirror") from err
            if _sha(raw) != e.get("sha256"):
                raise RefreshError(f"{step.name}: {inp.rel} does not match its recorded sha256")


# ------------------------------------------------------------------------------------------------- build

def select(only: str | None = None, skip: str | None = None) -> list[Step]:
    names = [s.name for s in STEPS]
    chosen = [n.strip() for n in only.split(",") if n.strip()] if only else names
    dropped = {n.strip() for n in skip.split(",") if n.strip()} if skip else set()
    unknown = sorted((set(chosen) | dropped) - set(names))
    if unknown:
        raise RefreshError(f"unknown step(s): {', '.join(unknown)} (see --list)")
    return [BY_NAME[n] for n in names if n in chosen and n not in dropped]


def build(steps, mirror: Path | None, staging: Path, base: Path, day: str, *, keep_curated_dates: bool = False,
          module_hook: Callable[[str, object], None] | None = None, log=print) -> None:
    """Run ``steps`` into ``staging`` (which must already hold the rest of the snapshot)."""
    index = read_index(mirror) if mirror is not None else {"inputs": {}}
    for step in steps:
        if step.kind == "upstream" and mirror is None:
            raise RefreshError(f"{step.name}: needs downloaded inputs")
        m = load_module(step.module) if step.module else None
        if module_hook and m is not None:
            module_hook(step.name, m)
        entries = index["inputs"].get(step.name, {})
        used = {rel: e.get("url", "") for rel, e in entries.items()}
        digest = hashlib.sha256("".join(f"{rel}\0{e.get('sha256', '-')}\n" for rel, e in sorted(entries.items()))
                                .encode("utf-8")).hexdigest()[:16] if entries else ""
        ctx = Ctx(date=day, src=(mirror / step.name) if mirror else staging, out=staging, base=base, used=used,
                  digest=digest, keep_curated_dates=keep_curated_dates)
        out, err = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                step.build(m, ctx)
        except SystemExit as e:
            if e.code not in (0, None):
                raise RefreshError(f"{step.name}: {e.code}\n{err.getvalue()}".rstrip()) from None
        except RefreshError as e:
            raise RefreshError(f"{step.name}: {e}\n{err.getvalue()}".rstrip()) from None
        except (OSError, ValueError, KeyError, TypeError) as e:
            raise RefreshError(f"{step.name}: {type(e).__name__}: {e}\n{err.getvalue()}".rstrip()) from None
        missing = [o for o in step.outputs if not (staging / o).is_file()]
        if missing:
            raise RefreshError(f"{step.name}: did not write {', '.join(missing)}")
        warn = err.getvalue().strip()
        log(f"built {step.name}: {', '.join(step.outputs)}" + (f"\n  {warn}" if warn else ""))


def stage_base(base: Path, staging: Path) -> None:
    """Start the staging directory as a copy of the current snapshot's data files (not its manifest)."""
    staging.mkdir(parents=True, exist_ok=True)
    for n in validate.expected_files():
        src = base / n
        if src.is_file():
            shutil.copyfile(src, staging / n)


def changed_files(staging: Path, target: Path) -> list[str]:
    out = []
    for n in [*validate.expected_files(), data.MANIFEST]:
        a, b = staging / n, target / n
        if not a.is_file():
            continue
        if not b.is_file() or a.read_bytes() != b.read_bytes():
            out.append(n)
    return out


def install(staging: Path, target: Path, names: list[str]) -> None:
    """Move ``names`` into ``target`` one by one (temp file + os.replace), MANIFEST.json last."""
    target.mkdir(parents=True, exist_ok=True)
    order = sorted(names, key=lambda n: (n == data.MANIFEST, n))
    for n in order:
        tmp = target / f".{n}.refresh-tmp"
        tmp.write_bytes((staging / n).read_bytes())
        tmp.replace(target / n)


def refresh(*, out: Path = DATA_DIR, steps=None, sources: Path | None = None, record_dir: Path | None = None,
            day: str | None = None, check: bool = False, pack_dir: Path | None = None, keep_curated_dates: bool = False,
            fetch: Callable[[str], bytes | None] = http_get, module_hook=None, log=print) -> dict:
    """Run a refresh. Returns ``{"changed": [...], "date", "asset"?}``; raises RefreshError (nothing installed)."""
    steps = list(STEPS if steps is None else steps)
    out = Path(out)
    with tempfile.TemporaryDirectory(prefix="kashif-webdata-refresh-") as tmp:
        tmp = Path(tmp)
        needs_net = any(s.kind == "upstream" for s in steps)
        if sources is not None:
            mirror = Path(sources)
            index = read_index(mirror)
            day = day or index["date"]
            verify_mirror(steps, mirror, index)
        elif needs_net:
            day = day or datetime.now(timezone.utc).date().isoformat()
            mirror = Path(record_dir) if record_dir is not None else tmp / "mirror"
            record(steps, mirror, day, fetch=fetch, log=log)
        else:
            mirror = None
            day = day or datetime.now(timezone.utc).date().isoformat()
        if not _DATE.match(day):
            raise RefreshError(f"bad date {day!r} (YYYY-MM-DD)")
        staging = tmp / "staging"
        stage_base(out, staging)
        build(steps, mirror, staging, out, day, keep_curated_dates=keep_curated_dates, module_hook=module_hook, log=log)
        errs = validate.validate_dir(staging)
        if errs:
            raise RefreshError("the rebuilt snapshot does not validate:\n  " + "\n  ".join(errs))
        validate.write_manifest(staging)
        changed = changed_files(staging, out)
        result: dict = {"date": day, "changed": changed}
        if check:
            log("up to date" if not changed else "differs from a rebuild: " + ", ".join(changed))
        else:
            install(staging, out, changed)
            log(f"installed {len(changed)} file(s) into {out}" if changed else "nothing changed")
        if pack_dir is not None:
            asset = validate.pack(staging, Path(pack_dir))
            result["asset"] = str(asset)
            log(validate.sha256_line(asset))
    return result


# --------------------------------------------------------------------------------------------------- CLI

def _list(log=print) -> None:
    for s in STEPS:
        log(f"{s.name:18} {s.kind:8} {', '.join(s.outputs)}")
        if s.kind == "upstream":
            for inp in s.inputs(load_module(s.module)):
                log(f"{'':28}{inp.urls[0]}" + ("  (optional)" if inp.optional else ""))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--only", help="comma-separated steps to run (default: all; see --list)")
    ap.add_argument("--skip", help="comma-separated steps to leave out")
    ap.add_argument("--date", help="snapshot date YYYY-MM-DD (default: today, UTC; with --sources: the recording date)")
    ap.add_argument("--sources", metavar="DIR", help="offline: rebuild from a mirror recorded with --record")
    ap.add_argument("--record", metavar="DIR", help="keep the downloaded upstream files (and sources.json) in DIR")
    ap.add_argument("--out", default=str(DATA_DIR), help="snapshot directory to refresh (default: vulnscan/data/web)")
    ap.add_argument("--check", action="store_true", help="do not install: exit 1 when a rebuild differs")
    ap.add_argument("--pack", metavar="DIR", help="also write the release asset kashif-webdata-<date>.tar.gz into DIR")
    ap.add_argument("--keep-curated-dates", action="store_true", help="do not restamp hand-curated files")
    ap.add_argument("--list", action="store_true", help="list the steps and their upstream URLs")
    args = ap.parse_args(argv)
    if args.list:
        _list()
        return 0
    if args.sources and args.record:
        ap.error("--sources and --record are exclusive")
    try:
        res = refresh(out=Path(args.out), steps=select(args.only, args.skip),
                      sources=Path(args.sources) if args.sources else None,
                      record_dir=Path(args.record) if args.record else None, day=args.date, check=args.check,
                      pack_dir=Path(args.pack) if args.pack else None, keep_curated_dates=args.keep_curated_dates)
    except RefreshError as e:
        print(f"refresh failed, nothing installed: {e}", file=sys.stderr)
        return 2
    return 1 if args.check and res["changed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
