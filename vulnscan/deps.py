"""Dependency analysis (SCA): manifests and lockfiles -> known vulnerabilities (OSV.dev) -> reachability.

``audit_dependencies(root)`` reads every supported manifest (vulnscan/sca.py), asks OSV.dev about each exact
package version (batched, retried, cached on disk for 24 hours), computes the severity (CVSS v3.x base score, or
the database's own label), finds the version to upgrade to, and checks whether the scanned code imports the
package and calls the advisory's vulnerable functions. A dependency the code never imports is reported one
severity level lower with a note; it is never hidden.

The only network access is to api.osv.dev; ``--no-deps`` (CLI) or the "use_osv" setting (UI) turns it off.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import pathlib
import re
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from . import sca
from .i18n import to_en
from .i18n.plural import ar_count
from .model import SEVERITIES, Finding

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{id}"
BATCH_SIZE = 500                 # OSV accepts up to 1000 queries per call
MAX_PAGES = 20
MAX_DETAIL_LOOKUPS = 400         # advisories fetched over the network in one run (cached ones are free)
RETRIES = 3
BACKOFF = 0.5
CACHE_TTL = 24 * 3600
_LABELS = ("critical", "high", "medium", "moderate", "low")
_NET_ERRORS = (urllib.error.URLError, OSError, ValueError)

# Counts in the notes agree with their noun (vulnscan/i18n/plural.py): one, two, few, many, other. "_GEN" forms
# follow a noun or a preposition (تفاصيل ثغرتين، لفحص اعتماديتين), "_NOM" forms are a subject (بقيت اعتماديتان).
_DEPS_GEN = ("اعتمادية واحدة", "اعتماديتين", "{n} اعتماديات", "{n} اعتماديةً", "{n} اعتمادية")
_DEPS_NOM = ("اعتمادية واحدة", "اعتماديتان", "{n} اعتماديات", "{n} اعتماديةً", "{n} اعتمادية")
_VULNS_GEN = ("ثغرة واحدة", "ثغرتين", "{n} ثغرات", "{n} ثغرةً", "{n} ثغرة")
_KNOWN_VULNS_NOM = ("ثغرة معروفة واحدة", "ثغرتان معروفتان", "{n} ثغرات معروفة", "{n} ثغرةً معروفةً", "{n} ثغرة معروفة")

NOTE_NOT_IMPORTED = "لم يُعثر على استيراد لهذه الحزمة في الكود المفحوص؛ خُفِّضت الخطورة درجة واحدة."
NOTE_IMPORTED = "الحزمة مستوردة في الكود المفحوص."
NOTE_NOT_CALLED = "الحزمة مستوردة، لكن لم يُعثر على استدعاء للدوال المصابة المذكورة في التقرير."
NOTE_UNKNOWN = "تعذّر تحديد ما إذا كان الكود يستخدم هذه الحزمة."
NOTE_TRANSITIVE = "هذه اعتمادية غير مباشرة؛ حدّث الحزمة التي تجلبها أو ثبّت الإصدار المُصحَّح."


def collect_packages(root: pathlib.Path) -> list[tuple[str, str, str, str]]:
    """Return (ecosystem, name, version, manifest) for pinned dependencies we can find."""
    return [(p.ecosystem, p.name, p.version, p.manifest) for p in sca.collect(pathlib.Path(root))]


# ------------------------------------------------------------------ network and cache

def _http(url: str, payload: dict | None, timeout: float) -> dict:
    """GET (payload None) or POST JSON, retrying transient failures. This is the default fetcher."""
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", "User-Agent": "kashif-sca"})
    last: Exception | None = None
    for attempt in range(RETRIES):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as e:
            if e.code not in (408, 429, 500, 502, 503, 504):
                raise
            last = e
        except _NET_ERRORS as e:
            last = e
        if attempt + 1 < RETRIES:
            time.sleep(BACKOFF * (2 ** attempt))
    raise last if last else OSError("OSV request failed")


def default_cache_dir() -> pathlib.Path:
    """``$KASHIF_HOME/cache/osv`` or ``$VULNSCAN_HOME/cache/osv``; otherwise a per-user directory under the temp dir."""
    home = os.environ.get("KASHIF_HOME") or os.environ.get("VULNSCAN_HOME")
    if home:
        return pathlib.Path(home) / "cache" / "osv"
    uid = os.getuid() if hasattr(os, "getuid") else "user"
    return pathlib.Path(tempfile.gettempdir()) / f"vulnscan-osv-cache-{uid}"


class _Cache:
    """One small JSON file per package@version and per advisory, valid for 24 hours."""

    def __init__(self, directory: pathlib.Path | None, enabled: bool = True, ttl: float = CACHE_TTL):
        self.dir = pathlib.Path(directory) if directory else default_cache_dir()
        self.ttl = ttl
        self.enabled = enabled and os.environ.get("VULNSCAN_OSV_CACHE", "1").lower() not in ("0", "off", "false", "no")
        if self.enabled:
            try:
                self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
                st = self.dir.lstat()
                # a temp-dir cache owned by someone else could feed us "no vulnerabilities": do not trust it
                if self.dir.is_symlink() or (hasattr(os, "getuid") and st.st_uid != os.getuid()):
                    self.enabled = False
                elif hasattr(os, "getuid") and st.st_mode & 0o022:
                    # ours but group/world-writable (made under a lax umask): others could plant answers in it
                    os.chmod(self.dir, 0o700)
                    self.enabled = not (self.dir.stat().st_mode & 0o022)
            except OSError:
                self.enabled = False

    def _path(self, kind: str, key: str) -> pathlib.Path:
        return self.dir / f"{kind}-{hashlib.sha256(key.encode('utf-8', 'replace')).hexdigest()[:40]}.json"

    def get(self, kind: str, key: str, stale: bool = False):
        if not self.enabled:
            return None
        try:
            rec = json.loads(self._path(kind, key).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(rec, dict) or rec.get("key") != key or "value" not in rec:
            return None
        age = time.time() - float(rec.get("time") or 0)
        return rec["value"] if stale or 0 <= age < self.ttl else None

    def put(self, kind: str, key: str, value) -> None:
        if not self.enabled:
            return
        path = self._path(kind, key)
        tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
        try:
            tmp.write_text(json.dumps({"key": key, "time": time.time(), "value": value}), encoding="utf-8")
            os.replace(tmp, path)
        except OSError:
            pass


def _id_list(value) -> list[str] | None:
    """A cached package answer, or None when the cache file holds anything but a list of advisory ids."""
    return value if isinstance(value, list) and all(isinstance(x, str) for x in value) else None


def _pkg_key(p: sca.Package) -> str:
    return f"{p.ecosystem}/{p.name}@{p.version}"


def _query_batch(fetch, pkgs: list[sca.Package], timeout: float) -> list[list[str]]:
    """Advisory ids for each package (same order), following OSV's per-query pagination."""
    queries = [{"package": {"name": p.name, "ecosystem": p.ecosystem}, "version": p.version} for p in pkgs]
    ids: list[list[str]] = [[] for _ in pkgs]
    todo = list(range(len(pkgs)))
    for _ in range(MAX_PAGES):
        if not todo:
            break
        results = (fetch(OSV_BATCH, {"queries": [queries[i] for i in todo]}, timeout) or {}).get("results")
        if not isinstance(results, list) or len(results) != len(todo):
            raise ValueError("unexpected OSV response")
        nxt = []
        for i, res in zip(todo, results):
            res = res or {}
            ids[i] += [v["id"] for v in res.get("vulns") or [] if isinstance(v, dict) and v.get("id")]
            if res.get("next_page_token"):
                queries[i] = {**queries[i], "page_token": res["next_page_token"]}
                nxt.append(i)
        todo = nxt
    return [list(dict.fromkeys(x)) for x in ids]


def _reason(e: Exception) -> str:
    text = str(getattr(e, "reason", "") or e) or type(e).__name__
    text = re.sub(r"\s+", " ", text)
    text = re.sub(r"[\u0600-\u06FF\u0750-\u077F\uFB50-\uFDFF\uFE70-\uFEFF]+", "?", text)   # keep the note translatable
    return f"{type(e).__name__}: {text}"[:160].strip()


# ------------------------------------------------------------------ advisory shape

def _dicts(value) -> list:
    return [x for x in value if isinstance(x, dict)] if isinstance(value, list) else []


def _dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _clean(detail) -> dict:
    """An OSV record with every field this module reads in the expected shape (lists of dicts, dicts, strings),
    so a malformed answer or a corrupted cache file degrades to "less information" instead of a crash."""
    d = dict(_dict(detail))
    if d.get("_clean") is True:
        return d
    affected = []
    for aff in _dicts(d.get("affected")):
        aff = dict(aff)
        aff["package"] = _dict(aff.get("package"))
        aff["ranges"] = [{**r, "events": _dicts(r.get("events"))} for r in _dicts(aff.get("ranges"))]
        aff["severity"] = _dicts(aff.get("severity"))
        aff["ecosystem_specific"] = _dict(aff.get("ecosystem_specific"))
        aff["database_specific"] = _dict(aff.get("database_specific"))
        affected.append(aff)
    d["affected"] = affected
    d["severity"] = _dicts(d.get("severity"))
    d["database_specific"] = _dict(d.get("database_specific"))
    d["aliases"] = [a for a in d.get("aliases") or [] if isinstance(a, str)] if isinstance(d.get("aliases"), list) else []
    for key in ("summary", "details"):
        if not isinstance(d.get(key), str):
            d.pop(key, None)
    d["_clean"] = True
    return d


# ------------------------------------------------------------------ severity (CVSS)

def _roundup(x: float) -> float:
    """CVSS v3.1 Roundup: smallest number with one decimal that is >= x, immune to float noise."""
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def _cvss_score(vector: str) -> float | None:
    """CVSS v3.0 / v3.1 base score from a vector string; None when the vector is not a complete v3 vector."""
    if not isinstance(vector, str) or not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    pairs = [part.split(":", 1) for part in vector.split("/")[1:] if ":" in part]
    m = dict(pairs)
    if len(m) != len(pairs):
        return None                                  # a metric given twice: not a valid vector (NVD rejects it)
    try:
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
        ac = {"L": 0.77, "H": 0.44}[m["AC"]]
        ui = {"N": 0.85, "R": 0.62}[m["UI"]]
        changed = {"C": True, "U": False}[m["S"]]
        pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[m["PR"]]
        cia = {"H": 0.56, "L": 0.22, "N": 0.0}
        iss = 1 - (1 - cia[m["C"]]) * (1 - cia[m["I"]]) * (1 - cia[m["A"]])
    except KeyError:
        return None
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    exploit = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    return _roundup(min(1.08 * (impact + exploit), 10)) if changed else _roundup(min(impact + exploit, 10))


def _cvss4_approx(vector: str) -> float | None:
    """A CVSS v4.0 vector scored through its v3.1 equivalent (v4's lookup tables are not reproduced here);
    close enough to pick a severity bucket when the database gives no label."""
    if not isinstance(vector, str) or not vector.startswith("CVSS:4"):
        return None
    m = dict(part.split(":", 1) for part in vector.split("/")[1:] if ":" in part)
    try:
        scope = "C" if any(m.get(k, "N") != "N" for k in ("SC", "SI", "SA")) else "U"
        ui = "N" if m["UI"] == "N" else "R"
        return _cvss_score(f"CVSS:3.1/AV:{m['AV']}/AC:{m['AC']}/PR:{m['PR']}/UI:{ui}/S:{scope}/C:{m['VC']}/I:{m['VI']}/A:{m['VA']}")
    except KeyError:
        return None


def _bucket(score: float) -> str:
    return "critical" if score >= 9.0 else "high" if score >= 7.0 else "medium" if score >= 4.0 else "low"


def _label(sev) -> str | None:
    if isinstance(sev, str) and sev.lower() in _LABELS:
        return "medium" if sev.lower() == "moderate" else sev.lower()
    return None


def cvss(v: dict) -> tuple[float | None, str]:
    """(highest CVSS v3 base score, its vector) of an OSV record, top level and per affected package."""
    best: tuple[float | None, str] = (None, "")
    v = _clean(v)
    entries = list(v.get("severity") or [])
    for aff in v.get("affected") or []:
        entries += aff.get("severity") or []
    for s in entries:
        score = _cvss_score(s.get("score", "")) if isinstance(s, dict) else None
        if score is not None and (best[0] is None or score > best[0]):
            best = (score, s["score"])
    return best


def _severity_from_vuln(v: dict) -> str:
    v = _clean(v)
    score, _ = cvss(v)
    if score is not None:
        return _bucket(score)
    for aff in v.get("affected") or []:
        sev = _label((aff.get("ecosystem_specific") or {}).get("severity")) or _label((aff.get("database_specific") or {}).get("severity"))
        if sev:
            return sev
    sev = _label((v.get("database_specific") or {}).get("severity"))
    if sev:
        return sev
    approx = [a for a in (_cvss4_approx(s.get("score", "")) for s in v.get("severity") or [] if isinstance(s, dict)) if a is not None]
    return _bucket(max(approx)) if approx else "medium"


# ------------------------------------------------------------------ advisory -> package facts

_SEMVER_ECOSYSTEMS = frozenset({"npm", "Go", "crates.io", "Pub", "NuGet", "Hex", "SwiftURL"})
# qualifier word -> rank. 6 is the release itself; lower ranks are pre-releases, higher ones come after it
_QUALIFIER_RANK = {"dev": 0, "snapshot": 5, "alpha": 1, "a": 1, "beta": 2, "b": 2, "milestone": 3, "m": 3,
                   "rc": 4, "c": 4, "cr": 4, "pre": 4, "preview": 4, "post": 7, "rev": 7, "r": 7, "sp": 7,
                   "patch": 7, "pl": 7, "p": 7}
_RELEASE_WORDS = frozenset({"final", "release", "ga", "stable"})
_RELEASE = (6, 0, "")


def _release_part(v: str) -> tuple[tuple, str]:
    """("1.2.3" as (1, 2, 3) with trailing zeros dropped, the rest of the string)."""
    m = re.match(r"\d+(?:\.\d+)*", v)
    if not m:
        return (), v
    nums = [int(x) for x in m.group(0).split(".")]
    while nums and nums[-1] == 0:
        nums.pop()                                   # 1.0 == 1.0.0
    return tuple(nums), v[m.end():]


def _semver_pre(pre: str) -> tuple:
    """SemVer 2.0 pre-release precedence: numeric identifiers compare numerically and sort before alphanumeric
    ones, which compare in ASCII order; a longer list wins when the shorter one is its prefix (the closing
    (2, 0, "") sorts below every identifier). Same (rank, number, word) shape as the other keys, all below 6."""
    return tuple((3, int(x), "") if x.isdigit() else (3.5, 0, x) for x in pre.split(".")) + ((2, 0, ""),)


def _vkey(v: str, ecosystem: str | None = None) -> tuple:
    """Ordering key for versions, per ecosystem: PEP 440 (epoch, dev < a < b < rc < release < post), SemVer 2.0
    (npm, Go incl. pseudo-versions, crates.io, Pub, NuGet: ``-pre`` sorts before the release), Maven
    (alpha < beta < milestone < rc < SNAPSHOT < release == Final/GA < sp) and RubyGems / Packagist (a letter
    segment starts a pre-release). Build metadata (``+...``) is ignored. Never raises."""
    eco = (ecosystem or "").split(":")[0]
    s = str(v).strip().split("+")[0].lstrip("vV=").strip()
    epoch = 0
    if eco == "PyPI" and "!" in s:
        e, _, s = s.partition("!")
        epoch = int(e) if e.isdigit() else 0
    release, rest = _release_part(s)
    if eco in _SEMVER_ECOSYSTEMS and (not rest or rest.startswith("-")):
        return (epoch, (2,) + release) + (_semver_pre(rest[1:]) if rest[1:] else (_RELEASE,))
    quals: list[tuple] = []
    for word, num in re.findall(r"([A-Za-z]+)?[.\-_]?(\d+)?", rest):
        if not word and not num:
            continue
        w = word.lower()
        if w in _RELEASE_WORDS and not num:
            continue
        rank = _QUALIFIER_RANK.get(w, 8 if eco == "Maven" else 3) if w else 7   # bare number: 1.0-1 is after 1.0
        quals.append((rank, int(num) if num else 0, w))
    return (epoch, (2,) + release) + tuple(quals) + (_RELEASE,)


def _same_package(aff: dict, name: str, ecosystem: str | None) -> bool:
    pkg = aff.get("package") or {}
    a, b = str(pkg.get("name", "")), name
    eco = str(pkg.get("ecosystem", "")).split(":")[0]
    if ecosystem and eco and eco.lower() != ecosystem.split(":")[0].lower():
        return False
    if (ecosystem or eco) == "PyPI":
        a, b = sca.pypi_name(a), sca.pypi_name(b)
    return a.lower() == b.lower()


def _fixed_version(detail: dict, name: str, ecosystem: str | None = None, version: str | None = None) -> str | None:
    """The version to upgrade to: the lowest fixed version above the installed one (so a 1.x user is sent to the
    1.x fix, not to 3.0); the first listed fix when the installed version is unknown."""
    fixed = []
    detail = _clean(detail)
    for aff in detail.get("affected") or []:
        if not _same_package(aff, name, ecosystem):
            continue
        for rng in aff.get("ranges") or []:
            if rng.get("type") == "GIT":
                continue
            fixed += [str(ev["fixed"]) for ev in rng.get("events") or [] if isinstance(ev, dict) and ev.get("fixed")]
    if not fixed:
        return None
    if version:
        key = lambda x: _vkey(x, ecosystem)                    # noqa: E731
        above = [f for f in fixed if key(f) > key(version)]
        if above:
            return min(above, key=key)
        return max(fixed, key=key)
    return fixed[0]


def vulnerable_symbols(detail: dict, name: str, ecosystem: str) -> list[tuple[str, str]]:
    """The advisory's vulnerable functions as (import path or '', symbol): Go ``ecosystem_specific.imports``,
    GitHub's ``affected_functions``, RustSec's ``affects.functions``."""
    out: list[tuple[str, str]] = []

    def add_list(value, path: str = "") -> None:
        for s in value if isinstance(value, list) else []:
            if isinstance(s, str) and s.strip():
                out.append((path, s.strip()))

    detail = _clean(detail)
    for aff in detail.get("affected") or []:
        if not _same_package(aff, name, ecosystem):
            continue
        for block in (aff.get("ecosystem_specific") or {}, aff.get("database_specific") or {}):
            if not isinstance(block, dict):
                continue
            for imp in block.get("imports") or []:
                if isinstance(imp, dict):
                    add_list(imp.get("symbols"), str(imp.get("path") or ""))
            add_list(block.get("affected_functions"))
            affects = block.get("affects")
            if isinstance(affects, dict):
                add_list(affects.get("functions"))
    add_list((detail.get("database_specific") or {}).get("affected_functions"))
    return list(dict.fromkeys(out))


def _lower(severity: str) -> str:
    """One level less severe, never below "low" (a known-vulnerable dependency stays visible)."""
    i = SEVERITIES.index(severity) if severity in SEVERITIES else 2
    return SEVERITIES[min(i + 1, SEVERITIES.index("low"))] if i < SEVERITIES.index("low") else severity


# ------------------------------------------------------------------ the audit

def audit_dependencies(root: pathlib.Path, timeout: float = 20.0, *, fetcher=None, cache_dir: pathlib.Path | None = None,
                       use_cache: bool = True, reachability: bool = True) -> tuple[list[Finding], str | None]:
    """Query OSV for every pinned package. Returns (findings, note or None); the note is set when OSV could not
    be reached for some or all packages. ``fetcher(url, payload_or_None, timeout) -> dict`` replaces the HTTP
    client (tests replay recorded OSV answers through it)."""
    root = pathlib.Path(root)
    pkgs = sca.collect(root)
    if not pkgs:
        return [], None
    fetch = fetcher or _http
    cache = _Cache(cache_dir, use_cache)

    ids: list[list[str] | None] = [_id_list(cache.get("pkg", _pkg_key(p))) for p in pkgs]
    need = [i for i, x in enumerate(ids) if not isinstance(x, list)]
    error: Exception | None = None
    for start in range(0, len(need), BATCH_SIZE):
        chunk = need[start:start + BATCH_SIZE]
        try:
            answers = _query_batch(fetch, [pkgs[i] for i in chunk], timeout)
        except _NET_ERRORS + (KeyError, TypeError, AttributeError) as e:
            error = e
            break                                    # OSV is unreachable: do not wait once per remaining chunk
        for i, answer in zip(chunk, answers):
            ids[i] = answer
            cache.put("pkg", _pkg_key(pkgs[i]), answer)
    stale = 0
    if error is not None:
        for i in need:
            if not isinstance(ids[i], list):
                old = _id_list(cache.get("pkg", _pkg_key(pkgs[i]), stale=True))   # an expired answer beats none
                if isinstance(old, list):
                    ids[i] = old
                    stale += 1
    unchecked = sum(1 for x in ids if not isinstance(x, list))

    wanted = list(dict.fromkeys(v for x in ids if isinstance(x, list) for v in x))
    details = _details(fetch, cache, wanted, timeout, offline=error is not None)
    index: sca.ImportIndex | None = None
    findings: list[Finding] = []
    for pkg, vuln_ids in zip(pkgs, ids):
        for vid in vuln_ids or []:
            detail = details.get(vid) or {}
            if detail.get("withdrawn"):
                continue
            if reachability and index is None:
                index = sca.ImportIndex(root)        # built once, and only when something is vulnerable
            findings.append(_finding(pkg, vid, detail, index))

    if error is None:
        lacking = sum(1 for v in wanted if not details.get(v))
        if lacking:                                  # ids are known, details (severity, fix) are not
            return findings, (f"تعذّر جلب تفاصيل {ar_count(lacking, _VULNS_GEN)} من OSV.dev؛ أُبلغ عنها بخطورة متوسطة ودون الإصدار "
                              "المُصحَّح. أعد الفحص لاحقًا للحصول على التفاصيل.")
        return findings, None
    checked = len(pkgs) - unchecked
    if not checked:
        return findings, (f"تعذّر الاتصال بـ OSV.dev لفحص {ar_count(len(pkgs), _DEPS_GEN)} ({_reason(error)}). "
                          "لم تُفحص ثغرات الاعتماديات؛ "
                          "أعد المحاولة عند توفّر الإنترنت، أو استخدم --no-deps لتعطيل هذا الفحص.")
    return findings, (f"تعذّر الاتصال بـ OSV.dev ({_reason(error)}): فُحصت {ar_count(checked, _DEPS_NOM)} من النتائج "
                      f"المخزَّنة مؤقتًا ({ar_count(len(findings), _KNOWN_VULNS_NOM)}) وبقيت "
                      f"{ar_count(unchecked, _DEPS_NOM)} بلا فحص.")


def _details(fetch, cache: _Cache, vuln_ids: list[str], timeout: float, offline: bool = False) -> dict[str, dict]:
    out: dict[str, dict] = {}
    missing = []
    for vid in vuln_ids:
        hit = cache.get("vuln", vid, stale=offline)
        if isinstance(hit, dict) and hit and hit.get("id") in (None, vid):
            out[vid] = hit
        else:
            missing.append(vid)
    if offline or not missing:
        return out

    down = threading.Event()

    def one(vid: str) -> tuple[str, dict]:
        if down.is_set():                            # the network went away mid-run: do not wait once per advisory
            return vid, {}
        try:
            data = fetch(OSV_VULN.format(id=urllib.parse.quote(vid, safe="")), None, timeout)
            return vid, data if isinstance(data, dict) else {}
        except urllib.error.HTTPError:
            return vid, {}                           # this advisory only (e.g. 404); the service is up
        except _NET_ERRORS:
            down.set()
            return vid, {}

    todo = missing[:MAX_DETAIL_LOOKUPS]
    with ThreadPoolExecutor(max_workers=min(8, len(todo))) as pool:
        for vid, data in pool.map(one, todo):
            if data:
                out[vid] = data
                cache.put("vuln", vid, data)
            else:
                old = cache.get("vuln", vid, stale=True)
                if isinstance(old, dict):
                    out[vid] = old
    return out


def _finding(pkg: sca.Package, vid: str, detail: dict, index: sca.ImportIndex | None) -> Finding:
    name, ver = pkg.name, pkg.version
    detail = _clean(detail)
    aliases = detail["aliases"]
    alias_text = ", ".join(aliases)
    fixed = _fixed_version(detail, name, pkg.ecosystem, ver)
    severity = _severity_from_vuln(detail)
    score, vector = cvss(detail)
    url = f"https://osv.dev/vulnerability/{vid}"
    extra: dict = {"ecosystem": pkg.ecosystem, "url": url, "package": name, "version": ver, "dependency": pkg.relation}
    if fixed:
        extra["fixed_version"] = fixed
    if aliases:
        extra["aliases"] = aliases
    if score is not None:
        extra["cvss_score"], extra["cvss_vector"] = score, vector
    if pkg.dev:
        extra["dev_dependency"] = True
    if pkg.also_in:
        extra["also_in"] = list(pkg.also_in)

    advice = [f"حدّث {name} إلى {fixed}." if fixed else f"حدّث {name} إلى إصدار مُصحَّح (راجع {url})."]
    if pkg.direct is False:
        advice.append(NOTE_TRANSITIVE)
    if index is not None:
        symbols = vulnerable_symbols(detail, name, pkg.ecosystem)
        status, called = index.reach(pkg, symbols)
        extra["reachability"] = status
        if symbols:
            extra["vulnerable_functions"] = [f"{p}.{s}" if p else s for p, s in symbols][:50]
        if status == sca.CALLED:
            extra["called_functions"] = called[:50]
            note = f"الكود يستدعي دوال مصابة في هذه الحزمة: {', '.join(called[:5])}."
        elif status == sca.NOT_IMPORTED:
            lowered = _lower(severity)
            if lowered != severity:
                extra["severity_original"], severity = severity, lowered
            note = NOTE_NOT_IMPORTED
        elif status == sca.IMPORTED:
            note = NOTE_NOT_CALLED if symbols else NOTE_IMPORTED
        else:
            note = NOTE_UNKNOWN
        extra["reachability_note"], extra["reachability_note_en"] = note, to_en(note)
        advice.append(note)
    cwes = (detail.get("database_specific") or {}).get("cwe_ids") or []
    return Finding(
        rule_id=f"OSV:{vid}", severity=severity,
        title=f"Vulnerable dependency {name} {ver} ({vid}{', ' + alias_text if alias_text else ''})",
        title_ar=f"اعتمادية مصابة بثغرة معروفة: {name} {ver}",
        file=pkg.manifest, line=0,
        snippet=(detail.get("summary") or detail.get("details") or "")[:200],
        advice=" ".join(advice), cwe=cwes[0] if cwes and isinstance(cwes[0], str) else "",
        source="osv", extra=extra,
    )
