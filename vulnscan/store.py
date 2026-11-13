"""Persistent settings and scan history under ~/.vulnscan (JSON files).

Scans are stored one JSON file each (``scans/<id>.json``). Every scan belongs to a *project*: the set of scans of
the same normalized target (a local path, a URL, or an upload of the same name). ``scans/../index.json`` is a
cache of each scan's metadata (everything but the findings) and of its finding fingerprints, keyed by scan id and
validated against the scan file's size and modification time, so listing projects does not re-read every finding of
every scan. The cache is rebuilt from the scan files whenever it is missing, stale or unreadable: scans written by
earlier versions need no migration.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import threading
import time
import urllib.parse
import uuid

DEFAULT_SETTINGS = {
    "language": "ar",
    "theme": "auto",
    "min_severity": "info",
    "web_timeout": 20,
    "web_delay": 0.5,
    # 1.1.0 passive web scanning (spec §4.5): the same options as the CLI's --web-* flags
    "web_profile": "standard",          # minimal | standard | deep
    "web_sensitivity": "default",       # strict | default | paranoid
    "web_respect_robots": True,
    "web_third_party_lookups": False,
    "web_use_proxy": True,
    "web_compare_previous": True,       # diff against the last scan of the same site (spec §3.7: default on in the UI)
    "web_cookie_ignore": [],
    "exclude": ["tests/*", "**/test_*", "**/*.test.*"],
    "ignore_rules": [],
    "use_osv": True,
    "use_external": True,
    "use_jadx": True,
    "audit": False,
    "models_dir": "",
    "queries_dir": "",
    "jadx_timeout": 600,
    "jadx_include_libs": False,
    "fail_on": "high",
    "authorized_targets": [],
    "keep_scans": 50,
    "check_updates": True,          # look for a newer release at UI start (GitHub API, cached 6 hours)
}

SEVERITIES = ("critical", "high", "medium", "low", "info")
INDEX_VERSION = 2          # 2: per-scan legacy keys, occurrence-numbered keys (older indexes are rebuilt).
# 1.1.0 web scans are indexed without their inventory and snapshot; scans saved by 1.0.x carry neither, so an index
# of version 2 needs no rebuild for them.
WEB_HEAVY_KEYS = ("web", "web_snapshot")  # kept in the scan file only; the index carries "web_brief"
TREND_POINTS = 20          # scans shown in a project's trend
DIFF_LIST_CAP = 200        # new / fixed findings listed per project


def project_key(scan: dict) -> str:
    """The normalized identity of what a scan looked at. Scans with the same key form one project.

    * URL: scheme and host lower-cased, default port, query, fragment and trailing slash dropped.
    * Upload: the temporary folder differs every time, so the upload's label (the archive name) is the identity.
    * Path: absolute, normalized (``a/./b/../c``, duplicate and trailing separators), case-folded on Windows.
    """
    target = str(scan.get("target") or "").strip()
    if scan.get("kind") == "upload":
        return "upload:" + str(scan.get("label") or pathlib.PurePath(target).name)
    if target.lower().startswith(("http://", "https://")):
        try:
            u = urllib.parse.urlsplit(target)
            host = (u.hostname or "").lower()
            port = u.port
        except ValueError:
            return "url:" + target.rstrip("/").lower()
        scheme = u.scheme.lower()
        if port and port != {"http": 80, "https": 443}.get(scheme):
            host += f":{port}"
        return f"url:{scheme}://{host}{u.path.rstrip('/')}"
    if not target:
        return "path:"
    norm = os.path.normcase(os.path.normpath(os.path.abspath(os.path.expanduser(target))))
    return "path:" + (norm.rstrip("\\/") or norm)


def project_id(key: str) -> str:
    """A short, URL-safe, stable id for a project key."""
    return hashlib.sha256(key.encode("utf-8", "surrogatepass")).hexdigest()[:12]


def project_name(scan: dict) -> str:
    """A short display name: the upload label, the URL host (+ path), or the last path component."""
    if scan.get("label"):
        return str(scan["label"])
    target = str(scan.get("target") or "")
    if target.lower().startswith(("http://", "https://")):
        try:
            u = urllib.parse.urlsplit(target)
            return (u.netloc or target) + (u.path.rstrip("/") if u.path not in ("", "/") else "")
        except ValueError:
            return target
    parts = [p for p in _display_path(target).replace("\\", "/").split("/") if p]
    return parts[-1] if parts else target


def _display_path(target: str) -> str:
    """A local target as shown for its project: absolute and normalized, original letter case kept."""
    if not target or target.lower().startswith(("http://", "https://")):
        return target
    return os.path.normpath(os.path.abspath(os.path.expanduser(target)))


def finding_key(f: dict) -> str:
    """Identity of a finding across scans: its fingerprint; for scans saved before fingerprints existed, the
    rule, the file (without an archive prefix) and the code."""
    fp = f.get("fingerprint")
    if fp:
        return str(fp)
    return _legacy_key(f)


def _legacy_key(f: dict) -> str:
    file = str(f.get("file") or "")
    return f"{f.get('rule_id')}|{file.rsplit('!', 1)[-1]}|{f.get('snippet')}"


def finding_keys(findings: list, legacy: bool = False) -> list[str]:
    """One identity per finding, in order: ``finding_key`` (or the legacy rule|file|code key), with a repeated
    identity numbered ``#2``, ``#3``... so two identical old-style findings in one file count as two."""
    out, seen = [], {}
    for f in findings:
        if not isinstance(f, dict):
            continue
        k = _legacy_key(f) if legacy else finding_key(f)
        n = seen[k] = seen.get(k, 0) + 1
        out.append(k if n == 1 else f"{k}#{n}")
    return out


def _comparable(a: dict, b: dict) -> tuple[set, set]:
    """Finding identities of two index entries, compared by fingerprint when both scans have them and by the
    legacy key otherwise (a scan saved before fingerprints next to a newer one must not look all new)."""
    if a.get("fp_all", True) and b.get("fp_all", True):
        return set(a.get("fps") or []), set(b.get("fps") or [])
    return set(a.get("lks") or []), set(b.get("lks") or [])


def _counts(meta: dict | None) -> dict:
    """Per-severity counts of a scan's summary; anything that is not a count reads as 0."""
    summary = (meta or {}).get("summary")
    summary = summary if isinstance(summary, dict) else {}
    out = {}
    for k in SEVERITIES:
        try:
            out[k] = max(0, int(summary.get(k) or 0))
        except (TypeError, ValueError):
            out[k] = 0
    return out


def web_brief(web: dict, has_snapshot: bool = False) -> dict:
    """What lists and dashboards show of a web scan: its profile and the three grades (letter and score)."""
    grades = web.get("grades") if isinstance(web.get("grades"), dict) else {}
    out = {"profile": web.get("profile") if isinstance(web.get("profile"), str) else "", "snapshot": bool(has_snapshot)}
    for alg in ("kashif", "observatory", "ssllabs"):
        g = grades.get(alg) if isinstance(grades.get(alg), dict) else {}
        out[alg] = {"grade": g.get("grade") if isinstance(g.get("grade"), str) else None,
                    "score": g.get("score") if isinstance(g.get("score"), (int, float)) else None}
    return out


def _brief(f: dict) -> dict:
    return {k: f.get(k) for k in ("rule_id", "severity", "title", "title_ar", "file", "line", "fingerprint", "cwe")}


class Store:
    def __init__(self, home: pathlib.Path | None = None):
        # nosec: VULNSCAN_HOME is the operator's own install location, not untrusted input; the store only ever writes under it.
        self.home = home or pathlib.Path(os.environ.get("VULNSCAN_HOME") or pathlib.Path.home() / ".vulnscan")
        self.scans_dir = self.home / "scans"
        self.scans_dir.mkdir(parents=True, exist_ok=True)  # nosec: scans_dir is under the operator-configured home.
        self.index_path = self.home / "index.json"
        self._lock = threading.Lock()
        self._index_cache: dict | None = None

    # ---------------------------------------------------------------- settings
    def settings(self) -> dict:
        p = self.home / "settings.json"
        data = dict(DEFAULT_SETTINGS)
        if p.exists():
            try:
                data.update(json.loads(p.read_text(encoding="utf-8")))
            except ValueError:
                pass
        return data

    def save_settings(self, patch: dict) -> dict:
        with self._lock:
            data = self.settings()
            for k, v in patch.items():
                if k in DEFAULT_SETTINGS:
                    data[k] = v
            (self.home / "settings.json").write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        return data

    # ------------------------------------------------------------------- scans
    def new_scan(self, target: str, kind: str) -> dict:
        scan = {"id": uuid.uuid4().hex[:12], "target": target, "kind": kind, "status": "running",
                "started_at": time.time(), "finished_at": None, "files_scanned": 0, "notes": [],
                "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}, "findings": [], "error": None}
        self.save_scan(scan)
        return scan

    def save_scan(self, scan: dict) -> None:
        """Atomic write (temp file + rename) so concurrent readers never see a partial file."""
        with self._lock:
            final = self.scans_dir / f"{scan['id']}.json"
            tmp = final.with_suffix(".tmp")
            tmp.write_text(json.dumps(scan, ensure_ascii=False), encoding="utf-8")
            os.replace(tmp, final)  # nosec: final is derived from the operator-configured home, not from scanned input.
        self._prune()

    def get_scan(self, scan_id: str) -> dict | None:
        if not scan_id.isalnum():                       # checked first: no filesystem probe for "../x"
            return None
        p = self.scans_dir / f"{scan_id}.json"
        if not p.exists():
            return None
        try:
            with self._lock:
                return json.loads(p.read_text(encoding="utf-8"))
        except ValueError:
            return None

    def list_scans(self, project: str | None = None) -> list[dict]:
        """Every stored scan without its findings, newest first; each carries the id of its project.
        `project` keeps only the scans of that project."""
        out = [dict(e["meta"]) for e in self._index().values()]
        if project:
            out = [s for s in out if s.get("project") == project]
        return sorted(out, key=lambda s: s.get("started_at") or 0, reverse=True)

    # ---------------------------------------------------------------- index
    def _index(self) -> dict:
        """scan id -> {"sig": [mtime_ns, size], "meta": scan without findings (+ "project"), "fps": [finding keys]}.
        Entries whose scan file changed are re-read; entries whose file is gone are dropped."""
        with self._lock:
            idx = self._index_cache
            if idx is None:
                idx = {}
                try:
                    data = json.loads(self.index_path.read_text(encoding="utf-8"))
                    if isinstance(data, dict) and data.get("version") == INDEX_VERSION and isinstance(data.get("scans"), dict):
                        idx = data["scans"]
                except (OSError, ValueError):
                    pass
            seen, dirty = set(), False
            for p in self.scans_dir.glob("*.json"):
                try:
                    st = p.stat()
                except OSError:
                    continue
                sid, sig = p.stem, [st.st_mtime_ns, st.st_size]
                seen.add(sid)
                e = idx.get(sid)
                if isinstance(e, dict) and e.get("sig") == sig and isinstance(e.get("meta"), dict):
                    continue
                dirty = True
                try:
                    scan = json.loads(p.read_text(encoding="utf-8"))
                    if not isinstance(scan, dict) or "started_at" not in scan:
                        raise ValueError("not a scan")
                except (OSError, ValueError):
                    idx.pop(sid, None)
                    seen.discard(sid)
                    continue
                findings = scan.pop("findings", None) or []
                web = scan.pop("web", None)
                snap = scan.pop("web_snapshot", None)
                if isinstance(web, dict) or isinstance(snap, dict):
                    scan["web_brief"] = web_brief(web if isinstance(web, dict) else {}, isinstance(snap, dict) and bool(snap))
                findings = [f for f in findings if isinstance(f, dict)] if isinstance(findings, list) else []
                scan["id"] = sid                         # the file name is the id the API serves it under
                if not isinstance(scan.get("summary"), dict):
                    scan["summary"] = {}
                scan["project"] = project_id(project_key(scan))
                idx[sid] = {"sig": sig, "meta": scan, "fps": sorted(finding_keys(findings)),
                            "lks": sorted(finding_keys(findings, legacy=True)),
                            "fp_all": all(f.get("fingerprint") for f in findings)}
            for sid in [k for k in idx if k not in seen]:
                del idx[sid]
                dirty = True
            self._index_cache = idx
            if dirty:
                try:
                    tmp = self.index_path.with_suffix(".tmp")
                    tmp.write_text(json.dumps({"version": INDEX_VERSION, "scans": idx}, ensure_ascii=False), encoding="utf-8")
                    os.replace(tmp, self.index_path)  # nosec: index_path is under the operator-configured home.
                except OSError:
                    pass                               # read-only home: the in-memory index still serves this process
            return dict(idx)

    # -------------------------------------------------------------- projects
    def list_projects(self) -> list[dict]:
        """One record per scanned target, most recently scanned first. See `_project`."""
        groups: dict[str, list[dict]] = {}
        for e in self._index().values():
            groups.setdefault(e["meta"]["project"], []).append(e)
        out = [self._project(pid, entries) for pid, entries in groups.items()]
        return sorted(out, key=lambda p: p["last_scan_at"] or 0, reverse=True)

    def get_project(self, pid: str) -> dict | None:
        """The project record plus its scans (newest first, without findings) and the findings that appeared
        (`new_findings`) or disappeared (`fixed_findings`) between its last two completed scans."""
        if not pid.isalnum():
            return None
        entries = [e for e in self._index().values() if e["meta"]["project"] == pid]
        if not entries:
            return None
        proj = self._project(pid, entries)
        proj["scans"] = sorted((dict(e["meta"]) for e in entries), key=lambda s: s.get("started_at") or 0, reverse=True)
        proj["new_findings"], proj["fixed_findings"] = [], []
        done = [s for s in proj["scans"] if s.get("status") == "done"]
        if len(done) >= 2:
            head, base = self.get_scan(done[0]["id"]) or {}, self.get_scan(done[1]["id"]) or {}
            hf = [f for f in head.get("findings") or [] if isinstance(f, dict)]
            bf = [f for f in base.get("findings") or [] if isinstance(f, dict)]
            legacy = not all(f.get("fingerprint") for f in hf + bf)      # same rule as the counts (_comparable)
            hk, bk = finding_keys(hf, legacy), finding_keys(bf, legacy)
            hs, bs = set(hk), set(bk)
            proj["new_findings"] = [_brief(f) for f, k in zip(hf, hk) if k not in bs][:DIFF_LIST_CAP]
            proj["fixed_findings"] = [_brief(f) for f, k in zip(bf, bk) if k not in hs][:DIFF_LIST_CAP]
        return proj

    @staticmethod
    def _project(pid: str, entries: list[dict]) -> dict:
        """id, key, name, target, kind, label · scans / done_scans (counts) · last_scan (newest scan of any status)
        and last_scan_at · latest (newest completed scan), summary and total of it · previous (the completed scan
        before it) · new / fixed (finding identities gained / lost between those two; None with fewer than two
        completed scans) · delta (change in total) · trend (completed scans, oldest first, at most TREND_POINTS)."""
        entries = sorted(entries, key=lambda e: e["meta"].get("started_at") or 0, reverse=True)
        newest = entries[0]["meta"]
        done = [e for e in entries if e["meta"].get("status") == "done"]
        latest = done[0]["meta"] if done else None
        summary = _counts(latest)
        new = fixed = delta = previous = None
        if len(done) >= 2:
            a, b = _comparable(done[1], done[0])
            new, fixed = len(b - a), len(a - b)
            previous = done[1]["meta"]["id"]
            delta = sum(summary.values()) - sum(_counts(done[1]["meta"]).values())
        trend = []
        for e in done[:TREND_POINTS][::-1]:
            m = e["meta"]
            counts = _counts(m)
            trend.append({"id": m["id"], "at": m.get("finished_at") or m.get("started_at"), **counts, "total": sum(counts.values())})
        ref = latest or newest
        return {"id": pid, "key": project_key(ref), "name": project_name(ref),
                "target": ref.get("target") if ref.get("kind") == "upload" else _display_path(str(ref.get("target") or "")),
                "kind": ref.get("kind"), "label": ref.get("label"),
                "scans": len(entries), "done_scans": len(done),
                "last_scan": {k: newest.get(k) for k in ("id", "status", "started_at", "finished_at", "error", "error_en")},
                "last_scan_at": newest.get("finished_at") or newest.get("started_at"),
                "latest": latest["id"] if latest else None, "files_scanned": (latest or {}).get("files_scanned", 0),
                "summary": summary, "total": sum(summary.values()),
                "previous": previous, "new": new, "fixed": fixed, "delta": delta, "trend": trend}

    def latest_web_snapshot(self, target: str, exclude: str | None = None) -> dict | None:
        """The ``web_snapshot`` (spec §3.7) of the newest completed scan of the same normalised target, or None.
        ``exclude``: a scan id to skip (the scan being compared)."""
        pid = project_id(project_key({"target": target, "kind": "url"}))
        for meta in self.list_scans(pid):
            if meta.get("status") != "done" or meta.get("id") == exclude:
                continue
            brief = meta.get("web_brief")
            if isinstance(brief, dict) and not brief.get("snapshot"):
                continue
            scan = self.get_scan(str(meta.get("id") or ""))
            snap = (scan or {}).get("web_snapshot")
            if isinstance(snap, dict) and snap:
                return snap
        return None

    def delete_scan(self, scan_id: str) -> bool:
        p = self.scans_dir / f"{scan_id}.json"
        if scan_id.isalnum() and p.exists():
            p.unlink()
            return True
        return False

    def _prune(self) -> None:
        keep = int(self.settings().get("keep_scans") or 50)
        scans = sorted(self.scans_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        for p in scans[keep:]:
            p.unlink(missing_ok=True)
