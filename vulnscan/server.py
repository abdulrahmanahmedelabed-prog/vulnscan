"""Local web UI: a small JSON API plus static files, bound to 127.0.0.1 only."""

from __future__ import annotations

import json
import mimetypes
import os
import pathlib
import re
import shutil
import tempfile
import sys
import threading
import time
import urllib.parse
from datetime import datetime, timezone
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__, updater
from .deps import audit_dependencies
from .external import available, run_external
from .i18n import to_en
from .model import SEVERITY_RANK, Finding, assign_fingerprints, sort_findings
from .report import render_html, render_json, render_markdown, render_sarif, summary_counts
from .rules import RULES
from .scanner import ARCHIVE_EXTS, JADX_EXTS, jadx_available, scan_path
from .store import Store
from .web import scan_site

# When frozen by PyInstaller the UI files are unpacked under sys._MEIPASS.
if getattr(sys, "frozen", False):
    UI_DIR = pathlib.Path(getattr(sys, "_MEIPASS", pathlib.Path(sys.executable).parent)) / "vulnscan" / "ui"
else:
    UI_DIR = pathlib.Path(__file__).parent / "ui"
MAX_UPLOAD = 512 * 1024 * 1024


def _dict_to_finding(d: dict) -> Finding:
    """Rebuild a Finding from its saved to_dict() form. Derived keys (fingerprint, severity_ar and the English
    counterparts advice_en / snippet_en / extra.path[*].text_en) are recomputed by to_dict, so they are dropped."""
    extra = dict(d.get("extra") or {})
    if isinstance(extra.get("path"), list):
        extra["path"] = [{k: v for k, v in st.items() if k != "text_en"} if isinstance(st, dict) else st
                         for st in extra["path"]]
    return Finding(d["rule_id"], d["severity"], d["title"], d["title_ar"], d["file"], d["line"], d["snippet"],
                   d["advice"], d.get("cwe", ""), d.get("source", "vulnscan"), extra)


def _upgrade(d: dict) -> dict:
    """A saved finding dict with the English keys added; every saved key (fingerprint included) is kept."""
    new = _dict_to_finding(d).to_dict()
    new.update({k: v for k, v in d.items() if k != "extra"})
    return new


def _with_english(scan: dict) -> dict:
    """Scans saved before English support lack notes_en / error_en and the per-finding *_en keys: fill them in
    on read (a copy; the stored file is left as it is)."""
    scan = dict(scan)
    if scan.get("notes") is not None and "notes_en" not in scan:
        scan["notes_en"] = [to_en(n) for n in scan["notes"]]
    if scan.get("error") and "error_en" not in scan:
        scan["error_en"] = to_en(scan["error"])
    if scan.get("findings") and any("advice_en" not in d for d in scan["findings"]):
        scan["findings"] = [d if "advice_en" in d else _upgrade(d) for d in scan["findings"]]
    return scan


MAX_JSON_BODY = 1024 * 1024          # triage / surface requests are small; refuse anything bigger
_ID = re.compile(r"^[0-9A-Za-z]{1,64}$")


def _scan_findings(scan: dict) -> list[dict]:
    """The saved finding dicts of a scan (anything malformed is skipped)."""
    return [d for d in scan.get("findings") or [] if isinstance(d, dict) and "rule_id" in d]


def _scan_meta(scan: dict) -> dict:
    """Report metadata of a saved scan, for exporters / compliance."""
    when = scan.get("finished_at") or scan.get("started_at")
    meta = {"target": scan.get("label") or scan.get("target", ""), "files_scanned": scan.get("files_scanned", 0),
            "notes": list(scan.get("notes") or []), "scan_id": scan.get("id")}
    for key, value in (("generated_at", when), ("started_at", scan.get("started_at"))):
        if isinstance(value, (int, float)):
            meta[key] = datetime.fromtimestamp(value, timezone.utc).isoformat(timespec="seconds")
    return meta


def local_root(scan: dict) -> pathlib.Path | None:
    """The scanned directory or file on this machine, for scans the server ran itself on a local path; None for
    URL scans and uploads (an upload's temporary copy is deleted after the scan)."""
    target = str(scan.get("target") or "")
    if scan.get("kind") != "path" or not target or target.startswith(("http://", "https://")):
        return None
    root = pathlib.Path(target)
    return root if root.exists() else None


def _is_pro_path(path: str) -> bool:
    """The endpoints added for 1.0 (exports, compliance, attack surface, triage)."""
    parts = path.split("/")
    return (path in ("/api/export/formats", "/api/compliance/frameworks", "/api/triage", "/api/triage/set",
                     "/api/triage/comment", "/api/triage/severity")
            or (len(parts) == 5 and parts[2] in ("scans", "projects")
                and parts[4] in ("export", "compliance", "audit.html", "surface")))


def triage_path(store: Store, scan: dict) -> pathlib.Path:
    """Where the decisions of a scan's project live, derived on the server side only (never from the request):
    ``<project>/.kashif/triage.json`` for a local path the server scanned (the file triage.py designs, committed
    with the code), else ``<home>/triage/<project id>.json`` for uploads and URLs, which have no project tree."""
    from . import triage
    from .store import project_id, project_key
    root = local_root(scan)
    if root is not None:
        return triage.default_path(root)
    return store.home / "triage" / f"{project_id(project_key(scan))}.json"


class _SurfaceJobs:
    """Attack-surface maps being built (one thread per scan; the result is cached under <home>/surface)."""

    def __init__(self):
        self.lock = threading.Lock()
        self.running: dict[str, float] = {}
        self.errors: dict[str, str] = {}

    def start(self, store: Store, scan: dict, settings: dict, engine: bool) -> bool:
        with self.lock:
            if scan["id"] in self.running:
                return False
            self.running[scan["id"]] = time.time()
            self.errors.pop(scan["id"], None)
        threading.Thread(target=self._run, args=(store, scan, settings, engine), daemon=True).start()
        return True

    def _run(self, store: Store, scan: dict, settings: dict, engine: bool) -> None:
        try:
            from . import surface
            root = local_root(scan)
            if root is None:
                raise FileNotFoundError(scan.get("target", ""))
            models = [settings["models_dir"]] if settings.get("models_dir") else None
            surf = surface.build_surface(root, findings=_scan_findings(scan), excludes=settings.get("exclude") or [],
                                         models_dirs=models, engine=engine)
            doc = {"scan": scan["id"], "engine": engine, "built_at": time.time(),
                   "surface": {"en": surf.to_dict("en"), "ar": surf.to_dict("ar")},
                   "mermaid": {"en": surface.render_mermaid(surf, "en"), "ar": surface.render_mermaid(surf, "ar")},
                   "openapi": surface.render_openapi(surf, "en")}
            out = store.home / "surface"
            out.mkdir(parents=True, exist_ok=True)
            tmp = out / f"{scan['id']}.tmp"
            tmp.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
            os.replace(tmp, out / f"{scan['id']}.json")
        except Exception as e:  # noqa: BLE001 - reported to the UI by GET .../surface
            with self.lock:
                self.errors[scan["id"]] = f"{type(e).__name__}: {e}"[:500]
        finally:
            with self.lock:
                self.running.pop(scan["id"], None)


def run_scan(store: Store, scan: dict, settings: dict, authorized: bool) -> None:
    """Executes in a worker thread and persists progress."""
    target = scan["target"]
    try:
        findings: list[Finding] = []
        notes: list[str] = []
        files = 0
        if target.startswith(("http://", "https://")):
            if not authorized:
                raise PermissionError("فحص عنوان ويب يتطلب تأكيد الصلاحية.")
            deep = bool(scan.get("deep"))
            crawl = bool(scan.get("crawl"))
            timeout = float(settings.get("web_timeout") or 20)
            delay = float(settings.get("web_delay", 0.5))
            # raises WebUnreachable -> status "error"
            findings, extra, files = scan_site(target, timeout=timeout, deep=deep, crawl=crawl, delay=delay)
            if crawl:
                notes.append(f"فحص ويب سلبي مع زحف على {files} صفحة من النطاق نفسه (طلب كل {delay:g} ثانية).")
            else:
                notes.append("فحص ويب سلبي أعمق: تحليل الصفحة ومسارات مكشوفة شائعة." if deep else "فحص ويب سلبي: طلب واحد فقط.")
            if extra:
                notes.append(extra)
        else:
            path = pathlib.Path(target)
            if not path.exists():
                raise FileNotFoundError(f"الهدف غير موجود: {target}")
            findings, files = scan_path(path, settings.get("exclude") or [], set(settings.get("ignore_rules") or []),
                                        jadx=bool(settings.get("use_jadx", True)), jadx_timeout=int(settings.get("jadx_timeout") or 600),
                                        jadx_include_libs=bool(settings.get("jadx_include_libs")), notes=notes,
                                        audit=bool(settings.get("audit")),
                                        models_dirs=[settings["models_dir"]] if settings.get("models_dir") else None,
                                        query_paths=[settings["queries_dir"]] if settings.get("queries_dir") else None)
            scan["files_scanned"] = files
            store.save_scan(scan)
            if settings.get("use_osv", True):
                dep, err = audit_dependencies(path)
                findings.extend(dep)
                notes.append(err or f"OSV.dev: {len(dep)} ثغرة معروفة في الاعتماديات.")
            if settings.get("use_external", True):
                ext, ran = run_external(path)
                findings.extend(ext)
                if ran:
                    notes.append("أدوات خارجية: " + ", ".join(ran))
        assign_fingerprints(findings)          # on the full list, as the CLI does, so every endpoint agrees
        min_sev = settings.get("min_severity", "info")
        findings = [f for f in sort_findings(findings) if SEVERITY_RANK[f.severity] <= SEVERITY_RANK[min_sev]]
        if not target.startswith(("http://", "https://")):
            try:                               # suggested fixes ("fix" in each finding), as the CLI attaches them
                from . import autofix
                autofix.attach_fixes(findings, target)
            except Exception:  # noqa: BLE001 - a missing or failing fixer never fails the scan
                pass
        scan.update(status="done", finished_at=time.time(), files_scanned=files, notes=notes,
                    notes_en=[to_en(n) for n in notes], summary=summary_counts(findings), findings=[f.to_dict() for f in findings])
    except Exception as e:  # noqa: BLE001 - surfaced to the UI
        scan.update(status="error", finished_at=time.time(), error=str(e), error_en=to_en(str(e)))
    finally:
        if scan.get("kind") == "upload" and scan.get("tmp_root"):
            shutil.rmtree(scan["tmp_root"], ignore_errors=True)  # nosec - operates on the user's own scan target / our temp dir by design
        store.save_scan(scan)


def parse_multipart(body: bytes, content_type: str) -> list[tuple[str, bytes]]:
    """Minimal multipart/form-data parser returning (filename, bytes) for file parts."""
    m = re.search(r'boundary="?([^";]+)"?', content_type)
    if not m:
        return []
    boundary = b"--" + m.group(1).encode()
    out: list[tuple[str, bytes]] = []
    for part in body.split(boundary)[1:]:
        if part.strip() in (b"", b"--"):
            continue
        head, sep, data = part.partition(b"\r\n\r\n")
        if not sep:
            continue
        data = data[:-2] if data.endswith(b"\r\n") else data
        fm = re.search(rb'filename="([^"]*)"', head)
        if not fm or not fm.group(1):
            continue
        out.append((fm.group(1).decode("utf-8", "replace"), data))
    return out


def _default_author() -> str:
    """Who records a triage decision from the UI when the request names nobody: $KASHIF_AUTHOR, else the OS user."""
    name = os.environ.get("KASHIF_AUTHOR", "")
    if not name:
        try:
            import getpass
            name = getpass.getuser()
        except (OSError, KeyError, ImportError):
            name = ""
    return name or "kashif-ui"


class Handler(BaseHTTPRequestHandler):
    store: Store
    lang = "both"
    update_job = updater.Job()
    surface_jobs = _SurfaceJobs()
    server_version = f"vulnscan/{__version__}"

    def log_message(self, fmt, *args):  # quiet
        pass

    # ----------------------------------------------------------------- helpers
    def _json(self, data, status: int = 200) -> None:
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _text(self, text: str, ctype: str, filename: str | None = None, csp: str | None = None) -> None:
        body = text.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", f"{ctype}; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        if csp:
            self.send_header("Content-Security-Policy", csp)
        if filename:
            self.send_header("Content-Disposition", f"attachment; filename*=UTF-8''{urllib.parse.quote(filename)}")
        self.end_headers()
        self.wfile.write(body)

    def _loopback_host(self) -> bool:
        """The Host header must name this machine. Defeats DNS rebinding: a page on attacker.example whose name
        is re-pointed at 127.0.0.1 is same-origin with itself, but its requests carry Host: attacker.example."""
        try:
            host = urllib.parse.urlsplit("//" + self.headers.get("Host", "")).hostname or ""
        except ValueError:
            return False
        return host in ("127.0.0.1", "localhost", "::1")

    def _same_origin(self) -> bool:
        """Reject cross-site requests: the UI is local-only and has no auth."""
        if not self._loopback_host():
            return False
        origin = self.headers.get("Origin") or self.headers.get("Referer")
        host = self.headers.get("Host", "")
        if not origin:
            return True
        return urllib.parse.urlparse(origin).netloc == host

    def _not_cross_site(self) -> bool:
        """Browsers label every request with Sec-Fetch-Site; anything a page on another site (or another local
        port) triggers, even a plain <img> GET, is refused. Clients that send no such header (curl, tests) pass."""
        return self.headers.get("Sec-Fetch-Site", "same-origin").strip().lower() in ("same-origin", "none")

    def _loopback_json(self) -> bool:
        """Extra guard for the update endpoints: a loopback Host (defeats DNS rebinding), not cross-site, and a JSON
        body type (a cross-site form cannot send one without a CORS preflight, which this server never grants)."""
        ctype = self.headers.get("Content-Type", "").split(";")[0].strip().lower()
        return self._loopback_host() and self._not_cross_site() and ctype == "application/json"

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode("utf-8"))
        except ValueError:
            return {}

    def _drain(self, n: int, cap: int = 16 * MAX_JSON_BODY) -> None:
        """Read and discard up to ``cap`` bytes of a refused request body (bounded in size and time)."""
        try:
            self.connection.settimeout(5)
            left = min(n, cap)
            while left > 0:
                chunk = self.rfile.read(min(65536, left))
                if not chunk:
                    break
                left -= len(chunk)
        except OSError:
            pass

    def _small_json_body(self) -> dict | None:
        """The JSON object of a request to the 1.0 endpoints (triage, surface): at most MAX_JSON_BODY bytes and an
        object; None otherwise (the caller answers 400)."""
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None
        if n < 0 or n > MAX_JSON_BODY:
            return None
        if n == 0:
            return {}
        try:
            data = json.loads(self.rfile.read(n).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None
        return data if isinstance(data, dict) else None

    # --------------------------------------------------------------- routing
    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path.startswith("/api/"):
            if not self._loopback_host():          # DNS rebinding would otherwise let a web page read scan results
                return self._json({"error": "forbidden"}, 403)
            if path.startswith("/api/update") and not self._not_cross_site():
                return self._json({"error": "forbidden"}, 403)   # e.g. <img src=".../api/update?force=1">
            if _is_pro_path(path) and not self._not_cross_site():
                return self._json({"error": "forbidden"}, 403)   # exports, compliance, surface, triage
            return self._api_get(path)
        return self._static(path)

    def do_POST(self):
        if not self._same_origin():
            return self._json({"error": "forbidden"}, 403)
        path = urllib.parse.urlparse(self.path).path
        if path == "/api/scan":
            return self._start_scan(self._body())
        if path == "/api/upload":
            return self._upload()
        if path == "/api/settings":
            return self._json(self.store.save_settings(self._body()))
        if path in ("/api/update", "/api/update/restart"):
            if not self._loopback_json():
                return self._json({"error": "forbidden"}, 403)
            return self._update_apply() if path == "/api/update" else self._update_restart()
        if _is_pro_path(path):                  # these write files: JSON body only, never cross-site
            if not self._loopback_json():
                return self._json({"error": "forbidden"}, 403)
            try:
                declared = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                declared = -1
            if declared > MAX_JSON_BODY:
                self._drain(declared)          # so the client reads the answer instead of a connection reset
                self.close_connection = True
                return self._json({"error": "request too large"}, 413)
            body = self._small_json_body()
            if body is None:
                return self._json({"error": "bad request"}, 400)
            if path in ("/api/triage/set", "/api/triage/comment", "/api/triage/severity"):
                return self._triage_post(path.rsplit("/", 1)[1], body)
            parts = path.split("/")
            if len(parts) == 5 and parts[2] == "scans" and parts[4] == "surface":
                return self._surface_start(parts[3], body)
        return self._json({"error": "not found"}, 404)

    def do_DELETE(self):
        if not self._same_origin():
            return self._json({"error": "forbidden"}, 403)
        path = urllib.parse.urlparse(self.path).path
        if path.startswith("/api/scans/"):
            scan_id = path.split("/")[3]
            ok = self.store.delete_scan(scan_id)
            if ok and _ID.match(scan_id):
                (self.store.home / "surface" / f"{scan_id}.json").unlink(missing_ok=True)
            return self._json({"ok": ok}, 200 if ok else 404)
        return self._json({"error": "not found"}, 404)

    def _api_get(self, path: str):
        parts = path.split("/")
        if path == "/api/settings":
            return self._json(self.store.settings())
        if path == "/api/rules":
            from .taint import TAINT_RULES
            rules = [{"id": r.id, "severity": r.severity, "title": r.title, "title_ar": r.title_ar,
                      "cwe": r.cwe, "advice": r.advice,
                      "langs": sorted(r.langs) if r.langs else ["*"]} for r in RULES]
            from .scanner import ENTROPY_RULE
            from .semantic import CATALOGUE as SEM
            rules.append({**ENTROPY_RULE, "langs": ["*"]})
            rules += [{**r, "advice": "", "langs": [".py"]} for r in SEM]
            rules += [{**t, "langs": [".py .js .ts (تدفق بيانات)"]} for t in TAINT_RULES]
            from .vql import catalogue
            rules += [{**q, "langs": ["VQL"]} for q in catalogue()]
            for r in rules:
                r["advice_en"] = to_en(r.get("advice") or "")
                r["langs_en"] = [to_en(x) for x in r.get("langs") or []]
            return self._json(rules)
        if path == "/api/meta":
            return self._json({"version": __version__, "external_tools": available(), "jadx": jadx_available(),
                               "archive_exts": list(ARCHIVE_EXTS), "jadx_exts": list(JADX_EXTS), "home": str(self.store.home)})
        if path == "/api/scans":            # ?project=<id> keeps one project's scans
            return self._json(self.store.list_scans(self._query("project") or None))
        if path == "/api/projects":
            return self._json(self.store.list_projects())
        if len(parts) == 4 and parts[2] == "projects":
            proj = self.store.get_project(parts[3])
            return self._json(proj, 200) if proj else self._json({"error": "not found"}, 404)
        if path == "/api/update":
            return self._update_check()
        if path == "/api/update/status":
            return self._json(self.update_job.snapshot())
        if path == "/api/stats":
            return self._json(self._stats())
        if path == "/api/export/formats":
            from .exporters import list_formats
            return self._json(list_formats(self._lang_param(("en", "ar"), "en")))
        if path == "/api/compliance/frameworks":
            from . import compliance
            lang = self._lang_param(("en", "ar"), "en")
            return self._json([compliance.framework_info(fid, lang) for fid in compliance.FRAMEWORKS])
        if path == "/api/triage":
            return self._triage_get()
        if len(parts) == 5 and parts[2] == "projects" and parts[4] == "surface":
            proj = self.store.get_project(parts[3])
            if not proj or not proj.get("latest"):
                return self._json({"error": "not found"}, 404)
            return self._surface_get(proj["latest"])
        if len(parts) >= 4 and parts[2] == "scans":
            scan = self.store.get_scan(parts[3])
            if not scan:
                return self._json({"error": "not found"}, 404)
            if len(parts) == 4:
                return self._json(_with_english(scan))
            fmt = parts[4]
            if len(parts) == 5 and fmt == "export":
                return self._export(scan)
            if len(parts) == 5 and fmt == "compliance":
                return self._compliance(scan)
            if len(parts) == 5 and fmt == "audit.html":
                return self._audit_html(scan)
            if len(parts) == 5 and fmt == "surface":
                return self._surface_get(scan["id"])
            findings = [_dict_to_finding(d) for d in scan.get("findings") or [] if isinstance(d, dict) and "rule_id" in d]
            args = (findings, scan.get("target", ""), scan.get("files_scanned", 0), scan.get("notes") or [])
            name = f"vulnscan-{scan['id']}"
            # ?lang=ar|en|both picks the report language (default both, as before)
            lang = (urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("lang") or ["both"])[0]
            lang = lang if lang in ("ar", "en", "both") else "both"
            if fmt == "report.md":
                return self._text(render_markdown(*args, lang=lang), "text/markdown", name + ".md")
            if fmt == "report.json":
                return self._text(render_json(*args), "application/json", name + ".json")
            if fmt == "report.html":
                return self._text(render_html(*args, lang=lang), "text/html", name + ".html")
            if fmt == "report.sarif":             # SARIF 2.1.0 (code-scanning platforms); messages are English
                return self._text(render_sarif(*args, lang=lang), "application/sarif+json", name + ".sarif")
        return self._json({"error": "not found"}, 404)

    # ------------------------------------------------- 1.0: exports, compliance, attack surface, triage
    def _lang_param(self, allowed: tuple, default: str) -> str:
        lang = self._query("lang")
        return lang if lang in allowed else default

    def _export(self, scan: dict):
        """GET /api/scans/<id>/export?format=FMT[&lang=en|ar][&min_severity=..][&exposure=..][&aws_account_id=..
        &aws_region=..]: the scan in an export format, as a download named kashif-<scan id>.<ext>."""
        from .exporters import FORMATS, ExportError, export, format_info
        fmt = self._query("format")
        if fmt not in FORMATS:
            return self._json({"error": "unknown format", "formats": list(FORMATS)}, 400)
        lang = self._lang_param(("en", "ar"), "en")
        meta = {**_scan_meta(scan), "lang": lang}
        for key in ("min_severity", "exposure", "aws_account_id", "aws_region", "fail_on", "project", "repo_url", "ref"):
            value = self._query(key)
            if value:
                meta[key] = value[:500]
        findings = self._with_triage(scan, _scan_findings(scan))
        try:
            text = export(findings, fmt, meta)
        except ExportError as e:
            return self._json({"error": str(e)}, 400)
        info = format_info(fmt)
        # the file name comes from the server's own scan id and the format's extension, never from request text
        return self._text(text, info["mime"], f"kashif-{scan['id']}.{info['ext']}")

    def _with_triage(self, scan: dict, findings: list[dict]) -> list[dict]:
        """Copies of the findings annotated with the project's triage decisions (extra.triage), when it has any."""
        try:
            from . import triage
            path = triage_path(self.store, scan)
            if not path.is_file():
                return findings
            copies = [dict(d, extra=dict(d.get("extra") or {})) for d in findings]
            triage.apply(copies, triage.load(path), show="all")
            return copies
        except Exception:  # noqa: BLE001 - a malformed triage file must not break the download
            return findings

    def _frameworks(self) -> list | None:
        from . import compliance
        raw = self._query("framework")
        if not raw or raw == "all":
            return None
        out = []
        for name in raw.split(","):
            fid = compliance.resolve_framework(name)
            if fid is None:
                raise ValueError(name)
            out.append(fid)
        return out

    def _compliance(self, scan: dict):
        """GET /api/scans/<id>/compliance?framework=ID[,ID]&lang=en|ar: the compliance report as JSON
        (schema kashif-compliance/1: per-framework control tables and every finding with its controls)."""
        from . import compliance
        try:
            fids = self._frameworks()
        except ValueError:
            return self._json({"error": "unknown framework", "frameworks": list(compliance.FRAMEWORKS)}, 400)
        lang = self._lang_param(("en", "ar"), "en")
        return self._json(json.loads(compliance.render_json(_scan_findings(scan), _scan_meta(scan), lang, fids)))

    def _audit_html(self, scan: dict):
        """GET /api/scans/<id>/audit.html?framework=..&lang=..: the printable auditor report (no script). Source lines
        are included only for a local path this server scanned; secrets are always masked."""
        from . import compliance
        try:
            fids = self._frameworks()
        except ValueError:
            return self._json({"error": "unknown framework", "frameworks": list(compliance.FRAMEWORKS)}, 400)
        lang = self._lang_param(("en", "ar"), "en")
        root = local_root(scan)
        html_text = compliance.render_html(_scan_findings(scan), _scan_meta(scan), lang, fids,
                                           source_root=str(root) if root is not None and root.is_dir() else None,
                                           mask_secrets=True)
        return self._text(html_text, "text/html", f"kashif-{scan['id']}-audit.html",
                          csp="default-src 'none'; style-src 'unsafe-inline'; img-src data:")

    def _surface_get(self, scan_id: str):
        """GET /api/scans/<id>/surface?lang=en|ar (or /api/projects/<id>/surface: the project's latest scan)."""
        if not _ID.match(scan_id):
            return self._json({"error": "not found"}, 404)
        jobs = Handler.surface_jobs
        cache = self.store.home / "surface" / f"{scan_id}.json"
        with jobs.lock:
            running = scan_id in jobs.running
            error = jobs.errors.get(scan_id)
        if running:
            return self._json({"status": "running", "scan": scan_id}, 202)
        if cache.is_file():
            try:
                doc = json.loads(cache.read_text(encoding="utf-8"))
            except ValueError:
                doc = None
            if isinstance(doc, dict):
                lang = self._lang_param(("en", "ar"), "en")
                return self._json({"status": "done", "scan": scan_id, "engine": doc.get("engine"),
                                   "built_at": doc.get("built_at"), "surface": doc["surface"][lang],
                                   "mermaid": doc["mermaid"][lang], "openapi": doc.get("openapi")})
        if error:
            return self._json({"status": "error", "scan": scan_id, "error": error}, 200)
        scan = self.store.get_scan(scan_id)
        available = bool(scan) and local_root(scan) is not None
        return self._json({"status": "none", "scan": scan_id, "available": available}, 404)

    def _surface_start(self, scan_id: str, body: dict):
        """POST /api/scans/<id>/surface {"engine": true}: build (or rebuild) the attack-surface map in the background."""
        scan = self.store.get_scan(scan_id)
        if not scan:
            return self._json({"error": "not found"}, 404)
        if scan.get("status") != "done":
            return self._json({"error": "scan not finished"}, 409)
        if local_root(scan) is None:
            return self._json({"error": "source not available",
                               "detail": "only a local folder or file scanned from this machine has a surface"}, 409)
        started = Handler.surface_jobs.start(self.store, scan, self.store.settings(), engine=body.get("engine", True) is not False)
        return self._json({"status": "running", "scan": scan["id"], "started": started}, 202)

    def _triage_scan(self, scan_id: str, project: str) -> dict | None:
        if scan_id:
            return self.store.get_scan(scan_id) if _ID.match(scan_id) else None
        if project and _ID.match(project):
            proj = self.store.get_project(project)
            if proj and (proj.get("latest") or (proj.get("last_scan") or {}).get("id")):
                return self.store.get_scan(proj.get("latest") or proj["last_scan"]["id"])
        return None

    def _triage_get(self):
        """GET /api/triage?scan=<id> (or ?project=<id>): the project's triage file, its statistics and the effective
        decision of every finding of that scan."""
        from . import triage
        scan = self._triage_scan(self._query("scan"), self._query("project"))
        if not scan:
            return self._json({"error": "not found"}, 404)
        lang = self._lang_param(("en", "ar"), "en")
        path = triage_path(self.store, scan)
        try:
            tri = triage.load(path)
        except triage.TriageError as e:
            return self._json({"error": e.message("en"), "error_ar": e.message("ar")}, 422)
        copies = [dict(d, extra=dict(d.get("extra") or {})) for d in _scan_findings(scan)]
        res = triage.apply(copies, tri, show="all", lang=lang)
        annotations = {d.get("fingerprint"): d["extra"].get("triage") for d in res.findings if d.get("fingerprint")}
        return self._json({"scan": scan["id"], "file": str(path), "in_project": local_root(scan) is not None,
                           "statuses": [{"id": st, "label": triage.status_label(st, lang),
                                         "label_en": triage.status_label(st, "en"),
                                         "label_ar": triage.status_label(st, "ar")} for st in triage.STATUSES],
                           "findings": tri.get("findings") or {}, "annotations": annotations,
                           "counts": res.counts, "stats": triage.stats(tri)})

    def _triage_post(self, action: str, body: dict):
        """POST /api/triage/set|comment|severity: record a decision for one finding of a scan."""
        from . import triage
        scan = self._triage_scan(str(body.get("scan") or ""), str(body.get("project") or ""))
        if not scan:
            return self._json({"error": "not found"}, 404)
        fp = str(body.get("fingerprint") or "")
        finding = next((d for d in _scan_findings(scan) if d.get("fingerprint") == fp), None)
        if finding is None:                       # only findings of this scan can be triaged from the UI
            return self._json({"error": "unknown fingerprint"}, 404)
        author = str(body.get("author") or "").strip() or _default_author()
        path = triage_path(self.store, scan)
        box: dict = {}

        def change(t: dict) -> None:
            if action == "set":
                box["entry"] = triage.set_status(t, fp, str(body.get("status") or ""), author=author,
                                                 justification=str(body.get("justification") or ""),
                                                 expires=body.get("expires") or None,
                                                 ticket=body.get("ticket") if isinstance(body.get("ticket"), str) else None,
                                                 comment=str(body.get("comment") or ""), finding=finding)
            elif action == "comment":
                box["entry"] = triage.add_comment(t, fp, str(body.get("text") or ""), author=author, finding=finding)
            else:
                sev = body.get("severity")
                box["entry"] = triage.override_severity(t, fp, None if sev in (None, "", "none") else str(sev),
                                                        reason=str(body.get("reason") or ""), author=author,
                                                        finding=finding)
        try:
            triage.update(path, change)
        except triage.TriageError as e:
            return self._json({"error": e.message("en"), "error_ar": e.message("ar")}, 400)
        except OSError as e:
            return self._json({"error": f"cannot write the triage file: {e.strerror or type(e).__name__}"}, 500)
        return self._json({"ok": True, "fingerprint": fp, "entry": box.get("entry"), "file": str(path)})

    # ----------------------------------------------------------------- update
    def _update_check(self):
        """GET /api/update[?force=1]: is a newer release out? Respects the "check_updates" setting unless forced."""
        force = (urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("force") or ["0"])[0] == "1"
        if not force and not self.store.settings().get("check_updates", True):
            info = updater.install_info()
            return self._json({"disabled": True, "current": __version__, "install_kind": info["kind"], "command": info["command"]})
        try:
            return self._json(updater.check(force=force, home=self.store.home))
        except updater.UpdateError as e:
            return self._json({**e.to_dict(), "current": __version__}, 502)

    def _update_apply(self):
        """POST /api/update: start installing the latest binary in the background; poll /api/update/status."""
        if updater.install_info()["kind"] != "binary":
            return self._json(updater.UpdateError("not_binary").to_dict(), 400)
        if self.update_job.running():
            return self._json(updater.UpdateError("busy").to_dict(), 409)
        if self.update_job.snapshot()["phase"] in ("done", "restarting"):
            return self._json(updater.UpdateError("restart_pending").to_dict(), 409)
        try:
            st = updater.check(force=False, home=self.store.home)
        except updater.UpdateError as e:
            return self._json(e.to_dict(), 502)
        if not st["newer"]:
            return self._json(updater.UpdateError("up_to_date").to_dict(), 409)
        if not st["can_self_update"]:
            return self._json(updater.UpdateError(st["reason"]).to_dict(), 409)
        if not self.update_job.start(home=self.store.home):
            return self._json(updater.UpdateError("busy").to_dict(), 409)
        return self._json(self.update_job.snapshot(), 202)

    def _update_restart(self):
        """POST /api/update/restart: after a successful update, replace this server with the new binary."""
        if not self.update_job.claim_restart():          # not updated yet, or a restart is already under way
            return self._json(updater.UpdateError("not_ready").to_dict(), 409)
        args = ["ui", "--port", str(self.server.server_address[1]), "--no-browser", "--lang", self.lang]
        job = self.update_job

        def go():
            try:
                updater.restart(args)
            except OSError as e:                           # exec failed: this server keeps running, the UI can retry
                job.restart_failed(str(e))
        threading.Timer(0.5, go).start()                   # answer first, then exec
        return self._json({"ok": True}, 202)

    def _query(self, name: str) -> str:
        return (urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get(name) or [""])[0]

    def _stats(self) -> dict:
        """GET /api/stats[?project=<id>]: the latest completed scan, the trend and the top rules / files, over
        every scan or over one project's scans."""
        scans = [s for s in self.store.list_scans(self._query("project") or None) if s.get("status") == "done"]
        latest = scans[0] if scans else None
        # .get: scan files from older versions may lack a key; the dashboard must still load
        trend = [{"id": s["id"], "target": s.get("target"), "at": s.get("finished_at") or s.get("started_at"),
                  **(s.get("summary") if isinstance(s.get("summary"), dict) else {})} for s in scans[:12]][::-1]
        top_files: dict[str, int] = {}
        top_rules: dict[str, dict] = {}
        if latest:
            full = self.store.get_scan(latest["id"]) or {}
            for f in full.get("findings") or []:
                if not isinstance(f, dict) or f.get("severity") not in SEVERITY_RANK:
                    continue
                top_files[f.get("file", "")] = top_files.get(f.get("file", ""), 0) + 1
                r = top_rules.setdefault(f.get("rule_id"), {"rule_id": f.get("rule_id"), "title": f.get("title", ""),
                                                            "title_ar": f.get("title_ar", ""), "severity": f["severity"],
                                                            "count": 0})
                r["count"] += 1
        return {"latest": latest, "total_scans": len(scans), "trend": trend,
                "top_files": sorted(top_files.items(), key=lambda kv: -kv[1])[:8],
                "top_rules": sorted(top_rules.values(), key=lambda r: (SEVERITY_RANK[r["severity"]], -r["count"]))[:8]}

    def _start_scan(self, body: dict):
        target = (body.get("target") or "").strip()
        if not target:
            return self._json({"error": "target required"}, 400)
        settings = self.store.settings()
        authorized = bool(body.get("authorized")) or target in settings.get("authorized_targets", [])
        if target.startswith(("http://", "https://")) and not authorized:
            return self._json({"error": "authorization required"}, 403)
        scan = self.store.new_scan(target, body.get("kind") or ("url" if target.startswith("http") else "path"))
        if body.get("deep"):
            scan["deep"] = True
        if body.get("crawl"):
            scan["crawl"] = True
        if body.get("deep") or body.get("crawl"):
            self.store.save_scan(scan)
        threading.Thread(target=run_scan, args=(self.store, scan, settings, authorized), daemon=True).start()
        return self._json(scan, 202)

    def _upload(self):
        """Accepts one archive (zip/apk/jar/tar…) or any number of loose files.

        A single archive is scanned as an archive; several files are written
        into one temporary folder (keeping relative paths from a folder
        upload) and scanned as a project.
        """
        ctype = self.headers.get("Content-Type", "")
        length = int(self.headers.get("Content-Length") or 0)
        if "multipart/form-data" not in ctype or length <= 0 or length > MAX_UPLOAD:
            return self._json({"error": "bad upload"}, 400)
        files = parse_multipart(self.rfile.read(length), ctype)
        if not files:
            return self._json({"error": "file required"}, 400)
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="vulnscan-upload-"))
        root = tmp / "upload"
        root.mkdir()
        written = []
        for name, data in files:
            rel = pathlib.PurePosixPath(name.replace("\\", "/"))
            parts = [p for p in rel.parts if p not in ("", ".", "..")]
            if not parts:
                continue
            dest = root.joinpath(*parts)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            written.append(dest)
        if not written:
            shutil.rmtree(tmp, ignore_errors=True)  # nosec - operates on the user's own scan target / our temp dir by design
            return self._json({"error": "file required"}, 400)
        if len(written) == 1 and written[0].name.lower().endswith(ARCHIVE_EXTS):
            target, label = written[0], written[0].name
        else:
            target, label = root, f"{len(written)} ملف مرفوع"
        scan = self.store.new_scan(str(target), "upload")
        scan["label"] = label
        scan["tmp_root"] = str(tmp)
        self.store.save_scan(scan)
        threading.Thread(target=run_scan, args=(self.store, scan, self.store.settings(), False), daemon=True).start()
        return self._json(scan, 202)

    def _static(self, path: str):
        if path in ("/", ""):
            path = "/index.html"
        file = (UI_DIR / path.lstrip("/")).resolve()
        # is_relative_to, not a string prefix: "/…/ui-old/x" starts with "/…/ui" but is outside the UI directory
        if not file.is_relative_to(UI_DIR.resolve()) or not file.is_file():
            self.send_response(404)
            self.end_headers()
            return
        body = file.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mimetypes.guess_type(file.name)[0] or "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
        self.end_headers()
        self.wfile.write(body)


def serve(port: int = 8765, open_browser: bool = True, home: pathlib.Path | None = None, lang: str = "both") -> None:
    Handler.store = Store(home)
    Handler.lang = lang
    updater.cleanup_stale()                       # the backup left by a previous in-app update (binary only)
    # Right after an in-app update the previous process may still hold the port for a moment.
    tries = 40 if os.environ.pop("VULNSCAN_UPDATE_RESTART", "") else 1
    for attempt in range(tries):
        try:
            httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
            break
        except OSError:
            if attempt == tries - 1:
                raise
            time.sleep(0.25)
    url = f"http://127.0.0.1:{httpd.server_address[1]}/"
    print(f"Kashif UI: {url}   (Ctrl+C to stop)" if lang == "en" else f"واجهة كاشِف: {url}   (Ctrl+C للإيقاف)")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
