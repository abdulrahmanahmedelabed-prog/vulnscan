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
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__, updater
from .deps import audit_dependencies
from .external import available, run_external
from .i18n import to_en
from .model import SEVERITY_RANK, Finding, assign_fingerprints, sort_findings
from .report import render_html, render_json, render_markdown, summary_counts
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


class Handler(BaseHTTPRequestHandler):
    store: Store
    lang = "both"
    update_job = updater.Job()
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

    def _text(self, text: str, ctype: str, filename: str | None = None) -> None:
        body = text.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", f"{ctype}; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
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

    # --------------------------------------------------------------- routing
    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path.startswith("/api/"):
            if not self._loopback_host():          # DNS rebinding would otherwise let a web page read scan results
                return self._json({"error": "forbidden"}, 403)
            if path.startswith("/api/update") and not self._not_cross_site():
                return self._json({"error": "forbidden"}, 403)   # e.g. <img src=".../api/update?force=1">
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
        return self._json({"error": "not found"}, 404)

    def do_DELETE(self):
        if not self._same_origin():
            return self._json({"error": "forbidden"}, 403)
        path = urllib.parse.urlparse(self.path).path
        if path.startswith("/api/scans/"):
            ok = self.store.delete_scan(path.split("/")[3])
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
        if path == "/api/scans":
            return self._json(self.store.list_scans())
        if path == "/api/update":
            return self._update_check()
        if path == "/api/update/status":
            return self._json(self.update_job.snapshot())
        if path == "/api/stats":
            return self._json(self._stats())
        if len(parts) >= 4 and parts[2] == "scans":
            scan = self.store.get_scan(parts[3])
            if not scan:
                return self._json({"error": "not found"}, 404)
            if len(parts) == 4:
                return self._json(_with_english(scan))
            fmt = parts[4]
            findings = [_dict_to_finding(d) for d in scan["findings"]]
            args = (findings, scan["target"], scan["files_scanned"], scan["notes"])
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
        return self._json({"error": "not found"}, 404)

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

    def _stats(self) -> dict:
        scans = [s for s in self.store.list_scans() if s["status"] == "done"]
        latest = scans[0] if scans else None
        trend = [{"id": s["id"], "target": s["target"], "at": s["finished_at"], **s["summary"]} for s in scans[:12]][::-1]
        top_files: dict[str, int] = {}
        top_rules: dict[str, dict] = {}
        if latest:
            full = self.store.get_scan(latest["id"]) or {}
            for f in full.get("findings", []):
                top_files[f["file"]] = top_files.get(f["file"], 0) + 1
                r = top_rules.setdefault(f["rule_id"], {"rule_id": f["rule_id"], "title": f["title"],
                                                        "title_ar": f["title_ar"], "severity": f["severity"], "count": 0})
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
    print(f"vulnscan UI: {url}   (Ctrl+C to stop)" if lang == "en" else f"vulnscan UI: {url}   (Ctrl+C للإيقاف)")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
