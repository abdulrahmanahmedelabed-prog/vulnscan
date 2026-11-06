"""Persistent settings and scan history under ~/.vulnscan (JSON files)."""

from __future__ import annotations

import json
import os
import pathlib
import threading
import time
import uuid

DEFAULT_SETTINGS = {
    "language": "ar",
    "theme": "auto",
    "min_severity": "info",
    "exclude": ["tests/*", "**/test_*", "**/*.test.*"],
    "ignore_rules": [],
    "use_osv": True,
    "use_external": True,
    "use_jadx": True,
    "models_dir": "",
    "queries_dir": "",
    "jadx_timeout": 600,
    "jadx_include_libs": False,
    "fail_on": "high",
    "authorized_targets": [],
    "keep_scans": 50,
}


class Store:
    def __init__(self, home: pathlib.Path | None = None):
        self.home = home or pathlib.Path(os.environ.get("VULNSCAN_HOME") or pathlib.Path.home() / ".vulnscan")
        self.scans_dir = self.home / "scans"
        self.scans_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

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
            os.replace(tmp, final)
        self._prune()

    def get_scan(self, scan_id: str) -> dict | None:
        p = self.scans_dir / f"{scan_id}.json"
        if not p.exists() or not scan_id.isalnum():
            return None
        try:
            with self._lock:
                return json.loads(p.read_text(encoding="utf-8"))
        except ValueError:
            return None

    def list_scans(self) -> list[dict]:
        out = []
        for p in self.scans_dir.glob("*.json"):
            try:
                with self._lock:
                    s = json.loads(p.read_text(encoding="utf-8"))
            except ValueError:
                continue
            s.pop("findings", None)
            out.append(s)
        return sorted(out, key=lambda s: s["started_at"], reverse=True)

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
