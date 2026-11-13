# PyInstaller spec — one-file executable that bundles the web UI assets.
# Build:  pyinstaller --clean --noconfirm vulnscan.spec
import glob
import os
import sys

# Data files, at the same relative paths as in the package (robust whether or not the package is installed).
datas = [(f, "vulnscan/ui") for f in glob.glob("vulnscan/ui/*")]                    # web UI
datas += [(f, "vulnscan/models") for f in glob.glob("vulnscan/models/*.json")]      # data-flow library models
datas += [(f, "vulnscan/queries") for f in glob.glob("vulnscan/queries/*.vql")]     # built-in VQL queries
datas += [(f, "vulnscan/data") for f in glob.glob("vulnscan/data/*") if os.path.isfile(f)]   # compliance.json
# web scanner data snapshots (1.1.0: retire.js, PSL, HSTS preload, tech, ... and MANIFEST.json), spec §4.4
datas += [(f, "vulnscan/data/web") for f in glob.glob("vulnscan/data/web/*") if os.path.isfile(f)]
for _required in ("vulnscan/ui/index.html", "vulnscan/ui/app.js", "vulnscan/data/compliance.json",
                  "vulnscan/data/web/psl.dat.gz", "vulnscan/data/web/retire-jsrepository.json.gz"):
    assert any(src.replace("\\", "/") == _required for src, _ in datas), f"{_required} not found: run from the repo root"
assert any(d == "vulnscan/models" for _, d in datas) and any(d == "vulnscan/queries" for _, d in datas), \
    "vulnscan/models or vulnscan/queries not found: run from the repo root"

# Modules reached only lazily (sub-commands, `importlib` in cli.run_subcommand, the MCP scan worker) are listed by
# name so a missing one fails the build loudly ...
EXPLICIT = [
    "vulnscan", "vulnscan.cli", "vulnscan.i18n", "vulnscan.server", "vulnscan.scanner", "vulnscan.web",
    "vulnscan.deps", "vulnscan.sca", "vulnscan.external", "vulnscan.report", "vulnscan.store", "vulnscan.rules",
    "vulnscan.updater", "vulnscan.lsp", "vulnscan.diffscope", "vulnscan.baseline", "vulnscan.integrations",
    "vulnscan.integrations.github_pr",
    # 1.0 sub-commands and features
    "vulnscan.mcp", "vulnscan.compliance", "vulnscan.history", "vulnscan.triage", "vulnscan.policy",
    "vulnscan.surface", "vulnscan.exporters", "vulnscan.ruletest", "vulnscan.autofix",
    # 1.1.0 passive web scanner: the engine imports its check modules lazily (inside scan())
    "vulnscan.webscan", "vulnscan.webscan.engine", "vulnscan.webscan.http", "vulnscan.webscan.tls",
    "vulnscan.webscan.remediation", "vulnscan.i18n.cat_web2",
    # i18n catalogs (imported by vulnscan.i18n; listed so a frozen build never lacks English text)
    "vulnscan.i18n.cat_cli", "vulnscan.i18n.cat_autofix", "vulnscan.i18n.cat_sca", "vulnscan.i18n.cat_integrations",
    "vulnscan.i18n.cat_updater", "vulnscan.i18n.cat_projects",
]
# ... and every module of the package is added as well, so new ones (and the i18n catalogs) are frozen too.
ALL_MODULES = sorted({f[:-3].replace("\\", "/").replace("/", ".").removesuffix(".__init__")
                      for f in glob.glob("vulnscan/**/*.py", recursive=True) if not f.endswith("__main__.py")})
_missing = [m for m in EXPLICIT if m not in ALL_MODULES]
assert not _missing, f"vulnscan.spec lists modules that do not exist: {_missing}"

a = Analysis(
    ["exe_entry.py"],
    pathex=["."],
    datas=datas,
    hiddenimports=sorted(set(EXPLICIT) | set(ALL_MODULES)),
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "test", "unittest", "pydoc", "PyInstaller"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    # dist/kashif (dist/kashif.exe on Windows). The release also publishes it under the legacy vulnscan-* names.
    name="kashif",
    debug=False,
    strip=False,
    upx=True,
    console=True,            # keep a console window: the UI prints its URL and Ctrl+C stops it
    disable_windowed_traceback=False,
    # Windows: the Kashif icon on the .exe (Explorer, taskbar); ignored on other systems
    icon="packaging/windows/kashif.ico" if sys.platform == "win32" else None,
)
