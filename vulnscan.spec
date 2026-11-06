# PyInstaller spec — one-file executable that bundles the web UI assets.
# Build:  pyinstaller --clean --noconfirm vulnscan.spec
import glob

# Bundle the web UI assets (robust whether or not the package is installed).
datas = [(f, "vulnscan/ui") for f in glob.glob("vulnscan/ui/*")]
datas += [(f, "vulnscan/models") for f in glob.glob("vulnscan/models/*.json")]
assert datas, "vulnscan/ui assets not found — run from the repo root"

a = Analysis(
    ["exe_entry.py"],
    pathex=["."],
    datas=datas,
    hiddenimports=["vulnscan", "vulnscan.server", "vulnscan.scanner", "vulnscan.web",
                   "vulnscan.deps", "vulnscan.external", "vulnscan.report", "vulnscan.store", "vulnscan.rules"],
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "test", "unittest", "pydoc", "PyInstaller"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name="vulnscan",
    debug=False,
    strip=False,
    upx=True,
    console=True,            # keep a console window: the UI prints its URL and Ctrl+C stops it
    disable_windowed_traceback=False,
    icon=None,
)
