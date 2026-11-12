"""Entry point for the standalone executable (PyInstaller).

Double-clicking the built ``kashif.exe`` launches the local web UI. Passing
arguments makes it behave exactly like the ``kashif`` command (alias ``vulnscan``), e.g.
``kashif.exe ./myproject`` or ``kashif.exe ui --port 9000``. Nothing depends on the
executable's file name: the MCP scan worker and the updater use ``sys.executable``.
"""

import multiprocessing
import sys

from vulnscan.cli import main

if __name__ == "__main__":
    multiprocessing.freeze_support()
    for _s in (sys.stdout, sys.stderr):
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    args = sys.argv[1:] or ["ui"]
    sys.exit(main(args))
