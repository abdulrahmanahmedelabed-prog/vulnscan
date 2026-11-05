"""Entry point for the standalone executable (PyInstaller).

Double-clicking the built ``vulnscan.exe`` launches the local web UI. Passing
arguments makes it behave exactly like the ``vulnscan`` command, e.g.
``vulnscan.exe ./myproject`` or ``vulnscan.exe ui --port 9000``.
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
