# Changelog

## 1.0.1

- Released with Kashif 1.0.1 (the extension follows the Kashif version).
- "Add to baseline" no longer writes through a fixed-name temporary file: a workspace that committed
  `.kashif-baseline.json.tmp` as a symbolic link could make it overwrite another file the user can write. A baseline
  file that is a device, a FIFO or larger than 64 MB is refused instead of hanging the language server.

## 1.0.0

- Released with Kashif 1.0.0 (the extension follows the Kashif version).
- "Apply Kashif fix" quick fix: where Kashif has a verified autofix for a finding, it is offered first and applied to
  the editor buffer.

## 0.8.0

- First release: diagnostics with data-flow trails, hover, quick fixes (suppress, baseline, open CWE), status bar,
  "Scan workspace" and "Open web UI" commands, English and Arabic messages.
