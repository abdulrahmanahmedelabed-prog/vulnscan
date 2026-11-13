# Changelog

## 1.0.2

- Released with Kashif 1.0.2 (the extension follows the Kashif version).
- The README names the language server command `kashif lsp` and explains the upgrade of a pip install made before
  Kashif 1.0.2, whose distribution is `vulnscan`: run `pip uninstall -y vulnscan kashif` before installing the new
  version (`vulnscan` on PyPI is an unrelated project).
- `kashif lsp --help` is in English and Arabic, and `kashif lsp --lang` is accepted. The language of the diagnostics
  still follows the `kashif.language` setting.

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
