# Changelog

## 1.5.0

- Released with Kashif 1.5.0 (the extension follows the Kashif version). The extension itself is unchanged; Kashif 1.5.0
  measures and improves JavaScript/TypeScript and PHP accuracy and closes the Oracle APEX limits of 1.4, so editor
  diagnostics follow.

## 1.4.0

- Released with Kashif 1.4.0 (the extension follows the Kashif version). The extension itself is unchanged; Kashif 1.4.0
  deepens PL/SQL and Oracle APEX analysis and makes Python results more precise, so editor diagnostics follow.

## 1.3.1

- Released with Kashif 1.3.1 (the extension follows the Kashif version). The extension itself is unchanged.

## 1.3.0

- First release published to the Visual Studio Marketplace and Open VSX. The extension itself is unchanged.

## 1.2.0

- Released with Kashif 1.2.0 (the extension follows the Kashif version). The extension itself is unchanged; Kashif 1.2.0
  makes Python dataflow results more precise (fewer false positives), so editor diagnostics follow.

## 1.1.1

- Released with Kashif 1.1.1 (the extension follows the Kashif version); the extension itself is unchanged.

## 1.1.0

- Released with Kashif 1.1.0 (the extension follows the Kashif version). The extension itself is unchanged: Kashif 1.1.0
  rebuilds the passive web scanner, and code scans, their diagnostics and fingerprints are the same as in 1.0.2.

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
