# Kashif (كاشِف) for Visual Studio Code

Security findings from [Kashif](https://github.com/abdulrahmanahmedelabed-prog/vulnscan) — an open-source static
application security tester with a type-aware, **cross-file taint engine** for 12 languages (Python, JavaScript/TypeScript,
Java, Kotlin, C#, Go, PHP, C/C++, Rust, Swift, Ruby, PL/SQL and Oracle APEX) — shown directly in the editor.

The extension is a thin client of the Kashif language server (`kashif lsp`). All analysis runs locally on your
machine, offline: no code leaves it, no account is needed.

## Features

- **Diagnostics** in the editor and the Problems panel when a file is opened or saved. The whole workspace folder is
  analysed, so a request parameter that reaches `os.system` through a helper in another file is reported at the call
  site, with the full source-to-sink trail as related locations.
- **Hover** on a flagged line: title, severity, rule, CWE link, remediation and the data-flow trail.
- **Quick fixes**: *Suppress this finding* (adds the `vulnscan: ignore` comment the scanner honours, also in CI),
  *Add to baseline* (writes `.vulnscan-baseline.json`, the same file `vulnscan --baseline` reads) and *Open CWE*.
- **Status bar** item with the number of findings; click it to open the Problems panel.
- Commands: **Kashif: Scan workspace**, **Kashif: Open web UI** (the local dashboard), **Kashif: Restart language server**.
- English or Arabic messages (`kashif.language`).

## Requirements

Kashif itself (Python 3.10+, no other dependencies):

```bash
pip install git+https://github.com/abdulrahmanahmedelabed-prog/vulnscan
kashif --version
```

The release binaries and the one-line installers (see the project's install guide) work as well. A pip install made
before Kashif 1.0.2 is the distribution `vulnscan`: run `pip uninstall -y vulnscan kashif` before installing the new
version (`vulnscan` on PyPI is an unrelated project).

If neither `kashif` nor `vulnscan` is on `PATH`, set `kashif.serverPath` to its absolute path, or to a Python interpreter together with
`"kashif.serverArgs": ["-m", "vulnscan"]`.

## Settings

| Setting | Default | Meaning |
|---|---|---|
| `kashif.serverPath` | `kashif` | Command that runs Kashif (`vulnscan` is used when only that older name is installed) |
| `kashif.serverArgs` | `[]` | Arguments placed before `lsp --stdio` |
| `kashif.minSeverity` | `info` | Show this severity and above |
| `kashif.audit` | `false` | Also list dangerous calls not proven reachable by input |
| `kashif.exclude` | `[]` | Glob patterns to leave out, e.g. `"tests/*"` |
| `kashif.baseline` | `.vulnscan-baseline.json` | Baseline file, relative to the workspace folder |
| `kashif.language` | `en` | `en` or `ar` |
| `kashif.webUiPort` | `8765` | Port for *Open web UI* |
| `kashif.trace.server` | `off` | Log the LSP traffic to the Output panel |

## Other editors

The same server works in JetBrains IDEs, Neovim, Helix, Zed, Sublime Text and Emacs — see
[editors/README.md](https://github.com/abdulrahmanahmedelabed-prog/vulnscan/tree/main/editors#readme).

## License

MIT
