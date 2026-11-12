# Kashif in your editor

Kashif ships a [Language Server Protocol](https://microsoft.github.io/language-server-protocol/) server, so one
implementation gives the same findings in every editor:

```bash
pip install git+https://github.com/abdulrahmanahmedelabed-prog/vulnscan
vulnscan lsp            # JSON-RPC over stdio; `--stdio` is accepted too, `python -m vulnscan lsp` works as well
```

What every editor gets:

| Feature | How |
|---|---|
| Findings as diagnostics | Scanned when a file is opened or saved. The **whole workspace folder** is analysed (in a background thread, debounced), so cross-file data flow is found exactly as by the CLI. Only files whose results changed are re-published. |
| Severity | critical/high → Error · medium → Warning · low → Information · info → Hint |
| Rule and CWE | `code` = rule id, `codeDescription` = link to the CWE entry |
| Data-flow trail | `relatedInformation`: one location per step from source to sink, also across files |
| Hover | title, severity, rule, CWE, remediation and the trail (Markdown) |
| Quick fixes | **Suppress this finding** (appends the `vulnscan: ignore` comment the scanner honours, in the file's comment syntax; not offered where a comment would change the file, e.g. a line that ends inside a template literal, text block, raw string or heredoc) · **Add to baseline** (writes the same file `vulnscan --baseline` reads) · **Open CWE** |
| Commands | `kashif.server.scanWorkspace`, `kashif.server.addToBaseline`, `kashif.server.openCwe` (`workspace/executeCommand`) |
| Progress | `$/progress` while a scan runs (when the editor supports work-done progress) |
| Deleted files | `workspace/didChangeWatchedFiles` re-scans the folder so a deleted file's findings disappear (changes under `.git`, `node_modules` and other never-scanned directories are ignored) |

It is **offline**: no OSV.dev query, no external tools; nothing leaves the machine.

## Settings

Sent as `initializationOptions`, through `workspace/didChangeConfiguration`, or answered to `workspace/configuration`,
under the section `kashif` (a flat object without the `kashif` key, or dotted keys such as `"kashif.minSeverity"`, are
accepted as well):

| Key | Default | Meaning |
|---|---|---|
| `minSeverity` | `"info"` | `critical`, `high`, `medium`, `low` or `info`: show that severity and above |
| `audit` | `false` | also list dangerous calls that data-flow analysis did not prove reachable by input |
| `exclude` | `[]` | glob patterns of paths to skip, e.g. `["tests/*", "vendor/*"]` |
| `baseline` | `".vulnscan-baseline.json"` | baseline file, relative to the workspace folder (or absolute) |
| `language` | `"en"` | `"en"` or `"ar"` for titles, remediation and trail steps |

Changing `audit` or `exclude` re-scans; the other settings only re-filter the cached results.

A line carrying `vulnscan: ignore` (or `nosec`) is hidden in the editor for every kind of check. On the command line
the same marker is honoured by the pattern rules and the data-flow engine.

---

## Visual Studio Code (and VSCodium, Cursor, Windsurf)

Install the extension from the `.vsix` attached to each
[GitHub release](https://github.com/abdulrahmanahmedelabed-prog/vulnscan/releases):

```bash
code --install-extension kashif-vscode.vsix
```

Settings are `kashif.serverPath` (default `kashif` on `PATH`, or `vulnscan` when only that older name is installed), `kashif.serverArgs`, `kashif.minSeverity`,
`kashif.audit`, `kashif.exclude`, `kashif.baseline`, `kashif.language`, `kashif.webUiPort`, `kashif.trace.server`.
Commands: **Kashif: Scan workspace**, **Kashif: Open web UI**, **Kashif: Restart language server**. A status bar item
shows the number of findings. If Kashif is installed in a virtual environment, point `kashif.serverPath` at that
environment's `vulnscan` (or at its Python with `"kashif.serverArgs": ["-m", "vulnscan"]`).
In Restricted Mode (an untrusted folder) the extension keeps scanning, but VS Code ignores the folder's own
values of `kashif.serverPath`, `kashif.serverArgs` and `kashif.baseline`, so opening a repository cannot make it
run another program or write elsewhere. The extension sends no telemetry.

Build the extension from source (Node.js 18+):

```bash
cd editors/vscode
npm ci
npm run compile                          # type-check (tsc) and bundle (esbuild) into dist/extension.js
npx @vscode/vsce package --no-dependencies   # -> kashif-<version>.vsix
```

Publishing needs the owner's tokens and is not automated. Once the publisher `kashif` exists (or after changing
`publisher` in `package.json` to the owner's publisher id), it is one command per registry:

```bash
npx @vscode/vsce publish --no-dependencies -p "$VSCE_PAT"         # Visual Studio Marketplace
npx ovsx publish kashif-<version>.vsix -p "$OVSX_PAT"            # Open VSX (VSCodium, Cursor, Gitpod ...)
```

## JetBrains IDEs (IntelliJ IDEA, PyCharm, WebStorm, GoLand, PhpStorm, Rider, CLion ...)

Use the free **LSP4IJ** plugin by Red Hat (works in Community and Ultimate editions):

1. *Settings → Plugins → Marketplace*, install **LSP4IJ**, restart.
2. *Settings → Languages & Frameworks → Language Servers → +*:
   - **Server** tab: Name `Kashif`, Command `vulnscan lsp --stdio`
     (on Windows, or inside a virtual environment, use the full path to `vulnscan.exe` / `vulnscan`).
   - **Mappings** tab → *File name patterns*: add `*.py`, `*.js`, `*.ts`, `*.tsx`, `*.java`, `*.kt`, `*.cs`, `*.go`,
     `*.php`, `*.c`, `*.cpp`, `*.rs`, `*.swift`, `*.rb`, `*.sql`, `*.pkb`, `*.pks` (or map *Languages* instead).
   - **Configuration** tab → *Server configuration*: `{"kashif": {"minSeverity": "low", "language": "en"}}`
     (and the same object under *Initialization options*).
3. Open a file: findings appear in the editor and in *Problems*; quick fixes are on <kbd>Alt</kbd>+<kbd>Enter</kbd>.
   *View → Tool Windows → Language Servers* shows the server's log and traces.

## Neovim

Neovim 0.11 and later (built-in client, no plugin needed):

```lua
vim.lsp.config("kashif", {
  cmd = { "vulnscan", "lsp", "--stdio" },
  filetypes = { "python", "javascript", "javascriptreact", "typescript", "typescriptreact", "java", "kotlin",
                "cs", "go", "php", "c", "cpp", "rust", "swift", "ruby", "sql", "plsql", "yaml", "dockerfile" },
  root_markers = { ".git", "pyproject.toml", "package.json", "pom.xml", "go.mod", "Cargo.toml" },
  settings = { kashif = { minSeverity = "low", language = "en" } },
})
vim.lsp.enable("kashif")
```

Neovim 0.10: start it from an autocommand instead:

```lua
vim.api.nvim_create_autocmd("FileType", {
  pattern = { "python", "javascript", "typescript", "java", "go", "php", "ruby", "rust", "c", "cpp", "sql" },
  callback = function(ev)
    vim.lsp.start({
      name = "kashif",
      cmd = { "vulnscan", "lsp", "--stdio" },
      root_dir = vim.fs.root(ev.buf, { ".git", "pyproject.toml", "package.json" }),
      settings = { kashif = { minSeverity = "low" } },
    })
  end,
})
```

Code actions: `vim.lsp.buf.code_action()` (default mapping `gra` in 0.11); hover: `K`; trail: `vim.diagnostic.open_float()`.

## Helix

`~/.config/helix/languages.toml` (keep the servers you already use in each `language-servers` list):

```toml
[language-server.kashif]
command = "vulnscan"
args = ["lsp", "--stdio"]
config = { kashif = { minSeverity = "low", language = "en" } }

[[language]]
name = "python"
language-servers = ["pylsp", "kashif"]

[[language]]
name = "javascript"
language-servers = ["typescript-language-server", "kashif"]

[[language]]
name = "java"
language-servers = ["jdtls", "kashif"]
```

Check with `hx --health python`. Code actions: <kbd>Space</kbd> <kbd>a</kbd>; diagnostics picker: <kbd>Space</kbd> <kbd>D</kbd>.

## Zed

Zed starts language servers through extensions; this repository contains a small one in [`editors/zed`](zed/):

1. Install Rust with `rustup` (Zed compiles the extension to WebAssembly).
2. In Zed: command palette → **zed: install dev extension** → choose the `editors/zed` folder.
3. Optional settings (`settings.json`):

```json
{
  "lsp": {
    "kashif": {
      "initialization_options": { "kashif": { "minSeverity": "low", "language": "en" } },
      "settings": { "kashif": { "minSeverity": "low", "language": "en" } },
      "binary": { "path": "/full/path/to/vulnscan", "arguments": ["lsp", "--stdio"] }
    }
  },
  "languages": {
    "Python": { "language_servers": ["...", "kashif"] }
  }
}
```

The extension finds `vulnscan` on the project's `PATH` unless `binary.path` is set. It runs on Zed's built-in
languages listed in `extension.toml`; add the names of other installed language extensions there (Java, PHP, Ruby ...).

## Sublime Text

Install the **LSP** package (Package Control), then *Preferences → Package Settings → LSP → Settings*:

```json
{
  "clients": {
    "kashif": {
      "enabled": true,
      "command": ["vulnscan", "lsp", "--stdio"],
      "selector": "source.python | source.js | source.ts | source.tsx | source.java | source.kotlin | source.cs | source.go | source.php | source.c | source.c++ | source.rust | source.swift | source.ruby | source.sql | source.yaml",
      "initializationOptions": { "kashif": { "minSeverity": "low", "language": "en" } },
      "settings": { "kashif.minSeverity": "low", "kashif.language": "en" }
    }
  }
}
```

Code actions: *LSP: Code Action* in the command palette; diagnostics panel: *LSP: Toggle Diagnostics Panel*.

## Emacs (eglot, built into Emacs 29+)

```elisp
(with-eval-after-load 'eglot
  (add-to-list 'eglot-server-programs
               '((python-mode python-ts-mode js-mode js-ts-mode typescript-ts-mode java-mode java-ts-mode
                  go-mode go-ts-mode php-mode ruby-mode ruby-ts-mode rust-mode rust-ts-mode sql-mode)
                 . ("vulnscan" "lsp" "--stdio"))))

(setq-default eglot-workspace-configuration
              '(:kashif (:minSeverity "low" :language "en")))
```

Then `M-x eglot`. Eglot runs one server per buffer, so this entry replaces another server for those modes; to keep
your usual language server and add Kashif's findings, use `lsp-mode` (which runs several servers side by side) with a
custom client for `("vulnscan" "lsp" "--stdio")`, or run Kashif for the modes where you need it most.
Code actions: `M-x eglot-code-actions`; findings: `M-x flymake-show-buffer-diagnostics`.

## Any other LSP client

Command `vulnscan lsp` (stdio), no initialization required beyond the standard `initialize`/`initialized`
exchange. The server logs to stderr; stdout carries only protocol messages.
