// Kashif for VS Code: a thin client of the Kashif language server (`vulnscan lsp`).
// All analysis happens in the server, so every editor that speaks LSP gets the same results.

import * as cp from "child_process";
import * as http from "http";
import * as vscode from "vscode";
import {
  CloseAction,
  ErrorAction,
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
  State,
} from "vscode-languageclient/node";

const SECTION = "kashif";
const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
type Counts = Partial<Record<(typeof SEVERITIES)[number], number>>;

interface StatusParams {
  state: "scanning" | "idle";
  counts?: Counts;
  total?: number;
}

let client: LanguageClient | undefined;
let status: vscode.StatusBarItem;
let output: vscode.OutputChannel;
let webUi: cp.ChildProcess | undefined;

function config(): vscode.WorkspaceConfiguration {
  return vscode.workspace.getConfiguration(SECTION);
}

function serverCommand(): { command: string; args: string[] } {
  const command = config().get<string>("serverPath", "vulnscan").trim() || "vulnscan";
  const args = config().get<string[]>("serverArgs", []).filter((a) => typeof a === "string");
  return { command, args };
}

function settingsPayload(): Record<string, unknown> {
  const c = config();
  return {
    minSeverity: c.get("minSeverity"),
    audit: c.get("audit"),
    exclude: c.get("exclude"),
    baseline: c.get("baseline"),
    language: c.get("language"),
  };
}

function showStatus(params: StatusParams): void {
  if (params.state === "scanning") {
    status.text = "$(sync~spin) Kashif";
    status.tooltip = "Kashif: scanning…";
    status.backgroundColor = undefined;
    status.show();
    return;
  }
  const counts = params.counts ?? {};
  const serious = (counts.critical ?? 0) + (counts.high ?? 0);
  const parts = SEVERITIES.filter((s) => (counts[s] ?? 0) > 0).map((s) => `${s}: ${counts[s]}`);
  status.text = serious > 0 ? `$(shield) Kashif ${serious}` : `$(shield) Kashif ${params.total ?? 0}`;
  status.tooltip = parts.length ? `Kashif findings — ${parts.join(", ")}\nClick to open the Problems panel` : "Kashif: no findings";
  status.backgroundColor = serious > 0 ? new vscode.ThemeColor("statusBarItem.errorBackground") : undefined;
  status.show();
}

async function startClient(context: vscode.ExtensionContext): Promise<void> {
  const { command, args } = serverCommand();
  const serverOptions: ServerOptions = {
    run: { command, args: [...args, "lsp", "--stdio"] },
    debug: { command, args: [...args, "lsp", "--stdio"] },
  };
  const deletions = vscode.workspace.createFileSystemWatcher("**/*", true, true, false);
  context.subscriptions.push(deletions);
  const clientOptions: LanguageClientOptions = {
    // Kashif also checks configuration files (Dockerfile, .env, YAML, XML ...): every file on disk is relevant.
    documentSelector: [{ scheme: "file" }],
    synchronize: {
      configurationSection: SECTION,
      // Deletions only: a deleted file's findings must leave the Problems panel. Saves already arrive as didSave,
      // and watching every change would re-scan the workspace on each build output write.
      fileEvents: deletions,
    },
    initializationOptions: { kashif: settingsPayload(), statusNotifications: true },
    outputChannel: output,
    errorHandler: {
      error: () => ({ action: ErrorAction.Continue }),
      closed: () => ({ action: CloseAction.DoNotRestart }),
    },
  };
  client = new LanguageClient("kashif", "Kashif", serverOptions, clientOptions);
  client.onDidChangeState((e) => {
    if (e.newState === State.Stopped) {
      status.text = "$(shield) Kashif (stopped)";
      status.tooltip = "Kashif language server is not running — run “Kashif: Restart language server”";
      status.show();
    }
  });
  try {
    await client.start();
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    const pick = await vscode.window.showErrorMessage(
      `Kashif could not start “${command} ${[...args, "lsp"].join(" ")}”: ${msg}. ` +
        "Install it with “pip install git+https://github.com/abdulrahmanahmedelabed-prog/vulnscan” or set kashif.serverPath.",
      "Open settings",
      "Installation guide",
    );
    if (pick === "Open settings") {
      void vscode.commands.executeCommand("workbench.action.openSettings", "kashif.serverPath");
    } else if (pick === "Installation guide") {
      void vscode.env.openExternal(
        vscode.Uri.parse("https://github.com/abdulrahmanahmedelabed-prog/vulnscan/tree/main/editors#readme"),
      );
    }
    client = undefined;
    return;
  }
  context.subscriptions.push(client.onNotification("kashif/status", (p: StatusParams) => showStatus(p)));
}

async function stopClient(): Promise<void> {
  const c = client;
  client = undefined;
  if (c) {
    try {
      await c.stop();
    } catch {
      /* already stopped */
    }
  }
}

function waitForHttp(url: string, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve) => {
    const attempt = () => {
      const req = http.get(url, (res) => {
        res.resume();
        resolve(true);
      });
      req.setTimeout(1000, () => req.destroy());
      req.on("error", () => {
        if (Date.now() > deadline) {
          resolve(false);
        } else {
          setTimeout(attempt, 300);
        }
      });
    };
    attempt();
  });
}

async function openWebUi(): Promise<void> {
  const port = Math.trunc(config().get<number>("webUiPort", 8765));
  const url = `http://127.0.0.1:${port}/`;
  if (!(await waitForHttp(url, 0))) {
    if (!webUi || webUi.exitCode !== null) {
      const { command, args } = serverCommand();
      webUi = cp.spawn(command, [...args, "ui", "--no-browser", "--port", String(port)], {
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true,
      });
      webUi.stdout?.on("data", (d: Buffer) => output.append(d.toString()));
      webUi.stderr?.on("data", (d: Buffer) => output.append(d.toString()));
      webUi.on("error", (e) => void vscode.window.showErrorMessage(`Kashif web UI: ${e.message}`));
    }
    if (!(await waitForHttp(url, 20000))) {
      void vscode.window.showErrorMessage(`Kashif web UI did not answer on ${url}; see the Kashif output channel.`);
      return;
    }
  }
  await vscode.env.openExternal(vscode.Uri.parse(url));
}

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  output = vscode.window.createOutputChannel("Kashif");
  status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  status.name = "Kashif";
  status.command = "workbench.actions.view.problems";
  status.text = "$(shield) Kashif";
  status.tooltip = "Kashif";
  status.show();
  context.subscriptions.push(output, status);

  context.subscriptions.push(
    vscode.commands.registerCommand("kashif.scanWorkspace", async () => {
      if (!client) {
        await startClient(context);
      }
      if (client) {
        await client.sendRequest("workspace/executeCommand", { command: "kashif.server.scanWorkspace", arguments: [] });
      }
    }),
    vscode.commands.registerCommand("kashif.openWebUI", () => openWebUi()),
    vscode.commands.registerCommand("kashif.restartServer", async () => {
      await stopClient();
      await startClient(context);
    }),
    vscode.workspace.onDidChangeConfiguration(async (e) => {
      if (e.affectsConfiguration("kashif.serverPath") || e.affectsConfiguration("kashif.serverArgs")) {
        await stopClient();
        await startClient(context);
      }
    }),
  );
  await startClient(context);
}

export async function deactivate(): Promise<void> {
  if (webUi && webUi.exitCode === null) {
    webUi.kill();
  }
  await stopClient();
}
