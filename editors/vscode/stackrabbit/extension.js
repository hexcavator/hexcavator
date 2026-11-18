// Stackrabbit: opens performance traces in a custom editor, answered by
// the stackrabbit engine (one per window, started on first use).
"use strict";

const vscode = require("vscode");
const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");
const { Session } = require("./lib/protocol");
const { LineHeat } = require("./lib/line-heat");

/** The requests a view may make of the engine about its trace. */
const VIEW_METHODS = new Set(["summary", "graph", "processes", "threads", "functions", "symbols", "events", "events.list", "tree.create", "tree.children", "tree.hotPath", "tree.close"]);

let channel;

/** The engine's path: the setting, the one shipped inside the extension, or a build of this repository. */
function enginePath(context) {
  const exe = process.platform === "win32" ? "stackrabbit.exe" : "stackrabbit";
  const configured = vscode.workspace.getConfiguration("stackrabbit").get("path");
  if (configured) {
    return configured;
  }
  const candidates = [path.join(context.extensionPath, "bin", exe)];
  // In this repository: editors/vscode/stackrabbit, beside target/.
  const repo = path.resolve(context.extensionPath, "..", "..", "..");
  for (const profile of ["release", "debug"]) {
    candidates.push(path.join(repo, "target", profile, exe));
  }
  return candidates.find((p) => fs.existsSync(p)) || candidates[0];
}

/** The engine: started when first needed, again if it exits. */
class Engine {
  constructor(context) {
    this.context = context;
    this.session = null;
    /** Each open trace's listeners (its editors) for what the engine says
     * about it. */
    this.listeners = new Map();
  }

  get() {
    if (this.session) {
      return this.session;
    }
    const exe = enginePath(this.context);
    channel.appendLine(`Starting ${exe} serve`);
    const child = spawn(exe, ["serve"], { stdio: ["pipe", "pipe", "pipe"] });
    const session = new Session(
      (bytes) => child.stdin.write(bytes),
      (method, params) => {
        for (const listen of this.listeners.get(params.trace) || []) {
          listen(method, params);
        }
      }
    );
    child.stdout.on("data", (chunk) => {
      try {
        session.receive(chunk);
      } catch (e) {
        channel.appendLine(`Engine output unreadable: ${e.message}`);
        child.kill();
      }
    });
    child.stderr.on("data", (chunk) => channel.append(chunk.toString()));
    const gone = (why) => {
      if (this.session === session) {
        this.session = null;
      }
      session.close(why);
    };
    child.on("error", (e) => gone(`The engine couldn't start (${exe}): ${e.message}`));
    child.on("exit", (code) => gone(`The engine exited (${code})`));
    this.child = child;
    this.session = session;
    return session;
  }

  dispose() {
    if (this.child) {
      this.child.kill();
    }
  }
}

/** A trace open in an editor: its engine trace ID, once open. */
class TraceDocument {
  constructor(uri) {
    this.uri = uri;
    this.trace = null;
    this.opening = null;
  }

  dispose() {}
}

class TraceEditorProvider {
  constructor(context, engine, heat) {
    this.context = context;
    this.engine = engine;
    this.heat = heat;
  }

  openCustomDocument(uri) {
    return new TraceDocument(uri);
  }

  resolveCustomEditor(document, panel) {
    const media = vscode.Uri.joinPath(this.context.extensionUri, "media");
    panel.webview.options = { enableScripts: true, localResourceRoots: [media] };
    panel.webview.html = html(panel.webview, media);
    const session = () => this.engine.get();
    const open = () => {
      if (!document.opening) {
        const config = vscode.workspace.getConfiguration("stackrabbit");
        document.opening = session()
          .request("open", {
            path: document.uri.fsPath,
            downloadSymbols: config.get("downloadSymbols"),
            symbolCache: config.get("symbolCache"),
            symbolServers: config.get("symbolServers"),
            stackTags: config.get("stackTags"),
          })
          .then((r) => {
            document.trace = r.trace;
            if (panel.active) {
              this.heat.setTrace(r.trace, path.basename(document.uri.fsPath));
            }
            return r;
          });
      }
      return document.opening;
    };
    let listening = false;
    const stateKey = `stackrabbit.view:${document.uri.fsPath.toLowerCase()}`;
    const listener = (method, params) => {
      panel.webview.postMessage({ type: "notification", method, params });
      // (PDBs loaded: the source lines have names now.)
      if (method === "symbols" && params.loaded !== undefined) {
        this.heat.changed(params.trace);
      }
    };
    // The source files show the active trace's line times.
    panel.onDidChangeViewState(() => {
      if (panel.active && document.trace !== null) {
        this.heat.setTrace(document.trace, path.basename(document.uri.fsPath));
      }
    });
    panel.webview.onDidReceiveMessage(async (m) => {
      if (m.type === "ready") {
        if (!listening) {
          listening = true;
          open()
            .then((r) => {
              const set = this.engine.listeners.get(r.trace) || new Set();
              set.add(listener);
              this.engine.listeners.set(r.trace, set);
            })
            .catch(() => {});
        }
        try {
          const r = await open();
          panel.webview.postMessage({ type: "opened", summary: r.summary, opened: r.opened, state: this.context.globalState.get(stateKey) });
        } catch (e) {
          document.opening = null;
          panel.webview.postMessage({ type: "failed", error: e.message });
        }
      } else if (m.type === "state") {
        // (Kept with the trace's path: it reopens where it was left.)
        this.context.globalState.update(stateKey, m.state);
      } else if (m.type === "copy") {
        await vscode.env.clipboard.writeText(m.text);
        vscode.window.setStatusBarMessage(`Stackrabbit: copied ${m.what} as Markdown`, 4000);
      } else if (m.type === "request") {
        if (!VIEW_METHODS.has(m.method) || document.trace === null) {
          panel.webview.postMessage({ type: "response", id: m.id, error: `${m.method}: not available` });
          return;
        }
        try {
          const result = await session().request(m.method, { ...m.params, trace: document.trace });
          panel.webview.postMessage({ type: "response", id: m.id, result });
        } catch (e) {
          panel.webview.postMessage({ type: "response", id: m.id, error: e.message });
        }
      }
    });
    panel.onDidDispose(() => {
      this.heat.forget(document.trace);
      const set = this.engine.listeners.get(document.trace);
      if (set) {
        set.delete(listener);
      }
      if (document.trace !== null && this.engine.session) {
        this.engine.session.request("close", { trace: document.trace }).catch(() => {});
      }
    });
  }
}

/** The view's page. */
function html(webview, media) {
  const nonce = Array.from({ length: 32 }, () => Math.floor(Math.random() * 36).toString(36)).join("");
  const src = (f) => webview.asWebviewUri(vscode.Uri.joinPath(media, f));
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${webview.cspSource}; script-src 'nonce-${nonce}';">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="stylesheet" href="${src("tree-view.css")}">
<title>Stackrabbit</title></head>
<body>
<div id="summary" class="summary">Opening…</div>
<div class="controls">
  <label>Weigh <select id="source">
    <option value="samples">CPU usage (sampled)</option>
    <option value="running">CPU usage (precise)</option>
    <option value="waits">Waits</option>
  </select></label>
  <label>Group by <select id="group">
    <option value="process">Process</option>
    <option value="process,thread">Process, thread</option>
    <option value="thread">Thread</option>
    <option value="cpu">Processor</option>
    <option value="tag">Stack tag</option>
    <option value="process,tag">Process, stack tag</option>
    <option value="">Nothing</option>
  </select></label>
  <label>Frames <select id="frames">
    <option value="function">By function</option>
    <option value="module">By module</option>
    <option value="address">By address</option>
  </select></label>
  <label><input type="checkbox" id="invert"> Callers (inverted)</label>
  <label>Graph <select id="graph-by">
    <option value="process">By process</option>
    <option value="thread">By thread</option>
    <option value="picked">Threads of the picked process</option>
  </select></label>
  <button id="hot" title="Expand the hot path under the selected row (*)">Hot path</button>
  <button id="highlight" title="Highlight the selected row's function in the graph; again to stop (H)">Highlight</button>
  <button id="copy" title="Copy as Markdown: the selected row and the rows open under it, or the tab's tables (Ctrl+C)">Copy</button>
  <span id="symbols" class="symbols"></span>
  <span id="status" class="status"></span>
</div>
<div class="graph"><canvas id="graph"></canvas><div id="graph-tip" class="graph-tip hidden"></div><div id="legend" class="legend"></div></div>
<div id="lost" class="lost"></div>
<div id="selection" class="selection">All of the trace. Drag across the graph to select a time range; double-click it to clear.</div>
<div class="tabs"><button id="tab-stacks" class="tab active">Stacks</button><button id="tab-functions" class="tab">Functions</button><button id="tab-processes" class="tab">Processes</button><button id="tab-symbols" class="tab">Symbols</button><button id="tab-events" class="tab">Events</button></div>
<div id="stacks-pane" class="pane">
<div id="focus-bar" class="focus-bar hidden"><span id="focus-text"></span> <button id="focus-clear" title="The whole tree again">Show all</button></div>
<div class="header"><span class="name">Stack</span><span class="num">Weight</span><span class="num">%</span><span class="num">Self</span></div>
<div id="viewport" class="viewport" tabindex="0"><div id="spacer"></div><div id="rows"></div></div>
</div>
<div id="functions-pane" class="pane hidden"><div id="card" class="card hidden"></div><div id="functions-title" class="threads-title"></div><table id="functions" class="processes"></table>
<div class="threads-title">Modules</div><table id="modules" class="processes"></table></div>
<div id="symbols-pane" class="pane hidden"><div id="symbols-title" class="threads-title"></div><table id="symbols-table" class="processes"></table>
<div id="no-debug-title" class="threads-title"></div><table id="no-debug" class="processes"></table></div>
<div id="events-pane" class="pane hidden"><div id="events-title" class="threads-title"></div><table id="events" class="processes"></table>
<div id="event-list-title" class="threads-title">Click a kind of event for its events.</div><div id="event-list-holder"></div></div>
<div id="processes-pane" class="pane hidden"><table id="processes" class="processes"></table>
<div id="threads-title" class="threads-title">Click a process for its threads.</div><table id="threads" class="processes"></table></div>
<script nonce="${nonce}" src="${src("tree-model.js")}"></script>
<script nonce="${nonce}" src="${src("graph.js")}"></script>
<script nonce="${nonce}" src="${src("tree-view.js")}"></script>
</body></html>`;
}

function activate(context) {
  channel = vscode.window.createOutputChannel("Stackrabbit");
  const engine = new Engine(context);
  const heat = new LineHeat(vscode, engine, (line) => channel.appendLine(line));
  context.subscriptions.push(
    channel,
    { dispose: () => engine.dispose() },
    heat,
    vscode.window.onDidChangeVisibleTextEditors(() => heat.refresh()),
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration("stackrabbit.lineHeat")) {
        heat.refresh();
      }
    }),
    vscode.window.registerCustomEditorProvider("stackrabbit.trace", new TraceEditorProvider(context, engine, heat), {
      webviewOptions: { retainContextWhenHidden: true },
      supportsMultipleEditorsPerDocument: true,
    }),
    vscode.commands.registerCommand("stackrabbit.openTrace", async () => {
      const picked = await vscode.window.showOpenDialog({ filters: { "Trace files": ["etl"] }, canSelectMany: false });
      if (picked && picked[0]) {
        await vscode.commands.executeCommand("vscode.openWith", picked[0], "stackrabbit.trace");
      }
    }),
    vscode.commands.registerCommand("stackrabbit.showLog", () => channel.show(true))
  );
}

function deactivate() {}

module.exports = { activate, deactivate };
