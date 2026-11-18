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
const VIEW_METHODS = new Set(["summary", "graph", "processes", "threads", "functions", "symbols", "events", "events.list", "regions", "disk", "fileio", "dpc", "registry", "hardfaults", "vmem", "heap", "pool", "memory", "tree.create", "tree.children", "tree.hotPath", "tree.close"]);

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
        vscode.window.setStatusBarMessage(`Stackrabbit: copied ${m.what} as ${m.format || "Markdown"}`, 4000);
      } else if (m.type === "request") {
        if (!VIEW_METHODS.has(m.method) || document.trace === null) {
          panel.webview.postMessage({ type: "response", id: m.id, error: `${m.method}: not available` });
          return;
        }
        // (The regions file is a setting.)
        const extra = m.method === "regions" ? { file: vscode.workspace.getConfiguration("stackrabbit").get("regionsFile") } : {};
        try {
          const result = await session().request(m.method, { ...m.params, ...extra, trace: document.trace });
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
  <button id="copy" title="Copy as Markdown: the selected row and the rows open under it, or the tab's tables (Ctrl+C)">Copy</button><button id="copy-csv" title="Copy as CSV, values unformatted: the selected row and the rows open under it, or the tab's tables (Ctrl+Shift+C)">Copy CSV</button>
  <span id="symbols" class="symbols"></span>
  <span id="status" class="status"></span>
</div>
<div class="graph"><canvas id="graph"></canvas><div id="graph-tip" class="graph-tip hidden"></div><div id="legend" class="legend"></div></div>
<div id="lost" class="lost"></div>
<div id="selection" class="selection">All of the trace. Drag across the graph to select a time range; double-click it to clear.</div>
<div class="tabs"><button id="tab-stacks" class="tab active">Stacks</button><button id="tab-functions" class="tab">Functions</button><button id="tab-processes" class="tab">Processes</button><button id="tab-symbols" class="tab">Symbols</button><button id="tab-events" class="tab">Events</button><button id="tab-regions" class="tab">Regions</button><button id="tab-disk" class="tab">Disk</button><button id="tab-fileio" class="tab">File I/O</button><button id="tab-dpc" class="tab">DPC/ISR</button><button id="tab-registry" class="tab">Registry</button><button id="tab-hardfaults" class="tab">Hard Faults</button><button id="tab-vmem" class="tab">Virtual Memory</button><button id="tab-heap" class="tab">Heap</button><button id="tab-pool" class="tab">Pool</button><button id="tab-memory" class="tab">Memory</button></div>
<div id="stacks-pane" class="pane">
<div id="focus-bar" class="focus-bar hidden"><span id="focus-text"></span> <button id="focus-clear" title="The whole tree again">Show all</button></div>
<div class="header"><span class="name">Stack</span><span class="num">Weight</span><span class="num">%</span><span class="num">Self</span></div>
<div id="viewport" class="viewport" tabindex="0"><div id="spacer"></div><div id="rows"></div></div>
</div>
<div id="functions-pane" class="pane hidden"><div id="card" class="card hidden"></div><div id="functions-title" class="threads-title"></div><table id="functions" class="processes"></table>
<div class="threads-title">Modules</div><table id="modules" class="processes"></table></div>
<div id="symbols-pane" class="pane hidden"><div id="symbols-title" class="threads-title"></div><table id="symbols-table" class="processes"></table>
<div id="no-debug-title" class="threads-title"></div><table id="no-debug" class="processes"></table></div>
<div id="disk-pane" class="pane hidden"><div class="threads-title"><span id="disk-title"></span> <label>Group by <select id="disk-by">
    <option value="process">Process</option><option value="file">File</option><option value="disk">Disk</option><option value="type">Type</option>
  </select></label></div><table id="disk-groups" class="processes"></table>
<div class="threads-title">The I/Os with the most disk service time</div><table id="disk-ios" class="processes"></table></div>
<div id="fileio-pane" class="pane hidden"><div class="threads-title"><span id="fileio-title"></span> <label>Group by <select id="fileio-by">
    <option value="process">Process</option><option value="file">File</option><option value="operation">Operation</option>
  </select></label></div><table id="fileio-groups" class="processes"></table>
<div class="threads-title">The longest file operations</div><table id="fileio-ops" class="processes"></table></div>
<div id="dpc-pane" class="pane hidden"><div class="threads-title"><span id="dpc-title"></span> <label>Group by <select id="dpc-by">
    <option value="module">Module</option><option value="function">Function</option><option value="processor">Processor</option><option value="type">Type</option>
  </select></label></div><table id="dpc-groups" class="processes"></table>
<div class="threads-title">How long they took</div><table id="dpc-histogram" class="processes"></table>
<div class="threads-title">The longest</div><table id="dpc-runs" class="processes"></table></div>
<div id="registry-pane" class="pane hidden"><div class="threads-title"><span id="registry-title"></span> <label>Group by <select id="registry-by">
    <option value="process">Process</option><option value="key">Key</option><option value="operation">Operation</option>
  </select></label></div><table id="registry-groups" class="processes"></table>
<div class="threads-title">The longest registry operations</div><table id="registry-ops" class="processes"></table></div>
<div id="hardfaults-pane" class="pane hidden"><div class="threads-title"><span id="hardfaults-title"></span> <label>Group by <select id="hardfaults-by">
    <option value="process">Process</option><option value="file">File</option><option value="thread">Thread</option>
  </select></label></div><table id="hardfaults-groups" class="processes"></table>
<div class="threads-title">The longest hard faults</div><table id="hardfaults-faults" class="processes"></table></div>
<div id="vmem-pane" class="pane hidden"><div class="threads-title"><span id="vmem-title"></span> <label>Group by <select id="vmem-by">
    <option value="process">Process</option><option value="thread">Thread</option>
  </select></label></div><table id="vmem-groups" class="processes"></table>
<div class="threads-title">The largest commits</div><table id="vmem-lifetimes" class="processes"></table></div>
<div id="heap-pane" class="pane hidden"><div class="threads-title"><span id="heap-title"></span> <label>Group by <select id="heap-by">
    <option value="process">Process</option><option value="heap">Heap</option><option value="thread">Thread</option>
  </select></label></div><table id="heap-groups" class="processes"></table>
<div class="threads-title">The largest heap blocks</div><table id="heap-blocks" class="processes"></table></div>
<div id="pool-pane" class="pane hidden"><div class="threads-title"><span id="pool-title"></span> <label>Group by <select id="pool-by">
    <option value="tag">Tag</option><option value="type">Type</option><option value="process">Process</option><option value="thread">Thread</option>
  </select></label></div><table id="pool-groups" class="processes"></table>
<div class="threads-title">The largest pool blocks</div><table id="pool-blocks" class="processes"></table></div>
<div id="memory-pane" class="pane hidden"><div class="threads-title"><span id="memory-title"></span> <label>Group by <select id="memory-by">
    <option value="process">Process</option><option value="name">Name</option>
  </select></label></div><table id="memory-groups" class="processes"></table>
<div class="threads-title">Each snapshot's totals</div><table id="memory-series" class="processes"></table></div>
<div id="regions-pane" class="pane hidden"><div id="regions-title" class="threads-title"></div><table id="regions" class="processes"></table>
<div id="region-instances-title" class="threads-title"></div><table id="region-instances" class="processes"></table></div>
<div id="events-pane" class="pane hidden"><div id="events-title" class="threads-title"></div><table id="events" class="processes"></table>
<div id="event-list-title" class="threads-title">Click a kind of event for its events.</div><div id="event-list-holder"></div><div id="event-stack" class="event-stack"></div></div>
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
