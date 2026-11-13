// Hexcavator: runs `hexc` on binaries and shows what it reports. A sidebar
// of binaries and builds compared (sidebar.js) opens their headers,
// symbols, types, sources, data, and disassembly. Size reports show as
// interactive treemaps or sunbursts, diffs, or findings, and there is an
// "Open With" editor for binaries.
"use strict";

const vscode = require("vscode");
const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const disasm = require("./media/disasm.js");
const sidebarModule = require("./sidebar.js");
const lib = require("./lib/hexc.js");

/** The sidebar, once activated (reports opened elsewhere are added to it). */
let sidebar = null;

// Binaries hexc reads: PE images and COFF objects and libraries, ELF and
// Mach-O files and archives, and WebAssembly modules.
const EXTENSIONS = ["exe", "dll", "sys", "efi", "obj", "lib", "so", "o", "a", "ko", "elf", "axf", "out", "dylib", "bundle", "wasm"];
const BINARIES = { Binaries: EXTENSIONS, "All files": ["*"] };

/**
 * One `hexc serve`, kept running: each command is a request to it, and
 * what it reads from a binary (its model, symbols, and maps) stays in its
 * memory for the next, until the binary changes.
 */
class HexcServer {
  /** `launch`: its arguments and added environment (lib.serveLaunch). */
  constructor(exe, launch) {
    this.exe = exe;
    this.launch = launch || { args: ["serve"], env: {} };
    this.key = exe + "\u0000" + JSON.stringify(this.launch);
    this.child = null;
    this.next = 1;
    /**
     * Requests waiting for their responses, by id: { resolve, reject,
     * args, started }.
     */
    this.pending = new Map();
    /** Called when a request starts or ends (for the status bar). */
    this.onChange = () => {};
  }

  start() {
    const child = spawn(this.exe, this.launch.args, {
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
      env: Object.assign({}, process.env, this.launch.env),
    });
    this.child = child;
    log(`started ${this.exe} ${this.launch.args.join(" ")} (pid ${child.pid})`);
    // A response's chunks, until its newline: each chunk is searched once
    // (responses run to megabytes; searching all that came before each
    // time held the extension host up for seconds).
    let parts = [];
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      let start = 0;
      let end;
      while ((end = chunk.indexOf("\n", start)) >= 0) {
        parts.push(chunk.slice(start, end));
        const line = parts.join("");
        parts = [];
        start = end + 1;
        if (line.trim()) {
          this.answer(line);
        }
      }
      if (start < chunk.length) {
        parts.push(chunk.slice(start));
      }
    });
    // (Its own messages, outside any request: a panic's, say.)
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (text) => log(`hexc serve: ${text.trimEnd()}`));
    // (Writing to a server that has just exited: its exit answers.)
    child.stdin.on("error", (e) => log(`hexc serve's input: ${e.message}`));
    const gone = (why) => {
      if (this.child !== child) {
        return;
      }
      this.child = null;
      log(`hexc serve ended: ${why.message}`);
      for (const { reject } of this.pending.values()) {
        reject(why);
      }
      this.pending.clear();
      this.onChange();
    };
    child.on("error", (e) =>
      gone(new Error(e.code === "ENOENT" ? `hexc was not found ("${this.exe}"); set hexcavator.path` : e.message))
    );
    child.on("exit", (code) => gone(new Error(`hexc serve exited (${code})`)));
  }

  answer(line) {
    let v;
    try {
      v = JSON.parse(line);
    } catch {
      return;
    }
    const waiting = this.pending.get(v.id);
    if (!waiting) {
      return; // Cancelled.
    }
    this.pending.delete(v.id);
    log(`#${v.id} ${v.code === 0 ? "done" : `failed (${v.error || v.code})`} in ${Date.now() - waiting.started} ms, ${(v.stdout || "").length} bytes`);
    this.onChange();
    if (v.error !== undefined) {
      waiting.reject(new Error(v.error));
    } else if (v.code !== 0) {
      // (Its output too: some commands answer and say no, as `signature`
      // does of a file that isn't signed.)
      waiting.reject(Object.assign(new Error((v.stderr || "").trim() || `hexc exited with ${v.code}`), { code: v.code, stdout: v.stdout }));
    } else {
      waiting.resolve(v.stdout);
    }
  }

  /** Runs hexc with `args`; resolves with its standard output. */
  run(args, cancel) {
    if (!this.child) {
      this.start();
    }
    const id = this.next++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject, args, started: Date.now() });
      log(`#${id} hexc ${args.map(lib.quote).join(" ")}`);
      this.onChange();
      if (cancel) {
        // The command runs on (what it builds is kept for the next); its
        // answer is dropped.
        cancel.onCancellationRequested(() => {
          if (this.pending.delete(id)) {
            log(`#${id} cancelled`);
            this.onChange();
            reject(Object.assign(new Error("Cancelled"), { cancelled: true }));
          }
        });
      }
      this.child.stdin.write(JSON.stringify({ id, args }) + "\n");
    });
  }

  stop() {
    if (this.child) {
      this.child.stdin.end();
      this.child = null;
    }
  }

  /** Ends the server now, failing what it was doing (a stuck command). */
  kill() {
    const child = this.child;
    if (!child) {
      return;
    }
    const why = new Error("hexc was restarted");
    for (const { reject } of this.pending.values()) {
      reject(why);
    }
    this.pending.clear();
    this.child = null;
    child.kill();
    log("hexc serve restarted");
    this.onChange();
  }
}

/** The server, for the configured hexc (restarted when that changes). */
let server = null;

/** The Hexcavator output channel: each hexc request, and how long it took. */
let channel = null;
function log(text) {
  if (channel) {
    channel.appendLine(`[${new Date().toISOString().slice(11, 23)}] ${text}`);
  }
}

/**
 * The status bar's note of hexc's requests that have run for a while
 * (click: the log; Restart hexc, in the Hexcavator pane's ... menu, ends
 * them).
 */
let busy = null;
let busyTimer = null;
function showBusy() {
  if (!busy || !server) {
    return;
  }
  const now = Date.now();
  const slow = [...server.pending.entries()].filter(([, p]) => now - p.started > 3000);
  if (!slow.length) {
    busy.hide();
  } else {
    const oldest = Math.max(...slow.map(([, p]) => now - p.started));
    busy.text = `$(sync~spin) hexc: ${slow.length} running (${Math.round(oldest / 1000)} s)`;
    busy.tooltip = new vscode.MarkdownString(
      slow.map(([id, p]) => `#${id} \`hexc ${p.args.map(lib.quote).join(" ").replace(/`/g, "'")}\` (${Math.round((now - p.started) / 1000)} s)`).join("\n\n") +
        "\n\nClick for the log; **Restart hexc**, in the Hexcavator pane's **…** menu, ends them."
    );
    busy.show();
  }
  clearTimeout(busyTimer);
  if (server.pending.size) {
    busyTimer = setTimeout(showBusy, 1000);
  }
}

/** Runs hexc with `args`; resolves with its standard output. */
function runHexc(args, cancel) {
  const config = vscode.workspace.getConfiguration("hexcavator");
  const exe = lib.hexcPath(config.get("path"));
  const launch = lib.serveLaunch((name) => config.get(name));
  const key = exe + "\u0000" + JSON.stringify(launch);
  if (!server || server.key !== key) {
    if (server) {
      server.stop();
    }
    server = new HexcServer(exe, launch);
    server.onChange = showBusy;
  }
  return server.run(args, cancel);
}

async function pickBinary(title) {
  const picked = await vscode.window.showOpenDialog({ title, canSelectMany: false, filters: BINARIES });
  return picked && picked[0];
}

/**
 * hexc size's arguments for a report on `file` (against `base`): by the
 * view's grouping and Others threshold (`view`), or the settings'.
 */
function sizeArgs(file, base, format, view) {
  const config = vscode.workspace.getConfiguration("hexcavator");
  const sources = (view && view.sources) || config.get("sources") || ["sections"];
  const rows = config.get("rows");
  // (The Symbols page has every row: its tree folds nothing, and its maps
  // fold what they can't draw.)
  const args = ["size", "-d", sources.join(","), "-n", view && view.all ? "0" : String(rows ?? 100)];
  const min = view && !view.all && view.min;
  if (min) {
    args.push("-min", min);
  }
  args.push(format || "-json", file);
  if (base) {
    args.push("--", base);
  }
  return args;
}

/** The page: header, toolbar, the map (with its hover card), and details. */
function pageHtml(webview, context, title) {
  const media = (name) => webview.asWebviewUri(vscode.Uri.file(path.join(context.extensionPath, "media", name)));
  const nonce = crypto.randomBytes(16).toString("base64");
  const esc = (s) => s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${webview.cspSource}; script-src 'nonce-${nonce}';">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="stylesheet" href="${media("view.css")}">
<link rel="stylesheet" href="${media("loading.css")}">
<title>${esc(title)}</title>
</head>
<body>
<header id="header"></header>
<div id="toolbar"></div>
<div id="main"><div id="map" role="tree"></div><div id="tip" role="tooltip"></div></div>
<div id="legend"></div>
<div id="details"></div>
<script nonce="${nonce}" src="${media("loading.js")}"></script>
<script nonce="${nonce}" src="${media("treemap.js")}"></script>
<script nonce="${nonce}" src="${media("disasm.js")}"></script>
<script nonce="${nonce}" src="${media("table.js")}"></script>
<script nonce="${nonce}" src="${media("view.js")}"></script>
</body>
</html>`;
}

/**
 * Runs hexc with `args` for a pane: its spinner shows there meanwhile,
 * saying `text`, with Cancel (in place of a notification).
 */
async function paneRun(webview, text, args) {
  const source = new vscode.CancellationTokenSource();
  const sub = webview.onDidReceiveMessage((m) => m && m.command === "cancel" && source.cancel());
  webview.postMessage({ kind: "loading", text });
  try {
    return await runHexc(args, source.token);
  } finally {
    sub.dispose();
    source.dispose();
  }
}

async function withProgress(title, task) {
  return vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title, cancellable: true },
    (_progress, cancel) => task(cancel)
  );
}

/** The status bar's summary of the report in the active panel. */
let status;
function showStatus(report) {
  if (!status) {
    return;
  }
  if (!report) {
    status.hide();
    return;
  }
  const t = report.total;
  const f = (n) => {
    const units = ["B", "KiB", "MiB", "GiB"];
    let v = Math.abs(n);
    let u = 0;
    while (v >= 1024 && u < units.length - 1) {
      v /= 1024;
      u++;
    }
    return (n < 0 ? "-" : report.diff && n > 0 ? "+" : "") + v.toFixed(u && v < 100 ? 1 : 0) + " " + units[u];
  };
  status.text = `$(graph) ${f(t.file)} file · ${f(t.vm)} memory`;
  status.tooltip = report.diff ? "Size change (Hexcavator)" : "Size (Hexcavator)";
  status.show();
}

/** Open report panels, by file and base, so that a second request reveals the first. */
const panels = new Map();

/** Wires a webview (a panel's or a custom editor's) to a report. */
/** The table of a binary's labels for `sources` (hexc size -table): every
 * one but the source files' unless they're asked for, which are apart; with
 * `base`, a diff's (each row's change, and its base's sizes). */
function tableArgs(file, sources, base) {
  const args = (sources || []).includes("sourcefiles") ? ["size", "-table", "-d", sources.join(","), file] : ["size", "-table", file];
  if (base) {
    args.push("--", base);
  }
  return args;
}

function attach(context, webview, onDispose, file, base, at, kind) {
  // The grouping last picked on a Symbols page (else none: every symbol).
  // (The Sources page: grouped by source file at first; remembered apart.)
  const viewKey = kind === "sources" ? "hexcavator.sourcesView" : "hexcavator.symbolsView";
  const first = kind === "sources" ? ["sourcefiles", "symbols"] : ["symbols"];
  const view = Object.assign({ sources: first, min: "", all: true }, context.globalState.get(viewKey) || {});
  view.all = true;
  const state = { file, base, report: null, at, view, caps: null, names: false };
  // What hexc says the file supports (its tools, its format), for the
  // page's menus and grouping chips.
  const capsOf = async () => {
    if (!state.caps && sidebar) {
      try {
        state.caps = await sidebar.caps({ file: state.file, base: null });
      } catch {
        state.caps = null;
      }
    }
    return state.caps;
  };
  // Each symbol's mangled name, read once, in the background (a PE
  // image's: the table has the others').
  const names = async () => {
    if (state.names || state.base || (state.table && state.table.columns.includes("rawsymbols"))) {
      return;
    }
    state.names = true;
    try {
      const out = await runHexc(["size", "-mangled", state.file]);
      webview.postMessage({ kind: "names", names: JSON.parse(out).names || [] });
    } catch {
      // (No names: the column stays empty.)
    }
  };
  const load = async (refresh) => {
    const name = path.basename(state.file);
    try {
      // Every label of every symbol at once (a diff's: each one's change),
      // which the page groups itself, as the chips choose.
      const out = await paneRun(
        webview,
        state.base ? `Comparing ${name} with ${path.basename(state.base)}…` : `Reading ${name}…`,
        tableArgs(state.file, state.view.sources, state.base)
      );
      state.table = JSON.parse(out);
      const t = state.table;
      state.report = { diff: !!t.diff, total: { name: "TOTAL", file: t.file, vm: t.vm, old_file: t.old_file, old_vm: t.old_vm } };
      const caps = await capsOf();
      webview.postMessage({
        kind: "report",
        file: state.file,
        base: state.base,
        report: state.table ? undefined : state.report,
        table: state.table || undefined,
        levels: (state.view.sources || ["symbols"]).filter((x) => x !== "symbols"),
        refresh,
        at: refresh ? undefined : state.at,
        min: state.view.min || "",
        tools: caps && Array.isArray(caps.tools) ? caps.tools : undefined,
        format: caps && caps.format,
      });
      showStatus(state.report);
      names();
    } catch (e) {
      // Cancelled as it opened: a panel closes (onDispose closes it).
      if (e.cancelled && !state.report && typeof onDispose === "function") {
        onDispose();
        return;
      }
      if (!e.cancelled) {
        vscode.window.showErrorMessage(`hexc: ${e.message}`);
      }
      webview.postMessage({ kind: "failed", message: e.message });
    }
  };
  const remember = () => context.globalState.update(viewKey, { sources: state.view.sources });
  webview.onDidReceiveMessage(async (m) => {
    switch (m && m.command) {
      case "refresh":
        await load(true);
        break;
      case "regroup":
        if (Array.isArray(m.sources) && m.sources.every((s) => typeof s === "string")) {
          state.view.sources = m.sources;
          remember();
          // (The page regrouped its table itself.)
          if (!m.local) {
            await load(true);
          }
        }
        break;
      case "threshold":
        if (typeof m.min === "string" && (m.min === "" || /^\s*\d+(\.\d+)?\s*(%|[kKmMgG])?\s*$/.test(m.min))) {
          state.view.min = m.min.trim();
          remember();
          await load(true);
        } else {
          vscode.window.showWarningMessage(`Others below: a size (512, 4k, 1M) or a percentage (0.5%), not "${m.min}"`);
        }
        break;
      case "inspect":
        if (typeof m.name === "string" && m.name) {
          await inspectSymbol(state.file, m.name, m.hint);
        }
        break;
      case "compare": {
        const remembered = context.workspaceState.get(`hexcavator.base:${state.file}`);
        const picked = await vscode.window.showOpenDialog({
          title: `Base build to compare ${path.basename(state.file)} with`,
          canSelectMany: false,
          filters: BINARIES,
          defaultUri: remembered ? vscode.Uri.file(remembered) : undefined,
        });
        if (picked && picked[0]) {
          context.workspaceState.update(`hexcavator.base:${state.file}`, picked[0].fsPath);
          openReport(context, state.file, picked[0].fsPath);
        }
        break;
      }
      case "export":
        await exportReport(state.file, state.base, state.view);
        break;
      case "copy":
        await vscode.env.clipboard.writeText(m.text || "");
        vscode.window.setStatusBarMessage("Copied the table", 2000);
        break;
      case "disassemble":
        if (typeof m.name === "string" && m.name) {
          await openDisassembly(state.file, m.name);
        }
        break;
    }
  }, undefined, context.subscriptions);
  return { load, state, onDispose };
}

/** Opens (or shows) the report on `file` (against `base`), at the row `at` (a path of names) if given. */
/**
 * Opens (or shows) the Symbols page of `file` (or its diff with `base`);
 * `kind` "sources": the Sources page, the same page grouped by source file
 * at first (its grouping remembered apart).
 */
function openReport(context, file, base, at, kind) {
  if (sidebar) {
    sidebar.add(file, base);
  }
  const key = `${file}\u0000${base || ""}\u0000${kind || ""}`;
  const existing = panels.get(key);
  if (existing) {
    existing.reveal();
    if (at) {
      existing.webview.postMessage({ kind: "goto", at });
    }
    return;
  }
  const name = path.basename(file);
  const title = base ? `Symbols: ${name} vs ${path.basename(base)}` : `${kind === "sources" ? "Sources" : "Symbols"}: ${name}`;
  const panel = vscode.window.createWebviewPanel("hexcSize", title, vscode.ViewColumn.Active, {
    enableScripts: true,
    retainContextWhenHidden: true,
    localResourceRoots: [vscode.Uri.file(path.join(context.extensionPath, "media"))],
  });
  panel.iconPath = vscode.Uri.file(path.join(context.extensionPath, "media", "icon.svg"));
  panel.webview.html = pageHtml(panel.webview, context, title);
  const view = attach(context, panel.webview, () => panel.dispose(), file, base, at, kind);
  panels.set(key, panel);
  panel.onDidDispose(() => {
    panels.delete(key);
    showStatus(null);
  });
  panel.onDidChangeViewState((e) => showStatus(e.webviewPanel.active ? view.state.report : null));
  view.load(false);
}

async function exportReport(file, base, view) {
  const choice = await vscode.window.showQuickPick(
    [
      { label: "CSV", description: "hexc size -csv", flag: "-csv", ext: "csv" },
      { label: "TSV", description: "hexc size -tsv", flag: "-tsv", ext: "tsv" },
      { label: "JSON", description: "hexc size -json", flag: "-json", ext: "json" },
    ],
    { title: "Export the report as" }
  );
  if (!choice) {
    return;
  }
  const target = await vscode.window.showSaveDialog({
    defaultUri: vscode.Uri.file(`${file}.size.${choice.ext}`),
    filters: { [choice.label]: [choice.ext] },
  });
  if (!target) {
    return;
  }
  try {
    const out = await withProgress(`hexc: exporting ${path.basename(file)}`, (cancel) => runHexc(sizeArgs(file, base, choice.flag, view), cancel));
    await vscode.workspace.fs.writeFile(target, Buffer.from(out, "utf8"));
    vscode.window.showInformationMessage(`Exported to ${target.fsPath}`);
  } catch (e) {
    vscode.window.showErrorMessage(`hexc: ${e.message}`);
  }
}

async function findings(context, uri) {
  const file = uri ? uri.fsPath : (await pickBinary("Image to examine"))?.fsPath;
  if (!file) {
    return;
  }
  if (sidebar) {
    sidebar.add(file, null);
  }
  const name = path.basename(file);
  const panel = vscode.window.createWebviewPanel("hexcFindings", `Size Reduction: ${name}`, vscode.ViewColumn.Active, {
    enableScripts: true,
    retainContextWhenHidden: true,
    localResourceRoots: [vscode.Uri.file(path.join(context.extensionPath, "media"))],
  });
  panel.webview.html = pageHtml(panel.webview, context, `Size Reduction: ${name}`);
  try {
    // The build changes that would save space (hexc recommend), alongside.
    const recs = runHexc(["recommend", "-json", file]).then(
      (out) => ({ recommendations: JSON.parse(out) }),
      (e) => ({ recommendationsError: e.message })
    );
    const out = await paneRun(panel.webview, `Examining ${name}…`, ["size", "-findings", "-json", "-top", "0", file]);
    panel.webview.postMessage(Object.assign({ kind: "findings", file, findings: JSON.parse(out) }, await recs));
  } catch (e) {
    if (e.cancelled) {
      panel.dispose();
    } else {
      vscode.window.showErrorMessage(`hexc: ${e.message}`);
      panel.webview.postMessage({ kind: "failed", message: e.message });
    }
  }
}

/**
 * Disassembly documents (`hexc-disasm:` URIs): `hexc size -disassemble`'s
 * listing of one function, read-only, highlighted by the extension's
 * grammar. Opening one again shows it again (VS Code keeps the document).
 */
class DisassemblyProvider {
  constructor() {
    this.changed = new vscode.EventEmitter();
    this.onDidChange = this.changed.event;
  }

  async provideTextDocumentContent(uri, cancel) {
    const target = disasm.parseDisasmQuery(uri.query);
    if (!target) {
      return "(no function named)";
    }
    try {
      const args = ["size", "-disassemble", target.name, target.file];
      if (target.style === "blocks") {
        args.push("-blocks");
      }
      const text = await runHexc(args, cancel);
      return target.style === "diff" ? disasm.withoutAddresses(text) : text;
    } catch (e) {
      return `(hexc could not disassemble ${target.name}: ${e.message})
`;
    }
  }
}

/**
 * What a symbol is: "code" or "data". The debug information says (by its
 * kind); otherwise `hint` (from the section it is in), else code.
 */
async function symbolKind(file, name, hint) {
  if (!lib.can(await sidebarModule.capsOf(file, runHexc), "query")) {
    return hint === "data" ? "data" : "code";
  }
  try {
    const out = await runHexc(["query", file, `${lib.nameIs(name)} select name, kind limit 5`, "-json"]);
    const kinds = (JSON.parse(out).rows || []).map((r) => r.kind);
    if (kinds.some((k) => /function|thunk|block/.test(k))) {
      return "code";
    }
    if (kinds.length) {
      return "data";
    }
  } catch {
    // (Fall back on the hint.)
  }
  return hint === "data" ? "data" : "code";
}

/** Opens a symbol: a function's code, or a datum's bytes and fields. */
async function inspectSymbol(file, name, hint) {
  const kind = await symbolKind(file, name, hint);
  if (kind === "code") {
    await openDisassembly(file, name);
  } else {
    await openData(file, name);
  }
}

/** Open table views, by their command line. */
const tablePanels = new Map();

/**
 * A tool's output (hexc `args` with -json) as tables. `options.file` is
 * the binary (for opening symbols); `options.query`, a query to edit.
 */
async function openTable(title, args, options) {
  const context = extension;
  const o = options || {};
  const file = o.file || "";
  let current = { title, args, query: o.query };
  const key = args.join("\u0000");
  const existing = tablePanels.get(key);
  if (existing) {
    existing.reveal(undefined, false);
    return;
  }
  const panel = vscode.window.createWebviewPanel("hexcTable", title, vscode.ViewColumn.Active, {
    enableScripts: true,
    retainContextWhenHidden: true,
    localResourceRoots: [vscode.Uri.file(path.join(context.extensionPath, "media"))],
  });
  panel.iconPath = vscode.Uri.file(path.join(context.extensionPath, "media", "icon.svg"));
  const media = (n) => panel.webview.asWebviewUri(vscode.Uri.file(path.join(context.extensionPath, "media", n)));
  const nonce = crypto.randomBytes(16).toString("base64");
  panel.webview.html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${panel.webview.cspSource}; script-src 'nonce-${nonce}';">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="stylesheet" href="${media("disasm-view.css")}">
<link rel="stylesheet" href="${media("loading.css")}">
<link rel="stylesheet" href="${media("table-view.css")}">
</head>
<body>
<header id="header"></header>
<div id="toolbar"></div>
<div id="body"></div>
<script nonce="${nonce}" src="${media("loading.js")}"></script>
<script nonce="${nonce}" src="${media("table.js")}"></script>
<script nonce="${nonce}" src="${media("table-view.js")}"></script>
</body>
</html>`;
  tablePanels.set(key, panel);
  panel.onDidDispose(() => tablePanels.delete(key));
  const exe = () => lib.hexcPath(vscode.workspace.getConfiguration("hexcavator").get("path"));
  let shown = false;
  const load = async () => {
    // (`pe`: the rows' symbols open in the views that need debug
    // information.)
    const full = lib.can(await sidebarModule.capsOf(file, runHexc), "why");
    const message = { kind: "table", title: current.title, file, pe: full, query: current.query, command: lib.commandLine(exe(), current.args) };
    try {
      const out = await paneRun(panel.webview, `Running ${lib.commandLine("hexc", current.args)}…`, lib.jsonArgs(current.args));
      panel.webview.postMessage({ ...message, json: JSON.parse(out) });
      shown = true;
    } catch (e) {
      if (e.cancelled) {
        // Cancelled as it opened: closed; on a refresh, as it was.
        if (!shown) {
          panel.dispose();
        } else {
          panel.webview.postMessage({ kind: "cancelled" });
        }
        return;
      }
      panel.webview.postMessage({ ...message, json: null, error: e.message });
    }
  };
  panel.webview.onDidReceiveMessage(async (m) => {
    switch (m && m.command) {
      case "inspect":
        if (typeof m.name === "string" && m.name && file) {
          await inspectSymbol(file, m.name);
        }
        break;
      case "openSource":
        if (typeof m.file === "string") {
          try {
            const local = sidebarModule.findSource(m.file, file) || m.file;
            const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(local));
            const line = Math.max(0, (m.line || 1) - 1);
            await vscode.window.showTextDocument(doc, { viewColumn: vscode.ViewColumn.Beside, selection: new vscode.Range(line, 0, line, 0) });
          } catch {
            vscode.window.showWarningMessage(`${m.file} is not on this machine.`);
          }
        }
        break;
      case "query":
        if (typeof m.query === "string" && m.query.trim() && current.query !== undefined) {
          current = { ...current, query: m.query.trim(), args: [current.args[0], current.args[1], m.query.trim()] };
          context.workspaceState.update("hexcavator.lastQuery", current.query);
          await load();
        }
        break;
      case "openText":
        if (sidebar && sidebar.showOutput) {
          await sidebar.showOutput(current.title, current.args);
        }
        break;
      case "copy":
        await vscode.env.clipboard.writeText(m.text || "");
        vscode.window.setStatusBarMessage(`Copied ${m.what || "it"}`, 2000);
        break;
      case "refresh":
        await load();
        break;
    }
  }, undefined, context.subscriptions);
  await load();
}

/** Open data views, by file and datum. */
const dataPanels = new Map();

/** Shows datum `name` of the binary at `file`: its value by type, and its bytes. */
async function openData(file, name) {
  const context = extension;
  if (!lib.can(await sidebarModule.capsOf(file, runHexc), "data")) {
    vscode.window.showInformationMessage(`hexc reads data with its type from debug information; none was found for ${path.basename(file)}.`);
    return;
  }
  const key = `${file}\u0000${name}`;
  const existing = dataPanels.get(key);
  if (existing) {
    existing.reveal(undefined, true);
    return;
  }
  const short = name.length > 40 ? name.slice(0, 39) + "…" : name;
  const panel = vscode.window.createWebviewPanel("hexcData", `▦ ${short}`, { viewColumn: vscode.ViewColumn.Beside, preserveFocus: false }, {
    enableScripts: true,
    retainContextWhenHidden: true,
    localResourceRoots: [vscode.Uri.file(path.join(context.extensionPath, "media"))],
  });
  panel.iconPath = vscode.Uri.file(path.join(context.extensionPath, "media", "icon.svg"));
  const media = (n) => panel.webview.asWebviewUri(vscode.Uri.file(path.join(context.extensionPath, "media", n)));
  const nonce = crypto.randomBytes(16).toString("base64");
  panel.webview.html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${panel.webview.cspSource}; script-src 'nonce-${nonce}';">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="stylesheet" href="${media("disasm-view.css")}">
<link rel="stylesheet" href="${media("loading.css")}">
<link rel="stylesheet" href="${media("data-view.css")}">
</head>
<body>
<header id="header"></header>
<div id="toolbar"></div>
<div id="body"></div>
<script nonce="${nonce}" src="${media("loading.js")}"></script>
<script nonce="${nonce}" src="${media("data-view.js")}"></script>
</body>
</html>`;
  dataPanels.set(key, panel);
  panel.onDidDispose(() => dataPanels.delete(key));
  let shown = false;
  const load = async () => {
    try {
      const out = await paneRun(panel.webview, `Reading ${short}…`, ["data", "-json", file, name]);
      panel.webview.postMessage({ kind: "data", file, data: JSON.parse(out) });
      shown = true;
    } catch (e) {
      if (e.cancelled) {
        if (!shown) {
          panel.dispose();
        } else {
          panel.webview.postMessage({ kind: "cancelled" });
        }
        return;
      }
      panel.webview.postMessage({ kind: "data", file, name, error: `hexc could not read ${name}: ${e.message}` });
    }
  };
  panel.webview.onDidReceiveMessage(async (m) => {
    switch (m && m.command) {
      case "inspect":
        if (typeof m.name === "string" && m.name) {
          await inspectSymbol(file, m.name);
        }
        break;
      case "copy":
        await vscode.env.clipboard.writeText(m.text || "");
        vscode.window.setStatusBarMessage("Copied the bytes", 2000);
        break;
      case "refresh":
        await load();
        break;
    }
  }, undefined, context.subscriptions);
  await load();
}

/** The listing as a text document (bloaty's labels, or by block). */
async function openDisassemblyText(file, name, style) {
  const uri = vscode.Uri.from(disasm.disasmUri(file, name, style));
  const doc = await vscode.workspace.openTextDocument(uri);
  if (doc.languageId !== "hexc-disasm") {
    await vscode.languages.setTextDocumentLanguage(doc, "hexc-disasm");
  }
  await vscode.window.showTextDocument(doc, { viewColumn: vscode.ViewColumn.Beside, preview: true });
}

/** The extension's context, once activated. */
let extension = null;

/** Open disassembly views, by file and function. */
const disasmPanels = new Map();

function disasmHtml(webview, context, title) {
  const media = (name) => webview.asWebviewUri(vscode.Uri.file(path.join(context.extensionPath, "media", name)));
  const nonce = crypto.randomBytes(16).toString("base64");
  const esc = (s) => s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${webview.cspSource}; script-src 'nonce-${nonce}';">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="stylesheet" href="${media("disasm-view.css")}">
<link rel="stylesheet" href="${media("loading.css")}">
<title>${esc(title)}</title>
</head>
<body>
<header id="header"></header>
<div id="toolbar"></div>
<div id="body"></div>
<script nonce="${nonce}" src="${media("loading.js")}"></script>
<script nonce="${nonce}" src="${media("graph.js")}"></script>
<script nonce="${nonce}" src="${media("disasm.js")}"></script>
<script nonce="${nonce}" src="${media("disasm-view.js")}"></script>
</body>
</html>`;
}

/** The text of each of `files` that is on this machine (by line), else null. */
async function readSources(files) {
  return Promise.all(
    (files || []).map(async (f) => {
      try {
        const stat = await fs.promises.stat(f);
        if (!stat.isFile() || stat.size > 8 << 20) {
          return { path: f, lines: null };
        }
        return { path: f, lines: (await fs.promises.readFile(f, "utf8")).split(/\r?\n/) };
      } catch {
        return { path: f, lines: null };
      }
    })
  );
}

/** Shows the code of function `name` of the binary at `file`. */
async function openDisassembly(file, name) {
  const context = extension;
  const key = `${file}\u0000${name}`;
  const existing = disasmPanels.get(key);
  if (existing) {
    existing.reveal(undefined, true);
    return;
  }
  const short = name.length > 40 ? name.slice(0, 39) + "…" : name;
  const panel = vscode.window.createWebviewPanel("hexcDisasm", `⟨/⟩ ${short}`, { viewColumn: vscode.ViewColumn.Beside, preserveFocus: false }, {
    enableScripts: true,
    retainContextWhenHidden: true,
    localResourceRoots: [vscode.Uri.file(path.join(context.extensionPath, "media"))],
  });
  panel.iconPath = vscode.Uri.file(path.join(context.extensionPath, "media", "icon.svg"));
  panel.webview.html = disasmHtml(panel.webview, context, name);
  disasmPanels.set(key, panel);
  panel.onDidDispose(() => disasmPanels.delete(key));
  const mode = () => context.globalState.get("hexcavator.disasmMode") || vscode.workspace.getConfiguration("hexcavator").get("disassemblyView") || "blocks";
  let shown = false;
  const load = async () => {
    try {
      const out = await paneRun(panel.webview, `Disassembling ${short}…`, ["size", "-disassemble", name, "-json", file]);
      const listing = JSON.parse(out);
      const sources = await readSources(listing.files);
      panel.webview.postMessage({ kind: "disasm", file, listing, sources, mode: mode() });
      shown = true;
    } catch (e) {
      if (e.cancelled) {
        if (!shown) {
          panel.dispose();
        } else {
          panel.webview.postMessage({ kind: "cancelled" });
        }
        return;
      }
      panel.webview.postMessage({ kind: "disasm", file, name, error: `hexc could not disassemble ${name}: ${e.message}` });
    }
  };
  panel.webview.onDidReceiveMessage(async (m) => {
    switch (m && m.command) {
      case "disassemble":
        if (typeof m.name === "string" && m.name) {
          await openDisassembly(file, m.name);
        }
        break;
      case "openSource":
        if (typeof m.file === "string") {
          try {
            const local = sidebarModule.findSource(m.file, file) || m.file;
            const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(local));
            const line = Math.max(0, (m.line || 1) - 1);
            await vscode.window.showTextDocument(doc, { viewColumn: vscode.ViewColumn.One, selection: new vscode.Range(line, 0, line, 0) });
          } catch {
            vscode.window.showWarningMessage(`${m.file} is not on this machine.`);
          }
        }
        break;
      case "openText":
        await openDisassemblyText(file, name, m.mode === "blocks" || m.mode === "graph" ? "blocks" : "raw");
        break;
      case "copy":
        await vscode.env.clipboard.writeText(m.text || "");
        vscode.window.setStatusBarMessage("Copied the listing", 2000);
        break;
      case "mode":
        context.globalState.update("hexcavator.disasmMode", m.mode);
        break;
      case "refresh":
        await load();
        break;
    }
  }, undefined, context.subscriptions);
  await load();
}

/** "Open With… → Hexcavator Size": the report as the binary's editor. */
class SizeEditor {
  constructor(context) {
    this.context = context;
  }

  openCustomDocument(uri) {
    return { uri, dispose() {} };
  }

  resolveCustomEditor(document, panel) {
    panel.webview.options = { enableScripts: true, localResourceRoots: [vscode.Uri.file(path.join(this.context.extensionPath, "media"))] };
    panel.webview.html = pageHtml(panel.webview, this.context, `Size: ${path.basename(document.uri.fsPath)}`);
    const view = attach(this.context, panel.webview, null, document.uri.fsPath, null);
    panel.onDidChangeViewState((e) => showStatus(e.webviewPanel.active ? view.state.report : null));
    panel.onDidDispose(() => showStatus(null));
    view.load(false);
  }
}

/** A page's HTML (the Types and Layout pages): header, toolbar, main. */
function plainHtml(webview, context, title, script) {
  const media = (name) => webview.asWebviewUri(vscode.Uri.file(path.join(context.extensionPath, "media", name)));
  const nonce = crypto.randomBytes(16).toString("base64");
  const esc = (s) => s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${webview.cspSource}; script-src 'nonce-${nonce}';">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="stylesheet" href="${media("view.css")}">
<link rel="stylesheet" href="${media("loading.css")}">
<title>${esc(title)}</title>
</head>
<body class="treemode">
<header id="header"></header>
<div id="toolbar"></div>
<div id="main"></div>
<script nonce="${nonce}" src="${media("loading.js")}"></script>
<script nonce="${nonce}" src="${media(script)}"></script>
</body>
</html>`;
}

/** A webview panel for a page of ours. */
function panelFor(context, viewType, title, script) {
  const panel = vscode.window.createWebviewPanel(viewType, title, vscode.ViewColumn.Active, {
    enableScripts: true,
    retainContextWhenHidden: true,
    localResourceRoots: [vscode.Uri.file(path.join(context.extensionPath, "media"))],
  });
  panel.iconPath = vscode.Uri.file(path.join(context.extensionPath, "media", "icon.svg"));
  panel.webview.html = plainHtml(panel.webview, context, title, script);
  return panel;
}

/** Open Types pages, by file. */
const typesPanels = new Map();

/**
 * Opens (or shows) the Types page of the binary at `file`. The page asks
 * for the rows in view (a page at a time, filtered and sorted by hexc,
 * which keeps the types in memory).
 */
function openTypes(context, file) {
  const existing = typesPanels.get(file);
  if (existing) {
    existing.reveal();
    return;
  }
  const name = path.basename(file);
  const panel = panelFor(context, "hexcTypes", `Types: ${name}`, "types-view.js");
  typesPanels.set(file, panel);
  panel.onDidDispose(() => typesPanels.delete(file));
  // (The spinner while a page is being read: the first, from the debug
  // information, can take a while.)
  let reading = 0;
  const page = async (m) => {
    const args = ["types", "-json", "-n", String(m.n || 200), "-from", String(m.from || 0), "-sort", String(m.sort || "name")];
    if (m.desc) {
      args.push("-desc");
    }
    if (typeof m.filter === "string" && m.filter) {
      args.push("-filter", m.filter);
      if (m.regex) {
        args.push("-regex");
      }
    }
    args.push(file);
    const slow = setTimeout(() => panel.webview.postMessage({ kind: "loading", text: `Reading ${name}'s types…`, cancellable: false }), 300);
    reading++;
    try {
      const out = await runHexc(args);
      panel.webview.postMessage(Object.assign({ kind: "page", generation: m.generation }, JSON.parse(out)));
    } catch (e) {
      panel.webview.postMessage({ kind: "failed", generation: m.generation, message: e.message });
    } finally {
      clearTimeout(slow);
      if (--reading === 0) {
        panel.webview.postMessage({ kind: "idle" });
      }
    }
  };
  panel.webview.onDidReceiveMessage(async (m) => {
    switch (m && m.command) {
      case "refresh":
        panel.webview.postMessage({ kind: "types", file });
        break;
      case "page":
        await page(m);
        break;
      case "layout":
        if (typeof m.name === "string" && m.name) {
          openLayout(context, file, m.name);
        }
        break;
    }
  }, undefined, context.subscriptions);
  panel.webview.postMessage({ kind: "types", file });
}

/** Opens a type's layout (as a tree whose bases and members open). */
function openLayout(context, file, typeName) {
  const panel = panelFor(context, "hexcLayout", `Layout: ${typeName}`, "layout-view.js");
  const load = async () => {
    try {
      const out = await paneRun(panel.webview, `Reading ${typeName}…`, ["types", "-layout", typeName, "-json", file]);
      panel.webview.postMessage({ kind: "layout", file, layout: JSON.parse(out) });
    } catch (e) {
      if (!e.cancelled) {
        vscode.window.showErrorMessage(`hexc: ${e.message}`);
      }
      panel.webview.postMessage({ kind: "failed", message: e.message });
    }
  };
  panel.webview.onDidReceiveMessage(async (m) => {
    if (m && m.command === "expand" && Number.isSafeInteger(m.ty)) {
      try {
        const out = await runHexc(["types", "-ty", String(m.ty), "-json", file]);
        panel.webview.postMessage({ kind: "inner", ty: m.ty, layout: JSON.parse(out) });
      } catch (e) {
        panel.webview.postMessage({ kind: "inner", ty: m.ty, layout: { parts: [] }, message: e.message });
      }
    }
  }, undefined, context.subscriptions);
  load();
}

/** Open Build Information pages, by file. */
const buildPanels = new Map();

/**
 * Opens (or shows) the Build Information page of the binary at `file`:
 * its security options, the build options its objects differ in, and each
 * object's command line (hexc checksec -audit -json).
 */
function openBuildInfo(context, file) {
  const existing = buildPanels.get(file);
  if (existing) {
    existing.reveal();
    return;
  }
  const name = path.basename(file);
  const panel = panelFor(context, "hexcBuildInfo", `Build Information: ${name}`, "buildinfo-view.js");
  buildPanels.set(file, panel);
  panel.onDidDispose(() => buildPanels.delete(file));
  const load = async () => {
    try {
      // How it was built, and its signatures (verified by hexc), at once.
      const signature = runHexc(["signature", "-json", file]).then(
        (out) => JSON.parse(out),
        (e) => {
          // (Unsigned or not verified: hexc says so in its output, and
          // exits 1.)
          if (e.stdout) {
            try {
              return JSON.parse(e.stdout);
            } catch {}
          }
          return { error: e.message };
        }
      );
      const out = await paneRun(panel.webview, `Reading how ${name} was built…`, ["checksec", "-audit", "-json", file]);
      panel.webview.postMessage({ kind: "build", file, report: JSON.parse(out), signature: await signature });
    } catch (e) {
      if (!e.cancelled) {
        vscode.window.showErrorMessage(`hexc: ${e.message}`);
      }
      panel.webview.postMessage({ kind: "failed", message: e.message });
    }
  };
  panel.webview.onDidReceiveMessage(async (m) => {
    switch (m && m.command) {
      case "refresh":
        await load();
        break;
      case "copy":
        if (typeof m.text === "string") {
          await vscode.env.clipboard.writeText(m.text);
          vscode.window.setStatusBarMessage(m.what ? `Copied ${m.what}` : "Copied", 2000);
        }
        break;
      case "open":
        // (A source file, where it is on this machine.)
        if (typeof m.path === "string" && fs.existsSync(m.path)) {
          vscode.window.showTextDocument(vscode.Uri.file(m.path), { preview: true });
        } else {
          vscode.window.showInformationMessage(`${m.path} is not on this machine`);
        }
        break;
    }
  }, undefined, context.subscriptions);
  load();
}

/** A type's layout. */
function typeLayout(file, name) {
  return openLayout(extension, file, name);
}

/** Opens where a type is defined (hexc types -definition), at its line. */
async function typeDefinition(file, name) {
  let where = null;
  try {
    const r = JSON.parse(await runHexc(["types", "-definition", name, "-json", file]));
    where = r && r.file ? { file: r.file, line: r.line || 1 } : null;
  } catch {
    // (Not recorded: said so below.)
  }
  await sidebarModule.openDefinition(where, name, file);
}

/** What refers to a type, as tables. */
function typeReferences(file, name) {
  return openTable(`References: ${name} (${path.basename(file)})`, ["types", "-refs", name, file], { file });
}

function activate(context) {
  extension = context;
  status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  channel = vscode.window.createOutputChannel("Hexcavator");
  busy = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 99);
  busy.command = "hexcavator.showLog";
  context.subscriptions.push(
    status,
    channel,
    busy,
    vscode.commands.registerCommand("hexcavator.showLog", () => channel.show(true)),
    vscode.commands.registerCommand("hexcavator.restartServer", () => {
      if (server) {
        server.kill();
      }
      vscode.window.setStatusBarMessage("hexc restarted", 2000);
    }),
    vscode.workspace.registerTextDocumentContentProvider(disasm.SCHEME, new DisassemblyProvider()),
    vscode.window.registerCustomEditorProvider("hexcavator.sizeEditor", new SizeEditor(context), {
      webviewOptions: { retainContextWhenHidden: true },
      supportsMultipleEditorsPerDocument: true,
    })
  );
  // The report's rows' context menu (VS Code passes the row's
  // data-vscode-context).
  const row = (fn) => (ctx) => ctx && typeof ctx.file === "string" && typeof ctx.name === "string" && fn(ctx);
  const symbolNode = (ctx) => ({ type: "symbol", entry: { file: ctx.file, base: null }, name: ctx.name });
  context.subscriptions.push(
    vscode.commands.registerCommand("hexcavator.row.disassemble", row((ctx) => openDisassembly(ctx.file, ctx.name))),
    // A function of both builds: its code in each, side by side (VS Code's
    // diff editor), without their addresses.
    vscode.commands.registerCommand(
      "hexcavator.row.disassemblyDiff",
      row((ctx) => {
        if (typeof ctx.base !== "string") {
          return;
        }
        const side = (file) => vscode.Uri.from(disasm.disasmUri(file, ctx.name, "diff"));
        return vscode.commands.executeCommand(
          "vscode.diff",
          side(ctx.base),
          side(ctx.file),
          `${ctx.name}: ${path.basename(ctx.base)} \u2194 ${path.basename(ctx.file)}`,
          { preview: false }
        );
      })
    ),
    vscode.commands.registerCommand("hexcavator.row.viewData", row((ctx) => openData(ctx.file, ctx.name))),
    // (Why it is there, and what refers to it and what it refers to: a
    // page each.)
    vscode.commands.registerCommand("hexcavator.row.why", row((ctx) => openTable(`Why is ${ctx.name} here?`, ["xref", "-why", ctx.name, ctx.file], { file: ctx.file }))),
    vscode.commands.registerCommand("hexcavator.row.refs", row((ctx) => openTable(`References: ${ctx.name}`, ["xref", "-refs", ctx.name, ctx.file], { file: ctx.file }))),
    vscode.commands.registerCommand("hexcavator.type.layout", row((ctx) => typeLayout(ctx.file, ctx.name))),
    vscode.commands.registerCommand("hexcavator.type.refs", row((ctx) => typeReferences(ctx.file, ctx.name))),
    vscode.commands.registerCommand("hexcavator.type.definition", row((ctx) => typeDefinition(ctx.file, ctx.name))),
    vscode.commands.registerCommand("hexcavator.row.goToSource", row((ctx) => vscode.commands.executeCommand("hexcavator.symbol.goToSource", symbolNode(ctx)))),
    vscode.commands.registerCommand("hexcavator.row.copyName", row(async (ctx) => {
      await vscode.env.clipboard.writeText(ctx.name);
      vscode.window.setStatusBarMessage("Copied the name", 2000);
    }))
  );
  sidebar = sidebarModule.register(context, {
    runHexc,
    pickBinary,
    openReport: (file, base, at) => openReport(context, file, base, at),
    openSources: (file) => openReport(context, file, undefined, undefined, "sources"),
    findings: (file) => findings(context, vscode.Uri.file(file)),
    openTypes: (file) => openTypes(context, file),
    openBuildInfo: (file) => openBuildInfo(context, file),
    openDisassembly,
    openData,
    openTable,
    inspect: (file, name) => inspectSymbol(file, name),
  });
}

function deactivate() {
  if (server) {
    server.stop();
    server = null;
  }
}

module.exports = { activate, deactivate, sizeArgs, runHexc, EXTENSIONS };
