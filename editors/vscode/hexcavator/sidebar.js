// The Hexcavator sidebar: the binaries and diffs opened. A binary's items
// say what it is (Headers, File Format, Build Information, Debug
// Information) and open its contents (the Symbols, Types, and Sources
// pages); Compare adds a diff; the other queries (each with its hexc
// command line, Findings among them) are under Miscellaneous Queries; and
// the answers asked for (why a symbol is there, what refers to it) follow.
"use strict";

const vscode = require("vscode");
const path = require("path");
const fs = require("fs");
const h = require("./lib/hexc.js");
const disasm = require("./media/disasm.js");

const STORE = "hexcavator.entries";
const MAX_ENTRIES = 20;
const OUT_SCHEME = "hexc-out";

const keyOf = (entry) => `${entry.file}\u0000${entry.base || ""}`;

/** hexc's output as a read-only document (`hexc-out:` URIs). */
class OutputProvider {
  constructor(runHexc) {
    this.runHexc = runHexc;
    this.changed = new vscode.EventEmitter();
    this.onDidChange = this.changed.event;
  }

  static uri(title, args) {
    const safe = title.replace(/[\\/:*?"<>|]+/g, "_").slice(0, 120);
    return vscode.Uri.from({ scheme: OUT_SCHEME, path: `/${safe}`, query: new URLSearchParams({ args: JSON.stringify(args) }).toString() });
  }

  static argsOf(uri) {
    try {
      return JSON.parse(new URLSearchParams(uri.query).get("args"));
    } catch {
      return null;
    }
  }

  async provideTextDocumentContent(uri, cancel) {
    const args = OutputProvider.argsOf(uri);
    if (!args) {
      return "(no command)";
    }
    const exe = h.hexcPath(vscode.workspace.getConfiguration("hexcavator").get("path"));
    const header = `$ ${h.commandLine(exe, args)}\n\n`;
    try {
      return header + (await this.runHexc(args, cancel));
    } catch (e) {
      return header + `(failed: ${e.message})\n`;
    }
  }

  refresh(uri) {
    this.changed.fire(uri);
  }
}

class Sidebar {
  /**
   * `deps`: runHexc(args, cancel), openReport(file, base), findings(file),
   * openDisassembly(file, name).
   */
  constructor(context, deps) {
    this.context = context;
    this.deps = deps;
    this.changed = new vscode.EventEmitter();
    this.onDidChangeTreeData = this.changed.event;
    this.entries = (context.workspaceState.get(STORE) || []).filter((e) => e && typeof e.file === "string");
    this.cache = new Map();
    this.watchers = new Map();
    this.entries.forEach((e) => this.watch(e));
  }

  // ------------------------------------------------------------ entries

  save() {
    this.context.workspaceState.update(
      STORE,
      this.entries.map((e) => ({ file: e.file, base: e.base || null }))
    );
  }

  add(file, base) {
    const entry = { file, base: base || null };
    const key = keyOf(entry);
    const existing = this.entries.find((e) => keyOf(e) === key);
    if (!existing) {
      // (In the order opened: an entry keeps its place, so that the list
      // doesn't move under the pointer; past the most kept, the oldest go.)
      this.entries.push(entry);
      this.watch(entry);
      for (const old of this.entries.splice(0, Math.max(0, this.entries.length - MAX_ENTRIES))) {
        this.unwatch(old);
      }
    }
    this.save();
    this.changed.fire();
    return existing || entry;
  }

  remove(entry) {
    this.entries = this.entries.filter((e) => keyOf(e) !== keyOf(entry));
    this.cache.delete(keyOf(entry));
    this.unwatch(entry);
    this.save();
    this.changed.fire();
  }

  clear() {
    this.entries.forEach((e) => this.unwatch(e));
    this.entries = [];
    this.cache.clear();
    this.save();
    this.changed.fire();
  }

  /** Forgets what was read of an entry (or all), and reads it again. */
  refresh(entry) {
    if (entry) {
      const c = this.cache.get(keyOf(entry));
      this.cache.set(keyOf(entry), { results: c ? c.results : [] });
    } else {
      for (const [k, c] of this.cache) {
        this.cache.set(k, { results: c.results });
      }
    }
    this.changed.fire();
  }

  /** A rebuilt binary invalidates what was read of it. */
  watch(entry) {
    const key = keyOf(entry);
    if (this.watchers.has(key)) {
      return;
    }
    const subs = [];
    for (const file of [entry.file, entry.base].filter(Boolean)) {
      const w = vscode.workspace.createFileSystemWatcher(new vscode.RelativePattern(vscode.Uri.file(path.dirname(file)), path.basename(file)));
      const again = () => this.refresh(this.entries.find((e) => keyOf(e) === key));
      w.onDidChange(again);
      w.onDidCreate(again);
      subs.push(w);
    }
    this.watchers.set(key, subs);
  }

  unwatch(entry) {
    for (const w of this.watchers.get(keyOf(entry)) || []) {
      w.dispose();
    }
    this.watchers.delete(keyOf(entry));
  }

  dispose() {
    for (const subs of this.watchers.values()) {
      subs.forEach((w) => w.dispose());
    }
  }

  state(entry) {
    const key = keyOf(entry);
    let c = this.cache.get(key);
    if (!c) {
      c = { results: [] };
      this.cache.set(key, c);
    }
    return c;
  }

  /** `what` of an entry, run once (and kept) until it is refreshed. */
  once(entry, what, args, parse) {
    const c = this.state(entry);
    if (!c[what]) {
      c[what] = this.deps.runHexc(args).then((out) => (parse ? parse(out) : out));
      // What it gave, for tree items to show; and a failure is kept too,
      // and shown, until a refresh.
      c[what].then((v) => {
        if (this.cache.get(keyOf(entry)) === c) {
          c.values = c.values || {};
          c.values[what] = v;
          if (what === "report" || what === "recs" || what === "fdiff") {
            // (The node's description shows it.)
            this.changed.fire();
          }
        }
      }, () => {});
    }
    return c[what];
  }

  /**
   * What hexc says `file` (the entry's, or its base's) supports: its
   * format, debug information, and tools (`hexc info -json`); what its
   * name suggests if hexc can't say.
   */
  caps(entry, which = "file") {
    const file = which === "base" ? entry.base : entry.file;
    return this.once(entry, which + "Caps", ["info", "-json", file], (out) => parseCaps(out, file)).catch(() => h.capsFallback(file));
  }

  /** `caps`, if it has finished (else what the file's name suggests). */
  capsNow(entry, which = "file") {
    const file = which === "base" ? entry.base : entry.file;
    return this.value(entry, which + "Caps") || h.capsFallback(file);
  }

  /** The functions of a diff's builds compared (`hexc xref -- base`). */
  functionsDiff(entry) {
    return this.once(entry, "fdiff", ["xref", "-json", "-n", "500", entry.file, "--", entry.base], JSON.parse);
  }

  /** What `once` gave for `what`, if it has finished. */
  value(entry, what) {
    const c = this.cache.get(keyOf(entry));
    return c && c.values ? c.values[what] : undefined;
  }

  report(entry) {
    const config = vscode.workspace.getConfiguration("hexcavator");
    const sources = config.get("treeSources") || config.get("sources") || ["sections", "compileunits", "symbols"];
    const rows = config.get("rows");
    const args = ["size", "-d", sources.join(","), "-n", String(rows ?? 100), "-json", entry.file];
    if (entry.base) {
      args.push("--", entry.base);
    }
    return this.once(entry, "report", args, JSON.parse);
  }

  symbols(entry, functionsOnly) {
    return this.once(entry, functionsOnly ? "functions" : "symbols", h.symbolsArgs(entry.file, functionsOnly), (out) => JSON.parse(out).rows || []);
  }

  /** The source file and line of the symbol `name`, if the debug information has them. */
  /** Where function `name` is defined (hexc size -definition): its file and line, or null. */
  async sourceOf(entry, name) {
    try {
      return await this.once(entry, "source:" + name, ["size", "-definition", name, "-json", entry.file], (out) => {
        const r = JSON.parse(out);
        return r && r.file ? { file: r.file, line: r.line || 1 } : null;
      });
    } catch {
      return null;
    }
  }

  addResult(entry, result) {
    const c = this.state(entry);
    c.results = [result, ...c.results.filter((r) => !(r.kind === result.kind && r.name === result.name))];
    this.changed.fire();
    return result;
  }

  removeResult(entry, result) {
    const c = this.state(entry);
    c.results = c.results.filter((r) => r !== result);
    this.changed.fire();
  }

  // --------------------------------------------------------------- tree

  getChildren(node) {
    if (!node) {
      return this.entries.map((entry) => ({ type: "entry", entry }));
    }
    const entry = node.entry;
    switch (node.type) {
      case "entry":
        return Promise.all([this.caps(entry), entry.base ? this.caps(entry, "base") : null]).then(([caps, baseCaps]) => {
          const kids = [];
          if (entry.base) {
            // A diff: its Symbols page (the change: what was added,
            // removed, grew, or shrank; each function's code compared), and
            // its Types (their layouts compared). (The rest, by section, by
            // function, and of the findings, the page shows.)
            kids.push({ type: "tool", entry, tool: { id: "symbols", label: "Symbols", icon: "symbol-method", detail: "every symbol's change in size: added, removed, grew, shrank; grouped, filtered, as a tree or a map", run: "panel" } });
            const types = h.toolsFor(entry, caps, baseCaps)
              .flatMap((g) => g.tools)
              .find((t) => t.id === "typesDiff");
            if (types) {
              kids.push({ type: "tool", entry, tool: Object.assign({}, types, { label: "Types" }) });
            }
          } else {
            const { items, misc } = h.sidebarFor(entry, caps);
            for (const tool of items) {
              kids.push({ type: "tool", entry, tool });
            }
            if (misc.length) {
              kids.push({ type: "group", entry, group: { label: "Miscellaneous Queries", icon: "search", tools: misc, collapsed: true } });
            }
          }
          for (const result of this.state(entry).results) {
            kids.push({ type: "result", entry, result });
          }
          return kids;
        });
      case "group":
        // (Recommendations: a tree of their own.)
        return node.group.tools.map((tool) => (tool.id === "recommend" ? { type: "recs", entry } : { type: "tool", entry, tool }));
      case "size":
        return this.report(entry).then(
          (r) => this.rowsOf(entry, r, r.total, []),
          (e) => [failure(e)]
        );
      case "row":
        return this.rowsOf(entry, node.report, node.row, node.path);
      case "recs":
        return this.once(entry, "recs", ["recommend", "-json", entry.file], JSON.parse).then(
          (r) => {
            const kids = (r.recommendations || []).map((rec) => ({ type: "rec", entry, rec }));
            const link = r.link || {};
            kids.push({
              type: "info",
              label: "Linked with",
              description: `/OPT:REF ${link.optRef ? "on" : "off"}, /OPT:ICF ${link.optIcf ? "on" : "off"}`,
              icon: "link",
            });
            if (!(r.recommendations || []).length) {
              kids.unshift({ type: "info", label: "Nothing to recommend", description: "", icon: "check" });
            }
            return kids;
          },
          (e) => [failure(e)]
        );
      case "rec":
        return (node.rec.examples || []).map((ex) => ({ type: "symbol", entry, name: ex.name, description: h.formatSize(ex.size), icon: "symbol-misc" }));
      case "result":
        return this.resultChildren(entry, node.result);
      case "fdiff":
        return this.functionsDiff(entry).then(
          (d) =>
            h.functionGroups(d).map((g) => ({ type: "fgroup", entry, group: g })),
          (e) => [failure(e)]
        );
      case "fgroup":
        return node.group.items.map((it) => ({
          type: "symbol",
          // What is in the new build is the new image's; what was removed, the base's.
          entry: { file: it.removed ? entry.base : entry.file, base: null },
          name: it.name,
          label: it.label,
          description: it.description,
          icon: it.icon,
          color: it.color,
          tooltip: it.tooltip,
        })).concat(node.group.more ? [{ type: "info", label: `${node.group.more} more`, description: "", icon: "ellipsis" }] : []);
      case "refGroup":
        return node.list.map((r) => ({ type: "ref", entry, name: r.name, edge: r.edge }));
      case "ref":
        return this.refsOf(entry, node.name);
      default:
        return [];
    }
  }

  rowsOf(entry, report, row, at) {
    const symbolLevel = disasm.isSymbolLevel(report.sources, at.length);
    return h.sortedRows(row, "file").map((child) => ({
      type: "row",
      entry,
      report,
      row: child,
      parent: row,
      path: [...at, child.name],
      symbol: symbolLevel && disasm.isSymbolName(child.name) && !child.children,
    }));
  }

  resultChildren(entry, result) {
    if (result.kind === "why") {
      return this.once(entry, "why:" + result.name, ["xref", "-why", result.name, "-json", entry.file], JSON.parse).then(
        (why) =>
          h.whyRows(why).map((r) => (r.name ? { type: "symbol", entry, name: r.name, label: r.label, description: r.description, icon: r.icon } : { type: "info", ...r })),
        (e) => [failure(e)]
      );
    }
    return this.refsOf(entry, result.name);
  }

  refsOf(entry, name) {
    return this.once(entry, "refs:" + name, ["xref", "-refs", name, "-json", entry.file], JSON.parse).then(
      (r) => {
        const groups = [];
        const head = { type: "info", label: r.reached ? "Reached from a root" : "Nothing reaches it", description: `${h.formatSize(r.size)}${r.code ? " of code" : ""}`, icon: r.reached ? "pass" : "circle-slash" };
        groups.push(head);
        if ((r.referrers || []).length) {
          groups.push({ type: "refGroup", entry, label: "Referred to by", list: r.referrers, icon: "arrow-left" });
        }
        if ((r.references || []).length) {
          groups.push({ type: "refGroup", entry, label: "Refers to", list: r.references, icon: "arrow-right" });
        }
        return groups;
      },
      (e) => [failure(e)]
    );
  }

  getTreeItem(node) {
    const C = vscode.TreeItemCollapsibleState;
    const icon = (id, color) => new vscode.ThemeIcon(id, color ? new vscode.ThemeColor(color) : undefined);
    switch (node.type) {
      case "entry": {
        const e = node.entry;
        const item = new vscode.TreeItem(e.base ? `${h.baseName(e.file)} ⇄ ${h.baseName(e.base)}` : h.baseName(e.file), C.Expanded);
        item.id = "entry:" + keyOf(e);
        item.description = path.dirname(e.file);
        item.tooltip = e.base ? `${e.file}\ncompared with\n${e.base}` : e.file;
        item.iconPath = icon(e.base ? "diff" : "file-binary");
        item.contextValue = e.base ? "hexc.diff" : "hexc.binary";
        item.resourceUri = undefined;
        return item;
      }
      case "size": {
        const item = new vscode.TreeItem(node.entry.base ? "Size Change" : "Size", C.Collapsed);
        item.id = "size:" + keyOf(node.entry);
        item.iconPath = icon("graph");
        item.contextValue = "hexc.size";
        item.tooltip = "Where the bytes go, rolled up at every level (file sizes). The levels are hexcavator.treeSources (or hexcavator.sources).";
        // The totals, once read (reading starts when it is expanded).
        const r = this.value(node.entry, "report");
        if (r) {
          const t = r.total;
          const sign = (n) => (r.diff && n > 0 ? "+" : "");
          item.description = `${sign(t.file)}${h.formatSize(t.file)} file · ${sign(t.vm)}${h.formatSize(t.vm)} memory`;
        }
        return item;
      }
      case "row": {
        const d = h.describeRow(node.row, node.parent, node.report.total, node.report.diff, "file");
        const item = new vscode.TreeItem(d.label, node.row.children ? C.Collapsed : C.None);
        item.id = "row:" + keyOf(node.entry) + "\u0000" + node.path.join("\u0000");
        item.description = d.description;
        item.tooltip = d.tooltip;
        const v = node.row.file || 0;
        if (node.report.diff) {
          item.iconPath = icon(v > 0 ? "arrow-up" : v < 0 ? "arrow-down" : "dash", v > 0 ? "charts.red" : v < 0 ? "charts.green" : undefined);
        } else {
          item.iconPath = icon(node.symbol ? "symbol-method" : node.row.other_count ? "ellipsis" : levelIcon(node.report.sources[node.path.length - 1]));
        }
        // (Symbols of an image with debug information: why, references, data.)
        const full = !node.entry.base && h.can(this.capsNow(node.entry), "why");
        item.contextValue = node.symbol ? (full ? "hexc.row.symbol.pe" : "hexc.row.symbol") : "hexc.row";
        return item;
      }
      case "recs": {
        const item = new vscode.TreeItem("Recommendations", C.Collapsed);
        item.id = "recs:" + keyOf(node.entry);
        item.iconPath = icon("lightbulb", "charts.yellow");
        item.tooltip = "Build changes that would make it smaller, each measured (hexc recommend)";
        const r = this.value(node.entry, "recs");
        if (r) {
          item.description = r.saving ? `save ${h.formatSize(r.saving)}` : "none";
        }
        return item;
      }
      case "rec": {
        const advice = node.rec.advice || "";
        const short = advice.split(":")[0];
        const item = new vscode.TreeItem(short, (node.rec.examples || []).length ? C.Collapsed : C.None);
        item.description = `save ${h.formatSize(node.rec.saving)}`;
        item.tooltip = new vscode.MarkdownString().appendText(advice).appendMarkdown(`\n\n**Saves ${h.formatSize(node.rec.saving)}** (${h.formatBytes(node.rec.saving)} bytes)`);
        item.iconPath = icon("lightbulb");
        return item;
      }
      case "result": {
        const r = node.result;
        const item = new vscode.TreeItem(r.name, C.Expanded);
        item.id = `result:${keyOf(node.entry)}\u0000${r.kind}\u0000${r.name}`;
        item.description = r.kind === "why" ? "why is it here?" : "references";
        item.iconPath = icon(r.kind === "why" ? "debug-step-into" : "references", "charts.blue");
        item.contextValue = "hexc.result";
        item.tooltip = r.kind === "why" ? `The chain of references from a root to ${r.name}` : `What refers to ${r.name}, and what it refers to: expand each to follow it`;
        return item;
      }
      case "refGroup": {
        const item = new vscode.TreeItem(node.label, C.Expanded);
        item.description = String(node.list.length);
        item.iconPath = icon(node.icon);
        return item;
      }
      case "ref": {
        const item = new vscode.TreeItem(node.name, C.Collapsed);
        item.description = node.edge;
        item.iconPath = icon(node.edge.startsWith("call") ? "symbol-method" : node.edge.startsWith("owns") ? "symbol-namespace" : "symbol-variable");
        item.contextValue = "hexc.symbol.pe";
        item.tooltip = `${node.edge} ${node.name}`;
        return item;
      }
      case "symbol": {
        const item = new vscode.TreeItem(node.label || node.name, C.None);
        item.description = node.description;
        item.iconPath = icon(node.icon || "symbol-misc", node.color);
        item.contextValue = "hexc.symbol.pe";
        item.tooltip = node.tooltip || node.name;
        return item;
      }
      case "fdiff": {
        const item = new vscode.TreeItem("Functions", C.Collapsed);
        item.id = "fdiff:" + keyOf(node.entry);
        item.iconPath = icon("symbol-method");
        item.tooltip = "The functions of the two builds compared: by name the same or changed, then by fingerprint renamed (the same code under another name), and the rest added or removed (hexc xref -- base)";
        const d = this.value(node.entry, "fdiff");
        if (d) {
          item.description = h.functionsSummary(d);
        }
        return item;
      }
      case "fgroup": {
        const g = node.group;
        const item = new vscode.TreeItem(g.label, g.items.length ? C.Collapsed : C.None);
        item.id = `fgroup:${keyOf(node.entry)}\u0000${g.label}`;
        item.description = g.description;
        item.iconPath = icon(g.icon, g.color);
        return item;
      }
      case "group": {
        const item = new vscode.TreeItem(node.group.label, node.group.collapsed ? C.Collapsed : C.Expanded);
        item.id = `group:${keyOf(node.entry)}\u0000${node.group.label}`;
        item.iconPath = icon(node.group.icon);
        return item;
      }
      case "tool": {
        const t = node.tool;
        const item = new vscode.TreeItem(t.label, C.None);
        item.iconPath = icon(t.icon);
        item.command = { command: "hexcavator.runTool", title: t.label, arguments: [node] };
        item.contextValue = t.args || t.ask ? "hexc.tool.command" : "hexc.tool";
        const md = new vscode.MarkdownString();
        md.appendText(t.detail);
        const line = this.commandFor(node);
        if (line) {
          md.appendMarkdown("\n\n").appendCodeblock(line, "shell");
        }
        item.tooltip = md;
        return item;
      }
      case "info": {
        const item = new vscode.TreeItem(node.label, C.None);
        item.description = node.description;
        item.iconPath = icon(node.icon || "info", node.color);
        item.tooltip = node.tooltip || [node.label, node.description].filter(Boolean).join(": ");
        return item;
      }
      default:
        return new vscode.TreeItem("?");
    }
  }

  getParent() {
    return undefined;
  }

  /** The command line a tool runs (with what it asks for as `<…>`). */
  commandFor(node, answer) {
    const exe = h.hexcPath(vscode.workspace.getConfiguration("hexcavator").get("path"));
    const t = node.tool;
    const e = node.entry;
    const ask = answer ?? (t.ask ? `<${t.ask}>` : undefined);
    switch (t.id) {
      case "report":
      case "symbols":
        return h.commandLine(exe, ["size", "-d", "symbols", "-n", "0", e.file, ...(e.base ? ["--", e.base] : [])]);
      case "buildinfo":
        return h.commandLine(exe, ["checksec", "-audit", e.file]);
      case "sourcesPage":
        return h.commandLine(exe, ["size", "-d", "sourcefiles,symbols", "-n", "0", e.file]);
      case "typesPage":
        return h.commandLine(exe, ["types", "-json", "-n", "0", e.file]);
      case "sizeDiff":
        return h.commandLine(exe, ["size", "-d", "sections,compileunits,symbols", e.file, "--", e.base]);
      case "findings":
        return h.commandLine(exe, ["size", "-findings", e.file]);
      case "why":
        return h.commandLine(exe, ["xref", "-why", ask, e.file]);
      case "refs":
        return h.commandLine(exe, ["xref", "-refs", ask, e.file]);
      case "disassemble":
        return h.commandLine(exe, ["size", "-disassemble", ask, e.file]);
      default: {
        const args = t.ask ? h.argsWith(t, e, ask) : t.args;
        return args ? h.commandLine(exe, args) : null;
      }
    }
  }
}

function failure(e) {
  return { type: "info", label: "hexc failed", description: e.message.split("\n")[0], tooltip: e.message, icon: "error", color: "errorForeground" };
}

/** An icon for a report level's rows, by its data source. */
function levelIcon(source) {
  switch (source) {
    case "sections":
    case "segments":
    case "groups":
      return "symbol-namespace";
    case "compileunits":
    case "inputfiles":
    case "armembers":
      return "file-code";
    case "libraries":
      return "library";
    case "inlines":
      return "fold";
    default:
      return "symbol-field";
  }
}

// ----------------------------------------------------------------- asking

/**
 * Asks for a symbol (or a function, or a type) of `entry`, from a list
 * hexc gives, largest first; a name typed that is not listed is taken as
 * given.
 */
async function askName(sidebar, entry, what) {
  // (A list to pick from needs the symbols hexc's queries give.)
  const listed = h.can(await sidebar.caps(entry), "query");
  if (!listed || what === "query") {
    return vscode.window.showInputBox({
      title: what === "query" ? `Query the symbols of ${h.baseName(entry.file)}` : `Function in ${h.baseName(entry.file)}`,
      prompt:
        what === "query"
          ? "A filter, then group by / sort by / select / limit: kind=function file>4k sort by file desc limit 20"
          : "Its name as the symbol table or name section has it, or demangled",
      value: what === "query" ? sidebar.context.workspaceState.get("hexcavator.lastQuery") || "" : "",
      ignoreFocusOut: true,
    });
  }
  const qp = vscode.window.createQuickPick();
  qp.title =
    what === "type" ? `Type in ${h.baseName(entry.file)}` : what === "function" ? `Function in ${h.baseName(entry.file)}` : `Symbol in ${h.baseName(entry.file)}`;
  qp.placeholder = "Type to filter (largest first); Enter takes what is typed if nothing matches";
  qp.matchOnDescription = false;
  qp.matchOnDetail = true;
  qp.busy = true;
  qp.show();
  const load =
    what === "type"
      ? sidebar
          .once(entry, "types", ["types", "-json", "-n", "0", entry.file], (out) => JSON.parse(out).list || [])
          .then((list) =>
            list
              .slice()
              .sort((a, b) => b.size - a.size)
              .map((t) => ({ label: t.name, description: `${h.formatSize(t.size)}${t.waste ? ` · ${h.formatSize(t.waste)} padding` : ""}`, name: t.name }))
          )
      : sidebar.symbols(entry, what === "function").then((rows) =>
          rows.map((r) => ({
            label: r.name,
            description: `${h.formatSize(r.file)} ${r.kind}`,
            detail: r.source ? `${h.baseName(r.source)}:${r.line}` : r.compiland ? h.baseName(r.compiland) : undefined,
            name: r.name,
          }))
        );
  load.then(
    (items) => {
      qp.items = items;
      qp.busy = false;
    },
    (e) => {
      qp.busy = false;
      qp.placeholder = `hexc could not list them (${e.message.split("\n")[0]}): type a name`;
    }
  );
  return new Promise((resolve) => {
    let done = false;
    qp.onDidAccept(() => {
      const picked = qp.selectedItems[0];
      done = true;
      resolve(picked ? picked.name : qp.value.trim() || undefined);
      qp.hide();
    });
    qp.onDidHide(() => {
      if (!done) {
        resolve(undefined);
      }
      qp.dispose();
    });
  });
}

// --------------------------------------------------------------- commands

async function openOutput(provider, title, args) {
  const uri = OutputProvider.uri(title, args);
  const doc = await vscode.workspace.openTextDocument(uri);
  await vscode.window.showTextDocument(doc, { preview: false });
}

async function runTool(sidebar, provider, node) {
  const { tool, entry } = node;
  const pickBinary = sidebar.deps.pickBinary;
  switch (tool.run) {
    case "panel":
      if (tool.id === "findings") {
        return sidebar.deps.findings(entry.file);
      }
      return sidebar.deps.openReport(entry.file, entry.base);
    case "types":
      return sidebar.deps.openTypes(entry.file);
    case "buildinfo":
      return sidebar.deps.openBuildInfo(entry.file);
    case "sources":
      return sidebar.deps.openSources(entry.file);
    case "pick-base": {
      const base = await pickBinary(`Base build to compare ${h.baseName(entry.file)} with`);
      if (base) {
        sidebar.add(entry.file, base.fsPath);
      }
      return;
    }
    case "disassemble": {
      const name = await askName(sidebar, entry, "function");
      if (name) {
        await sidebar.deps.openDisassembly(entry.file, name);
      }
      return;
    }
    case "tree": {
      const name = await askName(sidebar, entry, "symbol");
      if (name) {
        sidebar.addResult(entry, { kind: tool.id, name });
      }
      return;
    }
    case "text": {
      // A query opens its table, its query to edit there.
      if (tool.id === "query" && sidebar.deps.openTable) {
        const last = sidebar.context.workspaceState.get("hexcavator.lastQuery") || "kind=function sort by file desc limit 200";
        return sidebar.deps.openTable(h.titleOf(tool, entry), ["query", entry.file, last], { file: entry.file, query: last });
      }
      let answer;
      if (tool.ask) {
        answer = await askName(sidebar, entry, tool.ask);
        if (!answer) {
          return;
        }
        if (tool.ask === "query") {
          sidebar.context.workspaceState.update("hexcavator.lastQuery", answer);
        }
      }
      const args = tool.ask ? h.argsWith(tool, entry, answer) : tool.args;
      if (h.isTable(tool) && sidebar.deps.openTable) {
        return sidebar.deps.openTable(h.titleOf(tool, entry, answer), args, { file: entry.file });
      }
      return openOutput(provider, h.titleOf(tool, entry, answer), args);
    }
  }
}

/** The binary a symbol node is of, and its name. */
function symbolOf(node) {
  if (!node) {
    return null;
  }
  if (node.type === "row") {
    return { entry: node.entry, name: node.row.name };
  }
  return node.name ? { entry: node.entry, name: node.name } : null;
}

/**
 * Lenses over the functions of a source file that the binaries opened in
 * the sidebar have code from (by their debug information's line tables): each one's size,
 * and links to its code and why it is there.
 */
class SizeLenses {
  constructor(sidebar) {
    this.sidebar = sidebar;
    this.changed = new vscode.EventEmitter();
    this.onDidChangeCodeLenses = this.changed.event;
    sidebar.onDidChangeTreeData(() => this.changed.fire());
  }

  async provideCodeLenses(doc) {
    if (!vscode.workspace.getConfiguration("hexcavator").get("codeLens", true) || doc.uri.scheme !== "file") {
      return [];
    }
    const here = h.samePath(doc.uri.fsPath);
    const lenses = [];
    for (const entry of this.sidebar.entries) {
      if (entry.base || !h.can(await this.sidebar.caps(entry), "lenses")) {
        continue;
      }
      let rows;
      try {
        rows = await this.sidebar.symbols(entry, true);
      } catch {
        continue;
      }
      const elsewhere = new Map();
      const isElsewhere = (src) => {
        if (!elsewhere.has(src)) {
          elsewhere.set(src, !fs.existsSync(src));
        }
        return elsewhere.get(src);
      };
      for (const [line, fns] of h.functionsByLine(rows, here, sourceMaps(), isElsewhere)) {
        const range = new vscode.Range(line - 1, 0, line - 1, 0);
        const total = fns.reduce((s, r) => s + r.file, 0);
        const where = h.baseName(entry.file);
        if (fns.length === 1) {
          const node = { type: "symbol", entry, name: fns[0].name };
          lenses.push(
            new vscode.CodeLens(range, { title: `${h.formatSize(total)} in ${where}`, tooltip: `${fns[0].name}: ${h.formatBytes(total)} bytes of code in ${entry.file}`, command: "hexcavator.symbol.disassemble", arguments: [node] }),
            new vscode.CodeLens(range, { title: "why is it here?", command: "hexcavator.symbol.why", arguments: [node] })
          );
        } else {
          lenses.push(
            new vscode.CodeLens(range, {
              title: `${fns.length} functions, ${h.formatSize(total)} in ${where}`,
              tooltip: fns.map((r) => `${r.name}: ${h.formatSize(r.file)}`).join("\n"),
              command: "hexcavator.pickFunction",
              arguments: [entry, fns],
            })
          );
        }
      }
    }
    return lenses;
  }
}

function register(context, deps) {
  const sidebar = new Sidebar(context, deps);
  const lenses = new SizeLenses(sidebar);
  const provider = new OutputProvider(deps.runHexc);
  // (For the table views' Open as Text.)
  sidebar.showOutput = (title, args) => openOutput(provider, title, args);
  const view = vscode.window.createTreeView("hexcavator.binaries", { treeDataProvider: sidebar, showCollapseAll: true });
  const reveal = (entry) => view.reveal({ type: "entry", entry }, { expand: true, focus: false }).then(undefined, () => {});
  const cmd = (id, fn) => vscode.commands.registerCommand(id, fn);
  /** Open Binary: the file given (from the Explorer), or one picked, in the pane. */
  const open = async (uri) => {
    const file = uri && uri.fsPath ? uri.fsPath : (await deps.pickBinary("Binary to open in Hexcavator"))?.fsPath;
    if (file) {
      reveal(sidebar.add(file, null));
      vscode.commands.executeCommand("hexcavator.binaries.focus");
    }
  };
  context.subscriptions.push(
    sidebar,
    view,
    vscode.workspace.registerTextDocumentContentProvider(OUT_SCHEME, provider),
    vscode.languages.registerCodeLensProvider({ scheme: "file" }, lenses),
    cmd("hexcavator.pickFunction", async (entry, fns) => {
      if (!entry || !Array.isArray(fns)) {
        return;
      }
      const picked = await vscode.window.showQuickPick(
        fns.map((r) => ({ label: r.name, description: h.formatSize(r.file), r })),
        { title: `Functions here in ${h.baseName(entry.file)}`, placeHolder: "Disassemble which?" }
      );
      if (picked) {
        deps.openDisassembly(entry.file, picked.r.name);
      }
    }),
    cmd("hexcavator.open", (uri) => open(uri)),
    // The Explorer's Open in Hexcavator: the same, on the file clicked.
    cmd("hexcavator.openInPane", (uri) => open(uri)),
    cmd("hexcavator.openDiff", async (uri) => {
      const file = uri && uri.fsPath ? uri.fsPath : (await deps.pickBinary("New build"))?.fsPath;
      if (!file) {
        return;
      }
      const base = await deps.pickBinary(`Base build to compare ${h.baseName(file)} with`);
      if (base) {
        reveal(sidebar.add(file, base.fsPath));
        vscode.commands.executeCommand("hexcavator.binaries.focus");
      }
    }),
    cmd("hexcavator.remove", (node) => node && sidebar.remove(node.entry)),
    cmd("hexcavator.clear", () => sidebar.clear()),
    cmd("hexcavator.refresh", (node) => sidebar.refresh(node && node.entry)),
    cmd("hexcavator.revealFile", (node) => node && vscode.commands.executeCommand("revealFileInOS", vscode.Uri.file(node.entry.file))),
    cmd("hexcavator.showReport", (node) => {
      if (!node) {
        return;
      }
      deps.openReport(node.entry.file, node.entry.base, node.type === "row" ? node.path : undefined);
    }),
    cmd("hexcavator.runTool", (node) => node && runTool(sidebar, provider, node)),
    cmd("hexcavator.copyCommand", async (node) => {
      const line = node && sidebar.commandFor(node);
      if (line) {
        await vscode.env.clipboard.writeText(line);
        vscode.window.setStatusBarMessage(`Copied: ${line}`, 3000);
      }
    }),
    cmd("hexcavator.runInTerminal", (node) => {
      if (!node || !node.tool) {
        return;
      }
      const t = node.tool;
      const args =
        t.args ||
        {
          report: ["size", "-d", "sections,compileunits,symbols", node.entry.file],
          sizeDiff: ["size", "-d", "sections,compileunits,symbols", node.entry.file, "--", node.entry.base],
          findings: ["size", "-findings", node.entry.file],
        }[t.id];
      if (!args) {
        vscode.window.showInformationMessage(`"${t.label}" asks for a name: copy its command line instead.`);
        return;
      }
      const exe = h.hexcPath(vscode.workspace.getConfiguration("hexcavator").get("path"));
      // hexc itself, not a shell: nothing to quote.
      const term = vscode.window.createTerminal({ name: `hexc ${args[0]}`, shellPath: exe, shellArgs: args, isTransient: true });
      term.show();
    }),
    cmd("hexcavator.removeResult", (node) => node && sidebar.removeResult(node.entry, node.result)),
    cmd("hexcavator.symbol.why", (node) => {
      const s = symbolOf(node);
      if (s) {
        const entry = sidebar.add(s.entry.file, s.entry.base);
        sidebar.addResult(entry, { kind: "why", name: s.name });
        reveal(entry);
      }
    }),
    cmd("hexcavator.symbol.refs", (node) => {
      const s = symbolOf(node);
      if (s) {
        const entry = sidebar.add(s.entry.file, s.entry.base);
        sidebar.addResult(entry, { kind: "refs", name: s.name });
        reveal(entry);
      }
    }),
    cmd("hexcavator.symbol.open", (node) => {
      const s = symbolOf(node);
      if (s) {
        deps.inspect(s.entry.file, s.name);
      }
    }),
    cmd("hexcavator.symbol.viewData", (node) => {
      const s = symbolOf(node);
      if (s) {
        deps.openData(s.entry.file, s.name);
      }
    }),
    cmd("hexcavator.symbol.disassemble", (node) => {
      const s = symbolOf(node);
      if (s) {
        deps.openDisassembly(s.entry.file, s.name);
      }
    }),
    cmd("hexcavator.symbol.copyName", async (node) => {
      const s = symbolOf(node);
      if (s) {
        await vscode.env.clipboard.writeText(s.name);
      }
    }),
    cmd("hexcavator.symbol.goToSource", async (node) => {
      const s = symbolOf(node);
      if (!s) {
        return;
      }
      try {
        await openDefinition(await sidebar.sourceOf(s.entry, s.name), s.name, s.entry.file);
      } catch (e) {
        vscode.window.showErrorMessage(`hexc: ${e.message}`);
      }
    })
  );
  return sidebar;
}

/**
 * Opens a definition (`where`: the file the binary records, and a line)
 * beside, at its line: the file found on this machine (see findSource);
 * else says where it is.
 */
async function openDefinition(where, name, binary) {
  if (!where) {
    vscode.window.showInformationMessage(`The debug information doesn't say where ${name} is defined.`);
    return;
  }
  const local = findSource(where.file, binary);
  if (!local) {
    vscode.window.showWarningMessage(
      `${name} is defined at ${where.file}:${where.line}, which is not on this machine (hexcavator.sourcePathMap maps a build's paths to yours).`
    );
    return;
  }
  const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(local));
  const line = Math.max(0, where.line - 1);
  await vscode.window.showTextDocument(doc, { selection: new vscode.Range(line, 0, line, 0), viewColumn: vscode.ViewColumn.Beside });
}

/** The hexcavator.sourcePathMap setting, as [recorded, local] pairs. */
function sourceMaps() {
  const m = vscode.workspace.getConfiguration("hexcavator").get("sourcePathMap") || {};
  return Object.entries(m).filter(([k, v]) => typeof k === "string" && typeof v === "string");
}

/**
 * Where the source file a binary (`binary`) records as `recorded` is on
 * this machine (see lib/hexc.js localSource): looked for under the
 * workspace's folders and the binary's directories; `null` if nowhere.
 */
function findSource(recorded, binary) {
  const roots = (vscode.workspace.workspaceFolders || []).map((f) => f.uri.fsPath);
  let dir = binary ? path.dirname(binary) : null;
  for (let i = 0; dir && i < 8; i++) {
    roots.push(dir);
    const up = path.dirname(dir);
    dir = up === dir ? null : up;
  }
  return h.localSource(recorded, sourceMaps(), roots);
}

/** `hexc info -json`'s answer for `file`, else what its name suggests. */
function parseCaps(out, file) {
  try {
    const all = JSON.parse(out);
    const caps = Array.isArray(all) ? all[0] : null;
    return caps && Array.isArray(caps.tools) ? caps : h.capsFallback(file);
  } catch {
    return h.capsFallback(file);
  }
}

/** What hexc says files support, outside the sidebar's entries, by path. */
const looseCaps = new Map();

/**
 * What hexc says `file` supports (`hexc info -json`), with `runHexc`; kept
 * for a minute (a rebuilt file may say otherwise).
 */
function capsOf(file, runHexc) {
  const kept = looseCaps.get(file);
  if (kept && Date.now() - kept.at < 60000) {
    return kept.caps;
  }
  const caps = runHexc(["info", "-json", file]).then((out) => parseCaps(out, file), () => h.capsFallback(file));
  looseCaps.set(file, { at: Date.now(), caps });
  return caps;
}

module.exports = { register, Sidebar, SizeLenses, OutputProvider, keyOf, capsOf, parseCaps, findSource, openDefinition };
