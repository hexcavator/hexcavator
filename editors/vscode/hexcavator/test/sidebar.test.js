// Tests for lib/hexc.js, and for the sidebar's tree (sidebar.js) against a
// stand-in for the `vscode` module: `node test/sidebar.test.js [hexc.exe]`.
// With hexc, the tree is read from the repository's test binaries.
"use strict";

const assert = require("assert");
const path = require("path");
const Module = require("module");
const { execFile } = require("child_process");
const h = require(path.join(__dirname, "..", "lib", "hexc.js"));

const tests = [];
const test = (name, fn) => tests.push([name, fn]);

test("which hexc runs", () => {
  const exe = process.platform === "win32" ? "hexc.exe" : "hexc";
  const repo = path.join(__dirname, "..", "..", "..", "..", "target");
  const release = path.join(repo, "release", exe);
  const debug = path.join(repo, "debug", exe);
  assert.strictEqual(h.hexcPath("C:/tools/hexc.exe", () => true), "C:/tools/hexc.exe");
  assert.strictEqual(h.hexcPath("", (p) => p === release || p === debug), release);
  assert.strictEqual(h.hexcPath(undefined, (p) => p === debug), debug);
  assert.strictEqual(h.hexcPath("", () => false), "hexc");
  // A release VSIX's own hexc comes before any build in a repository.
  const bundled = path.join(__dirname, "..", "bin", exe);
  assert.strictEqual(h.hexcPath("", (p) => p === bundled || p === release), bundled);
  assert.strictEqual(h.hexcPath("C:/tools/hexc.exe", (p) => p === bundled), "C:/tools/hexc.exe");
});

test("kinds of files", () => {
  assert.strictEqual(h.kindOf("C:\\a\\b.DLL"), "pe");
  assert.strictEqual(h.kindOf("/x/y.lib"), "coff");
  assert.strictEqual(h.kindOf("libz.so"), "other");
  assert.strictEqual(h.kindOf("noext"), "other");
  assert.strictEqual(h.baseName("C:\\a/b\\c.exe"), "c.exe");
});

test("command lines quote what a shell would split", () => {
  assert.strictEqual(h.commandLine("hexc", ["xref", "-why", "main(int, char**)", "C:\\a b\\x.exe"]), 'hexc xref -why "main(int, char**)" "C:\\a b\\x.exe"');
  assert.strictEqual(h.quote('say "hi"'), '"say \\"hi\\""');
  assert.strictEqual(h.quote("C:\\dir with space\\"), '"C:\\dir with space\\\\"');
  assert.strictEqual(h.quote(""), '""');
  assert.strictEqual(h.quote("plain.exe"), "plain.exe");
});

test("a query that names a symbol exactly", () => {
  assert.strictEqual(h.nameIs("main"), "name='main'");
  assert.strictEqual(h.nameIs("`string'"), 'name="`string\'"');
  assert.strictEqual(h.nameIs(`\`string': "%s"`), "name~'^`string.: .%s.$'");
  assert.strictEqual(h.nameIs(`a'"(b)`), "name~'^a..\\(b\\)$'");
});

test("paths read as their file names", () => {
  assert.ok(h.isPath("C:\\work\\main.obj"));
  assert.ok(h.isPath("/usr/lib/x.o"));
  assert.ok(!h.isPath("std::ratio<1/2>"));
  assert.ok(!h.isPath(".text"));
  const d = h.describeRow({ name: "C:\\w\\main.obj", file: 512, vm: 600 }, { name: ".text", file: 2048, vm: 2048 }, { name: "TOTAL", file: 4096, vm: 4096 }, false, "file");
  assert.strictEqual(d.label, "main.obj");
  assert.strictEqual(d.description, "512 B · 25%");
  assert.ok(d.tooltip.includes("C:\\w\\main.obj") && d.tooltip.includes("25% of .text, 13% of all"));
});

test("rows roll up: children counted, diffs signed", () => {
  const row = { name: ".text", file: 2048, vm: 2000, children: [{}, {}, {}] };
  assert.strictEqual(h.describeRow(row, { name: "TOTAL", file: 4096 }, null, false, "file").description, "2.00 KiB · 50%  (3)");
  assert.strictEqual(h.describeRow({ name: "x", file: 100, vm: -4 }, null, null, true, "file").description, "+100 B");
  assert.strictEqual(h.describeRow({ name: "x", file: -100, vm: -4 }, null, null, true, "vm").description, "-4 B");
  const kids = h.sortedRows({ children: [{ name: "a", file: 1 }, { name: "b", file: -9 }, { name: "c", file: 5 }] }, "file");
  assert.deepStrictEqual(kids.map((k) => k.name), ["b", "c", "a"]);
});

test("tools: every one for a PE image, fewer for others, comparisons for a diff", () => {
  const ids = (entry) => h.toolsFor(entry).flatMap((g) => g.tools.map((t) => t.id));
  const pe = ids({ file: "a.exe" });
  for (const id of ["report", "compare", "findings", "why", "refs", "xref", "unreachable", "vtables", "identical", "query", "types", "layout", "inlines", "sourcefiles", "annotations", "disassemble", "dump"]) {
    assert.ok(pe.includes(id), id);
  }
  assert.deepStrictEqual(ids({ file: "a.o" }), ["report", "compare", "disassemble", "info"]);
  assert.deepStrictEqual(ids({ file: "a.lib" }), ["report", "compare", "dump", "info"]);
  assert.deepStrictEqual(ids({ file: "a.exe", base: "b.exe" }), ["sizeDiff", "sectionsDiff", "functionsDiff", "findingsDiff", "typesDiff"]);
  assert.deepStrictEqual(ids({ file: "a.so", base: "b.so" }), ["sizeDiff", "sectionsDiff"]);
  // Every tool runs something: arguments, or a question first.
  for (const g of h.toolsFor({ file: "a.exe" })) {
    for (const t of g.tools) {
      assert.ok(["panel", "pick-base", "disassemble", "tree", "text"].includes(t.run), t.id);
      if (t.run === "text") {
        assert.ok(t.args || t.ask, t.id);
      }
    }
  }
});

test("tools: as hexc says the file supports them, whatever its name", () => {
  const ids = (entry, caps, base) => h.toolsFor(entry, caps, base).flatMap((g) => g.tools.map((t) => t.id));
  // An ELF image with DWARF (no extension): every tool hexc lists.
  const elf = { format: "elf", tools: ["report", "compare", "info", "disassemble", "findings", "why", "refs", "xref", "query", "types", "sourcefiles", "functionsDiff"] };
  const got = ids({ file: "/bin/app" }, elf);
  for (const id of elf.tools.filter((t) => t !== "functionsDiff")) {
    assert.ok(got.includes(id), id);
  }
  assert.ok(!got.includes("annotations") && !got.includes("functionsDiff"));
  // A diff: the comparisons both files support.
  assert.deepStrictEqual(ids({ file: "/bin/app", base: "/old/app" }, elf, elf), ["sizeDiff", "sectionsDiff", "functionsDiff"]);
  assert.deepStrictEqual(ids({ file: "/bin/app", base: "/old/app" }, elf, { tools: [] }), ["sizeDiff", "sectionsDiff"]);
  // Empty groups are left out.
  assert.deepStrictEqual(h.toolsFor({ file: "x" }, { tools: ["report"] }).map((g) => g.label), ["Views"]);
  assert.ok(h.can(elf, "why") && !h.can(elf, "annotations") && !h.can(null, "why"));
});

test("tools that ask", () => {
  const tools = h.toolsFor({ file: "a.exe" }).flatMap((g) => g.tools);
  const tool = (id) => tools.find((t) => t.id === id);
  assert.deepStrictEqual(h.argsWith(tool("query"), { file: "a.exe" }, "group by library"), ["query", "a.exe", "group by library"]);
  assert.deepStrictEqual(h.argsWith(tool("layout"), { file: "a.exe" }, "Diamond"), ["types", "-layout", "Diamond", "a.exe"]);
  assert.strictEqual(h.titleOf(tool("layout"), { file: "C:\\x\\a.exe" }, "Diamond"), "A Type's Layout: Diamond (a.exe)");
  assert.strictEqual(h.titleOf(tool("types"), { file: "a.exe", base: "b.exe" }), "Type Layouts (a.exe vs b.exe)");
});

test("tools shown as tables, with -json", () => {
  const tools = h.toolsFor({ file: "a.exe" }).flatMap((g) => g.tools);
  const tool = (id) => tools.find((t) => t.id === id);
  for (const id of ["unreachable", "vtables", "identical", "types", "inlines", "sourcefiles", "annotations", "query", "layout"]) {
    assert.ok(h.isTable(tool(id)), id);
  }
  assert.ok(!h.isTable(tool("dump")), "headers stay text");
  assert.deepStrictEqual(h.jsonArgs(["xref", "-unreachable", "a.exe"]), ["xref", "-json", "-unreachable", "a.exe"]);
  assert.deepStrictEqual(h.jsonArgs(["query", "-json", "a.exe", "q"]), ["query", "-json", "a.exe", "q"]);
});

test("why-chains", () => {
  const rows = h.whyRows({
    reached: true,
    root: { name: "mainCRTStartup", reason: "the entry point" },
    chain: [
      { edge: "jumps to", name: "__scrt_common_main_seh()" },
      { edge: "calls", name: "main" },
    ],
  });
  assert.deepStrictEqual(rows.map((r) => [r.label, r.description]), [
    ["mainCRTStartup", "the entry point"],
    ["__scrt_common_main_seh()", "jumps to"],
    ["main", "calls"],
  ]);
  assert.strictEqual(h.whyRows({ reached: false, comdat: false })[0].label, "Nothing reaches it");
  assert.strictEqual(h.whyRows({ reached: true })[0].label, "It is a root");
});

test("functions by the source line they start at", () => {
  const rows = [
    { name: "f<int>", file: 40, source: "C:\\src\\a.cpp", line: 10 },
    { name: "f<long>", file: 90, source: "c:/SRC/A.cpp", line: 10 },
    { name: "g", file: 12, source: "C:\\src\\a.cpp", line: 3 },
    { name: "folded", file: 0, source: "C:\\src\\a.cpp", line: 5 },
    { name: "elsewhere", file: 7, source: "C:\\src\\b.cpp", line: 1 },
    { name: "no line", file: 7 },
  ];
  const by = h.functionsByLine(rows, h.samePath("C:\\Src\\a.cpp"));
  assert.deepStrictEqual(by.map(([line, fns]) => [line, fns.map((f) => f.name)]), [
    [3, ["g"]],
    [10, ["f<long>", "f<int>"]],
  ]);
});

test("hexc serve's options from the settings", () => {
  const none = h.serveLaunch(() => undefined);
  assert.deepStrictEqual(none, { args: ["serve"], env: {} });
  const set = {
    arch: "x86_64",
    symbolServers: ["https://msdl.microsoft.com/download/symbols", " "],
    debuginfod: ["https://debuginfod.example"],
    symbolCache: "C:\\symcache",
    symbolPath: "C:\\syms;D:\\more",
  };
  const l = h.serveLaunch((k) => set[k]);
  assert.deepStrictEqual(l.args, [
    "--arch",
    "x86_64",
    "--symbol-server",
    "https://msdl.microsoft.com/download/symbols",
    "--debuginfod",
    "https://debuginfod.example",
    "--symbol-cache",
    "C:\\symcache",
    "serve",
  ]);
  assert.deepStrictEqual(l.env, { HEXC_SYMBOL_PATH: "C:\\syms;D:\\more" });
});

test("source paths from another machine", () => {
  const maps = [["R:\\", "C:\\repo\\"], ["/build/", "/home/me/"]];
  assert.strictEqual(h.mapSource("r:/tools/a.cpp", maps), "C:\\repo\\tools/a.cpp");
  assert.strictEqual(h.mapSource("/build/x/y.c", maps), "/home/me/x/y.c");
  assert.strictEqual(h.mapSource("/elsewhere/y.c", maps), "/elsewhere/y.c");
  assert.strictEqual(h.sharedTail("R:\\tools\\xref\\main.cpp", "C:/jm/Analysis/tools/xref/main.cpp"), 3);
  // Found by its last directories under a root, the most of them first.
  const here = new Set([path.join("/ws", "tools", "xref", "main.cpp")]);
  const exists = (p) => here.has(p);
  assert.strictEqual(h.localSource("R:\\tools\\xref\\main.cpp", [], ["/other", "/ws"], exists), path.join("/ws", "tools", "xref", "main.cpp"));
  assert.strictEqual(h.localSource("R:\\main.cpp", [], ["/ws"], exists), null, "a name alone is not enough");
  // Lenses: rows recorded elsewhere match by their tail when none is exact.
  const rows = [
    { name: "main", file: 202, source: "R:\\tools\\xref\\main.cpp", line: 7 },
    { name: "other", file: 9, source: "R:\\tools\\lines\\main.cpp", line: 3 },
  ];
  const mine = h.samePath("C:\\jm\\Analysis\\tools\\xref\\main.cpp");
  const by = h.functionsByLine(rows, mine, [], () => true);
  assert.deepStrictEqual(by.map(([line, fns]) => [line, fns.map((f) => f.name)]), [[7, ["main"]]]);
  // Not when the recorded file is on this machine (another checkout).
  assert.deepStrictEqual(h.functionsByLine(rows, mine, [], () => false), []);
  // A mapping makes it exact.
  assert.strictEqual(h.functionsByLine(rows, h.samePath("C:\\repo\\tools\\xref\\main.cpp"), maps).length, 1);
});

test("functions compared, as groups", () => {
  const d = {
    unchanged: 5,
    changed: [
      { old: "a", new: "a", oldSize: 10, newSize: 40 },
      { old: "b", new: "b", oldSize: 100, newSize: 20 },
    ],
    changedCount: 3,
    renamed: [{ old: "f_old", new: "f", oldSize: 8, newSize: 8 }],
    renamedCount: 1,
    added: [{ name: "n", size: 16 }],
    addedCount: 1,
    removed: [{ name: "r", size: 4 }],
    removedCount: 1,
  };
  assert.strictEqual(h.functionsSummary(d), "3 changed · 1 renamed · 1 added · 1 removed");
  assert.strictEqual(h.functionsSummary({ unchanged: 7, changedCount: 0, renamedCount: 0, addedCount: 0, removedCount: 0 }), "7 the same");
  const [changed, renamed, added, removed] = h.functionGroups(d);
  // Largest change first; one more than listed.
  assert.deepStrictEqual(changed.items.map((i) => i.name), ["b", "a"]);
  assert.strictEqual(changed.more, 1);
  assert.strictEqual(changed.items[0].description, "100 B → 20 B (-80 B)");
  assert.strictEqual(changed.items[0].color, "charts.green");
  assert.strictEqual(changed.description, "3, -50 B");
  assert.strictEqual(renamed.items[0].description, "was f_old");
  assert.strictEqual(added.items[0].description, "+16 B");
  assert.strictEqual(removed.items[0].description, "-4 B");
  assert.strictEqual(removed.items[0].removed, true);
  assert.strictEqual(removed.description, "1, -4 B");
});

// ------------------------------------------------------- the tree itself

/** Enough of the `vscode` module for sidebar.js's tree. */
function fakeVscode(config) {
  class EventEmitter {
    constructor() {
      this.listeners = [];
      this.event = (l) => this.listeners.push(l);
    }
    fire(v) {
      this.listeners.forEach((l) => l(v));
    }
  }
  class TreeItem {
    constructor(label, collapsibleState) {
      this.label = label;
      this.collapsibleState = collapsibleState;
    }
  }
  class MarkdownString {
    constructor() {
      this.value = "";
    }
    appendText(t) {
      this.value += t;
      return this;
    }
    appendMarkdown(t) {
      this.value += t;
      return this;
    }
    appendCodeblock(t) {
      this.value += "\n```\n" + t + "\n```\n";
      return this;
    }
  }
  return {
    EventEmitter,
    TreeItem,
    MarkdownString,
    TreeItemCollapsibleState: { None: 0, Collapsed: 1, Expanded: 2 },
    ThemeIcon: class {
      constructor(id) {
        this.id = id;
      }
    },
    ThemeColor: class {},
    RelativePattern: class {},
    Range: class {
      constructor(l0, c0, l1, c1) {
        Object.assign(this, { line: l0, character: c0, endLine: l1, endCharacter: c1 });
      }
    },
    CodeLens: class {
      constructor(range, command) {
        Object.assign(this, { range, command });
      }
    },
    Uri: { file: (p) => ({ fsPath: p }), from: (x) => x },
    workspace: {
      getConfiguration: () => ({ get: (k, d) => (k in config ? config[k] : d) }),
      createFileSystemWatcher: () => ({ onDidChange() {}, onDidCreate() {}, dispose() {} }),
    },
  };
}

function loadSidebar(config) {
  const vscode = fakeVscode(config);
  const resolve = Module._resolveFilename;
  Module._resolveFilename = function (request, ...rest) {
    return request === "vscode" ? "vscode" : resolve.call(this, request, ...rest);
  };
  require.cache.vscode = { id: "vscode", filename: "vscode", loaded: true, exports: vscode };
  return require(path.join(__dirname, "..", "sidebar.js"));
}

function runner(exe) {
  const calls = [];
  const run = (args) =>
    new Promise((resolve, reject) => {
      calls.push(args);
      execFile(exe, args, { maxBuffer: 1 << 30 }, (error, stdout, stderr) => (error ? reject(new Error(stderr || error.message)) : resolve(stdout)));
    });
  return { run, calls };
}

const memento = () => {
  const m = new Map();
  return { get: (k) => m.get(k), update: (k, v) => m.set(k, v) };
};

async function treeTests(exe) {
  const repo = path.join(__dirname, "..", "..", "..", "..");
  const image = path.join(repo, "testdata", "xref", "xref-x64.exe");
  const renamed = path.join(repo, "testdata", "xref", "xref-x64-renamed.exe");
  const { Sidebar } = loadSidebar({ path: exe, sources: ["sections", "compileunits", "symbols"], rows: 100 });
  const { run, calls } = runner(exe);
  const context = { workspaceState: memento(), subscriptions: [] };
  const sidebar = new Sidebar(context, { runHexc: run });
  const kids = async (node) => await sidebar.getChildren(node);
  const item = async (node) => await sidebar.getTreeItem(node);

  // Entries: in the order opened (a binary opened again keeps its place),
  // kept in the workspace's state, no repeats.
  sidebar.add(image, null);
  sidebar.add(image, renamed);
  sidebar.add(image, null);
  const roots = await kids();
  assert.strictEqual(roots.length, 2);
  assert.strictEqual((await item(roots[0])).label, "xref-x64.exe");
  assert.strictEqual((await item(roots[1])).label, "xref-x64.exe ⇄ xref-x64-renamed.exe");
  assert.deepStrictEqual(context.workspaceState.get("hexcavator.entries").map((e) => !!e.base), [false, true]);

  // A binary: what it is, its pages, Compare; then the other queries.
  const top = await kids(roots[0]);
  assert.deepStrictEqual(top.map((n) => n.type), ["tool", "tool", "tool", "tool", "tool", "tool", "tool", "tool", "tool", "group"]);
  assert.deepStrictEqual(
    await Promise.all(top.map(async (n) => (await item(n)).label)),
    ["Headers", "File Format", "Build Information", "Debug Information", "Symbols", "Types", "Sources", "Size Reduction Opportunities", "Compare With Another Build…", "Miscellaneous Queries"]
  );
  assert.strictEqual(top[7].tool.id, "findings");
  // Build Information: a page of its own.
  assert.strictEqual(top[2].tool.run, "buildinfo");
  assert.ok(sidebar.commandFor(top[2]).includes(`checksec -audit ${image}`));
  // Debug Information: the PDB hexc found.
  const debugTool = top[3].tool;
  assert.deepStrictEqual(debugTool.args.slice(0, 2), ["pdb", "-summary"]);
  assert.ok(debugTool.args[2].endsWith("xref-x64.pdb"), debugTool.args[2]);
  assert.strictEqual(top[4].tool.run, "panel");
  assert.strictEqual(top[5].tool.run, "types");
  // Sources: the Symbols page, grouped by source file.
  assert.strictEqual(top[6].tool.run, "sources");
  assert.ok(sidebar.commandFor(top[6]).includes(`size -d "sourcefiles,symbols" -n 0 ${image}`));
  const misc = top[9];
  assert.strictEqual((await item(misc)).collapsibleState, 1, "collapsed");
  const miscKids = await kids(misc);
  // (Findings is a page of its own now; Recommendations is in it.)
  assert.ok(!miscKids.some((n) => n.type === "recs"), "no Recommendations");

  // Tools show their command lines.
  const tools = miscKids.filter((n) => n.type === "tool");
  const unreachable = tools.find((t) => t.tool.id === "unreachable");
  const tip = (await item(unreachable)).tooltip.value;
  assert.ok(tip.includes(`xref -unreachable -n 0 ${image}`), tip);
  // (Not what the pages do: Disassemble, Why Is This Here?, References,
  // Query Symbols, a type's layout; Hardening and the audit; type layouts by
  // padding; code by source file.)
  for (const id of ["disassemble", "why", "refs", "query", "layout", "checksec", "audit", "types", "sourcefiles", "recommend", "findings", "annotations"]) {
    assert.ok(!tools.some((t) => t.tool.id === id), id);
  }
  const whyTool = { tool: h.toolsFor({ file: image }, h.capsFallback(image)).flatMap((g) => g.tools).find((t) => t.id === "why"), entry: roots[0].entry };
  assert.ok(sidebar.commandFor(whyTool).includes(`xref -why "<symbol>"`));
  assert.ok(sidebar.commandFor(whyTool, "main").endsWith(`xref -why main ${image}`));

  // Why main is there, and what refers to it, as results under the binary.
  sidebar.addResult(roots[0].entry, { kind: "why", name: "main(int, char**)" });
  sidebar.addResult(roots[0].entry, { kind: "refs", name: "main(int, char**)" });
  const withResults = (await kids(roots[0])).filter((n) => n.type === "result");
  assert.strictEqual(withResults.length, 2);
  const refs = await kids(withResults[0]);
  assert.deepStrictEqual(refs.map((r) => r.label), ["Reached from a root", "Referred to by", "Refers to"]);
  const callers = await kids(refs[1]);
  assert.strictEqual(callers[0].name, "__scrt_common_main_seh()");
  // Each reference opens into its own.
  const further = await kids(callers[0]);
  assert.ok(further.some((g) => g.label === "Referred to by"));
  const why = await kids(withResults[1]);
  assert.deepStrictEqual(why.map((r) => r.label), ["mainCRTStartup(void*)", "__scrt_common_main_seh()", "main(int, char**)"]);
  assert.strictEqual(why[0].description, "the entry point");
  // What nothing reaches says so.
  sidebar.addResult(roots[0].entry, { kind: "why", name: "dead_entry(int)" });
  const results = async () => (await kids(roots[0])).filter((n) => n.type === "result");
  const dead = await kids((await results())[0]);
  assert.strictEqual(dead[0].label, "Nothing reaches it");
  // A name hexc doesn't know is a failure shown in the tree.
  sidebar.addResult(roots[0].entry, { kind: "why", name: "no such thing" });
  const none = await kids((await results())[0]);
  assert.strictEqual(none[0].label, "hexc failed");
  assert.match(none[0].description, /nothing named/);

  // The source of a function, from the PDB.
  const where = await sidebar.sourceOf(roots[0].entry, "main(int, char**)");
  assert.ok(where.file.endsWith("main.cpp") && where.line === 53, JSON.stringify(where));
  // Symbols to pick from, largest first.
  const fns = await sidebar.symbols(roots[0].entry, true);
  assert.ok(fns.length > 10 && fns.some((r) => r.name === "main(int, char**)"));
  assert.ok(fns[0].file >= fns[1].file);

  // Lenses over the functions of the fixture's main.cpp, from the PDB.
  const { SizeLenses } = require(path.join(__dirname, "..", "sidebar.js"));
  const lenses = new SizeLenses(sidebar);
  const mainCpp = path.join(repo, "tools", "xref", "main.cpp");
  const found = await lenses.provideCodeLenses({ uri: { scheme: "file", fsPath: mainCpp.toUpperCase() } });
  const titles = found.map((l) => l.command.title);
  assert.ok(found.length >= 4, titles.join("; "));
  const mainLens = found.find((l) => l.command.arguments[0] && l.command.arguments[0].name === "main(int, char**)");
  assert.ok(mainLens && mainLens.command.title === "202 B in xref-x64.exe", titles.join("; "));
  assert.strictEqual(mainLens.range.line, where.line - 1);
  assert.ok(titles.includes("why is it here?"));
  // None for a file the binaries have no code from, nor for diffs.
  assert.deepStrictEqual(await lenses.provideCodeLenses({ uri: { scheme: "file", fsPath: path.join(repo, "README.md") } }), []);

  // A diff: its Symbols page (the change), and its Types (their layouts
  // compared); nothing else.
  const diffTop = await kids(roots[1]);
  assert.deepStrictEqual(diffTop.map((n) => n.type), ["tool", "tool"]);
  assert.deepStrictEqual(await Promise.all(diffTop.map(async (n) => (await item(n)).label)), ["Symbols", "Types"]);
  assert.strictEqual(diffTop[1].tool.id, "typesDiff");

  // A refresh: the results stay.
  sidebar.refresh(roots[0].entry);
  await kids(roots[0]);
  assert.strictEqual(sidebar.state(roots[0].entry).results.length, 4);
  sidebar.remove(roots[1].entry);
  assert.strictEqual((await kids()).length, 1);
  sidebar.clear();
  assert.strictEqual((await kids()).length, 0);
}

(async () => {
  let failed = 0;
  for (const [name, fn] of tests) {
    try {
      await fn();
      console.log(`ok   ${name}`);
    } catch (e) {
      failed++;
      console.log(`FAIL ${name}\n${e.stack}`);
    }
  }
  const exe = process.argv[2];
  if (exe) {
    try {
      await treeTests(exe);
      console.log("ok   the tree, read from the test binaries");
    } catch (e) {
      failed++;
      console.log(`FAIL the tree\n${e.stack}`);
    }
  } else {
    console.log("(skipped the tree: give hexc's path to read the test binaries)");
  }
  process.exit(failed ? 1 : 0);
})();
