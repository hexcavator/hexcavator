// What the sidebar shows and runs, as plain data: the tools for a binary
// or a diff (each with its hexc command line), how a size row reads in a
// tree, and the like. No `vscode` dependency, so it is tested under Node.
"use strict";

const PE = ["exe", "dll", "sys", "efi"];
const COFF = ["obj", "lib"];

/** The extension of `file`, lower case ("" if none). */
function extOf(file) {
  const m = /\.([A-Za-z0-9]+)$/.exec(baseName(file));
  return m ? m[1].toLowerCase() : "";
}

/** The last part of a path (either separator). */
function baseName(file) {
  return String(file || "").replace(/^.*[\\/]/, "");
}

/** "pe" (an image with a PDB: every tool), "coff", or "other". */
function kindOf(file) {
  const ext = extOf(file);
  return PE.includes(ext) ? "pe" : COFF.includes(ext) ? "coff" : "other";
}

/** An argument as a shell would need it typed (for showing and copying). */
function quote(arg) {
  const s = String(arg);
  if (s && !/[\s"'`$&|<>^%!;(),*?~]/.test(s)) {
    return s;
  }
  return '"' + s.replace(/(\\*)"/g, '$1$1\\"').replace(/(\\+)$/, "$1$1") + '"';
}

/** The command line that runs hexc `exe` with `args`. */
function commandLine(exe, args) {
  return [exe, ...args].map(quote).join(" ");
}

/**
 * A query filter that matches the symbol named `name` exactly. (Query
 * strings have no escapes: quote with whichever quote the name lacks, or,
 * with both in it, match a regular expression that stands `.` for them.)
 */
function nameIs(name) {
  if (!name.includes("'")) {
    return `name='${name}'`;
  }
  if (!name.includes('"')) {
    return `name="${name}"`;
  }
  const re = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/['"]/g, ".");
  return `name~'^${re}$'`;
}

/** Whether a size row's name names a path (a compiland, a source file). */
function isPath(name) {
  return /^[A-Za-z]:[\\/]|^\\\\|^\/[^/]/.test(name) || (/\\/.test(name) && !/\s/.test(name));
}

/**
 * How a report row reads in a tree: a short label (a path's file name),
 * a description (its size, and its share of its parent, or a diff's
 * change), and a tooltip with the rest.
 */
function describeRow(row, parent, total, diff, domain) {
  const key = domain === "vm" ? "vm" : "file";
  const v = row[key] || 0;
  const label = isPath(row.name) ? baseName(row.name) || row.name : row.name;
  const sign = diff && v > 0 ? "+" : "";
  let description = sign + formatSize(v);
  if (!diff && parent && parent[key]) {
    description += " · " + percent(v, parent[key]);
  }
  if (row.children) {
    description += `  (${row.children.length})`;
  }
  const lines = [row.name, ""];
  const line = (what, n) => `${what}: ${diff && n > 0 ? "+" : ""}${formatSize(n)} (${formatBytes(n)} bytes)`;
  lines.push(line("File", row.file || 0), line("Memory", row.vm || 0));
  if (!diff && parent && parent[key]) {
    lines.push(`${percent(v, parent[key])} of ${parent.name}` + (total && total !== parent ? `, ${percent(v, total[key])} of all` : ""));
  }
  if (row.other_count) {
    lines.push(`${row.other_count} smaller rows together`);
  }
  return { label, description, tooltip: lines.join("\n") };
}

/** A row's children, largest (or largest change) first. */
function sortedRows(row, domain) {
  const key = domain === "vm" ? "vm" : "file";
  return [...(row.children || [])].sort((a, b) => Math.abs(b[key] || 0) - Math.abs(a[key] || 0));
}

/**
 * What hexc says a file supports (`hexc info -json`): its format, kind,
 * debug information, and `tools`. Without it (an older hexc), what the
 * file's extension suggests: everything for a PE image, headers for COFF,
 * and the rest for other files.
 */
function capsFallback(file) {
  const kind = kindOf(file);
  if (kind === "pe") {
    return {
      format: "pe",
      tools: ["report", "compare", "info", "dump", "disassemble", "findings", "recommend", "why", "refs", "xref", "unreachable", "vtables", "identical", "query", "types", "layout", "inlines", "sourcefiles", "annotations", "data", "functionsDiff", "findingsDiff", "typesDiff", "lenses"],
    };
  }
  if (kind === "coff") {
    return { format: "coff", tools: ["report", "compare", "info", "dump"] };
  }
  return { format: "other", tools: ["report", "compare", "info", "disassemble"] };
}

/** Whether `caps` (see capsFallback) has tool `id`. */
function can(caps, id) {
  return !!caps && Array.isArray(caps.tools) && caps.tools.includes(id);
}

/**
 * The tools for an entry (a binary, or a binary and its base), in groups,
 * as `caps` (and `baseCaps`, the base's) allow: what hexc says the files
 * support (see capsFallback). Each tool has an `id`, a `label`, an `icon`
 * (a codicon), a `detail` (what it shows), and `run`: "panel" (a
 * webview), "text" (hexc's output as a document; its `args`, with `ask`
 * naming what to ask for first: "symbol", "function", "type", "inlinee",
 * "source", or "query"), or "tree" (the result shown in the sidebar).
 */
function toolsFor(entry, caps, baseCaps) {
  const file = entry.file;
  const base = entry.base;
  caps = caps || capsFallback(file);
  const t = (id, label, icon, detail, more) => Object.assign({ id, label, icon, detail }, more);
  const keep = (tools, has) => tools.filter((tool) => has(tool.id));
  if (base) {
    baseCaps = baseCaps || capsFallback(base);
    const both = (id) => id === "sizeDiff" || id === "sectionsDiff" || (can(caps, id) && can(baseCaps, id));
    return [
      {
        label: "Compare",
        icon: "diff",
        tools: keep(
          [
            t("sizeDiff", "Size Diff (Treemap)", "graph", "the change by section, compiland, and symbol, drawn", { run: "panel" }),
            t("sectionsDiff", "Sections Compared", "list-flat", "bloaty's diff by section", { run: "text", args: ["size", "-d", "sections", "-n", "0", file, "--", base] }),
            t("functionsDiff", "Functions Compared", "symbol-method", "the same, changed, renamed (same code, another name), added, and removed functions", {
              run: "text",
              args: ["xref", "-n", "0", file, "--", base],
            }),
            t("findingsDiff", "Findings Compared", "lightbulb", "what each build's findings gained and lost", { run: "text", args: ["size", "-findings", file, "--", base] }),
            t("typesDiff", "Type Layouts Compared", "symbol-structure", "the types whose layout changed, and those added or removed", {
              run: "text",
              args: ["types", "-n", "0", file, "--", base],
            }),
          ],
          both
        ),
      },
    ];
  }
  const has = (id) => can(caps, id);
  const groups = [
    {
      label: "Views",
      icon: "eye",
      tools: keep(
        [
          t("report", "Size Report (Treemap)", "graph", "a nested treemap and sunburst of where the bytes go", { run: "panel" }),
          t("compare", "Compare With Another Build…", "diff", "add a diff of this binary against a base build", { run: "pick-base" }),
          t("findings", "Findings", "lightbulb", "duplicate data, wasteful virtuals, and template families", { run: "panel" }),
        ],
        has
      ),
    },
    {
      label: "Why Is It There?",
      icon: "question",
      tools: keep(
        [
          t("why", "Why Is This Here?…", "debug-step-into", "the chain of references from a root (the entry point, an export…) to a function or datum", {
            run: "tree",
            ask: "symbol",
          }),
          t("refs", "References…", "references", "what refers to a symbol and what it refers to, to explore", { run: "tree", ask: "symbol" }),
          t("xref", "Reference Summary", "type-hierarchy", "what refers to what: roots, edges, what nothing reaches", { run: "text", args: ["xref", file] }),
          t("unreachable", "Unreachable Code and Data", "circle-slash", "what no root reaches, largest first", { run: "text", args: ["xref", "-unreachable", "-n", "0", file] }),
          t("vtables", "Unreferenced Vtables", "symbol-interface", "vtables no constructor or destructor stores, and what does", { run: "text", args: ["xref", "-vtables", "-n", "0", file] }),
          t("identical", "Identical Functions", "files", "functions the linker could have folded, by saving", { run: "text", args: ["xref", "-identical", "-n", "0", file] }),
        ],
        has
      ),
    },
    {
      label: "Inside",
      icon: "search",
      tools: keep(
        [
          t("query", "Query Symbols…", "filter", "filter, group, and sort the symbols (name~'^std::' group by compiland)", { run: "text", ask: "query" }),
          t("types", "Type Layouts", "symbol-structure", "classes and structures by the bytes their padding wastes", { run: "text", args: ["types", "-n", "200", file] }),
          t("layout", "A Type's Layout…", "symbol-field", "each base, vfptr, member, and hole of one type", { run: "text", ask: "type" }),
          t("inlines", "Inlined Functions", "fold", "functions by the bytes their inlined copies take", { run: "text", args: ["inlines", "-n", "200", file] }),
          t("sourcefiles", "Code by Source File", "file-code", "code bytes by the source file (and line) they came from", { run: "text", args: ["sourcefiles", "-n", "200", file] }),
          t("annotations", "Annotations", "tag", "strings the code attached to addresses (__annotation)", { run: "text", args: ["annotations", file] }),
          t("disassemble", "Disassemble…", "code", "a function's code, by blocks", { run: "disassemble", ask: "function" }),
          t("checksec", "Hardening", "shield", "the exploit mitigations it was built with, and the inputs built without them", { run: "text", args: ["checksec", file] }),
          t("audit", "Build Options Audit", "checklist", "the compilers and options its parts were built with, and the parts that differ", { run: "text", args: ["checksec", "-audit", file] }),
          t("dump", "Headers", "list-tree", "the file's headers, as dumpbin, readelf, or otool show them", { run: "text", args: ["dump", "-headers", file] }),
          t("dwarf", "Debug Information", "symbol-namespace", "its DWARF: units, lines, and frames, as llvm-dwarfdump shows them", { run: "text", args: ["dwarf", "-summary", file] }),
          t("info", "File Format", "info", "what kind of file it is", { run: "text", args: ["info", file] }),
        ],
        has
      ),
    },
  ];
  return groups.filter((g) => g.tools.length > 0);
}

/**
 * A binary's items in the sidebar (not a diff's: see toolsFor): first
 * what it is (Headers, File Format, Build Information, Debug Information)
 * and the pages of
 * its contents (Symbols, Types), then Compare; and the rest, under
 * Miscellaneous Queries (Recommendations among them, as `recommend`).
 * `caps` is what hexc says the file supports (`hexc info -json`): its
 * tools, and where its debug information is.
 */
function sidebarFor(entry, caps) {
  caps = caps || capsFallback(entry.file);
  const all = toolsFor({ file: entry.file }, caps).flatMap((g) => g.tools);
  const tool = (id) => all.find((t) => t.id === id);
  const file = entry.file;
  const t = (id, label, icon, detail, more) => Object.assign({ id, label, icon, detail }, more);
  const items = [];
  if (tool("dump")) {
    items.push(Object.assign({}, tool("dump"), { label: "Headers" }));
  }
  if (tool("info")) {
    items.push(Object.assign({}, tool("info"), { label: "File Format", detail: "what kind of file it is, and its debug information" }));
  }
  if (tool("checksec")) {
    items.push(t("buildinfo", "Build Information", "tools", "how it was built: its security options, the options its parts differ in, and each object's command line", { run: "buildinfo" }));
  }
  const debug = caps.debug || null;
  if (debug && debug.kind === "pdb" && debug.path) {
    items.push(t("debuginfo", "Debug Information", "symbol-namespace", `its PDB: ${debug.path}`, { run: "text", args: ["pdb", "-summary", debug.path] }));
  } else if (can(caps, "dwarf")) {
    items.push(t("debuginfo", "Debug Information", "symbol-namespace", "its DWARF: units, lines, and frames, as llvm-dwarfdump shows them", { run: "text", args: ["dwarf", "-summary", file] }));
  }
  if (tool("report")) {
    items.push(t("symbols", "Symbols", "symbol-method", "every symbol, by size: grouped, filtered, as a tree or a map", { run: "panel" }));
  }
  if (can(caps, "types")) {
    items.push(t("typesPage", "Types", "symbol-structure", "every class, structure, and union, by size", { run: "types" }));
  }
  if (tool("sourcefiles")) {
    items.push(t("sourcesPage", "Sources", "file-code", "code by the source file it came from, each opening to its symbols", { run: "sources" }));
  }
  if (tool("findings")) {
    items.push(
      Object.assign({}, tool("findings"), {
        label: "Size Reduction Opportunities",
        detail: "build changes, duplicate data, wasteful virtuals, and template families: what could be smaller, and by how much",
      })
    );
  }
  if (tool("compare")) {
    items.push(tool("compare"));
  }
  // The rest: queries, and what could be smaller. (Not those the pages
  // do: Disassemble, a Type's Layout, Query Symbols, Why Is This Here?, and
  // References from the Symbols and Types pages; Hardening and the audit
  // on the Build Information page.)
  // (Not Recommendations and type layouts by padding either: the Findings
  // and Types pages have them; nor code by source file: the Sources page.)
  // (Annotations either: few binaries have any; hexc annotations shows them.)
  const shown = new Set(["report", "compare", "dump", "info", "dwarf", "types", "disassemble", "layout", "query", "why", "refs", "checksec", "audit", "sourcefiles", "findings", "annotations"]);
  const misc = all.filter((x) => !shown.has(x.id));
  return { items, misc };
}

/** Tools whose output (with -json) shows as tables. */
const TABLE_TOOLS = ["xref", "unreachable", "vtables", "identical", "query", "types", "layout", "inlines", "sourcefiles", "annotations", "functionsDiff", "findingsDiff", "typesDiff"];

/** Whether a tool's output shows as tables (else as text). */
function isTable(tool) {
  return TABLE_TOOLS.includes(tool.id);
}

/** A command's arguments with -json (after its command's name). */
function jsonArgs(args) {
  return args.includes("-json") ? args.slice() : [args[0], "-json", ...args.slice(1)];
}

/** The arguments of a tool that asks for something, once it is given. */
function argsWith(tool, entry, answer) {
  switch (tool.id) {
    case "query":
      return ["query", entry.file, answer];
    case "layout":
      return ["types", "-layout", answer, entry.file];
    default:
      return tool.args;
  }
}

/** A document's title for a tool's output. */
function titleOf(tool, entry, answer) {
  const name = baseName(entry.file) + (entry.base ? ` vs ${baseName(entry.base)}` : "");
  return `${tool.label.replace(/…$/, "")}${answer ? ": " + answer : ""} (${name})`;
}

/** The arguments for a symbols list (to pick from): functions, or all. */
function symbolsArgs(file, functionsOnly) {
  const filter = functionsOnly ? "kind=function" : "(kind=function or kind=data or kind=public or kind=string)";
  return ["query", file, `${filter} sort by file desc select name, kind, file, source, line, compiland limit 100000`, "-json"];
}

/**
 * The why-chain (`hexc xref -why -json`) as tree rows: the root, then each
 * step, or why there is none.
 */
function whyRows(why) {
  if (!why.reached) {
    return [{ label: "Nothing reaches it", description: why.comdat ? "(a COMDAT the linker kept)" : "(kept with its section)", icon: "circle-slash" }];
  }
  if (!why.root) {
    return [{ label: "It is a root", description: "", icon: "debug-start" }];
  }
  const rows = [{ label: why.root.name, description: why.root.reason, icon: "debug-start", name: why.root.name }];
  for (const step of why.chain || []) {
    rows.push({ label: step.name, description: step.edge, icon: step.edge.startsWith("call") ? "debug-step-into" : "arrow-right", name: step.name });
  }
  return rows;
}

/** A diff of functions (`hexc xref -json -- base`) in a line. */
function functionsSummary(d) {
  const parts = [];
  const add = (n, what) => n && parts.push(`${n} ${what}`);
  add(d.changedCount, "changed");
  add(d.renamedCount, "renamed");
  add(d.addedCount, "added");
  add(d.removedCount, "removed");
  return parts.length ? parts.join(" · ") : `${d.unchanged} the same`;
}

/**
 * A diff of functions as groups (changed, renamed, added, removed), each
 * with its items as tree rows: a label, a description of the size or its
 * change, an icon and its color, and the name (in the new build, or the
 * base for those removed).
 */
function functionGroups(d) {
  const delta = (n) => (n > 0 ? "+" : "") + formatSize(n);
  const growth = (n) => (n > 0 ? "charts.red" : n < 0 ? "charts.green" : undefined);
  const sum = (list, f) => list.reduce((s, x) => s + f(x), 0);
  const group = (label, icon, color, list, count, item, total) => ({
    label,
    icon,
    color,
    description: `${count}${total !== undefined && count ? `, ${delta(total)}` : ""}`,
    items: list.map(item),
    more: Math.max(0, count - list.length),
  });
  const changed = (d.changed || []).slice().sort((a, b) => Math.abs(b.newSize - b.oldSize) - Math.abs(a.newSize - a.oldSize));
  return [
    group("Changed", "diff-modified", "charts.yellow", changed, d.changedCount || 0, (c) => {
      const n = c.newSize - c.oldSize;
      return {
        name: c.new,
        label: c.new,
        description: `${formatSize(c.oldSize)} → ${formatSize(c.newSize)} (${delta(n)})`,
        icon: n > 0 ? "arrow-up" : n < 0 ? "arrow-down" : "dash",
        color: growth(n),
        tooltip: `${c.new}\n${formatBytes(c.oldSize)} → ${formatBytes(c.newSize)} bytes`,
      };
    }, sum(d.changed || [], (c) => c.newSize - c.oldSize)),
    group("Renamed", "diff-renamed", "charts.blue", d.renamed || [], d.renamedCount || 0, (r) => ({
      name: r.new,
      label: r.new,
      description: `was ${r.old}` + (r.newSize !== r.oldSize ? ` (${delta(r.newSize - r.oldSize)})` : ""),
      icon: "arrow-swap",
      tooltip: `${r.old}\n→ ${r.new}\nthe same code (by fingerprint) under another name`,
    })),
    group("Added", "diff-added", "charts.red", d.added || [], d.addedCount || 0, (a) => ({
      name: a.name,
      label: a.name,
      description: delta(a.size),
      icon: "add",
      color: "charts.red",
    }), sum(d.added || [], (a) => a.size)),
    group("Removed", "diff-removed", "charts.green", d.removed || [], d.removedCount || 0, (r) => ({
      name: r.name,
      label: r.name,
      description: delta(-r.size),
      icon: "remove",
      color: "charts.green",
      removed: true,
    }), -sum(d.removed || [], (r) => r.size)),
  ];
}

/**
 * A path as compared with another: separators and (as Windows does) case
 * made the same.
 */
function samePath(p) {
  return String(p || "").replace(/\//g, "\\").toLowerCase();
}

/**
 * A recorded source path with the first prefix of `maps` (pairs of
 * [recorded, local], as the hexcavator.sourcePathMap setting gives them)
 * that it starts with replaced; else as recorded. Prefixes compare as
 * paths do here: either separator, any case.
 */
function mapSource(p, maps) {
  const s = String(p || "");
  for (const [from, to] of maps || []) {
    if (from && samePath(s).startsWith(samePath(from))) {
      return String(to) + s.slice(String(from).length);
    }
  }
  return s;
}

/** A path's parts (either separator), without empty ones. */
function pathParts(p) {
  return String(p || "")
    .split(/[\\/]+/)
    .filter((x) => x && x !== ".");
}

/**
 * How many trailing parts (directories and the file name) two paths
 * share, by samePath's comparison.
 */
function sharedTail(a, b) {
  const x = pathParts(samePath(a));
  const y = pathParts(samePath(b));
  let n = 0;
  while (n < x.length && n < y.length && x[x.length - 1 - n] === y[y.length - 1 - n]) {
    n++;
  }
  return n;
}

/**
 * Where a recorded source file is on this machine: its path as `maps`
 * maps it, if that exists; else, for a path from another machine (a
 * build server's, a fixed drive like R:), the file under one of `roots`
 * (the workspace's folders, the binary's directories) with the most of
 * its trailing directories, at least its parent's; else `null`.
 * `exists` is for testing.
 */
function localSource(recorded, maps, roots, exists = require("fs").existsSync) {
  const mapped = mapSource(recorded, maps);
  if (mapped && exists(mapped)) {
    return mapped;
  }
  const parts = pathParts(mapped);
  const path = require("path");
  for (let take = parts.length - 1; take >= 2; take--) {
    const tail = parts.slice(parts.length - take);
    for (const root of roots || []) {
      const candidate = path.join(root, ...tail);
      if (exists(candidate)) {
        return candidate;
      }
    }
  }
  return null;
}

/**
 * The functions (query rows with name, file, source, line) whose code
 * starts in the source file `here` (a samePath), by line (largest first
 * at each), skipping those with no bytes (folded). A row's source is
 * `here` if it is (as `maps` maps it); else, if no row's is, the rows
 * whose source shares the most trailing parts with `here`, at least its
 * directory and name (a binary built elsewhere, or on a mapped drive),
 * where `isElsewhere(source)` says the recorded file isn't on this
 * machine.
 */
function functionsByLine(rows, here, maps, isElsewhere) {
  const valid = (rows || []).filter((r) => r.source && r.line && r.file);
  let mine = valid.filter((r) => samePath(mapSource(r.source, maps)) === here);
  if (mine.length === 0 && isElsewhere) {
    const shared = new Map();
    for (const r of valid) {
      if (!shared.has(r.source)) {
        const n = sharedTail(mapSource(r.source, maps), here);
        shared.set(r.source, n >= 3 || (n >= 2 && pathParts(here).length >= 2) ? n : 0);
      }
    }
    const best = Math.max(0, ...shared.values());
    if (best >= 2) {
      const sources = [...shared].filter(([src, n]) => n === best && isElsewhere(mapSource(src, maps))).map(([src]) => src);
      mine = valid.filter((r) => sources.includes(r.source));
    }
  }
  const by = new Map();
  for (const r of mine) {
    if (!by.has(r.line)) {
      by.set(r.line, []);
    }
    by.get(r.line).push(r);
  }
  for (const fns of by.values()) {
    fns.sort((a, b) => b.file - a.file);
  }
  return [...by.entries()].sort((a, b) => a[0] - b[0]);
}

// (Sizes as the report prints them; the same as media/treemap.js's.)
function formatSize(n) {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let v = Math.abs(n);
  let u = 0;
  while (v >= 1024 && u < units.length - 1) {
    v /= 1024;
    u++;
  }
  const digits = u === 0 || v >= 100 ? 0 : v >= 10 ? 1 : 2;
  return (n < 0 ? "-" : "") + v.toFixed(digits) + " " + units[u];
}

function formatBytes(n) {
  return (n < 0 ? "-" : "") + Math.abs(n).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

function percent(part, whole) {
  if (!whole) {
    return "";
  }
  const p = (100 * part) / whole;
  if (p > 0 && p < 0.1) {
    return "<0.1%";
  }
  return p.toFixed(p >= 10 ? 0 : 1) + "%";
}

/**
 * The hexc to run: `configured` (the hexcavator.path setting) if set;
 * else the one the extension's package carries (bin/, in a release
 * VSIX); else the build in the repository this extension is in (release,
 * then debug), so that F5 from the repository runs the hexc just built;
 * else `hexc` on PATH. `exists` is for testing.
 */
function hexcPath(configured, exists = require("fs").existsSync) {
  if (configured) {
    return configured;
  }
  const path = require("path");
  const exe = process.platform === "win32" ? "hexc.exe" : "hexc";
  const bundled = path.join(__dirname, "..", "bin", exe);
  if (exists(bundled)) {
    return bundled;
  }
  for (const build of ["release", "debug"]) {
    const candidate = path.join(__dirname, "..", "..", "..", "..", "target", build, exe);
    if (exists(candidate)) {
      return candidate;
    }
  }
  return "hexc";
}

/**
 * How to start `hexc serve` for the extension's settings (`get(name)`
 * reads one): its arguments (global options first: `--arch`, symbol
 * servers, the symbol cache) and the environment it adds (the symbol
 * directories, as HEXC_SYMBOL_PATH). Nothing is asked of a server unless
 * one is set.
 */
function serveLaunch(get) {
  const args = [];
  const arch = String(get("arch") || "").trim();
  if (arch) {
    args.push("--arch", arch);
  }
  for (const url of [].concat(get("symbolServers") || [])) {
    if (String(url).trim()) {
      args.push("--symbol-server", String(url).trim());
    }
  }
  for (const url of [].concat(get("debuginfod") || [])) {
    if (String(url).trim()) {
      args.push("--debuginfod", String(url).trim());
    }
  }
  const cache = String(get("symbolCache") || "").trim();
  if (cache) {
    args.push("--symbol-cache", cache);
  }
  args.push("serve");
  const env = {};
  const dirs = String(get("symbolPath") || "").trim();
  if (dirs) {
    env.HEXC_SYMBOL_PATH = dirs;
  }
  return { args, env };
}

module.exports = {
  PE,
  hexcPath,
  serveLaunch,
  mapSource,
  localSource,
  sharedTail,
  capsFallback,
  can,
  extOf,
  baseName,
  kindOf,
  quote,
  commandLine,
  nameIs,
  isPath,
  describeRow,
  sortedRows,
  toolsFor,
  sidebarFor,
  argsWith,
  titleOf,
  symbolsArgs,
  whyRows,
  samePath,
  isTable,
  jsonArgs,
  functionsSummary,
  functionGroups,
  functionsByLine,
  formatSize,
  formatBytes,
  percent,
};
