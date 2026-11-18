// The trace editor's view: a summary, the tree's settings, and the stack
// tree as a table whose rows are drawn only where they show. Every
// request goes to the extension, which asks the engine.
"use strict";
(function () {
  const vscode = acquireVsCodeApi();
  const { TreeModel, formatWeight, markdownTable } = globalThis.StackrabbitTree;
  const { Graph } = globalThis.StackrabbitGraph;
  const ROW = 22;

  const $ = (id) => document.getElementById(id);
  const summaryEl = $("summary");
  const statusEl = $("status");
  const symbolsEl = $("symbols");
  const viewport = $("viewport");
  const spacer = $("spacer");
  const rowsEl = $("rows");
  const controls = {
    source: $("source"),
    group: $("group"),
    frames: $("frames"),
    invert: $("invert"),
  };

  let model = null;
  let selection = null; // [startNs, endNs], or null for all of it
  // A function the stack tree is of (its callers, or callees): {fn, label}.
  let focus = null;
  const selectionEl = $("selection");
  /** Says what is selected (a time range, or all of the trace). */
  function showSelection() {
    const range = selection;
    selectionEl.textContent = range
      ? `Selected ${(range[0] / 1e9).toFixed(3)} s to ${(range[1] / 1e9).toFixed(3)} s ` +
        `(${((range[1] - range[0]) / 1e9).toFixed(3)} s). Double-click the graph to clear.`
      : "All of the trace. Drag across the graph to select a time range; double-click it to clear.";
  }
  const graph = new Graph($("graph"), $("legend"), (range) => selectTime(range), $("graph-tip"));
  /** Selects `range` (null: all of the trace), and everything follows. */
  function selectTime(range) {
    selection = range;
    graph.selection = range;
    graph.draw();
    showSelection();
    saveState();
    createTree();
    loadProcesses();
    loadFunctions();
    loadDisk();
    loadFileIo();
    if (listedKind) {
      loadEventList(listedKind);
    }
  }
  let view = null; // the engine's view ID
  let unit = "samples";
  let ticksPerSecond = 10000000;
  let selected = -1; // index in the visible rows
  let generation = 0; // ignores answers for an older tree

  // Requests to the engine, through the extension.
  let nextId = 1;
  const pending = new Map();
  function request(method, params) {
    const id = nextId++;
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject });
      vscode.postMessage({ type: "request", id, method, params });
    });
  }

  window.addEventListener("message", (e) => {
    const m = e.data;
    if (m.type === "response") {
      const w = pending.get(m.id);
      if (w) {
        pending.delete(m.id);
        if (m.error !== undefined) {
          w.reject(new Error(m.error));
        } else {
          w.resolve(m.result);
        }
      }
    } else if (m.type === "opened") {
      showSummary(m.summary, m.opened);
      // Where this trace was left, if it was opened before.
      restoreState(m.state);
      createTree();
      loadGraph();
      loadProcesses();
    } else if (m.type === "notification" && m.method === "symbols") {
      symbolsNote(m.params);
    } else if (m.type === "failed") {
      statusEl.textContent = m.error;
      statusEl.classList.add("error");
    }
  });

  function showSummary(s, opened) {
    const secs = (s.durationNs / 1e9).toFixed(2);
    const how = opened.how === "index" ? "opened from its index" : "imported";
    summaryEl.textContent =
      `${secs} s · ${s.processors} processors · ${s.processes} processes · ` +
      `${s.samples.toLocaleString("en-US")} samples · ${s.switches.toLocaleString("en-US")} switches · ` +
      `${how} in ${opened.seconds.toFixed(2)} s`;
    // What the recording lost: the trace is missing some of what happened.
    const lost = [];
    if (s.eventsLost) {
      lost.push(`${s.eventsLost.toLocaleString("en-US")} events`);
    }
    if (s.buffersLost) {
      lost.push(`${s.buffersLost.toLocaleString("en-US")} buffers`);
    }
    $("lost").textContent = lost.length
      ? `The recording lost ${lost.join(" and ")}: some events and stacks are missing.`
      : "";
  }

  /** Shows how the symbols' download goes; when it is done, makes the tree
   * again, with the new names. */
  function symbolsNote(p) {
    // (The Symbols tab, if it shows, follows.)
    loadSymbols();
    if (p.loaded !== undefined) {
      // PDBs loaded: the tree again, with their names.
      if (p.loaded > 0 && model) {
        createTree();
      }
      if (!symbolsEl.textContent) {
        symbolsEl.textContent = `Symbols: ${p.loaded} of ${p.wanted} loaded`;
      }
      return;
    }
    const have = p.cached + p.downloaded;
    if (!p.done) {
      symbolsEl.textContent = `Symbols: ${have + p.missing} of ${p.wanted}…`;
      return;
    }
    symbolsEl.textContent = `Symbols: ${have} of ${p.wanted}` + (p.missing ? ` (${p.missing} not found)` : "");
  }

  function spec() {
    const group = controls.group.value === "" ? [] : controls.group.value.split(",");
    const s = {
      source: controls.source.value,
      groupBy: group,
      frames: controls.frames.value,
      invert: controls.invert.checked,
    };
    if (selection) {
      s.time = selection;
    }
    if (focus) {
      s.focus = focus.fn;
    }
    return s;
  }

  // Tables of rows sorted by a column (click a heading; again for the
  // other way): the processes, and the threads of the one clicked.
  const number = (digits) => (v) => (v === null ? "" : v.toLocaleString("en-US", { maximumFractionDigits: digits }));
  const at = (before) => (v) => (v === null ? before : (v / 1e9).toFixed(3) + " s");
  class SortedTable {
    /**
     * A table in `el` of `columns` ({key, title, num?, cls?, text?(value)}),
     * sorted by `sortBy` ({key, down}); `onPick(row)` hears of a row clicked.
     */
    constructor(el, columns, sortBy, onPick) {
      this.el = el;
      this.columns = columns;
      this.sortBy = sortBy;
      this.rows = [];
      this.picked = null; // a row's `pick` key
      el.addEventListener("click", (e) => {
        const th = e.target.closest("th");
        if (th) {
          const key = th.dataset.key;
          const down = this.sortBy.key === key ? !this.sortBy.down : typeof this.rows[0]?.[key] !== "string";
          this.sortBy = { key, down };
          this.draw();
          return;
        }
        const tr = e.target.closest("tbody tr");
        if (tr && onPick) {
          const row = this.sorted[Number(tr.dataset.i)];
          onPick(row);
        }
      });
    }

    set(rows) {
      this.rows = rows;
      this.draw();
    }

    /** The table as it is sorted, as Markdown. */
    markdown() {
      const cells = (r) => this.columns.map((c) => (c.text ? c.text(r[c.key]) : r[c.key]));
      return markdownTable(
        this.columns.map((c) => c.title),
        (this.sorted || []).map(cells),
        this.columns.map((c) => !!c.num)
      );
    }

    draw() {
      const k = this.sortBy.key;
      this.sorted = [...this.rows].sort((a, b) => {
        const x = a[k] === null || a[k] === undefined ? -Infinity : a[k];
        const y = b[k] === null || b[k] === undefined ? -Infinity : b[k];
        const c = typeof x === "string" && typeof y === "string" ? x.localeCompare(y) : x < y ? -1 : x > y ? 1 : 0;
        return this.sortBy.down ? -c : c;
      });
      const head = this.columns
        .map((c) => {
          const mark = c.key === k ? (this.sortBy.down ? " ▾" : " ▴") : "";
          return `<th class="${c.num ? "num" : ""}" data-key="${c.key}">${c.title}${mark}</th>`;
        })
        .join("");
      const body = this.sorted
        .map((r, i) => {
          const cls = this.picked !== null && r.pick === this.picked ? ' class="selected"' : "";
          const cells = this.columns
            .map((c) => {
              const v = c.text ? c.text(r[c.key]) : r[c.key];
              return `<td class="${c.num ? "num" : c.cls || ""}">${escape(v === null || v === undefined ? "" : v)}</td>`;
            })
            .join("");
          return `<tr data-i="${i}"${cls}>${cells}</tr>`;
        })
        .join("");
      this.el.innerHTML = `<thead><tr>${head}</tr></thead><tbody>${body}</tbody>`;
    }
  }

  const processesTable = new SortedTable(
    $("processes"),
    [
      { key: "name", title: "Process" },
      { key: "pid", title: "ID", num: true },
      { key: "cpuMs", title: "CPU (ms)", num: true, text: number(1) },
      { key: "samples", title: "Samples", num: true, text: number(0) },
      { key: "threads", title: "Threads", num: true },
      { key: "startNs", title: "Started", num: true, text: at("before") },
      { key: "endNs", title: "Ended", num: true, text: at("after") },
      { key: "commandLine", title: "Command line", cls: "cmd" },
    ],
    { key: "samples", down: true },
    (row) => {
      processesTable.picked = row.pick;
      processesTable.draw();
      loadThreads();
      if ($("graph-by").value === "picked") {
        loadGraph();
      }
    }
  );
  const threadsTable = new SortedTable(
    $("threads"),
    [
      { key: "tid", title: "Thread", num: true },
      { key: "name", title: "Name" },
      { key: "cpuMs", title: "CPU (ms)", num: true, text: number(1) },
      { key: "samples", title: "Samples", num: true, text: number(0) },
      { key: "runningMs", title: "Running (ms)", num: true, text: number(1) },
      { key: "switches", title: "Switches in", num: true, text: number(0) },
      { key: "startNs", title: "Started", num: true, text: at("before") },
      { key: "endNs", title: "Ended", num: true, text: at("after") },
      { key: "startAddress", title: "Start address", cls: "cmd" },
    ],
    { key: "samples", down: true }
  );
  const threadsTitle = $("threads-title");

  async function loadProcesses() {
    try {
      const params = selection ? { time: selection } : {};
      const rows = (await request("processes", params)).rows;
      processesTable.set(rows.map((r) => ({ ...r, pick: r.index })));
      if (processesTable.picked !== null) {
        loadThreads();
      }
    } catch (e) {
      statusEl.textContent = e.message;
      statusEl.classList.add("error");
    }
  }

  /** The threads of the process picked, in the selected time range. */
  async function loadThreads() {
    const index = processesTable.picked;
    const p = processesTable.rows.find((r) => r.index === index);
    if (!p) {
      return;
    }
    try {
      const params = { process: index };
      if (selection) {
        params.time = selection;
      }
      const rows = (await request("threads", params)).rows;
      threadsTitle.textContent = `Threads of ${p.name} (${p.pid})`;
      threadsTable.set(rows);
    } catch (e) {
      statusEl.textContent = e.message;
      statusEl.classList.add("error");
    }
  }

  // The hot functions and modules: what the tree weighs, by function
  // (or module, or address: as Frames says), in the selected time range.
  // Loaded while their tab shows; otherwise when it next does.
  let functionsUnit = "samples";
  let functionsTps = 10000000;
  let functionsStale = true;
  const weight = (v) => formatWeight(v, functionsUnit, functionsTps);
  const percent = (v) => v.toFixed(1) + "%";
  const weightColumns = [
    { key: "exclusive", title: "Self", num: true, text: weight },
    { key: "selfPct", title: "Self %", num: true, text: percent },
    { key: "inclusive", title: "Inclusive", num: true, text: weight },
    { key: "inclusivePct", title: "Inclusive %", num: true, text: percent },
  ];
  const functionsTable = new SortedTable(
    $("functions"),
    [{ key: "label", title: "Function" }, { key: "module", title: "Module" }, ...weightColumns],
    { key: "exclusive", down: true },
    // Clicking a function highlights it in the graph (again: stops).
    (row) => {
      highlight(row);
      functionsTable.picked = lit ? row.pick : null;
      functionsTable.draw();
    }
  );
  const modulesTable = new SortedTable($("modules"), [{ key: "label", title: "Module" }, ...weightColumns], {
    key: "exclusive",
    down: true,
  });

  async function loadFunctions() {
    if ($("functions-pane").classList.contains("hidden")) {
      functionsStale = true;
      return;
    }
    functionsStale = false;
    try {
      const params = { source: controls.source.value, frames: controls.frames.value };
      if (selection) {
        params.time = selection;
      }
      const f = await request("functions", params);
      functionsUnit = f.unit;
      functionsTps = f.ticksPerSecond;
      const share = (rows) =>
        rows.map((r) => ({
          ...r,
          selfPct: f.total ? (100 * r.exclusive) / f.total : 0,
          inclusivePct: f.total ? (100 * r.inclusive) / f.total : 0,
        }));
      const shown = f.functions.length < f.functionCount ? ` (the heaviest ${f.functions.length.toLocaleString("en-US")})` : "";
      $("functions-title").textContent = `${f.functionCount.toLocaleString("en-US")} functions${shown}`;
      functionsTable.set(share(f.functions).map((r) => ({ ...r, pick: r.fn })));
      modulesTable.set(share(f.modules));
    } catch (e) {
      statusEl.textContent = e.message;
      statusEl.classList.add("error");
    }
  }

  // The symbols report: each PDB the stacks need, and what became of it.
  const symbolsTable = new SortedTable(
    $("symbols-table"),
    [
      { key: "pdb", title: "PDB" },
      { key: "status", title: "Status" },
      { key: "frames", title: "Frames", num: true, text: number(0) },
      { key: "download", title: "Download" },
      { key: "identity", title: "Identity", cls: "cmd" },
    ],
    { key: "frames", down: true }
  );
  const noDebugTable = new SortedTable(
    $("no-debug"),
    [
      { key: "module", title: "Module" },
      { key: "frames", title: "Frames", num: true, text: number(0) },
    ],
    { key: "frames", down: true }
  );

  async function loadSymbols() {
    if ($("symbols-pane").classList.contains("hidden")) {
      return;
    }
    try {
      const r = await request("symbols", {});
      if (!r.ready) {
        $("symbols-title").textContent = "Counting the frames the stacks need…";
        return;
      }
      const count = (s) => r.rows.filter((x) => x.status === s).length;
      $("symbols-title").textContent =
        `${r.rows.length} PDBs: ${count("saved") + count("loaded")} with names ` +
        `(${count("saved")} saved with the trace), ${count("not found")} not found` +
        (r.done ? "" : ", still looking") +
        `. Cache: ${r.cache}`;
      symbolsTable.set(r.rows);
      $("no-debug-title").textContent = r.noDebug.length
        ? `${r.noDebug.length} modules with no PDB identity (no symbols can be found for them)`
        : "";
      noDebugTable.set(r.noDebug);
    } catch (e) {
      statusEl.textContent = e.message;
      statusEl.classList.add("error");
    }
  }

  let tab = "stacks";
  // Every kind of event in the trace (all of it: imported or not).
  const eventsTable = new SortedTable(
    $("events"),
    [
      { key: "provider", title: "Provider" },
      { key: "event", title: "Event" },
      { key: "id", title: "ID", num: true },
      { key: "opcode", title: "Opcode", num: true },
      { key: "version", title: "Version", num: true },
      { key: "count", title: "Count", num: true, text: number(0) },
      { key: "bytes", title: "Bytes", num: true, text: number(0) },
      { key: "firstNs", title: "First", num: true, text: at("") },
      { key: "lastNs", title: "Last", num: true, text: at("") },
      { key: "guid", title: "Provider GUID", cls: "cmd" },
    ],
    { key: "count", down: true },
    (row) => {
      eventsTable.picked = row.pick;
      eventsTable.draw();
      loadEventList(row);
    }
  );
  // The kind of event picked: its events listed (in the time selected).
  let listedKind = null;
  async function loadEventList(kind) {
    listedKind = kind;
    const title = $("event-list-title");
    title.textContent = `Reading the trace for ${kind.provider || kind.guid} ${kind.event || ""}…`;
    try {
      const params = { guid: kind.guid, id: kind.id, version: kind.version, opcode: kind.opcode, limit: 1000, stacks: true };
      if (selection) {
        params.time = selection;
      }
      const r = await request("events.list", params);
      if (listedKind !== kind) {
        return;
      }
      const shown = r.rows.length < r.total ? `the first ${r.rows.length.toLocaleString("en-US")} of ` : "";
      title.textContent = `${kind.provider || kind.guid} ${kind.event || ""}: ${shown}${r.total.toLocaleString("en-US")} events${selection ? " in the time selected" : ""}`;
      // A table of its own (its columns are the kind's fields).
      const table = document.createElement("table");
      table.id = "event-list";
      table.className = "processes";
      $("event-list-holder").replaceChildren(table);
      const columns = [
        { key: "timeNs", title: "Time", num: true, text: (v) => (v / 1e9).toFixed(6) + " s" },
        { key: "cpu", title: "CPU", num: true },
        { key: "process", title: "Process" },
        { key: "pid", title: "PID", num: true },
        { key: "tid", title: "TID", num: true },
        ...r.columns.map((c, i) => ({ key: `f${i}`, title: c })),
      ];
      const rows = r.rows.map((x, i) => {
        const o = { timeNs: x.timeNs, cpu: x.cpu, process: x.process, pid: x.pid, tid: x.tid, stack: x.stack, pick: i };
        for (const [name, value] of x.fields) {
          o[`f${r.columns.indexOf(name)}`] = value;
        }
        return o;
      });
      const stackColumn = { key: "frames", title: "Stack", num: true };
      if (rows.some((x) => x.stack)) {
        columns.splice(5, 0, stackColumn);
        for (const x of rows) {
          x.frames = x.stack ? x.stack.length : null;
        }
      }
      $("event-stack").textContent = "";
      // Clicking an event: its stack, innermost frame first.
      eventListTable = new SortedTable(table, columns, { key: "timeNs", down: false }, (row) => {
        eventListTable.picked = row.pick;
        eventListTable.draw();
        $("event-stack").textContent = row.stack
          ? `Stack (innermost first):\n${row.stack.join("\n")}`
          : "This event has no stack.";
      });
      eventListTable.set(rows);
    } catch (e) {
      title.textContent = e.message;
    }
  }
  let eventListTable = null;
  let eventsLoaded = false;
  async function loadEvents() {
    if (eventsLoaded) {
      return;
    }
    try {
      const r = await request("events", {});
      eventsLoaded = true;
      const total = r.rows.reduce((a, x) => a + x.count, 0);
      $("events-title").textContent =
        `${total.toLocaleString("en-US")} events of ${r.rows.length.toLocaleString("en-US")} kinds, in all of the trace`;
      eventsTable.set(r.rows.map((x) => ({ ...x, pick: `${x.guid}/${x.id}/${x.version}/${x.opcode}/${x.task}` })));
    } catch (e) {
      statusEl.textContent = e.message;
      statusEl.classList.add("error");
    }
  }

  // Regions of interest (the regions file is a setting): each region's
  // count and time, and the instances; clicking one selects its time.
  const ms = (ns) => (ns / 1e6).toLocaleString("en-US", { maximumFractionDigits: 3 });
  const regionsTable = new SortedTable(
    $("regions"),
    [
      { key: "path", title: "Region" },
      { key: "count", title: "Instances", num: true, text: number(0) },
      { key: "totalNs", title: "Total (ms)", num: true, text: ms },
      { key: "unpairedStarts", title: "Unstopped", num: true },
      { key: "unpairedStops", title: "Unstarted", num: true },
      { key: "unsupported", title: "Not supported", cls: "cmd" },
    ],
    { key: "path", down: false }
  );
  const instancesTable = new SortedTable(
    $("region-instances"),
    [
      { key: "region", title: "Region" },
      { key: "name", title: "Name" },
      { key: "startNs", title: "Start", num: true, text: at("") },
      { key: "durationNs", title: "Duration (ms)", num: true, text: ms },
      { key: "pid", title: "PID", num: true },
      { key: "tid", title: "TID", num: true },
    ],
    { key: "startNs", down: false },
    (row) => {
      instancesTable.picked = row.pick;
      instancesTable.draw();
      selectTime([row.startNs, Math.max(row.stopNs, row.startNs + 1)]);
    }
  );
  let regionsLoaded = false;
  async function loadRegions() {
    if (regionsLoaded) {
      return;
    }
    try {
      const r = await request("regions", {});
      regionsLoaded = true;
      const path = (i) => {
        const parts = [];
        for (let at = i; at !== null && at !== undefined; at = r.regions[at].parent) {
          parts.unshift(r.regions[at].displayName);
        }
        return parts.join(" / ");
      };
      regionsTable.set(r.regions.map((x, i) => ({ ...x, path: path(i) })));
      $("regions-title").textContent = `${r.regions.length} regions`;
      instancesTable.set(r.instances.map((x, i) => ({ ...x, region: path(x.region), pick: i })));
      $("region-instances-title").textContent =
        `${r.instances.length.toLocaleString("en-US")} instances${r.truncated ? " (the first)" : ""}: click one to select its time`;
    } catch (e) {
      $("regions-title").textContent = /expected a regions file/.test(e.message)
        ? "Set stackrabbit.regionsFile to a regions-of-interest file (WPA's format) to see its regions here."
        : e.message;
    }
  }

  // Disk usage: totals grouped as chosen, and the heaviest I/Os, in the
  // time selected. Loaded while the tab shows; otherwise when it next does.
  const kb = (v) => (v / 1024).toLocaleString("en-US", { maximumFractionDigits: 1 });
  const diskGroups = new SortedTable(
    $("disk-groups"),
    [
      { key: "label", title: "Group" },
      { key: "count", title: "I/Os", num: true, text: number(0) },
      { key: "bytes", title: "KB", num: true, text: kb },
      { key: "ioNs", title: "I/O time (ms)", num: true, text: ms },
      { key: "serviceNs", title: "Service time (ms)", num: true, text: ms },
    ],
    { key: "serviceNs", down: true }
  );
  const diskIos = new SortedTable(
    $("disk-ios"),
    [
      { key: "kind", title: "Type" },
      { key: "process", title: "Process" },
      { key: "tid", title: "TID", num: true },
      { key: "file", title: "File", cls: "cmd" },
      { key: "disk", title: "Disk", num: true },
      { key: "size", title: "KB", num: true, text: kb },
      { key: "completeNs", title: "Completed", num: true, text: at("") },
      { key: "ioNs", title: "I/O time (ms)", num: true, text: ms },
      { key: "serviceNs", title: "Service time (ms)", num: true, text: ms },
    ],
    { key: "serviceNs", down: true }
  );
  let diskStale = true;
  async function loadDisk() {
    if ($("disk-pane").classList.contains("hidden")) {
      diskStale = true;
      return;
    }
    diskStale = false;
    $("disk-title").textContent = "Reading the trace's disk I/O…";
    try {
      const params = { by: $("disk-by").value, limit: 1000 };
      if (selection) {
        params.time = selection;
      }
      const d = await request("disk", params);
      $("disk-title").textContent =
        `${d.count.toLocaleString("en-US")} disk I/Os, ${kb(d.bytes)} KB${selection ? " in the time selected" : ""}.`;
      diskGroups.set(d.groups);
      diskIos.set(d.ios);
    } catch (e) {
      $("disk-title").textContent = e.message;
    }
  }
  $("disk-by").addEventListener("change", loadDisk);

  // File I/O: totals grouped as chosen, and the longest operations, in the
  // time selected. Loaded while the tab shows; otherwise when it next does.
  const fileGroups = new SortedTable(
    $("fileio-groups"),
    [
      { key: "label", title: "Group" },
      { key: "count", title: "Operations", num: true, text: number(0) },
      { key: "bytes", title: "KB", num: true, text: kb },
      { key: "durationNs", title: "Duration (ms)", num: true, text: ms },
    ],
    { key: "durationNs", down: true }
  );
  const fileOps = new SortedTable(
    $("fileio-ops"),
    [
      { key: "op", title: "Operation" },
      { key: "process", title: "Process" },
      { key: "tid", title: "TID", num: true },
      { key: "file", title: "File", cls: "cmd" },
      { key: "size", title: "KB", num: true, text: kb },
      { key: "startNs", title: "Started", num: true, text: at("") },
      { key: "durationNs", title: "Duration (ms)", num: true, text: ms },
      { key: "status", title: "Status" },
    ],
    { key: "durationNs", down: true }
  );
  let fileStale = true;
  async function loadFileIo() {
    if ($("fileio-pane").classList.contains("hidden")) {
      fileStale = true;
      return;
    }
    fileStale = false;
    $("fileio-title").textContent = "Reading the trace's file I/O…";
    try {
      const params = { by: $("fileio-by").value, limit: 1000 };
      if (selection) {
        params.time = selection;
      }
      const d = await request("fileio", params);
      $("fileio-title").textContent =
        `${d.count.toLocaleString("en-US")} file operations, ${kb(d.bytes)} KB read or written` +
        `${selection ? " in the time selected" : ""}` +
        `${d.unended ? ` (${d.unended.toLocaleString("en-US")} not ended in the trace)` : ""}.`;
      fileGroups.set(d.groups);
      fileOps.set(d.ops);
    } catch (e) {
      $("fileio-title").textContent = e.message;
    }
  }
  $("fileio-by").addEventListener("change", loadFileIo);

  function showTab(name) {
    tab = name;
    saveState();
    if (name === "events") {
      loadEvents();
    }
    if (name === "regions") {
      loadRegions();
    }
    for (const t of ["stacks", "processes", "functions", "symbols", "events", "regions", "disk", "fileio"]) {
      $(`tab-${t}`).classList.toggle("active", name === t);
      $(`${t}-pane`).classList.toggle("hidden", name !== t);
    }
    if (name === "stacks") {
      requestAnimationFrame(draw);
    }
    if (name === "functions" && functionsStale) {
      loadFunctions();
    }
    if (name === "symbols") {
      loadSymbols();
    }
    // (After the pane shows: it loads only if it does.)
    if (name === "disk" && diskStale) {
      loadDisk();
    }
    if (name === "fileio" && fileStale) {
      loadFileIo();
    }
  }
  $("tab-symbols").addEventListener("click", () => showTab("symbols"));
  $("tab-events").addEventListener("click", () => showTab("events"));
  $("tab-regions").addEventListener("click", () => showTab("regions"));
  $("tab-disk").addEventListener("click", () => showTab("disk"));
  $("tab-fileio").addEventListener("click", () => showTab("fileio"));
  symbolsEl.addEventListener("click", () => showTab("symbols"));
  /**
   * The shown tab as Markdown, to the clipboard (by way of the extension):
   * the stack tree's selected row and the rows open under it (or every
   * row shown), or the tab's tables as they are sorted.
   */
  function copy() {
    let text = "";
    let what = "";
    if (!$("stacks-pane").classList.contains("hidden")) {
      if (!model) {
        return;
      }
      const visible = model.visible();
      const rows = selected >= 0 && visible[selected] ? model.subtree(visible[selected].id) : visible;
      text = model.markdown(rows, (v) => formatWeight(v, unit, ticksPerSecond));
      what = `${rows.length} rows`;
    } else if (!$("functions-pane").classList.contains("hidden")) {
      text = functionsTable.markdown() + "\n" + modulesTable.markdown();
      what = "the functions and modules";
    } else if (!$("symbols-pane").classList.contains("hidden")) {
      text = symbolsTable.markdown();
      what = "the symbols";
    } else if (!$("events-pane").classList.contains("hidden")) {
      text = eventsTable.markdown() + (eventListTable ? "\n" + eventListTable.markdown() : "");
      what = "the events";
    } else {
      text = processesTable.markdown();
      what = "the processes";
      if (processesTable.picked !== null) {
        text += "\n" + threadsTable.markdown();
        what += " and threads";
      }
    }
    vscode.postMessage({ type: "copy", text, what });
  }
  $("copy").addEventListener("click", copy);
  $("highlight").addEventListener("click", () => {
    if (model) {
      highlight(model.visible()[selected]);
    }
    viewport.focus();
  });
  // Ctrl+C (or Cmd+C) copies the tab, unless text is selected.
  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "c" && !String(window.getSelection() || "")) {
      e.preventDefault();
      copy();
    }
  });

  $("tab-stacks").addEventListener("click", () => showTab("stacks"));
  $("tab-processes").addEventListener("click", () => showTab("processes"));
  $("tab-functions").addEventListener("click", () => showTab("functions"));

  // A function (or module) highlighted in the graph: its ID and label.
  let lit = null;
  /** Highlights `row`'s function in the graph (or stops, if it is). */
  function highlight(row) {
    if (!row || !row.fn) {
      return;
    }
    lit = lit && lit.fn === row.fn ? null : { fn: row.fn, label: row.label };
    saveState();
    loadGraph();
  }

  /**
   * The view's settings, for the extension to keep with the trace (so it
   * reopens where it was left): what the tree weighs and groups by, its
   * frames, callers or not, the tab, the time selected and the function
   * highlighted.
   */
  function saveState() {
    vscode.postMessage({
      type: "state",
      state: {
        source: controls.source.value,
        group: controls.group.value,
        frames: controls.frames.value,
        invert: controls.invert.checked,
        tab,
        selection,
        lit,
        graphBy: $("graph-by").value,
        focus,
      },
    });
  }

  /** Puts back settings `saveState` kept (those that still make sense). */
  function restoreState(s) {
    if (!s || typeof s !== "object") {
      return;
    }
    for (const k of ["source", "group", "frames"]) {
      const c = controls[k];
      if (typeof s[k] === "string" && [...c.options].some((o) => o.value === s[k])) {
        c.value = s[k];
      }
    }
    controls.invert.checked = s.invert === true;
    if (Array.isArray(s.selection) && s.selection.length === 2 && s.selection.every(Number.isFinite)) {
      selection = s.selection;
      graph.selection = selection;
      showSelection();
    }
    if (s.focus && typeof s.focus.fn === "string") {
      focus = { fn: s.focus.fn, label: String(s.focus.label || s.focus.fn) };
      showFocus();
    }
    if (["process", "thread"].includes(s.graphBy)) {
      $("graph-by").value = s.graphBy;
    }
    if (s.lit && typeof s.lit.fn === "string") {
      lit = { fn: s.lit.fn, label: String(s.lit.label || s.lit.fn) };
    }
    if (["stacks", "processes", "functions", "symbols", "events", "regions", "disk", "fileio"].includes(s.tab)) {
      showTab(s.tab);
    }
  }

  /** Says what the stack tree is of, if a function's callers or callees. */
  function showFocus() {
    $("focus-bar").classList.toggle("hidden", !focus);
    if (focus) {
      $("focus-text").textContent = `${controls.invert.checked ? "Callers" : "Callees"} of ${focus.label}`;
    }
  }

  /** The stack tree of `row`'s function's callers (or none: null). */
  function focusOn(row) {
    focus = row && row.fn ? { fn: row.fn, label: row.label } : null;
    if (focus) {
      controls.invert.checked = true;
      showTab("stacks");
    }
    showFocus();
    saveState();
    createTree();
  }
  $("focus-clear").addEventListener("click", () => focusOn(null));
  controls.invert.addEventListener("change", showFocus);
  // Double-clicking a function: its callers.
  $("functions").addEventListener("dblclick", (e) => {
    const tr = e.target.closest("tbody tr");
    if (tr) {
      focusOn(functionsTable.sorted[Number(tr.dataset.i)]);
    }
  });

  // Hovering a function: a card with its hottest call path (the hot path
  // of its callers' tree), after a moment.
  const card = $("card");
  let cardFor = null;
  let cardTimer = null;
  $("functions").addEventListener("mouseover", (e) => {
    const tr = e.target.closest("tbody tr");
    const row = tr && functionsTable.sorted[Number(tr.dataset.i)];
    if (!row || row === cardFor) {
      return;
    }
    cardFor = row;
    clearTimeout(cardTimer);
    card.classList.add("hidden");
    cardTimer = setTimeout(() => showCard(row, tr), 400);
  });
  $("functions").addEventListener("mouseleave", () => {
    cardFor = null;
    clearTimeout(cardTimer);
    card.classList.add("hidden");
  });

  async function showCard(row, tr) {
    if (!row.fn) {
      return;
    }
    try {
      const s = { ...spec(), groupBy: [], focus: row.fn, invert: true };
      const t = await request("tree.create", s);
      const hot = await request("tree.hotPath", { view: t.view, node: t.root.id, fraction: 0 });
      request("tree.close", { view: t.view }).catch(() => {});
      if (cardFor !== row) {
        return;
      }
      const total = t.root.inclusive || 1;
      const steps = hot.rows.map(
        (r, i) =>
          `<div class="step">${i === 0 ? "" : "\u2190 "}${escape(r.label)} <b>${((100 * r.inclusive) / total).toFixed(1)}%</b></div>`
      );
      card.innerHTML = `<div class="title">Hottest call path to it (its callers, outward):</div>` + steps.join("");
      card.classList.remove("hidden");
      const pane = $("functions-pane");
      const top = tr.offsetTop + tr.offsetHeight + 4 - pane.scrollTop;
      card.style.top = `${top + pane.scrollTop}px`;
      card.style.left = "40px";
    } catch (e) {
      // (A card is a nicety: no card.)
    }
  }

  /** Asks for the graph, as many buckets as it has pixels. */
  async function loadGraph() {
    try {
      const source = controls.source.value === "samples" ? "samples" : "running";
      const params = { source, buckets: graph.plotWidth(), top: 8 };
      if (lit) {
        params.highlight = lit.fn;
      }
      // By process, by thread, or the threads of the process picked in
      // the processes table (by process, until one is).
      const by = $("graph-by").value;
      if (by === "thread") {
        params.by = "thread";
      } else if (by === "picked" && processesTable.picked !== null) {
        params.by = "thread";
        params.process = processesTable.picked;
      }
      graph.set(await request("graph", params), lit && lit.label);
    } catch (e) {
      statusEl.textContent = e.message;
      statusEl.classList.add("error");
    }
  }

  async function createTree() {
    const mine = ++generation;
    statusEl.textContent = "";
    statusEl.classList.remove("error");
    if (view !== null) {
      request("tree.close", { view }).catch(() => {});
      view = null;
    }
    try {
      const t = await request("tree.create", spec());
      if (mine !== generation) {
        return;
      }
      view = t.view;
      unit = t.unit;
      ticksPerSecond = t.ticksPerSecond;
      model = new TreeModel(t.root);
      selected = -1;
      await load(t.root.id, mine);
      if (mine === generation && model.visible().length) {
        select(0);
      }
    } catch (e) {
      statusEl.textContent = e.message;
      statusEl.classList.add("error");
    }
  }

  /** Fetches `id`'s children if they aren't here yet. */
  async function load(id, mine) {
    if (model.hasLoaded(id)) {
      return;
    }
    const r = await request("tree.children", { view, node: id });
    if (mine === generation) {
      model.setChildren(id, r.rows);
      draw();
    }
  }

  async function toggle(index, on) {
    const row = model.visible()[index];
    if (!row) {
      return;
    }
    const want = on === undefined ? !model.isExpanded(row.id) : on;
    const needed = model.setExpanded(row.id, want);
    draw();
    if (needed) {
      await load(row.id, generation);
    }
  }

  /** Expands the hot path under the selected row (or the root). */
  async function hotPath() {
    const mine = generation;
    const start = selected >= 0 ? model.visible()[selected] : null;
    const from = start ? start.id : model.rootId;
    const r = await request("tree.hotPath", { view, node: from, fraction: 0.1 });
    if (mine !== generation) {
      return;
    }
    let parent = from;
    for (const row of r.rows) {
      await load(parent, mine);
      model.setExpanded(parent, true);
      parent = row.id;
    }
    draw();
    const last = r.rows[r.rows.length - 1];
    if (last) {
      select(model.visible().findIndex((v) => v.id === last.id));
    }
  }

  function select(index) {
    const rows = model ? model.visible() : [];
    if (!rows.length) {
      selected = -1;
      draw();
      return;
    }
    selected = Math.max(0, Math.min(rows.length - 1, index));
    // Keep it in view.
    const top = selected * ROW;
    if (top < viewport.scrollTop) {
      viewport.scrollTop = top;
    } else if (top + ROW > viewport.scrollTop + viewport.clientHeight) {
      viewport.scrollTop = top + ROW - viewport.clientHeight;
    }
    draw();
  }

  /** Draws the rows that show (and a few beyond, for smooth scrolling). */
  function draw() {
    if (!model) {
      return;
    }
    const rows = model.visible();
    spacer.style.height = rows.length * ROW + "px";
    const first = Math.max(0, Math.floor(viewport.scrollTop / ROW) - 5);
    const last = Math.min(rows.length, Math.ceil((viewport.scrollTop + viewport.clientHeight) / ROW) + 5);
    const html = [];
    for (let i = first; i < last; i++) {
      const r = rows[i];
      const twisty = r.hasChildren ? (model.isExpanded(r.id) ? "▾" : "▸") : "";
      const cls = i === selected ? "row selected" : "row";
      html.push(
        `<div class="${cls}" data-index="${i}" style="top:${i * ROW}px">` +
          `<span class="name" style="padding-left:${(r.depth - 1) * 14 + 4}px">` +
          `<span class="twisty">${twisty}</span>${escape(r.label)}</span>` +
          `<span class="num">${formatWeight(r.inclusive, unit, ticksPerSecond)}</span>` +
          `<span class="num">${model.share(r)}</span>` +
          `<span class="num">${formatWeight(r.exclusive, unit, ticksPerSecond)}</span>` +
          `</div>`
      );
    }
    rowsEl.innerHTML = html.join("");
  }

  function escape(s) {
    return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
  }

  viewport.addEventListener("scroll", () => requestAnimationFrame(draw));
  let resized = null;
  window.addEventListener("resize", () => {
    requestAnimationFrame(draw);
    // The graph again, at its new width, once the resizing stops.
    clearTimeout(resized);
    resized = setTimeout(() => {
      if (graph.data) {
        loadGraph();
      }
    }, 200);
  });
  rowsEl.addEventListener("click", (e) => {
    const el = e.target.closest(".row");
    if (!el) {
      return;
    }
    const i = Number(el.dataset.index);
    if (e.target.classList.contains("twisty")) {
      toggle(i);
    }
    select(i);
    viewport.focus();
  });
  rowsEl.addEventListener("dblclick", (e) => {
    const el = e.target.closest(".row");
    if (el) {
      toggle(Number(el.dataset.index));
    }
  });
  viewport.addEventListener("keydown", (e) => {
    if (!model) {
      return;
    }
    const rows = model.visible();
    const row = rows[selected];
    switch (e.key) {
      case "ArrowDown":
        select(selected + 1);
        break;
      case "ArrowUp":
        select(selected - 1);
        break;
      case "PageDown":
        select(selected + Math.floor(viewport.clientHeight / ROW));
        break;
      case "PageUp":
        select(selected - Math.floor(viewport.clientHeight / ROW));
        break;
      case "Home":
        select(0);
        break;
      case "End":
        select(rows.length - 1);
        break;
      case "ArrowRight":
        if (row && row.hasChildren && !model.isExpanded(row.id)) {
          toggle(selected, true);
        } else {
          select(selected + 1);
        }
        break;
      case "ArrowLeft":
        if (row && model.isExpanded(row.id)) {
          toggle(selected, false);
        } else if (row) {
          select(rows.findIndex((r) => r.id === row.parent));
        }
        break;
      case "h":
      case "H":
        highlight(row);
        break;
      case "Enter":
        toggle(selected);
        break;
      case "*":
        hotPath();
        break;
      default:
        return;
    }
    e.preventDefault();
  });
  for (const c of Object.values(controls)) {
    c.addEventListener("change", createTree);
    c.addEventListener("change", saveState);
  }
  // The graph shows what the tree weighs: sampled or precise CPU.
  controls.source.addEventListener("change", loadGraph);
  $("graph-by").addEventListener("change", () => {
    saveState();
    loadGraph();
  });
  controls.source.addEventListener("change", loadFunctions);
  controls.frames.addEventListener("change", loadFunctions);
  $("hot").addEventListener("click", () => {
    hotPath();
    viewport.focus();
  });

  vscode.postMessage({ type: "ready" });
})();
