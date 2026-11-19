// The Relocations page: what the loader patches when it loads a binary
// (hexc relocations -json): its relocation tables, then the relocations
// by type, by the section and the data (or code) each patches, and by what
// each points to; and the tables of pointers that offsets could replace.
// Each is a card with a sortable table; sizes are each relocation's share
// of its table's bytes.
"use strict";

(function () {
  const vscode = typeof acquireVsCodeApi === "function" ? acquireVsCodeApi() : null;
  window.__hexcVscode = vscode;
  const post = (m) => vscode && vscode.postMessage(m);
  const $ = (id) => document.getElementById(id);

  const state = { file: null, report: null };

  function el(tag, attrs, ...children) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === undefined || v === null || v === false) {
        continue;
      }
      if (k === "class") {
        e.className = v;
      } else if (k.startsWith("on")) {
        e.addEventListener(k.slice(2), v);
      } else {
        e.setAttribute(k, v === true ? "" : v);
      }
    }
    for (const c of children.flat()) {
      if (c !== undefined && c !== null && c !== false) {
        e.append(c instanceof Node ? c : document.createTextNode(String(c)));
      }
    }
    return e;
  }

  // (Sizes as the report prints them.)
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
  const size = (n) => ({ text: formatSize(n), sort: n, title: `${n} bytes` });
  const count = (n) => ({ text: n.toLocaleString(), sort: n });

  /** A card: its title, what it shows, its total, and a sortable table. */
  function card(title, summary, chip, head, rows, numeric, open) {
    const columns = head.map((h, i) => ({ label: h, numeric: i < numeric }));
    const table = rows.length ? sortableTable(columns, rows, { sort: { col: 0, desc: true } }) : el("p", { class: "none" }, "None.");
    return el(
      "details",
      { class: "card" + (rows.length ? "" : " empty"), open: open || undefined },
      el("summary", {}, el("h2", {}, title), chip ? el("span", { class: "chip" }, chip) : null),
      el("p", {}, summary),
      table
    );
  }

  function render() {
    const r = state.report;
    const file = state.file || "";
    $("header").replaceChildren(
      el("div", { class: "title" }, el("span", { class: "name" }, file.split(/[\\/]/).pop()), el("span", { class: "path", title: file }, file)),
      el(
        "div",
        { class: "chips" },
        el("span", { class: "chip" }, el("b", {}, "Relocations "), count(r.count).text),
        el("span", { class: "chip" }, el("b", {}, "Tables "), formatSize(r.bytes))
      )
    );
    $("toolbar").replaceChildren(el("span", { class: "here" }, "Relocations"), el("span", { class: "level" }, "what the loader patches when it loads it, and what that costs"));
    // (The cards scroll in the page's main area, as the Size Reduction
    // page's do below its map.)
    const main = $("main");
    main.style.overflow = "auto";
    main.style.padding = "10px 14px 12px";
    if (!r.count) {
      main.replaceChildren(el("p", { class: "none" }, "No relocations: the loader patches nothing."));
      return;
    }
    const rows = (list) => (list || []).map((x) => [size(x.bytes), count(x.count), x.name]);
    const from =
      r.symbolsFrom === "debug" ? "the debug information's symbols (and the symbol table's, where it has none)" : "the image's symbol table (no debug information was found)";
    main.replaceChildren(
      card(
        "Tables",
        "The tables the loader reads, and what each relocation in them costs.",
        formatSize(r.bytes),
        ["Size", "Entries", "Each", "Table"],
        (r.tables || []).map((t) => [size(t.size), count(t.entries), { text: t.entries ? (t.size / t.entries).toFixed(2) : "", sort: t.entries ? t.size / t.entries : 0 }, t.name]),
        3,
        true
      ),
      card("By type", "Each kind of relocation: relative ones move with the image; the rest are resolved by a symbol's name.", null, ["Size", "Count", "Type"], rows(r.types), 2, true),
      card("By section", "The section each patches: those pages are written as the image loads, and so aren't shared with other processes.", null, ["Size", "Count", "Section"], rows(r.sections), 2, true),
      card("By what each patches", `The data (or code) each is in, from ${from}: tables of pointers and vtables, mostly.`, null, ["Size", "Count", "Symbol"], rows(r.symbols), 2, true),
      card("By what each points to", "The symbol each binds, or where its target is: strings, functions, vtables.", null, ["Size", "Count", "Target"], rows(r.targets), 2, false),
      card(
        "Pointer tables",
        `Data holding pointers that 32-bit offsets (from the table, or into one blob of strings) could replace: each pointer costs its relocation${r.word > 4 ? ", and 4 bytes more than an offset" : ""}.`,
        formatSize((r.pointerTables || []).reduce((n, t) => n + t.relocationBytes + t.narrowerBytes, 0)),
        ["Saving", "Pointers", "Table"],
        (r.pointerTables || []).map((t) => [size(t.relocationBytes + t.narrowerBytes), count(t.pointers), t.name]),
        2,
        false
      )
    );
  }

  window.addEventListener("message", (e) => {
    const m = e.data;
    if (!m || !m.kind) {
      return;
    }
    if (m.kind === "failed") {
      if (!state.report) {
        $("header").replaceChildren(el("div", { class: "title" }, el("span", { class: "name" }, "hexc failed")), el("div", { class: "path" }, m.message || ""));
      }
      return;
    }
    if (m.kind === "relocations") {
      state.file = m.file;
      state.report = m.report;
      render();
    }
  });
  post({ command: "ready" });
})();
