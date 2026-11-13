// A tool's output as tables (hexc ... -json): its numbers as a summary,
// each list as a sortable table with a filter, names that open their
// symbols, and source paths that open their files. A query's view has
// its query to edit and run again.
"use strict";

(function () {
  const vscode = typeof acquireVsCodeApi === "function" ? acquireVsCodeApi() : null;
  window.__hexcVscode = vscode;
  const post = (m) => vscode && vscode.postMessage(m);
  const $ = (id) => document.getElementById(id);
  const state = { message: null, filter: "" };

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
    for (const c of children.flat(Infinity)) {
      if (c !== undefined && c !== null && c !== false) {
        e.append(c instanceof Node ? c : document.createTextNode(String(c)));
      }
    }
    return e;
  }

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

  // Columns whose values name a symbol (to open), or a source file.
  const NAME_KEYS = ["name", "new", "old", "class", "family", "function"];
  const PATH_KEYS = ["file", "source"];
  const isPath = (v) => typeof v === "string" && (/^[A-Za-z]:[\\/]/.test(v) || v.startsWith("/"));

  function cell(row, col) {
    const v = row[col.key];
    const m = state.message;
    if (col.size && typeof v === "number") {
      return { text: formatSize(v), sort: v, title: `${v.toLocaleString()} bytes` };
    }
    if (typeof v === "number") {
      return { text: v.toLocaleString(), sort: v };
    }
    const text = cellText(v);
    if (m.pe && NAME_KEYS.includes(col.key) && typeof v === "string" && v && !/^\[/.test(v)) {
      const link = el(
        "a",
        {
          href: "#",
          class: "sym",
          title: `Open ${v} (code or data); right-click for more`,
          onclick: (e) => {
            e.preventDefault();
            post({ command: "inspect", name: v });
          },
        },
        v
      );
      return { text, node: link, sort: text };
    }
    if (PATH_KEYS.includes(col.key) && isPath(v)) {
      const line = typeof row.line === "number" ? row.line : 1;
      const link = el(
        "a",
        {
          href: "#",
          title: `Open ${v}${row.line ? ":" + row.line : ""}`,
          onclick: (e) => {
            e.preventDefault();
            post({ command: "openSource", file: v, line });
          },
        },
        v.replace(/^.*[\\/]/, "")
      );
      return { text: v, node: link, sort: v, title: v };
    }
    // Addresses as written; other paths by their file name (in full on hover).
    if (/^0x[0-9a-f]+$/i.test(text)) {
      return { text, sort: parseInt(text, 16), cls: "hex" };
    }
    if (isPath(v)) {
      return { text: v.replace(/^.*[\\/]/, ""), sort: v, title: v };
    }
    return { text, sort: text };
  }

  /** What VS Code's context menu needs for a row: its symbol, if any. */
  function rowContext(row) {
    const m = state.message;
    const name = NAME_KEYS.map((k) => row[k]).find((v) => typeof v === "string" && v);
    return JSON.stringify({
      webviewSection: m.pe && name ? "symbol" : "row",
      symbolKind: "any",
      peImage: !!m.pe,
      canQuery: !!m.pe,
      canData: !!m.pe,
      file: m.file,
      name: name || "",
      preventDefaultContextMenuItems: true,
    });
  }

  function matches(row, columns, filter) {
    if (!filter) {
      return true;
    }
    const f = filter.toLowerCase();
    return columns.some((c) => cellText(row[c.key]).toLowerCase().includes(f));
  }

  function csv(table) {
    const q = (s) => (/[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s);
    const lines = [table.columns.map((c) => q(c.label)).join(",")];
    for (const r of table.rows) {
      lines.push(table.columns.map((c) => q(cellText(r[c.key]))).join(","));
    }
    return lines.join("\n") + "\n";
  }

  function render() {
    const m = state.message;
    if (!m) {
      return;
    }
    $("header").replaceChildren(
      el("div", { class: "title" }, el("span", { class: "name" }, m.title), el("span", { class: "path", title: m.file }, String(m.file || "").replace(/^.*[\\/]/, ""))),
      el(
        "div",
        { class: "actions" },
        vscode ? el("button", { class: "icon", title: "This command's output as text", onclick: () => post({ command: "openText" }) }, "Open as Text") : null,
        vscode ? el("button", { class: "icon", title: "Copy the command line", onclick: () => post({ command: "copy", text: m.command, what: "the command line" }) }, "Copy Command") : null,
        vscode ? el("button", { class: "icon", title: "Run hexc again", onclick: () => post({ command: "refresh" }) }, "⟳") : null
      )
    );
    const query =
      m.query !== undefined
        ? el(
            "span",
            { class: "query" },
            el("input", {
              id: "query",
              type: "text",
              value: m.query,
              placeholder: "kind=function file>4k group by compiland sort by file desc limit 50",
              title: "A filter (name~'^std::' and kind=data), then group by, sort by, select, limit: Enter runs it",
              onkeydown: (e) => {
                if (e.key === "Enter") {
                  post({ command: "query", query: e.target.value });
                }
              },
            }),
            el("button", { class: "icon", onclick: () => post({ command: "query", query: $("query").value }) }, "Run")
          )
        : null;
    $("toolbar").replaceChildren(
      ...[
        query,
        el("input", {
          id: "filter",
          type: "search",
          placeholder: "Filter rows…",
          value: state.filter,
          oninput: (e) => {
            state.filter = e.target.value;
            renderBody();
          },
        }),
        el("code", { class: "cmd muted", title: m.command }, m.command),
      ].filter(Boolean)
    );
    renderBody();
  }

  function renderBody() {
    const m = state.message;
    const body = $("body");
    body.replaceChildren();
    if (m.error) {
      body.append(el("pre", { class: "note error" }, m.error));
      return;
    }
    const { summary, tables } = tablesOf(m.json);
    if (summary.length) {
      body.append(
        el(
          "div",
          { class: "chips" },
          summary.map((s) =>
            el("span", { class: "chip" }, el("b", {}, s.label + " "), s.size && typeof s.value === "number" ? formatSize(s.value) : typeof s.value === "number" ? s.value.toLocaleString() : cellText(s.value))
          )
        )
      );
    }
    for (const t of tables) {
      const rows = t.rows.filter((r) => matches(r, t.columns, state.filter));
      const first = t.columns.findIndex((c) => c.size);
      const table = rows.length
        ? sortableTable(
            t.columns.map((c) => ({ label: c.label, numeric: c.numeric })),
            rows.map((r) => Object.assign(t.columns.map((c) => cell(r, c)), { raw: r })),
            {
              sort: first >= 0 ? { col: first, desc: true } : undefined,
              onrow: (tr, cells) => tr.setAttribute("data-vscode-context", rowContext(cells.raw)),
            }
          )
        : el("p", { class: "note" }, t.rows.length ? "No rows match the filter." : "None.");
      body.append(
        el(
          "section",
          { class: "tsection" },
          el(
            "div",
            { class: "tablebar" },
            el("h2", {}, t.title || "Rows"),
            el("span", { class: "muted" }, rows.length === t.rows.length ? `${t.rows.length} rows` : `${rows.length} of ${t.rows.length} rows`),
            el("span", { class: "spacer" }),
            vscode && t.rows.length ? el("a", { href: "#", onclick: (e) => { e.preventDefault(); post({ command: "copy", text: csv({ columns: t.columns, rows }), what: "the table as CSV" }); } }, "Copy as CSV") : null
          ),
          table
        )
      );
    }
    if (!tables.length && !summary.length) {
      body.append(el("pre", { class: "code text" }, JSON.stringify(m.json, null, 2)));
    }
  }

  window.addEventListener("message", (e) => {
    const m = e.data;
    if (!m || m.kind !== "table") {
      return;
    }
    state.message = m;
    render();
  });
})();
