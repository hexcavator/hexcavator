// The Initialization page: what runs when a binary is loaded, before its
// main (hexc init -json), as a list in the order it runs: each phase (TLS
// callbacks, the entry point, the CRT's lists, .init_array, ...) with its
// functions, each opening to what it calls, and what those call, asked of
// hexc as they're opened (hexc init -callees). A function whose source is
// known opens there (double-click); its context menu disassembles it, says
// why it's there, and what refers to it.
"use strict";

(function () {
  const vscode = typeof acquireVsCodeApi === "function" ? acquireVsCodeApi() : null;
  window.__hexcVscode = vscode;
  const post = (m) => vscode && vscode.postMessage(m);
  const $ = (id) => document.getElementById(id);

  const state = {
    file: null,
    data: null,
    // Callees asked for and given, by node; rows open, by key.
    callees: new Map(),
    asked: new Set(),
    open: new Set(),
    selected: null,
  };

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

  const base = (p) => (p || "").split(/[\\/]/).pop();

  /** A function's rows: it, then (open) what it calls, and so on. */
  function rows() {
    const out = [];
    const add = (f, key, depth, chain, number) => {
      const recursive = f.node != null && chain.includes(f.node);
      const expandable = f.node != null && f.callees > 0 && !recursive;
      const open = expandable && state.open.has(key);
      out.push({ f, key, depth, number, open, expandable, recursive });
      if (open) {
        const list = state.callees.get(f.node);
        if (!list) {
          out.push({ loading: true, key: key + "/…", depth: depth + 1 });
        } else {
          list.forEach((c, i) => add(c, `${key}/${i}`, depth + 1, [...chain, f.node], null));
        }
      }
    };
    state.data.phases.forEach((p, pi) => {
      out.push({ phase: p, key: `p${pi}` });
      p.entries.forEach((e, i) => add(e, `p${pi}/${i}`, 1, [], p.entries.length > 1 ? i + 1 : null));
    });
    if (state.data.main) {
      out.push({ phase: { name: "Then the program's own code", detail: "" }, key: "main" });
      add(state.data.main, "main/0", 1, [], null);
    }
    return out;
  }

  function toggle(r) {
    if (r.open) {
      state.open.delete(r.key);
    } else {
      state.open.add(r.key);
      if (!state.callees.has(r.f.node) && !state.asked.has(r.f.node)) {
        state.asked.add(r.f.node);
        post({ command: "callees", node: r.f.node });
      }
    }
    renderTree();
  }

  function render() {
    const d = state.data;
    const functions = d.phases.reduce((n, p) => n + p.entries.length, 0);
    $("header").replaceChildren(
      el("div", { class: "title" }, el("span", { class: "name" }, base(state.file)), el("span", { class: "path", title: state.file }, state.file)),
      el(
        "div",
        { class: "chips" },
        el("span", { class: "chip" }, d.library ? "a library: what runs when it's loaded" : "what runs before main"),
        el("span", { class: "chip" }, `${d.phases.length} phase${d.phases.length === 1 ? "" : "s"}`),
        el("span", { class: "chip" }, `${functions} function${functions === 1 ? "" : "s"} called`)
      )
    );
    $("toolbar").replaceChildren(
      el("span", { class: "here" }, "Initialization"),
      el("span", { class: "level" }, "in the order it runs; open a function to see what it calls"),
      el("span", { class: "spacer" }),
      el("a", { href: "#", onclick: (e) => { e.preventDefault(); state.open.clear(); renderTree(); } }, "Collapse all")
    );
    renderTree();
  }

  function renderTree() {
    const tbody = el("tbody");
    for (const r of rows()) {
      if (r.phase) {
        tbody.append(
          el(
            "tr",
            { class: "phase" },
            el("td", { colspan: 2 }, el("span", { class: "phasename" }, r.phase.name), r.phase.detail ? el("span", { class: "muted" }, `  ${r.phase.detail}`) : null)
          )
        );
        continue;
      }
      if (r.loading) {
        tbody.append(el("tr", {}, el("td", { class: "tname muted" }, el("span", { class: "indent" }, indent(r.depth)), "…"), el("td")));
        continue;
      }
      const f = r.f;
      const twisty = r.expandable
        ? el("span", { class: "twisty", role: "button", "aria-label": r.open ? "Collapse" : "Expand", onclick: (e) => { e.stopPropagation(); toggle(r); } }, r.open ? "▾" : "▸")
        : el("span", { class: "twisty leaf" });
      const place = f.file ? `${base(f.file)}${f.line ? ":" + f.line : ""}` : "";
      const tr = el(
        "tr",
        {
          class: r.key === state.selected ? "selected" : "",
          "data-key": r.key,
          "data-vscode-context": f.node != null ? JSON.stringify({ webviewSection: "symbol", file: state.file, name: f.name, symbolKind: "code", canQuery: true, preventDefaultContextMenuItems: true }) : undefined,
          onclick: () => {
            state.selected = r.key;
            for (const x of tbody.querySelectorAll("tr.selected")) {
              x.classList.remove("selected");
            }
            tr.classList.add("selected");
          },
          ondblclick: () => {
            if (f.file) {
              post({ command: "openSource", file: f.file, line: f.line || 1 });
            } else if (r.expandable) {
              toggle(r);
            }
          },
        },
        el(
          "td",
          { class: "tname" },
          el("span", { class: "indent" }, indent(r.depth)),
          twisty,
          r.number ? el("span", { class: "muted" }, `${r.number}  `) : null,
          r.depth > 1 ? el("span", { class: "muted" }, f.jump ? "jumps to " : "calls ") : null,
          el("span", { class: "label" }, f.name),
          r.recursive ? el("span", { class: "muted" }, "  (recursion)") : null
        ),
        el("td", { class: "where mono muted", title: f.file ? `${f.file}${f.line ? ":" + f.line : ""}  ·  ${f.address}` : f.address }, place || f.address)
      );
      tbody.append(tr);
    }
    const table = el("table", { class: "rows tree init" }, el("thead", {}, el("tr", {}, el("th", {}, "Function"), el("th", {}, "Source"))), tbody);
    const main = $("main");
    const old = main.querySelector(".treewrap");
    const top = old ? old.scrollTop : 0;
    const wrap = el("div", { class: "treewrap" }, table);
    main.replaceChildren(wrap);
    wrap.scrollTop = top;
  }

  function indent(depth) {
    const out = [];
    for (let i = 0; i < depth; i++) {
      out.push(el("span", { class: "guide none" }));
    }
    return out;
  }

  window.addEventListener("message", (e) => {
    const m = e.data;
    if (!m || !m.kind) {
      return;
    }
    if (m.kind === "failed") {
      $("header").replaceChildren(el("div", { class: "title" }, el("span", { class: "name" }, "hexc failed")), el("div", { class: "path" }, m.message || ""));
      return;
    }
    if (m.kind === "init") {
      state.file = m.file;
      state.data = m.data;
      // The phases' functions open a level, to begin.
      state.data.phases.forEach((p, pi) => p.entries.forEach((_, i) => state.open.add(`p${pi}/${i}`)));
      for (const p of state.data.phases) {
        for (const f of p.entries) {
          if (f.node != null && f.callees > 0 && !state.asked.has(f.node)) {
            state.asked.add(f.node);
            post({ command: "callees", node: f.node });
          }
        }
      }
      render();
    } else if (m.kind === "callees") {
      state.callees.set(m.node, m.callees || []);
      renderTree();
    }
  });
  post({ command: "ready" });
})();
