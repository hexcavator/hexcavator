// A type's layout as a tree: each base, vfptr, vbptr, member (bitfields by
// bit), and hole, by offset; a base or member that is a class, structure,
// or union (or an array of them) opens to show its own layout, a layer at
// a time, asked of hexc when first opened (hexc types -ty). Offsets are
// from the start of the outermost type.
"use strict";

(function () {
  const vscode = typeof acquireVsCodeApi === "function" ? acquireVsCodeApi() : null;
  window.__hexcVscode = vscode;
  const post = (m) => vscode && vscode.postMessage(m);
  const $ = (id) => document.getElementById(id);

  const state = {
    file: null,
    layout: null,
    // Layouts asked for and given, by type reference; open rows' keys.
    layouts: new Map(),
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

  const label = (p) => (p.kind === "member" ? p.name : `[${p.kind}]`);
  const at = (offset, p) => (p.bit != null ? `${offset}.${p.bit}` : String(offset));
  const extent = (p) => (p.bits != null ? `:${p.bits}` : String(p.size));

  /** A layout's parts, by offset (then bit). */
  const parts = (l) => [...(l.parts || [])].sort((a, b) => a.offset - b.offset || (a.bit || 0) - (b.bit || 0));

  function toggle(key, ty) {
    if (state.open.has(key)) {
      state.open.delete(key);
    } else {
      state.open.add(key);
      if (!state.layouts.has(ty) && !state.asked.has(ty)) {
        state.asked.add(ty);
        post({ command: "expand", ty });
      }
    }
    renderTree();
  }

  /** The rows shown: each open row's parts below it, at its offset. */
  function rows() {
    const out = [];
    const walk = (layout, base, depth, prefix, seen) => {
      for (const [k, p] of parts(layout).entries()) {
        const key = `${prefix}/${k}`;
        const open = p.expand != null && state.open.has(key);
        out.push({ p, offset: base + p.offset, depth, key, open });
        if (open) {
          const inner = state.layouts.get(p.expand);
          if (!inner) {
            out.push({ loading: true, depth: depth + 1, key: key + "/…" });
          } else if (!seen.includes(p.expand)) {
            walk(inner, base + p.offset, depth + 1, key, [...seen, p.expand]);
          }
        }
      }
    };
    walk(state.layout, 0, 0, "", []);
    return out;
  }

  function render() {
    const l = state.layout;
    const name = (state.file || "").split(/[\\/]/).pop();
    $("header").replaceChildren(
      el("div", { class: "title" }, el("span", { class: "name" }, (l.union ? "union " : "") + l.name), el("span", { class: "path", title: state.file }, name)),
      el(
        "div",
        { class: "chips" },
        el("span", { class: "chip" }, el("b", {}, "Size "), `${l.size.toLocaleString()} B`),
        el("span", { class: "chip" + (l.waste ? " grows" : "") }, el("b", {}, "Padding "), l.incomplete ? "unknown" : `${l.waste.toLocaleString()} B`)
      )
    );
    $("toolbar").replaceChildren(
      el("span", { class: "here" }, "Layout"),
      el("span", { class: "level" }, "by offset; open a base or member to see its own"),
      el("span", { class: "spacer" }),
      el("a", { href: "#", onclick: (e) => { e.preventDefault(); state.open.clear(); renderTree(); } }, "Collapse all")
    );
    renderTree();
  }

  function renderTree() {
    const tbody = el("tbody");
    for (const r of rows()) {
      if (r.loading) {
        tbody.append(el("tr", {}, el("td"), el("td"), el("td", { class: "tname muted" }, el("span", { class: "indent" }, indent(r.depth)), "…"), el("td")));
        continue;
      }
      const p = r.p;
      const twisty =
        p.expand != null
          ? el(
              "span",
              {
                class: "twisty",
                role: "button",
                "aria-label": r.open ? "Collapse" : "Expand",
                onclick: (e) => {
                  e.stopPropagation();
                  toggle(r.key, p.expand);
                },
              },
              r.open ? "▾" : "▸"
            )
          : el("span", { class: "twisty leaf" });
      const hole = p.kind === "padding" || p.kind === "tail padding" || p.kind === "bit padding";
      const tr = el(
        "tr",
        {
          class: (r.key === state.selected ? "selected" : "") + (hole ? " hole" : ""),
          "aria-expanded": p.expand != null ? String(r.open) : undefined,
          onclick: () => {
            state.selected = r.key;
            for (const x of tbody.querySelectorAll("tr.selected")) {
              x.classList.remove("selected");
            }
            tr.classList.add("selected");
          },
          ondblclick: () => p.expand != null && toggle(r.key, p.expand),
        },
        el("td", { class: "n" }, at(r.offset, p)),
        el("td", { class: "n" }, extent(p)),
        el("td", { class: "tname" }, el("span", { class: "indent" }, indent(r.depth)), twisty, el("span", { class: "label" + (hole ? " muted" : "") }, label(p))),
        el("td", { class: "mono type", title: p.type || "" }, p.type || "")
      );
      tbody.append(tr);
    }
    const table = el(
      "table",
      { class: "rows tree layout" },
      el("thead", {}, el("tr", {}, el("th", { class: "n" }, "Offset"), el("th", { class: "n" }, "Size"), el("th", {}, "Part"), el("th", {}, "Type"))),
      tbody
    );
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
      if (!state.layout) {
        $("header").replaceChildren(el("div", { class: "title" }, el("span", { class: "name" }, "hexc failed")), el("div", { class: "path" }, m.message || ""));
      }
      return;
    }
    if (m.kind === "layout") {
      state.file = m.file;
      state.layout = m.layout;
      render();
    } else if (m.kind === "inner") {
      state.layouts.set(m.ty, m.layout || { parts: [] });
      renderTree();
    }
  });
})();
