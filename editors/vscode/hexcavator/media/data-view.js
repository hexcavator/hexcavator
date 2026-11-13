// The data view: a datum's value read as its type (hexc data -json), as a
// tree beside its bytes as a debugger shows memory (db/dw/dd/dq). The two
// are linked: a member's bytes light up as it is pointed at, and a byte's
// member. Pointers are links to what they point into.
"use strict";

(function () {
  const vscode = typeof acquireVsCodeApi === "function" ? acquireVsCodeApi() : null;
  window.__hexcVscode = vscode;
  const post = (m) => vscode && vscode.postMessage(m);
  const $ = (id) => document.getElementById(id);
  const state = { message: null, mode: "both", unit: 1, open: new Set([""]), sel: null };
  const saved = vscode && vscode.getState();
  if (saved) {
    Object.assign(state, { mode: saved.mode || "both", unit: saved.unit || 1 });
  }
  const save = () => vscode && vscode.setState({ mode: state.mode, unit: state.unit });

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

  const data = () => state.message.data;
  const bytes = () => {
    const hex = data().bytes || "";
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) {
      out[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return out;
  };
  const hexAddr = (n) => BigInt(data().address) + BigInt(n);
  const fmtAddr = (a) => a.toString(16).padStart(16, "0");

  // ------------------------------------------------------------- the tree

  /** Each value with its path (a key), depth, and parent's key. */
  function flatten(root) {
    const out = [];
    const walk = (v, key, depth) => {
      out.push({ v, key, depth });
      if (v.children && state.open.has(key)) {
        v.children.forEach((c, i) => walk(c, key + "/" + i, depth + 1));
        if (v.elided) {
          out.push({ v: { name: `… ${v.elided} more`, kind: "elided", offset: v.offset, size: 0, text: "" }, key: key + "/more", depth: depth + 1 });
        }
      }
    };
    walk(root, "", 0);
    return out;
  }

  /** The leaf values (no children), for finding a byte's member. */
  function leaves(root) {
    const out = [];
    const walk = (v, key) => {
      if (v.children && v.children.length) {
        v.children.forEach((c, i) => walk(c, key + "/" + i));
      } else {
        out.push({ v, key });
      }
    };
    walk(root, "");
    return out;
  }

  /** What a pointer's target names, as a symbol to open (without +offset). */
  const symbolOf = (target) => String(target || "").replace(/\+0x[0-9a-f]+$/i, "");

  function targetLink(target) {
    return el(
      "a",
      {
        class: "target",
        href: "#",
        title: `Open ${symbolOf(target)}`,
        onclick: (e) => {
          e.preventDefault();
          e.stopPropagation();
          post({ command: "inspect", name: symbolOf(target) });
        },
      },
      target
    );
  }

  function renderTree(box) {
    const root = data().value;
    if (!root) {
      box.append(el("p", { class: "note" }, "No type for this datum in the PDB (a public, a string, or a compiler's table): its bytes only."));
      return;
    }
    const rows = flatten(root);
    const table = el(
      "table",
      { class: "vtree" },
      el("thead", {}, el("tr", {}, el("th", {}, "Name"), el("th", {}, "Value"), el("th", {}, "Type"), el("th", { class: "n" }, "Offset"), el("th", { class: "n" }, "Size")))
    );
    const body = el("tbody");
    for (const r of rows) {
      const v = r.v;
      const open = state.open.has(r.key);
      const twisty = v.children && v.children.length ? el("span", { class: "twisty", onclick: (e) => { e.stopPropagation(); toggle(r.key); } }, open ? "▾" : "▸") : el("span", { class: "twisty leaf" });
      const label = v.kind === "padding" ? "(padding)" : v.name || v.type || "";
      const bits = v.bits ? el("span", { class: "muted" }, ` :${v.bits[1]} @bit ${v.bits[0]}`) : null;
      const value = [v.text ? el("span", { class: "val k-" + v.kind }, v.text) : null, v.target ? [" ", targetLink(v.target)] : null];
      const tr = el(
        "tr",
        {
          class: "k-" + v.kind + (state.sel === r.key ? " selected" : ""),
          "data-key": r.key,
          onmouseenter: () => lightBytes(v.offset, v.size),
          onmouseleave: () => lightBytes(-1, 0),
          onclick: () => {
            state.sel = r.key;
            render();
          },
          ondblclick: () => v.children && toggle(r.key),
        },
        el("td", { class: "vname" }, el("span", { class: "indent" }, " ".repeat(r.depth * 3)), twisty, el("span", { class: "label" }, label), bits),
        el("td", { class: "vval" }, value),
        el("td", { class: "vtype muted" }, v.name ? v.type : ""),
        el("td", { class: "n muted" }, "+" + Number(v.offset).toString(16)),
        el("td", { class: "n muted" }, v.size ? String(v.size) : "")
      );
      body.append(tr);
    }
    table.append(body);
    box.append(
      el(
        "div",
        { class: "tablebar" },
        el("a", { href: "#", onclick: (e) => { e.preventDefault(); expandAll(root, "", 0); render(); } }, "Expand all"),
        el("a", { href: "#", onclick: (e) => { e.preventDefault(); state.open = new Set([""]); render(); } }, "Collapse all")
      ),
      table
    );
  }

  function expandAll(v, key, n) {
    if (n > 4000 || !v.children) {
      return n;
    }
    state.open.add(key);
    v.children.forEach((c, i) => {
      n = expandAll(c, key + "/" + i, n + 1);
    });
    return n;
  }

  function toggle(key) {
    if (state.open.has(key)) {
      state.open.delete(key);
    } else {
      state.open.add(key);
    }
    render();
  }

  // -------------------------------------------------------------- the hex

  function renderHex(box) {
    const b = bytes();
    const unit = state.unit;
    const pointers = new Map();
    for (const p of data().pointers || []) {
      for (let i = 0; i < p.size; i++) {
        pointers.set(p.offset + i, p);
      }
    }
    const selected = state.sel !== null ? findByKey(state.sel) : null;
    const rows = el("div", { class: "hex" });
    for (let line = 0; line < b.length; line += 16) {
      const cells = [];
      for (let i = line; i < Math.min(line + 16, b.length); i += unit) {
        // A unit's bytes, little-endian, as one number.
        let text = "";
        for (let k = Math.min(unit, b.length - i) - 1; k >= 0; k--) {
          text += b[i + k].toString(16).padStart(2, "0");
        }
        const p = pointers.get(i);
        const inSel = selected && i >= selected.offset && i < selected.offset + Math.max(selected.size, 1);
        cells.push(
          el(
            "span",
            {
              class: "b" + (p ? " ptr" : "") + (inSel ? " sel" : "") + ((i - line) === 8 && unit < 8 ? " gap" : ""),
              "data-off": String(i),
              title: p ? `+${i.toString(16)}: → ${p.target}${p.name ? " " + p.name : ""}` : `+${i.toString(16)}`,
              onmouseenter: () => lightMember(i),
              onmouseleave: () => lightMember(-1),
              onclick: () => {
                if (p && p.name) {
                  post({ command: "inspect", name: symbolOf(p.name) });
                }
              },
            },
            text
          )
        );
      }
      const ascii = Array.from(b.slice(line, line + 16), (x) => (x >= 0x20 && x < 0x7f ? String.fromCharCode(x) : ".")).join("");
      rows.append(el("div", { class: "hrow" }, el("span", { class: "addr" }, fmtAddr(hexAddr(line))), el("span", { class: "cells u" + unit }, cells), el("span", { class: "ascii" }, ascii)));
    }
    box.append(rows);
    const ps = data().pointers || [];
    if (ps.length) {
      box.append(
        el(
          "div",
          { class: "ptrs" },
          el("h3", {}, `Pointers (${ps.length}, from base relocations)`),
          ps.map((p) => el("div", { class: "prow" }, el("span", { class: "muted" }, "+" + p.offset.toString(16).padEnd(6)), " ", el("span", { class: "num" }, p.target), " ", p.name ? targetLink(p.name) : el("span", { class: "muted" }, "(no symbol)")))
        )
      );
    }
    if (data().read < data().size) {
      box.append(el("p", { class: "note" }, `The first ${data().read} of ${data().size} bytes.`));
    }
  }

  function findByKey(key) {
    let v = data().value;
    if (!v) {
      return null;
    }
    for (const part of key.split("/").slice(1)) {
      v = v.children && v.children[Number(part)];
      if (!v) {
        return null;
      }
    }
    return v;
  }

  function lightBytes(offset, size) {
    for (const c of document.querySelectorAll(".hex .b.hot")) {
      c.classList.remove("hot");
    }
    if (offset < 0) {
      return;
    }
    for (const c of document.querySelectorAll(".hex .b")) {
      const o = Number(c.getAttribute("data-off"));
      if (o + state.unit > offset && o < offset + Math.max(size, 1)) {
        c.classList.add("hot");
      }
    }
  }

  let leafCache = null;
  function lightMember(offset) {
    for (const r of document.querySelectorAll(".vtree tr.hot")) {
      r.classList.remove("hot");
    }
    const info = $("byteinfo");
    if (offset < 0 || !data().value) {
      if (info) {
        info.textContent = "";
      }
      return;
    }
    leafCache = leafCache || leaves(data().value);
    // The deepest value holding the byte: its row (if shown) and its path.
    const hit = leafCache.filter((l) => l.v.size > 0 && offset >= l.v.offset && offset < l.v.offset + l.v.size).pop();
    if (!hit) {
      return;
    }
    let key = hit.key;
    while (key && !document.querySelector(`.vtree tr[data-key="${key}"]`)) {
      key = key.slice(0, key.lastIndexOf("/"));
    }
    const row = document.querySelector(`.vtree tr[data-key="${key}"]`);
    if (row) {
      row.classList.add("hot");
    }
    if (info) {
      info.textContent = `+${offset.toString(16)}: ${pathOf(hit.key)}${hit.v.text ? " = " + hit.v.text : ""}`;
    }
  }

  function pathOf(key) {
    let v = data().value;
    const names = [];
    for (const part of key.split("/").slice(1)) {
      v = v.children[Number(part)];
      names.push(v.kind === "padding" ? "(padding)" : v.name.startsWith("[") ? v.name : (names.length ? "." : "") + v.name);
    }
    return names.join("").replace(/^\./, "") || data().name;
  }

  // ----------------------------------------------------------------- page

  function render() {
    const m = state.message;
    if (!m) {
      return;
    }
    if (m.error) {
      $("header").replaceChildren(el("div", { class: "title" }, el("span", { class: "name" }, m.name || "")));
      $("toolbar").replaceChildren();
      $("body").replaceChildren(el("p", { class: "note error" }, m.error));
      return;
    }
    const d = data();
    leafCache = null;
    $("header").replaceChildren(
      el("div", { class: "title" }, el("span", { class: "name", title: d.name }, d.name), el("span", { class: "path", title: m.file }, String(m.file).replace(/^.*[\\/]/, ""))),
      el("div", { class: "facts muted" }, [d.section, `${d.size} bytes`, d.fileSize < d.size ? `${d.fileSize} in the file` : null, d.address, d.value ? d.value.type : d.kind].filter(Boolean).join(" · ")),
      el(
        "div",
        { class: "actions" },
        vscode ? el("button", { class: "icon", title: "Copy the bytes as hex", onclick: () => post({ command: "copy", text: d.bytes }) }, "Copy Bytes") : null,
        vscode ? el("button", { class: "icon", title: "Run hexc again", onclick: () => post({ command: "refresh" }) }, "⟳") : null
      )
    );
    const seg = (options, value, onchange, title) =>
      el("span", { class: "segmented", title }, options.map(([v, label]) => el("button", { class: v === value ? "on" : "", onclick: () => onchange(v) }, label)));
    $("toolbar").replaceChildren(
      seg([["both", "Both"], ["typed", "Typed"], ["hex", "Hex"]], state.mode, (v) => { state.mode = v; save(); render(); }, "What to show"),
      state.mode !== "typed" ? seg([[1, "db"], [2, "dw"], [4, "dd"], [8, "dq"]], state.unit, (v) => { state.unit = v; save(); render(); }, "Bytes, words, doublewords, or quadwords (little-endian)") : null,
      el("span", { class: "spacer" }),
      el("span", { id: "byteinfo", class: "muted" })
    );
    const body = $("body");
    body.replaceChildren();
    body.className = "mode-" + state.mode;
    if (state.mode !== "hex") {
      const box = el("div", { class: "pane typed" });
      renderTree(box);
      body.append(box);
    }
    if (state.mode !== "typed") {
      const box = el("div", { class: "pane hexpane" });
      renderHex(box);
      body.append(box);
    }
  }

  window.addEventListener("message", (e) => {
    const m = e.data;
    if (!m || m.kind !== "data") {
      return;
    }
    state.message = m;
    state.open = new Set([""]);
    state.sel = null;
    render();
  });
})();
