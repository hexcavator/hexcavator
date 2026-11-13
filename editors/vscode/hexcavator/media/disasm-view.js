// The disassembly view: a function's code (hexc size -disassemble -json) as
// a listing (raw), by basic block, with its source lines, or as a graph of
// its blocks. Labels and calls are links; it talks to the extension through
// messages (disassemble, openSource, openText, copy, mode).
"use strict";

(function () {
  const vscode = typeof acquireVsCodeApi === "function" ? acquireVsCodeApi() : null;
  window.__hexcVscode = vscode;
  const post = (m) => vscode && vscode.postMessage(m);
  const $ = (id) => document.getElementById(id);
  const MODES = [
    ["raw", "Raw"],
    ["blocks", "Blocks"],
    ["source", "Source"],
    ["graph", "Graph"],
  ];
  const state = { message: null, mode: "blocks", bytes: false, zoom: 1, flash: null, reg: null };
  const saved = vscode && vscode.getState();
  if (saved) {
    Object.assign(state, { mode: saved.mode || state.mode, bytes: !!saved.bytes, zoom: saved.zoom || 1, vars: saved.vars !== false });
  }
  const save = () => vscode && vscode.setState({ mode: state.mode, bytes: state.bytes, zoom: state.zoom, vars: state.vars });
  if (state.vars === undefined) {
    state.vars = true;
  }

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
  const svgNS = "http://www.w3.org/2000/svg";
  function svg(tag, attrs) {
    const e = document.createElementNS(svgNS, tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      e.setAttribute(k, v);
    }
    return e;
  }

  const listing = () => state.message.listing;
  const hasCode = () => Array.isArray(listing().lines);
  const short = (p) => String(p || "").replace(/^.*[\\/]/, "");
  const hex = (a) => a.replace(/^0x/, "");

  // --------------------------------------------------------------- tokens

  const REG = /^(?:[re]?[abcd]x|[abcd][lh]|[re]?(?:si|di|sp|bp|ip)|sil|dil|spl|bpl|r(?:[89]|1[0-5])[dwb]?|[xyz]mm(?:[12]?\d|3[01])|k[0-7]|[cdefgs]s|st\(\d\)|[wx](?:[12]?\d|30)|[wx]zr|w?sp|[qdshbv](?:[12]?\d|3[01])|lr|fp|nzcv)$/i;

  /** An instruction's text, colored, its labels and its call's callee links. */
  function instruction(line) {
    const m = /^(\S+)(\s*)(.*)$/.exec(line.text) || [line.text, line.text, "", ""];
    const out = [el("span", { class: "mn" + (line.flow !== "next" ? " flow-" + line.flow : "") }, m[1]), m[2]];
    const ops = m[3];
    // A direct call's operand is its callee's name: a link to its code.
    if (line.flow === "call" && line.target && ops && !/^[\[{]/.test(ops) && !/^(?:0x)?[0-9a-f]+h?$/i.test(ops)) {
      out.push(
        el(
          "a",
          {
            class: "callee",
            href: "#",
            title: `Disassemble ${ops}`,
            onclick: (e) => {
              e.preventDefault();
              post({ command: "disassemble", name: ops });
            },
          },
          ops
        )
      );
      return out;
    }
    // Operands: labels, registers, numbers, the rest as is.
    const parts = ops.split(/(\bL\d+\b|[A-Za-z_][\w()]*|#?-?(?:0x[0-9a-fA-F]+|[0-9][0-9a-fA-F]*h|\d+)\b|[\[\],+\-*!{}#])/);
    for (const p of parts) {
      if (!p) {
        continue;
      }
      if (/^L\d+$/.test(p) && labelBlock(p) !== null) {
        out.push(el("a", { class: "lbl", href: "#", onclick: (e) => { e.preventDefault(); goToLabel(p); } }, p));
      } else if (REG.test(p)) {
        out.push(regSpan(p));
      } else if (/^#?-?(?:0x[0-9a-fA-F]+|[0-9][0-9a-fA-F]*h|\d+)$/.test(p)) {
        out.push(el("span", { class: "num" }, p));
      } else {
        out.push(p);
      }
    }
    return out;
  }

  /** A register, by its family: hovering lights every use; a click pins it. */
  function regSpan(name) {
    const family = registerFamily(name);
    return el(
      "span",
      {
        class: "reg" + (state.reg === family ? " pinned" : ""),
        "data-reg": family,
        title: state.reg === family ? "Click to stop highlighting" : `Click to highlight every ${family} (and its parts)`,
        onmouseenter: () => lightRegister(family, "lit"),
        onmouseleave: () => lightRegister(null, "lit"),
        onclick: (e) => {
          e.stopPropagation();
          state.reg = state.reg === family ? null : family;
          lightRegister(state.reg, "pinned");
        },
      },
      name
    );
  }

  function lightRegister(family, cls) {
    for (const r of document.querySelectorAll(".reg." + cls)) {
      r.classList.remove(cls);
    }
    if (family) {
      for (const r of document.querySelectorAll(`.reg[data-reg="${family}"]`)) {
        r.classList.add(cls);
      }
    }
  }

  let labelIndex = new Map();
  function labelBlock(name) {
    return labelIndex.has(name) ? labelIndex.get(name) : null;
  }

  function goToLabel(name) {
    const b = labelBlock(name);
    if (b === null) {
      return;
    }
    state.flash = b;
    const target = document.querySelector(`[data-block="${b}"]`);
    if (target) {
      target.scrollIntoView({ block: state.mode === "graph" ? "center" : "start", inline: "center", behavior: "smooth" });
      target.classList.remove("flash");
      void target.offsetWidth;
      target.classList.add("flash");
    }
  }

  // ---------------------------------------------------------------- views

  /** The block each line is in, and each block's label (or the entry's name). */
  function blockOfLines() {
    const of = new Array(listing().lines.length).fill(0);
    listing().blocks.forEach((b, k) => {
      for (let i = b.first; i < b.first + b.count; i++) {
        of[i] = k;
      }
    });
    return of;
  }

  const blockName = (k) => listing().blocks[k].label || (k === 0 ? "entry" : `block ${k}`);

  function lineRow(line, opts) {
    return el(
      "div",
      { class: "ln", "data-address": line.address },
      el("span", { class: "addr" }, hex(line.address)),
      state.bytes ? el("span", { class: "bytes" }, line.bytes.replace(/(..)(?!$)/g, "$1 ")) : null,
      opts && opts.label !== undefined ? el("span", { class: "lab" }, opts.label ? opts.label + ":" : "") : null,
      el("span", { class: "ins" }, instruction(line)),
      varNote(line)
    );
  }

  // ------------------------------------------------------------ variables

  /** The variables' notes for a line (as windbg shows them), or null. */
  function varNote(line) {
    const vars = listing().variables;
    if (!state.vars || !Array.isArray(vars) || !vars.length) {
      return null;
    }
    const notes = annotate(line.text, BigInt(line.address), vars);
    return notes.length ? el("span", { class: "vars", title: notes.join("\n") }, "; " + notes.join(", ")) : null;
  }

  function renderVariables(box) {
    const vars = listing().variables;
    if (!state.vars || !Array.isArray(vars) || !vars.length) {
      return;
    }
    const place = (r) =>
      r.register !== undefined
        ? r.field !== undefined
          ? `${r.register} (at +${r.field})`
          : r.register
        : `[${r.base}${r.offset < 0 ? "-" : "+"}${Math.abs(r.offset).toString(16)}h]`;
    const rows = vars.map((v) =>
      el(
        "tr",
        {},
        el("td", { class: "vname" }, v.name, v.param ? el("span", { class: "muted" }, " (param)") : null, v.inlined ? el("span", { class: "muted" }, " (inlined)") : null),
        el("td", { class: "muted" }, v.type),
        el(
          "td",
          {},
          v.ranges.map((r, i) => [i ? ", " : "", el("span", { class: "reg-like", title: `${hex(r.start)} to ${hex(r.end)}${r.gaps.length ? ` (${r.gaps.length} gaps)` : ""}` }, place(r)), el("span", { class: "muted" }, ` ${hex(r.start)}–${hex(r.end)}`)])
        )
      )
    );
    box.append(
      el(
        "details",
        { class: "varlist", open: state.varsOpen ? true : undefined, ontoggle: (e) => (state.varsOpen = e.target.open) },
        el("summary", {}, `Variables (${vars.length}) — where each lives (from the PDB)`),
        el("table", {}, rows)
      )
    );
  }

  function rest() {
    const r = listing().rest;
    return r ? el("div", { class: "ln rest" }, el("span", { class: "addr" }, hex(r.address)), el("span", { class: "ins muted" }, "(not instructions) " + r.bytes.replace(/(..)(?!$)/g, "$1 "))) : null;
  }

  function renderRaw(body) {
    const of = blockOfLines();
    const blocks = listing().blocks;
    body.append(
      el(
        "div",
        { class: "code raw" },
        listing().lines.map((line, i) => {
          const row = lineRow(line, { label: line.label || "" });
          if (blocks[of[i]].first === i) {
            row.setAttribute("data-block", String(of[i]));
          }
          return row;
        }),
        rest()
      )
    );
  }

  function edgeText(b) {
    const names = { taken: "taken", "not-taken": "else", jump: "jump", next: "falls into" };
    return b.successors.map((s) => [names[s.edge] || s.edge, blockName(s.block), s.block]);
  }

  function successorLinks(b) {
    const edges = edgeText(b);
    if (!edges.length) {
      return el("span", { class: "muted" }, "(leaves the function)");
    }
    return edges.map(([what, name, k], i) => [
      i ? " · " : "",
      el("span", { class: "muted" }, what + " "),
      el("a", { class: "lbl", href: "#", onclick: (e) => { e.preventDefault(); goToBlock(k); } }, name),
    ]);
  }

  function goToBlock(k) {
    const name = listing().blocks[k].label;
    if (name) {
      goToLabel(name);
      return;
    }
    const target = document.querySelector(`[data-block="${k}"]`);
    if (target) {
      target.scrollIntoView({ block: "center", inline: "center", behavior: "smooth" });
    }
  }

  function renderBlocks(body) {
    const l = listing();
    const code = el("div", { class: "code blocks" });
    l.blocks.forEach((b, k) => {
      const lines = l.lines.slice(b.first, b.first + b.count);
      const preds = l.blocks.map((p, j) => (p.successors.some((s) => s.block === k) ? j : -1)).filter((j) => j >= 0);
      code.append(
        el(
          "section",
          { class: "block", "data-block": String(k) },
          el(
            "div",
            { class: "bhead" },
            el("span", { class: "bname" }, b.label ? b.label + ":" : k === 0 ? l.name + ":" : ""),
            preds.length ? el("span", { class: "from muted" }, "from ", preds.map((j, i) => [i ? ", " : "", el("a", { class: "lbl", href: "#", onclick: (e) => { e.preventDefault(); goToBlock(j); } }, blockName(j))])) : null
          ),
          lines.map((line) => lineRow(line)),
          el("div", { class: "bfoot" }, "↳ ", successorLinks(b))
        )
      );
    });
    code.append(rest());
    body.append(code);
  }

  function renderSource(body) {
    const l = listing();
    const files = l.files || [];
    const sources = state.message.sources || [];
    const of = blockOfLines();
    const code = el("div", { class: "code source" });
    if (!files.length) {
      code.append(el("p", { class: "note" }, "No line information for this function (hexc reads it from a PE image's PDB)."));
    }
    let last = null;
    l.lines.forEach((line, i) => {
      const src = line.source;
      const key = src ? src.join(":") : "";
      if (key !== last) {
        last = key;
        if (src) {
          const [fi, n] = src;
          const text = sources[fi] && sources[fi].lines ? sources[fi].lines[n - 1] : null;
          code.append(
            el(
              "div",
              { class: "src" },
              el(
                "a",
                {
                  class: "where",
                  href: "#",
                  title: `${files[fi]}:${n}`,
                  onclick: (e) => {
                    e.preventDefault();
                    post({ command: "openSource", file: files[fi], line: n });
                  },
                },
                `${short(files[fi])}:${n}`
              ),
              el("span", { class: "stext" + (text === null || text === undefined ? " muted" : "") }, text === null || text === undefined ? "(source not found on this machine)" : text.replace(/\t/g, "    ") || " ")
            )
          );
        } else if (files.length) {
          code.append(el("div", { class: "src" }, el("span", { class: "where muted" }, "(no line)")));
        }
      }
      const row = lineRow(line, { label: line.label || "" });
      if (l.blocks[of[i]].first === i) {
        row.setAttribute("data-block", String(of[i]));
      }
      code.append(row);
    });
    code.append(rest());
    body.append(code);
  }

  // ---------------------------------------------------------------- graph

  let measure = null;
  function charWidth() {
    if (!measure) {
      const probe = el("span", { class: "gprobe" }, "0".repeat(100));
      document.body.append(probe);
      measure = probe.getBoundingClientRect().width / 100 || 7.2;
      probe.remove();
    }
    return measure;
  }

  function renderGraph(body) {
    const l = listing();
    const cw = charWidth();
    const lineH = 17;
    const sizes = l.blocks.map((b, k) => {
      const lines = l.lines.slice(b.first, b.first + b.count);
      const longest = Math.max(blockName(k).length + 2, ...lines.map((x) => x.text.length + (state.bytes ? x.bytes.length * 1.5 + 2 : 0) + 10));
      return { w: Math.min(720, Math.ceil(longest * cw) + 20), h: (lines.length + 1) * lineH + 12 };
    });
    const edges = [];
    l.blocks.forEach((b, k) => b.successors.forEach((s) => edges.push({ from: k, to: s.block, kind: s.edge })));
    const g = layoutGraph(l.blocks.length, sizes, edges);
    const canvas = el("div", { class: "gcanvas" });
    canvas.style.width = g.width + "px";
    canvas.style.height = g.height + "px";
    const lines = svg("svg", { class: "gedges", width: g.width, height: g.height });
    const defs = svg("defs");
    for (const kind of ["taken", "not-taken", "jump", "next"]) {
      const marker = svg("marker", { id: "arrow-" + kind, viewBox: "0 0 10 10", refX: "9", refY: "5", markerWidth: "7", markerHeight: "7", orient: "auto-start-reverse" });
      marker.append(svg("path", { d: "M0,0 L10,5 L0,10 z", class: "head " + kind }));
      defs.append(marker);
    }
    lines.append(defs);
    for (const e of g.edges) {
      lines.append(svg("path", { d: edgePath(e), class: "edge " + e.kind + (e.back ? " back" : ""), "marker-end": `url(#arrow-${e.kind})`, "data-from": e.from, "data-to": e.to }));
    }
    canvas.append(lines);
    g.nodes.forEach((n, k) => {
      const b = l.blocks[k];
      const node = el(
        "div",
        {
          class: "gnode" + (k === 0 ? " entry" : "") + (b.successors.length ? "" : " exit"),
          "data-block": String(k),
          onmouseenter: () => highlight(k, true),
          onmouseleave: () => highlight(k, false),
        },
        el("div", { class: "ghead" }, el("span", { class: "bname" }, k === 0 && !b.label ? l.name : blockName(k)), el("span", { class: "muted" }, hex(l.lines[b.first].address))),
        l.lines.slice(b.first, b.first + b.count).map((line) =>
          el("div", { class: "gline" }, state.bytes ? el("span", { class: "bytes" }, line.bytes) : null, el("span", { class: "ins" }, instruction(line)), varNote(line))
        )
      );
      Object.assign(node.style, { left: n.x + "px", top: n.y + "px", width: n.w + "px", minHeight: n.h + "px" });
      canvas.append(node);
    });
    const wrap = el("div", { class: "gwrap" }, canvas);
    applyZoom(canvas);
    body.append(wrap);
    // Drag to pan.
    let drag = null;
    wrap.addEventListener("mousedown", (e) => {
      if (e.target.closest("a")) {
        return;
      }
      drag = { x: e.clientX, y: e.clientY, left: wrap.scrollLeft, top: wrap.scrollTop };
      wrap.classList.add("dragging");
    });
    window.addEventListener("mousemove", (e) => {
      if (drag) {
        wrap.scrollLeft = drag.left - (e.clientX - drag.x);
        wrap.scrollTop = drag.top - (e.clientY - drag.y);
      }
    });
    window.addEventListener("mouseup", () => {
      drag = null;
      wrap.classList.remove("dragging");
    });
    wrap.addEventListener(
      "wheel",
      (e) => {
        if (e.ctrlKey) {
          e.preventDefault();
          setZoom(state.zoom * (e.deltaY < 0 ? 1.1 : 1 / 1.1));
        }
      },
      { passive: false }
    );
  }

  function highlight(k, on) {
    for (const p of document.querySelectorAll(`path.edge[data-from="${k}"], path.edge[data-to="${k}"]`)) {
      p.classList.toggle("hot", on);
    }
  }

  function applyZoom(canvas) {
    const c = canvas || document.querySelector(".gcanvas");
    if (!c) {
      return;
    }
    c.style.transform = `scale(${state.zoom})`;
    c.style.transformOrigin = "0 0";
    // The scroll area follows the scaled size.
    const holder = c.parentElement;
    if (holder) {
      c.style.marginRight = (parseFloat(c.style.width) * (state.zoom - 1)) + "px";
      c.style.marginBottom = (parseFloat(c.style.height) * (state.zoom - 1)) + "px";
    }
  }

  function setZoom(z) {
    state.zoom = Math.max(0.2, Math.min(2.5, z));
    save();
    applyZoom();
    const pct = $("zoompct");
    if (pct) {
      pct.textContent = Math.round(state.zoom * 100) + "%";
    }
  }

  function fit() {
    const wrap = document.querySelector(".gwrap");
    const c = document.querySelector(".gcanvas");
    if (!wrap || !c) {
      return;
    }
    const w = parseFloat(c.style.width);
    const h = parseFloat(c.style.height);
    setZoom(Math.min(1, (wrap.clientWidth - 8) / w, (wrap.clientHeight - 8) / h));
  }

  // ----------------------------------------------------------------- page

  function renderHeader() {
    const m = state.message;
    const l = listing();
    const facts = [];
    if (l.isa) {
      facts.push(l.isa);
    }
    if (hasCode()) {
      facts.push(`${l.size} bytes`, `${l.lines.length} instructions`, `${l.blocks.length} blocks`);
    }
    $("header").replaceChildren(
      el("div", { class: "title" }, el("span", { class: "name", title: l.name }, l.name), el("span", { class: "path", title: m.file }, short(m.file))),
      el("div", { class: "facts muted" }, facts.join(" · ")),
      el(
        "div",
        { class: "actions" },
        vscode ? el("button", { class: "icon", title: "Open this listing as a text document", onclick: () => post({ command: "openText", mode: state.mode }) }, "Open as Text") : null,
        vscode ? el("button", { class: "icon", title: "Copy the listing", onclick: () => post({ command: "copy", text: plainText() }) }, "Copy") : null,
        vscode ? el("button", { class: "icon", title: "Run hexc again", onclick: () => post({ command: "refresh" }) }, "⟳") : null
      )
    );
  }

  function renderToolbar() {
    const modes = el(
      "span",
      { class: "segmented", role: "radiogroup", title: "How to show it" },
      MODES.map(([v, label]) =>
        el(
          "button",
          {
            class: v === state.mode ? "on" : "",
            role: "radio",
            "aria-checked": v === state.mode ? "true" : "false",
            disabled: !hasCode() && v !== "raw" ? true : undefined,
            onclick: () => {
              state.mode = v;
              save();
              post({ command: "mode", mode: v });
              render();
            },
          },
          label
        )
      )
    );
    const bytes = el("label", { class: "check" }, el("input", { type: "checkbox", checked: state.bytes ? true : undefined, onchange: (e) => { state.bytes = e.target.checked; save(); render(); } }), " Bytes");
    const hasVars = Array.isArray(listing().variables) && listing().variables.length > 0;
    const vars = hasVars
      ? el("label", { class: "check", title: "Name the registers and stack slots that hold parameters and locals (from the PDB)" }, el("input", { type: "checkbox", checked: state.vars ? true : undefined, onchange: (e) => { state.vars = e.target.checked; save(); render(); } }), " Variables")
      : null;
    const zoom =
      state.mode === "graph"
        ? el(
            "span",
            { class: "zoom" },
            el("button", { class: "icon", title: "Zoom out", onclick: () => setZoom(state.zoom / 1.2) }, "−"),
            el("span", { id: "zoompct", class: "muted" }, Math.round(state.zoom * 100) + "%"),
            el("button", { class: "icon", title: "Zoom in", onclick: () => setZoom(state.zoom * 1.2) }, "+"),
            el("button", { class: "icon", title: "Fit the graph in the view", onclick: fit }, "Fit")
          )
        : null;
    const legend =
      state.mode === "graph"
        ? el("span", { class: "glegend muted" }, el("i", { class: "sw taken" }), "taken ", el("i", { class: "sw not-taken" }), "not taken ", el("i", { class: "sw jump" }), "jump ", el("i", { class: "sw next" }), "falls into")
        : null;
    $("toolbar").replaceChildren(...[modes, bytes, vars, el("span", { class: "spacer" }), legend, zoom].filter(Boolean));
  }

  /** The listing as text, as shown (for copying). */
  function plainText() {
    const l = listing();
    if (!hasCode()) {
      return l.text || "";
    }
    const lines = [l.name + ":"];
    const pad = (s, n) => s + " ".repeat(Math.max(0, n - s.length));
    if (state.mode === "blocks" || state.mode === "graph") {
      l.blocks.forEach((b, k) => {
        lines.push("");
        if (b.label) {
          lines.push(b.label + ":");
        }
        for (const x of l.lines.slice(b.first, b.first + b.count)) {
          lines.push(`  ${pad(hex(x.address), 16)}  ${x.text}`);
        }
        void k;
      });
    } else {
      for (const x of l.lines) {
        lines.push(`  ${pad(hex(x.address), 16)}  ${pad(x.label ? x.label + ":" : "", 5)}${x.text}`);
      }
    }
    return lines.join("\n") + "\n";
  }

  function render() {
    if (!state.message) {
      return;
    }
    if (state.message.error) {
      $("header").replaceChildren(el("div", { class: "title" }, el("span", { class: "name" }, state.message.name || "")));
      $("toolbar").replaceChildren();
      $("body").replaceChildren(el("p", { class: "note error" }, state.message.error));
      return;
    }
    const l = listing();
    labelIndex = new Map();
    if (hasCode()) {
      l.blocks.forEach((b, k) => b.label && labelIndex.set(b.label, k));
    } else if (state.mode !== "raw") {
      state.mode = "raw";
    }
    renderHeader();
    renderToolbar();
    const body = $("body");
    body.replaceChildren();
    body.className = "mode-" + state.mode;
    if (!hasCode()) {
      body.append(el("pre", { class: "code text" }, l.text || ""));
      return;
    }
    if (state.mode !== "graph") {
      renderVariables(body);
    }
    switch (state.mode) {
      case "raw":
        renderRaw(body);
        break;
      case "source":
        renderSource(body);
        break;
      case "graph":
        renderGraph(body);
        break;
      default:
        renderBlocks(body);
    }
  }

  window.addEventListener("message", (e) => {
    const m = e.data;
    if (!m || m.kind !== "disasm") {
      return;
    }
    state.message = m;
    if (m.mode && !saved) {
      state.mode = m.mode;
    }
    render();
  });
})();
