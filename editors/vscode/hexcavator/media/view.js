// The Symbols page: a report (or a diff) of every symbol, as a tree (by
// default), a nested treemap, or a sunburst; grouped by what the grouping
// chips choose (Section, Library, Object, Group, in the order dragged),
// filtered as you type (a substring of the name or mangled name, or a
// regular expression), with breadcrumbs, a sortable table of the current
// level, and a hover card; or the findings. It talks to the extension
// through messages (compare, refresh, export, copy, regroup); it renders on
// its own too (the tests load it in a plain page).
"use strict";

(function () {
  const vscode = typeof acquireVsCodeApi === "function" ? acquireVsCodeApi() : null;
  window.__hexcVscode = vscode;
  const post = (m) => vscode && vscode.postMessage(m);
  const $ = (id) => document.getElementById(id);

  // The levels a report can be grouped by (hexc's data sources), as the
  // grouping chips name them; symbols are always the last level.
  const CHIPS = [
    ["sections", "Section", "the section (or segment) each symbol is in"],
    ["libraries", "Library", "the library each symbol's object came from"],
    ["compileunits", "Object", "the object file (compiland) each symbol came from"],
    ["groups", "Group", "the COFF group (.text$mn, .rdata$r, ...) each symbol is in"],
    ["sourcefiles", "Source", "the source file each byte of code came from (its line tables: an inlined header's code, the header's)"],
  ];

  const state = {
    message: null,
    path: [],
    domain: "file",
    mode: "tree",
    sort: { key: "size", desc: true },
    // A diff's filter by change: "added", "removed", "grew", "shrank" (none:
    // all).
    kinds: new Set(),
    query: "",
    // The filter: a substring, or a regular expression; the last that
    // compiled (an invalid one leaves it).
    regex: false,
    matcher: null,
    invalid: false,
    // The report as the filter leaves it (null: unfiltered).
    filtered: null,
    // Each symbol's mangled name, by its shown name (hexc size -mangled).
    mangled: new Map(),
    showMangled: false,
    selected: -1,
    // The tree's open rows and selected row (keys of paths); and while
    // filtering (when rows holding a match are open), those closed.
    open: new Set(),
    closed: new Set(),
    treeSel: null,
    // The rows the tree shows (all of them; only those in view are drawn).
    treeRows: [],
  };
  // Restore the view's settings across reloads.
  const saved = vscode && vscode.getState();
  if (saved) {
    Object.assign(state, {
      domain: saved.domain || "file",
      mode: saved.mode || "tree",
      regex: !!saved.regex,
      showMangled: !!saved.showMangled,
      sort: saved.sort && ["name", "size", "file", "vm"].includes(saved.sort.key) ? saved.sort : state.sort,
    });
  }
  const save = () =>
    vscode && vscode.setState({ domain: state.domain, mode: state.mode, regex: state.regex, showMangled: state.showMangled, sort: state.sort });

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

  const svgNS = "http://www.w3.org/2000/svg";
  function svg(tag, attrs, ...children) {
    const e = document.createElementNS(svgNS, tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k.startsWith("on")) {
        e.addEventListener(k.slice(2), v);
      } else {
        e.setAttribute(k, v);
      }
    }
    for (const c of children) {
      e.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return e;
  }

  const report = () => state.message.report;
  const isDiff = () => !!report().diff;
  // (Before the report is drawn: the message's.)
  const isDiffMessage = () => !!(state.message && state.message.report && state.message.report.diff);
  // (What the filter leaves: every view draws it.)
  const total = () => state.filtered || report().total;
  const current = () => rowAt(total(), state.path) || total();
  const value = (row) => rowValue(row, state.domain);
  const signed = (row) => signedValue(row, state.domain);
  const sign = (n) => (isDiff() && n > 0 ? "+" : "");
  const shown = (n) => sign(n) + formatSize(n);

  /**
   * Shows the row at `at` (a path of names): the deepest part of it the
   * report has, among its siblings, selected.
   */
  function goTo(at) {
    let n = 0;
    while (n < at.length && rowAt(total(), at.slice(0, n + 1))) {
      n++;
    }
    if (state.mode === "tree") {
      revealInTree(at.slice(0, n));
      return;
    }
    const row = rowAt(total(), at.slice(0, n));
    if (n && row && !row.children) {
      go(at.slice(0, n - 1));
      select(sortedChildren(current()).findIndex((c) => c.name === at[n - 1]));
    } else {
      go(at.slice(0, n));
    }
  }

  function go(path) {
    state.path = path;
    state.selected = -1;
    render();
  }

  // ---------------------------------------------------------------- header

  function renderHeader() {
    const m = state.message;
    const head = $("header");
    const name = (p) => (p || "").split(/[\\/]/).pop();
    const t = total();
    const chips = [
      el("span", { class: "chip" + (isDiff() ? diffClass(t.file) : "") }, el("b", {}, "File "), shown(t.file)),
      el("span", { class: "chip" + (isDiff() ? diffClass(t.vm) : "") }, el("b", {}, "Virtual "), shown(t.vm)),
    ];
    if (state.filtered) {
      chips.unshift(el("span", { class: "chip muted", title: "The sizes beside it are what the filter leaves" }, "filtered, of " + shown(report().total.file)));
    }
    if (report().filtered) {
      chips.push(el("span", { class: "chip muted" }, "filtered: " + formatSize(report().filtered.file)));
    }
    head.replaceChildren(
      el(
        "div",
        { class: "title" },
        el("span", { class: "name" }, name(m.file)),
        m.base ? el("span", { class: "vs" }, " vs ", el("span", { class: "name" }, name(m.base))) : null,
        el("span", { class: "path", title: m.file }, m.file || "")
      ),
      el("div", { class: "chips" }, chips),
      el(
        "div",
        { class: "actions" },
        vscode ? el("button", { class: "icon", title: "Compare with another build…", onclick: () => post({ command: "compare" }) }, "⇄ Compare") : null,
        vscode ? el("button", { class: "icon", title: "Run hexc again", onclick: () => post({ command: "refresh" }) }, "⟳") : null,
        vscode ? el("button", { class: "icon", title: "Export the report", onclick: () => post({ command: "export" }) }, "⤓") : null
      )
    );
  }

  const diffClass = (n) => (n > 0 ? " grows" : n < 0 ? " shrinks" : "");

  // --------------------------------------------------------------- toolbar

  function segmented(options, value, onchange, title) {
    return el(
      "span",
      { class: "segmented", role: "radiogroup", title },
      options.map(([v, label]) =>
        el("button", { class: v === value ? "on" : "", role: "radio", "aria-checked": v === value ? "true" : "false", onclick: () => onchange(v) }, label)
      )
    );
  }

  function renderToolbar() {
    const bar = $("toolbar");
    const crumbs = el("nav", { class: "crumbs", "aria-label": "Path" });
    const names = ["TOTAL", ...state.path];
    names.forEach((name, i) => {
      if (i > 0) {
        crumbs.append(el("span", { class: "sep" }, "›"));
      }
      crumbs.append(
        i < names.length - 1
          ? el("a", { href: "#", onclick: (e) => { e.preventDefault(); go(state.path.slice(0, i)); } }, name)
          : el("span", { class: "here" }, name)
      );
    });
    const sources = report().sources || [];
    const level = state.path.length;
    const input = el("input", {
      id: "search",
      type: "search",
      class: state.invalid ? "invalid" : "",
      placeholder: state.regex ? "Filter by a regular expression…" : "Filter by name…",
      title: "Shows the symbols whose name (or mangled name) has this, and what they are in; Esc clears it",
      value: state.query,
      oninput: (e) => setFilter(e.target.value),
      onkeydown: (e) => {
        if (e.key === "Escape") {
          e.target.value = "";
          setFilter("");
        }
      },
    });
    const regex = el(
      "button",
      {
        class: "toggle" + (state.regex ? " on" : ""),
        title: "Use a regular expression",
        "aria-pressed": String(state.regex),
        onclick: () => {
          state.regex = !state.regex;
          save();
          setFilter(state.query, true);
        },
      },
      ".*"
    );
    bar.replaceChildren(
      ...[
      crumbs,
      el("span", { class: "level" }, level < sources.length ? `by ${sources[level]}` : ""),
      el("span", { class: "spacer" }),
      vscode ? groupingChips(sources) : null,
      isDiff() ? changeChips() : null,
      el("span", { class: "searchbox" }, input, regex),
      segmented([["file", "File"], ["vm", "Virtual"]], state.domain, (v) => { state.domain = v; save(); render(); }, "Which sizes"),
      segmented([["treemap", "Treemap"], ["sunburst", "Sunburst"], ["tree", "Tree"]], state.mode, (v) => { state.mode = v; save(); render(); }, "How to draw it"),
      ].filter(Boolean)
    );
    // (Typing goes on where it was.)
    if (state.typing) {
      const box = $("search");
      box.focus();
      box.setSelectionRange(box.value.length, box.value.length);
    }
  }

  /**
   * A diff's filter by what happened to each symbol: a chip each for added,
   * removed, grew, and shrank. None on: all of them; else only those on
   * (with the text filter, if any). Their groups are summed again.
   */
  function changeChips() {
    const box = el("span", { class: "chips-group changes", role: "group", "aria-label": "Show only" }, el("span", { class: "muted" }, "Show"));
    for (const [kind, mark, label] of [
      ["added", "+", "Added"],
      ["removed", "\u2212", "Removed"],
      ["grew", "\u2197", "Grew"],
      ["shrank", "\u2198", "Shrank"],
    ]) {
      const on = state.kinds.has(kind);
      box.append(
        el(
          "button",
          {
            class: "gchip kind " + kind + (on ? " on" : ""),
            "aria-pressed": String(on),
            "data-kind": kind,
            title: on ? `Showing what ${label.toLowerCase()}; click to stop` : `Show only what ${label.toLowerCase()} (with the others on)`,
            onclick: () => {
              if (on) {
                state.kinds.delete(kind);
              } else {
                state.kinds.add(kind);
              }
              applyFilter();
              state.path = state.path.filter((_, i) => rowAt(total(), state.path.slice(0, i + 1)));
              render();
            },
          },
          el("b", { class: "change " + kind }, mark),
          " " + label
        )
      );
    }
    return box;
  }

  /**
   * The grouping control: a chip for each level (Section, Library, Object,
   * Group). Click one to group by it or not; drag the ones on (or press
   * Alt+Left and Alt+Right) to order them, outermost first. With none,
   * the symbols are a list.
   */
  function groupingChips(sources) {
    const on = sources.filter((x) => x !== "symbols" && CHIPS.some((c) => c[0] === x));
    const available = (id) => id !== "groups" || (state.message.format || "pe") === "pe";
    const apply = (levels) => {
      const m = state.message;
      // (Made here when the table has each level; else hexc makes the
      // table that has: the source files' is apart, being costly.)
      if (m.table && levels.every((l) => m.table.columns.includes(l))) {
        // (Made here at once; the extension remembers the grouping.)
        m.levels = levels;
        m.report = fromTable(m.table, levels);
        applyFilter();
        state.path = [];
        render();
        post({ command: "regroup", sources: [...levels, "symbols"], local: true });
      } else {
        post({ command: "regroup", sources: [...levels, "symbols"] });
      }
    };
    const box = el("span", { class: "chips-group", role: "group", "aria-label": "Group by" }, el("span", { class: "muted" }, "Group by"));
    const ordered = [...on.map((id) => CHIPS.find((c) => c[0] === id)), ...CHIPS.filter((c) => !on.includes(c[0]))];
    for (const [id, label, about] of ordered) {
      const active = on.includes(id);
      const ok = available(id);
      const chip = el(
        "button",
        {
          class: "gchip" + (active ? " on" : "") + (ok ? "" : " off"),
          draggable: active ? "true" : undefined,
          disabled: ok ? undefined : true,
          title: ok
            ? `${active ? "Grouped" : "Group"} by ${about}${active ? " (drag to reorder; Alt+Left and Alt+Right move it)" : ""}`
            : "This file has no COFF groups (a PE image's PDB has them)",
          "aria-pressed": String(active),
          "data-id": id,
          onclick: () => apply(active ? on.filter((x) => x !== id) : [...on, id]),
          onkeydown: (e) => {
            if (!active || !e.altKey || (e.key !== "ArrowLeft" && e.key !== "ArrowRight")) {
              return;
            }
            e.preventDefault();
            const k = on.indexOf(id);
            const to = e.key === "ArrowLeft" ? k - 1 : k + 1;
            if (to >= 0 && to < on.length) {
              const next = on.slice();
              next.splice(k, 1);
              next.splice(to, 0, id);
              state.focusChip = id;
              apply(next);
            }
          },
          ondragstart: (e) => {
            e.dataTransfer.setData("text/plain", id);
            e.dataTransfer.effectAllowed = "move";
          },
          ondragover: (e) => {
            if (active) {
              e.preventDefault();
            }
          },
          ondrop: (e) => {
            e.preventDefault();
            const from = e.dataTransfer.getData("text/plain");
            if (!from || from === id || !on.includes(from)) {
              return;
            }
            const next = on.filter((x) => x !== from);
            next.splice(next.indexOf(id), 0, from);
            apply(next);
          },
        },
        active ? `${on.indexOf(id) + 1} ` : "",
        label
      );
      box.append(chip);
    }
    if (state.focusChip) {
      const id = state.focusChip;
      state.focusChip = null;
      requestAnimationFrame(() => {
        const c = document.querySelector(`.gchip[data-id="${id}"]`);
        if (c) {
          c.focus();
        }
      });
    }
    return box;
  }

  /**
   * A report from hexc's table (`hexc size -table`: a row per distinct set
   * of labels, one per source, with its sizes), grouped by `levels` (in
   * order), then symbols: the rows summed by those labels, as hexc rolls
   * them up (rows of no size left out; a row whose one child is [None] or
   * [Unmapped], below the top, or has its own name, has none).
   */
  function fromTable(t, levels) {
    const columns = [...levels, "symbols"].map((l) => t.columns.indexOf(l)).filter((i) => i >= 0);
    const S = t.strings;
    // (A diff's rows: the change in file and memory size, then the base's
    // sizes; a row unchanged is left out, as hexc's diffs leave it, but
    // counts in its groups' base sizes.)
    const diff = !!t.diff;
    const root = { name: "TOTAL", file: 0, vm: 0, old_file: 0, old_vm: 0, kids: new Map() };
    for (const r of t.rows) {
      const k = r.length - (diff ? 4 : 2);
      const f = r[k];
      const v = r[k + 1];
      const of = diff ? r[k + 2] : 0;
      const ov = diff ? r[k + 3] : 0;
      root.file += f;
      root.vm += v;
      root.old_file += of;
      root.old_vm += ov;
      let n = root;
      for (const i of columns) {
        const name = S[r[i]];
        let c = n.kids.get(name);
        if (!c) {
          c = { name, file: 0, vm: 0, old_file: 0, old_vm: 0, kids: new Map() };
          n.kids.set(name, c);
        }
        c.file += f;
        c.vm += v;
        c.old_file += of;
        c.old_vm += ov;
        n = c;
      }
    }
    const finish = (n, top) => {
      let kids = [...n.kids.values()].filter((c) => c.file || c.vm);
      if (!top && kids.length === 1 && (kids[0].name === "[None]" || kids[0].name === "[Unmapped]")) {
        kids = [];
      }
      if (kids.length === 1 && kids[0].name === n.name) {
        kids = [];
      }
      const out = { name: n.name, file: n.file, vm: n.vm };
      if (diff) {
        out.old_file = n.old_file;
        out.old_vm = n.old_vm;
      }
      if (kids.length) {
        out.children = kids.map((c) => finish(c, false));
      }
      return out;
    };
    return { sources: [...levels, "symbols"], diff, total: finish(root, true) };
  }

  /** Each symbol's mangled name, from a table that has them (not PE's). */
  function mangledFromTable(t) {
    const shown = t.columns.indexOf("symbols");
    const raw = t.columns.indexOf("rawsymbols");
    if (shown < 0 || raw < 0) {
      return;
    }
    const map = new Map();
    for (const r of t.rows) {
      const a = t.strings[r[shown]];
      const b = t.strings[r[raw]];
      if (a !== b && !b.startsWith("[") && !map.has(a)) {
        map.set(a, b);
      }
    }
    state.mangled = map;
  }

  /**
   * Sets the filter to `query` (a substring, or with the regex toggle a
   * regular expression; an invalid one leaves the last that compiled):
   * the report is then the symbols whose name or mangled name it matches,
   * and what they are in, their sizes summed again.
   */
  function setFilter(query, force) {
    if (query === state.query && !force) {
      return;
    }
    state.query = query;
    const q = query.trim();
    if (!q) {
      state.matcher = null;
      state.invalid = false;
    } else if (state.regex) {
      try {
        const re = new RegExp(q, "i");
        state.matcher = (s) => re.test(s);
        state.invalid = false;
      } catch {
        state.invalid = true;
      }
    } else {
      const lower = q.toLowerCase();
      state.matcher = (s) => s.toLowerCase().includes(lower);
      state.invalid = false;
    }
    applyFilter();
    state.path = state.path.filter((_, i) => rowAt(total(), state.path.slice(0, i + 1)));
    state.typing = true;
    render();
    state.typing = false;
  }

  function applyFilter() {
    state.closed.clear();
    const m = state.matcher;
    // (A diff's: what happened to each symbol, as the chips choose.)
    const kinds = isDiffMessage() && state.kinds.size ? state.kinds : null;
    if ((!m && !kinds) || !state.message || state.message.kind !== "report") {
      state.filtered = null;
      return;
    }
    const keep = (row) => {
      if (!row.children) {
        if (kinds && !kinds.has(changeOf(row)[0])) {
          return null;
        }
        if (!m) {
          return row;
        }
        const mangled = state.mangled.get(row.name);
        return m(row.name) || (mangled !== undefined && m(mangled)) ? row : null;
      }
      const kids = row.children.map(keep).filter(Boolean);
      if (!kids.length) {
        return null;
      }
      const sum = (k) => kids.reduce((n, c) => n + (c[k] || 0), 0);
      const out = { name: row.name, file: sum("file"), vm: sum("vm"), children: kids };
      if (isDiff()) {
        out.old_file = sum("old_file");
        out.old_vm = sum("old_vm");
      }
      return out;
    };
    const t = report().total;
    state.filtered = keep(t) || { name: t.name, file: 0, vm: 0, children: [] };
  }

  // ------------------------------------------------------------- the card

  function card(row, path, e) {
    const tip = $("tip");
    const parent = rowAt(total(), path.slice(0, -1)) || total();
    tip.replaceChildren(
      el("div", { class: "tname" }, row.name),
      state.mangled.get(row.name) ? el("div", { class: "tpath mono" }, state.mangled.get(row.name)) : null,
      el("div", { class: "tpath" }, path.slice(0, -1).join(" › ") || "TOTAL"),
      el(
        "table",
        {},
        el("tr", {}, el("td", {}, "File"), el("td", { class: "n" }, shown(row.file)), el("td", { class: "n muted" }, formatBytes(row.file) + " B")),
        el("tr", {}, el("td", {}, "Virtual"), el("td", { class: "n" }, shown(row.vm)), el("td", { class: "n muted" }, formatBytes(row.vm) + " B")),
        isDiff()
          ? null
          : el("tr", {}, el("td", {}, "Share"), el("td", { class: "n" }, percent(value(row), value(parent)) + " of parent"), el("td", { class: "n muted" }, percent(value(row), value(total())) + " of all"))
      ),
      row.children ? el("div", { class: "thint" }, `${row.children.length} inside · click to open`) : null,
      row.other_count ? el("div", { class: "thint" }, `${row.other_count} smaller rows together`) : null
    );
    tip.className = "show";
    const r = $("main").getBoundingClientRect();
    const x = Math.min(e.clientX - r.left + 14, r.width - tip.offsetWidth - 6);
    const y = Math.min(e.clientY - r.top + 14, r.height - tip.offsetHeight - 6);
    tip.style.left = Math.max(4, x) + "px";
    tip.style.top = Math.max(4, y) + "px";
  }

  function hideCard() {
    $("tip").className = "";
  }

  // --------------------------------------------------------------- treemap

  function zoomInto(path, from) {
    const row = rowAt(total(), path);
    if (!row || !row.children) {
      return;
    }
    // Grow the box to fill the map, then show what is inside.
    const map = $("map");
    if (from && !window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      const ghost = el("div", { class: "ghost" });
      Object.assign(ghost.style, { left: from.x + "px", top: from.y + "px", width: from.w + "px", height: from.h + "px", background: from.color });
      map.append(ghost);
      requestAnimationFrame(() => {
        Object.assign(ghost.style, { left: "0px", top: "0px", width: map.clientWidth + "px", height: map.clientHeight + "px", opacity: "0.6" });
      });
      setTimeout(() => go(path), 170);
    } else {
      go(path);
    }
  }

  function renderTreemap() {
    const map = $("map");
    map.replaceChildren();
    const rect = { x: 0, y: 0, w: map.clientWidth, h: map.clientHeight };
    const boxes = layoutNested(current(), rect, state.domain, { levels: 2, limit: 900 });
    if (!boxes.length) {
      map.append(el("div", { class: "empty" }, isDiff() ? "No change here." : "Nothing more to show here."));
      return;
    }
    const maxAbs = Math.max(1, ...boxes.map((b) => Math.abs(signed(b.row))));
    const top = state.path[0];
    const frag = document.createDocumentFragment();
    for (const b of boxes) {
      const c = b.row;
      const path = [...state.path, ...b.path];
      const color = isDiff() ? diffColor(signed(c), maxAbs) : colorFor(c.name, state.path.length + b.depth, top ?? b.path[0]);
      const box = el("div", {
        class: "box" + (c.children ? " zoomable" : "") + (b.header ? " parent" : "") + (b.depth ? " inner" : "") + (isDiff() ? diffClass(signed(c)) : ""),
        role: "treeitem",
        tabindex: b.depth ? "-1" : "0",
        "aria-label": `${c.name}, ${shown(signed(c))}`,
      });
      Object.assign(box.style, {
        left: b.x + "px",
        top: b.y + "px",
        width: Math.max(0, b.w - 1) + "px",
        height: Math.max(0, b.h - 1) + "px",
        background: color,
      });
      if (b.w > 40 && b.h > 16) {
        box.append(el("span", { class: "label" }, c.name));
        if (b.h > 30 || b.header) {
          box.append(el("span", { class: "size" }, shown(signed(c))));
        }
      }
      box.addEventListener("mousemove", (e) => { e.stopPropagation(); card(c, path, e); });
      box.addEventListener("mouseleave", hideCard);
      box.addEventListener("click", (e) => {
        e.stopPropagation();
        zoomInto(path, { x: b.x, y: b.y, w: b.w, h: b.h, color });
      });
      box.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
          zoomInto(path, { x: b.x, y: b.y, w: b.w, h: b.h, color });
        }
      });
      frag.append(box);
    }
    map.append(frag);
  }

  // -------------------------------------------------------------- sunburst

  function renderSunburst() {
    const map = $("map");
    map.replaceChildren();
    const w = map.clientWidth;
    const h = map.clientHeight;
    const arcs = sunburst(current(), state.domain, 4, 0.006);
    // As many rings as the tree has below here (up to 4), so none is empty.
    const levels = Math.max(1, ...arcs.map((a) => a.depth + 1));
    const radius = Math.max(40, Math.min(w, h) / 2 - 8);
    const hole = radius * (levels > 2 ? 0.22 : 0.3);
    const ring = (radius - hole) / levels;
    const cx = w / 2;
    const cy = h / 2;
    const maxAbs = Math.max(1, ...arcs.map((a) => Math.abs(signed(a.row))));
    const root = svg("svg", { width: w, height: h, class: "sun", role: "tree" });
    const center = svg("circle", { cx, cy, r: hole - 2, class: "center", onclick: () => state.path.length && go(state.path.slice(0, -1)) });
    root.append(center);
    const cur = current();
    root.append(
      svg("text", { x: cx, y: cy - 4, class: "ctitle", "text-anchor": "middle" }, cur.name.length > 18 ? cur.name.slice(0, 17) + "…" : cur.name),
      svg("text", { x: cx, y: cy + 14, class: "csize", "text-anchor": "middle" }, shown(signed(cur)))
    );
    const top = state.path[0];
    for (const a of arcs) {
      const path = [...state.path, ...a.path];
      const fill = isDiff() ? diffColor(signed(a.row), maxAbs) : colorFor(a.row.name, state.path.length + a.depth, top ?? a.path[0]);
      const p = svg("path", {
        d: arcPath(cx, cy, hole + a.depth * ring, hole + (a.depth + 1) * ring - 1, a.start, a.end),
        fill,
        class: "arc" + (a.row.children ? " zoomable" : ""),
        onmousemove: (e) => card(a.row, path, e),
        onmouseleave: hideCard,
        onclick: () => a.row.children && go(path),
      });
      root.append(p);
    }
    map.append(root);
  }

  // ----------------------------------------------------------------- table

  function sortedChildren(row) {
    const kids = [...(row.children || [])];
    const { key, desc } = state.sort;
    const by = {
      name: (a, b) => a.name.localeCompare(b.name),
      size: (a, b) => value(a) - value(b),
      file: (a, b) => a.file - b.file,
      vm: (a, b) => a.vm - b.vm,
    }[key];
    kids.sort((a, b) => (desc ? -1 : 1) * by(a, b));
    return kids;
  }

  /**
   * What a symbol row at `path` is, by the section it is in: "code",
   * "data", or (no section level) "any".
   */
  function sectionKind(path) {
    const sources = report().sources || [];
    const i = sources.findIndex((s) => s === "sections" || s === "segments" || s === "groups");
    if (i < 0 || i >= path.length) {
      return "any";
    }
    return /^(\.text|\.init|\.fini|\.plt|__text|__stubs|__stub_helper|Code|PAGE|INIT|\.orpc)/i.test(path[i]) ? "code" : "data";
  }

  const isPeFile = () => /\.(exe|dll|sys|efi)$/i.test(state.message.file || "");
  // What hexc says the file supports (its tools), else what its name says.
  const can = (tool) => {
    const tools = state.message.tools;
    return Array.isArray(tools) ? tools.includes(tool) : isPeFile();
  };

  /**
   * How a row can be opened: "code" (disassembled), "data" (its bytes
   * and value), "any" (hexc decides), or null (not a symbol, or nothing
   * opens it here).
   */
  function openKind(row, path) {
    if (!vscode || isDiff() || row.children || !isSymbolName(row.name) || !isSymbolLevel(report().sources, path.length - 1)) {
      return null;
    }
    const kind = sectionKind(path);
    const code = canDisassembleFile(state.message.file);
    if (kind === "code") {
      return code ? "code" : null;
    }
    if (kind === "data") {
      return can("data") ? "data" : null;
    }
    return code ? (can("data") ? "any" : "code") : null;
  }

  /** Opens a row's symbol: its code or its data. */
  function openRow(row, path) {
    const kind = openKind(row, path);
    if (kind) {
      post({ command: "inspect", name: row.name, hint: kind });
    }
  }

  /** The button that opens a row's symbol (in its own column). */
  function openButton(row, path) {
    const kind = openKind(row, path);
    if (!kind) {
      return null;
    }
    const what = { code: ["⟨/⟩", "Disassemble"], data: ["▦", "View data"], any: ["↗", "Open (code or data)"] }[kind];
    return el(
      "button",
      {
        class: "act",
        title: `${what[1]} (D)`,
        "aria-label": `${what[1]} ${row.name}`,
        onclick: (e) => {
          e.stopPropagation();
          openRow(row, path);
        },
      },
      what[0]
    );
  }

  /** VS Code's context menu for a row: what its commands need. */
  function rowContext(row, path) {
    const kind = openKind(row, path);
    // (A diff's symbol: its own menu, which compares its code in each build;
    // what opens one build's doesn't apply.)
    const diffSymbol = vscode && isDiff() && !row.children && isSymbolName(row.name) && isSymbolLevel(report().sources, path.length - 1);
    return JSON.stringify({
      webviewSection: diffSymbol ? "diffSymbol" : kind ? "symbol" : "row",
      symbolKind: diffSymbol ? sectionKind(path) : kind || "none",
      peImage: isPeFile() && !isDiff(),
      canQuery: can("why") && !isDiff(),
      canData: can("data") && !isDiff(),
      // (A diff's: the base, and what happened to it: a function in both
      // builds has its code compared.)
      symbolChange: isDiff() ? changeOf(row)[0] : "none",
      base: isDiff() ? state.message.base : undefined,
      file: state.message.file,
      name: row.name,
      path,
      preventDefaultContextMenuItems: true,
    });
  }

  // ------------------------------------------------------------------ tree

  // A tree of the rows below the current one, as Windows draws one: each
  // row with its twisty and guide lines, and its rollups (its sizes, share
  // of its parent and of the whole, and how many rows are inside).
  const treeKey = (path) => path.join("\u0000");

  /** The rows shown: each open row's children, depth first, largest first. */
  function visibleRows() {
    const out = [];
    const walk = (row, path, depth, lasts) => {
      const kids = sortedChildren(row);
      kids.forEach((c, i) => {
        const p = [...path, c.name];
        const last = i === kids.length - 1;
        out.push({ row: c, parent: row, path: p, depth, lasts: [...lasts, last] });
        // (Filtering opens every row that holds a match.)
        if (c.children && isOpen(treeKey(p))) {
          walk(c, p, depth + 1, [...lasts, last]);
        }
      });
    };
    walk(current(), state.path, 0, []);
    return out;
  }

  /** Shows the row at `path` (from the top) in the tree: its ancestors open, it selected. */
  function revealInTree(path) {
    state.path = [];
    for (let k = 1; k < path.length; k++) {
      state.open.add(treeKey(path.slice(0, k)));
    }
    state.treeSel = path.length ? treeKey(path) : null;
    render();
    scrollToSelected("center");
  }

  /** Scrolls the tree so that its selected row is in view, and draws it. */
  function scrollToSelected(where) {
    const wrap = $("map").querySelector(".treewrap");
    const i = state.treeRows.findIndex((r) => treeKey(r.path) === state.treeSel);
    if (!wrap || i < 0) {
      return;
    }
    const head = wrap.querySelector("thead");
    const above = (head ? head.offsetHeight : 0) + (wrap.querySelector(".tablebar") || { offsetHeight: 0 }).offsetHeight;
    const y = above + i * ROW;
    if (where === "center") {
      wrap.scrollTop = Math.max(0, y - wrap.clientHeight / 2);
    } else if (y < wrap.scrollTop + above) {
      wrap.scrollTop = y - above;
    } else if (y + ROW > wrap.scrollTop + wrap.clientHeight) {
      wrap.scrollTop = y + ROW - wrap.clientHeight;
    }
    paintTree();
  }

  /**
   * Whether the tree's row `key` is open: while filtering, every row that
   * holds a match is, but those closed since; else those opened.
   */
  function isOpen(key) {
    return state.filtered ? !state.closed.has(key) : state.open.has(key);
  }

  function toggle(path, open) {
    const k = treeKey(path);
    const now = open ?? !isOpen(k);
    if (state.filtered) {
      if (now) {
        state.closed.delete(k);
      } else {
        state.closed.add(k);
      }
    } else if (now) {
      state.open.add(k);
    } else {
      state.open.delete(k);
    }
    renderTree();
  }

  /** Opens every row below the current one (up to `limit` rows shown). */
  function expandAll(limit) {
    const queue = [[current(), state.path]];
    let shown = (current().children || []).length;
    while (queue.length) {
      const [row, path] = queue.shift();
      for (const c of row.children || []) {
        if (c.children && shown + c.children.length <= limit) {
          const p = [...path, c.name];
          state.open.add(treeKey(p));
          shown += c.children.length;
          queue.push([c, p]);
        }
      }
    }
    renderTree();
  }

  // Rows are this tall (view.css), so that only those in view are drawn.
  const ROW = 22;

  function renderTree() {
    const map = $("map");
    const rows = visibleRows();
    state.treeRows = rows;
    if (!rows.some((r) => treeKey(r.path) === state.treeSel)) {
      state.treeSel = rows.length ? treeKey(rows[0].path) : null;
    }
    const old = map.querySelector(".treewrap");
    const top = old ? old.scrollTop : 0;
    const mangledHead = state.showMangled ? el("th", {}, "Mangled") : null;
    // Sortable by name, or by either size (a diff's: its change, signed, so
    // that descending is growth first and ascending shrinkage first); a
    // click again reverses it.
    const head = (key, label, cls, about) =>
      el(
        "th",
        {
          class: (cls || "") + " sortable" + (state.sort.key === key ? " sorted" : ""),
          title: about,
          "aria-sort": state.sort.key === key ? (state.sort.desc ? "descending" : "ascending") : undefined,
          onclick: () => {
            state.sort = { key, desc: state.sort.key === key ? !state.sort.desc : key !== "name" };
            save();
            renderTree();
          },
        },
        label,
        state.sort.key === key ? (state.sort.desc ? " ▾" : " ▴") : ""
      );
    const change = isDiff() ? " (its change: ▾ growth first, ▴ shrinkage first)" : "";
    const table = el(
      "table",
      { class: "rows tree", role: "treegrid", "aria-rowcount": String(rows.length) },
      el(
        "thead",
        {},
        el(
          "tr",
          {},
          el("th", { class: "acts" }),
          head("name", "Name", "", "Sort by name"),
          mangledHead,
          head("file", "File", "n", "Sort by file size" + change),
          head("vm", "Virtual", "n", "Sort by virtual size" + change),
          el("th", { class: "share" }, isDiff() ? "" : "Of parent"),
          el("th", { class: "n" }, isDiff() ? "" : "Of all"),
          el("th", { class: "n" }, "Items")
        )
      ),
      el("tbody")
    );
    const wrap = el(
      "div",
      { class: "treewrap", onscroll: () => paintTree() },
      el(
        "div",
        { class: "tablebar" },
        el("span", {}, `${rows.length.toLocaleString()} rows` + (state.filtered ? " match" : "")),
        el("span", { class: "spacer" }),
        vscode
          ? el(
              "label",
              { class: "check", title: "Show each symbol's mangled (decorated) name" },
              el("input", {
                type: "checkbox",
                checked: state.showMangled ? true : undefined,
                onchange: (e) => {
                  state.showMangled = e.target.checked;
                  save();
                  renderTree();
                },
              }),
              "Mangled names"
            )
          : null,
        el("a", { href: "#", onclick: (e) => { e.preventDefault(); if (state.filtered) { state.closed.clear(); renderTree(); } else { expandAll(5000); } } }, "Expand all"),
        el("a", { href: "#", onclick: (e) => { e.preventDefault(); if (state.filtered) { for (const r of state.treeRows) { if (r.row.children) { state.closed.add(treeKey(r.path)); } } } else { state.open.clear(); } renderTree(); } }, "Collapse all")
      ),
      table
    );
    map.replaceChildren(wrap);
    wrap.scrollTop = top;
    paintTree();
  }

  /** Draws the tree's rows in view (and a few more), spacers for the rest. */
  function paintTree() {
    const wrap = $("map").querySelector(".treewrap");
    const tbody = wrap && wrap.querySelector("tbody");
    if (!tbody) {
      return;
    }
    const rows = state.treeRows;
    const whole = value(total());
    const first = Math.max(0, Math.floor(wrap.scrollTop / ROW) - 30);
    const last = Math.min(rows.length, Math.ceil((wrap.scrollTop + wrap.clientHeight) / ROW) + 30);
    const columns = state.showMangled ? 8 : 7;
    const spacer = (n) => {
      const tr = el("tr", { class: "spacer", "aria-hidden": "true" }, el("td", { colspan: String(columns) }));
      tr.style.height = n * ROW + "px";
      return tr;
    };
    const out = [];
    if (first > 0) {
      out.push(spacer(first));
    }
    for (let k = first; k < last; k++) {
      out.push(treeRow(rows[k], whole, tbody));
    }
    if (last < rows.length) {
      out.push(spacer(rows.length - last));
    }
    tbody.replaceChildren(...out);
  }

  /**
   * What happened to a diff's row, by its sizes before and after (in the
   * domain shown; either, where one is zero): added (nothing before),
   * removed (nothing after), grew, shrank, or the same. As [class, mark,
   * description].
   */
  function changeOf(c) {
    const before = (state.domain === "vm" ? c.old_vm : c.old_file) || 0;
    const now = signed(c);
    const beforeAny = (c.old_vm || 0) + (c.old_file || 0);
    const afterAny = (c.old_vm || 0) + (c.vm || 0) + (c.old_file || 0) + (c.file || 0);
    if (beforeAny === 0 && afterAny > 0) {
      return ["added", "+", "Added: new in this build"];
    }
    if (beforeAny > 0 && afterAny === 0) {
      return ["removed", "\u2212", "Removed: gone from this build"];
    }
    if (now > 0) {
      return ["grew", "\u2197", `Grew by ${formatSize(now)} (from ${formatSize(before)})`];
    }
    if (now < 0) {
      return ["shrank", "\u2198", `Shrank by ${formatSize(-now)} (from ${formatSize(before)})`];
    }
    return ["same", "", "The same size"];
  }

  /** One row of the tree. */
  function treeRow(r, whole, tbody) {
    const c = r.row;
    const key = treeKey(r.path);
    const open = isOpen(key);
    const parentValue = value(r.parent);
    const share = parentValue ? (100 * value(c)) / parentValue : 0;
    // Guides: a line down through each ancestor level with rows below.
    const guides = r.lasts.slice(0, -1).map((last) => el("span", { class: "guide" + (last ? " none" : "") }));
    const elbow = el("span", { class: "guide elbow" + (r.lasts[r.lasts.length - 1] ? " last" : "") });
    const twisty = c.children
      ? el(
          "span",
          {
            class: "twisty",
            role: "button",
            "aria-label": open ? "Collapse" : "Expand",
            onclick: (e) => {
              e.stopPropagation();
              state.treeSel = key;
              toggle(r.path);
            },
          },
          open ? "▾" : "▸"
        )
      : el("span", { class: "twisty leaf" });
    // A diff's row: what happened to it (added, removed, grew, shrank); else
    // its color.
    let swatch;
    if (isDiff()) {
      const [kind, mark, about] = changeOf(c);
      swatch = el("span", { class: "change " + kind, title: about, "aria-label": about }, mark);
    } else {
      swatch = el("span", { class: "swatch" });
      swatch.style.background = colorFor(c.name, r.path.length - 1, r.path[0]);
    }
    const act = openButton(c, r.path);
    const items = c.children ? `${c.children.length}` : c.other_count ? `${c.other_count} rows` : "";
    const mangled = state.mangled.get(c.name);
    const tr = el(
      "tr",
      {
        class: (key === state.treeSel ? "selected" : "") + (isDiff() ? diffClass(signed(c)) : ""),
        role: "row",
        "aria-level": String(r.depth + 1),
        "aria-expanded": c.children ? String(open) : undefined,
        "data-key": key,
        "data-vscode-context": rowContext(c, r.path),
        onclick: () => {
          state.treeSel = key;
          for (const x of tbody.querySelectorAll("tr.selected")) {
            x.classList.remove("selected");
          }
          tr.classList.add("selected");
        },
        ondblclick: () => c.children && toggle(r.path),
        onmousemove: (e) => card(c, r.path, e),
        onmouseleave: hideCard,
      },
      el("td", { class: "acts" }, act),
      el("td", { class: "tname" }, el("span", { class: "indent" }, guides, elbow), twisty, swatch, el("span", { class: "label", title: mangled ? `${c.name}\n${mangled}` : c.name }, c.name)),
      state.showMangled ? el("td", { class: "mangled mono", title: mangled || "" }, mangled || "") : null,
      el("td", { class: "n" + (isDiff() ? diffClass(c.file) : "") }, shown(c.file)),
      el("td", { class: "n" + (isDiff() ? diffClass(c.vm) : "") }, shown(c.vm)),
      el("td", { class: "share" }, isDiff() ? "" : bar(share), isDiff() ? "" : el("span", { class: "pct" }, percent(value(c), parentValue))),
      el("td", { class: "n muted" }, isDiff() ? "" : percent(value(c), whole)),
      el("td", { class: "n muted" }, items)
    );
    return tr;
  }

  /** Moves the tree's selection, or opens and closes rows (the arrow keys). */
  function treeKeydown(e) {
    const rows = state.treeRows;
    const i = rows.findIndex((r) => treeKey(r.path) === state.treeSel);
    if (i < 0) {
      return false;
    }
    const r = rows[i];
    const open = isOpen(state.treeSel);
    let next = i;
    switch (e.key) {
      case "ArrowDown":
        next = Math.min(rows.length - 1, i + 1);
        break;
      case "ArrowUp":
        next = Math.max(0, i - 1);
        break;
      case "Home":
        next = 0;
        break;
      case "End":
        next = rows.length - 1;
        break;
      case "ArrowRight":
        if (r.row.children && !open) {
          toggle(r.path, true);
          return true;
        }
        next = r.row.children ? i + 1 : i;
        break;
      case "ArrowLeft":
        if (open) {
          toggle(r.path, false);
          return true;
        }
        next = Math.max(0, rows.findIndex((x) => treeKey(x.path) === treeKey(r.path.slice(0, -1))));
        if (r.depth === 0) {
          next = i;
        }
        break;
      case "Enter":
      case " ":
        if (r.row.children) {
          toggle(r.path);
        }
        return true;
      case "d":
      case "D":
        openRow(r.row, r.path);
        return true;
      default:
        return false;
    }
    state.treeSel = treeKey(rows[next].path);
    scrollToSelected("nearest");
    return true;
  }

  function select(index) {
    state.selected = index;
    const rows = $("details").querySelectorAll("tbody tr");
    rows.forEach((r, i) => r.classList.toggle("selected", i === index));
    if (rows[index]) {
      rows[index].scrollIntoView({ block: "nearest" });
      rows[index].focus();
    }
  }

  function renderTable() {
    const details = $("details");
    const row = current();
    const kids = sortedChildren(row);
    const whole = value(row);
    const head = (key, label, cls) =>
      el(
        "th",
        {
          class: (cls || "") + " sortable" + (state.sort.key === key ? " sorted" : ""),
          onclick: () => {
            state.sort = { key, desc: state.sort.key === key ? !state.sort.desc : key !== "name" };
            save();
            renderTable();
          },
        },
        label,
        state.sort.key === key ? (state.sort.desc ? " ▾" : " ▴") : ""
      );
    const tbody = el("tbody");
    const LIMIT = 500;
    kids.slice(0, LIMIT).forEach((c, i) => {
      const share = whole ? (100 * value(c)) / whole : 0;
      const name = c.children
        ? el("a", { href: "#", onclick: (e) => { e.preventDefault(); go([...state.path, c.name]); } }, c.name)
        : el("span", {}, c.name);
      // A function's code, or a datum's bytes, from a symbols level.
      const act = openButton(c, [...state.path, c.name]);
      const tr = el(
        "tr",
        {
          tabindex: "-1",
          class: (i === state.selected ? "selected" : "") + (isDiff() ? diffClass(signed(c)) : ""),
          "data-vscode-context": rowContext(c, [...state.path, c.name]),
          onclick: () => select(i),
          ondblclick: () => c.children && go([...state.path, c.name]),
        },
        el("td", { class: "acts" }, act),
        el("td", { class: "name" }, name),
        el("td", { class: "n" + (isDiff() ? diffClass(c.file) : "") }, shown(c.file)),
        el("td", { class: "n" + (isDiff() ? diffClass(c.vm) : "") }, shown(c.vm)),
        el("td", { class: "share" }, isDiff() ? "" : bar(share), isDiff() ? "" : el("span", { class: "pct" }, percent(value(c), whole)))
      );
      tbody.append(tr);
    });
    const table = el(
      "table",
      { class: "rows" },
      el("thead", {}, el("tr", {}, el("th", { class: "acts" }), head("name", "Name"), head("file", "File", "n"), head("vm", "Virtual", "n"), head("size", isDiff() ? "" : "Share", "share"))),
      tbody
    );
    details.replaceChildren(
      el(
        "div",
        { class: "tablebar" },
        el("span", {}, kids.length > LIMIT ? `the largest ${LIMIT} of ${kids.length.toLocaleString()} rows (the filter finds the others)` : `${kids.length} rows`),
        el("span", { class: "spacer" }),
        vscode ? el("a", { href: "#", onclick: (e) => { e.preventDefault(); post({ command: "copy", text: markdown(row, kids) }); } }, "Copy as Markdown") : null
      ),
      table
    );
  }

  // (Styles set through the DOM, which the page's security policy allows.)
  function bar(share) {
    const b = el("span", { class: "bar" });
    b.style.width = Math.min(100, share).toFixed(1) + "px";
    return b;
  }

  function markdown(row, kids) {
    const lines = [`| ${row.name} | File | Virtual |`, "|---|--:|--:|"];
    for (const c of kids) {
      lines.push(`| ${c.name.replace(/\|/g, "\\|")} | ${shown(c.file)} | ${shown(c.vm)} |`);
    }
    return lines.join("\n");
  }

  // -------------------------------------------------------------- findings

  function renderFindings() {
    const f = state.message.findings;
    const file = state.message.file || "";
    // Build changes (hexc recommend): each measured, an estimate of the bytes
    // the change would save. (Not its duplicated variables: Duplicate data,
    // below, lists them.)
    const all = state.message.recommendations;
    const recs = all && Object.assign({}, all, { recommendations: (all.recommendations || []).filter((r) => r.kind !== "duplicates") });
    if (recs) {
      recs.saving = recs.recommendations.reduce((n, r) => n + (r.saving || 0), 0);
    }
    const wasted = f.duplicate_data.wasted_file + f.wasteful_virtuals.wasted + ((recs && recs.saving) || 0);
    $("header").replaceChildren(
      el("div", { class: "title" }, el("span", { class: "name" }, file.split(/[\\/]/).pop()), el("span", { class: "path", title: file }, file)),
      el("div", { class: "chips" }, el("span", { class: "chip" + (wasted ? " grows" : "") }, el("b", {}, "Recoverable "), formatSize(wasted)))
    );
    $("toolbar").replaceChildren(el("span", { class: "here" }, "Size Reduction Opportunities"), el("span", { class: "level" }, "what could be smaller, how, and by how much"));
    const main = $("main");
    if (main) {
      main.remove();
    }
    const details = $("details");
    details.className = "findings";
    details.replaceChildren();
    // Each kind of finding: a card, closed at first, with a sortable table.
    const size = (n) => ({ text: formatSize(n), sort: n });
    // (The first `numeric` columns are numbers: all but the last, unless said.)
    const section = (title, summary, wasted, head, rows, numeric = head.length - 1) => {
      const columns = head.map((h, i) => ({ label: h, numeric: i < numeric }));
      const table = rows.length ? sortableTable(columns, rows, { sort: { col: 0, desc: true } }) : el("p", { class: "none" }, "None found.");
      details.append(
        el(
          "details",
          { class: "card" + (rows.length ? "" : " empty") },
          el("summary", {}, el("h2", {}, title), el("span", { class: "chip" }, wasted)),
          el("p", {}, summary),
          table
        )
      );
    };
    if (recs) {
      const linked = [];
      if (recs.link) {
        linked.push(`/OPT:REF ${recs.link.optRef ? "on" : "off"}`, `/OPT:ICF ${recs.link.optIcf ? "on" : "off"}`);
      }
      section(
        "Build changes",
        `Changes to how it's built that would make it smaller, each measured on this build: the saving is the bytes it would no longer hold.${linked.length ? ` (Linked with ${linked.join(", ")}.)` : ""}`,
        `save ${formatSize(recs.saving || 0)}`,
        ["Saving", "Change", "For example"],
        (recs.recommendations || []).map((r) => [
          size(r.saving),
          r.advice,
          (r.examples || [])
            .slice(0, 5)
            .map((e) => `${e.name} (${formatSize(e.size)})`)
            .join("; "),
        ]),
        1
      );
    } else if (state.message.recommendationsError) {
      section("Build changes", state.message.recommendationsError, "", ["Saving", "Change", "For example"], []);
    }
    const d = f.duplicate_data;
    section(
      "Duplicate data",
      `${d.count} variables copied into several compilands. A file-scope static or non-extern const in a header gets a copy in every compiland that includes it: make it inline constexpr, or extern with one definition.`,
      `${formatSize(d.wasted_file)} wasted`,
      ["Wasted", "Size", "Copies", "Variable"],
      d.items.map((i) => [size(Math.max(i.wasted_file, i.wasted_vm)), size(Math.max(i.file_size, i.vm_size)), i.copies, i.name])
    );
    const v = f.wasteful_virtuals;
    section(
      "Wasteful virtuals",
      `${v.count} classes with virtual functions that needn't be virtual: each costs a vtable slot in every class that derives from it.`,
      `${formatSize(v.wasted)} of vtable slots`,
      ["Wasted", "Per slot", "Class and functions"],
      v.items.map((i) => [
        size(i.wasted),
        size(i.per_slot),
        `${i.class}: ${[...i.pure_with_one_override.map((n) => n + " (pure, one override)"), ...i.never_overridden.map((n) => n + " (never overridden)")].join("; ")}`,
      ])
    );
    const t = f.template_families;
    section(
      "Template families",
      `${t.count} templates instantiated several times. Nearly identical instances can share a type-independent base or helper.`,
      `${formatSize(t.size)} in all`,
      ["Size", "Instances", "Similar", "Template"],
      t.items.map((i) => [size(Math.max(i.file_size, i.vm_size)), i.instances, i.similarity == null ? { text: "-", sort: "" } : { text: Math.round(i.similarity * 100) + "%", sort: i.similarity }, i.family])
    );
  }

  // ------------------------------------------------------------------ main

  function render() {
    if (!state.message) {
      return;
    }
    if (state.message.kind === "findings") {
      renderFindings();
      return;
    }
    hideCard();
    renderHeader();
    renderToolbar();
    const tree = state.mode === "tree";
    document.body.classList.toggle("treemode", tree);
    if (state.mode === "sunburst") {
      renderSunburst();
    } else if (tree) {
      renderTree();
    } else {
      renderTreemap();
    }
    if (tree) {
      $("details").replaceChildren();
    } else {
      renderTable();
    }
    $("legend").replaceChildren(
      isDiff() && tree
        ? el(
            "span",
            { class: "changes" },
            el("b", { class: "change added" }, "+"),
            "added ",
            el("b", { class: "change removed" }, "−"),
            "removed ",
            el("b", { class: "change grew" }, "↗"),
            "grew ",
            el("b", { class: "change shrank" }, "↘"),
            "shrank · click File or Virtual to sort by the change, again to reverse"
          )
        : isDiff()
        ? el("span", {}, el("i", { class: "sw grows" }), "grew ", el("i", { class: "sw shrinks" }), "shrank · stronger color, larger change")
        : el("span", {}, tree ? "Arrows move, open, and close · Enter toggles · / filters · right-click a symbol for more" : "Click a box to open it · Backspace goes back · / filters")
    );
  }

  document.addEventListener("keydown", (e) => {
    if (!state.message || state.message.kind !== "report") {
      return;
    }
    const typing = e.target && e.target.tagName === "INPUT";
    if (state.mode === "tree" && !typing && e.key !== "/" && treeKeydown(e)) {
      e.preventDefault();
      return;
    }
    if (e.key === "/" && !typing) {
      e.preventDefault();
      $("search").focus();
    } else if ((e.key === "Backspace" || (e.altKey && e.key === "ArrowLeft")) && !typing && state.path.length) {
      e.preventDefault();
      go(state.path.slice(0, -1));
    } else if (!typing && (e.key === "ArrowDown" || e.key === "ArrowUp")) {
      e.preventDefault();
      const n = (current().children || []).length;
      if (n) {
        select(Math.max(0, Math.min(n - 1, state.selected + (e.key === "ArrowDown" ? 1 : -1))));
      }
    } else if (!typing && (e.key === "d" || e.key === "D") && state.selected >= 0) {
      const c = sortedChildren(current())[state.selected];
      if (c) {
        openRow(c, [...state.path, c.name]);
      }
    } else if (!typing && e.key === "Enter" && state.selected >= 0) {
      const c = sortedChildren(current())[state.selected];
      if (c && c.children) {
        go([...state.path, c.name]);
      }
    }
  });

  window.addEventListener("message", (e) => {
    const m = e.data;
    if (!m || !m.kind) {
      return;
    }
    if (m.kind === "failed") {
      // (A grouping this file lacks, say: the report shown stays.)
      if (!state.message) {
        $("header").replaceChildren(el("div", { class: "title" }, el("span", { class: "name" }, m.message === "Cancelled" ? "Cancelled" : "hexc failed")), el("div", { class: "path" }, m.message || ""));
      }
      return;
    }
    if (m.kind === "names") {
      state.mangled = new Map((m.names || []).map((n) => [n.name, n.mangled]));
      if (state.message && state.message.kind === "report") {
        applyFilter();
        render();
      }
      return;
    }
    if (m.kind === "goto") {
      if (state.message && state.message.kind === "report" && Array.isArray(m.at)) {
        goTo(m.at);
      }
      return;
    }
    // A refresh keeps the place, where it still exists.
    const keep = state.message && m.refresh && state.message.file === m.file ? state.path : [];
    // Every label of every symbol at once (hexc size -table): the report
    // is made here, by the grouping chosen, and made again when it changes.
    if (m.kind === "report" && m.table) {
      m.report = fromTable(m.table, m.levels || []);
      mangledFromTable(m.table);
    }
    state.message = m;
    applyFilter();
    state.path = m.kind === "report" && rowAt(total(), keep) ? keep : [];
    state.selected = -1;
    render();
    if (m.kind === "report" && Array.isArray(m.at)) {
      goTo(m.at);
    }
  });
  let pending = 0;
  window.addEventListener("resize", () => {
    cancelAnimationFrame(pending);
    pending = requestAnimationFrame(() => render());
  });
})();
