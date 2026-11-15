// The Dependencies page: what a binary loads (hexc deps -json), as a tree:
// each library it names, where its platform's loader would find it, what
// that loads (each library once: later, a pointer to it), and what's
// missing. The problems first (each opens to its library); a filter;
// system libraries' own dependencies on request (hexc deps -system); and
// the selected library's imports (what's missing marked) below the tree.
"use strict";

(function () {
  const vscode = typeof acquireVsCodeApi === "function" ? acquireVsCodeApi() : null;
  window.__hexcVscode = vscode;
  const post = (m) => vscode && vscode.postMessage(m);
  const $ = (id) => document.getElementById(id);

  const state = {
    file: null,
    graph: null,
    system: false,
    query: "",
    // Open rows' keys (paths of edge indexes), the selected row's.
    open: new Set(),
    closed: new Set(),
    selected: null,
    error: null,
  };
  const saved = vscode && vscode.getState();
  if (saved) {
    state.system = !!saved.system;
  }
  const save = () => vscode && vscode.setState({ system: state.system });

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
  const isApiSet = (name) => /^(api|ext)-/i.test(name);
  const KIND = {
    "delay-load": "delay-load",
    forwarder: "forwarder",
    interpreter: "interpreter",
    "weak-dylib": "weak",
    "reexport-dylib": "re-export",
    "lazy-dylib": "lazy",
    "upward-dylib": "upward",
    assembly: "assembly",
  };

  /** How a module's status reads. */
  function where(m) {
    switch (m.status) {
      case "found":
        return { text: m.path, how: m.how, bad: false };
      case "missing":
        return { text: "not found", bad: true };
      case "wrongArch":
        return { text: `wrong architecture: ${m.path} is ${m.detail && m.detail.arch}`, bad: true };
      case "unreadable":
        return { text: `unreadable: ${m.detail && m.detail.why}`, bad: true };
      case "apiSet":
        return m.detail && m.detail.known ? { text: "API set with no host on this system", bad: true } : { text: "API set (no schema to resolve it)", bad: false };
      case "apiSetHostMissing":
        return { text: `API set: its host, ${m.detail && m.detail.host}, not found`, bad: true };
      case "sharedCache":
        return { text: "in the dyld shared cache", bad: false };
      case "unsearched":
        return { text: "a system library: not searched (no system root for it on this machine)", bad: false };
      case "assembly":
        return m.path ? { text: m.path, how: "side-by-side assembly", bad: false } : { text: "side-by-side assembly, not found", bad: true };
      default:
        return { text: m.status, bad: false };
    }
  }

  /**
   * The rows shown, depth first: each module's dependencies under it, a
   * module's own only where it first appears (later ones point there).
   */
  function rows() {
    const g = state.graph;
    const out = [];
    const first = new Map();
    const q = state.query.toLowerCase();
    // (A filter shows every row whose name matches, and the rows above it.)
    const matches = (d) => !q || d.name.toLowerCase().includes(q) || base(g.modules[d.module].path || "").toLowerCase().includes(q);
    const walk = (m, depth, prefix) => {
      const mod = g.modules[m];
      const kept = [];
      mod.deps.forEach((d, i) => {
        const key = `${prefix}/${i}`;
        const again = first.has(d.module);
        if (!again) {
          first.set(d.module, key);
        }
        const target = g.modules[d.module];
        const expandable = !again && target.deps.length > 0;
        const open = expandable && (q ? !state.closed.has(key) : state.open.has(key) || (depth === 0 && !state.closed.has(key)));
        const row = { d, key, depth, again, expandable, open, target, firstKey: again ? first.get(d.module) : null };
        const at = out.length;
        out.push(row);
        let below = 0;
        if (open) {
          below = walk(d.module, depth + 1, key);
        }
        if (q && !matches(d) && below === 0) {
          out.length = at;
        } else {
          kept.push(row);
        }
      });
      return kept.length;
    };
    walk(0, 0, "");
    return out;
  }

  function render() {
    const g = state.graph;
    const root = g.modules[0];
    const errors = g.problems.filter((p) => p.severity === "error").length;
    const warnings = g.problems.length - errors;
    $("header").replaceChildren(
      el("div", { class: "title" }, el("span", { class: "name" }, root.name), el("span", { class: "path", title: state.file }, state.file)),
      el(
        "div",
        { class: "chips" },
        el("span", { class: "chip" }, el("b", {}, `${root.format || ""} ${root.arch || ""}`)),
        el("span", { class: "chip" }, `${g.modules.length - 1} libraries`),
        el("span", { class: "chip" + (errors ? " grows" : "") }, `${errors} error${errors === 1 ? "" : "s"}`),
        el("span", { class: "chip" + (warnings ? " grows" : "") }, `${warnings} warning${warnings === 1 ? "" : "s"}`),
        el("span", { class: "chip", title: "where system libraries are looked for" }, "System root: " + (g.sysroot || "none"))
      )
    );
    const filter = el("input", {
      type: "search",
      placeholder: "Filter by name",
      value: state.query,
      oninput: (e) => {
        state.query = e.target.value;
        renderTree();
      },
    });
    const system = el("input", {
      type: "checkbox",
      id: "system",
      checked: state.system,
      onchange: (e) => {
        state.system = e.target.checked;
        save();
        state.graph = null;
        post({ command: "refresh", system: state.system });
      },
    });
    $("toolbar").replaceChildren(
      el("span", { class: "here" }, "Dependencies"),
      el("span", { class: "level" }, "where its loader finds each library, and what's missing"),
      el("span", { class: "spacer" }),
      el("span", { class: "searchbox" }, filter),
      el("label", { class: "toggle", title: "read what system libraries load too (and report their problems)" }, system, " System libraries' own"),
      el("a", { href: "#", onclick: (e) => { e.preventDefault(); state.open.clear(); state.closed.clear(); renderTree(); } }, "Collapse all")
    );
    renderTree();
  }

  /** Opens the rows down to the first appearance of module `m`. */
  function reveal(m) {
    const all = [];
    const walk = (at, prefix, seen) => {
      state.graph.modules[at].deps.forEach((d, i) => {
        const key = `${prefix}/${i}`;
        all.push({ key, module: d.module });
        if (!seen.has(d.module)) {
          seen.add(d.module);
          walk(d.module, key, seen);
        }
      });
    };
    walk(0, "", new Set());
    const hit = all.find((r) => r.module === m);
    if (!hit) {
      return;
    }
    const parts = hit.key.split("/").slice(1);
    for (let i = 1; i < parts.length; i++) {
      const k = "/" + parts.slice(0, i).join("/");
      state.open.add(k);
      state.closed.delete(k);
    }
    state.selected = hit.key;
    renderTree();
    const row = document.querySelector(`tr[data-key="${hit.key}"]`);
    if (row) {
      row.scrollIntoView({ block: "center" });
    }
  }

  function toggle(r) {
    if (r.open) {
      state.open.delete(r.key);
      state.closed.add(r.key);
    } else {
      state.open.add(r.key);
      state.closed.delete(r.key);
    }
    renderTree();
  }

  function renderTree() {
    const g = state.graph;
    const all = rows();
    const tbody = el("tbody");
    for (const r of all) {
      const w = where(r.target);
      const name = isApiSet(r.d.name) && r.target.status === "found" ? `${r.d.name} → ${r.target.name}` : r.d.name;
      const missing = r.d.missing || 0;
      const twisty = r.expandable
        ? el("span", { class: "twisty", role: "button", "aria-label": r.open ? "Collapse" : "Expand", onclick: (e) => { e.stopPropagation(); toggle(r); } }, r.open ? "▾" : "▸")
        : el("span", { class: "twisty leaf" });
      const tr = el(
        "tr",
        {
          "data-key": r.key,
          class: [r.key === state.selected ? "selected" : "", w.bad ? "grows" : "", r.target.system ? "system" : ""].join(" ").trim(),
          onclick: () => {
            state.selected = r.key;
            for (const x of tbody.querySelectorAll("tr.selected")) {
              x.classList.remove("selected");
            }
            tr.classList.add("selected");
            details(r);
          },
          ondblclick: () => (r.again ? reveal(r.d.module) : r.expandable && toggle(r)),
        },
        el(
          "td",
          { class: "tname" },
          el("span", { class: "indent" }, indent(r.depth)),
          twisty,
          el("span", { class: "label" }, name),
          KIND[r.d.kind] ? el("span", { class: "muted" }, `  [${KIND[r.d.kind]}]`) : null,
          missing ? el("span", { class: "bad" }, `  ${missing} missing`) : null
        ),
        el("td", { class: "where mono" + (w.bad ? " bad" : "") + (r.again ? " muted" : ""), title: w.text }, r.again ? "(above)" : w.text),
        el("td", { class: "how muted" }, r.again ? "" : w.how || "")
      );
      tbody.append(tr);
    }
    const table = el(
      "table",
      { class: "rows tree deps" },
      el("thead", {}, el("tr", {}, el("th", {}, "Library"), el("th", {}, "Where"), el("th", {}, "Found by"))),
      tbody
    );
    const problems = g.problems.length
      ? el(
          "div",
          { class: "problems" },
          g.problems.map((p) =>
            el(
              "div",
              { class: "problem " + p.severity, onclick: () => reveal(p.module), title: "show it in the tree" },
              el("span", { class: "sev" }, p.severity === "error" ? "✖" : "⚠"),
              " ",
              p.message
            )
          )
        )
      : el("div", { class: "problems none" }, "No problems: everything it loads was found, with what it imports.");
    const notes = (g.notes || []).map((n) => el("div", { class: "note muted" }, n));
    const main = $("main");
    const old = main.querySelector(".treewrap");
    const top = old ? old.scrollTop : 0;
    const wrap = el("div", { class: "treewrap" }, table);
    main.replaceChildren(el("div", { class: "depspage" }, problems, ...notes, wrap, el("div", { id: "depdetails" })));
    wrap.scrollTop = top;
    const sel = all.find((r) => r.key === state.selected);
    if (sel) {
      details(sel);
    }
  }

  /** The selected library: where, and what's imported from it. */
  function details(r) {
    const d = r.d;
    const m = r.target;
    const w = where(m);
    const head = el(
      "div",
      { class: "detailhead" },
      el("b", {}, m.name),
      `  ${m.format || ""} ${m.arch || ""}`,
      m.exports ? `  ·  ${m.exports.toLocaleString()} exports` : "",
      m.path
        ? el("a", { href: "#", title: "add it to the Hexcavator view, to look inside it", onclick: (e) => { e.preventDefault(); post({ command: "openBinary", path: m.path }); } }, "  Explore it")
        : null
    );
    const rowsOf = (d.imports || []).map((i) =>
      el(
        "tr",
        { class: i.status === "missing" || i.status === "brokenForwarder" ? "grows" : "" },
        el("td", { class: "mono" }, i.name != null ? i.name + (i.version ? `@${i.version}` : "") : `#${i.ordinal}`),
        el(
          "td",
          { class: i.status === "missing" || i.status === "brokenForwarder" ? "bad" : "muted" },
          {
            found: "found",
            forwarded: `forwarded to ${i.forwardedTo}`,
            brokenForwarder: `MISSING: forwarded to ${i.forwardedTo}, which isn't there`,
            missing: i.weak ? "missing (weak: no failure)" : "MISSING",
            unchecked: "not checked",
          }[i.status] || i.status
        )
      )
    );
    const unresolved = (m.unresolved || []).map((i) => el("li", { class: "bad mono" }, i.name + (i.version ? `@${i.version}` : "")));
    const box = $("depdetails");
    if (!box) {
      return;
    }
    // (replaceChildren writes null as text: what isn't there is left out.)
    const parts = [
      head,
      el("div", { class: w.bad ? "bad" : "muted" }, w.text + (w.how ? `  (${w.how})` : "")),
      rowsOf.length
        ? el("table", { class: "rows imports" }, el("thead", {}, el("tr", {}, el("th", {}, `Imported from it (${rowsOf.length})`), el("th", {}, "Status"))), el("tbody", {}, rowsOf))
        : el("div", { class: "muted" }, d.kind === "needed" || d.kind === "interpreter" ? "(ELF imports are by name from every library loaded: see what's unresolved, if anything.)" : "(nothing imported by name)"),
      unresolved.length ? el("div", {}, el("b", {}, "Used, and defined by nothing loaded:"), el("ul", {}, unresolved)) : null,
    ];
    box.replaceChildren(...parts.filter((p) => p));
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
    if (m.kind === "deps") {
      state.file = m.file;
      state.graph = m.graph;
      render();
    }
  });
  post({ command: "ready", system: state.system });
})();
