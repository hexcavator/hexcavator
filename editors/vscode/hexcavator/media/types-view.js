// The Types page: every class, structure, and union of a binary (from its
// PDB or DWARF), with its size; sorted by name at first (or by any column),
// filtered as you type (a substring of the name or mangled name, or a
// regular expression). hexc keeps the types; the page asks it for the rows
// in view (hexc types -json -from -n, with the filter and the order), so a
// program with hundreds of thousands of types scrolls and filters at once.
// A row's context menu (or a double click) shows its layout or what refers
// to it.
"use strict";

(function () {
  const vscode = typeof acquireVsCodeApi === "function" ? acquireVsCodeApi() : null;
  window.__hexcVscode = vscode;
  const post = (m) => vscode && vscode.postMessage(m);
  const $ = (id) => document.getElementById(id);
  const ROW = 22;
  // Rows asked for at a time.
  const PAGE = 200;

  const state = {
    file: null,
    query: "",
    regex: false,
    showMangled: false,
    sort: { key: "name", desc: false },
    // What hexc said: how many types, and how many the filter leaves.
    types: 0,
    waste: 0,
    matched: null,
    // Rows by their place in the filtered, sorted list; and the pages asked
    // for (by their first row).
    rows: new Map(),
    asked: new Set(),
    // A new filter or order: answers to older questions are dropped.
    generation: 0,
    selected: null,
    error: null,
  };
  const saved = vscode && vscode.getState();
  if (saved) {
    Object.assign(state, { regex: !!saved.regex, showMangled: !!saved.showMangled, sort: saved.sort || state.sort });
  }
  const save = () => vscode && vscode.setState({ regex: state.regex, showMangled: state.showMangled, sort: state.sort });

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

  function formatSize(n) {
    const units = ["B", "KiB", "MiB", "GiB"];
    let v = Math.abs(n);
    let u = 0;
    while (v >= 1024 && u < units.length - 1) {
      v /= 1024;
      u++;
    }
    return (n < 0 ? "-" : "") + v.toFixed(u === 0 || v >= 100 ? 0 : v >= 10 ? 1 : 2) + " " + units[u];
  }

  /** Forgets the rows (a new filter or order), and asks for those in view. */
  function restart() {
    state.generation++;
    state.rows.clear();
    state.asked.clear();
    state.matched = null;
    state.error = null;
    renderTable();
  }

  /** Asks hexc for the page holding row `at`, unless it has. */
  function ask(at) {
    const from = Math.floor(at / PAGE) * PAGE;
    if (state.asked.has(from)) {
      return;
    }
    state.asked.add(from);
    post({
      command: "page",
      generation: state.generation,
      from,
      n: PAGE,
      filter: state.query.trim(),
      regex: state.regex,
      sort: state.sort.key,
      desc: state.sort.desc,
    });
  }

  let typing = 0;
  function setFilter(query, force) {
    if (query === state.query && !force) {
      return;
    }
    state.query = query;
    if (state.regex && query.trim()) {
      try {
        new RegExp(query.trim());
        $("search").classList.remove("invalid");
      } catch {
        // (The last that compiled stays.)
        $("search").classList.add("invalid");
        return;
      }
    } else {
      $("search").classList.remove("invalid");
    }
    // (A request a keystroke, at most every 60 ms.)
    clearTimeout(typing);
    typing = setTimeout(restart, 60);
  }

  function render() {
    renderHeader();
    renderToolbar();
    renderTable();
  }

  function renderHeader() {
    const name = (state.file || "").split(/[\\/]/).pop();
    $("header").replaceChildren(
      el("div", { class: "title" }, el("span", { class: "name" }, name), el("span", { class: "path", title: state.file }, state.file || "")),
      el(
        "div",
        { class: "chips" },
        el("span", { class: "chip" }, el("b", {}, "Types "), state.types.toLocaleString()),
        el("span", { class: "chip", title: "Bytes their padding wastes, per instance" }, el("b", {}, "Padding "), formatSize(state.waste))
      ),
      el("div", { class: "actions" }, vscode ? el("button", { class: "icon", title: "Run hexc again", onclick: () => post({ command: "refresh" }) }, "⟳") : null)
    );
  }

  /** The toolbar: drawn once (the filter box keeps its focus as you type). */
  function renderToolbar() {
    const input = el("input", {
      id: "search",
      type: "search",
      placeholder: state.regex ? "Filter by a regular expression…" : "Filter by name…",
      title: "Shows the types whose name (or mangled name) has this; Esc clears it",
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
        onclick: (e) => {
          state.regex = !state.regex;
          e.currentTarget.classList.toggle("on", state.regex);
          $("search").placeholder = state.regex ? "Filter by a regular expression…" : "Filter by name…";
          save();
          setFilter(state.query, true);
        },
      },
      ".*"
    );
    $("toolbar").replaceChildren(
      el("span", { class: "here" }, "Types"),
      el("span", { class: "level" }, "classes, structures, and unions"),
      el("span", { class: "spacer" }),
      el(
        "label",
        { class: "check", title: "Show each type's mangled (decorated) name" },
        el("input", {
          type: "checkbox",
          checked: state.showMangled ? true : undefined,
          onchange: (e) => {
            state.showMangled = e.target.checked;
            save();
            renderTable();
          },
        }),
        "Mangled names"
      ),
      el("span", { class: "searchbox" }, input, regex)
    );
  }

  function renderTable() {
    const main = $("main");
    const old = main.querySelector(".treewrap");
    const top = old ? old.scrollTop : 0;
    const head = (key, label, cls) =>
      el(
        "th",
        {
          class: (cls || "") + " sortable" + (state.sort.key === key ? " sorted" : ""),
          onclick: () => {
            state.sort = { key, desc: state.sort.key === key ? !state.sort.desc : key === "size" || key === "waste" };
            save();
            restart();
          },
        },
        label,
        state.sort.key === key ? (state.sort.desc ? " ▾" : " ▴") : ""
      );
    const table = el(
      "table",
      { class: "rows tree types", role: "grid", "aria-rowcount": String(state.matched || 0) },
      el("thead", {}, el("tr", {}, head("name", "Name"), state.showMangled ? head("mangled", "Mangled") : null, head("size", "Size", "n"), head("waste", "Padding", "n"))),
      el("tbody")
    );
    const count =
      state.error != null
        ? state.error
        : state.matched == null
          ? "…"
          : state.query.trim()
            ? `${state.matched.toLocaleString()} of ${state.types.toLocaleString()} types match`
            : `${state.types.toLocaleString()} types`;
    const wrap = el(
      "div",
      { class: "treewrap", onscroll: () => paint() },
      el(
        "div",
        { class: "tablebar" },
        el("span", { id: "count" }, count),
        el("span", { class: "spacer" }),
        el("span", { class: "muted" }, "Double-click a type for its layout; right-click for more")
      ),
      table
    );
    main.replaceChildren(wrap);
    wrap.scrollTop = state.matched == null ? 0 : top;
    paint();
  }

  /** Draws the rows in view (those hexc has sent; asks for the others). */
  function paint() {
    const wrap = $("main").querySelector(".treewrap");
    const tbody = wrap && wrap.querySelector("tbody");
    if (!tbody) {
      return;
    }
    const total = state.matched == null ? PAGE : state.matched;
    const first = Math.max(0, Math.floor(wrap.scrollTop / ROW) - 20);
    const last = Math.min(total, Math.ceil((wrap.scrollTop + wrap.clientHeight) / ROW) + 20);
    for (let k = first; k < Math.max(last, first + 1); k += PAGE) {
      ask(k);
    }
    ask(Math.max(first, last - 1));
    if (state.matched == null) {
      tbody.replaceChildren();
      return;
    }
    const columns = state.showMangled ? 4 : 3;
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
      const t = state.rows.get(k);
      if (!t) {
        out.push(el("tr", { class: "pending" }, el("td", { colspan: String(columns), class: "muted" }, "…")));
        continue;
      }
      const [name, mangled, size, waste, union, incomplete] = t;
      const tr = el(
        "tr",
        {
          class: name === state.selected ? "selected" : "",
          "data-vscode-context": JSON.stringify({ webviewSection: "type", file: state.file, name, preventDefaultContextMenuItems: true }),
          onclick: () => {
            state.selected = name;
            for (const x of tbody.querySelectorAll("tr.selected")) {
              x.classList.remove("selected");
            }
            tr.classList.add("selected");
          },
          ondblclick: () => post({ command: "layout", name }),
        },
        el("td", { class: "tname", title: mangled ? `${name}\n${mangled}` : name }, el("span", { class: "label" }, (union ? "union " : "") + name)),
        state.showMangled ? el("td", { class: "mangled mono", title: mangled || "" }, mangled || "") : null,
        el("td", { class: "n", title: `${size.toLocaleString()} bytes` }, formatSize(size)),
        el("td", { class: "n muted" }, incomplete ? "?" : waste ? formatSize(waste) : "")
      );
      out.push(tr);
    }
    if (last < total) {
      out.push(spacer(total - last));
    }
    tbody.replaceChildren(...out);
  }

  document.addEventListener("keydown", (e) => {
    const typingIn = e.target && e.target.tagName === "INPUT";
    if (e.key === "/" && !typingIn) {
      e.preventDefault();
      $("search").focus();
    }
  });

  window.addEventListener("message", (e) => {
    const m = e.data;
    if (!m || !m.kind) {
      return;
    }
    if (m.kind === "failed") {
      if (m.generation === undefined || m.generation === state.generation) {
        state.error = m.message || "hexc failed";
        state.matched = state.matched ?? 0;
        if (state.file) {
          renderTable();
        } else {
          $("header").replaceChildren(el("div", { class: "title" }, el("span", { class: "name" }, "hexc failed")), el("div", { class: "path" }, m.message || ""));
        }
      }
      return;
    }
    if (m.kind === "types") {
      // A page opened (or refreshed): the first rows come next.
      state.file = m.file;
      state.generation++;
      state.rows.clear();
      state.asked.clear();
      state.matched = null;
      render();
      return;
    }
    if (m.kind === "page" && m.generation === state.generation) {
      const fresh = state.matched == null;
      state.types = m.types;
      state.waste = m.waste;
      state.matched = m.matched;
      state.error = null;
      m.list.forEach((row, k) => state.rows.set(m.from + k, row));
      if (fresh) {
        // (Not the toolbar: the filter box is being typed in.)
        renderHeader();
        renderTable();
      } else {
        const count = $("count");
        if (count) {
          count.textContent = state.query.trim() ? `${state.matched.toLocaleString()} of ${state.types.toLocaleString()} types match` : `${state.types.toLocaleString()} types`;
        }
        paint();
      }
    }
  });
  let pending = 0;
  window.addEventListener("resize", () => {
    cancelAnimationFrame(pending);
    pending = requestAnimationFrame(() => paint());
  });
})();
