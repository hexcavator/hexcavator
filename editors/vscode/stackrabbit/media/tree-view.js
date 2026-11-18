// The trace editor's view: a summary, the tree's settings, and the stack
// tree as a table whose rows are drawn only where they show. Every
// request goes to the extension, which asks the engine.
"use strict";
(function () {
  const vscode = acquireVsCodeApi();
  const { TreeModel, formatWeight } = globalThis.StackrabbitTree;
  const ROW = 22;

  const $ = (id) => document.getElementById(id);
  const summaryEl = $("summary");
  const statusEl = $("status");
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
      createTree();
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
  }

  function spec() {
    const group = controls.group.value === "" ? [] : controls.group.value.split(",");
    return {
      source: controls.source.value,
      groupBy: group,
      frames: controls.frames.value,
      invert: controls.invert.checked,
    };
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
  window.addEventListener("resize", () => requestAnimationFrame(draw));
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
  }
  $("hot").addEventListener("click", () => {
    hotPath();
    viewport.focus();
  });

  vscode.postMessage({ type: "ready" });
})();
