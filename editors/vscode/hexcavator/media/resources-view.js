// The Resources page: what a binary holds besides its code, and what it says
// of itself (hexc resources -json): a PE image's resources by type, name,
// and language; a Mach-O image's Info.plist, entitlements, and versions; an
// ELF image's notes; a WebAssembly module's custom sections. The list
// (grouped, filtered) on the left; the selected one, decoded, on the right
// (hexc resources -json -show <id>): its version information, text, strings,
// a dialog drawn from its template, a menu, accelerators, icons, cursors,
// and bitmaps as images, or its bytes. Each can be saved (as an .ico, .cur,
// or .bmp file where it's an image) or copied.
"use strict";

(function () {
  const vscode = typeof acquireVsCodeApi === "function" ? acquireVsCodeApi() : null;
  window.__hexcVscode = vscode;
  const post = (m) => vscode && vscode.postMessage(m);
  const $ = (id) => document.getElementById(id);

  const state = {
    file: null,
    list: null,
    query: "",
    closed: new Set(),
    selected: null,
    // The selected item, decoded (once it's come).
    item: null,
  };
  const saved = vscode && vscode.getState();
  if (saved) {
    state.selected = saved.selected || null;
    state.closed = new Set(saved.closed || []);
  }
  const save = () => vscode && vscode.setState({ selected: state.selected, closed: [...state.closed] });

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

  const plural = (n, one, many) => `${n.toLocaleString()} ${n === 1 ? one : many || one + "s"}`;
  const size = (n) => (n < 1024 ? `${n} B` : n < 1 << 20 ? `${(n / 1024).toFixed(1)} KB` : `${(n / (1 << 20)).toFixed(1)} MB`);

  function render() {
    const l = state.list;
    const total = l.items.reduce((s, i) => s + i.size, 0);
    $("header").replaceChildren(
      el("div", { class: "title" }, el("span", { class: "name" }, l.file), el("span", { class: "path", title: state.file }, state.file)),
      el(
        "div",
        { class: "chips" },
        el("span", { class: "chip" }, el("b", {}, plural(l.items.length, "item"))),
        el("span", { class: "chip" }, size(total)),
        el("span", { class: "chip" }, plural(new Set(l.items.map((i) => i.group)).size, "group"))
      )
    );
    const filter = el("input", {
      type: "search",
      placeholder: "Filter by name or what it says",
      value: state.query,
      oninput: (e) => {
        state.query = e.target.value;
        renderList();
      },
    });
    $("toolbar").replaceChildren(
      el("span", { class: "here" }, "Resources"),
      el("span", { class: "level" }, "what it holds besides its code, and what it says of itself"),
      el("span", { class: "spacer" }),
      el("span", { class: "searchbox" }, filter)
    );
    $("main").replaceChildren(
      el(
        "div",
        { class: "respage" },
        el("div", { class: "reslist", id: "reslist" }),
        el("div", { class: "resitem", id: "resitem" })
      )
    );
    renderList();
    if (!l.items.length) {
      $("resitem").replaceChildren(el("div", { class: "muted" }, "No resources or metadata."));
    } else if (!state.selected || !l.items.some((i) => i.id === state.selected)) {
      select(l.items[0].id);
    } else {
      select(state.selected);
    }
  }

  function renderList() {
    const q = state.query.toLowerCase();
    const groups = new Map();
    for (const i of state.list.items) {
      if (q && ![i.id, i.name, i.summary, i.language || ""].some((s) => s.toLowerCase().includes(q))) {
        continue;
      }
      if (!groups.has(i.group)) {
        groups.set(i.group, []);
      }
      groups.get(i.group).push(i);
    }
    const tbody = el("tbody");
    for (const [g, items] of groups) {
      const open = q || !state.closed.has(g);
      tbody.append(
        el(
          "tr",
          {
            class: "group",
            onclick: () => {
              if (state.closed.has(g)) {
                state.closed.delete(g);
              } else {
                state.closed.add(g);
              }
              save();
              renderList();
            },
          },
          el("td", { colspan: 3 }, el("span", { class: "twisty" }, open ? "▾" : "▸"), el("b", {}, g), el("span", { class: "muted" }, `  ${items.length}`))
        )
      );
      if (!open) {
        continue;
      }
      for (const i of items) {
        tbody.append(
          el(
            "tr",
            {
              class: "res" + (i.id === state.selected ? " selected" : ""),
              "data-id": i.id,
              onclick: () => select(i.id),
              title: i.id,
            },
            el("td", { class: "rname" }, el("span", { class: "twisty leaf" }), i.name, i.language ? el("span", { class: "muted" }, `  ${i.language}`) : null),
            el("td", { class: "rsummary muted" }, i.summary),
            el("td", { class: "num muted" }, i.size ? size(i.size) : "")
          )
        );
      }
    }
    const list = $("reslist");
    const top = list.scrollTop;
    list.replaceChildren(groups.size ? el("table", { class: "rows restable" }, tbody) : el("div", { class: "muted" }, "Nothing matches."));
    list.scrollTop = top;
  }

  function select(id) {
    state.selected = id;
    save();
    for (const x of document.querySelectorAll("tr.res.selected")) {
      x.classList.remove("selected");
    }
    const row = document.querySelector(`tr.res[data-id="${CSS.escape(id)}"]`);
    if (row) {
      row.classList.add("selected");
    }
    if (state.item && state.item.id === id) {
      renderItem();
      return;
    }
    $("resitem").replaceChildren(el("div", { class: "muted" }, "Reading…"));
    post({ command: "show", id });
  }

  /** `s` (base64) as bytes. */
  function bytes(s) {
    const bin = atob(s || "");
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
      out[i] = bin.charCodeAt(i);
    }
    return out;
  }

  function hexdump(data, truncated) {
    const lines = [];
    for (let at = 0; at < data.length; at += 16) {
      const row = data.subarray(at, at + 16);
      const hex = [...row].map((b) => b.toString(16).padStart(2, "0")).join(" ");
      const text = [...row].map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join("");
      lines.push(`${at.toString(16).padStart(8, "0")}  ${hex.padEnd(48)} ${text}`);
    }
    if (truncated) {
      lines.push("… (the first 64 KB)");
    }
    return el("pre", { class: "hex" }, lines.join("\n"));
  }

  const pairs = (rows) =>
    el(
      "table",
      { class: "rows pairs" },
      el(
        "tbody",
        {},
        rows.map(([k, v]) => el("tr", {}, el("td", { class: "key" }, k), el("td", { class: "mono" }, v)))
      )
    );

  const image = (file, mime, w, h, title) => {
    const img = el("img", { src: `data:${mime};base64,${file}`, alt: title, title });
    if (w && h) {
      // (Small images, magnified so they can be seen: crisply.)
      const scale = Math.max(1, Math.min(4, Math.floor(64 / Math.max(w, h))));
      img.style.width = `${w * scale}px`;
      img.style.height = `${h * scale}px`;
    }
    return img;
  };

  /** A dialog, drawn from its template: its controls where they'd be, in
   *  dialog units (about a quarter of the font's average width, an eighth
   *  of its height: here, 1.5 by 1.75 pixels). */
  function dialog(d) {
    const X = 1.5;
    const Y = 1.75;
    const face = el("div", { class: "dlgface" });
    face.style.width = `${d.rect[2] * X}px`;
    face.style.height = `${d.rect[3] * Y}px`;
    for (const c of d.controls) {
      const cls = String(c.class || "").toLowerCase();
      const text = typeof c.text === "string" && !c.text.startsWith("#") ? c.text.replace(/&(.)/g, "$1") : "";
      const kind = cls === "button" ? "button" : cls === "edit" ? "edit" : cls === "static" ? "static" : cls === "listbox" || cls === "combobox" ? "list" : "other";
      const box = el("div", { class: `dlgctl ${kind}`, title: `${c.class} ${c.id}${c.text ? " " + c.text : ""}` }, kind === "other" && !text ? c.class : text);
      box.style.left = `${c.rect[0] * X}px`;
      box.style.top = `${c.rect[1] * Y}px`;
      box.style.width = `${c.rect[2] * X}px`;
      box.style.height = `${c.rect[3] * Y}px`;
      face.append(box);
    }
    const frame = el("div", { class: "dlgframe" }, el("div", { class: "dlgtitle" }, d.title || "(no title)"), face);
    const rows = d.controls.map((c) =>
      el(
        "tr",
        {},
        el("td", { class: "num" }, c.id),
        el("td", {}, c.class),
        el("td", {}, c.text === null ? "" : c.text),
        el("td", { class: "mono muted" }, c.rect.join(", ")),
        el("td", { class: "mono muted" }, c.style)
      )
    );
    return [
      el("div", { class: "muted" }, `${d.rect[2]} × ${d.rect[3]} dialog units` + (d.font ? `, ${d.font.face} ${d.font.size} pt` : "") + `, style ${d.style}`),
      frame,
      el(
        "table",
        { class: "rows" },
        el("thead", {}, el("tr", {}, el("th", {}, "ID"), el("th", {}, "Class"), el("th", {}, "Text"), el("th", {}, "Rectangle"), el("th", {}, "Style"))),
        el("tbody", {}, rows)
      ),
    ];
  }

  function menu(items) {
    return el(
      "ul",
      { class: "menu" },
      (items || []).map((i) =>
        i.separator
          ? el("li", { class: "sep" }, el("hr"))
          : i.items
            ? el("li", {}, el("span", {}, i.text || "(popup)"), menu(i.items))
            : el("li", {}, el("span", {}, i.text), el("span", { class: "muted" }, `  ${i.id}`))
      )
    );
  }

  /** The text to copy for the item shown. */
  function copyText(v) {
    switch (v.view) {
      case "text":
        return v.text;
      case "strings":
        return v.strings.map(([id, s]) => `${id}\t${s}`).join("\n");
      case "messages":
        return v.messages.map(([id, s]) => `${id}\t${s}`).join("\n");
      case "table":
        return v.pairs.map(([k, x]) => `${k}\t${x}`).join("\n");
      case "version":
        return (v.tables || []).flatMap((t) => t.strings.map(([k, x]) => `${k}\t${x}`)).join("\n");
      default:
        return null;
    }
  }

  function renderItem() {
    const v = state.item;
    const box = $("resitem");
    const copy = copyText(v);
    const head = el(
      "div",
      { class: "detailhead" },
      el("b", {}, v.id),
      v.language ? el("span", { class: "muted" }, `  ${v.language}`) : null,
      v.size ? el("span", { class: "muted" }, `  ${size(v.size)}`) : null,
      el("span", { class: "spacer" }),
      copy !== null ? el("a", { href: "#", onclick: (e) => { e.preventDefault(); post({ command: "copy", text: copy, what: v.id }); } }, "Copy") : null,
      v.size ? el("a", { href: "#", title: "write it to a file (an image as an .ico, .cur, or .bmp file)", onclick: (e) => { e.preventDefault(); post({ command: "save", id: v.id, view: v.view, name: v.name }); } }, "Save…") : null
    );
    let body;
    switch (v.view) {
      case "version": {
        const f = v.fixed;
        body = [
          f ? pairs([["File version", f.fileVersion], ["Product version", f.productVersion], ["Type", f.type], ...(f.flags && f.flags.length ? [["Flags", f.flags.join(", ")]] : [])]) : null,
          ...(v.tables || []).map((t) => [el("h4", {}, t.key), pairs(t.strings)]),
          (v.translations || []).length ? el("div", { class: "muted" }, "Translations: " + v.translations.map((t) => `${t.language} (code page ${t.codePage})`).join(", ")) : null,
        ];
        break;
      }
      case "text":
        body = el("pre", { class: "text" }, v.text);
        break;
      case "strings":
      case "messages": {
        const rows = v[v.view].map(([id, s]) => el("tr", {}, el("td", { class: "num" }, id), el("td", { class: "pre" }, s)));
        body = el("table", { class: "rows" }, el("thead", {}, el("tr", {}, el("th", {}, "ID"), el("th", {}, v.view === "strings" ? "String" : "Message"))), el("tbody", {}, rows));
        break;
      }
      case "dialog":
        body = v.dialog ? dialog(v.dialog) : el("div", { class: "bad" }, "Not a dialog template.");
        break;
      case "menu":
        body = v.menu ? el("div", { class: "menubox" }, menu(v.menu)) : el("div", { class: "bad" }, "Not a menu template.");
        break;
      case "accelerators":
        body = pairs(v.accelerators.map((a) => [a.keys, String(a.id)]));
        break;
      case "group":
        body = el(
          "div",
          { class: "images" },
          (v.images || []).map((i) =>
            el(
              "figure",
              {},
              image(i.file, "image/x-icon", i.width || 256, i.height || 256, `#${i.id}`),
              el("figcaption", { class: "muted" }, `${i.width || 256}×${i.height || 256}, ${i.bits} bits${i.png ? ", PNG" : ""}`)
            )
          )
        );
        break;
      case "image":
      case "bitmap":
        body = el("div", { class: "images" }, el("figure", {}, image(v.file, v.mime, 0, 0, v.id), el("figcaption", { class: "muted" }, v.summary || "")));
        break;
      case "table":
        body = pairs(v.pairs);
        break;
      default:
        body = hexdump(bytes(v.hex), v.truncated);
    }
    box.replaceChildren(head, el("div", { class: "resbody" }, body));
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
    if (m.kind === "resources") {
      state.file = m.file;
      state.list = m.list;
      state.item = null;
      render();
    }
    if (m.kind === "item" && m.item && m.item.id === state.selected) {
      state.item = m.item;
      renderItem();
    }
    if (m.kind === "itemFailed" && m.id === state.selected) {
      $("resitem").replaceChildren(el("div", { class: "bad" }, m.message || "hexc failed"));
    }
  });
  post({ command: "ready" });
})();
