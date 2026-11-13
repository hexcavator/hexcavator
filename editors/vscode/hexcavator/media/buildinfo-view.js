// The Build Information page: how a binary was built, from its debug
// information (hexc checksec -audit -json). Its security options (the
// exploit mitigations the image has); the build options its objects
// differ in, worst first (a value's objects shown in the table below at a
// click); the toolchain (the linker's command line, the compilers and
// languages); and every object, with the command line that compiled it:
// grouped (by library, directory, compiler, or language, in the order the
// chips are dragged), filtered as you type, sorted by any column.
"use strict";

(function () {
  const vscode = typeof acquireVsCodeApi === "function" ? acquireVsCodeApi() : null;
  window.__hexcVscode = vscode;
  const post = (m) => vscode && vscode.postMessage(m);
  const $ = (id) => document.getElementById(id);
  const ROW = 22;

  // The levels objects can be grouped by: id, label, what it groups by.
  const CHIPS = [
    ["library", "Library", "the library (.lib or .a) the object came from"],
    ["directory", "Directory", "the directory of the object file"],
    ["compiler", "Compiler", "the compiler and its version"],
    ["language", "Language", "the source language"],
  ];
  const SEVERITY = {
    mismatch: ["Mismatch", "objects built so can't safely be linked together (they disagree on the runtime, the iterator debug level, wchar_t, or exceptions)"],
    weakens: ["Weakens", "some objects were built without a mitigation the others have"],
    differs: ["Differs", "the objects were built differently"],
  };

  const state = {
    file: null,
    report: null,
    builds: [],
    levels: ["library"],
    query: "",
    regex: false,
    // A value of a differing option: only its objects shown.
    only: null,
    sort: { key: "order", desc: false },
    open: new Set(),
    closed: new Set(),
    selected: null,
    error: null,
  };
  const saved = vscode && vscode.getState();
  if (saved) {
    if (Array.isArray(saved.levels)) {
      state.levels = saved.levels.filter((l) => CHIPS.some((c) => c[0] === l));
    }
    state.regex = !!saved.regex;
    state.sort = saved.sort || state.sort;
  }
  const save = () => vscode && vscode.setState({ levels: state.levels, regex: state.regex, sort: state.sort });

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
  const dir = (p) => {
    const k = Math.max((p || "").lastIndexOf("/"), (p || "").lastIndexOf("\\"));
    return k > 0 ? p.slice(0, k) : "";
  };
  const plural = (n, one, many) => `${n.toLocaleString()} ${n === 1 ? one : many || one + "s"}`;
  // An object's key (its name, and its library's: objects of one name come
  // from many libraries).
  const keyOf = (object, library) => object + "\u0000" + (library === object ? "" : library || "");

  /** The full command line: the tool's path, quoted if it must be, then its arguments. */
  function commandLine(b) {
    if (!b.tool) {
      return b.command || "";
    }
    const tool = /\s/.test(b.tool) ? `"${b.tool}"` : b.tool;
    return `${tool} ${(b.command || "").trim()}`;
  }

  // ------------------------------------------------------------- the page

  /**
   * Draws the page. Drawn again (a value chosen, a refresh), it keeps where
   * it was scrolled to and which sections were closed.
   */
  function render() {
    renderHeader();
    const old = $("main").querySelector(".bpage");
    const top = old ? old.scrollTop : 0;
    const closed = new Set(old ? [...old.querySelectorAll("details.card:not([open])")].map((d) => d.id) : []);
    const page = el("div", { class: "bpage" });
    if (state.error) {
      page.append(el("p", { class: "muted" }, state.error));
      $("main").replaceChildren(page);
      return;
    }
    const r = state.report;
    page.append(security(r), signatures(state.signature), mismatches(r), toolchain(r), objects(r));
    for (const d of page.querySelectorAll("details.card")) {
      if (closed.has(d.id)) {
        d.open = false;
      }
    }
    $("toolbar").replaceChildren();
    $("main").replaceChildren(page);
    page.scrollTop = top;
    paint();
  }

  /** Draws the Objects section again, alone (the page stays where it is). */
  function renderObjects() {
    const old = $("objects");
    if (!old) {
      render();
      return;
    }
    const card = objects(state.report);
    card.open = old.open;
    old.replaceWith(card);
    paint();
    if (state.focusChip) {
      const c = card.querySelector(`.gchip[data-id="${state.focusChip}"]`);
      state.focusChip = null;
      if (c) {
        c.focus();
      }
    }
  }

  function renderHeader() {
    const r = state.report;
    const chips = [];
    if (r && r.audit) {
      chips.push(el("span", { class: "chip" }, el("b", {}, "Objects "), r.audit.objects.toLocaleString()));
      const libs = new Set(state.builds.map((b) => b.library).filter(Boolean));
      chips.push(el("span", { class: "chip" }, el("b", {}, "Libraries "), libs.size.toLocaleString()));
    }
    $("header").replaceChildren(
      el("div", { class: "title" }, el("span", { class: "name" }, base(state.file) || "Build Information"), el("span", { class: "path", title: state.file || "" }, state.file || "")),
      el("div", { class: "chips" }, chips),
      el("div", { class: "actions" }, vscode ? el("button", { class: "icon", title: "Run hexc again", onclick: () => post({ command: "refresh" }) }, "⟳") : null)
    );
  }

  function card(id, title, chip, ...body) {
    return el("details", { class: "card", open: true, id }, el("summary", {}, el("h2", {}, title), chip ? el("span", { class: "chip" }, chip) : null), ...body);
  }

  /** The exploit mitigations the image was built with. */
  function security(r) {
    const checks = r.checks || [];
    const on = checks.filter((c) => c.state === "on").length;
    const off = checks.filter((c) => c.state === "off").length;
    const tbody = el(
      "tbody",
      {},
      checks.map((c) =>
        el(
          "tr",
          { class: "check-" + c.state.replace("/", "") },
          el("td", { class: "state" }, el("span", { class: "badge " + c.state.replace("/", "") }, c.state === "n/a" ? "n/a" : c.state[0].toUpperCase() + c.state.slice(1))),
          el("td", { class: "cname" }, c.name),
          el("td", { class: "muted" }, c.detail)
        )
      )
    );
    return card(
      "security",
      "Security Options",
      `${on} on, ${off} off`,
      checks.length ? el("table", { class: "rows checks" }, el("thead", {}, el("tr", {}, el("th", {}, "State"), el("th", {}, "Option"), el("th", {}, "Detail"))), tbody) : el("p", { class: "none" }, "No checks for this kind of file.")
    );
  }

  // ----------------------------------------------------------- signatures

  // A check's status, as a badge's class and text.
  const STATUS = { pass: ["on", "Pass"], fail: ["off", "Fail"], warn: ["partial", "Warning"], unknown: ["na", "Unknown"] };
  const VERDICT = {
    pass: ["on", "Verified"],
    fail: ["off", "Not verified"],
    warn: ["partial", "Verified, with warnings"],
    unknown: ["na", "Couldn't verify"],
    unsigned: ["off", "Unsigned"],
  };
  const badge = (table, key) => {
    const [cls, text] = table[key] || ["na", key];
    return el("span", { class: "badge " + cls }, text);
  };

  /**
   * The file's signatures (hexc signature -json), verified by hexc the
   * same on any platform: Authenticode's (and those nested in it), or
   * each architecture's Apple code signature.
   */
  function signatures(sig) {
    if (!sig) {
      return card("signature", "Signature", null, el("p", { class: "none" }, "Not read."));
    }
    if (sig.error) {
      return card("signature", "Signature", null, el("p", { class: "none" }, sig.error));
    }
    const body = [];
    // What the file says it is (its version resource; a Mach-O image's
    // versions and Info.plist), as sigcheck shows it.
    if ((sig.info || []).length) {
      body.push(fields(sig.info.map((x) => [x.name, x.value])));
    }
    if (sig.status === "unsigned") {
      body.push(
        el(
          "p",
          {},
          badge(VERDICT, "unsigned"),
          " ",
          sig.format === "pe" ? "No embedded signature. (A Windows component may be signed in a catalog, which isn't in the file.)" : "No code signature."
        )
      );
    }
    for (const s of sig.authenticode || []) {
      body.push(signatureBlock(s, s.kind));
    }
    for (const a of sig.apple || []) {
      body.push(appleBlock(a));
    }
    body.push(
      el(
        "p",
        { class: "muted note" },
        `Verified by hexc, the same on every platform. Trust is hexc's own list of ${sig.roots} roots (Microsoft's, Apple's, and the public code-signing authorities), not this machine's; revocation isn't checked.`
      )
    );
    return card("signature", "Signature", (VERDICT[sig.status] || [null, sig.status])[1], ...body);
  }

  /** Checks as rows: status, name, detail. */
  function checksTable(list) {
    return el(
      "table",
      { class: "rows checks" },
      el(
        "tbody",
        {},
        list.map((c) => el("tr", {}, el("td", { class: "state" }, badge(STATUS, c.status)), el("td", { class: "cname" }, c.name), el("td", { class: "muted" }, c.detail)))
      )
    );
  }

  /** A certificate, its details in a disclosure. */
  function certificate(c, extra) {
    return el(
      "details",
      { class: "cert" },
      el(
        "summary",
        {},
        el("span", { class: "certname" }, c.name),
        extra || null,
        el("span", { class: "muted" }, ` ${c.key} · ${c.notBefore.slice(0, 10)} to ${c.notAfter.slice(0, 10)}`)
      ),
      fields([
        ["Subject", c.subject],
        ["Issuer", c.issuer],
        ["Serial number", c.serial],
        ["Valid", `${c.notBefore} to ${c.notAfter}`],
        ["Public key", c.key],
        ["Signature algorithm", c.signatureAlgorithm],
        ["Usages", c.usages ? c.usages.join(", ") : "(any)"],
        ["Key usage", (c.keyUsage || []).join(", ")],
        ["Certificate authority", c.ca ? "yes" : "no"],
        ["SHA-1 thumbprint", c.sha1],
        ["SHA-256 thumbprint", c.sha256],
      ])
    );
  }

  /** A signer's chain: from its certificate up to the root. */
  function chainView(chain) {
    if (!chain) {
      return null;
    }
    const last = chain.links.length - 1;
    return el(
      "div",
      { class: "chain" },
      chain.links.map((l, i) => {
        const mark =
          i === last && chain.trusted
            ? el("span", { class: "badge on small" }, "trusted root")
            : l.signed && l.signed !== "pass"
              ? el("span", { class: "badge off small", title: l.signed }, "bad signature")
              : null;
        return el("div", { class: "link", style: `margin-left:${i * 16}px` }, certificate(l.certificate, mark));
      })
    );
  }

  /** One Authenticode (or Apple CMS) signature. */
  function signatureBlock(s, title) {
    const signer = s.signer || {};
    const stamp = (s.timestamps || [])[0];
    const when =
      stamp && stamp.time
        ? `${stamp.time} (timestamped by ${stamp.signer.name})`
        : signer.signingTime
          ? `${signer.signingTime} (the signer's claim; no timestamp)`
          : "(no timestamp)";
    const out = el(
      "div",
      { class: "sig" },
      el("h3", {}, badge(VERDICT, s.status), " ", title, el("span", { class: "muted" }, " — " + s.summary)),
      fields([
        ["Signer", signer.name],
        ["Signed", when],
        ["Program", s.program],
        ["More information", s.url],
        ["Algorithms", signer.digestAlgorithm ? `${signer.digestAlgorithm}, ${signer.signatureAlgorithm}` : ""],
        ["Signed hash", s.fileDigest ? `${s.fileDigest.algorithm} ${s.fileDigest.signed}` : ""],
        ["File's hash", s.fileDigest && s.fileDigest.file !== s.fileDigest.signed ? s.fileDigest.file || "?" : ""],
      ]),
      checksTable([...(s.checks || []), ...(signer.checks || [])]),
      signer.chain ? el("h4", {}, "Certificate chain") : null,
      chainView(signer.chain)
    );
    for (const t of s.timestamps || []) {
      out.append(
        el(
          "details",
          { class: "stamp" },
          el("summary", {}, el("h4", {}, `Timestamp (${t.kind}): ${t.time || "?"} by ${t.signer.name}`)),
          checksTable(t.signer.checks || []),
          chainView(t.signer.chain)
        )
      );
    }
    const all = s.certificates || [];
    if (all.length) {
      out.append(
        el("details", { class: "stamp" }, el("summary", {}, el("h4", {}, `Every certificate in the signature (${all.length})`)), all.map((c) => certificate(c)))
      );
    }
    return out;
  }

  /** One architecture's Apple code signature. */
  function appleBlock(a) {
    const dirs = (a.directories || []).map((d) => `${d.hash}: CDHash ${d.cdhash} (${d.codeSlots} pages of ${d.pageSize} bytes)`);
    const out = el(
      "div",
      { class: "sig" },
      el("h3", {}, badge(VERDICT, a.status), ` Apple code signature (${a.arch})`, el("span", { class: "muted" }, " — " + a.summary)),
      fields([
        ["Identifier", a.identifier],
        ["Team ID", a.team],
        ["Flags", `${a.flags}${(a.flagNames || []).length ? " (" + a.flagNames.join(", ") + ")" : ""}`],
        ["Hardened runtime", a.runtime],
        ["Executable segment", (a.execSegment || []).join(", ")],
        ["Code directories", dirs.join("\n")],
        ["Requirements", (a.requirements || []).join("\n")],
      ]),
      checksTable(a.checks || [])
    );
    if (a.entitlements) {
      out.append(el("details", { class: "stamp" }, el("summary", {}, el("h4", {}, "Entitlements")), el("pre", { class: "mono ents" }, a.entitlements)));
    }
    if (a.signature && a.signature.signer) {
      out.append(signatureBlock(a.signature, "CMS signature"));
    }
    return out;
  }

  /** The options the objects were built with differently, worst first. */
  function mismatches(r) {
    if (!r.audit) {
      return card("mismatch", "Mismatching Build Options", null, el("p", { class: "none" }, r.auditError ? `No build records: ${r.auditError}` : "No build records."));
    }
    const rank = { mismatch: 0, weakens: 1, differs: 2 };
    const list = r.audit.options
      .filter((o) => o.values.length > 1 && o.option !== "language" && o.option !== "compiler")
      .sort((a, b) => rank[a.severity] - rank[b.severity] || a.option.localeCompare(b.option));
    if (!list.length) {
      return card("mismatch", "Mismatching Build Options", "none", el("p", { class: "none" }, "Every object was built with the same options."));
    }
    const tbody = el(
      "tbody",
      {},
      list.map((o) =>
        el(
          "tr",
          {},
          el("td", { class: "state" }, el("span", { class: "badge " + o.severity, title: SEVERITY[o.severity][1] }, SEVERITY[o.severity][0])),
          el("td", { class: "cname mono" }, o.option),
          el(
            "td",
            { class: "values" },
            o.values.map((v) => valueChip(o.option, v))
          )
        )
      )
    );
    return card(
      "mismatch",
      "Mismatching Build Options",
      plural(list.length, "option"),
      el("p", {}, "Click a value to show its objects below."),
      el("table", { class: "rows checks" }, el("thead", {}, el("tr", {}, el("th", {}, "Severity"), el("th", {}, "Option"), el("th", {}, "Values (objects)"))), tbody)
    );
  }

  /** A value of an option and how many objects have it; a click shows them. */
  function valueChip(option, v) {
    const on = state.only && state.only.option === option && state.only.value === v.value;
    return el(
      "button",
      {
        class: "vchip" + (on ? " on" : ""),
        title: on ? "Show every object again" : `Show the objects built with ${option} ${v.value}`,
        "aria-pressed": String(on),
        onclick: () => {
          state.only = on ? null : { option, value: v.value, keys: new Set(v.objects.map((o, k) => keyOf(o, (v.libraries || [])[k]))) };
          render();
          if (!on) {
            const t = $("objects");
            if (t) {
              t.scrollIntoView({ block: "start" });
            }
          }
        },
      },
      el("span", { class: "mono" }, v.value || "(none)"),
      el("span", { class: "count" }, v.objects.length.toLocaleString())
    );
  }

  /** The linker's command line, and the compilers and languages used. */
  function toolchain(r) {
    const out = [];
    const l = r.audit && r.audit.linker;
    if (l) {
      const cmd = (l.exe ? (/\s/.test(l.exe) ? `"${l.exe}"` : l.exe) + " " : "") + (l.cmd || "").trim();
      out.push(
        el("h3", {}, "Linker"),
        fields([
          ["Command line", cmd, true],
          ["Directory", l.cwd],
          ["PDB", l.pdb],
        ]),
        el("div", { class: "buttons" }, el("button", { onclick: () => post({ command: "copy", text: cmd, what: "the linker's command line" }) }, "Copy Command Line"))
      );
    }
    const count = (f) => {
      const m = new Map();
      for (const b of state.builds) {
        const k = f(b);
        m.set(k, (m.get(k) || 0) + 1);
      }
      return [...m].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    };
    if (state.builds.length) {
      const list = (title, pairs, none) =>
        el(
          "div",
          { class: "tally" },
          el("h3", {}, title),
          el(
            "table",
            { class: "rows" },
            el(
              "tbody",
              {},
              pairs.map(([k, n]) => el("tr", {}, el("td", { class: k ? "" : "muted" }, k || none), el("td", { class: "n" }, n.toLocaleString())))
            )
          )
        );
      out.push(
        el(
          "div",
          { class: "tallies" },
          list("Compilers", count((b) => b.compiler), "(no compiler record)"),
          list("Languages", count((b) => b.language), "(not recorded)")
        )
      );
    }
    if (!out.length) {
      out.push(el("p", { class: "none" }, "No toolchain records."));
    }
    return card("toolchain", "Toolchain", null, ...out);
  }

  /** Label/value rows (values in a monospace font). */
  function fields(rows) {
    return el(
      "table",
      { class: "fields" },
      el(
        "tbody",
        {},
        rows.filter(([, v]) => v).map(([k, v, wrap]) => el("tr", {}, el("th", {}, k), el("td", { class: "mono" + (wrap ? " wrap" : "") }, v)))
      )
    );
  }

  // --------------------------------------------------------- the objects

  /** The objects the filter (and the chosen value) leave. */
  function shown() {
    const q = state.query.trim();
    let test = null;
    if (q) {
      if (state.regex) {
        try {
          const re = new RegExp(q, "i");
          test = (s) => re.test(s);
        } catch {
          test = null;
        }
      } else {
        const lower = q.toLowerCase();
        test = (s) => s.toLowerCase().includes(lower);
      }
    }
    return state.builds.filter((b) => {
      if (state.only && !state.only.keys.has(keyOf(b.object, b.library))) {
        return false;
      }
      return !test || test(b.object) || test(b.library) || test(b.source) || test(b.compiler) || test(b.command);
    });
  }

  function groupOf(level, b) {
    switch (level) {
      case "library":
        return b.library ? [base(b.library), b.library] : ["(not from a library)", "Objects the linker was given directly"];
      case "directory": {
        const d = dir(b.object);
        return [d || "(no directory)", d];
      }
      case "compiler":
        return [b.compiler || "(no compiler record)", ""];
      default:
        return [b.language || "(not recorded)", ""];
    }
  }

  const SORTS = {
    order: (b) => b.order,
    object: (b) => base(b.object).toLowerCase(),
    library: (b) => base(b.library).toLowerCase(),
    compiler: (b) => b.compiler,
    language: (b) => b.language,
    command: (b) => b.command,
  };

  function sorted(list) {
    const f = SORTS[state.sort.key] || SORTS.order;
    const d = state.sort.desc ? -1 : 1;
    return list.slice().sort((a, b) => {
      const x = f(a);
      const y = f(b);
      return (x < y ? -1 : x > y ? 1 : a.order - b.order) * d;
    });
  }

  const filtering = () => !!state.query.trim() || !!state.only;
  const isOpen = (key) => (filtering() ? !state.closed.has(key) : state.open.has(key));

  /** The rows of the table: groups (by the levels) and objects, as open. */
  function flatten(list) {
    const out = [];
    const walk = (items, depth, prefix) => {
      if (depth === state.levels.length) {
        for (const b of sorted(items)) {
          out.push({ b, depth });
        }
        return;
      }
      const groups = new Map();
      for (const b of items) {
        const [name, title] = groupOf(state.levels[depth], b);
        let g = groups.get(name);
        if (!g) {
          g = { name, title, items: [] };
          groups.set(name, g);
        }
        g.items.push(b);
      }
      const ordered = [...groups.values()].sort((a, b) => b.items.length - a.items.length || a.name.localeCompare(b.name));
      for (const g of ordered) {
        const key = prefix + "\u0001" + g.name;
        const open = isOpen(key);
        out.push({ group: g, key, depth, open });
        if (open) {
          walk(g.items, depth + 1, key);
        }
      }
    };
    walk(list, 0, "");
    return out;
  }

  function objects() {
    const list = shown();
    state.rows = flatten(list);
    const input = el("input", {
      id: "search",
      type: "search",
      placeholder: state.regex ? "Filter by a regular expression…" : "Filter objects…",
      title: "Shows the objects whose name, library, source, compiler, or command line has this; Esc clears it",
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
          refreshTable(true);
        },
      },
      ".*"
    );
    const bar = el(
      "div",
      { class: "objbar" },
      groupingChips(),
      el("span", { class: "spacer" }),
      el("a", { href: "#", onclick: (e) => (e.preventDefault(), expandAll(true)) }, "Expand all"),
      el("a", { href: "#", onclick: (e) => (e.preventDefault(), expandAll(false)) }, "Collapse all"),
      el("span", { class: "searchbox" }, input, regex)
    );
    const count = el("span", { id: "count" }, countText(list.length));
    const only = state.only
      ? el(
          "span",
          { class: "only" },
          "Built with ",
          el("span", { class: "mono" }, `${state.only.option} ${state.only.value}`),
          " ",
          el("a", { href: "#", onclick: (e) => (e.preventDefault(), (state.only = null), render()) }, "Show all")
        )
      : null;
    return card(
      "objects",
      "Objects",
      plural(state.builds.length, "object"),
      bar,
      el("div", { class: "tablebar" }, count, only, el("span", { class: "spacer" }), el("span", { class: "muted" }, "Click an object for how it was built")),
      el("div", { class: "objwrap", id: "objwrap", onscroll: () => paint() }, table()),
      el("div", { id: "objdetail" }, detail())
    );
  }

  function countText(n) {
    return filtering() ? `${n.toLocaleString()} of ${state.builds.length.toLocaleString()} objects` : plural(state.builds.length, "object");
  }

  function table() {
    const head = (key, label, cls) =>
      el(
        "th",
        {
          class: (cls || "") + " sortable" + (state.sort.key === key ? " sorted" : ""),
          title: key === "object" ? "Sort by name (click again to reverse; once more, the link order)" : undefined,
          onclick: () => {
            if (state.sort.key === key && state.sort.desc) {
              state.sort = { key: "order", desc: false };
            } else {
              state.sort = { key, desc: state.sort.key === key };
            }
            save();
            refreshTable();
          },
        },
        label,
        state.sort.key === key ? (state.sort.desc ? " ▾" : " ▴") : ""
      );
    return el(
      "table",
      { class: "rows tree objects", role: "treegrid" },
      el("thead", {}, el("tr", {}, head("object", "Object"), head("library", "Library"), head("compiler", "Compiler"), head("language", "Language"), head("command", "Command Line"))),
      el("tbody")
    );
  }

  /** Draws the rows in view. */
  function paint() {
    const wrap = $("objwrap");
    const tbody = wrap && wrap.querySelector("tbody");
    if (!tbody) {
      return;
    }
    const rows = state.rows || [];
    const first = Math.max(0, Math.floor(wrap.scrollTop / ROW) - 20);
    const last = Math.min(rows.length, Math.ceil((wrap.scrollTop + (wrap.clientHeight || 600)) / ROW) + 20);
    const spacer = (n) => {
      const tr = el("tr", { class: "spacer", "aria-hidden": "true" }, el("td", { colspan: "5" }));
      tr.style.height = n * ROW + "px";
      return tr;
    };
    const out = [];
    if (first > 0) {
      out.push(spacer(first));
    }
    const indent = (d) => el("span", { class: "indent", style: `width:${d * 16}px` });
    for (let k = first; k < last; k++) {
      const r = rows[k];
      if (r.group) {
        const g = r.group;
        out.push(
          el(
            "tr",
            {
              class: "group",
              "aria-expanded": String(r.open),
              "aria-level": String(r.depth + 1),
              onclick: () => toggle(r.key),
            },
            el(
              "td",
              { class: "tname", colspan: "5", title: g.title || g.name },
              indent(r.depth),
              el("span", { class: "twisty", role: "button", "aria-label": r.open ? "Collapse" : "Expand" }, r.open ? "▾" : "▸"),
              el("span", { class: "label" }, g.name),
              el("span", { class: "count muted" }, " " + plural(g.items.length, "object"))
            )
          )
        );
        continue;
      }
      const b = r.b;
      const key = keyOf(b.object, b.library);
      const tr = el(
        "tr",
        {
          class: (key === state.selected ? "selected" : "") + (b.compiled ? "" : " notcompiled"),
          "aria-level": String(r.depth + 1),
          onclick: () => {
            state.selected = key;
            for (const x of tbody.querySelectorAll("tr.selected")) {
              x.classList.remove("selected");
            }
            tr.classList.add("selected");
            $("objdetail").replaceChildren(detail());
          },
        },
        el("td", { class: "tname", title: b.object }, indent(r.depth), el("span", { class: "twisty leaf" }), el("span", { class: "label" }, base(b.object) || "(unnamed)")),
        el("td", { class: "lib", title: b.library || "" }, base(b.library)),
        el("td", { class: "comp", title: b.compiler || "" }, b.compiler),
        el("td", {}, b.language),
        el("td", { class: "mono cmd", title: commandLine(b) }, b.command || (b.compiled ? "" : "(not compiled)"))
      );
      out.push(tr);
    }
    if (last < rows.length) {
      out.push(spacer(rows.length - last));
    }
    tbody.replaceChildren(...out);
  }

  /** How the selected object was built. */
  function detail() {
    const b = state.selected && state.builds.find((x) => keyOf(x.object, x.library) === state.selected);
    if (!b) {
      return el("p", { class: "muted none" }, "Select an object to see how it was built.");
    }
    const cmd = commandLine(b);
    const opts = Object.entries(b.options || {});
    return el(
      "div",
      { class: "objinfo" },
      el("h3", {}, base(b.object) || "(unnamed)"),
      fields([
        ["Object", b.object],
        ["Library", b.library],
        ["Source", b.source],
        ["Directory", b.cwd],
        ["Compiler", b.compiler],
        ["Tool", b.tool],
        ["PDB", b.pdb],
        ["Command line", cmd, true],
      ]),
      el(
        "div",
        { class: "buttons" },
        cmd ? el("button", { onclick: () => post({ command: "copy", text: cmd, what: "the command line" }) }, "Copy Command Line") : null,
        b.source ? el("button", { onclick: () => post({ command: "open", path: b.cwd && !/^([a-z]:)?[\\/]/i.test(b.source) ? b.cwd + "/" + b.source : b.source }) }, "Open Source") : null
      ),
      opts.length
        ? el(
            "table",
            { class: "rows opts" },
            el("thead", {}, el("tr", {}, el("th", {}, "Option"), el("th", {}, "Value"))),
            el(
              "tbody",
              {},
              opts.map(([k, v]) => el("tr", {}, el("td", { class: "mono" }, k), el("td", { class: "mono" }, v)))
            )
          )
        : null
    );
  }

  function toggle(key) {
    const set = filtering() ? state.closed : state.open;
    // (Filtering, the groups start open: a closed one is remembered.)
    const open = isOpen(key);
    if (filtering() ? open : !open) {
      set.add(key);
    } else {
      set.delete(key);
    }
    refreshTable();
  }

  function expandAll(open) {
    const keys = [];
    const walk = (items, depth, prefix) => {
      if (depth === state.levels.length) {
        return;
      }
      const groups = new Map();
      for (const b of items) {
        const name = groupOf(state.levels[depth], b)[0];
        if (!groups.has(name)) {
          groups.set(name, []);
        }
        groups.get(name).push(b);
      }
      for (const [name, list] of groups) {
        const key = prefix + "\u0001" + name;
        keys.push(key);
        walk(list, depth + 1, key);
      }
    };
    walk(shown(), 0, "");
    if (filtering()) {
      state.closed = open ? new Set() : new Set(keys);
    } else {
      state.open = open ? new Set(keys) : new Set();
    }
    refreshTable();
  }

  /** Draws the objects' table again (not the filter box: it is being typed in). */
  function refreshTable(all) {
    const old = $("objects");
    if (!old || all) {
      renderObjects();
      return;
    }
    const list = shown();
    state.rows = flatten(list);
    const wrap = $("objwrap");
    const top = wrap.scrollTop;
    wrap.replaceChildren(table());
    wrap.scrollTop = top;
    $("count").textContent = countText(list.length);
    paint();
  }

  let typing = 0;
  function setFilter(query) {
    if (query === state.query) {
      return;
    }
    if (state.regex && query.trim()) {
      try {
        new RegExp(query.trim());
        $("search").classList.remove("invalid");
      } catch {
        $("search").classList.add("invalid");
        return;
      }
    } else {
      $("search").classList.remove("invalid");
    }
    state.query = query;
    state.closed.clear();
    clearTimeout(typing);
    typing = setTimeout(() => refreshTable(), 30);
  }

  /**
   * The grouping control: a chip for each level. Click one to group by it
   * or not; drag the ones on (or press Alt+Left and Alt+Right) to order
   * them, outermost first. With none, the objects are a list.
   */
  function groupingChips() {
    const on = state.levels;
    const apply = (levels) => {
      state.levels = levels;
      state.open.clear();
      state.closed.clear();
      save();
      renderObjects();
    };
    const box = el("span", { class: "chips-group", role: "group", "aria-label": "Group by" }, el("span", { class: "muted" }, "Group by"));
    const ordered = [...on.map((id) => CHIPS.find((c) => c[0] === id)), ...CHIPS.filter((c) => !on.includes(c[0]))];
    for (const [id, label, about] of ordered) {
      const active = on.includes(id);
      box.append(
        el(
          "button",
          {
            class: "gchip" + (active ? " on" : ""),
            draggable: active ? "true" : undefined,
            title: `${active ? "Grouped" : "Group"} by ${about}${active ? " (drag to reorder; Alt+Left and Alt+Right move it)" : ""}`,
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
            ondragover: (e) => active && e.preventDefault(),
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
        )
      );
    }
    return box;
  }

  document.addEventListener("keydown", (e) => {
    if (e.key === "/" && !(e.target && e.target.tagName === "INPUT")) {
      e.preventDefault();
      const s = $("search");
      if (s) {
        s.focus();
      }
    }
  });

  window.addEventListener("message", (e) => {
    const m = e.data;
    if (!m || !m.kind) {
      return;
    }
    if (m.kind === "failed") {
      state.error = m.message || "hexc failed";
      render();
      return;
    }
    if (m.kind === "build") {
      state.file = m.file;
      state.report = m.report || {};
      state.signature = m.signature || null;
      state.error = null;
      const builds = (state.report.audit && state.report.audit.builds) || [];
      state.builds = builds.map((b, order) => Object.assign({ order }, b));
      if (state.only) {
        state.only = null;
      }
      render();
    }
  });
  let pending = 0;
  window.addEventListener("resize", () => {
    cancelAnimationFrame(pending);
    pending = requestAnimationFrame(() => paint());
  });
})();
