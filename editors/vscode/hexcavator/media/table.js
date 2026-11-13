// Sortable tables, for the webviews: a column header sorts by it (again:
// the other way). A cell is text, a number, or { text, sort, node,
// title, cls }: `sort` is what it sorts by (a size's bytes, say), `node`
// what is shown in place of its text. The comparison is plain functions,
// tested under Node.
"use strict";

/** What a cell sorts by. */
function sortKey(cell) {
  if (cell && typeof cell === "object" && !(typeof Node !== "undefined" && cell instanceof Node)) {
    return cell.sort !== undefined ? cell.sort : cell.text;
  }
  return cell;
}

/** Compares two cells' keys: numbers as numbers, the rest as text (naturally), empty last. */
function compareKeys(a, b) {
  const empty = (x) => x === undefined || x === null || x === "";
  if (empty(a) || empty(b)) {
    return empty(a) === empty(b) ? 0 : empty(a) ? 1 : -1;
  }
  if (typeof a === "number" && typeof b === "number") {
    return a - b;
  }
  return String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: "base" });
}

/** The rows' order by column `col`, descending or not (stable). */
function sortRows(rows, col, desc) {
  return rows
    .map((r, i) => [r, i])
    .sort((x, y) => {
      const c = compareKeys(sortKey(x[0][col]), sortKey(y[0][col]));
      // Empty cells last either way.
      const ex = sortKey(x[0][col]);
      const ey = sortKey(y[0][col]);
      const empty = (v) => v === undefined || v === null || v === "";
      if (empty(ex) !== empty(ey)) {
        return empty(ex) ? 1 : -1;
      }
      return (desc ? -c : c) || x[1] - y[1];
    })
    .map((x) => x[0]);
}

/**
 * A table of `rows` under `columns` ({ label, numeric, cls, title }),
 * sorted by `sort` ({ col, desc }) at first if given; `onrow(tr, row)`
 * may decorate each row.
 */
function sortableTable(columns, rows, options) {
  const o = options || {};
  let sort = o.sort ? { ...o.sort } : null;
  const table = document.createElement("table");
  table.className = "rows sortable-table" + (o.cls ? " " + o.cls : "");
  const thead = document.createElement("thead");
  const head = document.createElement("tr");
  const tbody = document.createElement("tbody");
  const cellNode = (cell) => {
    if (cell && typeof cell === "object" && !(cell instanceof Node)) {
      if (cell.node) {
        return cell.node;
      }
      return document.createTextNode(cell.text === undefined || cell.text === null ? "" : String(cell.text));
    }
    if (cell instanceof Node) {
      return cell;
    }
    return document.createTextNode(cell === undefined || cell === null ? "" : String(cell));
  };
  const fill = () => {
    const list = sort ? sortRows(rows, sort.col, sort.desc) : rows;
    tbody.replaceChildren();
    for (const r of list) {
      const tr = document.createElement("tr");
      r.forEach((cell, i) => {
        const td = document.createElement("td");
        const col = columns[i] || {};
        td.className = [col.numeric ? "n" : "", col.cls || "", cell && cell.cls ? cell.cls : ""].filter(Boolean).join(" ");
        if (cell && typeof cell === "object" && cell.title) {
          td.title = cell.title;
        }
        td.append(cellNode(cell));
        tr.append(td);
      });
      if (o.onrow) {
        o.onrow(tr, r);
      }
      tbody.append(tr);
    }
    [...head.children].forEach((th, i) => {
      th.classList.toggle("sorted", !!sort && sort.col === i);
      th.querySelector(".arrow").textContent = sort && sort.col === i ? (sort.desc ? " ▾" : " ▴") : "";
    });
  };
  columns.forEach((c, i) => {
    const th = document.createElement("th");
    th.className = ["sortable", c.numeric ? "n" : "", c.cls || ""].filter(Boolean).join(" ");
    th.title = c.title || `Sort by ${c.label}`;
    th.append(document.createTextNode(c.label), Object.assign(document.createElement("span"), { className: "arrow" }));
    th.addEventListener("click", () => {
      sort = sort && sort.col === i ? { col: i, desc: !sort.desc } : { col: i, desc: !!c.numeric };
      fill();
    });
    head.append(th);
  });
  thead.append(head);
  table.append(thead, tbody);
  fill();
  return table;
}

// ------------------------------------------------- hexc's JSON as tables

/** Keys that hold sizes in bytes. */
const SIZE_KEY = /^(size|bytes|waste|padding|bitPadding|file|vm|saving|wasted|wasted_file|wasted_vm|file_size|vm_size|per_slot|oldSize|newSize|withoutCodeSize|unreachableSize|base|new)$|Size$/;

/** A key as a column's heading: camelCase and snake_case as words. */
function heading(key) {
  const words = String(key)
    .replace(/_/g, " ")
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .toLowerCase();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

/** A value in a cell, as text: lists joined, objects by their name. */
function cellText(v) {
  if (v === null || v === undefined) {
    return "";
  }
  if (Array.isArray(v)) {
    return v.map((x) => (x && typeof x === "object" ? [x.edge, x.name].filter(Boolean).join(" ") || JSON.stringify(x) : String(x))).join("; ");
  }
  if (typeof v === "object") {
    return v.name !== undefined ? String(v.name) : JSON.stringify(v);
  }
  if (typeof v === "boolean") {
    return v ? "yes" : "";
  }
  return String(v);
}

/**
 * hexc's JSON as tables: each list of objects in it (at the top, or in an
 * object at the top) a table, its columns the objects' keys; and the
 * numbers and words beside them a summary. `sizes` tells which columns
 * hold sizes.
 */
function tablesOf(json) {
  const summary = [];
  const tables = [];
  const addList = (title, list) => {
    const keys = [];
    for (const row of list.slice(0, 500)) {
      for (const k of Object.keys(row || {})) {
        if (!keys.includes(k)) {
          keys.push(k);
        }
      }
    }
    const columns = keys.map((k) => {
      const values = list.map((r) => r && r[k]).filter((v) => v !== undefined && v !== null);
      const numeric = values.length > 0 && values.every((v) => typeof v === "number");
      return { key: k, label: heading(k), numeric, size: numeric && SIZE_KEY.test(k) };
    });
    tables.push({ title, columns, rows: list });
  };
  const isList = (v) => Array.isArray(v) && v.every((x) => x && typeof x === "object" && !Array.isArray(x));
  if (isList(json)) {
    addList("", json);
    return { summary, tables };
  }
  for (const [k, v] of Object.entries(json || {})) {
    if (isList(v)) {
      addList(heading(k), v);
    } else if (v && typeof v === "object" && !Array.isArray(v)) {
      for (const [k2, v2] of Object.entries(v)) {
        if (isList(v2)) {
          addList(`${heading(k)} › ${heading(k2).toLowerCase()}`, v2);
        } else if (v2 === null || typeof v2 !== "object") {
          summary.push({ label: `${heading(k)}: ${heading(k2).toLowerCase()}`, value: v2, size: SIZE_KEY.test(k2) || SIZE_KEY.test(k) });
        }
      }
    } else if (v === null || typeof v !== "object") {
      summary.push({ label: heading(k), value: v, size: SIZE_KEY.test(k) });
    } else if (Array.isArray(v)) {
      summary.push({ label: heading(k), value: v.map(String).join(", "), size: false });
    }
  }
  return { summary, tables };
}

if (typeof module !== "undefined") {
  module.exports = { sortKey, compareKeys, sortRows, heading, cellText, tablesOf, SIZE_KEY };
}
