// Tests for table.js's sorting: `node test/table.test.js`.
"use strict";

const assert = require("assert");
const path = require("path");
const t = require(path.join(__dirname, "..", "media", "table.js"));

const rows = [
  [{ text: "1.00 KiB", sort: 1024 }, "beta", 3],
  [{ text: "512 B", sort: 512 }, "Alpha", 10],
  [{ text: "2.00 KiB", sort: 2048 }, "item10", ""],
  [{ text: "8 B", sort: 8 }, "item9", 1],
];
const col = (rs, i) => rs.map((r) => t.sortKey(r[i]));

// Sizes by their bytes, not their text.
assert.deepStrictEqual(col(t.sortRows(rows, 0, true), 0), [2048, 1024, 512, 8]);
assert.deepStrictEqual(col(t.sortRows(rows, 0, false), 0), [8, 512, 1024, 2048]);
// Text naturally, ignoring case: item9 before item10.
assert.deepStrictEqual(col(t.sortRows(rows, 1, false), 1), ["Alpha", "beta", "item9", "item10"]);
// Empty cells last, either way.
assert.deepStrictEqual(col(t.sortRows(rows, 2, false), 2), [1, 3, 10, ""]);
assert.deepStrictEqual(col(t.sortRows(rows, 2, true), 2), [10, 3, 1, ""]);
// Stable: equal keys keep their order.
const same = [["a", 1], ["b", 1], ["c", 1]];
assert.deepStrictEqual(t.sortRows(same, 1, true).map((r) => r[0]), ["a", "b", "c"]);

// hexc's JSON as tables: the lists, and the numbers beside them.
const xref = {
  nodes: 10,
  unreachableSize: 936,
  kept: { comdat: 3, unknown: 0 },
  unreachable: [
    { name: "dead()", rva: "0x1000", size: 66, code: true, object: "C:/x/dead.obj", referrers: [{ edge: "calls", name: "f" }] },
    { name: "table", rva: "0x2000", size: 8, code: false },
  ],
};
const { summary, tables } = t.tablesOf(xref);
assert.deepStrictEqual(summary.map((s) => s.label), ["Nodes", "Unreachable size", "Kept: comdat", "Kept: unknown"]);
assert.strictEqual(summary[1].size, true);
assert.strictEqual(summary[0].size, false);
assert.strictEqual(tables.length, 1);
assert.strictEqual(tables[0].title, "Unreachable");
assert.deepStrictEqual(tables[0].columns.map((c) => c.key), ["name", "rva", "size", "code", "object", "referrers"]);
const size = tables[0].columns.find((c) => c.key === "size");
assert.ok(size.numeric && size.size);
assert.strictEqual(t.cellText(xref.unreachable[0].referrers), "calls f");
assert.strictEqual(t.cellText(true), "yes");
assert.strictEqual(t.cellText(false), "");
assert.strictEqual(t.cellText(["a", "b"]), "a; b");
// Lists inside objects (a findings diff's), each a table; empty ones too.
const findings = { duplicate_data: { base: 10, new: 4, changes: [{ name: "x", old: 10, new: 4 }] }, wasteful_virtuals: { base: 0, new: 0, changes: [] } };
const f = t.tablesOf(findings);
assert.deepStrictEqual(f.tables.map((x) => x.title), ["Duplicate data › changes", "Wasteful virtuals › changes"]);
assert.strictEqual(f.tables[1].rows.length, 0);
assert.ok(f.summary.find((s) => s.label === "Duplicate data: base").size);
// A bare list; headings from camelCase and snake_case.
assert.strictEqual(t.tablesOf([{ a: 1 }]).tables.length, 1);
assert.strictEqual(t.heading("bitPadding"), "Bit padding");
assert.strictEqual(t.heading("wasted_file"), "Wasted file");
console.log("all passed");
