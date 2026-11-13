// Tests for media/treemap.js. Run with any Node, or with VS Code's own:
//   set ELECTRON_RUN_AS_NODE=1 && "<VS Code>\Code.exe" test\treemap.test.js
"use strict";

const assert = require("assert");
const path = require("path");
const {
  squarify,
  layoutNested,
  sunburst,
  arcPath,
  search,
  formatSize,
  formatBytes,
  percent,
  rowValue,
  signedValue,
  rowAt,
  colorFor,
  diffColor,
} = require(path.join(__dirname, "..", "media", "treemap.js"));

let failures = 0;
function test(name, f) {
  try {
    f();
    console.log("ok   " + name);
  } catch (e) {
    failures++;
    console.log("FAIL " + name + "\n     " + (e && e.stack ? e.stack : e));
  }
}

const near = (a, b) => Math.abs(a - b) < 1e-6;

test("areas are proportional and tile the rectangle", () => {
  const items = [6, 6, 4, 3, 2, 2, 1].map((value, i) => ({ value, name: "n" + i }));
  const rect = { x: 0, y: 0, w: 6, h: 4 };
  const out = squarify(items, rect);
  assert.strictEqual(out.length, 7);
  let area = 0;
  for (const r of out) {
    assert.ok(near(r.w * r.h, r.item.value), `${r.item.name}: ${r.w * r.h} != ${r.item.value}`);
    assert.ok(r.x >= -1e-9 && r.y >= -1e-9 && r.x + r.w <= 6 + 1e-9 && r.y + r.h <= 4 + 1e-9);
    area += r.w * r.h;
  }
  assert.ok(near(area, 24));
  // No two rectangles overlap.
  for (let i = 0; i < out.length; i++) {
    for (let j = i + 1; j < out.length; j++) {
      const a = out[i];
      const b = out[j];
      const overlap =
        Math.min(a.x + a.w, b.x + b.w) - Math.max(a.x, b.x) > 1e-9 &&
        Math.min(a.y + a.h, b.y + b.h) - Math.max(a.y, b.y) > 1e-9;
      assert.ok(!overlap, `${a.item.name} overlaps ${b.item.name}`);
    }
  }
});

test("the paper's example lays out rows of good aspect ratio", () => {
  const out = squarify([6, 6, 4, 3, 2, 2, 1].map((value) => ({ value })), { x: 0, y: 0, w: 6, h: 4 });
  const worst = Math.max(...out.map((r) => Math.max(r.w / r.h, r.h / r.w)));
  assert.ok(worst < 3, `worst aspect ratio ${worst}`);
});

test("zero, negative, and non-finite values are skipped", () => {
  const out = squarify([{ value: 0 }, { value: -5 }, { value: NaN }, { value: 3 }], { x: 0, y: 0, w: 2, h: 2 });
  assert.strictEqual(out.length, 1);
  assert.ok(near(out[0].w * out[0].h, 4));
  assert.deepStrictEqual(squarify([], { x: 0, y: 0, w: 1, h: 1 }), []);
  assert.deepStrictEqual(squarify([{ value: 1 }], { x: 0, y: 0, w: 0, h: 1 }), []);
});

test("many items stay within bounds", () => {
  const items = [];
  for (let i = 1; i <= 5000; i++) {
    items.push({ value: (i * 7919) % 1000 + 1 });
  }
  const out = squarify(items, { x: 10, y: 20, w: 800, h: 600 });
  assert.strictEqual(out.length, 5000);
  let area = 0;
  for (const r of out) {
    assert.ok(r.x >= 10 - 1e-6 && r.y >= 20 - 1e-6 && r.x + r.w <= 810 + 1e-6 && r.y + r.h <= 620 + 1e-6);
    area += r.w * r.h;
  }
  assert.ok(Math.abs(area - 480000) < 1e-3);
});

test("sizes print in 1024-based units", () => {
  assert.strictEqual(formatSize(0), "0 B");
  assert.strictEqual(formatSize(1023), "1023 B");
  assert.strictEqual(formatSize(1536), "1.50 KiB");
  assert.strictEqual(formatSize(10.5 * 1024), "10.5 KiB");
  assert.strictEqual(formatSize(105 * 1024 * 1024), "105 MiB");
  assert.strictEqual(formatSize(-2048), "-2.00 KiB");
});

test("rows by domain and path", () => {
  const report = {
    name: "TOTAL",
    vm: 10,
    file: 20,
    children: [{ name: ".text", vm: 6, file: 8, children: [{ name: "f", vm: -4, file: 4 }] }],
  };
  assert.strictEqual(rowValue(report, "vm"), 10);
  assert.strictEqual(rowValue(report, "file"), 20);
  assert.strictEqual(rowValue(rowAt(report, [".text", "f"]), "vm"), 4);
  assert.strictEqual(rowAt(report, [".data"]), null);
  assert.strictEqual(rowAt(report, []), report);
});

test("colors are stable", () => {
  assert.strictEqual(colorFor(".text", 0), colorFor(".text", 0));
  assert.notStrictEqual(colorFor(".text", 0), colorFor(".data", 0));
  assert.ok(colorFor("x", 1).startsWith("hsl("));
});

const tree = {
  name: "TOTAL",
  vm: 100,
  file: 100,
  children: [
    { name: ".text", vm: 60, file: 60, children: [{ name: "main", vm: 40, file: 40 }, { name: "helper", vm: 20, file: 20 }] },
    { name: ".data", vm: 30, file: 30, children: [{ name: "table", vm: 30, file: 30 }] },
    { name: ".bss", vm: 10, file: 0 },
  ],
};

test("nested treemaps put children inside their parents", () => {
  const out = layoutNested(tree, { x: 0, y: 0, w: 400, h: 300 }, "file", { levels: 2 });
  const text = out.find((b) => b.path.join("/") === ".text");
  const main = out.find((b) => b.path.join("/") === ".text/main");
  assert.ok(text && main, "both levels laid out");
  assert.ok(text.header, "a parent gets a header");
  assert.strictEqual(main.depth, 1);
  assert.ok(main.x >= text.x && main.y >= text.y + 17 && main.x + main.w <= text.x + text.w + 1e-6 && main.y + main.h <= text.y + text.h + 1e-6);
  // .bss has no file bytes: not drawn by file size.
  assert.ok(!out.some((b) => b.row.name === ".bss"));
  assert.ok(layoutNested(tree, { x: 0, y: 0, w: 400, h: 300 }, "vm").some((b) => b.row.name === ".bss"));
  // One level only, and a cap on boxes.
  assert.ok(layoutNested(tree, { x: 0, y: 0, w: 400, h: 300 }, "file", { levels: 1 }).every((b) => b.depth === 0));
  assert.strictEqual(layoutNested(tree, { x: 0, y: 0, w: 400, h: 300 }, "file", { limit: 2 }).length, 2);
  // Small boxes are not nested.
  const small = layoutNested(tree, { x: 0, y: 0, w: 60, h: 40 }, "file");
  assert.ok(small.every((b) => b.depth === 0));
});

test("sunbursts span the circle by size", () => {
  const arcs = sunburst(tree, "vm", 3);
  const top = arcs.filter((a) => a.depth === 0);
  assert.strictEqual(top.length, 3);
  const total = top.reduce((s, a) => s + (a.end - a.start), 0);
  assert.ok(near(total, 2 * Math.PI));
  const text = arcs.find((a) => a.path.join("/") === ".text");
  assert.ok(near(text.end - text.start, 2 * Math.PI * 0.6));
  const main = arcs.find((a) => a.path.join("/") === ".text/main");
  assert.ok(main.start >= text.start - 1e-9 && main.end <= text.end + 1e-9 && main.depth === 1);
  assert.strictEqual(sunburst(tree, "vm", 1).length, 3);
  assert.ok(arcPath(0, 0, 10, 20, 0, Math.PI / 2).startsWith("M"));
  assert.ok(arcPath(0, 0, 10, 20, 0, 2 * Math.PI).includes(" M"), "a full ring is two halves");
});

test("search finds names at any depth, largest first", () => {
  const hits = search(tree, "a", "file");
  assert.deepStrictEqual(hits.map((h) => h.path.join("/")), [".text/main", ".data", ".data/table"]);
  assert.deepStrictEqual(search(tree, "  ", "file"), []);
  assert.deepStrictEqual(search(tree, "MAIN", "file").map((h) => h.row.name), ["main"]);
  assert.strictEqual(search(tree, "e", "file", 1).length, 1);
});

test("numbers, shares, and diffs", () => {
  assert.strictEqual(formatBytes(1234567), "1,234,567");
  assert.strictEqual(formatBytes(-1000), "-1,000");
  assert.strictEqual(percent(1, 4), "25%");
  assert.strictEqual(percent(1, 3), "33%");
  assert.strictEqual(percent(5, 100), "5.0%");
  assert.strictEqual(percent(1, 10000), "<0.1%");
  assert.strictEqual(percent(1, 0), "");
  assert.strictEqual(signedValue({ vm: -4, file: 2 }, "vm"), -4);
  assert.ok(diffColor(10, 100).startsWith("hsl(2,"));
  assert.ok(diffColor(-10, 100).startsWith("hsl(140,"));
  assert.notStrictEqual(diffColor(1, 100), diffColor(100, 100), "larger changes are stronger");
  assert.ok(diffColor(0, 100).startsWith("hsl(220"));
});

test("children share their top-level row's hue", () => {
  const hue = (c) => Number(c.match(/hsl\((\d+)/)[1]);
  const top = hue(colorFor(".text", 0, ".text"));
  const child = hue(colorFor("main", 1, ".text"));
  const d = Math.min(Math.abs(top - child), 360 - Math.abs(top - child));
  assert.ok(d <= 12, `hue ${child} far from ${top}`);
});

if (failures) {
  console.log(`${failures} failed`);
  process.exit(1);
}
console.log("all passed");
