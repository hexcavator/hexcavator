// Tests for graph.js (the control-flow graph's layout): `node test/graph.test.js`.
"use strict";

const assert = require("assert");
const path = require("path");
const { layoutGraph, edgePath } = require(path.join(__dirname, "..", "media", "graph.js"));

const tests = [];
const test = (name, fn) => tests.push([name, fn]);
const box = (w, h) => ({ w: w || 100, h: h || 40 });
const overlap = (a, b) => a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;

function checkNoOverlaps(g) {
  for (let i = 0; i < g.nodes.length; i++) {
    for (let j = i + 1; j < g.nodes.length; j++) {
      assert.ok(!overlap(g.nodes[i], g.nodes[j]), `blocks ${i} and ${j} overlap`);
    }
  }
  for (const n of g.nodes) {
    assert.ok(n.x >= 0 && n.y >= 0 && n.x + n.w <= g.width && n.y + n.h <= g.height, "inside the canvas");
  }
}

test("a straight line: a column", () => {
  const g = layoutGraph(3, [box(), box(), box()], [{ from: 0, to: 1, kind: "next" }, { from: 1, to: 2, kind: "jump" }]);
  assert.deepStrictEqual(g.nodes.map((n) => n.layer), [0, 1, 2]);
  assert.ok(g.nodes[0].y < g.nodes[1].y && g.nodes[1].y < g.nodes[2].y);
  assert.strictEqual(g.nodes[0].x, g.nodes[2].x);
  assert.ok(g.edges.every((e) => !e.back));
  checkNoOverlaps(g);
});

test("a diamond: the branches side by side, the join below both", () => {
  const edges = [
    { from: 0, to: 1, kind: "taken" },
    { from: 0, to: 2, kind: "not-taken" },
    { from: 1, to: 3, kind: "jump" },
    { from: 2, to: 3, kind: "next" },
  ];
  const g = layoutGraph(4, [box(), box(), box(), box()], edges);
  assert.deepStrictEqual(g.nodes.map((n) => n.layer), [0, 1, 1, 2]);
  assert.strictEqual(g.nodes[1].y, g.nodes[2].y);
  // The join centered under its two parents; the entry above them.
  const center = (n) => n.x + n.w / 2;
  assert.ok(Math.abs(center(g.nodes[3]) - (center(g.nodes[1]) + center(g.nodes[2])) / 2) < 1);
  checkNoOverlaps(g);
  // Two edges out of the entry leave from different points.
  const outs = g.edges.filter((e) => e.from === 0).map((e) => e.points[0][0]);
  assert.notStrictEqual(outs[0], outs[1]);
});

test("a loop: its back edge goes up the right side", () => {
  // 0 -> 1 (loop head) -> 2 (body) -> 1; 1 -> 3 (exit)
  const edges = [
    { from: 0, to: 1, kind: "next" },
    { from: 1, to: 2, kind: "not-taken" },
    { from: 1, to: 3, kind: "taken" },
    { from: 2, to: 1, kind: "jump" },
  ];
  const g = layoutGraph(4, [box(), box(), box(120), box()], edges);
  const back = g.edges.filter((e) => e.back);
  assert.strictEqual(back.length, 1);
  assert.deepStrictEqual([back[0].from, back[0].to], [2, 1]);
  const lane = back[0].points[2][0];
  assert.ok(lane > g.nodes[2].x + g.nodes[2].w && lane > g.nodes[1].x + g.nodes[1].w, "right of both");
  assert.ok(lane <= g.width);
  assert.ok(g.nodes[2].layer > g.nodes[1].layer);
  checkNoOverlaps(g);
  // A block that loops to itself.
  const self = layoutGraph(1, [box()], [{ from: 0, to: 0, kind: "jump" }]);
  assert.strictEqual(self.edges[0].back, true);
});

test("unreachable blocks are laid out too, just above where they lead", () => {
  const g = layoutGraph(3, [box(), box(), box()], [{ from: 0, to: 1, kind: "next" }]);
  assert.ok(g.nodes.every(Boolean));
  checkNoOverlaps(g);
  // 0 -> 1 -> 2 -> 3; a handler 4 (no way in) -> 3.
  const h = layoutGraph(5, [box(), box(), box(), box(), box()], [
    { from: 0, to: 1, kind: "next" },
    { from: 1, to: 2, kind: "next" },
    { from: 2, to: 3, kind: "next" },
    { from: 4, to: 3, kind: "jump" },
  ]);
  assert.strictEqual(h.nodes[4].layer, 2);
  checkNoOverlaps(h);
});

test("a long edge goes around the blocks between", () => {
  // 0 -> 1 -> 2 -> 3, and 0 -> 3 past them.
  const edges = [
    { from: 0, to: 1, kind: "not-taken" },
    { from: 1, to: 2, kind: "next" },
    { from: 2, to: 3, kind: "next" },
    { from: 0, to: 3, kind: "taken" },
  ];
  const g = layoutGraph(4, [box(200), box(200), box(200), box(200)], edges);
  const long = g.edges.find((e) => e.from === 0 && e.to === 3);
  assert.ok(long.lane, "routed by a lane");
  const x = long.points[2][0];
  for (const k of [1, 2]) {
    const n = g.nodes[k];
    assert.ok(x < n.x || x > n.x + n.w, `the lane misses block ${k}`);
  }
  assert.ok(x <= g.width);
  assert.ok(!edgePath(long).includes("NaN"));
});

test("edges become SVG paths", () => {
  const g = layoutGraph(3, [box(), box(), box()], [{ from: 0, to: 1, kind: "taken" }, { from: 1, to: 0, kind: "jump" }, { from: 1, to: 2, kind: "next" }]);
  for (const e of g.edges) {
    const d = edgePath(e);
    assert.ok(/^M[\d.]+,[\d.]+/.test(d) && !d.includes("NaN"), d);
  }
});

test("a large function: no overlaps, a reasonable size", () => {
  // A chain of 60 blocks, each branching ahead, some looping back.
  const n = 60;
  const edges = [];
  for (let i = 0; i < n - 1; i++) {
    edges.push({ from: i, to: i + 1, kind: "not-taken" });
    if (i + 3 < n) {
      edges.push({ from: i, to: i + 3, kind: "taken" });
    }
    if (i % 7 === 6) {
      edges.push({ from: i, to: i - 5, kind: "jump" });
    }
  }
  const sizes = Array.from({ length: n }, (_, i) => box(80 + (i % 5) * 30, 30 + (i % 3) * 20));
  const t = Date.now();
  const g = layoutGraph(n, sizes, edges);
  assert.ok(Date.now() - t < 500, "fast");
  checkNoOverlaps(g);
  assert.ok(g.edges.filter((e) => e.back).length >= 8);
});

let failed = 0;
for (const [name, fn] of tests) {
  try {
    fn();
    console.log(`ok   ${name}`);
  } catch (e) {
    failed++;
    console.log(`FAIL ${name}\n${e.stack}`);
  }
}
console.log(failed ? `${failed} failed` : "all passed");
process.exit(failed ? 1 : 0);
