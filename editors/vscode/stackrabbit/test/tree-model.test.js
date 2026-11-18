// The tree view's model: `node test/tree-model.test.js`.
"use strict";

const assert = require("assert");
const { TreeModel, formatWeight, markdownTable } = require("../media/tree-model");

const row = (id, parent, depth, inclusive, hasChildren) => ({
  id,
  parent,
  depth,
  label: `n${id}`,
  inclusive,
  exclusive: 0,
  count: inclusive,
  hasChildren,
});

const m = new TreeModel(row(0, 0, 0, 200, true));
assert.deepStrictEqual(m.visible(), [], "nothing until the root's children come");
m.setChildren(0, [row(1, 0, 1, 150, true), row(2, 0, 1, 50, false)]);
assert.deepStrictEqual(
  m.visible().map((r) => r.id),
  [1, 2]
);

// Expanding asks for children the first time only.
assert.strictEqual(m.setExpanded(1, true), true);
assert.deepStrictEqual(
  m.visible().map((r) => r.id),
  [1, 2],
  "children not here yet"
);
m.setChildren(1, [row(3, 1, 2, 100, false), row(4, 1, 2, 50, false)]);
assert.deepStrictEqual(
  m.visible().map((r) => r.id),
  [1, 3, 4, 2]
);
assert.strictEqual(m.setExpanded(1, false), false);
assert.deepStrictEqual(
  m.visible().map((r) => r.id),
  [1, 2]
);
assert.strictEqual(m.setExpanded(1, true), false, "already loaded");
assert.deepStrictEqual(
  m.visible().map((r) => r.id),
  [1, 3, 4, 2]
);

// A leaf doesn't expand; an unknown row doesn't either.
assert.strictEqual(m.setExpanded(2, true), false);
assert.strictEqual(m.isExpanded(2), false);
assert.strictEqual(m.setExpanded(77, true), false);

// Shares of the whole.
assert.strictEqual(m.share(m.rows.get(1)), "75.00%");
assert.strictEqual(new TreeModel(row(0, 0, 0, 0, false)).share(row(5, 0, 1, 0, false)), "0.00%");

// Weights: samples as counts, ticks as milliseconds.
assert.strictEqual(formatWeight(1234567, "samples"), "1,234,567");
assert.strictEqual(formatWeight(15000, "ticks", 10000000), "1.500 ms");

// Markdown: a table, numbers right-aligned, pipes escaped, lines joined.
assert.strictEqual(
  markdownTable(["Name", "N"], [["a|b", 1], ["two\nlines", null]], [false, true]),
  "| Name | N |\n| --- | ---: |\n| a\\|b | 1 |\n| two lines |  |\n"
);
// A subtree: a row and the rows open under it, indented from it.
{
  const t = new TreeModel(row(0, 0, 0, 100, true));
  t.setChildren(0, [row(1, 0, 1, 60, true), row(2, 0, 1, 40, true)]);
  t.setExpanded(1, true);
  t.setChildren(1, [row(3, 1, 2, 50, true), row(4, 1, 2, 10, false)]);
  t.setExpanded(3, true);
  t.setChildren(3, [row(5, 3, 3, 50, false)]);
  assert.deepStrictEqual(t.subtree(1).map((r) => r.id), [1, 3, 5, 4]);
  assert.deepStrictEqual(t.subtree(3).map((r) => r.id), [3, 5]);
  assert.deepStrictEqual(t.subtree(2).map((r) => r.id), [2]);
  assert.deepStrictEqual(t.subtree(99).map((r) => r.id), [1, 3, 5, 4, 2], "not shown: all of it");
  assert.strictEqual(
    t.markdown(t.subtree(3), (v) => String(v)),
    "| Stack | Weight | % | Self |\n| --- | ---: | ---: | ---: |\n| n3 | 50 | 50.00% | 0 |\n| \u2003n5 | 50 | 50.00% | 0 |\n"
  );
}

console.log("tree-model: ok");
