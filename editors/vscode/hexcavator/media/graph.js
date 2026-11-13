// A layered layout for a function's control-flow graph: blocks in rows
// (each below every block that can reach it, but for loops' back edges),
// ordered within a row to cross fewer edges, and edges routed between
// them (back edges up the right side). Plain functions, tested under Node.
"use strict";

/**
 * Lays out `n` blocks with `sizes[i] = { w, h }` and `edges` ({ from, to,
 * kind }), from block 0. Returns { nodes: [{ x, y, w, h, layer }], edges:
 * [{ from, to, kind, back, points: [[x, y], ...] }], width, height }.
 */
function layoutGraph(n, sizes, edges, options) {
  const o = Object.assign({ hgap: 36, vgap: 56, margin: 24, lane: 12 }, options || {});
  const out = new Array(n).fill(null).map(() => []);
  const inn = new Array(n).fill(null).map(() => []);
  edges.forEach((e, i) => {
    if (e.from >= 0 && e.from < n && e.to >= 0 && e.to < n) {
      out[e.from].push(i);
      inn[e.to].push(i);
    }
  });

  // Back edges: those to a block still being visited (a loop's), by a
  // depth-first walk from the entry, then from any block not yet reached.
  const back = new Array(edges.length).fill(false);
  const state = new Array(n).fill(0); // 0 new, 1 visiting, 2 done
  const order = [];
  const visit = (start) => {
    const stack = [[start, 0]];
    state[start] = 1;
    while (stack.length) {
      const top = stack[stack.length - 1];
      const [v, k] = top;
      if (k < out[v].length) {
        top[1]++;
        const ei = out[v][k];
        const w = edges[ei].to;
        if (state[w] === 1) {
          back[ei] = true;
        } else if (state[w] === 0) {
          state[w] = 1;
          stack.push([w, 0]);
        }
      } else {
        state[v] = 2;
        order.push(v);
        stack.pop();
      }
    }
  };
  for (let v = 0; v < n; v++) {
    if (state[v] === 0) {
      visit(v);
    }
  }
  // Rows: the longest path from a source over the forward edges (in
  // topological order: the reverse of the walk's finishing order).
  const layer = new Array(n).fill(0);
  for (let i = order.length - 1; i >= 0; i--) {
    const v = order[i];
    for (const ei of out[v]) {
      if (!back[ei] && edges[ei].to !== v) {
        layer[edges[ei].to] = Math.max(layer[edges[ei].to], layer[v] + 1);
      }
    }
  }
  // Blocks the entry doesn't reach (an exception handler's, say) go as low
  // as they can: just above their highest successor (sinks first, so that
  // what leads to them follows).
  const reached = new Array(n).fill(false);
  if (n) {
    const stack = [0];
    reached[0] = true;
    while (stack.length) {
      const v = stack.pop();
      for (const ei of out[v]) {
        const w = edges[ei].to;
        if (!reached[w]) {
          reached[w] = true;
          stack.push(w);
        }
      }
    }
  }
  for (const v of order) {
    if (reached[v]) {
      continue;
    }
    const below = out[v].filter((ei) => !back[ei] && edges[ei].to !== v).map((ei) => layer[edges[ei].to]);
    if (below.length) {
      layer[v] = Math.max(layer[v], Math.min(...below) - 1);
    }
  }
  const rows = [];
  for (let v = 0; v < n; v++) {
    (rows[layer[v]] = rows[layer[v]] || []).push(v);
  }
  for (let r = 0; r < rows.length; r++) {
    rows[r] = rows[r] || [];
  }

  // Order within rows: by the mean position of their neighbors in the row
  // above (then below), a few times over.
  const pos = new Array(n).fill(0);
  const renumber = () => rows.forEach((row) => row.forEach((v, i) => (pos[v] = i)));
  renumber();
  const mean = (v, dir) => {
    const list = (dir > 0 ? inn[v] : out[v]).filter((ei) => !back[ei]).map((ei) => (dir > 0 ? edges[ei].from : edges[ei].to));
    return list.length ? list.reduce((s, u) => s + pos[u], 0) / list.length : pos[v];
  };
  for (let pass = 0; pass < 6; pass++) {
    const down = pass % 2 === 0;
    const range = down ? rows.map((_, i) => i).slice(1) : rows.map((_, i) => i).reverse().slice(1);
    for (const r of range) {
      const keyed = rows[r].map((v) => [mean(v, down ? 1 : -1), pos[v], v]);
      keyed.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
      rows[r] = keyed.map((k) => k[2]);
      renumber();
    }
  }

  // Positions: rows stacked; within a row, each block as near the mean
  // center of its parents as the blocks beside it allow.
  const nodes = new Array(n);
  let y = o.margin;
  const rowY = [];
  for (const row of rows) {
    rowY.push(y);
    const h = Math.max(0, ...row.map((v) => sizes[v].h));
    let x = o.margin;
    for (const v of row) {
      nodes[v] = { x, y, w: sizes[v].w, h: sizes[v].h, layer: layer[v] };
      x += sizes[v].w + o.hgap;
    }
    y += h + o.vgap;
  }
  const center = (v) => nodes[v].x + nodes[v].w / 2;
  for (let pass = 0; pass < 4; pass++) {
    for (let r = 1; r < rows.length; r++) {
      const row = rows[r];
      const want = row.map((v) => {
        const parents = inn[v].filter((ei) => !back[ei]).map((ei) => edges[ei].from);
        return parents.length ? parents.reduce((s, u) => s + center(u), 0) / parents.length - nodes[v].w / 2 : nodes[v].x;
      });
      // Left to right, no overlaps; then right to left, pulled back
      // toward what each wants.
      for (let i = 0; i < row.length; i++) {
        const min = i ? nodes[row[i - 1]].x + nodes[row[i - 1]].w + o.hgap : o.margin;
        nodes[row[i]].x = Math.max(min, want[i]);
      }
      for (let i = row.length - 2; i >= 0; i--) {
        const max = nodes[row[i + 1]].x - o.hgap - nodes[row[i]].w;
        nodes[row[i]].x = Math.max(i ? nodes[row[i - 1]].x + nodes[row[i - 1]].w + o.hgap : o.margin, Math.min(nodes[row[i]].x, max));
      }
    }
  }
  // Nothing left of the margin.
  const minX = Math.min(...nodes.map((d) => d.x));
  if (minX !== o.margin) {
    nodes.forEach((d) => (d.x += o.margin - minX));
  }
  let width = Math.max(0, ...nodes.map((d) => d.x + d.w)) + o.margin;

  // Edges: from a block's bottom (several spread across it) to the top of
  // the next; back edges out its right side, up a lane right of both, and
  // into the target's top from above.
  let lanes = 0;
  const routed = edges.map((e, i) => {
    const s = nodes[e.from];
    const t = nodes[e.to];
    if (!s || !t) {
      return null;
    }
    const outs = out[e.from];
    const k = outs.indexOf(i);
    const sx = s.x + (s.w * (k + 1)) / (outs.length + 1);
    const ins = inn[e.to];
    const j = ins.indexOf(i);
    const tx = t.x + (t.w * (j + 1)) / (ins.length + 1);
    if (!back[i]) {
      const between = [];
      for (let r = s.layer + 1; r < t.layer; r++) {
        between.push(...rows[r].map((v) => nodes[v]));
      }
      const clear = (x) => between.every((b) => x < b.x - 4 || x > b.x + b.w + 4);
      if (!between.length || (clear(sx) && clear(tx) && clear((sx + tx) / 2))) {
        return { from: e.from, to: e.to, kind: e.kind, back: false, points: [[sx, s.y + s.h], [sx, s.y + s.h + o.vgap / 3], [tx, t.y - o.vgap / 3], [tx, t.y]] };
      }
      // Across rows with blocks in the way: down the clear lane nearest
      // the way straight there (beside a block, or right of them all).
      const candidates = [sx, tx];
      for (const b of between) {
        candidates.push(b.x - o.hgap / 2, b.x + b.w + o.hgap / 2);
      }
      candidates.push(Math.max(...between.map((b) => b.x + b.w)) + o.hgap / 2);
      let x = null;
      for (const c of candidates) {
        if (c > 0 && clear(c) && (x === null || Math.abs(c - sx) + Math.abs(c - tx) < Math.abs(x - sx) + Math.abs(x - tx))) {
          x = c;
        }
      }
      const y0 = s.y + s.h + o.vgap / 3;
      const y1 = t.y - o.vgap / 3;
      return { from: e.from, to: e.to, kind: e.kind, back: false, lane: true, points: [[sx, s.y + s.h], [sx, y0], [x, y0], [x, y1], [tx, y1], [tx, t.y]] };
    }
    lanes++;
    const laneX = Math.max(s.x + s.w, t.x + t.w) + o.lane * lanes;
    const above = t.y - o.vgap / 2 + (lanes % 3) * 4;
    return {
      from: e.from,
      to: e.to,
      kind: e.kind,
      back: true,
      points: [[sx, s.y + s.h], [sx, s.y + s.h + o.vgap / 4], [laneX, s.y + s.h + o.vgap / 4], [laneX, above], [tx, above], [tx, t.y]],
    };
  });
  width = Math.max(width, ...routed.filter((r) => r && (r.back || r.lane)).map((r) => Math.max(r.points[2][0], r.points[3][0]) + o.margin));
  return { nodes, edges: routed.filter(Boolean), width, height: y - o.vgap + o.margin, rows: rows.length };
}

/** An SVG path through `points`: smooth for forward edges, squared with round corners for back ones. */
function edgePath(e) {
  const p = e.points;
  if (!e.back && !e.lane) {
    const [a, b, c, d] = p;
    return `M${a[0]},${a[1]} L${b[0]},${b[1]} C${b[0]},${(b[1] + c[1]) / 2} ${c[0]},${(b[1] + c[1]) / 2} ${c[0]},${c[1]} L${d[0]},${d[1]}`;
  }
  let s = `M${p[0][0]},${p[0][1]}`;
  for (let i = 1; i < p.length - 1; i++) {
    const [x, y] = p[i];
    const [px, py] = p[i - 1];
    const [nx, ny] = p[i + 1];
    const r = Math.min(6, Math.hypot(x - px, y - py) / 2, Math.hypot(nx - x, ny - y) / 2);
    const ux = Math.sign(x - px);
    const uy = Math.sign(y - py);
    const vx = Math.sign(nx - x);
    const vy = Math.sign(ny - y);
    s += ` L${x - ux * r},${y - uy * r} Q${x},${y} ${x + vx * r},${y + vy * r}`;
  }
  const last = p[p.length - 1];
  return s + ` L${last[0]},${last[1]}`;
}

if (typeof module !== "undefined") {
  module.exports = { layoutGraph, edgePath };
}
