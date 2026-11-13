// Layout and tree helpers for the size view: the squarified treemap
// (Bruls, Huizing, and van Wijk, 2000), nested treemaps, sunbursts, search,
// and colors. Plain functions with no DOM access, so they run (and are
// tested) outside a browser too.
"use strict";

/**
 * Lays out `items` (each with a `value` > 0) in the rectangle
 * {x, y, w, h}, largest first, as rectangles whose aspect ratios are close
 * to 1. Returns [{item, x, y, w, h}], in the order laid out.
 */
function squarify(items, rect) {
  const sorted = items
    .filter((i) => i.value > 0 && Number.isFinite(i.value))
    .sort((a, b) => b.value - a.value);
  const total = sorted.reduce((s, i) => s + i.value, 0);
  const out = [];
  if (total <= 0 || rect.w <= 0 || rect.h <= 0) {
    return out;
  }
  // Scale values to areas.
  const scale = (rect.w * rect.h) / total;
  const areas = sorted.map((i) => i.value * scale);
  let { x, y, w, h } = rect;
  let start = 0;
  while (start < sorted.length) {
    const side = Math.min(w, h);
    // Grow the row while the worst aspect ratio improves.
    let end = start + 1;
    let rowArea = areas[start];
    let best = worst(areas, start, end, rowArea, side);
    while (end < sorted.length) {
      const next = worst(areas, start, end + 1, rowArea + areas[end], side);
      if (next > best) {
        break;
      }
      best = next;
      rowArea += areas[end];
      end++;
    }
    // Place the row along the shorter side.
    const thickness = rowArea / side;
    let offset = 0;
    for (let k = start; k < end; k++) {
      const length = areas[k] / thickness;
      if (w >= h) {
        out.push({ item: sorted[k], x, y: y + offset, w: thickness, h: length });
      } else {
        out.push({ item: sorted[k], x: x + offset, y, w: length, h: thickness });
      }
      offset += length;
    }
    if (w >= h) {
      x += thickness;
      w -= thickness;
    } else {
      y += thickness;
      h -= thickness;
    }
    start = end;
  }
  return out;
}

/** The worst aspect ratio of areas[start..end) laid along `side`. */
function worst(areas, start, end, sum, side) {
  let max = 0;
  let min = Infinity;
  for (let k = start; k < end; k++) {
    max = Math.max(max, areas[k]);
    min = Math.min(min, areas[k]);
  }
  const s2 = side * side;
  const sum2 = sum * sum;
  return Math.max((s2 * max) / sum2, sum2 / (s2 * min));
}

/**
 * A nested treemap of `root`'s children in `rect`: each box big enough
 * gets a header strip and its own children laid out inside, down to
 * `levels` levels. At most `limit` boxes are made (the smallest are left
 * out; their space stays with their parent). Returns
 * [{row, path, depth, x, y, w, h, header}], parents before children.
 */
function layoutNested(root, rect, domain, options) {
  const { levels = 2, limit = 800, header = 18, minNest = { w: 90, h: 54 }, pad = 2 } = options || {};
  const out = [];
  function place(row, path, area, depth) {
    if (out.length >= limit) {
      return;
    }
    const kids = (row.children || []).map((c) => ({ value: rowValue(c, domain), row: c }));
    for (const b of squarify(kids, area)) {
      if (out.length >= limit) {
        return;
      }
      const c = b.item.row;
      const box = { row: c, path: [...path, c.name], depth, x: b.x, y: b.y, w: b.w, h: b.h, header: false };
      out.push(box);
      const nest = depth + 1 < levels && c.children && c.children.length && b.w >= minNest.w && b.h >= minNest.h;
      if (nest) {
        box.header = true;
        place(c, box.path, { x: b.x + pad, y: b.y + header, w: b.w - 2 * pad, h: b.h - header - pad }, depth + 1);
      }
    }
  }
  place(root, [], rect, 0);
  return out;
}

/**
 * A sunburst of `root`: each row an arc of the ring at its depth (from 0,
 * the innermost), its angle in proportion to its size. Arcs smaller than
 * `minAngle` radians are left out. Returns [{row, path, depth, start, end}].
 */
function sunburst(root, domain, levels, minAngle) {
  const out = [];
  const min = minAngle ?? 0.004;
  function place(row, path, start, end, depth) {
    if (depth >= levels) {
      return;
    }
    const kids = (row.children || []).filter((c) => rowValue(c, domain) > 0);
    const total = kids.reduce((s, c) => s + rowValue(c, domain), 0);
    if (total <= 0) {
      return;
    }
    let a = start;
    for (const c of [...kids].sort((x, y) => rowValue(y, domain) - rowValue(x, domain))) {
      const span = ((end - start) * rowValue(c, domain)) / total;
      if (span >= min) {
        const arc = { row: c, path: [...path, c.name], depth, start: a, end: a + span };
        out.push(arc);
        place(c, arc.path, a, a + span, depth + 1);
      }
      a += span;
    }
  }
  place(root, [], 0, 2 * Math.PI, 0);
  return out;
}

/** The SVG path of a ring segment: radii r0..r1, angles a0..a1 (from 12 o'clock, clockwise). */
function arcPath(cx, cy, r0, r1, a0, a1) {
  const p = (r, a) => [cx + r * Math.sin(a), cy - r * Math.cos(a)];
  const large = a1 - a0 > Math.PI ? 1 : 0;
  // A full ring needs two halves.
  if (a1 - a0 >= 2 * Math.PI - 1e-9) {
    const mid = a0 + Math.PI;
    return arcPath(cx, cy, r0, r1, a0, mid) + " " + arcPath(cx, cy, r0, r1, mid, a1);
  }
  const [x0, y0] = p(r1, a0);
  const [x1, y1] = p(r1, a1);
  const [x2, y2] = p(r0, a1);
  const [x3, y3] = p(r0, a0);
  const f = (n) => n.toFixed(2);
  return (
    `M${f(x0)},${f(y0)} A${f(r1)},${f(r1)} 0 ${large} 1 ${f(x1)},${f(y1)} ` +
    `L${f(x2)},${f(y2)} A${f(r0)},${f(r0)} 0 ${large} 0 ${f(x3)},${f(y3)} Z`
  );
}

/**
 * Rows anywhere below `root` whose names contain `query` (case-insensitive),
 * largest first: [{row, path}], at most `limit`.
 */
function search(root, query, domain, limit) {
  const q = query.trim().toLowerCase();
  const out = [];
  if (!q) {
    return out;
  }
  const visit = (row, path) => {
    for (const c of row.children || []) {
      const p = [...path, c.name];
      if (c.name.toLowerCase().includes(q)) {
        out.push({ row: c, path: p });
      }
      visit(c, p);
    }
  };
  visit(root, []);
  out.sort((a, b) => rowValue(b.row, domain) - rowValue(a.row, domain));
  return out.slice(0, limit ?? 200);
}

/** A size as bloaty prints it: 1024-based units, about three digits. */
function formatSize(n) {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let v = Math.abs(n);
  let u = 0;
  while (v >= 1024 && u < units.length - 1) {
    v /= 1024;
    u++;
  }
  const digits = u === 0 || v >= 100 ? 0 : v >= 10 ? 1 : 2;
  return (n < 0 ? "-" : "") + v.toFixed(digits) + " " + units[u];
}

/** A byte count with thousands separators: 1,234,567. */
function formatBytes(n) {
  return (n < 0 ? "-" : "") + Math.abs(n).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

/** `part` as a percentage of `whole`, as text ("12.3%", "<0.1%"). */
function percent(part, whole) {
  if (!whole) {
    return "";
  }
  const p = (100 * part) / whole;
  if (p > 0 && p < 0.1) {
    return "<0.1%";
  }
  return p.toFixed(p >= 10 ? 0 : 1) + "%";
}

/**
 * The value of a report row in `domain` ("file" or "vm"): its size, or,
 * in a diff, the magnitude of its change.
 */
function rowValue(row, domain) {
  const v = domain === "vm" ? row.vm : row.file;
  return Math.abs(v || 0);
}

/** The signed size of a row in `domain` (a diff's change keeps its sign). */
function signedValue(row, domain) {
  return (domain === "vm" ? row.vm : row.file) || 0;
}

/** The row at `path` (a list of child names) below `root`, if any. */
function rowAt(root, path) {
  let row = root;
  for (const name of path) {
    const next = (row.children || []).find((c) => c.name === name);
    if (!next) {
      return null;
    }
    row = next;
  }
  return row;
}

/** A stable hash of a string (FNV-1a). */
function hashOf(s) {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619) >>> 0;
  }
  return h;
}

/**
 * A color for a box: its hue from the top-level row it is under (so a
 * section's symbols share the section's hue), lighter with depth, and
 * shifted a little by its own name so that neighbors differ.
 */
function colorFor(name, depth, topName) {
  const base = hashOf(topName ?? name) % 360;
  const own = topName === undefined ? 0 : (hashOf(name) % 25) - 12;
  const hue = (base + own + 360) % 360;
  const light = 30 + Math.min(depth, 4) * 6 + (hashOf(name) % 5);
  return `hsl(${hue}, 48%, ${light}%)`;
}

/**
 * A diff's color: red for growth, green for shrinkage, stronger for larger
 * changes (on a log scale relative to the largest change shown).
 */
function diffColor(value, maxAbs) {
  if (!value) {
    return "hsl(220, 8%, 38%)";
  }
  const t = maxAbs > 0 ? Math.log1p(Math.abs(value)) / Math.log1p(maxAbs) : 1;
  const sat = 30 + 45 * t;
  const light = 44 - 14 * t;
  return value > 0 ? `hsl(2, ${sat}%, ${light}%)` : `hsl(140, ${sat}%, ${light - 6}%)`;
}

if (typeof module !== "undefined") {
  module.exports = {
    squarify,
    worst,
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
    hashOf,
    colorFor,
    diffColor,
  };
}
