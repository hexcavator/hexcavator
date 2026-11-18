// A stack tree as the view shows it: the rows the engine has sent, which
// are expanded, and the visible rows in order. Runs in the webview and
// under Node (for tests).
"use strict";
(function (exports) {
  class TreeModel {
    /** A tree whose root row is `root` (the engine's row 0). */
    constructor(root) {
      this.rows = new Map([[root.id, root]]);
      this.children = new Map();
      this.expanded = new Set([root.id]);
      this.rootId = root.id;
      this.total = root.inclusive || 0;
      this.cache = null;
    }

    /** Whether `id`'s children have arrived. */
    hasLoaded(id) {
      return this.children.has(id);
    }

    /** Stores `id`'s children (heaviest first, as the engine sends them). */
    setChildren(id, rows) {
      for (const r of rows) {
        this.rows.set(r.id, r);
      }
      this.children.set(
        id,
        rows.map((r) => r.id)
      );
      this.cache = null;
    }

    isExpanded(id) {
      return this.expanded.has(id);
    }

    /**
     * Expands or collapses `id`; returns true if its children are needed
     * from the engine first.
     */
    setExpanded(id, on) {
      const row = this.rows.get(id);
      if (!row || (!row.hasChildren && on)) {
        return false;
      }
      if (on) {
        this.expanded.add(id);
      } else {
        this.expanded.delete(id);
      }
      this.cache = null;
      return on && !this.hasLoaded(id);
    }

    /** The visible rows, in order: each expanded row's children under it. */
    visible() {
      if (this.cache) {
        return this.cache;
      }
      const out = [];
      const walk = (id) => {
        for (const c of this.children.get(id) || []) {
          out.push(this.rows.get(c));
          if (this.expanded.has(c)) {
            walk(c);
          }
        }
      };
      walk(this.rootId);
      this.cache = out;
      return out;
    }

    /**
     * The visible rows from `id` down: it and its visible descendants, in
     * order (all the visible rows if `id` isn't one).
     */
    subtree(id) {
      const rows = this.visible();
      const at = rows.findIndex((r) => r.id === id);
      if (at < 0) {
        return rows;
      }
      let end = at + 1;
      while (end < rows.length && rows[end].depth > rows[at].depth) {
        end++;
      }
      return rows.slice(at, end);
    }

    /**
     * `rows` (from [`visible`] or [`subtree`]) as a Markdown table: each
     * indented by its depth below the first, with its weight, share and
     * self weight (`weight` formats them).
     */
    markdown(rows, weight) {
      const top = rows.length ? Math.min(...rows.map((r) => r.depth)) : 0;
      return markdownTable(
        ["Stack", "Weight", "%", "Self"],
        rows.map((r) => [
          "\u2003".repeat(r.depth - top) + r.label,
          weight(r.inclusive),
          this.share(r),
          weight(r.exclusive),
        ]),
        [false, true, true, true]
      );
    }

    /** The share of the whole that `row` is, as text ("12.34%"). */
    share(row) {
      if (!this.total) {
        return "0.00%";
      }
      return ((100 * row.inclusive) / this.total).toFixed(2) + "%";
    }
  }

  /**
   * A Markdown table: `headers`, then `rows` of cells (text; a `|` in one
   * is escaped, and line breaks become spaces); `right` says which
   * columns are numbers (aligned right).
   */
  function markdownTable(headers, rows, right) {
    const cell = (v) =>
      String(v === null || v === undefined ? "" : v)
        .replace(/\\/g, "\\\\")
        .replace(/\|/g, "\\|")
        .replace(/[\r\n]+/g, " ");
    const line = (cells) => "| " + cells.map(cell).join(" | ") + " |";
    const rule = "|" + headers.map((_, i) => (right && right[i] ? " ---: " : " --- ")).join("|") + "|";
    return [line(headers), rule, ...rows.map(line)].join("\n") + "\n";
  }

  /** A weight as text: samples as counts, ticks as milliseconds. */
  function formatWeight(value, unit, ticksPerSecond) {
    if (unit === "ticks") {
      const ms = (value * 1000) / (ticksPerSecond || 10000000);
      return ms.toLocaleString("en-US", { maximumFractionDigits: 3, minimumFractionDigits: 3 }) + " ms";
    }
    return value.toLocaleString("en-US");
  }

  exports.TreeModel = TreeModel;
  exports.formatWeight = formatWeight;
  exports.markdownTable = markdownTable;
})(typeof module !== "undefined" && module.exports ? module.exports : (globalThis.StackrabbitTree = {}));
