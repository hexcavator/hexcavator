// A graph of CPU usage over time, stacked by series, drawn on a canvas;
// dragging across it selects a time range, and double-clicking clears it.
"use strict";
(function (exports) {
  // Colors for series, then Other (gray). Distinguishable in light and dark.
  const COLORS = ["#4e79a7", "#f28e2b", "#e15759", "#76b7b2", "#59a14f", "#edc948", "#b07aa1", "#ff9da7", "#9c755f"];
  const OTHER = "#8c8c8c";
  const AXIS = 40; // Left margin for the axis labels, in CSS pixels.

  class Graph {
    /**
     * A graph on `canvas`; `onSelect(range)` hears of selections, as
     * [startNs, endNs], or null when cleared.
     */
    constructor(canvas, legend, onSelect) {
      this.canvas = canvas;
      this.legend = legend;
      this.onSelect = onSelect;
      this.data = null;
      this.selection = null; // [startNs, endNs]
      this.drag = null;
      canvas.addEventListener("mousedown", (e) => {
        const t = this.timeAt(e.offsetX);
        if (t !== null) {
          this.drag = [t, t];
          this.draw();
        }
      });
      canvas.addEventListener("mousemove", (e) => {
        if (this.drag) {
          const t = this.timeAt(e.offsetX);
          if (t !== null) {
            this.drag[1] = t;
            this.draw();
          }
        }
      });
      const finish = () => {
        if (!this.drag) {
          return;
        }
        const [a, b] = this.drag;
        this.drag = null;
        if (Math.abs(b - a) > 0) {
          this.selection = [Math.min(a, b), Math.max(a, b)];
          this.onSelect(this.selection);
        }
        this.draw();
      };
      canvas.addEventListener("mouseup", finish);
      canvas.addEventListener("mouseleave", finish);
      canvas.addEventListener("dblclick", () => {
        this.clear();
      });
    }

    /** Clears the selection. */
    clear() {
      this.drag = null;
      if (this.selection) {
        this.selection = null;
        this.onSelect(null);
      }
      this.draw();
    }

    /** The plot's width in CSS pixels: as many buckets as it has pixels. */
    plotWidth() {
      return Math.max(10, Math.floor(this.canvas.clientWidth - AXIS));
    }

    /** Shows `data` (the engine's graph). */
    set(data) {
      this.data = data;
      this.draw();
      this.drawLegend();
    }

    /** The time at x (CSS pixels), within the graph, or null. */
    timeAt(x) {
      if (!this.data) {
        return null;
      }
      const w = this.plotWidth();
      const f = Math.min(1, Math.max(0, (x - AXIS) / w));
      return Math.round(this.data.startNs + f * (this.data.endNs - this.data.startNs));
    }

    xOf(ns) {
      const d = this.data;
      return AXIS + ((ns - d.startNs) / Math.max(1, d.endNs - d.startNs)) * this.plotWidth();
    }

    draw() {
      const c = this.canvas;
      const ratio = window.devicePixelRatio || 1;
      const cw = c.clientWidth;
      const ch = c.clientHeight;
      c.width = Math.round(cw * ratio);
      c.height = Math.round(ch * ratio);
      const g = c.getContext("2d");
      g.setTransform(ratio, 0, 0, ratio, 0, 0);
      g.clearRect(0, 0, cw, ch);
      const style = getComputedStyle(document.body);
      const fg = style.getPropertyValue("--vscode-descriptionForeground") || "#888";
      const grid = style.getPropertyValue("--vscode-panel-border") || "#444";
      const top = 6;
      const bottom = ch - 16;
      const h = bottom - top;
      // The axes: 0, 50 and 100% of the processors; seconds below.
      g.font = "10px sans-serif";
      g.fillStyle = fg;
      g.strokeStyle = grid;
      for (const p of [0, 0.5, 1]) {
        const y = bottom - p * h;
        g.beginPath();
        g.moveTo(AXIS, y + 0.5);
        g.lineTo(cw, y + 0.5);
        g.stroke();
        g.fillText(`${p * 100}%`, 4, y + 3);
      }
      const d = this.data;
      if (!d) {
        return;
      }
      const span = (d.endNs - d.startNs) / 1e9;
      const ticks = 6;
      for (let i = 0; i <= ticks; i++) {
        const x = AXIS + (i / ticks) * this.plotWidth();
        const s = (d.startNs / 1e9 + (i / ticks) * span).toFixed(span < 1 ? 3 : 1);
        g.fillText(`${s} s`, Math.min(x, cw - 40), ch - 3);
      }
      // The series, stacked: each bucket a column, each series a band.
      const n = d.buckets;
      const step = this.plotWidth() / n;
      const base = new Float64Array(n);
      d.series.forEach((s, i) => {
        g.fillStyle = s.label === "Other" ? OTHER : COLORS[i % COLORS.length];
        g.beginPath();
        g.moveTo(AXIS, bottom);
        for (let b = 0; b < n; b++) {
          const y = bottom - Math.min(1, base[b] + s.values[b]) * h;
          g.lineTo(AXIS + b * step, y);
          g.lineTo(AXIS + (b + 1) * step, y);
        }
        for (let b = n - 1; b >= 0; b--) {
          g.lineTo(AXIS + (b + 1) * step, bottom - Math.min(1, base[b]) * h);
          g.lineTo(AXIS + b * step, bottom - Math.min(1, base[b]) * h);
        }
        g.closePath();
        g.fill();
        for (let b = 0; b < n; b++) {
          base[b] += s.values[b];
        }
      });
      // The selection, or the range being dragged.
      const range = this.drag || this.selection;
      if (range) {
        const x0 = this.xOf(Math.min(range[0], range[1]));
        const x1 = this.xOf(Math.max(range[0], range[1]));
        g.fillStyle = "rgba(128, 160, 255, 0.25)";
        g.fillRect(x0, top, Math.max(1, x1 - x0), h);
        g.strokeStyle = "rgba(128, 160, 255, 0.9)";
        g.strokeRect(x0 + 0.5, top + 0.5, Math.max(1, x1 - x0), h);
      }
    }

    drawLegend() {
      const d = this.data;
      if (!this.legend || !d) {
        return;
      }
      const total = d.series.reduce((a, s) => a + s.samples, 0) || 1;
      this.legend.innerHTML = d.series
        .map((s, i) => {
          const color = s.label === "Other" ? OTHER : COLORS[i % COLORS.length];
          const share = ((100 * s.samples) / total).toFixed(1);
          return `<span class="key"><span class="swatch" style="background:${color}"></span>${escape(s.label)} ${share}%</span>`;
        })
        .join("");
    }
  }

  function escape(s) {
    return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
  }

  exports.Graph = Graph;
})(typeof module !== "undefined" && module.exports ? module.exports : (globalThis.StackrabbitGraph = {}));
