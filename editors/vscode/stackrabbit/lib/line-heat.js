// Time by source line, shown in the source's own editor: which of a
// trace's source files (as its symbols name them, by the paths they were
// built at) an open file is, and what to show on each of its lines.
"use strict";

/** A path's parts, compared without regard to case or slash direction. */
function parts(p) {
  return p
    .replace(/\\/g, "/")
    .toLowerCase()
    .split("/")
    .filter((x) => x.length > 0);
}

/**
 * Which of `candidates` (the trace's source files, heaviest first) the
 * file at `local` is: the one ending in the most of its path's parts (at
 * least its name); the heaviest of those, if more than one. Null if none
 * has its name.
 */
function bestMatch(local, candidates) {
  const mine = parts(local);
  let best = null;
  let bestScore = 0;
  for (const c of candidates) {
    const theirs = parts(c);
    let n = 0;
    while (n < mine.length && n < theirs.length && mine[mine.length - 1 - n] === theirs[theirs.length - 1 - n]) {
      n++;
    }
    if (n > bestScore) {
      best = c;
      bestScore = n;
    }
  }
  return best;
}

/** How many heat levels lines are shown in. */
const LEVELS = 5;

/**
 * The heat level (0 to LEVELS - 1) of a line with `share` (0 to 1) of
 * the trace's weight: by powers of two, from 1/1024 up, so that both a
 * few hot lines and many warm ones show.
 */
function heatLevel(share) {
  if (!(share > 0)) {
    return -1;
  }
  const level = Math.floor(Math.log2(share * 1024) / 2);
  return Math.max(0, Math.min(LEVELS - 1, level));
}

/** A weight as text: samples as counts, ticks as milliseconds. */
function weightText(value, unit, ticksPerSecond) {
  if (unit === "ticks") {
    const ms = (value * 1000) / (ticksPerSecond || 10000000);
    return ms.toLocaleString("en-US", { maximumFractionDigits: 3 }) + " ms";
  }
  return value.toLocaleString("en-US") + (value === 1 ? " sample" : " samples");
}

/** A share (0 to 1) as text. */
function percent(share) {
  return (100 * share).toFixed(share < 0.001 ? 3 : 1) + "%";
}

/**
 * What a line shows: `after`, short text at its end (its share, and its
 * own share if any), and `hover`, Markdown with its weights.
 */
function describe(line, total, unit, ticksPerSecond) {
  const inc = total ? line.inclusive / total : 0;
  const ex = total ? line.exclusive / total : 0;
  const after = ex > 0 ? `${percent(inc)} (self ${percent(ex)})` : percent(inc);
  const hover =
    `**Stackrabbit**: ${percent(inc)} of the trace here or in what it calls ` +
    `(${weightText(line.inclusive, unit, ticksPerSecond)})` +
    (ex > 0 ? `; ${percent(ex)} on this line itself (${weightText(line.exclusive, unit, ticksPerSecond)})` : "") +
    ".";
  return { after, hover, level: heatLevel(inc) };
}

/**
 * Time by source line, in the source files' own editors: from the trace
 * whose view was active last, each visible file that is one of its source
 * files (by the paths its symbols name) gets each line's share at its end,
 * a background by how hot it is, and its weights on hover.
 */
class LineHeat {
  /** Shows line times through `vscode`'s API, from `engine`'s session. */
  constructor(vscode, engine, log) {
    this.vscode = vscode;
    this.engine = engine;
    this.log = log || (() => {});
    this.trace = null; // {id, name}
    this.files = null; // its source files, heaviest first
    this.generation = 0;
    const heat = (alpha) =>
      vscode.window.createTextEditorDecorationType({
        isWholeLine: true,
        backgroundColor: `rgba(255, 120, 0, ${alpha})`,
        overviewRulerColor: `rgba(255, 120, 0, ${Math.min(1, alpha * 2.5)})`,
        overviewRulerLane: vscode.OverviewRulerLane.Right,
      });
    this.levels = [0.05, 0.09, 0.14, 0.21, 0.3].slice(0, LEVELS).map(heat);
    this.text = vscode.window.createTextEditorDecorationType({
      after: { color: new vscode.ThemeColor("editorCodeLens.foreground"), margin: "0 0 0 2em" },
    });
  }

  /** Shows the trace `id` (named `name`), if it isn't already. */
  setTrace(id, name) {
    if (this.trace && this.trace.id === id) {
      return;
    }
    this.trace = { id, name };
    this.files = null;
    this.refresh();
  }

  /** The trace `id` closed: if it was shown, nothing is. */
  forget(id) {
    if (this.trace && this.trace.id === id) {
      this.trace = null;
      this.files = null;
      this.refresh();
    }
  }

  /** The trace `id`'s symbols changed: its lines again. */
  changed(id) {
    if (this.trace && this.trace.id === id) {
      this.files = null;
      this.refresh();
    }
  }

  enabled() {
    return this.vscode.workspace.getConfiguration("stackrabbit").get("lineHeat", true);
  }

  async refresh() {
    const generation = ++this.generation;
    const editors = this.vscode.window.visibleTextEditors.filter((e) => e.document.uri.scheme === "file");
    const session = this.engine.session;
    if (!this.trace || !this.enabled() || !session) {
      editors.forEach((e) => this.clear(e));
      return;
    }
    const trace = this.trace;
    try {
      if (!this.files) {
        const r = await session.request("lines", { trace: trace.id, limit: 100000 });
        if (generation !== this.generation) {
          return;
        }
        this.files = r.files.map((f) => f.path);
      }
      for (const editor of editors) {
        const file = bestMatch(editor.document.uri.fsPath, this.files);
        if (!file) {
          this.clear(editor);
          continue;
        }
        const r = await session.request("lines", { trace: trace.id, file });
        if (generation !== this.generation) {
          return;
        }
        this.show(editor, r, trace.name);
      }
    } catch (e) {
      this.log(`Line times: ${e.message}`);
    }
  }

  show(editor, r, name) {
    const byLevel = this.levels.map(() => []);
    const texts = [];
    for (const l of r.lines) {
      const line = l.line - 1; // (The symbols count from 1.)
      if (line < 0 || line >= editor.document.lineCount) {
        continue;
      }
      const d = describe(l, r.total, r.unit, r.ticksPerSecond);
      if (d.level < 0) {
        continue;
      }
      const range = editor.document.lineAt(line).range;
      byLevel[d.level].push({ range, hoverMessage: new this.vscode.MarkdownString(`${d.hover} (${name})`) });
      texts.push({ range: new this.vscode.Range(range.end, range.end), renderOptions: { after: { contentText: d.after } } });
    }
    this.levels.forEach((t, i) => editor.setDecorations(t, byLevel[i]));
    editor.setDecorations(this.text, texts);
  }

  clear(editor) {
    this.levels.forEach((t) => editor.setDecorations(t, []));
    editor.setDecorations(this.text, []);
  }

  dispose() {
    this.levels.forEach((t) => t.dispose());
    this.text.dispose();
  }
}

module.exports = { parts, bestMatch, heatLevel, describe, weightText, LEVELS, LineHeat };
