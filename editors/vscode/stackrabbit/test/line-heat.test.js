// Line heat's matching and text: `node test/line-heat.test.js`.
"use strict";

const assert = require("assert");
const { bestMatch, heatLevel, describe, LEVELS, LineHeat } = require("../lib/line-heat");

// A local file is the trace's file ending in the most of its path's parts.
const built = ["d:\\build\\proj\\src\\main.cpp", "d:\\build\\proj\\test\\main.cpp", "d:\\build\\proj\\src\\util.cpp"];
assert.strictEqual(bestMatch("c:/work/proj/src/main.cpp", built), built[0]);
assert.strictEqual(bestMatch("C:\\Work\\Proj\\TEST\\Main.cpp", built), built[1], "any case, any slashes");
assert.strictEqual(bestMatch("c:/elsewhere/util.cpp", built), built[2], "by name alone");
assert.strictEqual(bestMatch("c:/elsewhere/other.cpp", built), null, "no file of its name");
assert.strictEqual(bestMatch("c:/x/main.cpp", built), built[0], "a tie: the heaviest (first)");
assert.strictEqual(bestMatch("c:/x/main.cpp", []), null);

// Heat: none for nothing; by powers of four from 1/1024; capped.
assert.strictEqual(heatLevel(0), -1);
assert.strictEqual(heatLevel(1 / 2048), 0);
assert.strictEqual(heatLevel(1 / 1024), 0);
assert.strictEqual(heatLevel(4 / 1024), 1);
assert.strictEqual(heatLevel(0.5), LEVELS - 1);
assert.strictEqual(heatLevel(1), LEVELS - 1);
for (let s = 1e-6; s <= 1; s *= 1.7) {
  const l = heatLevel(s);
  assert.ok(l >= 0 && l < LEVELS, `${s}: ${l}`);
}

// What a line shows.
const d = describe({ inclusive: 250, exclusive: 50 }, 1000, "samples", 0);
assert.strictEqual(d.after, "25.0% (self 5.0%)");
assert.ok(d.hover.includes("250 samples") && d.hover.includes("50 samples"), d.hover);
assert.strictEqual(describe({ inclusive: 1, exclusive: 0 }, 1000, "samples", 0).after, "0.1%");
assert.strictEqual(describe({ inclusive: 1, exclusive: 0 }, 100000, "samples", 0).after, "0.001%");
const t = describe({ inclusive: 15000, exclusive: 0 }, 30000, "ticks", 10000000);
assert.strictEqual(t.after, "50.0%");
assert.ok(t.hover.includes("1.5 ms"), t.hover);

// The editors: through a fake of VS Code's API, from a fake engine.
(async () => {
  const decorated = new Map(); // editor path -> decoration type -> options
  let types = 0;
  const editor = (fsPath, lineCount) => ({
    document: {
      uri: { scheme: "file", fsPath },
      lineCount,
      lineAt: (n) => ({ range: { start: { line: n, character: 0 }, end: { line: n, character: 80 } } }),
    },
    setDecorations(type, options) {
      const m = decorated.get(fsPath) || new Map();
      m.set(type.id, options);
      decorated.set(fsPath, m);
    },
  });
  let enabled = true;
  const vscode = {
    window: {
      visibleTextEditors: [editor("c:/work/proj/src/main.cpp", 100), editor("c:/work/notes.txt", 10)],
      createTextEditorDecorationType: (o) => ({ id: types++, options: o, dispose() {} }),
    },
    workspace: { getConfiguration: () => ({ get: (k, d) => (k === "lineHeat" ? enabled : d) }) },
    OverviewRulerLane: { Right: 4 },
    ThemeColor: class {},
    MarkdownString: class {
      constructor(v) {
        this.value = v;
      }
    },
    Range: class {
      constructor(a, b) {
        this.start = a;
        this.end = b;
      }
    },
  };
  const asked = [];
  const engine = {
    session: {
      async request(method, params) {
        asked.push({ method, params });
        assert.strictEqual(method, "lines");
        if (!params.file) {
          return { files: [{ path: "d:\\build\\proj\\src\\main.cpp" }, { path: "d:\\build\\proj\\src\\util.cpp" }] };
        }
        assert.strictEqual(params.file, "d:\\build\\proj\\src\\main.cpp");
        return {
          unit: "samples",
          ticksPerSecond: 10000000,
          total: 1000,
          // Lines 10 (hot) and 20 (warm); 0 and 500 aren't in the file.
          lines: [
            { line: 0, exclusive: 1, inclusive: 1 },
            { line: 10, exclusive: 400, inclusive: 600 },
            { line: 20, exclusive: 0, inclusive: 5 },
            { line: 500, exclusive: 1, inclusive: 1 },
          ],
        };
      },
    },
  };
  const heat = new LineHeat(vscode, engine);
  assert.strictEqual(heat.levels.length, LEVELS);
  heat.setTrace(7, "t.etl");
  await new Promise((r) => setTimeout(r, 10));
  // Asked for the files, then main.cpp's lines (notes.txt is none of them).
  assert.deepStrictEqual(
    asked.map((a) => a.params.file || null),
    [null, "d:\\build\\proj\\src\\main.cpp"]
  );
  assert.ok(asked.every((a) => a.params.trace === 7));
  const main = decorated.get("c:/work/proj/src/main.cpp");
  const text = main.get(heat.text.id);
  assert.deepStrictEqual(
    text.map((t) => [t.range.start.line, t.renderOptions.after.contentText]),
    [
      [9, "60.0% (self 40.0%)"],
      [19, "0.5%"],
    ],
    "lines 10 and 20 (counted from 1), and no others"
  );
  const levelOf = (line) => heat.levels.findIndex((t) => (main.get(t.id) || []).some((o) => o.range.start.line === line));
  assert.ok(levelOf(9) > levelOf(19) && levelOf(19) >= 0, "the hotter line hotter");
  assert.ok(main.get(heat.levels[levelOf(9)].id)[0].hoverMessage.value.includes("(t.etl)"));
  const notes = decorated.get("c:/work/notes.txt");
  assert.ok([...notes.values()].every((o) => o.length === 0), "a file not in the trace: nothing");

  // Turned off: cleared. The trace closed: cleared, and no more asked.
  enabled = false;
  await heat.refresh();
  assert.ok([...main.values()].every((o) => o.length === 0));
  enabled = true;
  await heat.refresh();
  assert.ok(main.get(heat.text.id).length === 2, "on again");
  heat.forget(7);
  await new Promise((r) => setTimeout(r, 10));
  assert.ok([...main.values()].every((o) => o.length === 0));
  const before = asked.length;
  await heat.refresh();
  assert.strictEqual(asked.length, before);
  console.log("line-heat: ok");
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
