// A session with the real engine, as the extension runs it, on a synthetic
// trace: `node test/engine.test.js <stackrabbit>`.
"use strict";

const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawn, execFileSync } = require("child_process");
const { Session } = require("../lib/protocol");

const exe = process.argv[2];
if (!exe) {
  console.error("usage: node test/engine.test.js <stackrabbit>");
  process.exit(2);
}

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "stackrabbit-ext-"));
  const etl = path.join(dir, "t.etl");
  const truthPath = path.join(dir, "t.json");
  execFileSync(exe, ["synth", etl, "-duration-ms", "200", "-truth", truthPath]);
  const truth = JSON.parse(fs.readFileSync(truthPath, "utf8"));

  const child = spawn(exe, ["serve"], { stdio: ["pipe", "pipe", "inherit"] });
  const s = new Session((bytes) => child.stdin.write(bytes));
  child.stdout.on("data", (chunk) => s.receive(chunk));

  const opened = await s.request("open", { path: etl });
  assert.strictEqual(opened.summary.samples, truth.samples);
  const tree = await s.request("tree.create", { trace: opened.trace, groupBy: ["process"], frames: "module" });
  assert.strictEqual(tree.root.inclusive, truth.samples);
  const { rows } = await s.request("tree.children", { trace: opened.trace, view: tree.view, node: 0 });
  for (const p of truth.processes) {
    const r = rows.find((x) => x.label === `${p.name} (${p.pid})`);
    assert.strictEqual(r ? r.inclusive : 0, p.samples, p.name);
  }
  const hot = await s.request("tree.hotPath", { trace: opened.trace, view: tree.view, node: rows[0].id });
  assert.ok(hot.rows.length > 0);
  await assert.rejects(s.request("tree.children", { trace: opened.trace, view: 99, node: 0 }), /no such view/);

  // Reopened: from the index saved beside it.
  const again = await s.request("open", { path: etl });
  assert.strictEqual(again.opened.how, "index");
  await s.request("shutdown");
  child.stdin.end();
  fs.rmSync(dir, { recursive: true, force: true });
  console.log("engine: ok");
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
