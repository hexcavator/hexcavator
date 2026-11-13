// A smoke test in a real VS Code: the extension activates, its commands and
// view exist, and the sidebar opens a binary and reads its tree. Run by
// test/integration/run.cmd (VS Code's --extensionTestsPath); it writes what
// it found to the file in HEXC_SMOKE_OUT, and with HEXC_SMOKE_PAUSE waits
// that many milliseconds at the end (to take a screenshot).
"use strict";

const vscode = require("vscode");
const fs = require("fs");
const path = require("path");

async function run() {
  const out = [];
  const log = (s) => out.push(s);
  const fail = (s) => {
    out.push("FAIL " + s);
  };
  try {
    const ext = vscode.extensions.all.find((e) => e.packageJSON.name === "hexcavator");
    if (!ext) {
      throw new Error("the extension is not loaded");
    }
    await ext.activate();
    log("activated");
    const commands = await vscode.commands.getCommands(true);
    const ours = ext.packageJSON.contributes.commands.map((c) => c.command);
    const missing = ours.filter((c) => !commands.includes(c));
    if (missing.length) {
      fail("unregistered commands: " + missing.join(", "));
    } else {
      log(`${ours.length} commands registered`);
    }
    const image = process.env.HEXC_SMOKE_IMAGE;
    const base = process.env.HEXC_SMOKE_BASE;
    await vscode.commands.executeCommand("workbench.view.extension.hexcavator");
    await vscode.commands.executeCommand("hexcavator.open", vscode.Uri.file(image));
    log("opened " + path.basename(image));
    // The size tree, through the command that shows a row in the treemap.
    await vscode.commands.executeCommand("hexcavator.showReport", { type: "entry", entry: { file: image, base: null } });
    log("report opened");
    if (base) {
      // A diff, added as the report on it is.
      await vscode.commands.executeCommand("hexcavator.showReport", { type: "entry", entry: { file: image, base } });
      log("diff report opened");
    }
    // A tool's output as a document.
    const tool = { id: "unreachable", label: "Unreachable Code and Data", run: "text", args: ["xref", "-unreachable", "-n", "0", image] };
    await vscode.commands.executeCommand("hexcavator.runTool", { type: "tool", entry: { file: image, base: null }, tool });
    await new Promise((r) => setTimeout(r, 3000));
    const doc = vscode.workspace.textDocuments.find((d) => d.uri.scheme === "hexc-out");
    if (!doc) {
      fail("no hexc-out document");
    } else {
      const text = doc.getText();
      log(`output document: ${doc.uri.path} (${text.split("\n").length} lines)`);
      if (!text.startsWith("$ ") || !text.includes("xref -unreachable")) {
        fail("the document doesn't start with its command line");
      }
      if (/failed/.test(text.split("\n").slice(0, 3).join("\n"))) {
        fail("hexc failed: " + text.slice(0, 300));
      }
    }
    // ELF and Mach-O images with DWARF (no extension, or a loose DWARF
    // file beside): a tool that needs debug information, as text.
    for (const other of (process.env.HEXC_SMOKE_OTHERS || "").split(";").filter(Boolean)) {
      await vscode.commands.executeCommand("hexcavator.open", vscode.Uri.file(other));
      const t = { id: "sourcefiles", label: "Code by Source File", run: "text", args: ["sourcefiles", "-n", "5", other] };
      await vscode.commands.executeCommand("hexcavator.runTool", { type: "tool", entry: { file: other, base: null }, tool: t });
      await new Promise((r) => setTimeout(r, 3000));
      const d = vscode.workspace.textDocuments.find((x) => x.uri.scheme === "hexc-out" && x.getText().includes(other));
      const text = d ? d.getText() : "";
      if (!/source files: \d+ bytes of code/.test(text)) {
        fail(`${path.basename(other)}: sourcefiles gave ${JSON.stringify(text.slice(0, 300))}`);
      } else {
        log(`${path.basename(other)}: sourcefiles from its DWARF`);
      }
    }
    // Why main is there, in the tree.
    await vscode.commands.executeCommand("hexcavator.symbol.why", { type: "symbol", entry: { file: image, base: null }, name: "main(int, char**)" });
    log("why main added");
    await vscode.commands.executeCommand("hexcavator.binaries.focus");
  } catch (e) {
    fail(e.stack || String(e));
  }
  const pause = Number(process.env.HEXC_SMOKE_PAUSE || 0);
  if (pause) {
    await new Promise((r) => setTimeout(r, pause));
  }
  fs.writeFileSync(process.env.HEXC_SMOKE_OUT, out.join("\n") + "\n");
  if (out.some((l) => l.startsWith("FAIL"))) {
    throw new Error(out.join("\n"));
  }
}

module.exports = { run };
