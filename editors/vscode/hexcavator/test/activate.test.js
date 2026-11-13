// The extension activates against a stand-in `vscode` (one that takes any
// call), registering every command package.json declares, and its view:
// `node test/activate.test.js`. (A real VS Code: test/integration.)
"use strict";

const assert = require("assert");
const path = require("path");
const Module = require("module");

const registered = { commands: [], views: [], other: [] };

/** Anything: callable, constructible, and with any property. */
function anything(name) {
  const target = function () {};
  return new Proxy(target, {
    get(_, prop) {
      if (prop === Symbol.toPrimitive) {
        return () => name;
      }
      if (prop === "then") {
        return undefined;
      }
      return anything(`${name}.${String(prop)}`);
    },
    apply() {
      return anything(`${name}()`);
    },
    construct() {
      return anything(`new ${name}`);
    },
  });
}

const vscode = new Proxy(
  {
    commands: new Proxy(
      {},
      {
        get(_, prop) {
          if (prop === "registerCommand") {
            return (id, fn) => {
              assert.strictEqual(typeof fn, "function", id);
              registered.commands.push(id);
              return { dispose() {} };
            };
          }
          return anything(`commands.${String(prop)}`);
        },
      }
    ),
    window: new Proxy(
      {},
      {
        get(_, prop) {
          if (prop === "createTreeView") {
            return (id, options) => {
              assert.ok(options.treeDataProvider, id);
              registered.views.push(id);
              return anything("treeView");
            };
          }
          return anything(`window.${String(prop)}`);
        },
      }
    ),
    workspace: new Proxy(
      {},
      {
        get(_, prop) {
          if (prop === "getConfiguration") {
            return () => ({ get: (k, d) => d });
          }
          return anything(`workspace.${String(prop)}`);
        },
      }
    ),
  },
  {
    get(target, prop) {
      return prop in target ? target[prop] : anything(String(prop));
    },
  }
);

const resolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  return request === "vscode" ? "vscode" : resolve.call(this, request, ...rest);
};
require.cache.vscode = { id: "vscode", filename: "vscode", loaded: true, exports: vscode };

const root = path.join(__dirname, "..");
const ext = require(path.join(root, "extension.js"));
const memento = () => {
  const m = new Map();
  return { get: (k) => m.get(k), update: (k, v) => m.set(k, v) };
};
const context = { subscriptions: [], extensionPath: root, workspaceState: memento(), globalState: memento() };
ext.activate(context);

const pkg = require(path.join(root, "package.json"));
const declared = pkg.contributes.commands.map((c) => c.command).sort();
assert.deepStrictEqual([...new Set(registered.commands)].sort(), declared, "the commands registered are those declared");
const views = Object.values(pkg.contributes.views).flat().map((v) => v.id);
assert.deepStrictEqual(registered.views.sort(), views.sort(), "the views");
// Every command a menu or a welcome view names is declared.
for (const [menu, items] of Object.entries(pkg.contributes.menus)) {
  for (const item of items) {
    assert.ok(declared.includes(item.command), `${menu}: ${item.command}`);
  }
}
for (const w of pkg.contributes.viewsWelcome) {
  for (const m of w.contents.matchAll(/\(command:([\w.]+)/g)) {
    assert.ok(declared.includes(m[1]) || m[1].startsWith("workbench."), m[1]);
  }
}
assert.ok(context.subscriptions.length > declared.length, "disposables kept");
console.log(`ok   activates: ${declared.length} commands, ${views.length} view`);
console.log("all passed");
