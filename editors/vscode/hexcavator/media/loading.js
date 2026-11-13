// The pane's own "working" indicator: a spinner over the pane while hexc
// runs (with what it's doing, and Cancel), in place of a notification.
// It shows as the page opens; a "loading" message shows it again (over
// what is there, on a refresh); any other message hides it.
"use strict";

(function () {
  let box = null;

  function show(text, cancellable) {
    if (!document.body) {
      return;
    }
    if (!box) {
      box = document.createElement("div");
      box.id = "loading";
      box.setAttribute("role", "status");
      box.setAttribute("aria-live", "polite");
      const card = document.createElement("div");
      card.className = "card";
      const spin = document.createElement("div");
      spin.className = "spinner";
      const label = document.createElement("div");
      label.className = "text";
      const cancel = document.createElement("button");
      cancel.className = "cancel";
      cancel.textContent = "Cancel";
      cancel.addEventListener("click", () => {
        // (The page's own vscode API object: acquireVsCodeApi may be
        // called once only, so the page shares it.)
        const api = window.__hexcVscode;
        if (api) {
          api.postMessage({ command: "cancel" });
        }
        cancel.disabled = true;
        label.textContent = "Cancelling…";
      });
      card.append(spin, label, cancel);
      box.append(card);
      document.body.append(box);
    }
    box.querySelector(".text").textContent = text || "Running hexc…";
    const cancel = box.querySelector(".cancel");
    cancel.disabled = false;
    cancel.hidden = !cancellable;
    // Over what's there already (a refresh), or the whole pane.
    box.classList.toggle("over", document.body.dataset.loaded === "1");
    box.hidden = false;
  }

  function hide() {
    if (box) {
      box.hidden = true;
    }
    if (document.body) {
      document.body.dataset.loaded = "1";
    }
  }

  window.addEventListener("message", (e) => {
    const m = e.data;
    if (!m || !m.kind) {
      return;
    }
    if (m.kind === "loading") {
      show(m.text, m.cancellable !== false);
    } else {
      hide();
    }
  });
  // (The script is in the body: the body is there.)
  if (document.body) {
    show(null, false);
  } else {
    document.addEventListener("DOMContentLoaded", () => document.body.dataset.loaded !== "1" && show(null, false));
  }
})();
