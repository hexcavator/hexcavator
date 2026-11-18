"""Renders the trace view (media/tree-view.js) in headless Edge with the
engine's answers for a synthetic trace, and checks what it draws:
`python harness.py <stackrabbit> [shots]` (with a directory `shots`, it also
saves screenshots there, to look at).

The page gets a stand-in for VS Code's webview API that answers the view's
requests from answers the engine gave beforehand (the harness asks the
engine every question the view can ask of the trace's first levels).
"""

import html
import json
import os
import re
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
MEDIA = os.path.join(os.path.dirname(HERE), "media")
EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"

# A dark theme's variables, as VS Code gives a webview.
THEME = """
:root {
  --vscode-font-family: "Segoe UI", system-ui, sans-serif;
  --vscode-font-size: 13px;
  --vscode-foreground: #cccccc;
  --vscode-descriptionForeground: #9d9d9d;
  --vscode-editor-background: #1f1f1f;
  --vscode-panel-border: #2b2b2b;
  --vscode-list-hoverBackground: #2a2d2e;
  --vscode-list-activeSelectionBackground: #04395e;
  --vscode-list-activeSelectionForeground: #ffffff;
  --vscode-button-background: #0078d4;
  --vscode-button-foreground: #ffffff;
  --vscode-dropdown-background: #313131;
  --vscode-dropdown-foreground: #cccccc;
  --vscode-dropdown-border: #3c3c3c;
  --vscode-errorForeground: #f85149;
}
"""


class Engine:
    """A session with `stackrabbit serve`."""

    def __init__(self, exe):
        self.p = subprocess.Popen([exe, "serve"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        self.next = 1

    def request(self, method, params=None):
        rid = self.next
        self.next += 1
        header = json.dumps({"id": rid, "method": method, "params": params or {}}).encode()
        self.p.stdin.write(struct.pack("<II", len(header), 0) + header)
        self.p.stdin.flush()
        while True:
            hl, pl = struct.unpack("<II", self.read(8))
            answer = json.loads(self.read(hl))
            self.read(pl)
            if answer.get("id") == rid:
                if "error" in answer:
                    raise RuntimeError(answer["error"])
                return answer["result"]

    def read(self, n):
        data = b""
        while len(data) < n:
            chunk = self.p.stdout.read(n - len(data))
            if not chunk:
                raise RuntimeError("the engine ended")
            data += chunk
        return data

    def close(self):
        try:
            self.request("shutdown")
        finally:
            self.p.stdin.close()
            self.p.wait(timeout=60)


def answers(engine, path, spec, depth=4, limit=4000):
    """Everything the view can ask about the tree `spec` makes of the trace's
    first `depth` levels: the tree, each node's children, each hot path."""
    opened = engine.request("open", {"path": path})
    trace = opened["trace"]
    tree = engine.request("tree.create", dict(spec, trace=trace))
    view = tree["view"]
    children, hot = {}, {}
    queue = [(tree["root"]["id"], 0)]
    while queue and len(children) < limit:
        node, d = queue.pop(0)
        rows = engine.request("tree.children", {"trace": trace, "view": view, "node": node})["rows"]
        children[node] = {"rows": rows}
        hot[node] = engine.request("tree.hotPath", {"trace": trace, "view": view, "node": node, "fraction": 0.1})
        if d + 1 < depth:
            queue.extend((r["id"], d + 1) for r in rows if r["hasChildren"])
    # The rows along each first-level hot path, which the view expands.
    for top in children[tree["root"]["id"]]["rows"]:
        for r in hot.get(top["id"], {"rows": []})["rows"]:
            if r["id"] not in children:
                children[r["id"]] = {"rows": engine.request("tree.children", {"trace": trace, "view": view, "node": r["id"]})["rows"]}
    graph = engine.request("graph", {"trace": trace, "buckets": 1000, "top": 8})
    processes = engine.request("processes", {"trace": trace})
    threads = {str(p["index"]): engine.request("threads", {"trace": trace, "process": p["index"]}) for p in processes["rows"]}
    # (The view's view IDs: its first tree is view 1 of its own.)
    tree = dict(tree, view=1)
    return {"opened": opened, "tree": tree, "children": children, "hot": hot, "graph": graph, "processes": processes, "threads": threads}


STUB = """
window.__posted = [];
window.acquireVsCodeApi = function () {
  var A = ANSWERS;
  function answer(m) {
    var r = { type: "response", id: m.id };
    if (m.method === "tree.create") r.result = A.tree;
    else if (m.method === "tree.children" && A.children[m.params.node]) r.result = A.children[m.params.node];
    else if (m.method === "tree.hotPath" && A.hot[m.params.node]) r.result = A.hot[m.params.node];
    else if (m.method === "tree.close") r.result = {};
    else if (m.method === "graph") r.result = A.graph;
    else if (m.method === "processes") r.result = A.processes;
    else if (m.method === "threads" && A.threads[m.params.process]) r.result = A.threads[m.params.process];
    else r.error = m.method + ": no answer for " + JSON.stringify(m.params);
    setTimeout(function () { window.postMessage(r, "*"); }, 0);
  }
  return {
    postMessage: function (m) {
      window.__posted.push(m);
      document.getElementById("posted").textContent = JSON.stringify(window.__posted);
      if (m.type === "ready") {
        setTimeout(function () {
          window.postMessage({ type: "opened", summary: A.opened.summary, opened: A.opened.opened }, "*");
        }, 0);
      } else if (m.type === "request") {
        answer(m);
      }
    },
    getState: function () { return null; },
    setState: function () {},
  };
};
"""


def page(data, then=""):
    def read(name):
        with open(os.path.join(MEDIA, name), encoding="utf-8") as f:
            return f.read()

    body = read_body()
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><style>{THEME}{read("tree-view.css")}</style></head><body>
{body}<pre id="posted" style="display:none"></pre>
<script>var ANSWERS = {json.dumps(data)};{STUB}</script>
<script>{read("tree-model.js")}</script>
<script>{read("graph.js")}</script>
<script>{read("tree-view.js")}</script>
<script>setTimeout(function () {{ {then} }}, 300);</script>
</body></html>"""


def read_body():
    """The view page's body, as the extension writes it (without scripts)."""
    with open(os.path.join(os.path.dirname(HERE), "extension.js"), encoding="utf-8") as f:
        text = f.read()
    m = re.search(r"<body>\n(.*?)<script", text, re.S)
    return m.group(1)


def render(data, then="", shot=None):
    """The page's DOM after `then` runs (and a screenshot, if asked).

    The page is served from a local server, and posts its DOM back to it
    when it is done: Edge's `--dump-dom` prints nothing in some builds."""
    import http.server
    import threading

    got = {}
    done = threading.Event()
    text = page(data, then + " setTimeout(function () { fetch('/dom', {method: 'POST', body: document.documentElement.outerHTML}); }, 500);")

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = text.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            n = int(self.headers.get("Content-Length", "0"))
            got["dom"] = self.rfile.read(n).decode("utf-8")
            self.send_response(204)
            self.end_headers()
            done.set()

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    # (Edge's profile can stay locked a moment after it exits.)
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
        # (A profile of its own: otherwise a running Edge takes the command
        # over, and nothing comes back.)
        common = [EDGE, "--headless", "--disable-gpu", "--hide-scrollbars", "--window-size=1200,700", "--no-first-run"]
        profile = lambda name: f"--user-data-dir={os.path.join(d, name)}"
        if shot:
            subprocess.run(common + [profile("shot"), "--virtual-time-budget=5000", f"--screenshot={shot}", url], capture_output=True, timeout=120)
        browser = subprocess.Popen(common + [profile("dom"), url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            done.wait(60)
        finally:
            browser.kill()
            browser.wait()
            server.shutdown()
    return got.get("dom", "")


def rows(dom):
    """The drawn rows: (index, label, weight, share, self)."""
    out = []
    for m in re.finditer(r'<div class="row[^"]*" data-index="(\d+)".*?</div>', dom, re.S):
        cells = re.findall(r'<span class="num">([^<]*)</span>', m.group(0))
        label = re.search(r'</span>([^<]*)</span>', m.group(0)).group(1)
        out.append((int(m.group(1)), html.unescape(label), *cells))
    return out


def main():
    exe = os.path.abspath(sys.argv[1])
    shots = sys.argv[2] if len(sys.argv) > 2 else None
    shot = (lambda name: os.path.join(shots, name + ".png")) if shots else (lambda name: None)
    with tempfile.TemporaryDirectory() as d:
        etl, truth_path = os.path.join(d, "t.etl"), os.path.join(d, "t.json")
        subprocess.run([exe, "synth", etl, "-duration-ms", "500", "-truth", truth_path], check=True, capture_output=True)
        with open(truth_path, encoding="utf-8") as f:
            truth = json.load(f)
        engine = Engine(exe)
        try:
            spec = {"source": "samples", "groupBy": ["process"], "frames": "function", "invert": False}
            data = answers(engine, etl, spec)
        finally:
            engine.close()

    # Opened: the summary, and the processes heaviest first.
    dom = render(data, shot=shot("opened"))
    assert f"{truth['samples']:,} samples" in dom, "the summary: " + dom[:800]
    drawn = rows(dom)
    procs = sorted((p for p in truth["processes"] if p["samples"]), key=lambda p: -p["samples"])
    labels = [r[1] for r in drawn]
    for p in procs:
        assert f"{p['name']} ({p['pid']})" in labels, p["name"]
    weights = [int(r[2].replace(",", "")) for r in drawn]
    assert weights == sorted(weights, reverse=True), "heaviest first"
    assert sum(weights) == truth["samples"], "the processes add up to every sample"
    assert 'class="row selected" data-index="0"' in dom, "the first row selected"

    # The heaviest process that isn't Idle: its row, reached by the keys.
    top = data["children"][data["tree"]["root"]["id"]]["rows"]
    at = next(i for i, r in enumerate(top) if not r["label"].startswith("Idle"))
    down = "var v = document.getElementById('viewport'); v.focus();" + (
        " v.dispatchEvent(new KeyboardEvent('keydown', {key: 'ArrowDown'}));" * at
    )
    key = lambda k: f" v.dispatchEvent(new KeyboardEvent('keydown', {{key: '{k}'}}));"

    # Expanding it (Enter): its children under it, one level in.
    first_children = data["children"][top[at]["id"]]["rows"]
    dom = render(data, down + key("Enter"), shot=shot("expanded"))
    drawn2 = rows(dom)
    assert len(drawn2) == len(drawn) + len(first_children), f"{len(drawn2)} rows after expanding"
    assert drawn2[at + 1][1] == first_children[0]["label"], "the first child under its parent"
    assert f'class="row selected" data-index="{at}"' in dom, "the process still selected"

    # Collapsing it again (ArrowLeft), and the arrow keys' bounds.
    dom = render(data, down + key("Enter") + key("ArrowLeft") + key("End") + key("ArrowDown"))
    assert len(rows(dom)) == len(drawn), "collapsed again"
    assert f'class="row selected" data-index="{len(drawn) - 1}"' in dom, "End, and no further"

    # The hot path (*): every row of it drawn, each a level deeper than the
    # last, and the last selected.
    hot = data["hot"][top[at]["id"]]["rows"]
    assert len(hot) > 3, "a deep hot path to show"
    dom = render(data, down + key("*"), shot=shot("hot"))
    drawn3 = rows(dom)
    labels3 = [r[1] for r in drawn3]
    # (Each row the next one down: names repeat, as a module calls back.)
    last = at
    for h in hot:
        assert h["label"] in labels3[last + 1 :], f"hot path row {h['label']}"
        last = labels3.index(h["label"], last + 1)
    depths = re.findall(r"padding-left:(\d+)px", dom)
    assert len(set(depths)) >= len(hot), "a level per hot path row"
    assert f'class="row selected" data-index="{last}"' in dom, "the hot path's end selected"

    # Another tree: by module, inverted (asked of the engine again, by the
    # view, when the settings change): the answers come for the new tree.
    dom = render(
        data,
        "var f = document.getElementById('frames'); f.value = 'module'; f.dispatchEvent(new Event('change'));",
    )
    assert rows(dom), "the new tree's rows"
    posted = json.loads(html.unescape(re.search(r'<pre id="posted"[^>]*>(.*?)</pre>', dom, re.S).group(1)))
    creates = [m for m in posted if m.get("method") == "tree.create"]
    assert len(creates) == 2 and creates[1]["params"]["frames"] == "module", "a second tree, by module"
    assert any(m.get("method") == "tree.close" for m in posted), "the first tree closed"
    # Dragging across the graph: a time range, and a tree of it.
    drag = (
        "var c = document.getElementById('graph'); var r = c.getBoundingClientRect();"
        " function at(type, f) { c.dispatchEvent(new MouseEvent(type, {bubbles: true,"
        " clientX: r.left + 40 + f * (r.width - 40), clientY: r.top + 40})); }"
        " at('mousedown', 0.25); at('mousemove', 0.5); at('mouseup', 0.5);"
    )
    dom = render(data, drag, shot=shot("selected"))
    posted = json.loads(html.unescape(re.search(r'<pre id="posted"[^>]*>(.*?)</pre>', dom, re.S).group(1)))
    timed = [m for m in posted if m.get("method") == "tree.create" and "time" in m["params"]]
    assert timed, "a tree of the selected range"
    start, end = timed[-1]["params"]["time"]
    span = data["graph"]["endNs"] - data["graph"]["startNs"]
    assert abs((start - data["graph"]["startNs"]) / span - 0.25) < 0.02, "the range's start"
    assert abs((end - data["graph"]["startNs"]) / span - 0.5) < 0.02, "the range's end"
    assert "Selected " in dom, "the selection described"
    # Double-clicking clears it: a tree of all of it again.
    dom = render(data, drag + " c.dispatchEvent(new MouseEvent('dblclick', {bubbles: true}));")
    posted = json.loads(html.unescape(re.search(r'<pre id="posted"[^>]*>(.*?)</pre>', dom, re.S).group(1)))
    creates = [m for m in posted if m.get("method") == "tree.create"]
    assert "time" not in creates[-1]["params"], "all of it again"
    assert "All of the trace" in dom
    # The processes tab: every process, heaviest first; sorted by name when
    # its heading is clicked.
    dom = render(data, "document.getElementById('tab-processes').click();", shot=shot("processes"))
    assert 'id="stacks-pane" class="pane hidden"' in dom, "the stacks hidden"
    names = re.findall(r'<tr data-i="\d+"><td class="">([^<]*)</td>', dom)
    assert len(names) == len(data["processes"]["rows"]), f"{len(names)} process rows"
    assert names[0] == data["processes"]["rows"][0]["name"], "heaviest first"
    dom = render(data, "document.getElementById('tab-processes').click(); document.querySelector('th[data-key=name]').click();")
    names = [html.unescape(n) for n in re.findall(r'<tr data-i="\d+"><td class="">([^<]*)</td>', dom)]
    assert names == sorted(names, key=str.lower) or names == sorted(names), f"by name: {names}"
    # Clicking the heaviest process: it is picked, and its threads show
    # under it, heaviest first.
    first = data["processes"]["rows"][0]
    want = data["threads"][str(first["index"])]["rows"]
    dom = render(
        data,
        "document.getElementById('tab-processes').click(); document.querySelector('#processes tbody tr').click();",
        shot=shot("threads"),
    )
    assert f"Threads of {html.escape(first['name'])} ({first['pid']})" in dom, "the threads' title"
    assert '<tr data-i="0" class="selected">' in dom, "the process picked"
    table = dom[dom.index('id="threads"'):]
    tids = re.findall(r'<tr data-i="\d+"><td class="num">(\d+)</td>', table)
    assert len(want) == first["threads"] and len(tids) == len(want), f"{len(tids)} thread rows, {len(want)} threads"
    assert tids == [str(t["tid"]) for t in want], "heaviest first"
    print("harness: ok")


if __name__ == "__main__":
    main()
