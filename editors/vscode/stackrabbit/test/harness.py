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
    functions = engine.request("functions", {"trace": trace, "source": "samples", "frames": "function"})
    lit = engine.request("graph", {"trace": trace, "buckets": 1000, "top": 8, "highlight": functions["functions"][1]["fn"]})
    symbols = engine.request("symbols", {"trace": trace, "wait": True})
    events = engine.request("events", {"trace": trace})
    top_kind = events["rows"][0]
    event_list = engine.request("events.list", {"trace": trace, "guid": top_kind["guid"], "id": top_kind["id"], "version": top_kind["version"], "opcode": top_kind["opcode"], "limit": 1000, "stacks": True})
    perf_info = next(k for k in events["rows"] if k["event"] == "SampleProf")
    sample_list = engine.request("events.list", {"trace": trace, "guid": perf_info["guid"], "id": perf_info["id"], "version": perf_info["version"], "opcode": perf_info["opcode"], "limit": 1000, "stacks": True})
    # A function's callers, and their hot path (for the hover card).
    heavy = functions["functions"][0]
    focus_tree = engine.request("tree.create", {"trace": trace, "focus": heavy["fn"], "invert": True, "groupBy": []})
    focus_hot = engine.request("tree.hotPath", {"trace": trace, "view": focus_tree["view"], "node": focus_tree["root"]["id"], "fraction": 0})
    focus_tree = dict(focus_tree, view=99)
    # (The view's view IDs: its first tree is view 1 of its own.)
    tree = dict(tree, view=1)
    return {"opened": opened, "tree": tree, "children": children, "hot": hot, "graph": graph, "processes": processes, "threads": threads, "functions": functions, "lit": lit, "symbols": symbols, "focusTree": focus_tree, "focusHot": focus_hot, "events": events, "eventList": event_list, "sampleList": sample_list, "sampleKind": perf_info}


STUB = """
window.__posted = [];
window.acquireVsCodeApi = function () {
  var A = ANSWERS;
  function answer(m) {
    var r = { type: "response", id: m.id };
    if (m.method === "tree.create" && m.params.focus && A.focusTree) r.result = A.focusTree;
    else if (m.method === "tree.create") r.result = A.tree;
    else if (m.method === "tree.hotPath" && A.focusTree && m.params.view === A.focusTree.view) r.result = A.focusHot;
    else if (m.method === "tree.children" && A.children[m.params.node]) r.result = A.children[m.params.node];
    else if (m.method === "tree.hotPath" && A.hot[m.params.node]) r.result = A.hot[m.params.node];
    else if (m.method === "tree.close") r.result = {};
    else if (m.method === "graph") r.result = m.params.highlight ? A.lit : A.graph;
    else if (m.method === "processes") r.result = A.processes;
    else if (m.method === "functions") r.result = A.functions;
    else if (m.method === "events") r.result = A.events;
    else if (m.method === "regions" && A.regions) r.result = A.regions;
    else if (m.method === "disk" && A.disk) r.result = A.disk;
    else if (m.method === "fileio" && A.fileio) r.result = A.fileio;
    else if (m.method === "dpc" && A.dpc) r.result = A.dpc;
    else if (m.method === "registry" && A.registry) r.result = A.registry;
    else if (m.method === "hardfaults" && A.hardfaults) r.result = A.hardfaults;
    else if (m.method === "vmem" && A.vmem) r.result = A.vmem;
    else if (m.method === "heap" && A.heap) r.result = A.heap;
    else if (m.method === "pool" && A.pool) r.result = A.pool;
    else if (m.method === "regions") r.error = "regions: file: expected a regions file";
    else if (m.method === "events.list" && A.sampleKind && m.params.opcode === A.sampleKind.opcode && m.params.guid === A.sampleKind.guid) r.result = A.sampleList;
    else if (m.method === "events.list") r.result = A.eventList;
    else if (m.method === "symbols") r.result = A.symbols;
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
          window.postMessage({ type: "opened", summary: A.opened.summary, opened: A.opened.opened, state: A.state }, "*");
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


def render(data, then="", shot=None, wait=500):
    """The page's DOM after `then` runs (and a screenshot, if asked).

    The page is served from a local server, and posts its DOM back to it
    when it is done: Edge's `--dump-dom` prints nothing in some builds."""
    import http.server
    import threading

    got = {}
    done = threading.Event()
    text = page(data, then + " setTimeout(function () { fetch('/dom', {method: 'POST', body: document.documentElement.outerHTML}); }, " + str(wait) + ");")

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
            # (Its helpers too, once it has written the screenshot.)
            shooter = in_job(
                subprocess.Popen(
                    common + [profile("shot"), "--virtual-time-budget=5000", f"--screenshot={shot}", url],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            )
            try:
                shooter.wait(120)
            except subprocess.TimeoutExpired:
                pass
            end_tree(shooter)
        browser = in_job(subprocess.Popen(common + [profile("dom"), url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        try:
            done.wait(60)
        finally:
            end_tree(browser)
            server.shutdown()
    return got.get("dom", "")


def end_tree(p):
    """Ends `p` and every process it started. (Edge starts renderer, GPU
    and utility processes that outlive their parent if only it is killed:
    a run of the harness used to leave dozens behind, and a night of runs
    thousands, until the machine ran out of memory.) On Windows, `p` is in
    a job (see `in_job`) whose processes all end with it."""
    job = getattr(p, "job", None)
    if job is not None:
        kernel32 = _kernel32()
        kernel32.TerminateJobObject(job, 1)
        kernel32.CloseHandle(job)
        p.job = None
    else:
        p.kill()
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait()


def _kernel32():
    import ctypes
    from ctypes import wintypes

    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateJobObjectW.restype = wintypes.HANDLE
    k.OpenProcess.restype = wintypes.HANDLE
    k.GetCurrentProcess.restype = wintypes.HANDLE
    k.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    k.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    k.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    return k


def _kill_on_close_job():
    """A new Windows job that ends every process in it when its last
    handle closes; None if it can't be made."""
    import ctypes
    from ctypes import wintypes

    class BASIC(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class IO(ctypes.Structure):
        _fields_ = [(n, ctypes.c_uint64) for n in ("r", "w", "o", "rb", "wb", "ob")]

    class EXTENDED(ctypes.Structure):
        _fields_ = [
            ("Basic", BASIC),
            ("Io", IO),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = _kernel32()
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        return None
    info = EXTENDED()
    info.Basic.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    # (9: JobObjectExtendedLimitInformation.)
    if not kernel32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)):
        kernel32.CloseHandle(job)
        return None
    return job


# The harness's own job (see `hold_children`): kept open while it runs.
_JOB = None


def hold_children():
    """Puts the harness in a Windows job that ends every process in it when
    the harness exits (the job's handle closes), so that nothing it starts
    outlives it, whatever `end_tree` misses. Elsewhere, nothing."""
    global _JOB
    if os.name != "nt" or _JOB is not None:
        return
    job = _kill_on_close_job()
    if job is None:
        return
    kernel32 = _kernel32()
    if kernel32.AssignProcessToJobObject(job, kernel32.GetCurrentProcess()):
        _JOB = job
    else:
        kernel32.CloseHandle(job)


def in_job(p):
    """Puts `p` (just started) in a Windows job of its own, so that
    `end_tree` ends what it starts too. Elsewhere, nothing."""
    p.job = None
    if os.name != "nt":
        return p
    job = _kill_on_close_job()
    if job is None:
        return p
    kernel32 = _kernel32()
    process = kernel32.OpenProcess(0x0001 | 0x0100, False, p.pid)  # (Terminate, set quota.)
    if process and kernel32.AssignProcessToJobObject(job, process):
        p.job = job
    else:
        kernel32.CloseHandle(job)
    if process:
        kernel32.CloseHandle(process)
    return p


def rows(dom):
    """The drawn rows: (index, label, weight, share, self)."""
    out = []
    for m in re.finditer(r'<div class="row[^"]*" data-index="(\d+)".*?</div>', dom, re.S):
        cells = re.findall(r'<span class="num">([^<]*)</span>', m.group(0))
        label = re.search(r'</span>([^<]*)</span>', m.group(0)).group(1)
        out.append((int(m.group(1)), html.unescape(label), *cells))
    return out


def main():
    # Everything the harness starts (Edge, and what Edge starts) ends when
    # it does, however it ends.
    hold_children()
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
    # The functions tab: every function, heaviest self first, with shares;
    # then the modules.
    dom = render(data, "document.getElementById('tab-functions').click();", shot=shot("functions"))
    assert 'id="functions-pane" class="pane"' in dom, "the functions shown"
    f = data["functions"]
    assert f"{f['functionCount']:,} functions" in dom, "the functions' title"
    table = dom[dom.index('id="functions"'):dom.index('id="modules"')]
    labels = [html.unescape(x) for x in re.findall(r'<tr data-i="\d+"><td class="">([^<]*)</td>', table)]
    assert labels == [r["label"] for r in f["functions"]], "every function, heaviest self first"
    heaviest = f["functions"][0]
    share = f"{100 * heaviest['exclusive'] / f['total']:.1f}%"
    assert share in table, f"the top function's share {share}"
    modules = dom[dom.index('id="modules"'):dom.index('id="processes-pane"')]
    names = [html.unescape(x) for x in re.findall(r'<tr data-i="\d+"><td class="">([^<]*)</td>', modules)]
    assert names == [m["label"] for m in f["modules"]], "every module"
    # Copy: the functions tab's tables as Markdown, to the extension.
    dom = render(data, "document.getElementById('tab-functions').click(); setTimeout(function () { document.getElementById('copy').click(); }, 50);")
    posted = json.loads(html.unescape(re.search(r'<pre id="posted"[^>]*>(.*?)</pre>', dom, re.S).group(1)))
    copies = [m for m in posted if m.get("type") == "copy"]
    assert copies, "a copy message"
    md = copies[-1]["text"]
    assert md.startswith("| Function | Module | Self | Self % | Inclusive | Inclusive % |\n| --- | --- | ---: | ---: | ---: | ---: |\n"), md[:200]
    assert f"| {f['functions'][0]['label']} | {f['functions'][0]['module']} | {f['functions'][0]['exclusive']:,} |" in md, "the heaviest function's row"
    assert "\n| Module | Self |" in md, "then the modules"
    # In the stacks: the selected row (the first) and the rows open under
    # it, indented.
    dom = render(data, down + key("Enter") + " setTimeout(function () { document.getElementById('copy').click(); }, 50);")
    posted = json.loads(html.unescape(re.search(r'<pre id="posted"[^>]*>(.*?)</pre>', dom, re.S).group(1)))
    md = [m for m in posted if m.get("type") == "copy"][-1]["text"]
    lines = md.strip().split("\n")
    assert lines[0] == "| Stack | Weight | % | Self |", lines[0]
    assert lines[2].startswith(f"| {top[at]['label']} |"), lines[2]
    assert len(lines) == 3 + len(first_children), f"{len(lines)} lines"
    assert lines[3].startswith("|  " + first_children[0]["label"]), lines[3]
    # Highlighting a function (the second heaviest: clicking its row): the
    # graph is asked for it, and its line's key names it; again, and not.
    second = f["functions"][1]
    click = "document.getElementById('tab-functions').click(); setTimeout(function () { document.querySelector('#functions tbody tr[data-i=\"1\"]').click(); }, 50);"
    dom = render(data, click, shot=shot("highlight"))
    posted = json.loads(html.unescape(re.search(r'<pre id="posted"[^>]*>(.*?)</pre>', dom, re.S).group(1)))
    graphs = [m for m in posted if m.get("method") == "graph"]
    assert graphs[-1]["params"].get("highlight") == second["fn"], graphs[-1]
    legend = lambda dom: dom[dom.index('id="legend"'):dom.index("</div>", dom.index('id="legend"'))]
    assert 'class="key lit"' in legend(dom) and html.escape(second["label"]) in legend(dom), "the highlight's key"
    assert '<tr data-i="1" class="selected">' in dom, "the function picked"
    again = click + " setTimeout(function () { document.querySelector('#functions tbody tr[data-i=\"1\"]').click(); }, 300);"
    dom = render(data, again)
    posted = json.loads(html.unescape(re.search(r'<pre id="posted"[^>]*>(.*?)</pre>', dom, re.S).group(1)))
    graphs = [m for m in posted if m.get("method") == "graph"]
    assert "highlight" not in graphs[-1]["params"], "clicked again: no highlight"
    assert 'class="key lit"' not in legend(dom), "no highlight's key"
    # The symbols tab: every PDB the stacks need, most frames first, and
    # what became of each (the synthetic machine's: not found).
    sy = data["symbols"]
    assert sy["ready"] and sy["rows"], sy
    dom = render(data, "document.getElementById('tab-symbols').click();", shot=shot("symbols"))
    table = dom[dom.index('id="symbols-table"'):dom.index('id="no-debug-title"')]
    pdbs = [html.unescape(x) for x in re.findall(r'<tr data-i="\d+"><td class="">([^<]*)</td>', table)]
    assert pdbs == [r["pdb"] for r in sy["rows"]], pdbs
    assert f"{len(sy['rows'])} PDBs: 0 with names" in dom, "the symbols' title"
    assert "not found" in table
    # A recording that lost events says so; one that didn't, doesn't.
    assert '<div id="lost" class="lost"></div>' in render(data), "nothing lost: no warning"
    lossy = json.loads(json.dumps(data))
    lossy["opened"]["summary"]["eventsLost"] = 1234
    lossy["opened"]["summary"]["buffersLost"] = 2
    dom = render(lossy)
    assert "The recording lost 1,234 events and 2 buffers" in dom, "the warning"
    # Reopened where it was left: the settings, tab and time selection
    # the extension kept, put back before the first tree is asked for.
    left = json.loads(json.dumps(data))
    left["state"] = {"source": "running", "group": "thread", "frames": "module", "invert": True,
                     "tab": "functions", "selection": [100000000, 200000000], "lit": None}
    dom = render(left)
    posted = json.loads(html.unescape(re.search(r'<pre id="posted"[^>]*>(.*?)</pre>', dom, re.S).group(1)))
    first = next(m for m in posted if m.get("method") == "tree.create")["params"]
    assert first == {"source": "running", "groupBy": ["thread"], "frames": "module", "invert": True,
                     "time": [100000000, 200000000]}, first
    assert 'id="functions-pane" class="pane"' in dom, "the tab it was left on"
    assert "Selected 0.100 s to 0.200 s" in dom, "the time it was left on"
    assert any(m.get("method") == "functions" and m["params"].get("time") == [100000000, 200000000] for m in posted)
    # Nonsense kept from before is ignored.
    odd = json.loads(json.dumps(data))
    odd["state"] = {"source": "bogus", "tab": "nowhere", "selection": ["a", 1]}
    dom = render(odd)
    posted = json.loads(html.unescape(re.search(r'<pre id="posted"[^>]*>(.*?)</pre>', dom, re.S).group(1)))
    first = next(m for m in posted if m.get("method") == "tree.create")["params"]
    assert first["source"] == "samples" and "time" not in first, first
    # Changing a setting says so, for the extension to keep.
    change = "var c = document.getElementById('source'); c.value = 'waits'; c.dispatchEvent(new Event('change'));"
    dom = render(data, change)
    posted = json.loads(html.unescape(re.search(r'<pre id="posted"[^>]*>(.*?)</pre>', dom, re.S).group(1)))
    states = [m["state"] for m in posted if m.get("type") == "state"]
    assert states and states[-1]["source"] == "waits" and states[-1]["tab"] == "stacks", states
    # The graph by thread; then the picked process's threads.
    pick = "var g = document.getElementById('graph-by'); g.value = 'thread'; g.dispatchEvent(new Event('change'));"
    dom = render(data, pick)
    posted = json.loads(html.unescape(re.search(r'<pre id="posted"[^>]*>(.*?)</pre>', dom, re.S).group(1)))
    graphs = [m["params"] for m in posted if m.get("method") == "graph"]
    assert graphs[-1].get("by") == "thread" and "process" not in graphs[-1], graphs[-1]
    heaviest = data["processes"]["rows"][0]
    picked = ("document.getElementById('tab-processes').click();"
              "var g = document.getElementById('graph-by'); g.value = 'picked'; g.dispatchEvent(new Event('change'));"
              "setTimeout(function () { document.querySelector('#processes tbody tr').click(); }, 50);")
    dom = render(data, picked)
    posted = json.loads(html.unescape(re.search(r'<pre id="posted"[^>]*>(.*?)</pre>', dom, re.S).group(1)))
    graphs = [m["params"] for m in posted if m.get("method") == "graph"]
    assert "by" not in graphs[-2], "nothing picked yet: by process"
    assert graphs[-1].get("by") == "thread" and graphs[-1].get("process") == heaviest["index"], graphs[-1]
    states = [m["state"] for m in posted if m.get("type") == "state"]
    assert states[-1]["graphBy"] == "picked", states[-1]
    # Hovering the graph: a tip with the time and the busiest series
    # there; leaving it, none.
    move = ("var c = document.getElementById('graph'); var r = c.getBoundingClientRect();"
            "c.dispatchEvent(new MouseEvent('mousemove', {clientX: r.left + r.width / 2, clientY: r.top + 40, bubbles: true}));")
    dom = render(data, move, shot=shot("hover"))
    tip = re.search(r'<div id="graph-tip" class="([^"]*)"[^>]*>(.*?)</div></div>', dom, re.S)
    assert tip and "hidden" not in tip.group(1), "the tip shows"
    assert "% busy" in tip.group(2), tip.group(2)[:300]
    labels = [html.escape(x["label"]) for x in data["graph"]["series"]]
    assert any(l in tip.group(2) for l in labels), "a series in it"
    dom = render(data, move + " c.dispatchEvent(new MouseEvent('mouseleave'));")
    tip = re.search(r'<div id="graph-tip" class="([^"]*)"', dom)
    assert "hidden" in tip.group(1), "gone when the mouse leaves"
    # Double-clicking a function: the stacks, of its callers.
    heavy = f["functions"][0]
    dbl = ("document.getElementById('tab-functions').click();"
           "setTimeout(function () { document.querySelector('#functions tbody tr').dispatchEvent(new MouseEvent('dblclick', {bubbles: true})); }, 50);")
    dom = render(data, dbl, shot=shot("callers"))
    posted = json.loads(html.unescape(re.search(r'<pre id="posted"[^>]*>(.*?)</pre>', dom, re.S).group(1)))
    trees = [m["params"] for m in posted if m.get("method") == "tree.create"]
    assert trees[-1].get("focus") == heavy["fn"] and trees[-1]["invert"] is True, trees[-1]
    assert 'id="stacks-pane" class="pane"' in dom, "the stacks shown"
    assert 'id="focus-bar" class="focus-bar"' in dom and f"Callers of {html.escape(heavy['label'])}" in dom, "the focus bar"
    # Hovering a function: its hottest call path, in a card.
    hover = ("document.getElementById('tab-functions').click();"
             "setTimeout(function () { document.querySelector('#functions tbody td').dispatchEvent(new MouseEvent('mouseover', {bubbles: true})); }, 50);")
    dom = render(data, hover, shot=shot("card"), wait=1000)
    card = re.search(r'<div id="card" class="([^"]*)"[^>]*>(.*?)<div id="functions-title"', dom, re.S)
    assert card and "hidden" not in card.group(1), "the card shows"
    path = [html.unescape(x) for x in re.findall(r'<div class="step">(?:← )?([^<]*) <b>', card.group(2))]
    assert path == [r["label"] for r in data["focusHot"]["rows"]], (path, data["focusHot"]["rows"])
    # The events tab: every kind, most numerous first, and how many in all.
    dom = render(data, "document.getElementById('tab-events').click();", shot=shot("events"))
    kinds = data["events"]["rows"]
    total = sum(r["count"] for r in kinds)
    assert f"{total:,} events of {len(kinds):,} kinds" in dom, "the events' title"
    table = dom[dom.index('id="events"'):dom.index('id="processes-pane"')]
    counts = [int(x.replace(",", "")) for x in re.findall(r'<tr data-i="\d+">(?:<td[^>]*>[^<]*</td>){5}<td class="num">([^<]*)</td>', table)]
    assert counts == [r["count"] for r in kinds], counts[:5]
    # Clicking the most numerous kind: its events listed, a column for
    # each field.
    click = ("document.getElementById('tab-events').click();"
             "setTimeout(function () { document.querySelector('#events tbody tr').click(); }, 50);")
    dom = render(data, click, shot=shot("event-list"))
    posted = json.loads(html.unescape(re.search(r'<pre id="posted"[^>]*>(.*?)</pre>', dom, re.S).group(1)))
    asked = [m["params"] for m in posted if m.get("method") == "events.list"]
    top_kind = data["events"]["rows"][0]
    assert asked and asked[-1]["guid"] == top_kind["guid"] and asked[-1]["opcode"] == top_kind["opcode"], asked
    el = data["eventList"]
    assert f"{el['total']:,} events" in dom, "the list's title"
    table = dom[dom.index('id="event-list"'):]
    heads = re.findall(r'<th[^>]*data-key="f\d+"[^>]*>([^<▾▴]*)', table)
    assert [h.strip() for h in heads] == el["columns"], (heads, el["columns"])
    n = len(re.findall(r'<tr data-i="\d+"', table[:table.index("</table>")]))
    assert n == len(el["rows"]), f"{n} rows"
    # The samples listed, with their stacks; clicking one shows its stack.
    sl = data["sampleList"]
    first_with = next(i for i, x in enumerate(sl["rows"]) if x["stack"])
    sample_row = [k["event"] for k in data["events"]["rows"]].index("SampleProf")
    click = ("document.getElementById('tab-events').click();"
             f"setTimeout(function () {{ document.querySelectorAll('#events tbody tr')[{sample_row}].click(); }}, 50);"
             f"setTimeout(function () {{ document.querySelector('#event-list tbody tr[data-i=\"{first_with}\"]').click(); }}, 300);")
    dom = render(data, click, wait=800)
    m = re.search(r'<div id="event-stack" class="event-stack">(.*?)</div>', dom, re.S)
    assert m, "the stack pane"
    shown = html.unescape(m.group(1)).split("\n")
    assert shown[0] == "Stack (innermost first):" and shown[1:] == sl["rows"][first_with]["stack"], shown[:3]
    assert 'data-key="frames"' in dom, "a column of stack depths"
    # Regions: none without a file (a note about the setting); with one,
    # its regions and instances, and clicking one selects its time.
    dom = render(data, "document.getElementById('tab-regions').click();")
    assert "Set stackrabbit.regionsFile" in dom, "the setting's note"
    regioned = json.loads(json.dumps(data))
    regioned["regions"] = {
        "regions": [
            {"name": "Root", "displayName": "Root", "parent": None, "unsupported": None, "count": 1, "totalNs": 200000000, "unpairedStarts": 0, "unpairedStops": 0},
            {"name": "Work", "displayName": "Work items", "parent": 0, "unsupported": None, "count": 2, "totalNs": 150000000, "unpairedStarts": 1, "unpairedStops": 0},
        ],
        "instances": [
            {"region": 0, "name": None, "startNs": 100000000, "stopNs": 300000000, "durationNs": 200000000, "pid": None, "tid": None},
            {"region": 1, "name": "a", "startNs": 100000000, "stopNs": 200000000, "durationNs": 100000000, "pid": 4, "tid": 10},
            {"region": 1, "name": "b", "startNs": 250000000, "stopNs": 300000000, "durationNs": 50000000, "pid": 4, "tid": 11},
        ],
        "truncated": False,
    }
    click = ("document.getElementById('tab-regions').click();"
             "setTimeout(function () { document.querySelector('#region-instances tbody tr[data-i=\"1\"]').click(); }, 100);")
    dom = render(regioned, click, shot=shot("regions"))
    assert "Root / Work items" in dom, "the region's path"
    assert "3 instances" in dom
    posted = json.loads(html.unescape(re.search(r'<pre id="posted"[^>]*>(.*?)</pre>', dom, re.S).group(1)))
    trees = [m["params"] for m in posted if m.get("method") == "tree.create"]
    assert trees[-1].get("time") == [100000000, 200000000], trees[-1]
    assert "Selected 0.100 s to 0.200 s" in dom
    # The disk tab: totals by the grouping chosen, and the heaviest I/Os;
    # changing the grouping asks again.
    disked = json.loads(json.dumps(data))
    disked["disk"] = {
        "count": 3, "bytes": 12288,
        "groups": [{"label": "app.exe (100)", "count": 2, "bytes": 8192, "ioNs": 3000000, "serviceNs": 2500000},
                   {"label": "System (4)", "count": 1, "bytes": 4096, "ioNs": 1000000, "serviceNs": 1000000}],
        "ios": [{"kind": "Read", "process": "app.exe (100)", "tid": 7, "file": "C:\\a.txt", "disk": 0, "size": 4096, "completeNs": 3000000, "ioNs": 2000000, "serviceNs": 2000000}],
    }
    change = ("document.getElementById('tab-disk').click();"
              "setTimeout(function () { var b = document.getElementById('disk-by'); b.value = 'file'; b.dispatchEvent(new Event('change')); }, 100);")
    dom = render(disked, change, shot=shot("disk"))
    assert "3 disk I/Os, 12 KB." in dom, "the disk title"
    posted = json.loads(html.unescape(re.search(r'<pre id="posted"[^>]*>(.*?)</pre>', dom, re.S).group(1)))
    asked = [m["params"]["by"] for m in posted if m.get("method") == "disk"]
    assert asked == ["process", "file"], asked
    table = dom[dom.index('id="disk-groups"'):dom.index('id="disk-ios"')]
    labels = [html.unescape(x) for x in re.findall(r'<tr data-i="\d+"><td class="">([^<]*)</td>', table)]
    assert labels == ["app.exe (100)", "System (4)"], labels
    assert "C:\\a.txt" in html.unescape(dom[dom.index('id="disk-ios"'):])
    # The file I/O tab: totals by the grouping chosen, and the longest
    # operations; changing the grouping asks again.
    filed = json.loads(json.dumps(data))
    filed["fileio"] = {
        "count": 3, "unended": 1, "bytes": 8192,
        "groups": [{"label": "app.exe (100)", "count": 2, "bytes": 8192, "durationNs": 3000000},
                   {"label": "System (4)", "count": 1, "bytes": 0, "durationNs": 1000000}],
        "ops": [{"op": "Read", "process": "app.exe (100)", "tid": 7, "file": "C:\f.txt", "size": 8192, "startNs": 1000000, "durationNs": 2000000, "status": "0x00000000"}],
    }
    change = ("document.getElementById('tab-fileio').click();"
              "setTimeout(function () { var b = document.getElementById('fileio-by'); b.value = 'operation'; b.dispatchEvent(new Event('change')); }, 100);")
    dom = render(filed, change, shot=shot("fileio"))
    assert "3 file operations, 8 KB read or written (1 not ended in the trace)." in dom, "the file I/O title"
    posted = json.loads(html.unescape(re.search(r'<pre id="posted"[^>]*>(.*?)</pre>', dom, re.S).group(1)))
    asked = [m["params"]["by"] for m in posted if m.get("method") == "fileio"]
    assert asked == ["process", "operation"], asked
    table = dom[dom.index('id="fileio-groups"'):dom.index('id="fileio-ops"')]
    labels = [html.unescape(x) for x in re.findall(r'<tr data-i="\d+"><td class="">([^<]*)</td>', table)]
    assert labels == ["app.exe (100)", "System (4)"], labels
    rest = html.unescape(dom[dom.index('id="fileio-ops"'):])
    assert "C:\f.txt" in rest and "0x00000000" in rest
    # The DPC/ISR tab: totals by the grouping chosen, the histogram, and
    # the longest; changing the grouping asks again.
    dpced = json.loads(json.dumps(data))
    dpced["dpc"] = {
        "count": 3, "durationNs": 1500000,
        "groups": [{"label": "drv.sys", "count": 2, "durationNs": 1200000, "maxNs": 1000000},
                   {"label": "net.sys", "count": 1, "durationNs": 300000, "maxNs": 300000}],
        "bucketsNs": [1000, 10000, 100000, 1000000, 10000000],
        "histogram": [{"type": "ISR", "counts": [0, 1, 0, 0, 0, 0]}, {"type": "DPC", "counts": [0, 0, 0, 1, 1, 0]}],
        "runs": [{"type": "DPC", "processor": 3, "startNs": 1000000, "durationNs": 1000000, "module": "drv.sys", "function": "drv.sys!Work", "vector": None}],
    }
    change = ("document.getElementById('tab-dpc').click();"
              "setTimeout(function () { var b = document.getElementById('dpc-by'); b.value = 'function'; b.dispatchEvent(new Event('change')); }, 100);")
    dom = render(dpced, change, shot=shot("dpc"))
    assert "3 DPCs and ISRs, 1.5 ms." in dom, "the DPC/ISR title"
    posted = json.loads(html.unescape(re.search(r'<pre id="posted"[^>]*>(.*?)</pre>', dom, re.S).group(1)))
    asked = [m["params"]["by"] for m in posted if m.get("method") == "dpc"]
    assert asked == ["module", "function"], asked
    table = dom[dom.index('id="dpc-groups"'):dom.index('id="dpc-histogram"')]
    labels = [html.unescape(x) for x in re.findall(r'<tr data-i="\d+"><td class="cmd">([^<]*)</td>', table)]
    assert labels == ["drv.sys", "net.sys"], labels
    hist = html.unescape(dom[dom.index('id="dpc-histogram"'):dom.index('id="dpc-runs"')])
    assert "0.1–1 ms" in hist and "≥ 10 ms" in hist, "the buckets"
    hist_rows = re.findall(r'<tr data-i="\d+">(.*?)</tr>', hist, re.S)
    cells = [re.findall(r'<td[^>]*>([^<]*)</td>', r) for r in hist_rows]
    assert cells == [["DPC", "0", "0", "0", "1", "1", "0"], ["ISR", "0", "1", "0", "0", "0", "0"]], cells
    assert "drv.sys!Work" in html.unescape(dom[dom.index('id="dpc-runs"'):])
    # The registry tab: totals by the grouping chosen (and how many of all
    # the groups), and the longest; changing the grouping asks again.
    regd = json.loads(json.dumps(data))
    regd["registry"] = {
        "count": 5, "failed": 2, "durationNs": 2500000, "groupsTotal": 3,
        "groups": [{"label": "app.exe (100)", "count": 3, "failed": 2, "durationNs": 2000000},
                   {"label": "svc.exe (200)", "count": 2, "failed": 0, "durationNs": 500000}],
        "ops": [{"op": "QueryValue", "process": "app.exe (100)", "tid": 7, "key": "\\REGISTRY\\MACHINE\\SOFTWARE\\App", "value": "Version",
                 "startNs": 1000000, "durationNs": 1500000, "status": "0xc0000034"}],
    }
    change = ("document.getElementById('tab-registry').click();"
              "setTimeout(function () { var b = document.getElementById('registry-by'); b.value = 'key'; b.dispatchEvent(new Event('change')); }, 100);")
    dom = render(regd, change, shot=shot("registry"))
    assert "5 registry operations, 2 failed, 2.5 ms (the 2 groups that took longest of 3)." in dom, "the registry title"
    posted = json.loads(html.unescape(re.search(r'<pre id="posted"[^>]*>(.*?)</pre>', dom, re.S).group(1)))
    asked = [m["params"]["by"] for m in posted if m.get("method") == "registry"]
    assert asked == ["process", "key"], asked
    table = dom[dom.index('id="registry-groups"'):dom.index('id="registry-ops"')]
    labels = [html.unescape(x) for x in re.findall(r'<tr data-i="\d+"><td class="cmd">([^<]*)</td>', table)]
    assert labels == ["app.exe (100)", "svc.exe (200)"], labels
    rest = html.unescape(dom[dom.index('id="registry-ops"'):])
    assert "\\REGISTRY\\MACHINE\\SOFTWARE\\App" in rest and "Version" in rest and "0xc0000034" in rest
    # The hard faults tab: totals by the grouping chosen, and the longest;
    # changing the grouping asks again (with the time selected, if any).
    faulted = json.loads(json.dumps(data))
    faulted["hardfaults"] = {
        "count": 3, "bytes": 12288, "durationNs": 1500000, "groupsTotal": 2,
        "groups": [{"label": "C:\\a.dll", "count": 2, "bytes": 8192, "durationNs": 1000000},
                   {"label": "C:\\b.exe", "count": 1, "bytes": 4096, "durationNs": 500000}],
        "faults": [{"startNs": 1000000, "durationNs": 700000, "size": 4096, "offset": 8192, "address": "0x7ff000001000",
                    "process": "app.exe (100)", "tid": 7, "file": "C:\\a.dll"}],
    }
    change = ("document.getElementById('tab-hardfaults').click();"
              "setTimeout(function () { var b = document.getElementById('hardfaults-by'); b.value = 'file'; b.dispatchEvent(new Event('change')); }, 100);")
    dom = render(faulted, change, shot=shot("hardfaults"))
    assert "3 hard faults, 12 KB read, 1.5 ms." in dom, "the hard faults title"
    posted = json.loads(html.unescape(re.search(r'<pre id="posted"[^>]*>(.*?)</pre>', dom, re.S).group(1)))
    asked = [m["params"]["by"] for m in posted if m.get("method") == "hardfaults"]
    assert asked == ["process", "file"], asked
    table = dom[dom.index('id="hardfaults-groups"'):dom.index('id="hardfaults-faults"')]
    labels = [html.unescape(x) for x in re.findall(r'<tr data-i="\d+"><td class="cmd">([^<]*)</td>', table)]
    assert labels == ["C:\\a.dll", "C:\\b.exe"], labels
    rest = html.unescape(dom[dom.index('id="hardfaults-faults"'):])
    assert "0x2000" in rest and "700" in rest, "the offset and duration"
    # The virtual memory tab: commits by the grouping chosen, and the
    # largest lifetimes (one still committed).
    vm = json.loads(json.dumps(data))
    vm["vmem"] = {
        "commits": 3, "committed": 3145728, "decommits": 1, "decommitted": 1048576, "outstanding": 2097152,
        "groupsTotal": 2,
        "groups": [{"label": "app.exe (100)", "commits": 2, "committed": 2097152, "decommits": 1, "decommitted": 1048576, "outstanding": 1048576},
                   {"label": "svc.exe (200)", "commits": 1, "committed": 1048576, "decommits": 0, "decommitted": 0, "outstanding": 1048576}],
        "lifetimes": [{"process": "app.exe (100)", "tid": 7, "base": "0x10000", "size": 1048576, "commitNs": 1000000, "decommitNs": None, "decommitTid": None}],
    }
    change = ("document.getElementById('tab-vmem').click();"
              "setTimeout(function () { var b = document.getElementById('vmem-by'); b.value = 'thread'; b.dispatchEvent(new Event('change')); }, 100);")
    dom = render(vm, change, shot=shot("vmem"))
    assert "3 commits (3 MB) and 1 decommits (1 MB); 2 MB of it still committed at the end." in dom, "the vmem title"
    posted = json.loads(html.unescape(re.search(r'<pre id="posted"[^>]*>(.*?)</pre>', dom, re.S).group(1)))
    asked = [m["params"]["by"] for m in posted if m.get("method") == "vmem"]
    assert asked == ["process", "thread"], asked
    table = dom[dom.index('id="vmem-groups"'):dom.index('id="vmem-lifetimes"')]
    labels = [html.unescape(x) for x in re.findall(r'<tr data-i="\d+"><td class="cmd">([^<]*)</td>', table)]
    assert labels == ["app.exe (100)", "svc.exe (200)"], labels
    rest = html.unescape(dom[dom.index('id="vmem-lifetimes"'):])
    assert "0x10000" in rest and "still committed" in rest
    # The heap and pool tabs: allocations by the grouping chosen, and the
    # largest blocks (the pool's with their type).
    for name, first, second, group in [("heap", "process", "heap", "0x1000 in app.exe (100)"), ("pool", "tag", "type", "Abcd")]:
        alloc = json.loads(json.dumps(data))
        alloc[name] = {
            "allocs": 4, "allocated": 4096, "frees": 2, "freed": 1024, "outstandingCount": 2, "outstanding": 3072,
            "groupsTotal": 2,
            "groups": [{"label": "g1", "allocs": 3, "allocated": 3072, "frees": 1, "freed": 512, "outstandingCount": 2, "outstanding": 2560},
                       {"label": "g2", "allocs": 1, "allocated": 1024, "frees": 1, "freed": 512, "outstandingCount": 0, "outstanding": 512}],
            "blocks": [{"process": "app.exe (100)", "tid": 7, "group": group, "kind": "Paged", "address": "0xb1", "size": 2048,
                        "allocNs": 1000000, "freeNs": None}],
        }
        change = (f"document.getElementById('tab-{name}').click();"
                  f"setTimeout(function () {{ var b = document.getElementById('{name}-by'); b.value = '{second}'; b.dispatchEvent(new Event('change')); }}, 100);")
        dom = render(alloc, change, shot=shot(name))
        assert f"4 {name} allocations (4 KB) and 2 frees (1 KB); 2 (3 KB) still allocated at the end." in dom, f"the {name} title"
        posted = json.loads(html.unescape(re.search(r'<pre id="posted"[^>]*>(.*?)</pre>', dom, re.S).group(1)))
        asked = [m["params"]["by"] for m in posted if m.get("method") == name]
        assert asked == [first, second], asked
        table = dom[dom.index(f'id="{name}-groups"'):dom.index(f'id="{name}-blocks"')]
        labels = [html.unescape(x) for x in re.findall(r'<tr data-i="\d+"><td class="cmd">([^<]*)</td>', table)]
        assert labels == ["g1", "g2"], labels
        start = dom.index(f'id="{name}-blocks"')
        rest = html.unescape(dom[start:dom.index("</table>", start)])
        assert group in rest and "still allocated" in rest and "2,048" in rest
        assert ("Paged" in rest) == (name == "pool"), (name, "the pool's types")
    print("harness: ok")


if __name__ == "__main__":
    main()
