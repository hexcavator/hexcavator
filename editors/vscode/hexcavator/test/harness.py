"""Renders media/view.js in headless Edge with real reports and checks the
result: `python harness.py <hexc.exe> <image> <another image> [shots]` (the
second image is the base of a diff; with a directory `shots`, it also saves
screenshots of each view there, to look at).

Builds a page that loads the view's scripts and posts it a report as the
extension does, runs a script against it (a click, a search), then dumps the
DOM and checks what was drawn.
"""

import html
import json
import re
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
# The repository: test/ is in editors/vscode/hexcavator.
REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(HERE))))
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
  --vscode-sideBar-background: #181818;
  --vscode-panel-border: #2b2b2b;
  --vscode-textLink-foreground: #4daafc;
  --vscode-focusBorder: #0078d4;
  --vscode-list-activeSelectionBackground: #04395e;
}
"""


# VS Code's webview API, recording what the view posts (shown in
# <pre id="posted"> for the DOM dump).
VSCODE_STUB = """
window.__posted = [];
window.acquireVsCodeApi = function () {
  return {
    postMessage: function (m) {
      window.__posted.push(m);
      var p = document.getElementById("posted");
      p.textContent = JSON.stringify(window.__posted);
    },
    getState: function () { return null; },
    setState: function () {},
  };
};
"""


def page(message, then="", vscode=False):
    def read(name):
        with open(os.path.join(MEDIA, name), encoding="utf-8") as f:
            return f.read()

    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><style>{THEME}{read("view.css")}{read("loading.css")}</style></head><body>
<header id="header"></header><div id="toolbar"></div>
<div id="main"><div id="map"></div><div id="tip"></div></div>
<div id="legend"></div><div id="details"></div><pre id="posted"></pre>
<script>{VSCODE_STUB if vscode else ""}</script>
<script>{read("loading.js")}</script>
<script>{read("treemap.js")}</script>
<script>{read("disasm.js")}</script>
<script>{read("table.js")}</script>
<script>{read("view.js")}</script>
<script>window.postMessage({json.dumps(message)}, "*");
setTimeout(function () {{ {then} }}, 50);</script>
</body></html>"""


def disasm_page(message, then="", vscode=False, state=None):
    def read(name):
        with open(os.path.join(MEDIA, name), encoding="utf-8") as f:
            return f.read()

    stub = VSCODE_STUB if vscode else ""
    if state is not None:
        stub = (stub or "window.acquireVsCodeApi = function () { return { postMessage: function () {}, setState: function () {}, getState: function () { return null; } }; };").replace(
            "getState: function () { return null; }", "getState: function () { return %s; }" % json.dumps(state)
        )
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><style>{THEME}{read("disasm-view.css")}{read("loading.css")}</style></head><body>
<header id="header"></header><div id="toolbar"></div><div id="body"></div><pre id="posted"></pre>
<script>{stub}</script>
<script>{read("loading.js")}</script>
<script>{read("graph.js")}</script>
<script>{read("disasm.js")}</script>
<script>{read("disasm-view.js")}</script>
<script>window.postMessage({json.dumps(message)}, "*");
setTimeout(function () {{ {then} }}, 50);</script>
</body></html>"""


def data_page(message, then="", state=None):
    def read(name):
        with open(os.path.join(MEDIA, name), encoding="utf-8") as f:
            return f.read()

    stub = VSCODE_STUB
    if state is not None:
        stub = stub.replace("getState: function () { return null; }", "getState: function () { return %s; }" % json.dumps(state))
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><style>{THEME}{read("disasm-view.css")}{read("data-view.css")}{read("loading.css")}</style></head><body>
<header id="header"></header><div id="toolbar"></div><div id="body"></div><pre id="posted"></pre>
<script>{stub}</script>
<script>{read("loading.js")}</script>
<script>{read("data-view.js")}</script>
<script>window.postMessage({json.dumps(message)}, "*");
setTimeout(function () {{ {then} }}, 50);</script>
</body></html>"""


def table_page(message, then=""):
    def read(name):
        with open(os.path.join(MEDIA, name), encoding="utf-8") as f:
            return f.read()

    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><style>{THEME}{read("disasm-view.css")}{read("table-view.css")}{read("loading.css")}</style></head><body>
<header id="header"></header><div id="toolbar"></div><div id="body"></div><pre id="posted"></pre>
<script>{VSCODE_STUB}</script>
<script>{read("loading.js")}</script>
<script>{read("table.js")}</script>
<script>{read("table-view.js")}</script>
<script>window.postMessage({json.dumps(message)}, "*");
setTimeout(function () {{ {then} }}, 50);</script>
</body></html>"""


def render(message, then="", shot=None, vscode=False, html_page=None):
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "page.html")
        with open(path, "w", encoding="utf-8") as f:
            f.write(html_page if html_page is not None else page(message, then, vscode))
        url = "file:///" + path.replace("\\", "/")
        common = [EDGE, "--headless", "--disable-gpu", "--hide-scrollbars", "--window-size=1200,800", "--virtual-time-budget=3000"]
        if shot:
            subprocess.run(common + [f"--screenshot={shot}", url], capture_output=True, timeout=120)
        out = subprocess.run(common + ["--dump-dom", url], capture_output=True, text=True, encoding="utf-8", timeout=120)
        return out.stdout


def hexc(*args):
    return json.loads(subprocess.run(list(args), capture_output=True, text=True, check=True).stdout)


def main():
    # (A full path: Windows can't start `target/release/hexc.exe`, a relative
    # path with forward slashes, as given in CI.)
    exe, image, other = os.path.abspath(sys.argv[1]), sys.argv[2], sys.argv[3]
    shots = sys.argv[4] if len(sys.argv) > 4 else None
    shot = (lambda name: os.path.join(shots, name + ".png")) if shots else (lambda name: None)
    report = hexc(exe, "size", "-d", "sections,symbols", "-n", "20", "-json", image)
    # (The page opens as a tree: the map checks switch to the treemap.)
    to_map = "document.querySelectorAll('.segmented')[1].firstChild.click();"
    dom = render({"kind": "report", "file": image, "report": report}, to_map, shot=shot("treemap"))
    top = [c for c in report["total"]["children"] if abs(c["file"]) > 0]
    classes = re.findall(r'class="(box[^"]*)"', dom)
    outer = len([c for c in classes if "inner" not in c.split()])
    assert outer == len(top), f"{outer} top-level boxes for {len(top)} sections"
    assert "TOTAL" in dom and "by sections" in dom, "toolbar"
    for child in top:
        assert html.escape(child["name"]) in dom, child["name"]
    assert 'class="chip"' in dom, "header chips"
    assert dom.count("<tr") == 1 + len(report["total"]["children"]), "table rows"
    # Zoom into a section: its symbols, under breadcrumbs.
    zoomable = [c for c in top if c.get("children")]
    first = max(zoomable, key=lambda c: abs(c["file"]))
    dom = render({"kind": "report", "file": image, "report": report}, to_map + "setTimeout(function () { document.querySelector('.box.zoomable').click(); }, 100);", shot=shot("zoomed"))
    assert '<span class="here">' + html.escape(first["name"]) + "</span>" in dom, "breadcrumb"
    assert "by symbols" in dom, "level"
    # The filter: a symbol's name (as typed), the rows that have it and the
    # sections they are in, opened; their sizes summed again.
    leaf = next((g for c in zoomable for g in c["children"] if not g["name"].startswith("[")), None)
    if leaf:
        needle = json.dumps(leaf["name"][:12])
        dom = render(
            {"kind": "report", "file": image, "report": report},
            f"var s = document.getElementById('search'); s.value = {needle}; s.dispatchEvent(new Event('input'));",
            shot=shot("filter"),
        )
        assert html.escape(leaf["name"][:12]) in dom and "match" in dom, "filtered rows"
        matching = [g for c in zoomable for g in c["children"] if leaf["name"][:12].lower() in g["name"].lower()]
        holders = {c["name"] for c in zoomable for g in c["children"] if g in matching}
        assert dom.count('role="row"') == len(matching) + len(holders), f"{dom.count('role=\"row\"')} rows for {len(matching)} matches in {len(holders)} sections"
        assert "filtered, of" in dom, "the whole, beside what the filter leaves"
        # A section that holds a match closes when its twisty is clicked.
        dom = render(
            {"kind": "report", "file": image, "report": report},
            f"var s = document.getElementById('search'); s.value = {needle}; s.dispatchEvent(new Event('input'));"
            " setTimeout(function () { document.querySelector('.twisty:not(.leaf)').click(); }, 100);",
        )
        assert dom.count('aria-expanded="false"') == 1, "a filtered row closed"
        # A regular expression that doesn't compile: marked, the rows kept.
        dom = render(
            {"kind": "report", "file": image, "report": report},
            "document.querySelector('button.toggle').click(); var s = document.getElementById('search'); s.value = '(['; s.dispatchEvent(new Event('input'));",
        )
        assert 'class="invalid"' in dom, "invalid regular expression"
    # In VS Code, a symbols level's rows can be disassembled (in ELF,
    # Mach-O, and WebAssembly files): a button on each named row posts its
    # name.
    zoom_then_click = to_map + (
        "setTimeout(function () { var code = Array.from(document.querySelectorAll('.box.zoomable')).find(function (b) { return /^Code/.test(b.textContent); }) || document.querySelector('.box.zoomable');"
        " code.click(); setTimeout(function () { var b = document.querySelector('td.acts .act'); if (b) b.click(); }, 600); }, 100);"
    )
    module = os.path.join(REPO, "testdata", "wasm", "module.wasm")
    wasm = hexc(exe, "size", "-d", "sections,symbols", "-json", module)
    dom = render({"kind": "report", "file": module, "report": wasm}, zoom_then_click, vscode=True)
    assert 'class="act"' in dom, "disassemble buttons"
    posted = re.search(r'<pre id="posted">(.*?)</pre>', dom, re.S)
    assert posted and '"command":"inspect"' in html.unescape(posted.group(1)) and '"hint":"code"' in html.unescape(posted.group(1)), "disassemble message"
    # Each row carries what VS Code's context menu needs.
    assert "data-vscode-context" in dom and "webviewSection" in html.unescape(dom), "context menu data"
    # A data section's symbols in a PE image: a View Data button.
    data_then_click = to_map + (
        "setTimeout(function () { var d = Array.from(document.querySelectorAll('.box.zoomable')).find(function (b) { return /^[.]rdata/.test(b.textContent); });"
        " d.click(); setTimeout(function () { var b = document.querySelector('td.acts .act'); if (b) b.click(); }, 600); }, 100);"
    )
    dom = render({"kind": "report", "file": image, "report": report}, data_then_click, vscode=True)
    posted = re.search(r'<pre id="posted">(.*?)</pre>', dom, re.S)
    assert posted and '"hint":"data"' in html.unescape(posted.group(1)), "view data message"
    # The grouping chips: Section on (the report's level), the others not.
    assert re.search(r'class="gchip on"[^>]*data-id="sections"', dom), "Section chip on"
    assert re.search(r'class="gchip"[^>]*data-id="compileunits"', dom), "Object chip off"
    # A chip clicked: grouped by it too, symbols last.
    dom = render({"kind": "report", "file": image, "report": report}, "document.querySelector('.gchip[data-id=\"compileunits\"]').click();", vscode=True)
    posted = re.search(r'<pre id="posted">(.*?)</pre>', dom, re.S)
    assert posted and '"sources":["sections","compileunits","symbols"]' in html.unescape(posted.group(1)), "regroup"
    # Not at a sections level, nor for a COFF object (not yet), nor outside
    # VS Code.
    dom = render({"kind": "report", "file": module, "report": wasm}, vscode=True)
    assert 'class="act"' not in dom, "no buttons for sections"
    dom = render({"kind": "report", "file": "C:\\x\\a.obj", "report": wasm}, zoom_then_click, vscode=True)
    assert 'class="act"' not in dom, "no buttons for a COFF object"
    # The sunburst.
    dom = render({"kind": "report", "file": image, "report": report}, "document.querySelectorAll('.segmented')[1].children[1].click();", shot=shot("sunburst"))
    assert dom.count('class="arc') >= len(top), "sunburst arcs"
    # The tree: a row per section, closed; open the first (by its twisty),
    # then the second by the keyboard (down, right).
    tree_report = hexc(exe, "size", "-d", "sections,compileunits,symbols", "-n", "20", "-json", image)
    sections = tree_report["total"]["children"]
    to_tree = "document.querySelectorAll('.segmented')[1].lastChild.click();"
    dom = render({"kind": "report", "file": image, "report": tree_report})
    assert 'class="rows tree"' in dom, "a tree, at first"
    assert dom.count('role="row"') == len(sections), "a row per section"
    assert 'id="details"></div>' in dom, "no table below the tree"
    ordered = sorted(sections, key=lambda c: -abs(c["file"]))
    first, second = ordered[0], ordered[1]
    then = to_tree + """
      setTimeout(function () {
        document.querySelector('.twisty').click();
        setTimeout(function () {
          var key = function (k) { document.dispatchEvent(new KeyboardEvent('keydown', { key: k, bubbles: true })); };
          var n = %d;
          for (var i = 0; i < n; i++) key('ArrowDown');
          key('ArrowRight');
        }, 100);
      }, 100);""" % (1 + len(first.get("children", [])))
    dom = render({"kind": "report", "file": image, "report": tree_report}, then, shot=shot("tree"))
    want = len(sections) + len(first.get("children", [])) + len(second.get("children", []))
    assert dom.count('role="row"') == want, f"{dom.count('role=\"row\"')} rows after opening two sections, expected {want}"
    assert dom.count('aria-expanded="true"') == 2, "two open rows"
    assert 'class="guide elbow' in dom, "guide lines"
    # Rollups: each open section's share of the whole, and its item count.
    assert re.search(r'<tr class="selected[^"]*"[^>]*aria-level="1"', dom), "the second section selected"
    # Going to a symbol's row (from the sidebar) opens its ancestors.
    sym_path = next(
        ([s["name"], c["name"], g["name"]] for s in sections for c in s.get("children", []) for g in c.get("children", []) if not g["name"].startswith("[")),
        None,
    )
    if sym_path:
        dom = render({"kind": "report", "file": image, "report": tree_report, "at": sym_path}, "", vscode=False)
        sel = re.search(r'<tr class="selected[^"]*"[^>]*data-key="([^"]*)"', dom)
        assert sel and html.unescape(sel.group(1)).split("\u0000") == sym_path, "goto: the symbol's row, selected"
        dom = render({"kind": "report", "file": image, "report": tree_report}, to_tree + "setTimeout(function () { window.postMessage(%s, '*'); }, 100);" % json.dumps({"kind": "goto", "at": sym_path}))
        sel = re.search(r'<tr class="selected[^"]*"[^>]*data-key="([^"]*)"', dom)
        assert sel and html.unescape(sel.group(1)).split("\u0000") == sym_path, "goto in the tree selects the symbol"
    # A diff: growth and shrinkage are colored.
    diff = hexc(exe, "size", "-d", "sections,symbols", "-n", "20", "-json", image, "--", other)
    dom = render({"kind": "report", "file": image, "base": other, "report": diff}, to_map, shot=shot("diff"))
    assert ("grows" in dom) or ("shrinks" in dom), "diff colors"
    assert "grew" in dom, "diff legend"
    findings = hexc(exe, "size", "-findings", "-json", image)
    dom = render({"kind": "findings", "file": image, "findings": findings}, shot=shot("findings"))
    for heading in ["Duplicate data", "Wasteful virtuals", "Template families"]:
        assert f"<h2>{heading}</h2>" in dom, heading
    # The build changes (hexc recommend), first, each with its saving.
    recs = hexc(exe, "recommend", "-json", image)
    # (Its duplicated variables are Duplicate data's: not listed twice, nor
    # counted twice.)
    dup = {"kind": "duplicates", "advice": "define 3 variables once", "saving": 1000000, "examples": []}
    with_dup = dict(recs, recommendations=recs["recommendations"] + [dup], saving=recs["saving"] + dup["saving"])
    rdom = render({"kind": "findings", "file": image, "findings": findings, "recommendations": with_dup}, "document.querySelector('details').open = true;", shot=shot("buildchanges"))
    drawn = re.sub(r"<script.*?</script>", "", rdom, flags=re.S)
    assert "define 3 variables once" not in drawn, "duplicates left to Duplicate data"
    assert "save 976 KiB" not in drawn and "Size Reduction Opportunities" in drawn
    assert "<h2>Build changes</h2>" in rdom and rdom.index("Build changes") < rdom.index("Duplicate data"), "build changes first"
    for r in recs["recommendations"]:
        assert html.escape(r["advice"]) in rdom, r["advice"]
    assert f"save " in rdom, "the saving"
    assert "Recoverable" in dom, "findings header"
    rows = dom.count("<tr>")
    # A heading row per section with items, and a row per item.
    counts = [findings["duplicate_data"]["count"], len(findings["wasteful_virtuals"]["items"]), len(findings["template_families"]["items"])]
    expected = sum(1 + n for n in counts if n)
    assert dom.count('<p class="none">None found.</p>') == counts.count(0), "empty sections"
    assert rows == expected, f"{rows} rows, expected {expected}"
    # Closed at first; tables sortable by any column.
    assert "<details open" not in dom and 'class="card"' in dom, "cards closed"
    if any(counts):
        assert 'class="sortable n sorted"' in dom, "sorted by the first column"
        # Sorting by the last column (a name) sorts the rows by it.
        dom = render(
            {"kind": "findings", "file": image, "findings": findings},
            "document.querySelectorAll('details').forEach(function (d) { d.open = true; });"
            " var t = document.querySelector('table.sortable-table'); var ths = t.querySelectorAll('th'); ths[ths.length - 1].click();",
        )
        table = re.search(r'<table class="rows sortable-table">(.*?)</table>', dom, re.S).group(1)
        body = table.split("<tbody>", 1)[1]
        names = [html.unescape(re.findall(r"<td[^>]*>([^<]*)</td>", tr)[-1]) for tr in re.findall(r"<tr[^>]*>(.*?)</tr>", body, re.S)]
        assert names and names == sorted(names, key=str.lower), f"sorted by name: {names[:5]}"
    # The pane's spinner: gone once the report is there; over it while
    # hexc runs again (a refresh), saying what it does, with Cancel.
    dom = render({"kind": "report", "file": image, "report": report}, vscode=True)
    assert re.search(r'<div id="loading" role="status" aria-live="polite" hidden', dom), "hidden once loaded"
    # From hexc's table (every label of every symbol at once): grouped here
    # by the chips, without asking the extension to run hexc again.
    table = hexc(exe, "size", "-table", image)
    dom = render(
        {"kind": "report", "file": image, "table": table, "levels": [], "format": "pe", "tools": []},
        "document.querySelector('.gchip[data-id=\"sections\"]').click();",
        vscode=True,
    )
    posted = html.unescape(re.search(r'<pre id="posted">(.*?)</pre>', dom, re.S).group(1))
    assert '"local":true' in posted, "regrouped here"
    want = hexc(exe, "size", "-d", "sections,symbols", "-n", "0", "-json", image)
    for c in want["total"]["children"]:
        assert html.escape(c["name"]) in dom, "a section row: " + c["name"]
    assert "by sections" in dom, "grouped by section"
    # The Source chip: the table has no source files (they're costly), so
    # the extension is asked for the table that has.
    dom = render(
        {"kind": "report", "file": image, "table": table, "levels": [], "format": "pe", "tools": []},
        "document.querySelector('.gchip[data-id=\"sourcefiles\"]').click();",
        vscode=True,
    )
    posted = html.unescape(re.search(r'<pre id="posted">(.*?)</pre>', dom, re.S).group(1))
    assert '"sources":["sourcefiles","symbols"]' in posted and '"local":true' not in posted, "asked for the source files' table"
    # Given it: grouped by source file, then symbol.
    sources_table = hexc(exe, "size", "-table", "-d", "sourcefiles,symbols", image)
    dom = render({"kind": "report", "file": image, "table": sources_table, "levels": ["sourcefiles"], "format": "pe", "tools": []}, vscode=True)
    want = hexc(exe, "size", "-d", "sourcefiles", "-n", "0", "-json", image)
    files = [c["name"] for c in want["total"]["children"] if not c["name"].startswith("[")]
    assert files and all(html.escape(f) in dom for f in files[:5]), "source file rows"
    # Every symbol, ungrouped (the page's first view): only the rows in view
    # are drawn, the rest spacers.
    flat = hexc(exe, "size", "-d", "symbols", "-n", "0", "-json", image)
    count = len(flat["total"]["children"])
    dom = render({"kind": "report", "file": image, "report": flat}, shot=shot("symbols"))
    drawn = dom.count('role="row"')
    assert count > 100 and drawn < count and 'class="spacer"' in dom, f"{drawn} of {count} rows drawn"
    dom = render(
        {"kind": "report", "file": image, "report": report},
        "window.postMessage({ kind: 'loading', text: 'Reading x.exe…' }, '*'); setTimeout(function () { document.querySelector('#loading .cancel').click(); }, 50);",
        shot=shot("loading"),
        vscode=True,
    )
    assert 'id="loading" role="status" aria-live="polite" class="over"' in dom, "over the report"
    assert "Cancelling…" in dom, "cancel"
    posted = re.search(r'<pre id="posted">(.*?)</pre>', dom, re.S)
    assert posted and '"command":"cancel"' in html.unescape(posted.group(1)), "cancel posted"
    modes = disasm_checks(exe, shot)
    data_checks(exe, shot)
    table_checks(exe, image, shot)
    types_checks(exe, image, shot)
    build_checks(exe, shot)
    diff_checks(exe, shot)
    print(f"ok: {outer} sections in the treemap; zoom, search, disassembly actions, sunburst, tree, diff, and findings ({rows} rows) render; disassembly: {modes}")


def types_page(message, then="", pages=None, script="types-view.js"):
    """A page of ours (the Types or Layout page), with a stand-in for the
    extension that answers its questions from `pages`: "page" requests (by
    their filter) and "expand" requests (by type), as hexc would."""
    def read(name):
        with open(os.path.join(MEDIA, name), encoding="utf-8") as f:
            return f.read()

    answers = f"""
window.__answers = {json.dumps(pages or {})};
(function () {{
  var post = window.acquireVsCodeApi().postMessage;
  window.acquireVsCodeApi = function () {{ return {{
    postMessage: function (m) {{
      post(m);
      var a = m.command === "page" ? window.__answers["page:" + (m.filter || "")] : m.command === "expand" ? window.__answers["ty:" + m.ty] : null;
      if (a) setTimeout(function () {{
        if (m.command === "page") window.postMessage(Object.assign({{ kind: "page", generation: m.generation }}, a), "*");
        else window.postMessage({{ kind: "inner", ty: m.ty, layout: a }}, "*");
      }}, 5);
    }},
    getState: function () {{ return null; }}, setState: function () {{}} }}; }};
}})();
"""
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><style>{THEME}{read("view.css")}{read("loading.css")}</style></head><body class="treemode">
<header id="header"></header><div id="toolbar"></div><div id="main"></div><pre id="posted"></pre>
<script>{VSCODE_STUB}{answers}</script>
<script>{read("loading.js")}</script>
<script>{read(script)}</script>
<script>window.postMessage({json.dumps(message)}, "*");
setTimeout(function () {{ {then} }}, 100);</script>
</body></html>"""


def types_checks(exe, image, shot):
    """The Types page: the rows in view asked of hexc a page at a time,
    sorted by name; filtered as typed (asked again); a double click asks
    for the layout. The Layout page: by offset, a member that is a
    structure opens to show its own."""
    first = hexc(exe, "types", "-json", "-n", "200", "-from", "0", "-sort", "name", image)
    names = [r[0] for r in first["list"]]
    assert names == sorted(names, key=lambda n: (n.lower(), n)), "by name"
    filtered = hexc(exe, "types", "-json", "-n", "200", "-from", "0", "-sort", "name", "-filter", "except", image)
    pages = {"page:": first, "page:except": filtered}
    message = {"kind": "types", "file": image}
    dom = render(None, shot=shot("types"), html_page=types_page(message, pages=pages))
    drawn = dom.count("data-vscode-context")
    assert 0 < drawn <= len(first["list"]), f"{drawn} rows drawn"
    assert "webviewSection&quot;:&quot;type" in dom, "rows' context menu"
    assert html.escape(names[0]) in dom, "the first by name"
    dom = render(
        None,
        html_page=types_page(
            message,
            "var s = document.getElementById('search'); s.value = 'except'; s.dispatchEvent(new Event('input'));"
            " setTimeout(function () { document.querySelector('tbody tr:not(.spacer):not(.pending)').dispatchEvent(new MouseEvent('dblclick', { bubbles: true })); }, 300);",
            pages=pages,
        ),
    )
    assert f"{filtered['matched']} of {filtered['types']} types match" in dom, "filtered"
    # Typing keeps the filter box's focus while the rows come.
    focus = render(
        None,
        html_page=types_page(
            message,
            "var s = document.getElementById('search'); s.focus(); s.value = 'except'; s.dispatchEvent(new Event('input'));"
            " setTimeout(function () { document.getElementById('posted').setAttribute('data-focus', document.activeElement.id); }, 300);",
            pages=pages,
        ),
    )
    assert 'data-focus="search"' in focus, "the filter box keeps its focus"
    posted = html.unescape(re.search(r'<pre id="posted">(.*?)</pre>', dom, re.S).group(1))
    assert '"filter":"except"' in posted, "the filter asked of hexc"
    assert '"command":"layout"' in posted, "layout asked for"
    # The layout: EHExceptionRecord's params (a structure) opens.
    layout = hexc(exe, "types", "-layout", "EHExceptionRecord", "-json", image)
    member = next(p for p in layout["parts"] if p["name"] == "params")
    inner = hexc(exe, "types", "-ty", str(member["expand"]), "-json", image)
    offsets = [p["offset"] for p in layout["parts"]]
    assert offsets == sorted(offsets), "by offset"
    dom = render(
        None,
        shot=shot("layout"),
        html_page=types_page(
            {"kind": "layout", "file": image, "layout": layout},
            "Array.from(document.querySelectorAll('.twisty')).find(function (t) { return t.closest('tr').textContent.indexOf('params') >= 0; }).click();",
            pages={"ty:%d" % member["expand"]: inner},
            script="layout-view.js",
        ),
    )
    assert "magicNumber" in dom and 'aria-expanded="true"' in dom, "params opened"
    # Its members at their offsets in the outer type.
    magic = next(p for p in inner["parts"] if p["name"] == "magicNumber")
    assert f'<td class="n">{member["offset"] + magic["offset"]}</td>' in dom, "absolute offsets"


def diff_checks(exe, shot):
    """A diff's tree (testdata/diff): each row marked added, removed, grew,
    or shrank; sorted by the change in file size, either way, or by name."""
    repo = REPO
    new = os.path.join(repo, "testdata", "diff", "diff-v2.exe")
    old = os.path.join(repo, "testdata", "diff", "diff-v1.exe")
    report = hexc(exe, "size", "-d", "symbols", "-n", "0", "-json", new, "--", old)
    message = {"kind": "report", "file": new, "base": old, "report": report}
    dom = render(message, shot=shot("difftree"))

    def mark(name):
        m = re.search(r'<span class="change (\w+)"[^>]*>[^<]*</span><span class="label"[^>]*>' + re.escape(html.escape(name)) + "<", dom)
        return m and m.group(1)

    for name, want in [
        ("added_fn(int)", "added"),
        ("g_added_table", "added"),
        ("removed_fn(int)", "removed"),
        ("g_removed_table", "removed"),
        ("transform(int)", "grew"),
        ("g_lookup", "grew"),
    ]:
        assert mark(name) == want, f"{name}: {mark(name)}"

    def order(d):
        return re.findall(r'<span class="label"[^>]*>([^<]*)</span>', d)

    # File: descending at the first click (growth first), ascending at the
    # second (shrinkage first); and by name.
    click = "var h = Array.from(document.querySelectorAll('table.tree th')).find(function (t) { return t.textContent.indexOf('%s') === 0; }); h.click();"
    down = order(render(message, click % "File"))
    up = order(render(message, click % "File" + click % "File"))
    by_name = order(render(message, click % "Name"))
    rows = {c["name"]: c["file"] for c in report["total"]["children"]}
    shown = lambda names: [html.unescape(n) for n in names if html.unescape(n) in rows]
    assert shown(up) == sorted(shown(up), key=lambda n: rows[n]), "ascending: shrinkage first"
    assert shown(down) == sorted(shown(down), key=lambda n: -rows[n]), "descending: growth first"
    assert shown(up)[0] == "g_removed_table" and shown(down)[0] == "g_added_table"
    assert shown(by_name) == sorted(shown(by_name), key=lambda n: n.lower()) or shown(by_name) == sorted(shown(by_name)), "by name"

    # From hexc's diff table (what the extension sends): the same marks,
    # grouped here by the chips, and filtered by what happened.
    table = hexc(exe, "size", "-table", new, "--", old)
    tmessage = {"kind": "report", "file": new, "base": old, "table": table, "levels": [], "format": "pe", "tools": []}
    dom = render(tmessage, vscode=True)
    for name, want in [("added_fn(int)", "added"), ("removed_fn(int)", "removed"), ("transform(int)", "grew"), ("g_removed_table", "removed")]:
        assert mark(name) == want, f"table: {name}: {mark(name)}"
    assert html.escape("kept_same(int)") not in re.sub(r"<script.*?</script>", "", dom, flags=re.S), "the unchanged left out"
    # Only what was added.
    dom = render(tmessage, "document.querySelector('.gchip.kind[data-kind=\"added\"]').click();", vscode=True)
    drawn = [html.unescape(n) for n in order(re.sub(r"<script.*?</script>", "", dom, flags=re.S))]
    assert sorted(drawn) == ["added_fn(int)", "g_added_table"], f"added only: {drawn}"
    # By section, here (no hexc asked).
    dom = render(tmessage, "document.querySelector('.gchip[data-id=\"sections\"]').click();", vscode=True)
    posted = html.unescape(re.search(r'<pre id="posted">(.*?)</pre>', dom, re.S).group(1))
    assert '"local":true' in posted, "a diff regrouped here"
    assert html.escape("[section .text]") not in dom or ".text" in dom
    # A changed function's menu compares its code; an added one's doesn't.
    dom = render(tmessage, vscode=True)
    ctx = {}
    for m in re.finditer(r'<tr[^>]*data-vscode-context="([^"]*)"[^>]*>(.*?)</tr>', dom, re.S):
        label = re.search(r'<span class="label"[^>]*>([^<]*)<', m.group(2))
        if label:
            ctx[html.unescape(label.group(1))] = json.loads(html.unescape(m.group(1)))
    # (What package.json's menu asks of the row: a diff's symbol, code,
    # in both builds.)
    t = ctx["transform(int)"]
    assert t["webviewSection"] == "diffSymbol" and t["symbolKind"] != "data", t
    assert t["symbolChange"] == "grew" and t["base"] == old
    assert ctx["added_fn(int)"]["symbolChange"] == "added"
    menu = json.load(open(os.path.join(os.path.dirname(HERE), "package.json"), encoding="utf-8"))["contributes"]["menus"]["webview/context"]
    when = next(m["when"] for m in menu if m["command"] == "hexcavator.row.disassemblyDiff")
    for key in ("webviewSection == 'diffSymbol'", "symbolChange == 'grew'"):
        assert key in when, when


def build_checks(exe, shot):
    """The Build Information page: the security options, the options that
    differ (a value's objects shown at a click), the linker's command line,
    and the objects, grouped by library and filtered as typed."""
    repo = REPO
    image = os.path.join(repo, "testdata", "types", "types.exe")
    report = hexc(exe, "checksec", "-audit", "-json", image)
    builds = report["audit"]["builds"]
    unsigned = json.loads(subprocess.run([exe, "signature", "-json", image], capture_output=True, text=True).stdout)
    message = {"kind": "build", "file": image, "report": report, "signature": unsigned}
    page = lambda then="": types_page(message, then, script="buildinfo-view.js")
    dom = render(None, shot=shot("buildinfo"), html_page=page())
    for title in ("Security Options", "Signature", "Mismatching Build Options", "Toolchain", "Objects"):
        assert f"<h2>{title}</h2>" in dom, title
    assert "No embedded signature" in dom, "unsigned"
    # A file's version details, at the top of the section.
    versioned = os.path.join(repo, "testdata", "sizebench", "bin", "SizeBenchV2.AnalysisEngine.Tests.CodePageWin32Rsrc.dll")
    vsig = json.loads(subprocess.run([exe, "signature", "-json", versioned], capture_output=True, text=True).stdout)
    dom = render(None, html_page=types_page({"kind": "build", "file": versioned, "report": report, "signature": vsig}, script="buildinfo-view.js"))
    assert "TODO: &lt;Company name&gt;" in dom and "Product version" in dom, "version details"
    assert "/DYNAMICBASE" in dom, "a check's detail"
    assert "link.exe" in dom and "/OPT:REF" in dom, "the linker's command line"
    # Grouped by library: the groups, closed.
    assert "MSVCRT.lib" in dom and "(not from a library)" in dom, "library groups"
    assert '<td class="mono cmd"' not in dom, "groups start closed"
    # Filtered: the groups open to the objects left.
    dom = render(
        None,
        html_page=page(
            "var s = document.getElementById('search'); s.value = 'types.cpp'; s.dispatchEvent(new Event('input'));"
            " setTimeout(function () { document.querySelector('#objwrap tbody tr:not(.group):not(.spacer)').click(); }, 200);"
        ),
    )
    want = sum(1 for b in builds if "types.cpp" in (b["object"] + b["library"] + b["source"] + b["compiler"] + b["command"]).lower())
    assert f"{want} of {len(builds)} objects" in dom, "filtered"
    assert re.search(r'<td class="mono cmd"[^>]*>-nologo -c -O1', dom), "the object's command line"
    assert '<div class="objinfo"><h3>types.obj</h3>' in dom and ">Copy Command Line</button>" in dom, "its details"
    # A value of a differing option: its objects only.
    differing = [o for o in report["audit"]["options"] if len(o["values"]) > 1 and o["option"] not in ("language", "compiler")]
    if differing:
        v = differing[0]["values"][-1]
        dom = render(None, html_page=page("document.querySelectorAll('.vchip')[%d].click();" % (len(differing[0]["values"]) - 1)))
        assert f"{len(v['objects'])} of {len(builds)} objects" in dom, "a value's objects"
        assert "Built with" in dom
    # A signed file: the verdict, the checks, the chain (its certificates'
    # details open), each signature (the nested one too).
    signed = os.path.join(repo, "testdata", "signature", "signed.exe")
    root = os.path.join(repo, "testdata", "signature", "test-root.cer")
    sig = hexc(exe, "signature", "-json", "-root", root, signed)
    dom = render(
        None,
        shot=shot("signature"),
        html_page=types_page(
            {"kind": "build", "file": signed, "report": report, "signature": sig},
            "document.getElementById('signature').scrollIntoView(); document.querySelector('#signature details.cert').open = true;",
            script="buildinfo-view.js",
        ),
    )
    assert "Authenticode (nested)" in dom and "Hexcavator Test Signer" in dom, "both signatures"
    assert ">Verified<" in dom and "trusted root" in dom, "verified, to the test root"
    assert "SHA-256 thumbprint" in dom and sig["authenticode"][1]["certificates"][0]["sha256"] in dom, "a certificate's details"
    assert "File hash" in dom and "Chain" in dom, "the checks"
    # A chip clicked down the page: the page stays where it was scrolled to
    # (only the Objects section is drawn again), grouped anew.
    dom = render(
        None,
        html_page=page(
            "var p = document.querySelector('.bpage'); p.scrollTop = document.getElementById('objects').offsetTop; var before = p.scrollTop;"
            " document.querySelector('.gchip[data-id=\"compiler\"]').click();"
            " setTimeout(function () { document.body.setAttribute('data-scroll', before + ':' + document.querySelector('.bpage').scrollTop); }, 50);"
        ),
    )
    before, after = re.search(r'data-scroll="(\d+):(\d+)"', dom).groups()
    assert int(before) > 0 and before == after, f"scrolled from {before} to {after}"
    assert '>2 </span>Compiler' in dom or '2 Compiler' in html.unescape(re.sub("<[^>]+>", "", dom)), "grouped by compiler too"
    # Ungrouped: a list.
    dom = render(None, html_page=page("document.querySelector('.gchip[data-id=\"library\"]').click();"))
    assert '<tr class="group"' not in dom and re.search(r'<td class="mono cmd"[^>]*>-nologo -c -O1', dom), "a list"


def table_checks(exe, image, shot):
    """Tools' output as tables: the unreachable list (sizes sortable,
    names that open), and a query with its query to edit."""
    unreachable = hexc(exe, "xref", "-json", "-unreachable", "-n", "0", image)
    message = {"kind": "table", "title": "Unreachable Code and Data", "file": image, "pe": True, "command": "hexc xref -unreachable", "json": unreachable}
    dom = render(None, shot=shot("table"), html_page=table_page(message))
    rows = len(unreachable["unreachable"])
    assert f"{rows} rows" in dom, "the row count"
    named = len([u for u in unreachable["unreachable"] if not u["name"].startswith("[")])
    assert dom.count('<a href="#" class="sym"') == named, "names open their symbols"
    assert 'class="chip"' in dom, "the summary"
    assert "data-vscode-context" in dom, "context menus"
    # Sorted by size, largest first; then by name.
    sizes = [int(m) for m in re.findall(r'<td class="n" title="([\d,]+) bytes"', dom.replace(",", ""))]
    assert sizes == sorted(sizes, reverse=True), f"by size: {sizes[:6]}"
    # The filter.
    first = unreachable["unreachable"][0]["name"]
    dom = render(None, html_page=table_page(message, "var f = document.getElementById('filter'); f.value = %s; f.dispatchEvent(new Event('input'));" % json.dumps(first)))
    assert re.search(r"(\d+) of %d rows" % rows, dom), "filtered"
    # A name opens its symbol.
    dom = render(None, html_page=table_page(message, "document.querySelector('a.sym').click();"))
    posted = re.search(r'<pre id="posted">(.*?)</pre>', dom, re.S)
    assert posted and '"command":"inspect"' in html.unescape(posted.group(1)), "inspect"
    # A query: its box, and Enter runs it.
    query = hexc(exe, "query", "-json", image, "group by library")
    qmessage = {"kind": "table", "title": "Query", "file": image, "pe": True, "query": "group by library", "command": "hexc query", "json": query}
    dom = render(None, shot=shot("query"), html_page=table_page(qmessage, "var q = document.getElementById('query'); q.value = 'kind=data'; q.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter' }));"))
    assert 'id="query"' in dom, "the query box"
    posted = re.search(r'<pre id="posted">(.*?)</pre>', dom, re.S)
    assert posted and '"query":"kind=data"' in html.unescape(posted.group(1)), "a query runs"


def data_checks(exe, shot):
    """The data view of a structure of the types test program: its tree
    and its bytes, linked."""
    repo = REPO
    image = os.path.join(repo, "testdata", "types", "types.exe")
    data = hexc(exe, "data", "-json", image, "g_sample")
    message = {"kind": "data", "file": image, "data": data}
    # Open everything: each member's row, and the bytes.
    dom = render(None, shot=shot("data"), html_page=data_page(message, "document.querySelector('.tablebar a').click();"))
    assert 'class="vtree"' in dom, "the typed tree"
    for name in ["padded", "bits", "color", "ratio", "text", "numbers", "either"]:
        assert f'<span class="label">{name}</span>' in dom, name
    assert "Green (2)" in dom, "an enumerator"
    assert dom.count('class="hrow"') == (data["size"] + 15) // 16, "a line per 16 bytes"
    assert 'class="b ptr' in dom, "the pointer's bytes"
    assert 'class="target"' in dom and "hello" in dom, "the pointer's target"
    # A pointer's target opens it.
    dom = render(None, html_page=data_page(message, "document.querySelector('a.target').click();"))
    posted = re.search(r'<pre id="posted">(.*?)</pre>', dom, re.S)
    assert posted and '"command":"inspect"' in html.unescape(posted.group(1)), "a pointer opens its target"
    # Hex only, by quadwords.
    dom = render(None, html_page=data_page(message, state={"mode": "hex", "unit": 8}))
    assert 'class="vtree"' not in dom and 'class="cells u8"' in dom, "quadwords"
    # Pointing at a member lights its bytes.
    dom = render(None, html_page=data_page(message, "var r = document.querySelector('tr[data-key=\"/0\"]'); r.dispatchEvent(new MouseEvent('mouseenter'));"))
    assert dom.count(" hot") >= 12, "a member's bytes lit"


def disasm_checks(exe, shot):
    """The disassembly view, in each mode, of a function of the xref test
    image (with branches, a loop, calls, and source lines)."""
    repo = REPO
    image = os.path.join(repo, "testdata", "xref", "xref-x64.exe")
    name = "__scrt_common_main_seh()"
    listing = hexc(exe, "size", "-disassemble", name, "-json", image)
    sources = []
    for f in listing["files"]:
        try:
            with open(f, encoding="utf-8") as fh:
                sources.append({"path": f, "lines": fh.read().split("\n")})
        except OSError:
            sources.append({"path": f, "lines": None})
    message = {"kind": "disasm", "file": image, "listing": listing, "sources": sources}
    blocks = listing["blocks"]
    labels = [b["label"] for b in blocks if b["label"]]

    def view(mode, then=""):
        return render(None, shot=shot("disasm-" + mode), html_page=disasm_page(message, then, vscode=True, state={"mode": mode}))

    # Raw: a line per instruction, labels L1.. beside the lines they label.
    dom = view("raw")
    assert dom.count('class="ln"') == len(listing["lines"]), "raw lines"
    assert '<span class="lab">L1:</span>' in dom, "raw labels"
    assert dom.count('class="lbl"') >= 5, "branch labels are links"
    assert 'class="callee"' in dom, "calls are links"
    # Blocks: a section per block, each with where it goes after it.
    dom = view("blocks")
    assert dom.count('<section class="block"') == len(blocks), "a section per block"
    assert dom.count('class="bfoot"') == len(blocks), "where each goes"
    assert f'<span class="bname">{labels[0]}:</span>' in dom, "block labels"
    # Clicking a label scrolls to its block (and flashes it).
    dom = render(None, html_page=disasm_page(message, "document.querySelector('a.lbl').click();", vscode=True, state={"mode": "blocks"}))
    assert "flash" in dom, "a label goes to its block"
    # Clicking a callee asks the extension to disassemble it.
    dom = render(None, html_page=disasm_page(message, "document.querySelector('a.callee').click();", vscode=True, state={"mode": "raw"}))
    posted = re.search(r'<pre id="posted">(.*?)</pre>', dom, re.S)
    assert posted and '"command":"disassemble"' in html.unescape(posted.group(1)), "a callee's code"
    # Clicking a register pins every use of its family (ecx and rcx alike).
    dom = render(None, html_page=disasm_page(message, "document.querySelector('.reg[data-reg=rcx]').click();", vscode=True, state={"mode": "raw"}))
    pinned = re.findall(r'<span class="reg pinned" data-reg="([^"]*)"[^>]*>([^<]*)</span>', dom)
    assert len(pinned) >= 3 and {f for f, _ in pinned} == {"rcx"}, f"pinned: {pinned[:5]}"
    assert {"ecx", "rcx"} <= {n for _, n in pinned}, "a family's parts"
    # Source: a heading per source line, with its text where the file is here.
    dom = view("source")
    assert 'class="src"' in dom and "exe_common.inl:" in dom, "source headings"
    # Graph: a node per block, an edge per successor, back edges dashed.
    dom = view("graph")
    assert dom.count('class="gnode') == len(blocks), "a node per block"
    edges = sum(len(b["successors"]) for b in blocks)
    assert len(re.findall(r'<path d="[^"]*" class="edge ', dom)) == edges, "an edge per successor"
    assert "edge taken" in dom and "edge not-taken" in dom, "edge kinds"
    # Variables (from the PDB): registers and memory named, through
    # pointers too (p->b), and their list.
    types_exe = os.path.join(repo, "testdata", "types", "types.exe")
    use = hexc(exe, "size", "-disassemble", "use(Padded*, Bits*, Derived*, WithEmpty*, Diamond*, Either*, Grows*)", "-json", types_exe)
    assert [v["name"] for v in use["variables"]] == ["p", "b", "d", "w", "m", "e", "g"], use["variables"]
    vmessage = {"kind": "disasm", "file": types_exe, "listing": use, "sources": []}
    dom = render(None, html_page=disasm_page(vmessage, vscode=True, state={"mode": "raw"}))
    assert "[rbp+4] = p-&gt;b" in dom and "rcx = p" in dom, "variables named"
    assert "d-&gt;x" in dom, "a base's member through a pointer"
    assert "Variables (7)" in dom, "the list"
    dom = render(None, html_page=disasm_page(vmessage, vscode=True, state={"mode": "raw", "vars": False}))
    assert 'class="vars"' not in dom, "off"
    # A module's code is text only.
    wasm = hexc(exe, "size", "-disassemble", "main", "-json", os.path.join(repo, "testdata", "wasm", "module.wasm"))
    dom = render(None, html_page=disasm_page({"kind": "disasm", "file": "module.wasm", "listing": wasm, "sources": []}, vscode=True, state={"mode": "graph"}))
    assert 'class="code text"' in dom and "i32.const" in dom, "text-only listing"
    return f"raw, blocks ({len(blocks)}), source, graph ({edges} edges), text"


if __name__ == "__main__":
    main()
