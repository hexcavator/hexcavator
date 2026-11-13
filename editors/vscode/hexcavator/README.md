# Hexcavator for VS Code

Explore your binaries in VS Code: PE images, COFF objects and libraries,
ELF and Mach-O files and archives, and WebAssembly modules, with their
PDBs or DWARF. A sidebar opens each binary to its headers, build
information, debug information, symbols, types, source files, data, and
disassembly. You can ask why any function or datum is there and what
refers to it, compare two builds, and see where the bytes go as an
interactive treemap, sunburst, or tree, with measured ways to make it
smaller. It runs `hexc`, and each view can show its command line.

## The sidebar

The Hexcavator icon in the activity bar opens a list of the binaries and
diffs you've opened (**Hexcavator: Open Binary…** and **Hexcavator: Diff
Binaries…** in the Command Palette and the pane's title bar, **Open in
Hexcavator** in the Explorer's context menu, or any report opened
elsewhere). The pane's **…** menu also has **Close All**, **Show hexc's
Log**, and **Restart hexc**. Under each
binary, as `hexc info -json` says it supports them (by its format and
whether its debug information was found, not by its name: an ELF or
Mach-O file with DWARF gets what a PE image with its PDB does):

- **Headers** and **File Format**: `hexc`'s output, as text.
- **Build Information**: the Build Information page (below).
- **Debug Information** (its PDB's summary, or its DWARF's units, lines,
  and frames; a Mach-O image without a dSYM, each object's of its debug
  map): `hexc`'s output, as text.
- **Symbols**: the Symbols page (below).
- **Types**: the Types page (below).
- **Sources**: the Symbols page grouped by source file (each byte of code
  by the file its line tables name), each file opening to the symbols
  whose code came from it; its grouping is remembered apart.
- **Size Reduction Opportunities**: what could be smaller, and by how much
  (below).
- **Compare With Another Build…**: adds a diff of it.
- **Miscellaneous Queries**: the rest: unreachable code and data,
  unreferenced vtables, identical functions, and inlined functions.
  (`hexc annotations` lists the strings MSVC's `__annotation` attaches to
  code, as drivers' WPP tracing does; few binaries have any.) (Disassembly, **Why Is This Here?**,
  **References**, queries, a type's layout, and **View Definition** are on
  the Symbols and Types pages' context menus; types by padding on the Types
  page; code by source file on the Sources page.)
  Hover one for its `hexc` command line; right-click to copy it or run it
  in a terminal. Each opens as tables (from `-json`): its numbers as a
  summary, each list sortable by any column, filterable, and copyable as
  CSV, with names that open their symbols (right-click for more) and
  source paths that open their files; **Open as Text** shows `hexc`'s own
  output.
- The answers asked for (why a symbol is there, what refers to it) follow,
  each reference opening into its own, until closed.

A diff has its **Symbols** page (the change: below) and its **Types**
(the types whose layout changed, and those added or removed).

The list is kept per workspace, in the order the binaries were opened (one
opened again keeps its place), and a binary rebuilt is read again.

In source files, a lens above each function the opened binaries have code
from (by their debug information's line tables) shows its size in each,
with links to its code and why it is there (`hexcavator.codeLens` turns
them off).

Source paths a binary recorded on another machine (a build server's, a
mapped drive) are found here by `hexcavator.sourcePathMap` (prefixes, from
the build's to yours), else by their last directories under the
workspace's folders and the binary's directories; lenses match them the
same way.

## The Build Information page

How the binary was built, from its headers and debug information (`hexc
checksec -audit -json`):

- **Security Options**: each exploit mitigation (ASLR, DEP, CFG, CET,
  stack cookies, RELRO, PIE, pointer authentication, and so on), on, off,
  or partial, with what says so.
- **Signature**: what the file says it is (a PE image's version resource:
  company, description, product, versions, copyright, original name; a
  Mach-O image's versions and Info.plist), then its signatures (`hexc
  signature -json`), verified by hexc the same on any platform: Authenticode's (and those nested in it), or
  each architecture's Apple code signature. The verdict; the signer, when
  it was timestamped, the program, the algorithms, and the signed hash;
  each check (the file's hash, the signature, the chain, validity, usage,
  trust; for Mach-O, every page of code, the special slots, and the
  cdhashes); the certificate chain, each certificate's details (subject,
  issuer, serial, validity, key, usages, thumbprints) a click away; the
  timestamps, checked too; and for Mach-O the identifier, Team ID, flags,
  hardened runtime, code directories, requirements, and entitlements.
- **Mismatching Build Options**: the options its objects were built with
  differently, worst first (a mismatch that can break at run time; a
  mitigation some objects lack; other differences), each value with its
  number of objects. Click a value to show only its objects below.
- **Toolchain**: the linker's command line (from the PDB), and the
  compilers and languages, by objects.
- **Objects**: every object (a PDB's modules, DWARF's units, a debug map's
  objects) with its library, compiler, language, and command line.
  Group by Library, Directory, Compiler, or Language (the chips, dragged
  into order); filter as you type (a substring of the name, library,
  source, compiler, or command line, or a regular expression); sort by any
  column (a third click restores the link order). Click an object for how
  it was built: its source, directory, tool, PDB, full command line (to
  copy), and options.

The debug information names one library per object (the one the linker
read it from): a library made of other libraries isn't recorded.

## The Symbols page

Every symbol of a binary (or a diff's change), with its file and virtual
sizes:

- **As a tree** at first (no rows folded: only those in view are drawn),
  or as a nested treemap or a sunburst (which fold what they can't draw).
  In the tree each row has its share of its parent and of the whole and
  its count of rows inside; the arrow keys move, open, and close, Enter
  toggles. In the maps, click a box to zoom in, and Backspace or the
  breadcrumbs to zoom out; hover for sizes, shares, and the path; the table
  below lists the current level (sort by any column, copy as Markdown).
- **Group by** chips: **Section**, **Library**, **Object**, **Group** (a PE
  image's COFF groups), **Source** (the source file each byte of code came
  from, by the line tables: a header's inlined code is the header's; data
  stays in its section). Click one to group by it, or not; drag the ones on
  (or Alt+Left and Alt+Right) to order them, outermost first. With none,
  the symbols are a list. The grouping is remembered. (`hexc` sends every
  symbol's labels once, `hexc size -table`; the page regroups them itself,
  at once. The source files' are sent apart, when **Source** is on, being
  costlier: `hexc size -table -d sourcefiles,...`.)
- **Filter** (`/`): as you type, the symbols whose name or mangled name has
  the text, and what they are in (opened), their sizes summed again; `.*`
  makes it a regular expression (one that doesn't compile is marked, and
  the last that did stays). Esc clears it.
- **Mangled names** (in the tree's bar): a column of each symbol's mangled
  (decorated) name; the name's tooltip has it either way.
- **Right-click a symbol**: **Disassemble**, **View Data**, **Why Is This
  Here?** (the chain of references from a root, as a page), **References**
  (what refers to it and what it refers to, as a page), **View
  Definition** (a function's source file, at its line: `hexc size
  -definition`), **Copy Name**. The button in the first column (or `D`) opens its code or
  its data.
- **Compare** (⇄ in the header): the difference from a base build, growth
  in red and shrinkage in green, stronger for larger changes. In the tree,
  each row is marked: **+** added, **−** removed, **↗** grew, **↘** shrank
  (a group by its total). Click **File** or **Virtual** to sort by the
  change (growth first; again, shrinkage first), or **Name**; the order is
  remembered. **Show** chips (**Added**, **Removed**, **Grew**, **Shrank**)
  keep only those symbols (with the filter), their groups summed again. The
  grouping chips regroup a diff at once too (`hexc size -table new -- old`:
  each set of labels either build has, with its change and its base's
  sizes). Right-click a function in both builds: **Compare Disassembly**
  opens its code in each side by side (VS Code's diff editor), without
  addresses (which move between builds: branches are labeled, calls and
  data named), so that only what changed differs. **Refresh**
  (⟳) runs hexc again; **Export** (⤓) saves the report as CSV, TSV, or
  JSON.

**Open With… → Hexcavator Size** on a binary opens it too. The status bar shows the
active page's totals. The views take their colors from the editor's theme.

## The Types page

Every class, structure, and union of a binary (from its PDB or DWARF), with
its size and the bytes its padding wastes: by name at first, or sorted by
any column; filtered as you type (name or mangled name; `.*` for a regular
expression); with an optional **Mangled names** column (a PDB's unique
names; for DWARF, the Itanium name where it can be made exactly). `hexc`
keeps the types in memory and sends the rows in view, so a program with
hundreds of thousands scrolls, sorts, and filters at once (the first page
waits for its debug information to be read). Double-click a type, or
right-click **View Layout**, for its layout; right-click **References** for
the types it is a base or member of, and the variables and functions whose
types name it; right-click **View Definition** for its source file, at the
line that defines it (where the debug information records it: a PDB's
`LF_UDT_SRC_LINE`, DWARF's declaration; `hexc types -definition`).

Source paths recorded on another machine are found here as lenses' are
(`hexcavator.sourcePathMap`, else by their last directories).

## The Size Reduction Opportunities page

What could make the binary smaller, each kind a section, its total in its
heading: **Build changes** (`hexc recommend`: changes to how it's built,
such as compiling an object with `/Gy` or linking with `/OPT:REF`, each
measured on this build: its saving is the bytes it would no longer hold;
its duplicated variables are left to the next section), **Duplicate
data**, **Wasteful virtuals**, and **Template families**. The header's
**Recoverable** sums them.

## The Layout page

A type's bases, vfptr, vbptr, members (bitfields by bit), and holes, by
offset; a base or member that is a class, structure, or union (or an array
of them) opens to show its own, a layer at a time, at its offsets in the
outermost type.

## Data

A datum (**View Data** on a symbol in a data section) opens as its value,
read as its type from the debug information (a PDB, or DWARF), beside its
bytes as a
debugger shows memory (`db`, `dw`, `dd`, `dq`): each base, member
(bitfields by bit), element, padding, enumerator, and pointer, the
pointer named by the symbol it points into and a link to it. Point at a
member to light its bytes, or at a byte to see its member. Pointer slots
the loader fixes up (base relocations, dynamic relocations, Mach-O
fixups) are marked in the bytes and listed.
`hexc data <image> <name>` prints the same.

## Disassembly

**Disassemble** (⟨/⟩ on a symbol's row, `D`, the sidebar, or a source
file's size code lens) shows a function's code, for PE images (with
their PDBs), ELF and Mach-O files (x86, x86-64, ARM64), and WebAssembly
modules, four ways:

- **Raw**: a line per instruction, with its address and label.
- **Blocks**: each basic block set apart, its label (`L1`, `L2`, …) above
  it, where control comes from beside that, and where it goes below.
- **Source**: under each source line (from the line tables), the
  instructions it became, with its text if the file is on this machine;
  click the line to open it.
- **Graph**: the blocks and the branches between them: green taken, red
  not taken, blue jumps, gray falling through, loops dashed up the right.
  Drag to pan; Ctrl+wheel or the buttons zoom; Fit fits it.

**Variables** (from the debug information's records of where each parameter
and local lives over which code) names what registers and memory hold, as
windbg does: `; rcx = this`, `; edx = s.count` (a field in a register),
`; [rsp+40h] = buf.len` (on the stack), `; [rbp+4] = p->b` (through a
pointer, its bases' members too); the list of them, with their places,
is above the code. Point at a register to light every use of it (eax,
ax, and al are rax); click to pin it.

Labels are links to their blocks, and calls to their callees' code. **Bytes**
shows each instruction's encoding. **Open as Text** opens the listing as a
document. `hexcavator.disassemblyView` picks the first view; after that,
the last one picked is used.

It runs `hexc`: `hexcavator.path` if set, else the build in the repository
it is in (`target/release`, then `target/debug`), else `hexc` on `PATH`. Images need their
debug information for most tools, found as `hexc` finds it: beside the
image, in the symbol directories (`hexcavator.symbolPath`, and
`_NT_SYMBOL_PATH`'s), or on the symbol servers `hexcavator.symbolServers` and
`hexcavator.debuginfod` name (nothing is asked of a server unless one is
set; `hexcavator.symbolCache` keeps what they send). `hexcavator.arch` picks
the image of universal Mach-O files. `hexcavator.rows` limits the rows per level
(the rest are folded into "[N Others]").

## Development

The extension is plain JavaScript with no dependencies and no build
step. To try it, press F5 in VS Code with the repository open (it builds
hexc in release, then opens a window with the extension loaded, on the
repository's test binaries), or run VS Code with
`code --extensionDevelopmentPath=<this folder>`. The helpers' tests
run under any Node, or VS Code's own; the sidebar's reads the test
binaries with the hexc given:

    set ELECTRON_RUN_AS_NODE=1
    "%LOCALAPPDATA%\Programs\Microsoft VS Code\Code.exe" test\treemap.test.js
    "%LOCALAPPDATA%\Programs\Microsoft VS Code\Code.exe" test\disasm.test.js
    "%LOCALAPPDATA%\Programs\Microsoft VS Code\Code.exe" test\graph.test.js
    "%LOCALAPPDATA%\Programs\Microsoft VS Code\Code.exe" test\sidebar.test.js <hexc.exe>

`test/harness.py` renders the views in headless Edge with real reports (a
treemap, a zoom, a search, the disassembly actions, a sunburst, the tree,
a diff, the findings, and each disassembly view) and checks what they
drew; with a directory as a fourth argument, it also saves a screenshot
of each there:

    python test\harness.py <hexc.exe> <image> <base image> [shots]

`test/integration/run.ps1 <hexc.exe>` runs a smoke test in a separate VS
Code (its own settings and extensions): the extension activates, its
commands exist, and the sidebar, a report, a tool's output, and a
why-chain open.
