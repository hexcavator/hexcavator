# Cross-reference test program

`tools/xref/build.cmd` builds `tools/xref` (`main.cpp`, `dead.cpp`) with
MSVC for x64 and ARM64: `xref-<arch>.exe` with its PDB and map, and the
linker's `/VERBOSE` output (`xref-<arch>.verbose.txt`, trimmed).

`xref-x64-renamed.exe` is the x64 build with `inner` renamed
(`inner_renamed`, by `RENAMED`), for comparing builds.

What it holds, for `hexc xref` (`apps/hexcavator/tests/xref.rs`):

- `Square`, constructed by `main`: its virtual functions are reached
  through its constructor and vtable.
- `Circle`, constructed only by a static initializer (`.CRT$XCU`).
- `op_add` and `op_sub`, reached only through a table of pointers.
- `outer` and `inner`: plain calls.
- `exported_twice`, an export.
- `Tag`, whose only object is initialized at compile time (`constinit`,
  and no virtual destructor): no code refers to its vtable, only the
  object.
- `dead.cpp`, compiled without `/Gy`: `dead_entry` (which nothing calls)
  shares a section with `live_in_dead_object` (which `main` calls), so the
  linker keeps it, and with it `Ghost`'s constructor, vtable, virtual
  functions, and RTTI. None of them is reachable.
