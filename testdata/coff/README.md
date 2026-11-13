# COFF test inputs

Built by `tools/coff/build.cmd` with MSVC (x64, `/Brepro`) from
`tools/coff/objects.cpp` and `tools/coff/imports.def`:

- `objects.obj`: `/O1 /Gy /Z7` (COMDATs, associative `.pdata`/`.xdata`,
  `.debug$S` per function, a function's static, `.bss`, `.data`, `.rdata`).
- `objects-big.obj`: the same with `/bigobj`.
- `objects.lib`: a static library of both.
- `imports.lib`: an import library (short import objects by name, by
  ordinal, undecorated, data, and renamed).
