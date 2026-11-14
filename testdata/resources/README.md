# Resource test images

`tools/resources/build.cmd` builds them, for `hexc resources`
(`apps/hexcavator/tests/it/resources.rs`):

- `resources.exe`: `resources.c` (a stand-in) with `resources.rc`'s
  resources, built with MSVC for x64: version information, a manifest, an
  icon group (a 16×16 bitmap and a 32×32 PNG), a cursor group (its hot spot
  at 5,7), a bitmap, a menu and a shortcut menu (`MENUEX`), accelerators,
  a `DIALOGEX` and a classic dialog, string tables (in English and German;
  `rc /n` ends each string with a NUL), a message table (`messages.mc`),
  HTML, and raw data under a name and a type of its own. The images are
  drawn by `images.py`.
- `resources-x86_64-linux-gnu`: `unix.c`, linked with `ld.lld`: an ABI tag
  note, a build ID, package metadata (`--package-metadata`), `.comment`.
- `resources-arm64`: a Mach-O program with an Info.plist
  (`-sectcreate __TEXT __info_plist`), its ad-hoc signature given
  entitlements by `entitle.py` (so it no longer verifies: its hashes
  aren't redone).
