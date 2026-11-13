# SizeBench test data

`bin/` holds test binaries (PE images, PDBs, linker maps, an import library)
copied unmodified from Microsoft's SizeBench repository,
<https://github.com/microsoft/SizeBench>, directory `src/TestPEs`, at commit
`8d884866ab90ea596f47c7121fa2c331f99c6619` (2026-07-14). They are
distributed under SizeBench's MIT license, reproduced in [`LICENSE`](LICENSE).
[`Readme - AnalysisEngine PE Files.txt`](<Readme - AnalysisEngine PE Files.txt>)
(from `src/TestPEProjects`) describes what each binary exercises.

`oracle/` holds the output of `tools/sizebench-oracle` (SizeBench's analysis
engine, run over each binary in `bin/`). hexc's size analysis is tested
against it. Two binaries have no oracle output, because SizeBench rejects
them by design: `Dllx64Managed` (managed code) and `Dllx64MinimalPDB`
(`/DEBUG:FASTLINK` PDB).

Not copied: SizeBench's `TestPEs/External` binaries (Microsoft.UI.Xaml,
ReactNativeXaml; 317 MB). Tests that use them read them from a SizeBench
checkout named by `HEXC_SIZEBENCH_DIR` and are skipped otherwise.

To regenerate `oracle/`, build `tools/sizebench-oracle` and run it over each
image and PDB pair (see that tool's README).
