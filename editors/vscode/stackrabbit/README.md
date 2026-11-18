# Stackrabbit

A fast performance trace viewer for VS Code. Open a Windows ETW trace
(`.etl`) and explore where the time went: CPU usage, sampled or precise,
and waits, as stack trees grouped by process, thread or processor.

Stackrabbit is a preview. It aims to do what Windows Performance Analyzer
does, with every click answered at once.

## Using it

Open an `.etl` file: it opens in Stackrabbit. The first time, the trace is
imported (on every core) and an index is saved beside it
(`trace.etl.hxtrace`), so it opens again at once.

- **Weigh**: CPU usage (sampled), CPU usage (precise: how long threads ran
  after being switched in), or waits (how long threads waited before
  running).
- **Group by**: process, thread, both, processor, or nothing.
- **Frames**: by function (with symbols from `_NT_SYMBOL_PATH`), by module,
  or by address.
- **Callers**: the inverted tree, from the innermost frames out.

In the tree: arrow keys move and expand, Enter toggles, and `*` (or the Hot
path button) expands the heaviest path under the selected row.

## The engine

The extension runs `stackrabbit serve`, the engine in this repository's
`apps/stackrabbit`. The `stackrabbit.path` setting picks a different build;
without it, the extension uses the engine it ships with, or, in this
repository, `target/release` or `target/debug`.
