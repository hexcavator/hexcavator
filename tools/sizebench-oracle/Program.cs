// sizebench-oracle <binary> <pdb>
//
// Prints SizeBench's view of a binary as sorted text lines, for comparison
// with hexc. Numbers are decimal except RVAs (hex). Line kinds:
//   SECTION <name> rva=<hex> size=<n> vsize=<n> vsizepad=<n> chars=<hex>
//   COFFGROUP <section> <name> rva=<hex> size=<n> vsize=<n> vsizepad=<n> chars=<hex>
//   LIB <name> size=<n> vsize=<n>
//   LIBSECTION <lib> <section> size=<n> vsize=<n>
//   LIBCOFFGROUP <lib> <group> size=<n> vsize=<n>
//   COMPILAND <lib> | <name> size=<n> vsize=<n>
//   COMPILANDSECTION <lib> | <compiland> | <section> size=<n> vsize=<n>
//   COMPILANDCOFFGROUP <lib> | <compiland> | <group> size=<n> vsize=<n>
//   RANGE <lib> | <compiland> <rva-hex> <vsize> <virtual 0|1>
//   SYMBOL <rva-hex> size=<n> vsize=<n> <kind> <folded 0|1> <name>
//
// With --findings, SizeBench's analyses instead:
//   DUPDATA <name> size=<n> vsize=<n> copies=<n> wasted=<n> | <compiland> | ...
//   WASTEFUL <type> wasted=<n> perslot=<n> | pure:<function> ... | unoverridden:<function> ...
using SizeBench.AnalysisEngine;
using SizeBench.AnalysisEngine.Symbols;
using SizeBench.Logging;

if (args.Length != 2 && !(args.Length == 3 && args[2] == "--findings"))
{
    Console.Error.WriteLine("usage: sizebench-oracle <binary> <pdb> [--findings]");
    return 2;
}

var lines = new List<string>();
var token = CancellationToken.None;
if (args.Length == 3)
{
    await using var findings = await Session.Create(args[0], args[1], new NoOpLogger());
    foreach (var d in await findings.EnumerateDuplicateDataItems(token))
    {
        var compilands = string.Join(" | ", d.ReferencedIn.Select(c => c.Name).OrderBy(n => n, StringComparer.Ordinal));
        lines.Add($"DUPDATA {d.Symbol.Name} size={d.Symbol.Size} vsize={d.Symbol.VirtualSize} copies={d.ReferencedIn.Count} wasted={d.WastedSize} | {compilands}");
    }
    foreach (var v in await findings.EnumerateWastefulVirtuals(token))
    {
        var flags = WastefulVirtualItem.NameFormattingForWastedOverrides;
        var pure = v.WastedOverridesPureWithExactlyOneOverride.Select(f => "pure:" + f.FormattedName.GetFormattedName(flags)).OrderBy(n => n, StringComparer.Ordinal);
        var plain = v.WastedOverridesNonPureWithNoOverrides.Select(f => "unoverridden:" + f.FormattedName.GetFormattedName(flags)).OrderBy(n => n, StringComparer.Ordinal);
        lines.Add($"WASTEFUL {v.UserDefinedType.Name} wasted={v.WastedSize} perslot={v.WastePerSlot} | {string.Join(" | ", pure.Concat(plain))}");
    }
    lines.Sort(StringComparer.Ordinal);
    var w = new StreamWriter(Console.OpenStandardOutput(), new System.Text.UTF8Encoding(false)) { NewLine = "\n" };
    foreach (var l in lines) w.WriteLine(l);
    w.Flush();
    return 0;
}
await using (var session = await Session.Create(args[0], args[1], new NoOpLogger()))
{
    var sections = await session.EnumerateBinarySectionsAndCOFFGroups(token);
    foreach (var s in sections)
    {
        lines.Add($"SECTION {s.Name} rva={s.RVA:x} size={s.Size} vsize={s.VirtualSize} vsizepad={s.VirtualSizeIncludingPadding} chars={(uint)s.Characteristics:x}");
        foreach (var g in s.COFFGroups)
        {
            lines.Add($"COFFGROUP {s.Name} {g.Name} rva={g.RVA:x} size={g.Size} vsize={g.VirtualSize} vsizepad={g.VirtualSizeIncludingPadding} chars={(uint)g.Characteristics:x}");
        }
    }

    foreach (var lib in await session.EnumerateLibs(token))
    {
        lines.Add($"LIB {lib.Name} size={lib.Size} vsize={lib.VirtualSize}");
        foreach (var (name, c) in lib.SectionContributionsByName)
            lines.Add($"LIBSECTION {lib.Name} | {name} size={c.Size} vsize={c.VirtualSize}");
        foreach (var (name, c) in lib.COFFGroupContributionsByName)
            lines.Add($"LIBCOFFGROUP {lib.Name} | {name} size={c.Size} vsize={c.VirtualSize}");
        foreach (var comp in lib.Compilands.Values)
        {
            var id = $"{lib.Name} | {comp.Name}";
            lines.Add($"COMPILAND {id} size={comp.Size} vsize={comp.VirtualSize}");
            foreach (var (name, c) in comp.SectionContributionsByName)
            {
                lines.Add($"COMPILANDSECTION {id} | {name} size={c.Size} vsize={c.VirtualSize}");
                foreach (var r in c.RVARanges)
                    lines.Add($"RANGE {id} {r.RVAStart:x8} {r.VirtualSize} {(r.IsVirtualSize ? 1 : 0)}");
            }
            foreach (var (name, c) in comp.COFFGroupContributionsByName)
                lines.Add($"COMPILANDCOFFGROUP {id} | {name} size={c.Size} vsize={c.VirtualSize}");
        }
    }

    foreach (var s in sections)
    {
        foreach (var sym in await session.EnumerateSymbolsInBinarySection(s, token))
        {
            var folded = sym is Symbol { IsCOMDATFolded: true } ? 1 : 0;
            lines.Add($"SYMBOL {sym.RVA:x8} size={sym.Size} vsize={sym.VirtualSize} {sym.GetType().Name} {folded} {sym.Name}");
        }
    }
}

lines.Sort(StringComparer.Ordinal);
var stdout = new StreamWriter(Console.OpenStandardOutput(), new System.Text.UTF8Encoding(false)) { NewLine = "\n" };
foreach (var l in lines) stdout.WriteLine(l);
stdout.Flush();
return 0;
