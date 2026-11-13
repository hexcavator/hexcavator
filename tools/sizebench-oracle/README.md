# sizebench-oracle

Prints SizeBench's analysis of a binary as sorted text lines (format at the
top of `Program.cs`), to test `hexc`'s size analysis against it.

Requires a SizeBench checkout (<https://github.com/microsoft/SizeBench>) and
the .NET SDK. Give the checkout's location with
`-p:SizeBenchSrc=<path to SizeBench\src>`. Build from this directory
(SizeBench's own `global.json` pins an older SDK, so don't build from there):

    dotnet build -c Release -p:SizeBenchSrc=<path to SizeBench\src>
    bin\Release\net10.0-windows10.0.17763\win-x64\sizebench-oracle.exe <image> <pdb>

`testdata/sizebench/oracle` holds its output for the binaries in
`testdata/sizebench/bin`. With `--findings` it prints SizeBench's analyses
instead (duplicate data so far); `testdata/sizebench/findings` holds those.
