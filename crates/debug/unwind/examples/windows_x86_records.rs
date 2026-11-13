//! Prints a PDB's x86 frame records near an RVA, and the public symbol at
//! it (a diagnostic).
//! `cargo run -p hexcavator-unwind --example windows_x86_records -- PDB RVA`
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let data = std::fs::read(&args[1]).unwrap();
    let rva = u32::from_str_radix(args[2].trim_start_matches("0x"), 16).unwrap();
    let pdb = hexcavator_pdb::Pdb::parse(&data).unwrap();
    let dbi = pdb.dbi().unwrap();
    let names = pdb.names().unwrap();
    // The public symbol at or before the RVA (in the first section, .text).
    let sections = pdb.sections().unwrap();
    if let Some((va, _, _)) = sections.first()
        && let Ok(Some((sym, off))) = pdb.public_at(1, rva - va)
    {
        println!(
            "{}+{off:#x}",
            String::from_utf8_lossy(sym.name().unwrap_or(b"?"))
        );
    }
    for (which, label) in [(0, "FPO"), (9, "FrameData")] {
        let Some(i) = dbi.debug_stream(which) else {
            println!("{label}: no stream");
            continue;
        };
        let s = pdb.msf().stream(i).unwrap();
        println!("{label}: stream {i}, {} bytes", s.len());
        if which == 0 {
            for f in hexcavator_unwind::windows_x86::Fpo::parse(&s) {
                if f.start.abs_diff(rva) < 0x80 {
                    println!("  {f:?}");
                }
            }
        } else {
            for d in hexcavator_unwind::windows_x86::FrameData::parse(&s) {
                if d.start.abs_diff(rva) < 0x80 {
                    println!("  {d:?} {:?}", names.get_str(d.program));
                }
            }
        }
    }
}
