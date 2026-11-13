//! Lists the debug symbols whose names contain a string, with their
//! modules: `symfind <pdb> <text>`.

use hexcavator_debuginfo::DebugInfo;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [pdb, text] = args.as_slice() else {
        eprintln!("usage: symfind <pdb> <text>");
        std::process::exit(2);
    };
    let map = hexcavator_mmap::Mmap::open(std::path::Path::new(pdb)).expect("pdb");
    let debug = DebugInfo::parse(&map).expect("parse pdb");
    let comps = debug.compilands().unwrap();
    for s in debug
        .symbols()
        .unwrap()
        .iter()
        .filter(|s| s.name.contains(text.as_str()))
    {
        let m = s.compiland.map(|c| comps[c as usize].name.as_str());
        println!(
            "{:?} {:08x} {:?} {} type={:#x} module={m:?}",
            s.kind, s.addr, s.size, s.name, s.type_index
        );
    }
}
