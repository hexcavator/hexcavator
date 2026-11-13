//! Times the phases of laying out every type of a PDB:
//! `cargo run --release -p hexcavator-pdb --example layout_timing -- <pdb>`.

fn main() {
    let path = std::env::args().nth(1).expect("a PDB");
    let data = std::fs::read(&path).expect("readable");
    let t = std::time::Instant::now();
    let pdb = hexcavator_pdb::Pdb::parse(&data).expect("a PDB");
    let types = pdb.types().expect("types");
    eprintln!("parse: {:?}", t.elapsed());
    let t = std::time::Instant::now();
    types.build_offsets();
    eprintln!("offsets: {:?}", t.elapsed());
    let t = std::time::Instant::now();
    let n = types.iter().filter(|(_, r)| r.udt().is_some()).count();
    eprintln!("udt scan ({n}): {:?}", t.elapsed());
    let t = std::time::Instant::now();
    let all = hexcavator_codeview::layout::all(types);
    eprintln!("layouts ({}): {:?}", all.len(), t.elapsed());
}
