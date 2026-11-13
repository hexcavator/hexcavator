//! Prints what the DWARF backend reads of a file (for checking against
//! llvm-dwarfdump by eye).

fn main() {
    let path = std::env::args().nth(1).expect("a file");
    let data = std::fs::read(&path).unwrap();
    let d = hexcavator_debuginfo::DebugInfo::parse(&data).unwrap();
    println!("compilands {:?}", d.compilands().unwrap());
    println!("contributions {:x?}", d.contributions().unwrap());
    let lines = d.source_lines().unwrap();
    println!("files {:?}", lines.files);
    for l in &lines.spans {
        println!("  line {:#x}+{} {}:{}", l.addr, l.size, l.file, l.line);
    }
    for s in d.symbols().unwrap() {
        println!(
            "sym {:?} {:#x} {:?} {} global={} tls={} parent={:x?} ty={:#x} {:?}",
            s.kind,
            s.addr,
            s.size,
            s.name,
            s.global,
            s.thread_local,
            s.parent,
            s.type_index,
            s.function.map(|f| (f.name, f.params))
        );
        if s.type_index != 0 {
            let t = hexcavator_debuginfo::TypeRef(s.type_index);
            println!("   shape {:?} size {:?}", d.type_shape(t), d.type_size(t));
        }
        if s.kind == hexcavator_debuginfo::SymbolKind::Function
            && let Ok(Some(v)) = d.variables(s.compiland, s.addr)
        {
            for var in v.variables {
                println!(
                    "   var {} param={} inl={} {:x?}",
                    var.name, var.param, var.inlined, var.ranges
                );
            }
        }
    }
    let inl = d.inline_sites().unwrap();
    println!("inlinees {:?}", inl.inlinees);
    for s in inl.sites {
        println!("  site {s:?}");
    }
    for c in d.classes().unwrap() {
        println!("class {c:?}");
    }
    for l in d.layouts().unwrap() {
        println!(
            "layout {} ({} bytes, {} wasted, key {})",
            l.name,
            l.size,
            l.waste(),
            l.key
        );
        for p in &l.parts {
            println!(
                "   {:>4} {:>4} {:?} {:?} {} {}",
                p.offset, p.size, p.kind, p.bits, p.name, p.type_name
            );
        }
    }
}
