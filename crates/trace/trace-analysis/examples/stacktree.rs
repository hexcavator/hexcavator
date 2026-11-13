//! Prints a trace's stack trees, by module, with timings:
//! CPU usage (sampled) by process and stack, inverted, and waits.
//!
//!     cargo run --release -p hexcavator-trace-analysis --example stacktree -- trace.etl
//!
//! The output names processes and modules, so it is for your own traces.

use std::time::Instant;

use hexcavator_etl::Etl;
use hexcavator_symbolize::SymbolPath;
use hexcavator_trace::{Trace, etw};
use hexcavator_trace_analysis::{
    Filter, FrameMode, Framer, GroupBy, Keys, NodeId, PdbSymbolizer, Precise, Resolver,
    SwitchWeight, Symbolizer, Tree, label, sources,
};

#[allow(clippy::too_many_arguments)]
fn print(
    tree: &mut Tree,
    trace: &Trace,
    keys: &Keys,
    symbols: &dyn Symbolizer,
    node: NodeId,
    depth: usize,
    max_depth: usize,
    unit: &str,
) {
    let children: Vec<NodeId> = tree.children(node).iter().take(4).copied().collect();
    let total = tree.inclusive(NodeId::ROOT).max(1);
    for c in children {
        let k = keys.get(tree.key(c).unwrap());
        #[allow(clippy::cast_precision_loss)]
        let pct = 100.0 * tree.inclusive(c) as f64 / total as f64;
        println!(
            "{:indent$}{:<50} {:>12} {unit} {pct:6.2}%  self {}",
            "",
            label(trace, k, symbols),
            tree.inclusive(c),
            tree.exclusive(c),
            indent = 2 * depth
        );
        if depth + 1 < max_depth {
            print(tree, trace, keys, symbols, c, depth + 1, max_depth, unit);
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: stacktree trace.etl")?;
    let map = hexcavator_mmap::Mmap::open(path)?;
    let etl = Etl::parse(&map)?;
    let t = Instant::now();
    let (trace, _) = etw::import(&etl)?;
    println!("import {:.2} s", t.elapsed().as_secs_f64());

    let resolver = Resolver::new(&trace);
    // Functions from the PDBs found on this machine; images without one
    // show as whole modules.
    let symbols = PdbSymbolizer::new(SymbolPath::from_env());
    let mut framer = Framer::new(&trace, &resolver, &symbols, FrameMode::Function);
    let mut keys = Keys::default();

    let t = Instant::now();
    let inst = sources::samples(
        &trace,
        &mut framer,
        &mut keys,
        &[GroupBy::Process],
        &Filter::default(),
    );
    println!(
        "\nCPU (sampled): {} distinct stacks in {:.3} s",
        inst.len(),
        t.elapsed().as_secs_f64()
    );
    let inverted = inst.inverted();
    let mut tree = Tree::new(inst);
    let t = Instant::now();
    print(
        &mut tree,
        &trace,
        &keys,
        &symbols,
        NodeId::ROOT,
        0,
        3,
        "samples",
    );
    let first = tree.children(NodeId::ROOT)[0];
    let hot = tree.hot_path(first, 0.5);
    for &n in &hot {
        println!(
            "  hot: {}",
            label(&trace, keys.get(tree.key(n).unwrap()), &symbols)
        );
    }
    println!(
        "hot path under the top process: {} levels; expanding took {:.3} s",
        hot.len(),
        t.elapsed().as_secs_f64()
    );

    println!("\nCPU (sampled), inverted:");
    let mut tree = Tree::new(inverted);
    print(
        &mut tree,
        &trace,
        &keys,
        &symbols,
        NodeId::ROOT,
        0,
        3,
        "samples",
    );

    let t = Instant::now();
    let precise = Precise::new(&trace);
    let inst = sources::switches(
        &trace,
        &precise,
        &mut framer,
        &mut keys,
        &[GroupBy::Process],
        &Filter::default(),
        SwitchWeight::Waited,
    );
    println!(
        "\nWaits: {} distinct stacks in {:.3} s",
        inst.len(),
        t.elapsed().as_secs_f64()
    );
    let mut tree = Tree::new(inst);
    print(
        &mut tree,
        &trace,
        &keys,
        &symbols,
        NodeId::ROOT,
        0,
        2,
        "ticks",
    );
    let (looked, found) = symbols.loaded();
    println!(
        "
PDBs: {found} found of {looked} looked for"
    );
    Ok(())
}
