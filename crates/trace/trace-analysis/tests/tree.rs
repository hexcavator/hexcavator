//! Stack trees over a small trace built by hand.

use hexcavator_trace::{
    Clock, Image, ImageIx, Process, ProcessIx, StackId, Thread, ThreadIx, Trace,
};
use hexcavator_trace_analysis::{
    Filter, FrameMode, Framer, GroupBy, Key, KeyId, Keys, NoSymbols, NodeId, Precise, Resolver,
    SwitchWeight, Symbolizer, Tree, label, sources,
};

/// Functions are 0x100 bytes each: the function at `offset` starts at
/// `offset & !0xff`, named `f<start>`.
struct Fixed;

impl Symbolizer for Fixed {
    fn function(&self, _: &Trace, _: ImageIx, offset: u64) -> Option<(u64, String)> {
        let start = offset & !0xff;
        Some((start, format!("f{start:x}")))
    }
}

const APP: u64 = 0x1000_0000;
const LIB: u64 = 0x2000_0000;
const KERNEL: u64 = 0xffff_f800_0000_0000;

/// Process 10 (app.exe) has threads 1 and 2; app.exe, lib.dll and a kernel
/// driver are loaded.
fn trace() -> Trace {
    let mut t = Trace::new(
        Clock {
            ticks_per_second: 1000,
            origin: 0,
        },
        2,
    );
    t.processes.push(Process {
        pid: 10,
        name: "app.exe".into(),
        ..Process::default()
    });
    for tid in [1, 2] {
        t.threads.push(Thread {
            tid,
            process: ProcessIx(0),
            name: None,
            start_address: 0,
            start: None,
            end: None,
        });
    }
    for (process, base, path) in [
        (ProcessIx(0), APP, r"C:\app.exe"),
        (ProcessIx(0), LIB, r"C:\lib.dll"),
        (ProcessIx::NONE, KERNEL, r"\SystemRoot\ntoskrnl.exe"),
    ] {
        t.images.push(Image {
            process,
            base,
            size: 0x10_0000,
            path: path.into(),
            time_date_stamp: 0,
            checksum: 0,
            debug_id: None,
            load: None,
            unload: None,
        });
    }
    t
}

/// Adds a sample of `thread` at `time` with `frames` (innermost first).
fn sample(t: &mut Trace, time: i64, thread: u32, frames: &[u64]) {
    let stack = t.stacks.intern_innermost_first(frames);
    let s = &mut t.samples;
    s.time.push(time);
    s.cpu.push(0);
    s.thread.push(ThreadIx(thread));
    s.ip.push(frames.first().copied().unwrap_or(0));
    s.stack.push(stack);
    s.weight.push(1);
}

/// main (APP+0x10) calls work (APP+0x210), which calls lib (LIB+0x20) or
/// spins (APP+0x250); thread 1 also calls into the kernel.
fn sampled() -> Trace {
    let mut t = trace();
    sample(&mut t, 1, 0, &[LIB + 0x20, APP + 0x210, APP + 0x10]);
    sample(&mut t, 2, 0, &[LIB + 0x24, APP + 0x214, APP + 0x11]);
    sample(&mut t, 3, 0, &[APP + 0x250, APP + 0x10]);
    sample(
        &mut t,
        4,
        1,
        &[KERNEL + 5, LIB + 0x20, APP + 0x210, APP + 0x10],
    );
    t
}

/// Labels of the children of `node`, with inclusive and exclusive weights.
fn level(tree: &mut Tree, keys: &Keys, t: &Trace, node: NodeId) -> Vec<(String, u64, u64)> {
    let children = tree.children(node).to_vec();
    children
        .into_iter()
        .map(|c| {
            (
                label(t, keys.get(tree.key(c).unwrap()), &Fixed),
                tree.inclusive(c),
                tree.exclusive(c),
            )
        })
        .collect()
}

fn child(tree: &mut Tree, keys: &Keys, t: &Trace, node: NodeId, name: &str) -> NodeId {
    let children = tree.children(node).to_vec();
    children
        .into_iter()
        .find(|&c| label(t, keys.get(tree.key(c).unwrap()), &Fixed) == name)
        .unwrap_or_else(|| panic!("no {name}"))
}

fn owned(v: &[(&str, u64, u64)]) -> Vec<(String, u64, u64)> {
    v.iter().map(|&(s, a, b)| (s.to_string(), a, b)).collect()
}

#[test]
fn top_down_by_function() {
    let t = sampled();
    let resolver = Resolver::new(&t);
    let mut framer = Framer::new(&t, &resolver, &Fixed, FrameMode::Function);
    let mut keys = Keys::default();
    let inst = sources::samples(
        &t,
        &mut framer,
        &mut keys,
        &[GroupBy::Process],
        &Filter::default(),
    );
    let mut tree = Tree::new(inst);
    assert_eq!(tree.inclusive(NodeId::ROOT), 4);
    assert_eq!(
        level(&mut tree, &keys, &t, NodeId::ROOT),
        owned(&[("app.exe (10)", 4, 0)])
    );
    let p = child(&mut tree, &keys, &t, NodeId::ROOT, "app.exe (10)");
    assert_eq!(
        level(&mut tree, &keys, &t, p),
        owned(&[("app.exe!f0", 4, 0)])
    );
    let main = child(&mut tree, &keys, &t, p, "app.exe!f0");
    assert_eq!(
        level(&mut tree, &keys, &t, main),
        owned(&[("app.exe!f200", 4, 1)])
    );
    let work = child(&mut tree, &keys, &t, main, "app.exe!f200");
    assert_eq!(
        level(&mut tree, &keys, &t, work),
        owned(&[("lib.dll!f0", 3, 2)])
    );
    let lib = child(&mut tree, &keys, &t, work, "lib.dll!f0");
    assert_eq!(
        level(&mut tree, &keys, &t, lib),
        owned(&[("ntoskrnl.exe!f0", 1, 1)])
    );
    // The hot path from the process follows the heaviest children.
    let hot = tree.hot_path(p, 0.5);
    // main, work, lib; the kernel frame under lib holds too little.
    assert_eq!(hot.len(), 3);
    assert_eq!(tree.depth(*hot.last().unwrap()), 4);
}

#[test]
fn inverted_and_focused() {
    let t = sampled();
    let resolver = Resolver::new(&t);
    let mut framer = Framer::new(&t, &resolver, &Fixed, FrameMode::Function);
    let mut keys = Keys::default();
    let inst = sources::samples(&t, &mut framer, &mut keys, &[], &Filter::default());

    // Inverted: where time was spent, then callers. (A node's own weight
    // is what ends there: in an inverted tree, outermost frames.)
    let mut tree = Tree::new(inst.inverted());
    assert_eq!(
        level(&mut tree, &keys, &t, NodeId::ROOT),
        owned(&[
            ("lib.dll!f0", 2, 0),
            ("app.exe!f200", 1, 0),
            ("ntoskrnl.exe!f0", 1, 0)
        ])
    );
    let main = keys
        .find(&Key::Frame {
            image: ImageIx(0),
            offset: 0,
        })
        .unwrap();
    let lib_node = tree.children(NodeId::ROOT)[0];
    let work_node = tree.children(lib_node)[0];
    let main_node = tree.children(work_node)[0];
    assert_eq!(
        (tree.key(main_node), tree.exclusive(main_node)),
        (Some(main), 2)
    );

    // Callers of lib's function: itself, then work, then main.
    let lib = keys
        .find(&Key::Frame {
            image: ImageIx(1),
            offset: 0,
        })
        .unwrap();
    let mut tree = Tree::new(inst.callers(lib));
    assert_eq!(tree.inclusive(NodeId::ROOT), 3);
    let l = child(&mut tree, &keys, &t, NodeId::ROOT, "lib.dll!f0");
    assert_eq!(
        level(&mut tree, &keys, &t, l),
        owned(&[("app.exe!f200", 3, 0)])
    );

    // Callees of work: lib (and the kernel under it), and its own time.
    let work = keys
        .find(&Key::Frame {
            image: ImageIx(0),
            offset: 0x200,
        })
        .unwrap();
    let mut tree = Tree::new(inst.callees(work));
    let w = child(&mut tree, &keys, &t, NodeId::ROOT, "app.exe!f200");
    assert_eq!(tree.exclusive(w), 1);
    assert_eq!(
        level(&mut tree, &keys, &t, w),
        owned(&[("lib.dll!f0", 3, 2)])
    );
}

#[test]
fn recursion_is_merged_in_focused_views() {
    let mut t = trace();
    // f100 -> f200 -> f100 -> f300 (innermost last).
    sample(
        &mut t,
        1,
        0,
        &[APP + 0x310, APP + 0x110, APP + 0x210, APP + 0x110],
    );
    let resolver = Resolver::new(&t);
    let mut framer = Framer::new(&t, &resolver, &Fixed, FrameMode::Function);
    let mut keys = Keys::default();
    let inst = sources::samples(&t, &mut framer, &mut keys, &[], &Filter::default());
    let f100 = keys
        .find(&Key::Frame {
            image: ImageIx(0),
            offset: 0x100,
        })
        .unwrap();
    // Callees from the outermost f100: the whole recursion below it.
    let callees = inst.callees(f100);
    assert_eq!(callees.keys(0).len(), 4);
    // Callers from the innermost f100: f200, then the outer f100.
    let callers = inst.callers(f100);
    let labels: Vec<String> = callers
        .keys(0)
        .iter()
        .map(|&k: &KeyId| label(&t, keys.get(k), &Fixed))
        .collect();
    assert_eq!(labels, ["app.exe!f100", "app.exe!f200", "app.exe!f100"]);
}

#[test]
fn by_module_collapses_runs() {
    let t = sampled();
    let resolver = Resolver::new(&t);
    let mut framer = Framer::new(&t, &resolver, &NoSymbols, FrameMode::Module);
    let mut keys = Keys::default();
    let inst = sources::samples(
        &t,
        &mut framer,
        &mut keys,
        &[GroupBy::Thread],
        &Filter::default(),
    );
    let mut tree = Tree::new(inst);
    let t0 = child(&mut tree, &keys, &t, NodeId::ROOT, "Thread 1");
    assert_eq!(
        level(&mut tree, &keys, &t, t0),
        owned(&[("app.exe!<module>", 3, 1)])
    );
    let app = child(&mut tree, &keys, &t, t0, "app.exe!<module>");
    // app.exe's three frames are one node; the spin sample ends in it.
    assert_eq!(tree.exclusive(app), 1);
    assert_eq!(
        level(&mut tree, &keys, &t, app),
        owned(&[("lib.dll!<module>", 2, 2)])
    );
}

#[test]
fn by_address_and_unknown_frames() {
    let mut t = trace();
    sample(&mut t, 1, 0, &[0x5555, APP + 0x10]);
    let resolver = Resolver::new(&t);
    let mut framer = Framer::new(&t, &resolver, &NoSymbols, FrameMode::Address);
    let mut keys = Keys::default();
    let inst = sources::samples(&t, &mut framer, &mut keys, &[], &Filter::default());
    let mut tree = Tree::new(inst);
    // (Labels here come from the test's symbolizer.)
    let app = child(&mut tree, &keys, &t, NodeId::ROOT, "app.exe!f0+0x10");
    assert_eq!(level(&mut tree, &keys, &t, app), owned(&[("0x5555", 1, 1)]));
}

#[test]
fn filters() {
    let t = sampled();
    let resolver = Resolver::new(&t);
    let mut framer = Framer::new(&t, &resolver, &Fixed, FrameMode::Function);
    let mut keys = Keys::default();
    let by_time = Filter {
        time: Some((2, 4)),
        ..Filter::default()
    };
    let inst = sources::samples(&t, &mut framer, &mut keys, &[], &by_time);
    assert_eq!(inst.total(), 2);
    let by_thread = Filter {
        threads: Some([ThreadIx(1)].into_iter().collect()),
        ..Filter::default()
    };
    let inst = sources::samples(&t, &mut framer, &mut keys, &[], &by_thread);
    assert_eq!(inst.total(), 1);
    let by_process = Filter {
        processes: Some([ProcessIx(5)].into_iter().collect()),
        ..Filter::default()
    };
    assert!(sources::samples(&t, &mut framer, &mut keys, &[], &by_process).is_empty());
}

#[test]
fn samples_without_stacks_use_the_instruction_pointer() {
    let mut t = trace();
    sample(&mut t, 1, 0, &[]);
    t.samples.ip[0] = LIB + 0x30;
    t.samples.stack[0] = StackId::EMPTY;
    let resolver = Resolver::new(&t);
    let mut framer = Framer::new(&t, &resolver, &Fixed, FrameMode::Function);
    let mut keys = Keys::default();
    let mut tree = Tree::new(sources::samples(
        &t,
        &mut framer,
        &mut keys,
        &[],
        &Filter::default(),
    ));
    assert_eq!(
        level(&mut tree, &keys, &t, NodeId::ROOT),
        owned(&[("lib.dll!f0", 1, 1)])
    );
}

#[test]
fn precise_times() {
    let mut t = trace();
    let wait = t
        .stacks
        .intern_innermost_first(&[KERNEL + 0x100, APP + 0x10]);
    // cpu 0: thread 0 in at 10, thread 1 in at 15, thread 0 in at 40.
    for (time, new, old, stack) in [
        (10, 0, 1, StackId::EMPTY),
        (15, 1, 0, StackId::EMPTY),
        (40, 0, 1, wait),
    ] {
        let sw = &mut t.switches;
        sw.time.push(time);
        sw.cpu.push(0);
        sw.new_thread.push(ThreadIx(new));
        sw.old_thread.push(ThreadIx(old));
        sw.new_priority.push(0);
        sw.old_priority.push(0);
        sw.wait_reason.push(0);
        sw.old_state.push(0);
        sw.stack.push(stack);
        sw.ready.push(hexcavator_trace::ReadyIx::NONE);
    }
    let p = Precise::new(&t);
    assert_eq!(p.running, [5, 25, 0]);
    // Thread 0 was switched out at 15 and back in at 40.
    assert_eq!(p.waited, [0, 5, 25]);
    let resolver = Resolver::new(&t);
    let mut framer = Framer::new(&t, &resolver, &Fixed, FrameMode::Function);
    let mut keys = Keys::default();
    let waits = sources::switches(
        &t,
        &p,
        &mut framer,
        &mut keys,
        &[],
        &Filter::default(),
        SwitchWeight::Waited,
    );
    assert_eq!(waits.total(), 30);
    let mut tree = Tree::new(waits);
    let app = child(&mut tree, &keys, &t, NodeId::ROOT, "app.exe!f0");
    assert_eq!(tree.inclusive(app), 25);
    let running = sources::switches(
        &t,
        &p,
        &mut framer,
        &mut keys,
        &[],
        &Filter::default(),
        SwitchWeight::Running,
    );
    assert_eq!(running.total(), 30);
}

#[test]
fn stack_tags_group_by_the_deepest_match() {
    use hexcavator_trace_analysis::StackTags;
    let t = sampled();
    let resolver = Resolver::new(&t);
    let tags = StackTags::from_xml(
        r#"<Tag Name="">
             <Tag Name="Lib"><Entrypoint Module="lib.dll" Method="f0"/></Tag>
             <Tag Name="Work"><Entrypoint Module="app.exe" Method="f200"/></Tag>
           </Tag>"#,
    )
    .unwrap();
    let mut framer = Framer::new(&t, &resolver, &Fixed, FrameMode::Function).with_tags(tags);
    let mut keys = Keys::default();
    let inst = sources::samples(
        &t,
        &mut framer,
        &mut keys,
        &[GroupBy::StackTag],
        &Filter::default(),
    );
    let mut tree = Tree::new(inst);
    let top: Vec<(String, u64)> = tree
        .children(NodeId::ROOT)
        .to_vec()
        .into_iter()
        .map(|c| {
            (
                framer.label(keys.get(tree.key(c).unwrap())),
                tree.inclusive(c),
            )
        })
        .collect();
    // Samples 1, 2 and 4 are deepest in lib (4 goes on into the kernel,
    // which no tag names); sample 3 is deepest in work.
    assert_eq!(top, [("Lib".to_string(), 3), ("Work".to_string(), 1)]);

    // With no tag file, every stack is "Other".
    let mut plain = Framer::new(&t, &resolver, &Fixed, FrameMode::Function);
    let inst = sources::samples(
        &t,
        &mut plain,
        &mut keys,
        &[GroupBy::StackTag],
        &Filter::default(),
    );
    let mut tree = Tree::new(inst);
    let only = tree.children(NodeId::ROOT)[0];
    assert_eq!(plain.label(keys.get(tree.key(only).unwrap())), "Other");
    assert_eq!(tree.inclusive(only), 4);
}

#[test]
fn folding_collapses_runs() {
    use hexcavator_trace_analysis::Folds;
    let t = sampled();
    let resolver = Resolver::new(&t);
    let folds = Folds::from_text("fold App module=app.exe").unwrap();
    let mut framer = Framer::new(&t, &resolver, &Fixed, FrameMode::Function).with_folds(folds);
    let mut keys = Keys::default();
    let inst = sources::samples(&t, &mut framer, &mut keys, &[], &Filter::default());
    let mut tree = Tree::new(inst);
    let app = tree.children(NodeId::ROOT)[0];
    assert_eq!(framer.label(keys.get(tree.key(app).unwrap())), "[App]");
    assert_eq!((tree.inclusive(app), tree.exclusive(app)), (4, 1));
    let under: Vec<String> = tree
        .children(app)
        .to_vec()
        .into_iter()
        .map(|c| framer.label(keys.get(tree.key(c).unwrap())))
        .collect();
    assert_eq!(under, ["lib.dll!f0"]);
}

/// Like `Fixed`, with a call to `inl` inlined at 0x260..0x270 of every
/// image.
struct WithInline;

impl Symbolizer for WithInline {
    fn function(&self, t: &Trace, i: ImageIx, offset: u64) -> Option<(u64, String)> {
        Fixed.function(t, i, offset)
    }
    fn inlines(&self, _: &Trace, _: ImageIx, offset: u64) -> Vec<(u32, String)> {
        if (0x260..0x270).contains(&offset) {
            vec![(7, "inl".to_string())]
        } else {
            Vec::new()
        }
    }
    fn inline_name(&self, _: &Trace, _: ImageIx, site: u32) -> Option<String> {
        (site == 7).then(|| "inl".to_string())
    }
}

#[test]
fn inlined_calls_are_nodes() {
    let mut t = trace();
    // lib's f0 called from inside the inlined call in app's f200.
    sample(&mut t, 1, 0, &[LIB + 0x20, APP + 0x265, APP + 0x10]);
    // A sample in f200 outside the inlined code.
    sample(&mut t, 2, 0, &[APP + 0x240, APP + 0x10]);
    let resolver = Resolver::new(&t);
    let mut framer = Framer::new(&t, &resolver, &WithInline, FrameMode::Function);
    let mut keys = Keys::default();
    let inst = sources::samples(&t, &mut framer, &mut keys, &[], &Filter::default());
    let mut tree = Tree::new(inst);
    let name = |tree: &Tree, n: NodeId| label(&t, keys.get(tree.key(n).unwrap()), &WithInline);
    let main = tree.children(NodeId::ROOT)[0];
    let work = tree.children(main)[0];
    assert_eq!(name(&tree, work), "app.exe!f200");
    assert_eq!((tree.inclusive(work), tree.exclusive(work)), (2, 1));
    let inl = tree.children(work)[0];
    assert_eq!(name(&tree, inl), "app.exe!inl (inlined)");
    let lib = tree.children(inl)[0];
    assert_eq!(name(&tree, lib), "lib.dll!f0");
}
