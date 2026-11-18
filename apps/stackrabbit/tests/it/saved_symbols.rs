//! Symbol names saved beside a trace's index: a trace reopens with its
//! functions named, without its PDBs.

use std::collections::HashMap;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use hexcavator_symbolize::{FunctionTable, SymbolPath};
use hexcavator_trace::index;
use hexcavator_trace_analysis::{NodeId, PdbSymbolizer, Resolver};
use serde_json::{Value, json};
use stackrabbit::protocol::{Frame, read_frame, write_frame};
use stackrabbit::serve::{Output, serve};
use stackrabbit::store;
use stackrabbit::symbols;
use stackrabbit::views::{TreeSpec, TreeView};

use crate::common::{scratch, small};

fn lines_pdb() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/lines/lines.pdb")
}

/// A session's answers by ID, and its notifications.
fn session(requests: &[Value]) -> (HashMap<u64, Value>, Vec<Value>) {
    let mut input = Vec::new();
    for (i, r) in requests.iter().enumerate() {
        let mut r = r.clone();
        r["id"] = json!(i + 1);
        write_frame(&mut input, &Frame::new(r)).unwrap();
    }
    let sink = Arc::new(Mutex::new(Vec::<u8>::new()));
    let out: Output = sink.clone();
    serve(Cursor::new(input), &out).unwrap();
    let data = sink.lock().unwrap().clone();
    let mut r = Cursor::new(data);
    let (mut answers, mut notes) = (HashMap::new(), Vec::new());
    while let Some(f) = read_frame(&mut r).unwrap() {
        match f.header["id"].as_u64() {
            Some(id) => {
                answers.insert(id, f.header);
            }
            None => notes.push(f.header),
        }
    }
    (answers, notes)
}

fn result(answers: &HashMap<u64, Value>, id: u64) -> &Value {
    let a = &answers[&id];
    assert!(a.get("error").is_none(), "request {id}: {a}");
    &a["result"]
}

/// A synthetic trace in `dir` one of whose executables' PDB is
/// `lines.pdb` (its GUID put in the trace's), and a symbol cache holding
/// it: the executable's file name and the cache.
fn trace_with_a_real_pdb(dir: &Path) -> (PathBuf, String, PathBuf) {
    let mut s = hexcavator_trace_synth::generate(&small());
    let pdb = std::fs::read(lines_pdb()).unwrap();
    let parsed = hexcavator_pdb::Pdb::parse(&pdb).unwrap();
    let info = parsed.info();
    assert!(info.age() >= 1, "the synthetic PDBs are age 1");
    // The first process's executable: sampled in every trace.
    let m = s
        .truth
        .modules
        .iter()
        .find(|m| m.process.is_some() && m.name.ends_with(".exe"))
        .unwrap()
        .clone();
    let guid = m.pdb.0;
    let mut found = 0;
    for i in 0..s.etl.len() - 16 {
        if s.etl[i..i + 16] == guid {
            s.etl[i..i + 16].copy_from_slice(&info.guid());
            found += 1;
        }
    }
    assert!(found >= 1, "the PDB's GUID is in the trace");
    let path = dir.join("t.etl");
    std::fs::write(&path, &s.etl).unwrap();
    let cache = dir.join("cache");
    std::fs::create_dir_all(&cache).unwrap();
    let pdb_name = m.pdb.2.rsplit('\\').next().unwrap().to_string();
    std::fs::copy(lines_pdb(), cache.join(&pdb_name)).unwrap();
    (path, m.name, cache)
}

/// Every node's children's labels, of the default tree, from the trace's
/// PDBs in `cache` (waiting for each).
fn reference(path: &Path, cache: &Path) -> Vec<Vec<String>> {
    let loaded = store::open(path, &store::Options::default()).unwrap();
    let trace = &loaded.trace;
    let symbolizer = PdbSymbolizer::new(SymbolPath {
        dirs: vec![cache.to_path_buf()],
    });
    let resolver = Resolver::new(trace);
    let mut view = TreeView::build(trace, &resolver, &symbolizer, None, TreeSpec::default());
    let mut out = Vec::new();
    let mut node = 0;
    while view.has_node(NodeId(node)) {
        out.push(
            view.children(trace, &symbolizer, NodeId(node))
                .into_iter()
                .map(|r| r.label)
                .collect(),
        );
        node += 1;
    }
    out
}

#[test]
fn a_trace_reopens_with_its_names_and_without_its_pdbs() {
    let dir = scratch("saved-symbols");
    let (path, exe, cache) = trace_with_a_real_pdb(&dir);
    let open = json!({"method": "open", "params": {
        "path": path, "useIndex": true, "symbolCache": cache, "downloadSymbols": false,
    }});
    // The first time: imported, its PDB found and loaded, and its names
    // saved beside the index.
    let (a, notes) = session(std::slice::from_ref(&open));
    let first = result(&a, 1);
    assert_eq!(first["opened"]["how"], "import");
    assert_eq!(first["savedSymbols"], 0);
    let loaded = notes
        .iter()
        .rfind(|n| n["params"].get("loaded").is_some())
        .unwrap();
    assert_eq!(loaded["params"]["loaded"], 1, "lines.pdb");
    let saved = dir.join("t.etl.hxsyms");
    assert!(saved.exists(), "saved beside the index");
    let size = std::fs::metadata(&saved).unwrap().len();
    assert!(
        size < std::fs::metadata(lines_pdb()).unwrap().len() / 4,
        "{size} bytes: only what the trace needs"
    );

    // What the PDB names, for every node of the tree.
    let want = reference(&path, &cache);
    let named = |labels: &[Vec<String>]| {
        labels
            .iter()
            .flatten()
            .filter(|l| l.starts_with(&format!("{exe}!")) && !l.ends_with("!<module>"))
            .count()
    };
    assert!(
        named(&want) > 0,
        "the tree names the executable's functions"
    );

    // Without the PDB, the second time: from the index, and its names
    // from the start, the same in every node.
    std::fs::remove_dir_all(&cache).unwrap();
    std::fs::create_dir_all(&cache).unwrap();
    let modified = std::fs::metadata(&saved).unwrap().modified().unwrap();
    let mut requests = vec![
        open,
        json!({"method": "tree.create", "params": {"trace": 1}}),
    ];
    for node in 0..want.len() {
        requests.push(
            json!({"method": "tree.children", "params": {"trace": 1, "view": 1, "node": node}}),
        );
    }
    let (a, notes) = session(&requests);
    let second = result(&a, 1);
    assert_eq!(second["opened"]["how"], "index");
    assert_eq!(second["savedSymbols"], 1);
    let got: Vec<Vec<String>> = (0..want.len())
        .map(|node| {
            result(&a, node as u64 + 3)["rows"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r["label"].as_str().unwrap().to_string())
                .collect()
        })
        .collect();
    assert_eq!(got, want);
    assert_eq!(named(&got), named(&want));
    let loaded = notes
        .iter()
        .rfind(|n| n["params"].get("loaded").is_some())
        .unwrap();
    assert_eq!(
        loaded["params"]["loaded"], 1,
        "the saved names count as loaded"
    );
    // Nothing new found: not saved again.
    assert_eq!(
        std::fs::metadata(&saved).unwrap().modified().unwrap(),
        modified
    );
}

#[test]
fn without_an_index_nothing_is_saved() {
    let dir = scratch("saved-symbols-no-index");
    let (path, _, cache) = trace_with_a_real_pdb(&dir);
    let (a, _) = session(&[json!({"method": "open", "params": {
        "path": path, "useIndex": false, "symbolCache": cache,
    }})]);
    assert_eq!(result(&a, 1)["savedSymbols"], 0);
    let names: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(
        !names
            .iter()
            .any(|n| n.to_string_lossy().ends_with(".hxsyms")),
        "{names:?}"
    );
}

#[test]
fn saved_symbols_are_only_for_their_trace_and_undamaged() {
    let dir = scratch("saved-symbols-checks");
    let pdb = std::fs::read(lines_pdb()).unwrap();
    let table = Arc::new(FunctionTable::from_pdb(&pdb).unwrap());
    let main = table.iter().find(|f| f.2 == "main").unwrap().0;
    let key = ([7u8; 16], 3);
    let frames = symbols::Frames {
        wanted: Vec::new(),
        addresses: [(key, vec![main])].into_iter().collect(),
        ..symbols::Frames::default()
    };
    let source = index::Source {
        size: 1234,
        hash: 99,
    };
    let path = dir.join("t.hxsyms");
    // A PDB no frame is in isn't saved.
    let other = (([8u8; 16], 1), Arc::clone(&table));
    symbols::save(&path, source, &frames, &[(key, Arc::clone(&table)), other]).unwrap();
    let back = symbols::load_saved(&path, source);
    assert_eq!(back.len(), 1);
    assert_eq!(back[0].0, key);
    assert_eq!(*back[0].1, table.subset(&[main]));
    assert_eq!(back[0].1.function(main).map(|f| f.1), Some("main"));
    // Another trace's (or another version of this one's).
    assert!(
        symbols::load_saved(
            &path,
            index::Source {
                size: 1234,
                hash: 98
            }
        )
        .is_empty()
    );
    assert!(
        symbols::load_saved(
            &path,
            index::Source {
                size: 1235,
                hash: 99
            }
        )
        .is_empty()
    );
    assert!(symbols::load_saved(&dir.join("none.hxsyms"), source).is_empty());
    // Damaged: cut short anywhere, or a byte of a table changed so that
    // it doesn't read (all or nothing).
    let bytes = std::fs::read(&path).unwrap();
    let damaged = dir.join("damaged.hxsyms");
    for len in 0..bytes.len() {
        std::fs::write(&damaged, &bytes[..len]).unwrap();
        assert!(symbols::load_saved(&damaged, source).is_empty(), "{len}");
    }
    let mut extra = bytes.clone();
    extra.push(0);
    std::fs::write(&damaged, &extra).unwrap();
    assert!(symbols::load_saved(&damaged, source).is_empty());
    // (The table's magic, just after the header and its key and length.)
    let mut bad = bytes.clone();
    bad[8 + 4 + 8 + 8 + 4 + 16 + 4 + 8] ^= 0xff;
    std::fs::write(&damaged, &bad).unwrap();
    assert!(symbols::load_saved(&damaged, source).is_empty());
    // Written aside: no partial file is left.
    assert!(!dir.join("t.hxsyms.partial").exists());
    assert_eq!(
        symbols::saved_path(Path::new("a/t.etl.hxtrace")),
        Path::new("a/t.etl.hxsyms")
    );
}

#[test]
fn a_pdb_missing_at_first_is_found_when_it_comes() {
    let dir = scratch("saved-symbols-later");
    let (path, exe, cache) = trace_with_a_real_pdb(&dir);
    let loaded = store::open(
        &path,
        &store::Options {
            use_index: false,
            cache_dir: None,
        },
    )
    .unwrap();
    let trace = &loaded.trace;
    let image = trace
        .images
        .iter()
        .position(|i| i.file_name() == exe)
        .map(|i| hexcavator_trace::ImageIx(u32::try_from(i).unwrap()))
        .unwrap();
    let id = trace.images[image.index()].debug_id.clone().unwrap();
    let pdb = std::fs::read(lines_pdb()).unwrap();
    let table = Arc::new(FunctionTable::from_pdb(&pdb).unwrap());
    let main = u64::from(table.iter().find(|f| f.2 == "main").unwrap().0);
    let named = |s: &PdbSymbolizer| s.function_start(trace, image, main);
    use hexcavator_trace_analysis::Symbolizer;

    // Not waiting: missing until it is seeded (asked about many times, so
    // that "missing" is remembered).
    let s = PdbSymbolizer::new(SymbolPath::default());
    s.set_waiting(false);
    for _ in 0..3 {
        assert_eq!(named(&s), None);
    }
    s.seed(&id.guid, id.age, Arc::clone(&table));
    assert_eq!(named(&s), Some(main));

    // Not waiting: missing until a background load loads it.
    let s = PdbSymbolizer::new(SymbolPath {
        dirs: vec![cache.clone()],
    });
    s.set_waiting(false);
    assert_eq!(named(&s), None);
    assert!(s.load(&id.pdb_path, &id.guid, id.age).is_some());
    assert_eq!(named(&s), Some(main));

    // Waiting: missing (not in the cache) until it is downloaded and the
    // missing are forgotten.
    let elsewhere = dir.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    let s = PdbSymbolizer::new(SymbolPath {
        dirs: vec![elsewhere.clone()],
    });
    assert_eq!(named(&s), None);
    assert_eq!(named(&s), None);
    for f in std::fs::read_dir(&cache).unwrap() {
        let f = f.unwrap();
        std::fs::copy(f.path(), elsewhere.join(f.file_name())).unwrap();
    }
    assert_eq!(named(&s), None, "still missing: not looked for again yet");
    s.forget_missing();
    assert_eq!(named(&s), Some(main));
    // And a symbolizer that didn't wait at first, then does.
    let s = PdbSymbolizer::new(SymbolPath { dirs: vec![cache] });
    s.set_waiting(false);
    assert_eq!(named(&s), None);
    s.set_waiting(true);
    assert_eq!(named(&s), Some(main));
}

#[test]
fn the_symbols_report_says_what_became_of_each_pdb() {
    let dir = scratch("saved-symbols-report");
    let (path, _, cache) = trace_with_a_real_pdb(&dir);
    let pdb = std::fs::read(lines_pdb()).unwrap();
    let parsed = hexcavator_pdb::Pdb::parse(&pdb).unwrap();
    let lines = hexcavator_symbolize::symbol_store_key(&parsed.info().guid(), 1);
    let report = |requests: &[Value]| {
        let (a, _) = session(requests);
        result(&a, requests.len() as u64).clone()
    };
    let row_of = |r: &Value, identity: &str| {
        r["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["identity"] == identity)
            .cloned()
            .unwrap()
    };
    let wait = json!({"method": "symbols", "params": {"trace": 1, "wait": true}});

    // Opened with its PDB in the cache: loaded; the rest (the synthetic
    // machine's) not found; nothing downloaded.
    let open = json!({"method": "open", "params": {
        "path": path, "useIndex": true, "symbolCache": cache, "downloadSymbols": false,
    }});
    let r = report(&[open.clone(), wait.clone()]);
    assert_eq!(r["ready"], true);
    assert_eq!(r["done"], true);
    let rows = r["rows"].as_array().unwrap();
    assert!(rows.len() >= 4, "{} PDBs", rows.len());
    let row = row_of(&r, &lines);
    assert_eq!(row["status"], "loaded");
    assert!(row["frames"].as_u64().unwrap() > 0);
    assert_eq!(
        row["pdb"].as_str().unwrap(),
        row["path"].as_str().unwrap().rsplit('\\').next().unwrap()
    );
    for other in rows.iter().filter(|x| x["identity"] != lines.as_str()) {
        assert_eq!(other["status"], "not found", "{other}");
        assert_eq!(other["download"], "downloads off");
    }
    // Most wanted first.
    let frames: Vec<u64> = rows.iter().map(|x| x["frames"].as_u64().unwrap()).collect();
    assert!(frames.windows(2).all(|w| w[0] >= w[1]), "{frames:?}");
    // Every synthetic image has a PDB identity.
    assert_eq!(r["noDebug"], json!([]));

    // Reopened without it: its names from the saved symbols.
    std::fs::remove_dir_all(&cache).unwrap();
    std::fs::create_dir_all(&cache).unwrap();
    let r = report(&[open, wait.clone()]);
    assert_eq!(row_of(&r, &lines)["status"], "saved");

    // Downloading from a server that refuses connections: on no server.
    let r = report(&[
        json!({"method": "open", "params": {
            "path": path, "useIndex": false, "symbolCache": cache,
            "downloadSymbols": true, "symbolServers": ["http://127.0.0.1:9"],
        }}),
        wait,
    ]);
    let rows = r["rows"].as_array().unwrap();
    assert!(
        rows.iter()
            .all(|x| x["download"] == "on no server" && x["status"] == "not found"),
        "{rows:?}"
    );
}
