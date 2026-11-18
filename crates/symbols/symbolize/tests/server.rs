//! Downloading PDBs from a symbol server (a local one, serving the
//! repository's test PDBs) into a cache.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use hexcavator_symbolize::server::{Fetched, MICROSOFT, PdbId, SymbolServers};
use hexcavator_symbolize::symbol_store_key;

fn testdata(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../testdata")
        .join(rel)
}

/// A PDB's identity, read from it.
fn id_of(rel: &str) -> PdbId {
    let map = hexcavator_mmap::Mmap::open(testdata(rel)).unwrap();
    let pdb = hexcavator_pdb::Pdb::parse(&map).unwrap();
    let info = pdb.info();
    PdbId {
        name: format!(
            r"d:\build\out\{}",
            Path::new(rel).file_name().unwrap().to_str().unwrap()
        ),
        guid: info.guid(),
        age: info.age(),
    }
}

/// A symbol server on this machine: serves `files` (URL path to bytes),
/// and 404 for anything else. Returns its URL and a count of requests.
fn server(files: Vec<(String, Vec<u8>)>) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let hits = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&hits);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            counted.fetch_add(1, Ordering::Relaxed);
            let files = files.clone();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                // (The rest of the request's head.)
                loop {
                    let mut h = String::new();
                    if reader.read_line(&mut h).unwrap() <= 2 {
                        break;
                    }
                }
                let path = line.split(' ').nth(1).unwrap_or("");
                match files.iter().find(|(p, _)| p.eq_ignore_ascii_case(path)) {
                    Some((_, body)) => {
                        let _ = write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = stream.write_all(body);
                    }
                    None => {
                        let _ = stream
                            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    }
                }
            });
        }
    });
    (url, hits)
}

fn key(id: &PdbId) -> String {
    let name = Path::new(&id.name.replace('\\', "/"))
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_ascii_lowercase();
    format!("/{name}/{}/{name}", symbol_store_key(&id.guid, id.age))
}

fn cache(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("symsrv-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[test]
fn downloads_into_the_cache_once() {
    let id = id_of("lines/lines.pdb");
    let bytes = std::fs::read(testdata("lines/lines.pdb")).unwrap();
    let (url, hits) = server(vec![(key(&id), bytes.clone())]);
    let s = SymbolServers {
        cache: cache("once"),
        urls: vec![url],
    };
    let path = s.cached_path(&id).unwrap();
    assert!(
        path.ends_with(
            Path::new("lines.pdb")
                .join(symbol_store_key(&id.guid, id.age))
                .join("lines.pdb")
        )
    );
    assert_eq!(s.fetch(&id), Fetched::Downloaded(path.clone()));
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    // Again: from the cache, without asking.
    let before = hits.load(Ordering::Relaxed);
    assert_eq!(s.fetch(&id), Fetched::Cached(path));
    assert_eq!(hits.load(Ordering::Relaxed), before);
}

#[test]
fn the_wrong_pdb_is_not_kept() {
    let id = id_of("lines/lines.pdb");
    // The server sends another PDB under this one's key.
    let other = std::fs::read(testdata("init/init.pdb")).unwrap();
    let (url, _) = server(vec![(key(&id), other)]);
    let s = SymbolServers {
        cache: cache("wrong"),
        urls: vec![url],
    };
    assert_eq!(s.fetch(&id), Fetched::Missing);
    assert!(!s.cached_path(&id).unwrap().exists());
}

#[test]
fn servers_are_asked_in_order() {
    let id = id_of("lines/lines.pdb");
    let bytes = std::fs::read(testdata("lines/lines.pdb")).unwrap();
    let (empty, _) = server(vec![]);
    let (full, _) = server(vec![(key(&id), bytes)]);
    let s = SymbolServers {
        cache: cache("order"),
        urls: vec![empty, full],
    };
    assert!(matches!(s.fetch(&id), Fetched::Downloaded(_)));
    let none = SymbolServers {
        cache: cache("none"),
        urls: vec![server(vec![]).0],
    };
    assert_eq!(none.fetch(&id), Fetched::Missing);
}

#[test]
fn names_that_would_escape_are_refused() {
    let s = SymbolServers {
        cache: cache("names"),
        urls: vec!["http://127.0.0.1:9".into()],
    };
    for name in ["..", "a/..", "x y.pdb", "a\u{0}.pdb", ""] {
        let id = PdbId {
            name: name.into(),
            guid: [0; 16],
            age: 1,
        };
        assert_eq!(s.fetch(&id), Fetched::BadName, "{name:?}");
    }
}

#[test]
fn many_at_once_in_order() {
    let names = [
        "lines/lines.pdb",
        "init/init.pdb",
        "init/initdll.pdb",
        "diff/diff-v1.pdb",
    ];
    let ids: Vec<PdbId> = names.iter().map(|n| id_of(n)).collect();
    let mut files: Vec<(String, Vec<u8>)> = names
        .iter()
        .zip(&ids)
        .map(|(n, id)| (key(id), std::fs::read(testdata(n)).unwrap()))
        .collect();
    // One the server doesn't have.
    files.pop();
    let (url, _) = server(files);
    let s = SymbolServers {
        cache: cache("many"),
        urls: vec![url],
    };
    let heard = AtomicUsize::new(0);
    let r = s.fetch_all(&ids, 8, |_, _, _| {
        heard.fetch_add(1, Ordering::Relaxed);
    });
    assert_eq!(heard.load(Ordering::Relaxed), ids.len());
    assert!(r[..3].iter().all(|f| matches!(f, Fetched::Downloaded(_))));
    assert_eq!(r[3], Fetched::Missing);
    // The symbol path finds them in the cache.
    let path = hexcavator_symbolize::SymbolPath {
        dirs: vec![s.cache.clone()],
    };
    for id in &ids[..3] {
        assert_eq!(
            path.find_pdb(&id.name, &id.guid, id.age).as_deref(),
            s.cached_path(id).as_deref()
        );
    }
}

#[test]
fn symbol_paths_name_servers_and_a_cache() {
    let s = SymbolServers::from_nt_symbol_path(
        r"c:\local;srv*c:\jm\symbols*https://msdl.microsoft.com/download/symbols;SRV*d:\other*https://example.com/sym/",
    )
    .unwrap();
    assert_eq!(s.cache, PathBuf::from(r"c:\jm\symbols"));
    assert_eq!(s.urls, [MICROSOFT, "https://example.com/sym"]);
    assert_eq!(
        SymbolServers::from_nt_symbol_path(r"c:\local;cache*c:\x"),
        None
    );
    assert_eq!(SymbolServers::from_nt_symbol_path(""), None);
    assert_eq!(
        SymbolServers::from_nt_symbol_path("srv*https://only.example"),
        None
    );
}
