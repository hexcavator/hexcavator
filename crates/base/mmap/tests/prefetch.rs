//! Reading a mapped file ahead of its parser, and evicting it from the
//! cache.

use hexcavator_mmap::{Mmap, evict_from_cache};

fn scratch(name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("hexcavator-mmap-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| u8::try_from(i * 7 % 251).unwrap()).collect()
}

#[test]
fn prefetch_reads_the_whole_file() {
    // Not a multiple of the chunk: the last read is short.
    let data = pattern(5 * 65_536 + 123);
    let path = scratch("whole.bin", &data);
    for threads in [1, 3] {
        let map = Mmap::open(&path).unwrap();
        let read = map.prefetch(threads, 65_536).unwrap().wait().unwrap();
        assert_eq!(read, data.len() as u64);
        assert_eq!(map.as_slice(), &data[..], "the mapping reads the same");
    }
}

#[test]
fn prefetch_of_data_in_memory_has_nothing_to_read() {
    let map = Mmap::from(pattern(1000));
    assert_eq!(map.prefetch(4, 4096).unwrap().wait().unwrap(), 1000);
    let empty = Mmap::open(scratch("empty.bin", &[])).unwrap();
    assert_eq!(empty.prefetch(1, 4096).unwrap().wait().unwrap(), 0);
}

#[test]
fn dropping_a_prefetch_stops_it() {
    let data = pattern(8 << 20);
    let path = scratch("stop.bin", &data);
    let map = Mmap::open(&path).unwrap();
    let p = map.prefetch(1, 4096).unwrap();
    drop(p); // Joins its thread; no hang, no panic.
    // The mapping is unaffected.
    assert_eq!(map[1234], data[1234]);
}

#[test]
fn eviction_leaves_the_file_as_it_was() {
    let data = pattern(100_000);
    let path = scratch("evict.bin", &data);
    let evicted = evict_from_cache(&path).unwrap();
    assert_eq!(evicted, cfg!(windows));
    assert_eq!(std::fs::read(&path).unwrap(), data);
    assert!(evict_from_cache(&path.with_extension("missing")).is_err());
}
