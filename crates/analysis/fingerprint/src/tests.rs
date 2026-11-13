#![allow(
    clippy::cast_possible_truncation,
    reason = "tests encode instructions and indexes from wider values"
)]

use super::*;

/// Nodes as `[start, end)` ranges.
struct Nodes(Vec<(u64, u64)>);

impl Resolve for Nodes {
    fn node_at(&self, address: u64) -> Option<u32> {
        self.0
            .iter()
            .position(|&(s, e)| (s..e).contains(&address))
            .map(|i| i as u32)
    }

    fn node_starting_at(&self, address: u64) -> Option<u32> {
        self.0
            .iter()
            .position(|&(s, _)| s == address)
            .map(|i| i as u32)
    }
}

fn item(local: u64, refs: &[u32]) -> Item {
    Item {
        local,
        refs: refs.to_vec(),
    }
}

/// Callees count: two functions alike but for what they call are alike
/// only if what they call is.
#[test]
fn callees_decide() {
    // 0 and 1 are alike locally; 0 calls 2, 1 calls 3.
    let differ = [item(7, &[2]), item(7, &[3]), item(5, &[]), item(6, &[])];
    let c = refine(&differ, 64);
    assert_ne!(c[0], c[1]);
    let same = [item(7, &[2]), item(7, &[3]), item(5, &[]), item(5, &[])];
    let c = refine(&same, 64);
    assert_eq!(c[0], c[1]);
    assert_eq!(c[2], c[3]);
    // Deeper: 0 -> 2 -> 4, 1 -> 3 -> 5, and 4 and 5 differ.
    let deep = [
        item(7, &[2]),
        item(7, &[3]),
        item(5, &[4]),
        item(5, &[5]),
        item(1, &[]),
        item(2, &[]),
    ];
    let c = refine(&deep, 64);
    assert_ne!(c[0], c[1]);
    assert_ne!(c[2], c[3]);
    // The order of references counts.
    let order = [
        item(7, &[2, 3]),
        item(7, &[3, 2]),
        item(5, &[]),
        item(6, &[]),
    ];
    let c = refine(&order, 64);
    assert_ne!(c[0], c[1]);
}

/// Cycles need nothing special: two pairs of mutually recursive functions,
/// alike, are alike pairwise.
#[test]
fn cycles() {
    let items = [
        item(1, &[1]), // p -> q
        item(2, &[0]), // q -> p
        item(1, &[3]), // r -> s
        item(2, &[2]), // s -> r
        item(1, &[4]), // t -> t (a different shape)
    ];
    let c = refine(&items, 64);
    assert_eq!(c[0], c[2]);
    assert_eq!(c[1], c[3]);
    assert_ne!(c[0], c[1]);
    assert_ne!(c[0], c[4]);
    // Converges quickly, and with no rounds is just the local hashes.
    assert_eq!(refine(&items, 0), [1, 2, 1, 2, 1]);
    assert!(refine(&[], 64).is_empty());
}

/// The same x86-64 function at two addresses, calling and reading the same
/// nodes: the same local hash and references; branches inside it count by
/// offset.
#[test]
fn x86_64_code_is_position_independent() {
    // call f; lea rax, [rip+d]; jne +0 (to the next instruction); ret
    let make = |at: u64, callee: u64, datum: u64| {
        let mut c = vec![0xE8];
        c.extend_from_slice(&((callee.wrapping_sub(at + 5)) as u32).to_le_bytes());
        c.extend_from_slice(&[0x48, 0x8D, 0x05]);
        c.extend_from_slice(&((datum.wrapping_sub(at + 12)) as u32).to_le_bytes());
        c.extend_from_slice(&[0x75, 0x00, 0xC3]);
        c
    };
    let nodes = Nodes(vec![
        (0x1000, 0x100F),
        (0x2000, 0x200F),
        (0x5000, 0x5010), // f
        (0x6000, 0x6008), // the datum
        (0x7000, 0x7010), // another function
    ]);
    let a = code(
        Arch::X64,
        &make(0x1000, 0x5000, 0x6000),
        0x1000,
        None,
        &[],
        &nodes,
    );
    let b = code(
        Arch::X64,
        &make(0x2000, 0x5000, 0x6004),
        0x2000,
        None,
        &[],
        &nodes,
    );
    assert_eq!(a, b);
    assert_eq!(a.refs, [2, 3]);
    // Calling another node: the same local hash, other references.
    let c = code(
        Arch::X64,
        &make(0x2000, 0x7000, 0x6000),
        0x2000,
        None,
        &[],
        &nodes,
    );
    assert_eq!(c.local, a.local);
    assert_eq!(c.refs, [4, 3]);
    // A different register: a different hash.
    let mut d = make(0x2000, 0x5000, 0x6000);
    d[7] = 0x0D; // lea rcx
    assert_ne!(
        code(Arch::X64, &d, 0x2000, None, &[], &nodes).local,
        a.local
    );
    // A different immediate (not an address): a different hash.
    let imm = |v: u8| code(Arch::X64, &[0x83, 0xC0, v, 0xC3], 0x1000, None, &[], &nodes).local;
    assert_ne!(imm(1), imm(2));
    // A call to no node: hashed as such, no reference.
    let e = code(
        Arch::X64,
        &make(0x2000, 0x9000, 0x6000),
        0x2000,
        None,
        &[],
        &nodes,
    );
    assert_ne!(e.local, a.local);
    assert_eq!(e.refs, [3]);
}

/// 32-bit x86: the absolute addresses relocations name are masked, and are
/// references.
#[test]
fn x86_absolute_addresses() {
    // mov eax, [addr]; ret
    let make = |addr: u32| {
        let mut c = vec![0xA1];
        c.extend_from_slice(&addr.to_le_bytes());
        c.push(0xC3);
        c
    };
    let nodes = Nodes(vec![
        (0x40_1000, 0x40_1006),
        (0x40_3000, 0x40_3004),
        (0x40_4000, 0x40_4004),
    ]);
    let a = code(
        Arch::X86,
        &make(0x40_3000),
        0x40_1000,
        None,
        &[(0x40_1001, 0x40_3000)],
        &nodes,
    );
    let b = code(
        Arch::X86,
        &make(0x40_4000),
        0x40_1000,
        None,
        &[(0x40_1001, 0x40_4000)],
        &nodes,
    );
    assert_eq!(a.local, b.local);
    assert_eq!((a.refs.as_slice(), b.refs.as_slice()), (&[1][..], &[2][..]));
    // Without the relocation, the value is just a value.
    let c = code(Arch::X86, &make(0x40_4000), 0x40_1000, None, &[], &nodes);
    assert_ne!(c.local, b.local);
    assert!(c.refs.is_empty());
}

/// ARM64: BL, ADRP and ADD at two addresses.
#[test]
fn arm64_code_is_position_independent() {
    // bl f; adrp x1, page; add x1, x1, #off; ret
    let make = |at: u64, callee: u64, datum: u64| -> Vec<u8> {
        let bl = 0x9400_0000 | (((callee.wrapping_sub(at) >> 2) as u32) & 0x3FF_FFFF);
        let pages = ((datum >> 12).wrapping_sub((at + 4) >> 12)) as u32;
        let adrp = 0x9000_0001 | ((pages & 3) << 29) | (((pages >> 2) & 0x7FFFF) << 5);
        let add = 0x9100_0021 | (((datum & 0xFFF) as u32) << 10);
        [bl, adrp, add, 0xD65F_03C0]
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect()
    };
    let nodes = Nodes(vec![
        (0x1000, 0x1010),
        (0x8000, 0x8010),
        (0x5000, 0x5010),
        (0x3_6010, 0x3_6020),
    ]);
    let a = code(
        Arch::Arm64,
        &make(0x1000, 0x5000, 0x3_6010),
        0x1000,
        None,
        &[],
        &nodes,
    );
    let b = code(
        Arch::Arm64,
        &make(0x8000, 0x5000, 0x3_6010),
        0x8000,
        None,
        &[],
        &nodes,
    );
    assert_eq!(a, b);
    assert_eq!(a.refs, [2, 3]);
}

/// Data: alike but for its pointers' values.
#[test]
fn data_masks_pointers() {
    let a = data(&[1, 2, 0xAA, 0xAA, 0xAA, 0xAA, 3], 7, &[(2, 4, Some(9))]);
    let b = data(&[1, 2, 0xBB, 0xBB, 0xBB, 0xBB, 3], 7, &[(2, 4, Some(4))]);
    assert_eq!(a.local, b.local);
    assert_eq!((a.refs, b.refs), (vec![9], vec![4]));
    assert_ne!(
        data(&[1, 2, 3], 3, &[]).local,
        data(&[1, 2, 4], 3, &[]).local
    );
    // Zero-filled tails count by size.
    assert_ne!(data(&[], 4, &[]).local, data(&[], 8, &[]).local);
    // A pointer to nothing known differs from one to a node.
    let c = data(&[1, 2, 0, 0, 0, 0, 3], 7, &[(2, 4, None)]);
    assert_ne!(c.local, a.local);
    // Bad offsets are skipped, not a panic.
    data(&[1, 2], 2, &[(5, 4, Some(1)), (u64::MAX, 8, None)]);
    assert_eq!(named("GetLastError"), named("GetLastError"));
    assert_ne!(named("GetLastError").local, named("SetLastError").local);
}
