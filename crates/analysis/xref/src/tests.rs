use super::*;

fn node(start: u64, end: u64, code: bool) -> Node {
    Node { start, end, code }
}

fn refs(arch: Arch, code: &[u8], at: u64) -> Vec<(u64, u64, Via)> {
    let mut out = Vec::new();
    scan(arch, code, at, &mut out);
    out.iter().map(|r| (r.from, r.to, r.via)).collect()
}

#[test]
fn x86_64_calls_branches_and_addresses() {
    let code = [
        0xE8, 0x0B, 0x00, 0x00, 0x00, // 1000: call 1010
        0x48, 0x8D, 0x05, 0xF4, 0x0F, 0x00, 0x00, // 1005: lea rax, [rip+0FF4h] -> 2000
        0x74, 0x02, // 100c: je 1010
        0xEB, 0x00, // 100e: jmp 1010
        0xFF, 0x15, 0xEA, 0x1F, 0x00, 0x00, // 1010: call [rip+1FEAh] -> 3000
        0x48, 0x8B, 0x04, 0xC5, 0, 0x40, 0, 0, // 1016: mov rax, [rax*8+4000h]: no
        0xFF, 0xD0, // 101e: call rax: no
    ];
    assert_eq!(
        refs(Arch::X64, &code, 0x1000),
        [
            (0x1000, 0x1010, Via::Call),
            (0x1005, 0x2000, Via::AddressOf),
            (0x100C, 0x1010, Via::Jump),
            (0x100E, 0x1010, Via::Jump),
            (0x1010, 0x3000, Via::Address),
        ]
    );
}

/// MSVC's x64 tables: a register holding the image's address, plus the
/// table's offset from it; the register forgotten when written.
#[test]
fn x86_64_tables_by_image_offset() {
    let code = [
        0x4C, 0x8D, 0x0D, 0xF9, 0xEF, 0xFF, 0xFF, // 1000: lea r9, [rip-1007h] -> 0
        0x41, 0x8B, 0x84, 0x89, 0x00, 0x50, 0x00, 0x00, // 1007: mov eax, [r9+rcx*4+5000h]
        0x42, 0x0F, 0xB6, 0x84, 0x09, 0x00, 0x60, 0x00,
        0x00, // 100f: movzx eax, byte [rcx+r9+6000h]
        0x49, 0x8D, 0x81, 0xFF, 0x6F, 0x00, 0x00, // 1018: lea rax, [r9+6FFFh]
        0xE8, 0x00, 0x00, 0x00, 0x00, // 101f: call 1024 (r9 still the base)
        0x41, 0x8B, 0x01, // 1024: mov eax, [r9]: no displacement, no table
        0x4D, 0x31, 0xC9, // 1027: xor r9, r9
        0x41, 0x8B, 0x84, 0x89, 0x00, 0x07, 0x00, 0x00, // 102a: mov eax, [r9+rcx*4+700h]: no
        // 1032: mov eax, [r9+rcx*4+7000h]: past the first page, it held the
        // image's address before (a jump table's case could reach this).
        0x41, 0x8B, 0x84, 0x89, 0x00, 0x70, 0x00, 0x00,
    ];
    let got = refs_with_base(&code, 0x1000, 0);
    assert_eq!(
        got,
        [
            (0x1007, 0x5000, Via::Address),
            (0x100F, 0x6000, Via::Address),
            (0x1018, 0x6FFF, Via::AddressOf),
            (0x101F, 0x1024, Via::Call),
            (0x1032, 0x7000, Via::Address),
        ]
    );
    // The table's offset scaled, the image's address added after.
    let scaled = [
        0x48, 0x8D, 0x15, 0xF9, 0xEF, 0xFF, 0xFF, // 1000: lea rdx, [rip-1007h] -> 0
        0x48, 0x8D, 0x04, 0x85, 0x00, 0x80, 0x00, 0x00, // 1007: lea rax, [rax*4+8000h]
        0x48, 0x01, 0xD0, // 100f: add rax, rdx
    ];
    assert_eq!(
        refs_with_base(&scaled, 0x1000, 0),
        [(0x1007, 0x8000, Via::AddressOf)]
    );
    // A jump ahead carries the register past code that overwrites it.
    let jumped = [
        0x48, 0x8D, 0x0D, 0xF9, 0xEF, 0xFF, 0xFF, // 1000: lea rcx, [rip-1007h] -> 0
        0x74, 0x08, // 1007: je 1011
        0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00, // 1009: lea rcx, [rip+0] (not the base)
        0xC3, // 1010: ret
        0x0F, 0xB7, 0x84, 0x41, 0xA0, 0x82, 0x00,
        0x00, // 1011: movzx eax, word [rcx+rax*2+82A0h]
    ];
    assert_eq!(
        refs_with_base(&jumped, 0x1000, 0),
        [
            (0x1007, 0x1011, Via::Jump),
            (0x1009, 0x1010, Via::AddressOf),
            (0x1011, 0x82A0, Via::Address),
        ]
    );
    // With no register holding it, an index without a base is no table.
    assert_eq!(refs_with_base(&scaled[7..], 0x1000, 0), []);
    // Without the image's address, none of the tables.
    assert_eq!(
        refs(Arch::X64, &code, 0x1000),
        [(0x101F, 0x1024, Via::Call)]
    );
    // A lea of anything else is no base.
    let code = [
        0x4C, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00, // lea r9, [rip+0] -> 1007
        0x41, 0x8B, 0x84, 0x89, 0x00, 0x50, 0x00, 0x00, // mov eax, [r9+rcx*4+5000h]
    ];
    assert_eq!(
        refs_with_base(&code, 0x1000, 0),
        [(0x1000, 0x1007, Via::AddressOf)]
    );
}

fn refs_with_base(code: &[u8], at: u64, base: u64) -> Vec<(u64, u64, Via)> {
    let mut out = Vec::new();
    scan_image(Arch::X64, code, at, Some(base), &mut out);
    out.iter().map(|r| (r.from, r.to, r.via)).collect()
}

#[test]
fn x86_code_stops_at_what_does_not_decode() {
    // call; then bytes that are no instruction (a jump table, say).
    let code = [0xE8, 0x00, 0x00, 0x00, 0x00, 0x0F, 0xFF];
    assert_eq!(refs(Arch::X86, &code, 0x400), [(0x400, 0x405, Via::Call)]);
    assert_eq!(refs(Arch::X86, &[], 0x400), []);
    // 32-bit code's absolute addresses are relocations', not the scan's.
    let code = [0xB8, 0x00, 0x20, 0x40, 0x00]; // mov eax, 402000h
    assert_eq!(refs(Arch::X86, &code, 0x401000), []);
}

#[test]
fn arm64_branches_and_pages() {
    let words: [u32; 8] = [
        0x9400_0004, // 1000: bl 1010
        0x1400_0003, // 1004: b 1010
        0xB400_0040, // 1008: cbz x0, 1010
        0x5400_0020, // 100c: b.eq 1010
        0x3600_0000, // 1010: tbz w0, #0, 1010
        0xF000_0001, // 1014: adrp x1, 4000 (pc page 1000 + 3 pages)
        0x9100_4021, // 1018: add x1, x1, #0x10 -> 4010
        0xD65F_03C0, // 101c: ret
    ];
    let code: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    assert_eq!(
        refs(Arch::Arm64, &code, 0x1000),
        [
            (0x1000, 0x1010, Via::Call),
            (0x1004, 0x1010, Via::Jump),
            (0x1008, 0x1010, Via::Jump),
            (0x100C, 0x1010, Via::Jump),
            (0x1010, 0x1010, Via::Jump),
            (0x1018, 0x4010, Via::AddressOf),
        ]
    );
    // Backward branches.
    let back = 0x17FF_FFFFu32.to_le_bytes(); // b .-4
    assert_eq!(
        refs(Arch::Arm64, &back, 0x2000),
        [(0x2000, 0x1FFC, Via::Jump)]
    );
}

#[test]
fn nodes_by_address() {
    let b = Builder::new(vec![
        node(0x300, 0x400, false),
        node(0x100, 0x200, true),
        node(0x200, 0x200, true),  // empty
        node(0x320, 0x330, false), // nested in 0x300
    ]);
    let starts: Vec<u64> = b.nodes().iter().map(|n| n.start).collect();
    assert_eq!(starts, [0x100, 0x200, 0x300, 0x320]);
    assert_eq!(b.node_at(0x100), Some(0));
    assert_eq!(b.node_at(0x1FF), Some(0));
    assert_eq!(
        b.node_at(0x200),
        None,
        "end is exclusive; empty holds nothing"
    );
    assert_eq!(b.node_at(0x325), Some(3), "the inner node");
    assert_eq!(b.node_at(0x330), Some(2), "past the inner, the outer");
    assert_eq!(b.node_at(0x400), None);
    assert_eq!(b.node_at(0), None);
    assert_eq!(b.node_starting_at(0x200), Some(1));
    assert_eq!(b.node_starting_at(0x201), None);
}

/// A call into a node's middle is dropped (control flow, or data decoded
/// as code); an address into one is kept.
#[test]
fn code_edges_to_nodes() {
    let code = [
        0xE8, 0xFB, 0x0F, 0x00, 0x00, // 1000: call 2000
        0xE8, 0xF7, 0x0F, 0x00, 0x00, // 1005: call 2001 (middle)
        0x48, 0x8D, 0x05, 0xF2, 0x0F, 0x00, 0x00, // 100a: lea rax, [2003]
        0xE8, 0xF1, 0xFF, 0xFF, 0xFF, // 1011: call 1007 (itself)
    ];
    let mut b = Builder::new(vec![node(0x1000, 0x1016, true), node(0x2000, 0x2010, true)]);
    b.code(0, Arch::X64, &code);
    let g = b.finish();
    // The call and the address to 2000 dedupe to the call.
    assert_eq!(g.references(0), [(1, Edge::Call)]);
    assert_eq!(g.referrers(1), [(0, Edge::Call)]);
    assert_eq!(g.referrers(0), []);
    assert_eq!(g.edge_count(), 1);
}

/// An address computed just before a node means it, even inside another;
/// one accessed there is the other's.
#[test]
fn addresses_just_before_a_node() {
    let code = [
        0x48, 0x8D, 0x05, 0xF2, 0x0F, 0x00, 0x00, // 1000: lea rax, [1FF9h] (2000 - 7)
        0x8B, 0x05, 0xF2, 0x0F, 0x00, 0x00, // 1007: mov eax, [1FFFh]
        0x48, 0x8D, 0x05, 0xF9, 0x1F, 0x00, 0x00, // 100d: lea rax, [3014h]: in a gap
    ];
    let mut b = Builder::new(vec![
        node(0x1000, 0x1014, true),
        node(0x1F00, 0x2000, false), // packed against the next
        node(0x2000, 0x2100, false),
        node(0x3018, 0x3100, false), // after a gap
    ]);
    b.code(0, Arch::X64, &code);
    let g = b.finish();
    assert_eq!(
        g.references(0),
        [(1, Edge::Address), (2, Edge::Address), (3, Edge::Address)]
    );
    // A computed address at a node's start means that node alone, even
    // with another just after it.
    let mut b = Builder::new(vec![
        node(0x1000, 0x1007, true),
        node(0x2000, 0x2003, true),
        node(0x2004, 0x2008, true),
    ]);
    b.code(0, Arch::X64, &[0x48, 0x8D, 0x05, 0xF9, 0x0F, 0x00, 0x00]); // lea rax, [2000h]
    assert_eq!(b.finish().references(0), [(1, Edge::Address)]);
    // The load alone keeps only the node it reads.
    let mut b = Builder::new(vec![
        node(0x1000, 0x1014, true),
        node(0x1F00, 0x2000, false),
        node(0x2000, 0x2100, false),
    ]);
    b.code(0, Arch::X64, &code[7..13]);
    let g = b.finish();
    assert_eq!(g.references(0), [(1, Edge::Address)]);
}

#[test]
fn reach_and_chains() {
    // 0 -> 1 -> 2 -> 3, 0 -> 3 (shorter), 4 <-> 5 (a cycle, unreached),
    // 6 a second root -> 2.
    let nodes = (0..7).map(|i| node(i * 16, i * 16 + 16, true)).collect();
    let mut b = Builder::new(nodes);
    b.edge(0, 1, Edge::Call);
    b.edge(1, 2, Edge::Pointer);
    b.edge(2, 3, Edge::Jump);
    b.edge(0, 3, Edge::Address);
    b.edge(4, 5, Edge::Call);
    b.edge(5, 4, Edge::Call);
    b.edge(6, 2, Edge::Attached);
    b.edge(6, 6, Edge::Call); // dropped
    b.edge_at(0x48, 0x50, Edge::Call); // 4 -> 5 again
    b.edge_at(0x48, 0x1000, Edge::Call); // to nothing: dropped
    let g = b.finish();
    assert_eq!(g.edge_count(), 7);
    let r = g.reach(&[0, 6]);
    for i in 0..4 {
        assert!(r.is_reached(i), "{i}");
    }
    assert!(!r.is_reached(4) && !r.is_reached(5));
    assert!(r.is_root(0) && r.is_root(6) && !r.is_root(1));
    assert_eq!(r.chain(3), Some((0, vec![(Edge::Address, 3)])));
    // 2 is one step from the second root, two from the first.
    assert_eq!(r.chain(2), Some((6, vec![(Edge::Attached, 2)])));
    assert_eq!(r.chain(1), Some((0, vec![(Edge::Call, 1)])));
    assert_eq!(
        g.reach(&[0]).chain(2),
        Some((0, vec![(Edge::Call, 1), (Edge::Pointer, 2)]))
    );
    assert_eq!(r.chain(0), Some((0, vec![])));
    assert_eq!(r.chain(4), None);
    // Roots given twice, or none.
    assert!(g.reach(&[0, 0]).is_root(0));
    assert!(!g.reach(&[]).is_reached(0));
}

/// A node split where it is referred to: each piece reaches only what its
/// own pointers do.
#[test]
fn split_nodes() {
    // 0: code; 1: unlabeled data at 0x100-0x140 holding two "vtables"
    // (0x100 and 0x120), each pointing to its own function (2, 3); 4: code
    // that refers to neither.
    let mut b = Builder::new(vec![
        node(0x0, 0x10, true),
        node(0x100, 0x140, false),
        node(0x200, 0x210, true),
        node(0x300, 0x310, true),
        node(0x400, 0x410, true),
    ]);
    b.split(1);
    b.edge_at(0x8, 0x120, Edge::Address); // 0 refers to the second
    b.edge_at(0x108, 0x200, Edge::Pointer); // the first points to 2
    b.edge_at(0x128, 0x300, Edge::Pointer); // the second points to 3
    b.edge_at(0x130, 0x400, Edge::Pointer); // and to 4
    b.edge(0, 4, Edge::Call); // by index: not split, unaffected
    let g = b.finish();
    let starts: Vec<(u64, u64)> = g.nodes().iter().map(|n| (n.start, n.end)).collect();
    assert_eq!(
        starts,
        [
            (0, 0x10),
            (0x100, 0x120),
            (0x120, 0x140),
            (0x200, 0x210),
            (0x300, 0x310),
            (0x400, 0x410)
        ]
    );
    assert_eq!(g.pieces(1), 1..3);
    assert_eq!(g.pieces(0), 0..1);
    assert_eq!(g.pieces(4), 5..6);
    assert_eq!(g.origin(2), 1);
    assert_eq!(g.origin(5), 4);
    let r = g.reach(&[0]);
    assert!(r.is_reached(2) && r.is_reached(4) && r.is_reached(5));
    // The first piece, and what only it points to, are not.
    assert!(!r.is_reached(1) && !r.is_reached(3));
    assert_eq!(g.references(1), [(3, Edge::Pointer)]);
    // A node to split that nothing refers into stays whole.
    let mut b = Builder::new(vec![node(0, 0x10, false), node(0x10, 0x20, true)]);
    b.split(0);
    b.edge_at(0x4, 0x10, Edge::Pointer);
    let g = b.finish();
    assert_eq!(g.nodes().len(), 2);
    assert_eq!(g.references(0), [(1, Edge::Pointer)]);
}

#[test]
fn duplicate_edges_keep_the_strongest_kind() {
    let mut b = Builder::new(vec![node(0, 1, true), node(1, 2, true)]);
    b.edge(0, 1, Edge::Attached);
    b.edge(0, 1, Edge::Address);
    b.edge(0, 1, Edge::Call);
    let g = b.finish();
    assert_eq!(g.references(0), [(1, Edge::Call)]);
    assert_eq!(Edge::Call.verb(), "calls");
}

/// Hostile input: random bytes as code never panic.
#[test]
fn random_code() {
    let mut x = 0x1234_5678_9ABC_DEF0u64;
    let mut bytes = vec![0u8; 4096];
    for b in &mut bytes {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = x.to_le_bytes()[0];
    }
    let mut b = Builder::new(vec![
        node(0, 4096, true),
        node(u64::MAX - 8, u64::MAX, false),
    ]);
    for arch in [Arch::X86, Arch::X64, Arch::Arm64] {
        b.code(0, arch, &bytes);
        b.code(1, arch, &bytes[..8]);
    }
    b.finish();
}
