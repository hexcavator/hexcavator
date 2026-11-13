use super::*;
use alloc::vec;

/// x86-64: a loop, a forward branch, a jump back, a call, a return, and a
/// byte that isn't an instruction.
const X64: &[u8] = &[
    0x31, 0xC0, // 1000: xor eax,eax
    0xFF, 0xC0, // 1002: inc eax          <- loop
    0x83, 0xF8, 0x05, // 1004: cmp eax,5
    0x7C, 0xF9, // 1007: jl 1002
    0x74, 0x02, // 1009: je 100d
    0xEB, 0xF5, // 100b: jmp 1002
    0xE8, 0xEE, 0x0F, 0x00, 0x00, // 100d: call 2000
    0xC3, // 1012: ret
    0x06, // 1013: (not in 64-bit mode)
];

#[test]
fn x64_instructions_and_blocks() {
    let (insns, stopped) = sweep(Arch::X64, X64, 0x1000);
    assert_eq!(stopped, Some(0x1013));
    let flows: Vec<Flow> = insns.iter().map(|i| i.flow).collect();
    use Flow::*;
    assert_eq!(
        flows,
        [Next, Next, Next, Branch, Branch, Jump, Call, Return]
    );
    assert_eq!(insns[3].target, Some(0x1002));
    assert_eq!(insns[6].target, Some(0x2000));
    assert_eq!(insns[6].end(), 0x1012);
    let b = blocks(&insns);
    type Shape = (usize, usize, Vec<(usize, Edge)>);
    let shape: Vec<Shape> = b
        .iter()
        .map(|b| (b.first, b.count, b.successors.clone()))
        .collect();
    assert_eq!(
        shape,
        [
            (0, 1, vec![(1, Edge::Next)]),
            (1, 3, vec![(1, Edge::Taken), (2, Edge::NotTaken)]),
            (4, 1, vec![(4, Edge::Taken), (3, Edge::NotTaken)]),
            (5, 1, vec![(1, Edge::Jump)]),
            (6, 2, vec![]),
        ]
    );
    assert_eq!(branch_targets(&insns), [0x1002, 0x100d]);
}

#[test]
fn x86_is_32_bit() {
    // inc eax (40 in 32-bit mode; a REX prefix in 64-bit), ret.
    let (insns, stopped) = sweep(Arch::X86, &[0x40, 0xC3], 0x400);
    assert_eq!(stopped, None);
    assert_eq!(insns.len(), 2);
    assert_eq!(insns[1].flow, Flow::Return);
}

fn words(ws: &[u32]) -> Vec<u8> {
    ws.iter().flat_map(|w| w.to_le_bytes()).collect()
}

#[test]
fn arm64_branches() {
    let code = words(&[
        0x5280_0000, // 1000: mov w0,#0
        0x1100_0400, // 1004: add w0,w0,#1     <- loop
        0x7100_141F, // 1008: cmp w0,#5
        0x54FF_FFCB, // 100c: b.lt 1004
        0x3400_0040, // 1010: cbz w0,1018
        0x3600_0040, // 1014: tbz w0,#0,101c
        0x9400_0400, // 1018: bl 2018
        0x1400_0001, // 101c: b 1020
        0xD61F_0000, // 1020: br x0
        0xD65F_03C0, // 1024: ret
    ]);
    let (insns, stopped) = sweep(Arch::Arm64, &code, 0x1000);
    assert_eq!(stopped, None);
    let got: Vec<(Flow, Option<u64>)> = insns.iter().map(|i| (i.flow, i.target)).collect();
    use Flow::*;
    assert_eq!(
        got,
        [
            (Next, None),
            (Next, None),
            (Next, None),
            (Branch, Some(0x1004)),
            (Branch, Some(0x1018)),
            (Branch, Some(0x101C)),
            (Call, Some(0x2018)),
            (Jump, Some(0x1020)),
            (Jump, None),
            (Return, None),
        ]
    );
    // An indirect jump ends a block, with nowhere known to go.
    let b = blocks(&insns);
    let last_two: Vec<_> = b
        .iter()
        .rev()
        .take(2)
        .map(|b| b.successors.clone())
        .collect();
    assert_eq!(last_two, [vec![], vec![]]);
}

/// The targets computed from the encodings agree with those the
/// formatter names, on every branch form, over a sample of words.
#[test]
fn arm64_targets_agree_with_the_formatter() {
    struct Record(core::cell::RefCell<Vec<u64>>);
    impl hexcavator_arm64::Symbols for Record {
        fn name_at(&self, address: u64) -> Option<&str> {
            self.0.borrow_mut().push(address);
            None
        }
    }
    let mut checked = 0;
    for top in [
        0x14u32, 0x17, 0x94, 0x97, 0x54, 0x34, 0x35, 0xB4, 0xB5, 0x36, 0x37, 0xB6, 0xB7,
    ] {
        for low in (0..1u32 << 24).step_by(4093) {
            let word = top << 24 | low;
            let pc = 0x4000_0000;
            let Some(i) = hexcavator_arm64::decode(word, pc) else {
                continue;
            };
            let Some(insn) = decode(Arch::Arm64, &word.to_le_bytes(), pc) else {
                continue;
            };
            let r = Record(core::cell::RefCell::new(Vec::new()));
            hexcavator_arm64::format_with(&i, &r);
            let named = r.0.into_inner().first().copied();
            if matches!(insn.flow, Flow::Call | Flow::Jump | Flow::Branch) {
                assert_eq!(insn.target, named, "{word:08x}");
                checked += 1;
            }
        }
    }
    assert!(checked > 10_000, "{checked}");
}

#[test]
fn nothing_to_decode() {
    assert_eq!(sweep(Arch::Arm64, &[1, 2], 0), (vec![], Some(0)));
    assert_eq!(
        sweep(Arch::RiscV64, &[0x13, 0, 0, 0], 0x10),
        (vec![], Some(0x10))
    );
    assert!(blocks(&[]).is_empty());
    assert!(!decodes(Arch::Wasm32));
    assert!(decodes(Arch::X86));
}
