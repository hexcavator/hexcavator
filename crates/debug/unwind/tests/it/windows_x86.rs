//! Hermetic x86 tests: FrameData and FPO records, program strings, and
//! stacks built from MSVC's frame shapes.

// Synthetic test data: small values, casts are exact.
#![allow(clippy::cast_possible_truncation)]

use hexcavator_unwind::windows_x86::{
    self, Context, Env, Fpo, FrameData, FrameTable, Method, Record,
};
use hexcavator_unwind::{Error, Memory};

const STACK: u32 = 0x0010_0000;
/// Addresses "after a call", for the return address test.
const CODE: u32 = 0x0040_0000;

/// A stack of 256 words from [`STACK`]; unset words hold a marker (not a
/// return address).
struct Stack {
    words: Vec<u32>,
}

impl Stack {
    fn new() -> Self {
        Stack {
            words: (0..256).map(|i| 0xAA00_0000 + i * 4).collect(),
        }
    }
    fn set(&mut self, address: u32, value: u32) {
        self.words[((address - STACK) / 4) as usize] = value;
    }
}

impl Memory for Stack {
    fn read(&self, address: u64, buf: &mut [u8]) -> bool {
        for (i, b) in buf.iter_mut().enumerate() {
            let Some(off) = (address + i as u64).checked_sub(u64::from(STACK)) else {
                return false;
            };
            let Some(w) = self.words.get((off / 4) as usize) else {
                return false;
            };
            *b = w.to_le_bytes()[(off % 4) as usize];
        }
        true
    }
}

fn is_code(v: u32) -> bool {
    (CODE..CODE + 0x1_0000).contains(&v)
}

fn env(stack: &Stack, callee_params: u32) -> Env<'_> {
    Env {
        memory: stack,
        is_return_address: &is_code,
        callee_params,
        // (Past any prolog.)
        rva: 0x1080,
    }
}

fn frame_data(locals: u32, saved_regs: u16, params: u32) -> FrameData {
    FrameData {
        start: 0x1000,
        size: 0x100,
        locals,
        params,
        max_stack: 0,
        program: 0,
        prolog: 0,
        saved_regs,
        has_seh: false,
        has_eh: false,
        is_function_start: true,
    }
}

fn context(esp: u32) -> Context {
    Context {
        eip: CODE + 0x1010,
        esp,
        ebp: 0xEB00,
        ebx: 0xB0,
        esi: 0x51,
        edi: 0xD1,
        ..Context::default()
    }
}

#[test]
fn parses_records() {
    let mut fd = Vec::new();
    for w in [0x1000u32, 0x40, 12, 8, 0, 77] {
        fd.extend(w.to_le_bytes());
    }
    fd.extend(3u16.to_le_bytes());
    fd.extend(16u16.to_le_bytes());
    fd.extend(5u32.to_le_bytes());
    let d = FrameData::parse(&fd);
    assert_eq!(d.len(), 1);
    assert_eq!(
        (
            d[0].start,
            d[0].size,
            d[0].locals,
            d[0].params,
            d[0].program
        ),
        (0x1000, 0x40, 12, 8, 77)
    );
    assert_eq!((d[0].prolog, d[0].saved_regs), (3, 16));
    assert!(d[0].has_seh && !d[0].has_eh && d[0].is_function_start);

    let mut fpo = Vec::new();
    for w in [0x2000u32, 0x17, 2] {
        fpo.extend(w.to_le_bytes());
    }
    fpo.extend(1u16.to_le_bytes());
    // prolog 5, regs 2, SEH, BP, frame 3.
    fpo.extend((5u16 | 2 << 8 | 1 << 11 | 1 << 12 | 3 << 14).to_le_bytes());
    let f = Fpo::parse(&fpo);
    assert_eq!(
        f,
        [Fpo {
            start: 0x2000,
            size: 0x17,
            locals: 2,
            params: 1,
            prolog: 5,
            regs: 2,
            has_seh: true,
            uses_bp: true,
            frame: 3,
        }]
    );
    // (A partial record is ignored.)
    assert_eq!(FrameData::parse(&fd[..31]).len(), 0);
}

#[test]
fn table_lookup_prefers_the_innermost_block() {
    let outer = FrameData {
        start: 0x1000,
        size: 0x100,
        ..frame_data(0, 0, 0)
    };
    let inner = FrameData {
        start: 0x1004,
        size: 0x10,
        ..frame_data(4, 0, 0)
    };
    let fpo = Fpo {
        start: 0x3000,
        size: 0x20,
        locals: 0,
        params: 0,
        prolog: 0,
        regs: 0,
        has_seh: false,
        uses_bp: false,
        frame: 0,
    };
    let t = FrameTable::new(vec![inner, outer], vec![fpo]);
    assert_eq!(t.find(0x1000), Some(Record::FrameData(outer)));
    assert_eq!(t.find(0x1008), Some(Record::FrameData(inner)));
    // Past the inner block, still in the outer.
    assert_eq!(t.find(0x1020), Some(Record::FrameData(outer)));
    assert_eq!(t.find(0x3010), Some(Record::Fpo(fpo)));
    assert_eq!(t.find(0x3020), None);
    assert_eq!(t.find(0x0FFF), None);
}

#[test]
fn program_with_frame_pointer() {
    // The EBP frame MSVC describes: `$T0 $ebp = $eip $T0 4 + ^ = $ebp $T0 ^
    // = $esp $T0 8 + =`, with saved EBX (by CodeView number).
    let mut stack = Stack::new();
    let ebp = STACK + 0x40;
    stack.set(ebp, 0x1111);
    stack.set(ebp + 4, CODE + 0x55);
    stack.set(ebp - 8, 0xBBBB);
    let mut c = context(STACK);
    c.ebp = ebp;
    let program = b"$T0 $ebp = $eip $T0 4 + ^ = $ebp $T0 ^ = $esp $T0 8 + =  $20 $T0 8 - ^ = ";
    let d = frame_data(16, 8, 4);
    let f = windows_x86::unwind(
        &mut c,
        Some(Record::FrameData(d)),
        Some(program),
        &env(&stack, 0),
    )
    .unwrap();
    assert_eq!(f.method, Method::Program);
    assert_eq!(f.params, 4);
    assert_eq!(f.return_address_at, ebp + 4);
    assert_eq!(
        (c.eip, c.esp, c.ebp, c.ebx),
        (CODE + 0x55, ebp + 8, 0x1111, 0xBBBB)
    );
    // Registers the program doesn't assign keep their values.
    assert_eq!((c.esi, c.edi), (0x51, 0xD1));
}

#[test]
fn ra_search_skips_locals_saved_registers_and_finds_the_return_address() {
    // `.raSearch` starts past the locals and saved registers, and moves up
    // past words that aren't return addresses (an aligned frame's
    // padding).
    let mut stack = Stack::new();
    let sp = STACK + 0x20;
    stack.set(sp + 4, CODE + 1); // an argument that looks like one (ignored)
    stack.set(sp + 24 + 8, CODE + 0x77);
    stack.set(sp + 24 - 4, 0x5151);
    let mut c = context(sp);
    let program = b"$T0 .raSearch = $eip $T0 ^ = $esp $T0 4 + =  $23 $T0 4 - ^ = ";
    let d = frame_data(16, 8, 0);
    let f = windows_x86::unwind(
        &mut c,
        Some(Record::FrameData(d)),
        Some(program),
        &env(&stack, 0),
    )
    .unwrap();
    assert_eq!(f.return_address_at, sp + 32);
    assert_eq!((c.eip, c.esp), (CODE + 0x77, sp + 36));
    assert_eq!(c.esi, Stack::new().words[((sp + 28 - STACK) / 4) as usize]);

    // Nothing found: the start itself.
    let stack = Stack::new();
    let mut c = context(sp);
    let f = windows_x86::unwind(
        &mut c,
        Some(Record::FrameData(d)),
        Some(program),
        &env(&stack, 0),
    )
    .unwrap();
    assert_eq!(f.return_address_at, sp + 24);
}

#[test]
fn ra_search_start_is_from_the_stack_pointer() {
    // An exception filter's call stub: its record has its parent's sizes,
    // but its return address is at the stack pointer.
    let mut stack = Stack::new();
    let sp = STACK + 0x20;
    stack.set(sp, CODE + 0x10);
    stack.set(sp + 40, CODE + 0x20);
    let mut c = context(sp);
    let program =
        b"$T0 $ebp = $T2 $esp = $T1 .raSearchStart = $eip $T1 ^ = $ebp $T0 = $esp $T1 4 + = ";
    let d = frame_data(24, 16, 4);
    windows_x86::unwind(
        &mut c,
        Some(Record::FrameData(d)),
        Some(program),
        &env(&stack, 0),
    )
    .unwrap();
    assert_eq!((c.eip, c.esp, c.ebp), (CODE + 0x10, sp + 4, 0xEB00));
}

#[test]
fn realigned_frame() {
    // `$T1 .raSearch = $T0 $T1 4 - 8 @ = $ebp $T1 4 - ^ = ...`: align.
    let mut stack = Stack::new();
    let sp = STACK + 0x20;
    stack.set(sp + 12, 0x4444);
    stack.set(sp + 16, CODE + 0x99);
    let mut c = context(sp);
    let program =
        b"$T1 .raSearch = $T0  $T1 4 - 8 @ = $ebp $T1 4 - ^ = $eip $T1 ^ = $esp $T1 4 + =";
    let d = frame_data(16, 0, 0);
    windows_x86::unwind(
        &mut c,
        Some(Record::FrameData(d)),
        Some(program),
        &env(&stack, 0),
    )
    .unwrap();
    assert_eq!((c.eip, c.esp, c.ebp), (CODE + 0x99, sp + 20, 0x4444));
}

#[test]
fn operators() {
    let stack = Stack::new();
    let run = |p: &[u8]| {
        let mut c = context(STACK + 0x10);
        windows_x86::unwind(
            &mut c,
            Some(Record::FrameData(frame_data(0, 0, 0))),
            Some(p),
            &env(&stack, 0),
        )
        .map(|_| (c.eip, c.esp))
    };
    assert_eq!(run(b"$eip 7 3 * = $esp 100 7 % ="), Ok((21, 2)));
    assert_eq!(run(b"$eip 20 6 / = $esp 0x10 3 - ="), Ok((3, 13)));
    assert_eq!(run(b"$eip 0x1237 16 @ = $esp -4 8 + ="), Ok((0x1230, 4)));
    // A temporary, reassigned; and `.cbSavedRegs` and friends.
    assert_eq!(
        run(b"$T0 5 = $T0 $T0 1 + = $eip $T0 = $esp .cbLocals .cbParams + ="),
        Ok((6, 0))
    );
    // Errors: division by zero, alignment to 0, an unknown name, a short
    // stack, assigning to a number, no $eip, a bad number, memory.
    for bad in [
        &b"$eip 1 0 / = $esp 0 ="[..],
        b"$eip 1 0 % = $esp 0 =",
        b"$eip 1 0 @ = $esp 0 =",
        b"$eip $T9 = $esp 0 =",
        b"$eip + = $esp 0 =",
        b"1 2 = $eip 0 = $esp 0 =",
        b"$esp 0 =",
        b"$eip 12x = $esp 0 =",
    ] {
        assert_eq!(
            run(bad),
            Err(Error::Expression),
            "{:?}",
            core::str::from_utf8(bad)
        );
    }
    assert_eq!(
        run(b"$eip 8 ^ = $esp 0 ="),
        Err(Error::Memory { address: 8 })
    );
}

#[test]
fn fpo_record_sizes() {
    // asm_fpo: push ebx; push esi; sub esp, 8 (2 locals, 2 registers).
    let mut stack = Stack::new();
    let sp = STACK + 0x20;
    stack.set(sp + 16, CODE + 0x31);
    let f = Fpo {
        start: 0x1000,
        size: 0x20,
        locals: 2,
        params: 1,
        prolog: 5,
        regs: 2,
        has_seh: false,
        uses_bp: false,
        frame: 0,
    };
    let mut c = context(sp);
    let fr = windows_x86::unwind(&mut c, Some(Record::Fpo(f)), None, &env(&stack, 0)).unwrap();
    assert_eq!((fr.method, fr.params), (Method::Sizes, 4));
    assert_eq!((c.eip, c.esp, c.ebp), (CODE + 0x31, sp + 20, 0xEB00));

    // A trap or TSS frame: unsupported. A standard frame: the EBP chain.
    let mut c = context(sp);
    assert_eq!(
        windows_x86::unwind(
            &mut c,
            Some(Record::Fpo(Fpo { frame: 1, ..f })),
            None,
            &env(&stack, 0)
        ),
        Err(Error::Unsupported { rva: 0x1000 })
    );
    let mut stack = Stack::new();
    stack.set(sp, 0x7777);
    stack.set(sp + 4, CODE + 0x41);
    let mut c = context(STACK);
    c.ebp = sp;
    let fr = windows_x86::unwind(
        &mut c,
        Some(Record::Fpo(Fpo { frame: 3, ..f })),
        None,
        &env(&stack, 0),
    )
    .unwrap();
    assert_eq!(fr.method, Method::FramePointer);
    assert_eq!((c.eip, c.esp, c.ebp), (CODE + 0x41, sp + 8, 0x7777));
}

#[test]
fn no_record_is_the_ebp_chain() {
    let mut stack = Stack::new();
    let ebp = STACK + 0x80;
    stack.set(ebp, 0x2222);
    stack.set(ebp + 4, CODE + 0x12);
    let mut c = context(STACK);
    c.ebp = ebp;
    let fr = windows_x86::unwind(&mut c, None, None, &env(&stack, 0)).unwrap();
    assert_eq!(fr.method, Method::FramePointer);
    assert_eq!((c.eip, c.esp, c.ebp), (CODE + 0x12, ebp + 8, 0x2222));
    // Off the stack: an error.
    let mut c = context(STACK);
    c.ebp = 0x10;
    assert_eq!(
        windows_x86::unwind(&mut c, None, None, &env(&stack, 0)),
        Err(Error::Memory { address: 0x14 })
    );
}

#[test]
fn frame_data_without_a_program() {
    let mut stack = Stack::new();
    let sp = STACK + 0x20;
    // The callee's 8 bytes of arguments lie above its return address.
    stack.set(sp + 12 + 4, CODE + 0x66);
    let mut c = context(sp);
    windows_x86::unwind(
        &mut c,
        Some(Record::FrameData(frame_data(8, 4, 0))),
        None,
        &env(&stack, 8),
    )
    .unwrap();
    assert_eq!((c.eip, c.esp), (CODE + 0x66, sp + 20));
}

#[test]
fn context_record() {
    let mut stack = Stack::new();
    let at = STACK + 0x100;
    for (off, v) in [
        (0x9C, 1u32),
        (0xA0, 2),
        (0xA4, 3),
        (0xA8, 4),
        (0xAC, 5),
        (0xB0, 6),
        (0xB4, 7),
        (0xB8, CODE + 8),
        (0xC4, 9),
    ] {
        stack.set(at + off, v);
    }
    let mut c = context(STACK);
    let f = windows_x86::unwind_context_record(&mut c, &stack, at).unwrap();
    assert_eq!(f.method, Method::ContextRecord);
    assert_eq!(
        c,
        Context {
            edi: 1,
            esi: 2,
            ebx: 3,
            edx: 4,
            ecx: 5,
            eax: 6,
            ebp: 7,
            eip: CODE + 8,
            esp: 9,
        }
    );
}

#[test]
fn hostile_programs_never_panic() {
    let mut x = 0x2545_F491_4F6C_DD1Du64;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let tokens: [&[u8]; 20] = [
        b"$eip",
        b"$esp",
        b"$ebp",
        b"$T0",
        b"$T1",
        b"$20",
        b".raSearch",
        b".raSearchStart",
        b".cbLocals",
        b"+",
        b"-",
        b"*",
        b"/",
        b"%",
        b"@",
        b"^",
        b"=",
        b"4",
        b"0",
        b"-8",
    ];
    let mut stack = Stack::new();
    for i in 0..256 {
        stack.set(
            STACK + 4 * i,
            if i % 7 == 0 {
                CODE + i
            } else {
                STACK + 4 * (i * 13 % 256)
            },
        );
    }
    for _ in 0..20_000 {
        let n = (next() % 24) as usize;
        let mut p = Vec::new();
        for _ in 0..n {
            p.extend_from_slice(tokens[(next() % 20) as usize]);
            p.push(b' ');
        }
        let mut c = context(STACK + 4 * (next() % 64) as u32);
        let d = frame_data((next() % 64) as u32 * 4, (next() % 8) as u16 * 4, 0);
        let _ = windows_x86::unwind(
            &mut c,
            Some(Record::FrameData(d)),
            Some(&p),
            &env(&stack, (next() % 4) as u32 * 4),
        );
    }
    // A very long program is refused.
    let long: Vec<u8> = b"1 ".repeat(5000);
    let mut c = context(STACK);
    assert_eq!(
        windows_x86::unwind(
            &mut c,
            Some(Record::FrameData(frame_data(0, 0, 0))),
            Some(&long),
            &env(&stack, 0)
        ),
        Err(Error::Expression)
    );
}
