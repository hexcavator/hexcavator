//! The addresses code refers to, found by disassembling it.
//!
//! - Direct calls and branches (x86 `call`/`jmp`/`jcc` with a relative
//!   target; ARM64 `B`, `BL`, `B.cond`, `BC.cond`, `CBZ`/`CBNZ`,
//!   `TBZ`/`TBNZ`).
//! - x86-64: every RIP-relative memory operand without a segment or index
//!   (`lea rax, [rip + x]`, `mov eax, [rip + x]`, `call [rip + x]`); with
//!   [`scan_image`], operands relative to the image's address too.
//! - ARM64: `ADRP` page addresses completed by the `ADD` (immediate) or
//!   unsigned-offset load or store that uses them, and addresses an `ADD`
//!   computes from those (an object's fields, an array, by immediate,
//!   unscaled, or register offset); `ADR`, and literal loads
//!   (`LDR x0, label`). A register's page is forgotten when an
//!   instruction may write the register, so an unrelated value is never
//!   taken for one.
//!
//! 32-bit x86 code holds absolute addresses, which the image's relocations
//! (not disassembly) find. Decoding is a linear sweep that stops at the
//! first invalid instruction (data in a function's range, such as a
//! literal pool or jump table, can follow its code).

/// The instruction sets (x86, x64, and ARM64 code is scanned; others
/// have no references found).
pub use hexcavator_core::Arch;

/// How code refers to an address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Via {
    /// A direct call.
    Call,
    /// A direct branch (within a function, or a tail call).
    Jump,
    /// An address an operand accesses (data loaded or stored, an import
    /// address table entry called through).
    Address,
    /// An address an instruction computes without accessing it (x86 `lea`,
    /// ARM64 `ADR` and `ADRP` with `ADD`): a datum's or a function whose
    /// address is taken.
    AddressOf,
}

/// One reference: the instruction's address, the address it refers to,
/// and how.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CodeRef {
    /// The referring instruction's address.
    pub from: u64,
    /// The address it refers to.
    pub to: u64,
    /// How.
    pub via: Via,
}

/// Appends the references of `code`, which is at `address`, to `out`.
pub fn scan(arch: Arch, code: &[u8], address: u64, out: &mut Vec<CodeRef>) {
    scan_image(arch, code, address, None, out);
}

/// [`scan`], knowing where the image starts (`image_base`, in the same
/// address space as `address`): x86-64 code then also refers to tables by
/// their offset from a register holding the image's address, as MSVC
/// compiles them (`lea r9, [__ImageBase]`, then `[r9 + rcx*4 + table]`).
/// A register holds the image's address from a `lea` of exactly it until
/// an instruction writes the register (its first operand). Calls don't end
/// it: the sweep is in address order, not control flow, and code after a
/// call can be reached without one; a compiler reloads the register before
/// using it again after a call that changes it, and the reload is a write.
pub fn scan_image(
    arch: Arch,
    code: &[u8],
    address: u64,
    image_base: Option<u64>,
    out: &mut Vec<CodeRef>,
) {
    match arch {
        Arch::X86 => x86(code, address, hexcavator_x86::Mode::Bits32, None, out),
        Arch::X64 => x86(code, address, hexcavator_x86::Mode::Bits64, image_base, out),
        Arch::Arm64 => arm64(code, address, out),
        // (No scanner for the others yet: no references.)
        _ => {}
    }
}

fn x86(
    code: &[u8],
    address: u64,
    mode: hexcavator_x86::Mode,
    image_base: Option<u64>,
    out: &mut Vec<CodeRef>,
) {
    use hexcavator_x86::{Flow, Mnemonic, Operand, RegClass, Register};
    let gpr = |r: Register| {
        matches!(
            r.class(),
            RegClass::Gpr8
                | RegClass::Gpr8High
                | RegClass::Gpr16
                | RegClass::Gpr32
                | RegClass::Gpr64
        )
        .then(|| r.full().index())
        .filter(|&i| i < 32)
    };
    // The registers holding the image's address, by number; and what they
    // are at the targets of jumps ahead, where the sweep merges them in (a
    // register holds it there if it does on any path seen).
    let mut based = 0u32;
    // Those that held it anywhere so far.
    let mut ever = 0u32;
    let mut ahead: Vec<(u64, u32)> = Vec::new();
    let holds_base =
        |based: u32, r: Option<Register>| r.and_then(gpr).is_some_and(|i| based & (1 << i) != 0);
    let mut at = 0usize;
    while at < code.len() {
        let pc = address.wrapping_add(at as u64);
        if !ahead.is_empty() {
            ahead.retain(|&(target, regs)| {
                if target == pc {
                    based |= regs;
                }
                target > pc
            });
        }
        let Ok(inst) = hexcavator_x86::decode(&code[at..], mode, pc) else {
            return;
        };
        if based != 0
            && matches!(inst.flow(), Flow::Jump | Flow::ConditionalJump)
            && let Some(target) = inst.branch_target()
            && target > pc
        {
            ahead.push((target, based));
        }
        let branch = matches!(inst.flow(), Flow::Call | Flow::Jump | Flow::ConditionalJump);
        let ops = inst.operands();
        let access = if inst.mnemonic() == Mnemonic::Lea {
            Via::AddressOf
        } else {
            Via::Address
        };
        if let Some(base) = image_base {
            for op in ops {
                // [base + index*scale + table], or [index*scale + table]
                // with the image's address added after (`lea rax,
                // [rax*4 + table]` then `add rax, rdx`): a register holds
                // it, and no base register makes the displacement absolute.
                // A register that held it anywhere in the function counts
                // too with an offset past the image's first page (a jump
                // table's cases run in an order the sweep can't see, so a
                // write in one case doesn't end it in the next; a field's
                // offset is rarely that large).
                let Operand::Mem(m) = op else {
                    continue;
                };
                let sticky = m.disp >= 0x1000;
                let held = |r| holds_base(based, r) || (sticky && holds_base(ever, r));
                if !m.is_rip_relative()
                    && m.disp > 0
                    && (held(m.base)
                        || (m.scale <= 1 && held(m.index))
                        || (m.base.is_none() && m.index.is_some() && (based | ever) != 0))
                {
                    out.push(CodeRef {
                        from: pc,
                        to: base.wrapping_add(m.disp as u64),
                        via: access,
                    });
                }
            }
            // What the instruction writes no longer holds the image's
            // address, unless it is a lea of it.
            let lea_of_base = match ops {
                [Operand::Reg(r), Operand::Mem(m)]
                    if inst.mnemonic() == Mnemonic::Lea && m.is_rip_relative() =>
                {
                    (inst.next_address().wrapping_add_signed(m.disp) == base)
                        .then(|| gpr(*r))
                        .flatten()
                }
                _ => None,
            };
            if let Some(Operand::Reg(r)) = ops.first()
                && let Some(i) = gpr(*r)
            {
                based &= !(1 << i);
            }
            if let Some(i) = lea_of_base {
                based |= 1 << i;
                ever |= 1 << i;
            }
        }
        for op in ops {
            match op {
                Operand::Rel(target) if branch => out.push(CodeRef {
                    from: pc,
                    to: *target,
                    via: if inst.flow() == Flow::Call {
                        Via::Call
                    } else {
                        Via::Jump
                    },
                }),
                Operand::Mem(m)
                    if m.is_rip_relative() && m.segment.is_none() && m.index.is_none() =>
                {
                    let to = inst.next_address().wrapping_add_signed(m.disp);
                    if to != 0 {
                        out.push(CodeRef {
                            from: pc,
                            to,
                            via: access,
                        });
                    }
                }
                _ => {}
            }
        }
        at += inst.len().max(1);
    }
}

/// Sign-extends the low `bits` bits of `v`.
fn sext(v: u32, bits: u32) -> i64 {
    let shift = 64 - bits;
    (i64::from(v) << shift) >> shift
}

fn arm64(code: &[u8], address: u64, out: &mut Vec<CodeRef>) {
    // Each register's page, from an ADRP not yet overwritten; and each
    // register's address, from an ADD to a page or to another address (an
    // object's fields and arrays are reached from it).
    let mut pages = [None::<u64>; 32];
    let mut addrs = [None::<u64>; 32];
    for (i, w) in code.as_chunks::<4>().0.iter().enumerate() {
        let word = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
        let pc = address.wrapping_add(i as u64 * 4);
        let Some(inst) = hexcavator_arm64::decode(word, pc) else {
            return;
        };
        let name = inst.encoding_name();
        let rd = (word & 31) as usize;
        let rn = ((word >> 5) & 31) as usize;
        let adr_imm = || sext(((word >> 5) & 0x7FFFF) << 2 | ((word >> 29) & 3), 21);
        let mut push = |to: u64, via: Via| out.push(CodeRef { from: pc, to, via });
        // The address an ADD computes, which its destination then holds.
        let mut computed = None;
        match name {
            "ADRP_only_pcreladdr" => {
                pages[rd] = Some((pc & !0xFFF).wrapping_add_signed(adr_imm() << 12));
                continue;
            }
            "BL_only_branch_imm" | "B_only_branch_imm" => {
                let to = pc.wrapping_add_signed(sext(word & 0x3FF_FFFF, 26) << 2);
                push(
                    to,
                    if name.starts_with("BL") {
                        Via::Call
                    } else {
                        Via::Jump
                    },
                );
                continue;
            }
            "B_only_condbranch" | "BC_only_condbranch" => {
                push(
                    pc.wrapping_add_signed(sext((word >> 5) & 0x7FFFF, 19) << 2),
                    Via::Jump,
                );
                continue;
            }
            "TBZ_only_testbranch" | "TBNZ_only_testbranch" => {
                push(
                    pc.wrapping_add_signed(sext((word >> 5) & 0x3FFF, 14) << 2),
                    Via::Jump,
                );
                continue;
            }
            _ => {}
        }
        if name.ends_with("_compbranch") {
            push(
                pc.wrapping_add_signed(sext((word >> 5) & 0x7FFFF, 19) << 2),
                Via::Jump,
            );
            continue;
        }
        if name == "ADR_only_pcreladdr" {
            push(pc.wrapping_add_signed(adr_imm()), Via::AddressOf);
        } else if name.ends_with("_loadlit") {
            push(
                pc.wrapping_add_signed(sext((word >> 5) & 0x7FFFF, 19) << 2),
                Via::Address,
            );
        } else if name.ends_with("ADD_64_addsub_imm") {
            if let Some(base) = pages[rn].or(addrs[rn]) {
                let shift = if (word >> 22) & 1 == 1 { 12 } else { 0 };
                let imm = u64::from((word >> 10) & 0xFFF) << shift;
                let to = base.wrapping_add(imm);
                push(to, Via::AddressOf);
                computed = Some(to);
            }
        } else if name.ends_with("_ldst_regoff")
            && let Some(base) = pages[rn].or(addrs[rn])
        {
            // An array's element: the array.
            push(base, Via::Address);
        } else if name.ends_with("_ldst_unscaled")
            && let Some(base) = addrs[rn]
        {
            push(
                base.wrapping_add_signed(sext((word >> 12) & 0x1FF, 9)),
                Via::Address,
            );
        } else if name.ends_with("_ldst_pos")
            && let Some(page) = pages[rn].or(addrs[rn])
        {
            let size = (word >> 30) & 3;
            let simd = (word >> 26) & 1 == 1;
            let opc = (word >> 22) & 3;
            // A 128-bit SIMD access scales by 16, the rest by their size.
            let scale = if simd && size == 0 && opc & 2 != 0 {
                4
            } else {
                size
            };
            let imm = u64::from((word >> 10) & 0xFFF) << scale;
            push(page.wrapping_add(imm), Via::Address);
        }
        // What the instruction may have written is no longer a page.
        // (Stores and branches write no general register at bits 0-4;
        // loads of SIMD registers don't either.)
        let simd_load = name.starts_with("LD") && (word >> 26) & 1 == 1;
        let writes_rd = !(name.starts_with("ST")
            || name.starts_with('B')
            || name.starts_with("CB")
            || name.starts_with("TB")
            || name.starts_with("RET")
            || name.starts_with("PRFM")
            || simd_load);
        if writes_rd {
            pages[rd] = None;
            addrs[rd] = None;
        }
        if name.starts_with("LDP") && !simd_load {
            pages[((word >> 10) & 31) as usize] = None;
            addrs[((word >> 10) & 31) as usize] = None;
        }
        // Writeback (pre- or post-indexed) changes the base.
        if name.contains("_ldst_immpre") || name.contains("_ldst_immpost") {
            pages[rn] = None;
            addrs[rn] = None;
        }
        if let Some(to) = computed {
            addrs[rd] = Some(to);
        }
    }
}
