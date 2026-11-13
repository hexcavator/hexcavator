//! The addresses a function's code refers to, found by disassembling it:
//! bloaty's `DisassembleFindReferences`, which charges otherwise-unlabeled
//! data (string literals, jump tables, anonymous constants) to the first
//! function that refers to it.
//!
//! - x86-64: every RIP-relative memory operand without a segment or index
//!   (`lea rax, [rip + x]`, `mov eax, [rip + x]`), as bloaty does.
//! - ARM64 (bloaty has nothing): `ADRP` page addresses completed by the
//!   `ADD` (immediate) or unsigned-offset load or store that uses them,
//!   `ADR`, and literal loads (`LDR x0, label`). A register's page is
//!   forgotten when an instruction may write the register, so an
//!   unrelated value is never taken for one.
//!
//! Decoding stops at the first invalid instruction, as bloaty's does
//! (data in a function's range, such as a literal pool, can follow).

use crate::rangemap::{DualMap, Label};

/// Charges what `refs` refer to, where `map` labels nothing yet, to whoever
/// `map` gives the referring instruction: each referenced address to the
/// first reference to it (in `refs`' order), up to the next referenced
/// address, the next labeled range, or the end of the `loaded` range
/// (`[start, end)`, a section) it is in, whichever is first. Addresses in
/// no loaded range are skipped.
pub fn charge(map: &mut DualMap, base: &DualMap, refs: &[Reference], loaded: &[(u64, u64)]) {
    let mut wanted: Vec<(u64, Label)> = refs
        .iter()
        .filter(|r| map.vm.get(r.to).is_none())
        .filter_map(|r| Some((r.to, map.vm.get(r.from)?.label)))
        .collect();
    // Stable: the first reference to an address stays first.
    wanted.sort_by_key(|w| w.0);
    wanted.dedup_by_key(|w| w.0);
    for (i, &(to, label)) in wanted.iter().enumerate() {
        let Some(&(_, mut end)) = loaded.iter().find(|(s, e)| to >= *s && to < *e) else {
            continue;
        };
        if let Some(next) = wanted.get(i + 1) {
            end = end.min(next.0);
        }
        if let Some(e) = map.vm.overlapping(to, end).next() {
            end = end.min(e.start);
        }
        map.add_vm(to, end, label, base);
    }
}

/// The instruction sets (x86, x64, and ARM64 are decoded; others show as
/// bytes).
pub use hexcavator_core::Arch;

/// A function to disassemble: its code, where it is, and the names of the
/// image's addresses (sorted by address), for its branches and data.
pub struct Function<'d> {
    pub name: String,
    pub isa: Arch,
    /// For 32-bit ARM: T32 (Thumb) code, not A32.
    pub thumb: bool,
    /// Where the code gives way to data, if it does (an ARM function's
    /// literal pool, by its `$d` mapping symbol): not decoded.
    pub data: Option<u64>,
    pub address: u64,
    pub code: &'d [u8],
    pub symbols: Vec<(u64, String)>,
}

/// The fallback when no function is named exactly as asked: the one
/// function whose name is the given one followed by its parameters
/// (`f` for `f(int)`), kept by address so that a function listed twice
/// (as in an ELF file's two symbol tables) is still one.
pub struct ByNameAlone<'n, T> {
    name: &'n str,
    found: Option<(u64, T)>,
    ambiguous: bool,
}

impl<'n, T> ByNameAlone<'n, T> {
    pub fn new(name: &'n str) -> Self {
        ByNameAlone {
            name,
            found: None,
            ambiguous: false,
        }
    }

    /// Offers the function at `address` named `shown`.
    pub fn offer(&mut self, address: u64, shown: &str, item: impl FnOnce() -> T) {
        let matches =
            !self.name.is_empty() && shown.strip_prefix(self.name).is_some_and(is_parameters);
        if !matches {
            return;
        }
        match &self.found {
            None => self.found = Some((address, item())),
            Some((a, _)) if *a != address => self.ambiguous = true,
            Some(_) => {}
        }
    }

    /// The one function offered, unless there were several.
    pub fn take(self) -> Option<T> {
        if self.ambiguous {
            None
        } else {
            self.found.map(|f| f.1)
        }
    }
}

/// Whether `rest` (what follows a function's name) is just its parameters:
/// a parenthesized list, then at most qualifiers (` const`, ` &&`), not
/// more of a name (as `f(int)::{lambda()#1}::operator()` has).
fn is_parameters(rest: &str) -> bool {
    if !rest.starts_with('(') {
        return false;
    }
    let mut depth = 0usize;
    for (i, c) in rest.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    let after = &rest[i + 1..];
                    return !after.contains("::") && !after.contains('(');
                }
            }
            _ => {}
        }
    }
    false
}

/// Names for the formatters: a local label for a target within the
/// function (`>0` ahead, `<0` behind, as bloaty writes them), else the
/// symbol at the address.
struct Names<'a> {
    labels: &'a [(u64, String, String)],
    current: u64,
    symbols: &'a [(u64, String)],
}

impl Names<'_> {
    fn name(&self, address: u64) -> Option<&str> {
        if let Ok(i) = self.labels.binary_search_by_key(&address, |l| l.0) {
            let (_, ahead, behind) = &self.labels[i];
            return Some(if address > self.current {
                ahead
            } else {
                behind
            });
        }
        let i = self.symbols.binary_search_by_key(&address, |s| s.0).ok()?;
        Some(&self.symbols[i].1)
    }
}

impl hexcavator_x86::format::Symbols for Names<'_> {
    fn name_at(&self, address: u64) -> Option<&str> {
        self.name(address)
    }
}

impl hexcavator_arm64::Symbols for Names<'_> {
    fn name_at(&self, address: u64) -> Option<&str> {
        self.name(address)
    }
}

/// Records the addresses the ARM64 formatter asks names for: its branch
/// and literal targets.
struct Targets(std::cell::RefCell<Vec<u64>>);

impl hexcavator_arm64::Symbols for Targets {
    fn name_at(&self, address: u64) -> Option<&str> {
        self.0.borrow_mut().push(address);
        None
    }
}

/// How control moves: hexcavator-code's, which builds the blocks.
pub use hexcavator_code::{Block, Edge, Flow};

/// How the labels of a listing are named.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Labels {
    /// bloaty's: numbered from 0 where a branch within the function lands
    /// (`0:`), and read `>0` ahead and `<0` behind.
    Bloaty,
    /// A label at each basic block but the first (or it too, if a branch
    /// lands there): `L1`, `L2`, ..., in address order.
    Blocks,
}

/// One instruction of a listing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Line {
    pub address: u64,
    pub bytes: Vec<u8>,
    /// Its text (mnemonic and operands), with labels and symbols named.
    pub text: String,
    /// Its label's number, if it has one.
    pub label: Option<usize>,
    pub flow: Flow,
    /// A direct branch's or call's target.
    pub target: Option<u64>,
}

/// A function's instructions, decoded, in basic blocks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listing {
    pub name: String,
    pub lines: Vec<Line>,
    pub blocks: Vec<Block>,
    /// What didn't decode, from where.
    pub rest: Option<(u64, Vec<u8>)>,
    pub labels: Labels,
}

impl Listing {
    /// A label's name as the listing writes it where it is defined.
    pub fn label_name(&self, n: usize) -> String {
        match self.labels {
            Labels::Bloaty => format!("{n}"),
            Labels::Blocks => format!("L{n}"),
        }
    }

    /// The block that starts at `address`, if one does.
    pub fn block_at(&self, address: u64) -> Option<usize> {
        self.blocks
            .binary_search_by_key(&address, |b| self.lines[b.first].address)
            .ok()
    }
}

/// The function's instructions, decoded, with their labels and blocks:
/// where a branch within the function lands starts a block, as does the
/// instruction after a branch, jump, return, or trap. Other targets, and
/// data, are named by the symbol there. Where the code stops decoding,
/// the rest is kept as bytes.
pub fn decode(f: &Function<'_>, style: Labels) -> Listing {
    enum Inst {
        X86(hexcavator_x86::Instruction),
        Arm64(hexcavator_arm64::Instruction),
        /// With the condition an IT block gives it.
        Arm32(hexcavator_arm32::Instruction, Option<u32>),
    }
    struct Decoded {
        pc: u64,
        len: usize,
        inst: Inst,
        flow: Flow,
        /// A direct branch's or call's target.
        target: Option<u64>,
        /// Every address the instruction names (bloaty labels each).
        named: Vec<u64>,
    }
    let mut insts: Vec<Decoded> = Vec::new();
    let mut rest = 0usize;
    let end = f.address.saturating_add(f.code.len() as u64);
    match f.isa {
        Arch::X86 | Arch::X64 => {
            let mode = if f.isa == Arch::X86 {
                hexcavator_x86::Mode::Bits32
            } else {
                hexcavator_x86::Mode::Bits64
            };
            while rest < f.code.len() {
                let pc = f.address + rest as u64;
                let Ok(i) = hexcavator_x86::decode(&f.code[rest..], mode, pc) else {
                    break;
                };
                let insn = hexcavator_code::decode(f.isa, &f.code[rest..], pc);
                let flow = insn.map_or(Flow::Next, |c| c.flow);
                let target = i.branch_target();
                insts.push(Decoded {
                    pc,
                    len: i.len(),
                    inst: Inst::X86(i),
                    flow,
                    target,
                    named: target.into_iter().collect(),
                });
                rest += i.len();
            }
        }
        Arch::Arm64 => {
            for w in f.code.as_chunks::<4>().0 {
                let pc = f.address + rest as u64;
                let word = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
                let Some(i) = hexcavator_arm64::decode(word, pc) else {
                    break;
                };
                // The formatter's own targets: branches' and literals'.
                let record = Targets(Default::default());
                hexcavator_arm64::format_with(&i, &record);
                let named = record.0.into_inner();
                let insn = hexcavator_code::decode(Arch::Arm64, w, pc);
                let flow = insn.map_or(Flow::Next, |c| c.flow);
                let target = insn.and_then(|c| c.target);
                insts.push(Decoded {
                    pc,
                    len: 4,
                    inst: Inst::Arm64(i),
                    flow,
                    target,
                    named,
                });
                rest += 4;
            }
        }
        Arch::Arm => {
            // The conditions of the IT block the next instructions are in.
            let mut it: Vec<u32> = Vec::new();
            let stop = f
                .data
                .and_then(|d| usize::try_from(d.checked_sub(f.address)?).ok())
                .map_or(f.code.len(), |d| d.min(f.code.len()));
            while rest < stop {
                let pc = f.address + rest as u64;
                let Some(c) = hexcavator_code::decode_arm32(&f.code[rest..], pc, f.thumb) else {
                    break;
                };
                let bytes = &f.code[rest..];
                let i = if f.thumb {
                    let first = u16::from_le_bytes([bytes[0], bytes[1]]);
                    let second = (c.len == 4).then(|| u16::from_le_bytes([bytes[2], bytes[3]]));
                    hexcavator_arm32::decode_t32(first, second)
                } else {
                    hexcavator_arm32::decode_a32(u32::from_le_bytes([
                        bytes[0], bytes[1], bytes[2], bytes[3],
                    ]))
                };
                let Some(i) = i else { break };
                let cond = if it.is_empty() {
                    None
                } else {
                    Some(it.remove(0))
                };
                // (Conditional by its IT block: a branch, which may fall
                // through.)
                let flow = match (cond, c.flow) {
                    (Some(k), Flow::Jump | Flow::Return) if k < 14 => Flow::Branch,
                    (_, flow) => flow,
                };
                if i.encoding.name == "IT_T1" {
                    let field = |name: &str| {
                        i.encoding
                            .fields
                            .iter()
                            .find(|x| x.0 == name)
                            .map_or(0, |x| (i.word >> x.2) & ((1 << (x.1 - x.2 + 1)) - 1))
                    };
                    it = hexcavator_arm32::format::it_conditions(field("firstcond"), field("mask"))
                        .collect();
                }
                insts.push(Decoded {
                    pc,
                    len: usize::from(c.len),
                    inst: Inst::Arm32(i, cond),
                    flow,
                    target: c.target,
                    named: c.target.into_iter().collect(),
                });
                rest += usize::from(c.len);
            }
        }
        // (No decoder for the others: the code shows as bytes.)
        _ => {}
    }
    let starts_inst =
        |t: &u64| *t >= f.address && *t < end && insts.binary_search_by_key(t, |i| i.pc).is_ok();
    // The blocks (hexcavator-code's), and where they start.
    let insns: Vec<hexcavator_code::Insn> = insts
        .iter()
        .map(|d| hexcavator_code::Insn {
            address: d.pc,
            len: u8::try_from(d.len).unwrap_or(u8::MAX),
            flow: d.flow,
            target: d.target,
        })
        .collect();
    let branched = hexcavator_code::branch_targets(&insns);
    let blocks = hexcavator_code::blocks(&insns);
    let starts: Vec<u64> = blocks.iter().map(|b| insns[b.first].address).collect();
    // Labels, numbered in address order (bloaty's from 0, blocks' from 1).
    let mut labeled: Vec<u64> = match style {
        Labels::Bloaty => insts
            .iter()
            .flat_map(|i| i.named.iter().copied())
            .filter(starts_inst)
            .collect(),
        Labels::Blocks => {
            let entry_targeted = branched.contains(&f.address);
            starts
                .iter()
                .copied()
                .filter(|&s| s != f.address || entry_targeted)
                .collect()
        }
    };
    labeled.sort_unstable();
    labeled.dedup();
    let first_label = usize::from(style == Labels::Blocks);
    let names_of: Vec<(u64, String, String)> = labeled
        .iter()
        .enumerate()
        .map(|(n, &t)| {
            let n = n + first_label;
            match style {
                Labels::Bloaty => (t, format!(">{n}"), format!("<{n}")),
                Labels::Blocks => (t, format!("L{n}"), format!("L{n}")),
            }
        })
        .collect();
    let mut lines = Vec::with_capacity(insts.len());
    for d in &insts {
        let names = Names {
            labels: &names_of,
            current: d.pc,
            symbols: &f.symbols,
        };
        let text = match &d.inst {
            Inst::X86(i) => {
                let mut s = String::new();
                hexcavator_x86::format::format_with(i, &mut s, &names);
                s
            }
            Inst::Arm64(i) => hexcavator_arm64::format_with(i, &names),
            Inst::Arm32(i, cond) => {
                use hexcavator_arm32::format::{Targets, format_in_it};
                let mut s = String::new();
                format_in_it(i, d.pc, Targets::Addresses, *cond, &mut s);
                // (The target by its label or symbol, where it has one.)
                if let Some(t) = d.target
                    && let Some(name) = names.name(t)
                {
                    s = s.replace(&format!("{t:#x}"), name);
                }
                s
            }
        };
        let offset = (d.pc - f.address) as usize;
        lines.push(Line {
            address: d.pc,
            bytes: f.code[offset..offset + d.len].to_vec(),
            text: text.trim_end().to_string(),
            label: labeled.binary_search(&d.pc).ok().map(|n| n + first_label),
            flow: d.flow,
            target: d.target,
        });
    }
    Listing {
        name: f.name.clone(),
        lines,
        blocks,
        rest: (rest < f.code.len()).then(|| (f.address + rest as u64, f.code[rest..].to_vec())),
        labels: style,
    }
}

/// bloaty's `--disassemble`: the function's instructions, one a line, each
/// with its address, and a numbered label (`0:`) where a branch within the
/// function lands. Branches to labels read `>0` (ahead) or `<0` (behind);
/// other targets, and data, are named by the symbol there. Where the code
/// stops decoding, the rest is shown as bytes.
pub fn listing(f: &Function<'_>) -> String {
    text(&decode(f, Labels::Bloaty))
}

/// A listing as text: a line per instruction, with its address and label.
pub fn text(l: &Listing) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "{}:", l.name);
    for line in &l.lines {
        let label = line
            .label
            .map_or_else(String::new, |n| format!("{}:", l.label_name(n)));
        let _ = writeln!(out, " {:>16x}  {label:<4}{}", line.address, line.text);
    }
    if let Some((at, bytes)) = &l.rest {
        let bytes: Vec<String> = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let _ = writeln!(
            out,
            " {at:>16x}  {:<4}(not instructions) {}",
            "",
            bytes.join(" ")
        );
    }
    out
}

/// One reference: the instruction's address, and the address it refers to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reference {
    pub from: u64,
    pub to: u64,
}

/// The references in `code`, which is at `address`: the addresses its
/// operands compute or access (not its calls and branches; see
/// `hexcavator_xref::scan`).
pub fn references(arch: Arch, code: &[u8], address: u64, out: &mut Vec<Reference>) {
    references_in_image(arch, code, address, None, out);
}

/// [`references`], knowing where the image starts (`image_base`, in the
/// same address space as `address`: 0 for RVAs): MSVC's x64 tables, read
/// by their offset from a register holding the image's address, too.
pub fn references_in_image(
    arch: Arch,
    code: &[u8],
    address: u64,
    image_base: Option<u64>,
    out: &mut Vec<Reference>,
) {
    let mut refs = Vec::new();
    hexcavator_xref::scan_image(arch, code, address, image_base, &mut refs);
    out.extend(
        refs.iter()
            .filter(|r| {
                matches!(
                    r.via,
                    hexcavator_xref::Via::Address | hexcavator_xref::Via::AddressOf
                )
            })
            .map(|r| Reference {
                from: r.from,
                to: r.to,
            }),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alone(name: &str, offers: &[(u64, &str)]) -> Option<u64> {
        let mut a = ByNameAlone::new(name);
        for &(addr, shown) in offers {
            a.offer(addr, shown, || addr);
        }
        a.take()
    }

    #[test]
    fn functions_by_name_alone() {
        let lambda = (2, "f(int)::$_0::operator()(int) const");
        assert_eq!(alone("f", &[(1, "f(int)"), lambda]), Some(1));
        assert_eq!(alone("f", &[(1, "f(int) const"), (5, "g(int)")]), Some(1));
        assert_eq!(alone("f", &[(1, "f(void (*)(int), char)&&")]), Some(1));
        // The same function twice (two symbol tables) is one.
        assert_eq!(alone("f", &[(1, "f(int)"), (1, "f(int)")]), Some(1));
        // Overloads: either.
        assert_eq!(alone("f", &[(1, "f(int)"), (3, "f(long)")]), None);
        // Not a name with parameters.
        for shown in [
            "f",
            "fg(int)",
            "f::g(int)",
            "f<int>(int)",
            "f(int",
            "f(int)(x)",
        ] {
            assert_eq!(alone("f", &[(1, shown)]), None, "{shown}");
        }
        assert_eq!(alone("", &[(1, "(int)")]), None);
        assert_eq!(alone("f", &[]), None);
    }

    fn refs(arch: Arch, code: &[u8], at: u64) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        references(arch, code, at, &mut out);
        out.into_iter().map(|r| (r.from, r.to)).collect()
    }

    #[test]
    fn x86_64_rip_relative() {
        let code = [
            0x48, 0x8D, 0x05, 0x10, 0x00, 0x00, 0x00, // lea rax, [rip + 0x10]
            0x8B, 0x0D, 0xF0, 0xFF, 0xFF, 0xFF, // mov ecx, [rip - 0x10]
            0x48, 0x8B, 0x04, 0x25, 0x00, 0x10, 0x00, 0x00, // mov rax, [0x1000] (absolute)
            0x48, 0x8B, 0x04, 0xC5, 0x00, 0x10, 0x00, 0x00, // mov rax, [rax*8 + 0x1000]
            0x64, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, // mov rax, fs:[rip + 0]
            0xC3, // ret
        ];
        assert_eq!(
            refs(Arch::X64, &code, 0x1000),
            [(0x1000, 0x1017), (0x1007, 0x0FFD)]
        );
        // Decoding stops at bytes that aren't an instruction.
        assert_eq!(
            refs(
                Arch::X64,
                &[0x0F, 0x0B, 0x06, 0x48, 0x8D, 0x05, 0, 0, 0, 0],
                0
            ),
            []
        );
        assert_eq!(refs(Arch::X64, &[], 0), []);
        assert_eq!(refs(Arch::X64, &[0x48, 0x8D], 0), []);
    }

    fn words(ws: &[u32]) -> Vec<u8> {
        ws.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    #[test]
    fn arm64_pages_and_literals() {
        let code = words(&[
            0x9000_0080, // adrp x0, #+0x10000 (page)
            0x9100_4000, // add  x0, x0, #0x10
            0xB000_0001, // adrp x1, #+0x1000
            0xF940_0422, // ldr  x2, [x1, #8]
            0x3DC0_0820, // ldr  q0, [x1, #0x20] (scaled by 16)
            0x1000_0043, // adr  x3, #+8
            0x5800_0044, // ldr  x4, #+8 (literal)
            0xD65F_03C0, // ret
        ]);
        let base = 0x40_0000;
        assert_eq!(
            refs(Arch::Arm64, &code, base),
            [
                (base + 4, 0x41_0010),
                (base + 12, 0x40_1008),
                (base + 16, 0x40_1020),
                (base + 20, base + 20 + 8),
                (base + 24, base + 24 + 8),
            ]
        );
    }

    #[test]
    fn blocks_and_their_edges() {
        let code = [
            0x31, 0xC0, // xor eax,eax
            0xFF, 0xC0, // L1: inc eax
            0x83, 0xF8, 0x05, // cmp eax,5
            0x7C, 0xF9, // jl L1
            0x74, 0x02, // L2: je L4
            0xEB, 0xF5, // L3: jmp L1
            0xE8, 0xEE, 0x0F, 0x00, 0x00, // L4: call helper (0x2000)
            0xC3, // ret
            0x06, // not an instruction in 64-bit mode
        ];
        let f = Function {
            name: "f".into(),
            isa: Arch::X64,
            thumb: false,
            data: None,
            address: 0x1000,
            code: &code,
            symbols: vec![(0x1000, "f".into()), (0x2000, "helper".into())],
        };
        let l = decode(&f, Labels::Blocks);
        let texts: Vec<&str> = l
            .lines
            .iter()
            .map(|l| l.text.split_whitespace().last().unwrap())
            .collect();
        assert_eq!(
            texts,
            ["eax,eax", "eax", "eax,5", "L1", "L4", "L1", "helper", "ret"]
        );
        let labels: Vec<Option<usize>> = l.lines.iter().map(|l| l.label).collect();
        assert_eq!(
            labels,
            [None, Some(1), None, None, Some(2), Some(3), Some(4), None]
        );
        let flows: Vec<Flow> = l.lines.iter().map(|l| l.flow).collect();
        use Flow::*;
        assert_eq!(
            flows,
            [Next, Next, Next, Branch, Branch, Jump, Call, Return]
        );
        // The entry; the loop; after its branch; the jump back; the call
        // and return.
        type Shape = (usize, usize, Vec<(usize, Edge)>);
        let shape: Vec<Shape> = l
            .blocks
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
        assert_eq!(l.block_at(0x1009), Some(2));
        assert_eq!(l.rest, Some((0x1013, vec![0x06])));
        // A branch to the entry labels it too.
        let code = [0x90, 0xEB, 0xFD]; // L1: nop; jmp L1
        let f = Function {
            name: "spin".into(),
            isa: Arch::X64,
            thumb: false,
            data: None,
            address: 0x1000,
            code: &code,
            symbols: vec![],
        };
        let l = decode(&f, Labels::Blocks);
        assert_eq!(l.lines[0].label, Some(1));
        assert_eq!(l.lines[1].text.split_whitespace().last(), Some("L1"));
        assert_eq!(l.blocks.len(), 1);
        assert_eq!(l.blocks[0].successors, [(0, Edge::Jump)]);
        // ARM64: conditional, test, and compare branches; calls; returns.
        assert_eq!(
            hexcavator_code::arm64_flow("B_only_condbranch"),
            Flow::Branch
        );
        assert_eq!(
            hexcavator_code::arm64_flow("CBZ_64_compbranch"),
            Flow::Branch
        );
        assert_eq!(
            hexcavator_code::arm64_flow("TBNZ_only_testbranch"),
            Flow::Branch
        );
        assert_eq!(hexcavator_code::arm64_flow("B_only_branch_imm"), Flow::Jump);
        assert_eq!(hexcavator_code::arm64_flow("BR_64_branch_reg"), Flow::Jump);
        assert_eq!(
            hexcavator_code::arm64_flow("BRAA_64P_branch_reg"),
            Flow::Jump
        );
        assert_eq!(
            hexcavator_code::arm64_flow("BL_only_branch_imm"),
            Flow::Call
        );
        assert_eq!(
            hexcavator_code::arm64_flow("BLRAAZ_64_branch_reg"),
            Flow::Call
        );
        assert_eq!(
            hexcavator_code::arm64_flow("RET_64R_branch_reg"),
            Flow::Return
        );
        assert_eq!(
            hexcavator_code::arm64_flow("RETAA_64E_branch_reg"),
            Flow::Return
        );
        assert_eq!(hexcavator_code::arm64_flow("BRK_EX_exception"), Flow::Stop);
        assert_eq!(hexcavator_code::arm64_flow("ADD_64_addsub_imm"), Flow::Next);
    }

    #[test]
    fn listings_label_branches_and_name_targets() {
        let code = [
            0x31, 0xC0, // xor eax,eax
            0xFF, 0xC0, // 0: inc eax
            0x83, 0xF8, 0x05, // cmp eax,5
            0x7C, 0xF9, // jl 0
            0x74, 0x02, // je 1
            0xEB, 0xF5, // jmp 0
            0xE8, 0xEE, 0x0F, 0x00, 0x00, // 1: call helper (0x2000)
            0xC3, // ret
            0x06, // not an instruction in 64-bit mode
        ];
        let f = Function {
            name: "f".into(),
            isa: Arch::X64,
            thumb: false,
            data: None,
            address: 0x1000,
            code: &code,
            symbols: vec![(0x1000, "f".into()), (0x2000, "helper".into())],
        };
        let text = listing(&f);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "f:");
        assert_eq!(lines.len(), 1 + 8 + 1, "{text}");
        let row = |n: usize| lines[n].split_whitespace().collect::<Vec<_>>();
        assert_eq!(row(1), ["1000", "xor", "eax,eax"]);
        assert_eq!(row(2), ["1002", "0:", "inc", "eax"]);
        assert_eq!(row(4), ["1007", "jl", "<0"]);
        assert_eq!(row(5), ["1009", "je", ">1"]);
        assert_eq!(row(6), ["100b", "jmp", "<0"]);
        assert_eq!(row(7), ["100d", "1:", "call", "helper"]);
        assert_eq!(row(8), ["1012", "ret"]);
        assert_eq!(row(9), ["1013", "(not", "instructions)", "06"]);

        // ARM64: the same, from the formatter's own targets.
        let words = words(&[
            0x5280_0000, // mov w0, #0
            0x1100_0400, // 0: add w0, w0, #1
            0x7100_141F, // cmp w0, #5
            0x54FF_FFCB, // b.lt 0
            0x9400_0400, // bl helper (+0x1000)
            0xD65F_03C0, // ret
        ]);
        let f = Function {
            name: "g".into(),
            isa: Arch::Arm64,
            thumb: false,
            data: None,
            address: 0x1000,
            code: &words,
            symbols: vec![(0x2010, "helper".into())],
        };
        let text = listing(&f);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 7, "{text}");
        let row = |n: usize| lines[n].split_whitespace().collect::<Vec<_>>();
        assert_eq!(row(2)[..2], ["1004", "0:"]);
        assert_eq!(row(4), ["100c", "blt", "<0"]);
        assert_eq!(row(5), ["1010", "bl", "helper"]);
    }

    #[test]
    fn arm64_pages_are_forgotten() {
        let code = words(&[
            0x9000_0080, // adrp x0, page
            0xAA01_03E0, // mov  x0, x1 (overwrites x0)
            0x9100_4000, // add  x0, x0, #0x10: not a page any more
            0x9000_0081, // adrp x1, page
            0xF940_0421, // ldr  x1, [x1, #8]: a reference, then x1 is data
            0xF940_0422, // ldr  x2, [x1, #8]: not a reference
            0x9000_0082, // adrp x2, page
            0xF900_0442, // str  x2, [x2, #8]: a reference; x2 still the page
            0x9100_4042, // add  x2, x2, #0x10: a reference
        ]);
        let got = refs(Arch::Arm64, &code, 0);
        assert_eq!(got, [(16, 0x10008), (28, 0x10008), (32, 0x10010)]);
        // An undecodable word ends the function.
        assert!(hexcavator_arm64::decode(0xFFFF_FFFF, 0).is_none());
        assert_eq!(
            refs(
                Arch::Arm64,
                &words(&[0xFFFF_FFFF, 0x9000_0080, 0x9100_4000]),
                0
            ),
            []
        );
    }
}

/// Parsing llvm-objdump's disassembly, the oracle for [`references`].
#[cfg(test)]
pub(crate) mod oracle {
    use std::collections::HashMap;

    /// Each function's references, as llvm-objdump's disassembly gives them:
    /// on x86-64 the `# 0x...` target of each RIP-relative operand; on ARM64
    /// `adr`, and `adrp` pages completed by the `add` or `[reg, #imm]` that
    /// uses the register (until something else writes it).
    pub(crate) fn objdump_references(text: &str) -> Vec<(String, Vec<u64>)> {
        let hex = |s: &str| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok();
        let mut out: Vec<(String, Vec<u64>)> = Vec::new();
        let mut pages: HashMap<String, u64> = HashMap::new();
        for line in text.lines() {
            if let Some(name) = line.strip_suffix(">:").and_then(|l| l.split_once(" <")) {
                out.push((name.1.to_string(), Vec::new()));
                pages.clear();
                continue;
            }
            // `  2011a0:      \tleaq ...` (ELF), `1000003c0:     \tpushq ...`
            // (Mach-O): an address, a colon, spaces, a tab.
            let Some((addr, inst)) = line.split_once(':') else {
                continue;
            };
            if !addr.trim().bytes().all(|b| b.is_ascii_hexdigit())
                || !inst.trim_start_matches(' ').starts_with('\t')
            {
                continue;
            }
            let inst = inst.trim_start();
            let Some(refs) = out.last_mut().map(|f| &mut f.1) else {
                continue;
            };
            let inst = inst
                .split(" //")
                .next()
                .unwrap()
                .split(" ; ")
                .next()
                .unwrap();
            if let Some((_, target)) = inst.split_once("# 0x") {
                // x86-64 (only RIP-relative operands get a target comment here).
                if inst.contains("(%rip)") {
                    refs.push(hex(target.split_whitespace().next().unwrap()).unwrap());
                }
                continue;
            }
            let (mnemonic, ops) = inst.split_once('\t').unwrap_or((inst, ""));
            let ops: Vec<&str> = ops.split(", ").collect();
            let reg = |s: &str| s.trim_start_matches('[').replace('w', "x");
            match mnemonic {
                "adrp" => {
                    pages.insert(reg(ops[0]), hex(ops[1].split(' ').next().unwrap()).unwrap());
                    continue;
                }
                "adr" => refs.push(hex(ops[1].split(' ').next().unwrap()).unwrap()),
                "add" if ops.len() == 3 && ops[2].starts_with("#0x") => {
                    if let Some(p) = pages.get(&reg(ops[1])) {
                        refs.push(p + hex(&ops[2][1..]).unwrap());
                    }
                }
                _ => {
                    let i = ops.iter().position(|o| o.starts_with('['));
                    if let Some(i) = i
                        && ops.len() == i + 2
                        && ops[i + 1].starts_with("#0x")
                        && ops[i + 1].ends_with(']')
                        && let Some(p) = pages.get(&reg(ops[i]))
                    {
                        refs.push(
                            p + hex(ops[i + 1].trim_end_matches(']').trim_start_matches('#'))
                                .unwrap(),
                        );
                    } else if let Some(i) = i
                        && ops.len() == i + 1
                        && ops[i].ends_with(']')
                        && let Some(p) = pages.get(&reg(ops[i].trim_end_matches(']')))
                    {
                        // `[x8]`: no offset.
                        refs.push(*p);
                    }
                }
            }
            // The destination is no longer a page (stores write no register).
            if !mnemonic.starts_with("st") && !ops.is_empty() {
                pages.remove(&reg(ops[0]));
            }
        }
        out
    }
}
