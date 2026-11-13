//! Fingerprints: for each function and datum of an image, a value that is
//! the same for two that do the same thing and refer to things that are
//! the same, wherever each is.
//!
//! Each node starts from a local hash ([`code`], [`data`], [`named`]) and
//! the ordered list of nodes it refers to. Code's local hash is of its
//! instructions with every address masked out: a branch within the
//! function counts as its offset from the function's start; anything else
//! it refers to (a call's target, the data an operand reaches) is a
//! reference, in the order the code makes them. Data's is of its bytes with
//! its pointers masked out, which are its references. What is known by its
//! name (an import) is its name.
//!
//! [`refine`] then gives each node a class: its local hash and its
//! references' classes, in order, rehashed until the classes stop
//! splitting. Two functions identical but for their callees get different
//! classes unless the callees' classes are the same; cycles (recursion)
//! need no special case. This is how linkers fold identical code (lld's
//! ICF), and it makes the classes comparable across images: nothing in
//! them depends on an address.

#![warn(missing_docs)]

use std::hash::Hasher;

use hexcavator_xref::{Arch, CodeRef, Via};
use rustc_hash::FxHasher;

/// A node's local hash and what it refers to (node indexes, in order).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Item {
    /// The hash of its own bytes (references masked out).
    pub local: u64,
    /// The nodes it refers to, in order.
    pub refs: Vec<u32>,
}

/// Where an address is, for [`code`] and [`data`]: in another node, or in
/// none known.
pub trait Resolve {
    /// The node `address` is in (an address code computes or accesses).
    fn node_at(&self, address: u64) -> Option<u32>;
    /// The node starting at `address` (a call's or branch's target).
    fn node_starting_at(&self, address: u64) -> Option<u32>;
}

fn hasher(tag: u8) -> FxHasher {
    let mut h = FxHasher::default();
    h.write_u8(tag);
    h
}

/// A datum known by its name (an imported function's address table entry,
/// say): its name alone.
pub fn named(name: &str) -> Item {
    let mut h = hasher(b'n');
    h.write(name.as_bytes());
    h.write_usize(name.len());
    Item {
        local: h.finish(),
        refs: Vec::new(),
    }
}

/// Data: its bytes (`bytes`, of a node `size` long; past `bytes`, zero),
/// with its pointers masked out: `pointers` are each pointer's offset,
/// width, and the node it points to (if any), in order.
pub fn data(bytes: &[u8], size: u64, pointers: &[(u64, u32, Option<u32>)]) -> Item {
    let mut h = hasher(b'd');
    h.write_u64(size);
    let mut at = 0usize;
    let mut refs = Vec::new();
    for &(offset, width, to) in pointers {
        let Ok(start) = usize::try_from(offset) else {
            break;
        };
        if start < at || start > bytes.len() {
            continue;
        }
        h.write(&bytes[at..start]);
        h.write_u8(0xFE);
        h.write_u32(width);
        match to {
            Some(n) => refs.push(n),
            None => h.write_u8(0xFD),
        }
        at = (start + width as usize).min(bytes.len());
    }
    h.write(&bytes[at.min(bytes.len())..]);
    Item {
        local: h.finish(),
        refs,
    }
}

/// Code: the function `[start, start + code.len())` in `arch`, with
/// `image_base` as for [`hexcavator_xref::scan_image`], and `absolute`
/// the addresses its instructions hold that relocations name (32-bit x86:
/// each one's slot and the address there), sorted by slot.
pub fn code(
    arch: Arch,
    code: &[u8],
    start: u64,
    image_base: Option<u64>,
    absolute: &[(u64, u64)],
    resolve: &impl Resolve,
) -> Item {
    let mut refs = Vec::new();
    hexcavator_xref::scan_image(arch, code, start, image_base, &mut refs);
    let end = start + code.len() as u64;
    let mut item = Item::default();
    let mut h = hasher(b'c');
    // What an address the code uses is: a place in the function, or a
    // reference to another node.
    let target = |h: &mut FxHasher, to: u64, via: Via, item: &mut Item| {
        if (start..end).contains(&to) {
            h.write_u8(1);
            h.write_u64(to - start);
            return;
        }
        let node = match via {
            Via::Call | Via::Jump => resolve.node_starting_at(to),
            // (An address used any other way: where it falls.)
            _ => resolve.node_at(to),
        };
        match node {
            Some(n) => {
                h.write_u8(2);
                item.refs.push(n);
            }
            None => h.write_u8(3),
        }
    };
    let mut r = 0;
    match arch {
        Arch::X86 | Arch::X64 => {
            let mode = if arch == Arch::X86 {
                hexcavator_x86::Mode::Bits32
            } else {
                hexcavator_x86::Mode::Bits64
            };
            let mut a = 0;
            let mut at = 0usize;
            while at < code.len() {
                let pc = start + at as u64;
                let Ok(inst) = hexcavator_x86::decode(&code[at..], mode, pc) else {
                    h.write_u8(0xFF);
                    h.write(&code[at..]);
                    break;
                };
                let next = pc + inst.len() as u64;
                // The references this instruction makes, and the absolute
                // addresses in it.
                let mine = take_refs(&refs, &mut r, pc);
                let first = a;
                while a < absolute.len() && absolute[a].0 < next {
                    a += 1;
                }
                let abs = &absolute[first..a];
                let masked = !mine.is_empty() || !abs.is_empty();
                x86_instruction(&mut h, &inst, masked);
                for c in mine {
                    target(&mut h, c.to, c.via, &mut item);
                }
                for &(_, to) in abs {
                    target(&mut h, to, Via::Address, &mut item);
                }
                at += inst.len().max(1);
            }
        }
        Arch::Arm64 => {
            for (i, w) in code.chunks(4).enumerate() {
                let pc = start + i as u64 * 4;
                let Ok(w) = <[u8; 4]>::try_from(w) else {
                    h.write(w);
                    break;
                };
                let word = u32::from_le_bytes(w);
                let mine = take_refs(&refs, &mut r, pc);
                let Some(inst) = hexcavator_arm64::decode(word, pc) else {
                    h.write_u32(word);
                    continue;
                };
                h.write_u32(word & !arm64_address_bits(inst.encoding_name(), !mine.is_empty()));
                for c in mine {
                    target(&mut h, c.to, c.via, &mut item);
                }
            }
        }
        // (Code no decoder reads: its bytes, as they are.)
        _ => h.write(code),
    }
    h.write_usize(code.len());
    item.local = h.finish();
    item
}

/// The references at `pc`, advancing `r` past them (`refs` is in
/// instruction order).
fn take_refs<'a>(refs: &'a [CodeRef], r: &mut usize, pc: u64) -> &'a [CodeRef] {
    while *r < refs.len() && refs[*r].from < pc {
        *r += 1;
    }
    let first = *r;
    while *r < refs.len() && refs[*r].from == pc {
        *r += 1;
    }
    &refs[first..*r]
}

/// Hashes an x86 instruction: its operation and operands, with
/// displacements and immediates that may be addresses left out if
/// `masked` (the instruction refers to something).
fn x86_instruction(h: &mut FxHasher, inst: &hexcavator_x86::Instruction, masked: bool) {
    use hexcavator_x86::Operand;
    h.write_u16(inst.mnemonic() as u16);
    h.write_u16(inst.prefixes());
    h.write_u8(inst.mask().unwrap_or(0xFF));
    h.write_u8(u8::from(inst.zeroing()));
    h.write_u8(inst.vector_length());
    let reg = |h: &mut FxHasher, r: Option<hexcavator_x86::Register>| match r {
        Some(r) => {
            h.write_u8(r.class() as u8);
            h.write_u8(r.index());
        }
        None => h.write_u8(0xFF),
    };
    for op in inst.operands() {
        match op {
            Operand::Reg(r) => {
                h.write_u8(b'r');
                reg(h, Some(*r));
            }
            Operand::Imm(i) => {
                h.write_u8(b'i');
                h.write_u8(i.size);
                if !masked {
                    h.write_u64(i.value);
                }
            }
            Operand::Mem(m) => {
                h.write_u8(b'm');
                reg(h, m.segment);
                reg(h, m.base);
                reg(h, m.index);
                h.write_u8(m.scale);
                h.write_u8(m.size as u8);
                h.write_u8(m.address_size);
                h.write_u8(m.broadcast);
                // (A RIP-relative displacement depends on where the code is,
                // whatever it reaches.)
                if !masked && !m.is_rip_relative() {
                    h.write_i64(m.disp);
                }
            }
            Operand::Rel(_) => h.write_u8(b'l'),
            Operand::Far {
                segment,
                offset,
                offset_size,
            } => {
                h.write_u8(b'f');
                h.write_u16(*segment);
                h.write_u32(*offset);
                h.write_u8(*offset_size);
            }
            Operand::None => h.write_u8(b'-'),
            // (Operand kinds yet to come: their kind, not their value.)
            _ => h.write_u8(b'?'),
        }
    }
}

/// The bits of an ARM64 instruction that hold an address, for `encoding`:
/// always a PC-relative one (a branch's or literal's offset, `ADR`'s, a
/// page), which depends on where the code is; a page offset (`ADD`, a
/// load or store after `ADRP`) if the instruction makes a reference
/// (`refers`).
fn arm64_address_bits(encoding: &str, refers: bool) -> u32 {
    const IMM19: u32 = 0x7FFFF << 5;
    const IMMLO: u32 = 3 << 29;
    const IMM12: u32 = 0xFFF << 10;
    match encoding {
        "ADRP_only_pcreladdr" | "ADR_only_pcreladdr" => IMM19 | IMMLO,
        "BL_only_branch_imm" | "B_only_branch_imm" => 0x3FF_FFFF,
        "TBZ_only_testbranch" | "TBNZ_only_testbranch" => 0x3FFF << 5,
        e if e.ends_with("condbranch") || e.ends_with("_compbranch") || e.ends_with("_loadlit") => {
            IMM19
        }
        e if refers && (e.ends_with("ADD_64_addsub_imm") || e.ends_with("_ldst_pos")) => IMM12,
        _ => 0,
    }
}

/// The class of each item: its local hash and its references' classes,
/// rehashed until the number of classes stops growing (at most `rounds`
/// times). Each round's class includes the last's, so classes only split.
pub fn refine(items: &[Item], rounds: usize) -> Vec<u64> {
    let mut classes: Vec<u64> = items.iter().map(|i| i.local).collect();
    let mut count = distinct(&classes);
    for _ in 0..rounds {
        let next: Vec<u64> = items
            .iter()
            .zip(&classes)
            .map(|(item, &own)| {
                let mut h = hasher(b'r');
                h.write_u64(own);
                h.write_usize(item.refs.len());
                for &r in &item.refs {
                    h.write_u64(classes.get(r as usize).copied().unwrap_or(0));
                }
                h.finish()
            })
            .collect();
        let n = distinct(&next);
        classes = next;
        if n == count {
            break;
        }
        count = n;
    }
    classes
}

fn distinct(v: &[u64]) -> usize {
    let mut s: Vec<u64> = v.to_vec();
    s.sort_unstable();
    s.dedup();
    s.len()
}

#[cfg(test)]
mod tests;
