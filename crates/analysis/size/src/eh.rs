//! Symbols for exception-handling data: `.pdata` entries, unwind data, and
//! the language-specific data of the handlers (C++ EH tables for
//! `__CxxFrameHandler3`/`4`, SEH scope tables, GS cookie data).
//!
//! Each is named for the function it describes (`[unwind] f(int)`). Data
//! shared by several functions (folded functions share their unwind data)
//! is listed once, for the first function, in `.pdata` order.

use std::collections::HashSet;

use hexcavator_core::Rva;
use hexcavator_pe::PeFile;
use hexcavator_pe::consts::machine;
use hexcavator_pe::exception::{RuntimeFunction, arm_xdata_extent};

use crate::Size;
use crate::symbols::{Symbol, SymbolKind};

/// Bounds the length of chains of chained unwind data (input is untrusted).
const MAX_CHAIN: u32 = 32;

/// What a handler's language-specific data is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Handler {
    /// `__CxxFrameHandler`/`2`/`3`: the RVA of a `FuncInfo`.
    Cxx3,
    /// `__CxxFrameHandler4`: the RVA of a compressed `FuncInfo4`.
    Cxx4,
    /// `__C_specific_handler`: a scope table.
    Seh,
    /// `__GSHandlerCheck`: GS cookie data.
    Gs,
    /// `__GSHandlerCheck_EH`: a `FuncInfo` RVA, then GS data.
    GsCxx3,
    /// `__GSHandlerCheck_EH4`: a `FuncInfo4` RVA, then GS data.
    GsCxx4,
    /// `__GSHandlerCheck_SEH`: a scope table, then GS data.
    GsSeh,
    /// A handler with no language-specific data we know of.
    Other,
}

impl Handler {
    /// The handler a function's name says it is.
    pub fn from_name(name: &str) -> Self {
        // x86-style decoration does not reach these (x64 and ARM only), but
        // an import of one is `__imp_<name>`.
        let name = name.strip_prefix("__imp_").unwrap_or(name);
        match name {
            "__CxxFrameHandler" | "__CxxFrameHandler2" | "__CxxFrameHandler3" => Handler::Cxx3,
            "__CxxFrameHandler4" => Handler::Cxx4,
            "__C_specific_handler" | "__C_specific_handler_noexcept" => Handler::Seh,
            "__GSHandlerCheck" => Handler::Gs,
            "__GSHandlerCheck_EH" => Handler::GsCxx3,
            "__GSHandlerCheck_EH4" => Handler::GsCxx4,
            "__GSHandlerCheck_SEH" | "__GSHandlerCheck_SEH_noexcept" => Handler::GsSeh,
            _ => Handler::Other,
        }
    }
}

/// What the builder needs to know about the image's other symbols.
pub trait Context {
    /// The name of the function (or other symbol) containing `addr`.
    fn target_name(&self, addr: u64) -> Option<String>;
    /// The handler whose code is at `addr`.
    fn handler(&self, addr: u64) -> Handler;
}

struct Builder<'a, 'data, C: Context> {
    pe: &'a PeFile<'data>,
    context: &'a C,
    seen: HashSet<u64>,
    out: Vec<Symbol>,
    x64_gs_alignment: bool,
}

impl<C: Context> Builder<'_, '_, C> {
    fn name(&self, kind: SymbolKind, target: u64) -> String {
        let prefix = kind.prefix().unwrap_or("");
        match self.context.target_name(target) {
            Some(n) => format!("{prefix} {n}"),
            None => format!("{prefix} <unnamed code at 0x{target:X}>"),
        }
    }

    /// Adds a symbol unless one is already at `addr`; returns whether it
    /// was added.
    fn add(&mut self, kind: SymbolKind, addr: u64, size: u64, target: u64) -> bool {
        if size == 0 || !self.seen.insert(addr) {
            return false;
        }
        let name = self.name(kind, target);
        self.out.push(Symbol {
            addr,
            size: Size::new(size, size),
            kind,
            folded: false,
            name,
            compiland: None,
            file_static: false,
        });
        true
    }

    fn u32(&self, rva: u32) -> Option<u32> {
        let b = self.pe.bytes_at_rva(Rva(rva), 4).ok()?;
        Some(u32::from_le_bytes(b.try_into().ok()?))
    }

    /// x64 unwind data at `rva`, for the function at `target`.
    fn x64_unwind(&mut self, target: u64, rva: u32, depth: u32) {
        if depth > MAX_CHAIN || self.seen.contains(&u64::from(rva)) {
            return;
        }
        let Some(info) = self.pe.x64_unwind_info(Rva(rva)) else {
            return;
        };
        // Version 0 with no flags: a stub (incremental linking leaves them).
        if info.version == 0 && info.flags == 0 {
            return;
        }
        let size = u64::from(info.size());
        if let Some(chained) = info.chained() {
            self.add(SymbolKind::ChainUnwind, u64::from(rva), size, target);
            if let RuntimeFunction::X64 { begin, unwind, .. } = chained {
                self.x64_unwind(u64::from(begin.get()), unwind.get(), depth + 1);
            }
            return;
        }
        let data = info.handler_data().map(hexcavator_core::Rva::get);
        let extra = match (info.handler(), data) {
            (Some(handler), Some(data)) => {
                let kind = self.context.handler(u64::from(handler.get()));
                self.handler_data(target, kind, data)
            }
            _ => 0,
        };
        self.add(SymbolKind::Unwind, u64::from(rva), size + extra, target);
    }

    /// ARM or ARM64 `.xdata` at `rva`.
    fn arm_unwind(&mut self, target: u64, rva: u32, arm32: bool) {
        if self.seen.contains(&u64::from(rva)) {
            return;
        }
        let Some((size, handler)) = arm_xdata_extent(self.pe, Rva(rva), arm32) else {
            return;
        };
        let extra = match handler {
            Some(h) => {
                let h = if arm32 { h.get() & !1 } else { h.get() };
                let kind = self.context.handler(u64::from(h));
                self.handler_data(target, kind, rva + size)
            }
            None => 0,
        };
        self.add(
            SymbolKind::Unwind,
            u64::from(rva),
            u64::from(size) + extra,
            target,
        );
    }

    /// Adds the tables a handler's data at `data` points to, and returns
    /// the data's own size (which belongs to the unwind data).
    fn handler_data(&mut self, target: u64, kind: Handler, data: u32) -> u64 {
        let scope_table = |b: &Self| -> u64 { 4 + 16 * u64::from(b.u32(data).unwrap_or(0)) };
        let gs = |b: &Self, at: u32| -> u64 {
            let word = b.u32(at).unwrap_or(0);
            // On x64, aligned frames add the aligned base offset and the
            // alignment.
            if b.x64_gs_alignment && word & 4 != 0 {
                12
            } else {
                4
            }
        };
        match kind {
            Handler::Cxx3 | Handler::GsCxx3 => {
                if let Some(info) = self.u32(data) {
                    self.cxx3(target, info);
                }
                if kind == Handler::GsCxx3 {
                    4 + gs(self, data + 4)
                } else {
                    4
                }
            }
            Handler::Cxx4 | Handler::GsCxx4 => {
                if let Some(info) = self.u32(data) {
                    self.cxx4(target, info);
                }
                if kind == Handler::GsCxx4 {
                    4 + gs(self, data + 4)
                } else {
                    4
                }
            }
            Handler::Seh => scope_table(self),
            Handler::GsSeh => {
                let table = scope_table(self);
                table + gs(self, data + table as u32)
            }
            Handler::Gs => gs(self, data),
            Handler::Other => 0,
        }
    }

    /// `__CxxFrameHandler3` tables.
    fn cxx3(&mut self, target: u64, rva: u32) {
        let Some(info) = self.pe.func_info(Rva(rva)) else {
            return;
        };
        if !self.add(SymbolKind::CppXdata, u64::from(rva), 40, target) {
            return;
        }
        let max_state = u64::try_from(info.max_state.get()).unwrap_or(0);
        self.add(
            SymbolKind::StateUnwindMap,
            u64::from(info.unwind_map.get()),
            max_state * 8,
            target,
        );
        let try_map = u64::from(info.try_block_map.get());
        self.add(
            SymbolKind::TryMap,
            try_map,
            u64::from(info.try_blocks.get()) * 20,
            target,
        );
        for block in self.pe.try_block_map(info) {
            let catches = u64::try_from(block.catches.get()).unwrap_or(0);
            self.add(
                SymbolKind::HandlerMap,
                u64::from(block.handler_array.get()),
                catches * 20,
                target,
            );
        }
        self.add(
            SymbolKind::IpToStateMap,
            u64::from(info.ip_to_state_map.get()),
            u64::from(info.ip_map_entries.get()) * 8,
            target,
        );
    }

    /// `__CxxFrameHandler4` tables.
    fn cxx4(&mut self, target: u64, rva: u32) {
        let Some(info) = self.pe.func_info4(Rva(rva)) else {
            return;
        };
        if !self.add(
            SymbolKind::CppXdata,
            u64::from(rva),
            u64::from(info.size),
            target,
        ) {
            return;
        }
        if let Some(map) = info.unwind_map.and_then(|m| self.pe.unwind_map4(m)) {
            self.add(
                SymbolKind::StateUnwindMap,
                u64::from(map.rva.get()),
                u64::from(map.size),
                target,
            );
        }
        if let Some(map) = info.try_map.and_then(|m| self.pe.try_map4(m)) {
            self.add(
                SymbolKind::TryMap,
                u64::from(map.rva.get()),
                u64::from(map.size),
                target,
            );
            for block in &map.entries {
                if let Some(h) = self.pe.handler_map4(block.handlers) {
                    self.add(
                        SymbolKind::HandlerMap,
                        u64::from(h.rva.get()),
                        u64::from(h.size),
                        target,
                    );
                }
            }
        }
        if info.is_separated() {
            let Some(segments) = self.pe.segment_map4(info.ip_map) else {
                return;
            };
            self.add(
                SymbolKind::SegmentMap,
                u64::from(segments.rva.get()),
                u64::from(segments.size),
                target,
            );
            // Each segment's map is named for the code it starts.
            for s in &segments.entries {
                if let Some(map) = self.pe.ip_to_state4(s.ip_map) {
                    self.add(
                        SymbolKind::IpToStateMap,
                        u64::from(map.rva.get()),
                        u64::from(map.size),
                        u64::from(s.segment.get()),
                    );
                }
            }
        } else if let Some(map) = self.pe.ip_to_state4(info.ip_map) {
            self.add(
                SymbolKind::IpToStateMap,
                u64::from(map.rva.get()),
                u64::from(map.size),
                target,
            );
        }
    }
}

/// The exception-handling symbols of `pe`.
pub fn symbols(pe: &PeFile<'_>, context: &impl Context) -> Vec<Symbol> {
    let arm32 = pe.machine() == machine::ARMNT;
    let mut b = Builder {
        pe,
        context,
        seen: HashSet::new(),
        out: Vec::new(),
        x64_gs_alignment: !matches!(pe.machine(), machine::ARMNT | machine::ARM64),
    };
    let entries: Vec<_> = pe
        .runtime_functions()
        .filter(|e| e.in_exception_directory)
        .collect();
    for e in &entries {
        let addr = u64::from(e.rva.get());
        match e.function {
            RuntimeFunction::X64 { begin, end, unwind } => {
                if begin.get() == 0 && end.get() == 0 && unwind.get() == 0 {
                    continue;
                }
                b.add(SymbolKind::Pdata, addr, 12, u64::from(begin.get()));
            }
            RuntimeFunction::Arm { begin, unwind } => {
                if begin.get() == 0 && unwind == 0 {
                    continue;
                }
                let target = u64::from(if arm32 { begin.get() & !1 } else { begin.get() });
                let kind = match unwind & 3 {
                    0 => SymbolKind::Pdata,
                    3 => SymbolKind::ForwarderPdata,
                    _ => SymbolKind::PackedPdata,
                };
                b.add(kind, addr, 8, target);
            }
        }
    }
    // Unwind data in `.pdata` order (the first function to use shared data
    // names it).
    for e in &entries {
        match e.function {
            RuntimeFunction::X64 { begin, unwind, .. } => {
                // An odd unwind RVA marks an entry that points to another
                // entry (as BBT writes them), not to unwind data.
                if unwind.get() & 1 == 0 && unwind.get() != 0 {
                    b.x64_unwind(u64::from(begin.get()), unwind.get(), 0);
                }
            }
            RuntimeFunction::Arm { begin, unwind } if unwind & 3 == 0 && unwind != 0 => {
                let target = u64::from(if arm32 { begin.get() & !1 } else { begin.get() });
                b.arm_unwind(target, unwind, arm32);
            }
            RuntimeFunction::Arm { .. } => {}
        }
    }
    b.out.sort_by_key(|s| s.addr);
    b.out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handlers_by_name() {
        assert_eq!(Handler::from_name("__CxxFrameHandler3"), Handler::Cxx3);
        assert_eq!(Handler::from_name("__CxxFrameHandler"), Handler::Cxx3);
        assert_eq!(Handler::from_name("__CxxFrameHandler4"), Handler::Cxx4);
        assert_eq!(
            Handler::from_name("__imp___CxxFrameHandler4"),
            Handler::Cxx4
        );
        assert_eq!(
            Handler::from_name("__C_specific_handler_noexcept"),
            Handler::Seh
        );
        assert_eq!(Handler::from_name("__GSHandlerCheck"), Handler::Gs);
        assert_eq!(Handler::from_name("__GSHandlerCheck_EH"), Handler::GsCxx3);
        assert_eq!(Handler::from_name("__GSHandlerCheck_EH4"), Handler::GsCxx4);
        assert_eq!(Handler::from_name("__GSHandlerCheck_SEH"), Handler::GsSeh);
        assert_eq!(Handler::from_name("RtlpExceptionHandler"), Handler::Other);
    }
}
