//! What the hermetic tests share: a synthetic stack.

use hexcavator_unwind::Memory;

/// Where the synthetic stack lives.
pub const STACK: u64 = 0x10_0000;

/// A stack of 512 words from [`STACK`]; unset words hold a marker.
pub struct Stack {
    words: Vec<u64>,
}

impl Stack {
    pub fn new() -> Self {
        Stack {
            words: (0..512).map(|i| 0xAAAA_0000_0000 + STACK + i * 8).collect(),
        }
    }
    pub fn set(&mut self, address: u64, value: u64) {
        self.words[((address - STACK) / 8) as usize] = value;
    }
}

impl Memory for Stack {
    fn read(&self, address: u64, buf: &mut [u8]) -> bool {
        for (i, b) in buf.iter_mut().enumerate() {
            let a = address.wrapping_add(i as u64);
            let Some(off) = a.checked_sub(STACK) else {
                return false;
            };
            let Some(w) = self.words.get((off / 8) as usize) else {
                return false;
            };
            *b = w.to_le_bytes()[(off % 8) as usize];
        }
        true
    }
}
