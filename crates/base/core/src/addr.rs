//! Typed addresses, so that different address spaces cannot be mixed up.

use core::fmt;

macro_rules! address {
    ($($(#[$meta:meta])* $name:ident($int:ty);)*) => {$(
        $(#[$meta])*
        #[repr(transparent)]
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
        pub struct $name(pub $int);

        impl $name {
            /// The address `value`.
            #[inline]
            pub const fn new(value: $int) -> Self {
                Self(value)
            }

            /// Its value.
            #[inline]
            pub const fn get(self) -> $int {
                self.0
            }

            /// The address `delta` past it, or `None` on overflow.
            #[inline]
            pub const fn checked_add(self, delta: $int) -> Option<Self> {
                match self.0.checked_add(delta) {
                    Some(v) => Some(Self(v)),
                    None => None,
                }
            }

            /// The distance from `base` to `self`, or `None` if `self < base`.
            #[inline]
            pub const fn checked_offset_from(self, base: Self) -> Option<$int> {
                self.0.checked_sub(base.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({:#x})"), self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::LowerHex::fmt(&self.0, f)
            }
        }

        impl fmt::LowerHex for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::LowerHex::fmt(&self.0, f)
            }
        }

        impl fmt::UpperHex for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::UpperHex::fmt(&self.0, f)
            }
        }
    )*};
}

address! {
    /// A virtual address in the target's address space.
    Va(u64);
    /// An address relative to an image's load base. PE and PDB define these as
    /// 32-bit.
    Rva(u32);
    /// An offset into a file.
    FileOffset(u64);
}

impl Rva {
    /// The virtual address of this RVA when the image is loaded at `base`.
    #[inline]
    pub const fn to_va(self, base: Va) -> Option<Va> {
        base.checked_add(self.0 as u64)
    }
}

impl Va {
    /// The RVA of this address relative to `base`, if it is in range.
    #[inline]
    pub fn to_rva(self, base: Va) -> Option<Rva> {
        let delta = self.checked_offset_from(base)?;
        u32::try_from(delta).ok().map(Rva)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rva_va_round_trip() {
        let base = Va(0x1_4000_0000);
        assert_eq!(Rva(0x1000).to_va(base), Some(Va(0x1_4000_1000)));
        assert_eq!(Va(0x1_4000_1000).to_rva(base), Some(Rva(0x1000)));
        assert_eq!(Va(0x1000).to_rva(base), None);
        assert_eq!(Va(0x2_4000_0000).to_rva(base), None);
        assert_eq!(Rva(1).to_va(Va(u64::MAX)), None);
    }
}
