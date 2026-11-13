//! Explicit-endian integer types with alignment 1.
//!
//! Fixed-order types (`U32Le`, `U32Be`, ...) are for formats whose byte order is
//! fixed by the spec (PE/COFF, PDB). Runtime-order types (`U32E`, ...) are for
//! formats whose byte order is only known from the file itself (ELF, Mach-O,
//! DWARF); read them with an [`Endian`].

use core::fmt;

use crate::Pod;

/// A byte order, chosen at runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Endian {
    /// Least significant byte first.
    Little,
    /// Most significant byte first.
    Big,
}

macro_rules! fixed_endian {
    ($($name:ident: $int:ty, $n:literal, $from:ident, $to:ident, $order:literal;)*) => {$(
        #[doc = concat!("A `", stringify!($int), "` stored in ", $order, "-endian byte order, with alignment 1.")]
        #[repr(transparent)]
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
        pub struct $name([u8; $n]);

        impl $name {
            /// `value`, stored.
            #[inline]
            pub const fn new(value: $int) -> Self {
                Self(value.$to())
            }

            /// The value stored.
            #[inline]
            pub const fn get(self) -> $int {
                <$int>::$from(self.0)
            }

            /// The value these bytes store.
            #[inline]
            pub const fn from_bytes(bytes: [u8; $n]) -> Self {
                Self(bytes)
            }

            /// Its bytes, as stored.
            #[inline]
            pub const fn to_bytes(self) -> [u8; $n] {
                self.0
            }
        }

        impl From<$int> for $name {
            #[inline]
            fn from(value: $int) -> Self {
                Self::new(value)
            }
        }

        impl From<$name> for $int {
            #[inline]
            fn from(value: $name) -> Self {
                value.get()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Debug::fmt(&self.get(), f)
            }
        }

        // SAFETY: a transparent wrapper around a byte array: alignment 1, no
        // padding, and every bit pattern is valid.
        unsafe impl Pod for $name {}
    )*};
}

fixed_endian! {
    U16Le: u16, 2, from_le_bytes, to_le_bytes, "little";
    U32Le: u32, 4, from_le_bytes, to_le_bytes, "little";
    U64Le: u64, 8, from_le_bytes, to_le_bytes, "little";
    I16Le: i16, 2, from_le_bytes, to_le_bytes, "little";
    I32Le: i32, 4, from_le_bytes, to_le_bytes, "little";
    I64Le: i64, 8, from_le_bytes, to_le_bytes, "little";
    U16Be: u16, 2, from_be_bytes, to_be_bytes, "big";
    U32Be: u32, 4, from_be_bytes, to_be_bytes, "big";
    U64Be: u64, 8, from_be_bytes, to_be_bytes, "big";
    I16Be: i16, 2, from_be_bytes, to_be_bytes, "big";
    I32Be: i32, 4, from_be_bytes, to_be_bytes, "big";
    I64Be: i64, 8, from_be_bytes, to_be_bytes, "big";
}

macro_rules! runtime_endian {
    ($($name:ident: $int:ty, $n:literal;)*) => {$(
        #[doc = concat!("A `", stringify!($int), "` whose byte order is determined at runtime, with alignment 1.")]
        #[repr(transparent)]
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
        pub struct $name([u8; $n]);

        impl $name {
            /// `value`, stored in `endian` byte order.
            #[inline]
            pub const fn new(value: $int, endian: Endian) -> Self {
                Self(match endian {
                    Endian::Little => value.to_le_bytes(),
                    Endian::Big => value.to_be_bytes(),
                })
            }

            /// The value stored, read in `endian` byte order.
            #[inline]
            pub const fn get(self, endian: Endian) -> $int {
                match endian {
                    Endian::Little => <$int>::from_le_bytes(self.0),
                    Endian::Big => <$int>::from_be_bytes(self.0),
                }
            }

            /// The value these bytes store (in either order).
            #[inline]
            pub const fn from_bytes(bytes: [u8; $n]) -> Self {
                Self(bytes)
            }

            /// Its bytes, as stored.
            #[inline]
            pub const fn to_bytes(self) -> [u8; $n] {
                self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                // The byte order is unknown here, so show the raw bytes.
                fmt::Debug::fmt(&self.0, f)
            }
        }

        // SAFETY: a transparent wrapper around a byte array: alignment 1, no
        // padding, and every bit pattern is valid.
        unsafe impl Pod for $name {}
    )*};
}

runtime_endian! {
    U16E: u16, 2;
    U32E: u32, 4;
    U64E: u64, 8;
    I16E: i16, 2;
    I32E: i32, 4;
    I64E: i64, 8;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_order_is_host_independent() {
        assert_eq!(
            U32Le::from_bytes([0x78, 0x56, 0x34, 0x12]).get(),
            0x1234_5678
        );
        assert_eq!(
            U32Be::from_bytes([0x12, 0x34, 0x56, 0x78]).get(),
            0x1234_5678
        );
        assert_eq!(U16Le::new(0xABCD).to_bytes(), [0xCD, 0xAB]);
        assert_eq!(I32Le::new(-2).get(), -2);
        assert_eq!(
            I64Be::new(-2).to_bytes(),
            [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE]
        );
    }

    #[test]
    fn runtime_order() {
        let v = U32E::from_bytes([0x12, 0x34, 0x56, 0x78]);
        assert_eq!(v.get(Endian::Big), 0x1234_5678);
        assert_eq!(v.get(Endian::Little), 0x7856_3412);
        assert_eq!(
            U64E::new(1, Endian::Big).to_bytes(),
            [0, 0, 0, 0, 0, 0, 0, 1]
        );
    }

    #[test]
    fn alignment_is_one() {
        assert_eq!(core::mem::align_of::<U64Le>(), 1);
        assert_eq!(core::mem::align_of::<I64Be>(), 1);
        assert_eq!(core::mem::align_of::<U64E>(), 1);
    }
}
