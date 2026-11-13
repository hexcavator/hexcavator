//! Plain-old-data overlays: reinterpreting byte slices as on-disk structures.

use core::mem::{align_of, size_of};

/// A type that can be safely overlaid on any byte sequence of its size.
///
/// # Safety
///
/// Implementors must have alignment 1, contain no padding, and accept every
/// bit pattern as a valid value. Declare structures with [`pod!`](crate::pod)
/// rather than implementing this by hand; the macro checks all three.
pub unsafe trait Pod: Copy + 'static {}

// SAFETY: single bytes have alignment 1 and every bit pattern is valid.
unsafe impl Pod for u8 {}
// SAFETY: as above.
unsafe impl Pod for i8 {}
// SAFETY: an array of `Pod` elements has the element's alignment and no padding.
unsafe impl<T: Pod, const N: usize> Pod for [T; N] {}

/// Reinterprets the start of `bytes` as a `T`, or returns `None` if too short.
#[inline]
pub fn from_bytes<T: Pod>(bytes: &[u8]) -> Option<&T> {
    const { assert!(align_of::<T>() == 1) };
    if bytes.len() < size_of::<T>() {
        return None;
    }
    // SAFETY: `T: Pod` has alignment 1 and accepts any bit pattern, and the
    // length was checked above. The result borrows from `bytes`.
    Some(unsafe { &*bytes.as_ptr().cast::<T>() })
}

/// Reinterprets the start of `bytes` as `count` consecutive `T`s, or returns
/// `None` if too short.
#[inline]
pub fn slice_from_bytes<T: Pod>(bytes: &[u8], count: usize) -> Option<&[T]> {
    const { assert!(align_of::<T>() == 1) };
    let len = size_of::<T>().checked_mul(count)?;
    if bytes.len() < len {
        return None;
    }
    // SAFETY: as in `from_bytes`; `count` elements fit within `bytes`.
    Some(unsafe { core::slice::from_raw_parts(bytes.as_ptr().cast::<T>(), count) })
}

/// Views a `Pod` value as its bytes.
#[inline]
pub fn as_bytes<T: Pod>(value: &T) -> &[u8] {
    // SAFETY: `T: Pod` has no padding, so all `size_of::<T>()` bytes are
    // initialized.
    unsafe { core::slice::from_raw_parts((value as *const T).cast::<u8>(), size_of::<T>()) }
}

/// Declares on-disk structures that implement [`Pod`].
///
/// Every field must itself be `Pod` (use the explicit-endian integer types,
/// byte arrays, or other `pod!` structures). The macro adds `#[repr(C)]` and
/// `Clone, Copy`, and checks at compile time that the result has alignment 1
/// and no padding.
///
/// ```
/// hexcavator_core::pod! {
///     #[derive(Debug)]
///     pub struct Header {
///         pub magic: [u8; 4],
///         pub count: hexcavator_core::U32Le,
///     }
/// }
/// let bytes = [b'R', b'B', b'A', b'T', 3, 0, 0, 0];
/// let header: &Header = hexcavator_core::from_bytes(&bytes).unwrap();
/// assert_eq!(header.count.get(), 3);
/// ```
#[macro_export]
macro_rules! pod {
    ($(
        $(#[$meta:meta])*
        $vis:vis struct $name:ident {
            $($(#[$field_meta:meta])* $field_vis:vis $field:ident : $ty:ty),* $(,)?
        }
    )*) => {$(
        $(#[$meta])*
        #[repr(C)]
        #[derive(Clone, Copy)]
        $vis struct $name {
            $($(#[$field_meta])* $field_vis $field: $ty,)*
        }

        const _: () = {
            const fn assert_pod<T: $crate::Pod>() {}
            $(assert_pod::<$ty>();)*
            assert!(::core::mem::align_of::<$name>() == 1);
            assert!(::core::mem::size_of::<$name>() == 0 $(+ ::core::mem::size_of::<$ty>())*);
        };

        // SAFETY: checked above: every field is `Pod`, alignment is 1, and the
        // size equals the sum of the field sizes, so there is no padding.
        #[allow(unsafe_code)]
        unsafe impl $crate::Pod for $name {}
    )*};
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{U16Le, U32Be};

    crate::pod! {
        #[derive(Debug, PartialEq)]
        struct Mixed {
            a: u8,
            b: U32Be,
            c: [U16Le; 2],
        }
    }

    #[test]
    fn overlay_at_odd_offset() {
        let bytes = [0xFF, 7, 0, 0, 0, 1, 2, 0, 3, 0, 0xEE];
        let m: &Mixed = from_bytes(&bytes[1..]).unwrap();
        assert_eq!(m.a, 7);
        assert_eq!(m.b.get(), 1);
        assert_eq!(m.c[0].get(), 2);
        assert_eq!(m.c[1].get(), 3);
        assert_eq!(as_bytes(m), &bytes[1..10]);
    }

    #[test]
    fn short_input_is_rejected() {
        assert!(from_bytes::<Mixed>(&[0; 8]).is_none());
        assert!(slice_from_bytes::<U16Le>(&[0; 5], 3).is_none());
        assert!(slice_from_bytes::<U16Le>(&[0; 5], usize::MAX).is_none());
        assert_eq!(
            slice_from_bytes::<U16Le>(&[1, 0, 2, 0, 9], 2).unwrap()[1].get(),
            2
        );
    }
}
