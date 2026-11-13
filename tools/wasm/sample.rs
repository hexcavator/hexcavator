// Builds testdata/wasm/sample.wasm, real compiler output for checking the
// disassembler against llvm-objdump (see testdata/wasm/README.md):
//
//   rustc --target wasm32-wasip1 --crate-type cdylib -C opt-level=2
//     -C panic=abort -C target-feature=+simd128,+bulk-memory,+nontrapping-fptoint,+sign-ext
//     -C strip=none tools/wasm/sample.rs -o testdata/wasm/sample.wasm

#![no_std]

use core::arch::wasm32::*;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

/// A switch: br_table.
#[unsafe(no_mangle)]
pub extern "C" fn classify(x: u32) -> u32 {
    match x {
        0 => 10,
        1 => 20,
        2 => 35,
        3 => 47,
        4 => 51,
        5 => 68,
        _ => 0,
    }
}

/// Loops, loads and stores with offsets.
#[unsafe(no_mangle)]
pub extern "C" fn sum(p: *const u32, n: usize) -> u64 {
    let s = unsafe { core::slice::from_raw_parts(p, n) };
    let mut t = 0u64;
    for (i, v) in s.iter().enumerate() {
        t = t.wrapping_add(u64::from(*v) << (i & 7));
    }
    t
}

/// Floats: constants, conversions, comparisons.
#[unsafe(no_mangle)]
pub extern "C" fn blend(a: f32, b: f64, k: i32) -> f64 {
    let x = f64::from(a) * 1.5 + b / 3.25;
    let y = if x > 1e10 { -0.125 } else { x };
    y + f64::from(k as f32 * 0.1f32) + (x as i64) as f64
}

/// SIMD: vector constants, shuffles, lanes.
#[unsafe(no_mangle)]
pub extern "C" fn dot(a: *const v128, b: *const v128) -> i32 {
    unsafe {
        let x = v128_load(a);
        let y = v128_load(b);
        let p = i32x4_mul(x, y);
        let q = i32x4_add(p, i32x4_shuffle::<2, 3, 0, 1>(p, p));
        let r = i32x4_add(q, i32x4(7, -7, 9, -9));
        i32x4_extract_lane::<0>(r) + i32x4_extract_lane::<1>(i8x16_swizzle(r, u8x16_splat(3)))
    }
}

/// Bulk memory: memory.copy and memory.fill.
#[unsafe(no_mangle)]
pub extern "C" fn move_and_clear(dst: *mut u8, src: *const u8, n: usize) {
    unsafe {
        core::ptr::copy(src, dst, n);
        core::ptr::write_bytes(dst.add(n), 0, n);
    }
}

/// Indirect calls: call_indirect, through a table.
#[unsafe(no_mangle)]
pub extern "C" fn apply(f: extern "C" fn(u32) -> u32, x: u32) -> u32 {
    f(x) + classify(x)
}

/// Sign extension and saturating conversions.
#[unsafe(no_mangle)]
pub extern "C" fn narrow(x: i64, f: f32) -> i32 {
    (x as i8) as i32 + (x as i16) as i32 + f as i32
}
