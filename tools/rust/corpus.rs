// Rust code whose v0 symbol names exercise the demangler: generics,
// closures, trait impls, dyn traits with associated types, const generics,
// lifetimes and higher-ranked bounds, fn pointers, arrays, tuples, and
// non-ASCII identifiers (Punycode). Built by build.cmd; its symbols, and
// llvm-cxxfilt's demanglings of them, are the demangler's test data.

#![allow(dead_code, non_snake_case, uncommon_codepoints)]

use std::collections::HashMap;
use std::fmt::Debug;

pub trait Shape {
    type Unit;
    fn area(&self) -> f64;
}

pub struct Square<T>(pub T);

impl<T: Copy + Into<f64>> Shape for Square<T> {
    type Unit = T;
    #[inline(never)]
    fn area(&self) -> f64 {
        let s: f64 = self.0.into();
        s * s
    }
}

#[inline(never)]
pub fn total(shapes: &[&dyn Shape<Unit = u8>]) -> f64 {
    shapes.iter().map(|s| s.area()).sum()
}

#[inline(never)]
pub fn sized<const N: usize, T: Default + Copy>() -> [T; N] {
    [T::default(); N]
}

#[inline(never)]
pub fn flags<const B: bool, const C: char, const I: i64>() -> (bool, char, i64) {
    (B, C, I)
}

#[inline(never)]
pub fn apply<F: for<'a> Fn(&'a str) -> &'a str>(f: F, s: &str) -> usize {
    f(s).len()
}

#[inline(never)]
pub fn pointers(f: fn(u32, *const u8, *mut i16) -> !, g: unsafe extern "C" fn(&mut [u64])) -> usize {
    f as usize ^ g as usize
}

#[inline(never)]
pub fn tuples(t: (u8, (i128, u128), ()), one: (char,)) -> usize {
    t.0 as usize + one.0 as usize
}

pub mod ünïcödé {
    #[inline(never)]
    pub fn größe(x: &str) -> usize {
        x.len()
    }

    pub struct Ŝtruct;

    impl Ŝtruct {
        #[inline(never)]
        pub fn méthode(&self) -> u32 {
            7
        }
    }
}

pub struct Wrapper<'a, K, V> {
    map: HashMap<K, V>,
    name: &'a str,
}

impl<'a, K: std::hash::Hash + Eq + Debug, V: Debug> Wrapper<'a, K, V> {
    #[inline(never)]
    pub fn new(name: &'a str) -> Self {
        Wrapper { map: HashMap::new(), name }
    }

    #[inline(never)]
    pub fn describe(&self) -> String {
        format!("{} {:?}", self.name, self.map.keys().collect::<Vec<_>>())
    }
}

impl<'a, K, V> Drop for Wrapper<'a, K, V> {
    #[inline(never)]
    fn drop(&mut self) {}
}

#[inline(never)]
pub fn closures(v: Vec<i32>) -> Vec<String> {
    let offset = v.len() as i32;
    let mut out: Vec<String> = v.into_iter().map(move |x| (x + offset).to_string()).collect();
    out.sort_by(|a, b| b.cmp(a));
    out
}

#[inline(never)]
pub fn boxed() -> Box<dyn Fn(u8) -> u16 + Send + Sync> {
    Box::new(|x| u16::from(x) * 2)
}

fn never(_: u32, _: *const u8, _: *mut i16) -> ! {
    panic!()
}

unsafe extern "C" fn c_abi(_: &mut [u64]) {}

fn main() {
    let sq = Square(3u8);
    let shapes: [&dyn Shape<Unit = u8>; 1] = [&sq];
    let mut sink = total(&shapes) as usize;
    sink += sized::<4, u16>().len();
    sink += sized::<0, ()>().len();
    let (b, c, i) = flags::<true, 'ß', -42>();
    sink += b as usize + c as usize + i as usize;
    let (b, c, i) = flags::<false, '\n', 1234567890123>();
    sink += b as usize + c as usize + i as usize;
    sink += apply(|s| s.trim(), " x ");
    sink += pointers(never, c_abi);
    sink += tuples((1, (2, 3), ()), ('x',));
    sink += ünïcödé::größe("é");
    sink += ünïcödé::Ŝtruct.méthode() as usize;
    let w: Wrapper<'_, String, Vec<u8>> = Wrapper::new("w");
    sink += w.describe().len();
    sink += closures(vec![3, 1, 2]).len();
    sink += boxed()(9) as usize;
    std::process::exit((sink & 1) as i32);
}
