//! Every word in golden.txt (tools/arm32/oracle.py -golden: up to four
//! words of each encoding, as llvm-objdump writes them) written the same.

#![allow(clippy::cast_possible_truncation)]

use hexcavator_arm32::format::{Targets, format};
use hexcavator_arm32::{decode_a32, decode_t32};

#[test]
fn llvm_text() {
    let golden = include_str!("golden.txt");
    let mut wrong = Vec::new();
    let mut count = 0;
    for line in golden
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let (head, want) = line.split_once('\t').unwrap();
        let mut it = head.split_whitespace();
        let (iset, word, at) = (it.next().unwrap(), it.next().unwrap(), it.next().unwrap());
        let w = u32::from_str_radix(word, 16).unwrap();
        let at = u64::from_str_radix(at, 16).unwrap();
        let i = match iset {
            "A32" => decode_a32(w),
            "T16" => decode_t32(w as u16, None),
            _ => decode_t32((w >> 16) as u16, Some(w as u16)),
        }
        .unwrap_or_else(|| panic!("{line}: doesn't decode"));
        let got = format(&i, at, Targets::Addresses);
        let got = got.split_whitespace().collect::<Vec<_>>().join(" ");
        count += 1;
        if got != want {
            wrong.push(format!("{line}\n    got  {got} ({})", i.encoding.name));
        }
    }
    assert!(count > 6000, "{count} words");
    assert!(
        wrong.is_empty(),
        "{} of {count} differ:\n{}",
        wrong.len(),
        wrong[..wrong.len().min(20)].join("\n")
    );
}
