//! Checks hexcavator-x86 against `tests/data/golden.txt`: a sample of every
//! opcode space, as disassembled by dumpbin (regenerate it with the
//! `generate_golden` test in `dumpbin.rs`). Unlike the dumpbin tests, this
//! runs everywhere.

use hexcavator_x86::{Mode, decode, format};

#[test]
fn golden() {
    let data = include_str!("../data/golden.txt");
    let mut checked = 0;
    let mut failures = Vec::new();
    for line in data
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let mut parts = line.split(" | ");
        let (head, text, len) = (
            parts.next().unwrap(),
            parts.next().unwrap(),
            parts.next().unwrap(),
        );
        let (mode_addr, hex) = head.split_once(' ').unwrap();
        let (mode, addr) = mode_addr.split_once('@').unwrap();
        let mode = if mode == "64" {
            Mode::Bits64
        } else {
            Mode::Bits32
        };
        let address = u64::from_str_radix(addr, 16).unwrap();
        let mut bytes: Vec<u8> = hex
            .split_whitespace()
            .map(|b| u8::from_str_radix(b, 16).unwrap())
            .collect();
        // The listing slot was padded with int3.
        bytes.resize(32, 0xCC);
        let actual = match decode(&bytes, mode, address) {
            Ok(inst) => (format::to_string(&inst), inst.len()),
            Err(_) => (String::new(), 0),
        };
        let expected = (text.to_string(), len.parse::<usize>().unwrap());
        if actual != expected {
            failures.push(format!(
                "{hex}: expected '{}' [{}], got '{}' [{}]",
                expected.0, expected.1, actual.0, actual.1
            ));
        }
        checked += 1;
    }
    assert!(
        checked > 10_000,
        "golden data is too small ({checked} cases)"
    );
    assert!(
        failures.is_empty(),
        "{} of {checked} differ:\n{}",
        failures.len(),
        failures[..failures.len().min(30)].join("\n")
    );
}
