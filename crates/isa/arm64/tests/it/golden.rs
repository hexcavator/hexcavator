//! Checks hexcavator-arm64 against a committed golden file of dumpbin's output:
//! up to four words of every encoding dumpbin decodes, and words both
//! reject. Runs everywhere; regenerate with `examples/golden.rs`.

/// Encodings newer than the dumpbin that made the golden file, which shows
/// their words as invalid: (encoding, why).
const NEWER: &[(&str, &str)] = &[(
    "FMININM_D_floatdp2",
    "FMININM (scalar) postdates dumpbin; LLVM decodes it",
)];

#[test]
fn golden() {
    let text = include_str!("../data/golden.txt");
    let mut failures = Vec::new();
    let mut count = 0;
    for line in text.lines() {
        count += 1;
        let (address, rest) = line.split_once(' ').unwrap();
        let (word, expected) = rest.split_once(' ').unwrap_or((rest, ""));
        let word = u32::from_str_radix(word, 16).unwrap();
        if address == "-" {
            if let Some(inst) = hexcavator_arm64::decode(word, 0) {
                if NEWER.iter().any(|(name, _)| *name == inst.encoding_name()) {
                    continue;
                }
                // Should-be bits that differ: CONSTRAINED UNPREDICTABLE, so
                // decoded (and marked `?`), where dumpbin rejects the word.
                if !inst.should_bits_hold() && inst.is_unpredictable() {
                    continue;
                }
                failures.push(format!(
                    "{word:08X}: expected invalid, got {}",
                    hexcavator_arm64::format(&inst)
                ));
            }
            continue;
        }
        let address = u64::from_str_radix(address, 16).unwrap();
        let ours = hexcavator_arm64::decode(word, address)
            .map(|i| hexcavator_arm64::format(&i))
            .unwrap_or_default();
        if !ours.split_whitespace().eq(expected.split_whitespace()) {
            failures.push(format!("{word:08X}: expected '{expected}', got '{ours}'"));
        }
    }
    assert!(count > 15_000, "golden file too small");
    assert!(
        failures.is_empty(),
        "{} of {count} differ:\n{}",
        failures.len(),
        failures[..failures.len().min(30)].join("\n")
    );
}
