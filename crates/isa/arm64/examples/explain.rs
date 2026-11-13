//! How hexcavator-arm64 decodes words: every encoding that matches, and how each
//! renders them, operand by operand.
//! `cargo run -p hexcavator-arm64 --example explain -- 3C72F89F 7F7EE7AB`

fn main() {
    for arg in std::env::args().skip(1) {
        let word = u32::from_str_radix(arg.trim_start_matches("0x"), 16).expect("a hex word");
        let shown = hexcavator_arm64::decode(word, 0).map(|i| hexcavator_arm64::format(&i));
        println!("{word:08X}: {shown:?}");
        print!("{}", hexcavator_arm64::explain(word));
    }
}
