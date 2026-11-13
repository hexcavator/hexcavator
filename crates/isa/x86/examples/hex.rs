//! Decodes hex byte strings (64-bit mode unless `-32`) and prints each.
//!
//!     cargo run -p hexcavator-x86 --example hex -- "d5 08 50" "62f4fc1801cb"

use hexcavator_x86::{Mode, decode, format};

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mode = if args.first().is_some_and(|a| a == "-32") {
        args.remove(0);
        Mode::Bits32
    } else {
        Mode::Bits64
    };
    for a in &args {
        let hex: String = a.chars().filter(char::is_ascii_hexdigit).collect();
        let bytes: Vec<u8> = (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap_or(0))
            .collect();
        match decode(&bytes, mode, 0) {
            Ok(i) => println!("{a:<36} {} [{}]", format::to_string(&i), i.len()),
            Err(e) => println!("{a:<36} <{e:?}>"),
        }
    }
}
