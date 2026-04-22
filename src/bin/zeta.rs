//! ZETA CLI - Zero-Trust Extended Archive Format tool.

use std::process;

fn main() {
    if let Err(e) = zeta::cli::run() {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}
