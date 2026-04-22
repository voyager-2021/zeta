//! Command-line interface for ZETA.

pub mod list;
pub mod pack;
pub mod unpack;
pub mod verify;

use crate::error::Result;
use clap::{Parser, Subcommand};

/// ZETA CLI - Zero-Trust Extended Archive Format
#[derive(Parser)]
#[command(name = "zeta")]
#[command(about = "Zero-Trust Extended Archive Format tool")]
#[command(version)]
pub struct Cli {
    /// Enable verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Subcommand to execute
    #[command(subcommand)]
    pub command: Commands,
}

/// CLI subcommands.
#[derive(Subcommand)]
pub enum Commands {
    /// Pack files into a ZETA container
    Pack(pack::PackArgs),
    /// Unpack a ZETA container
    Unpack(unpack::UnpackArgs),
    /// List streams in a ZETA container
    List(list::ListArgs),
    /// Verify a ZETA container
    Verify(verify::VerifyArgs),
}

/// Run the CLI.
pub fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Pack(args) => pack::run(args, cli.verbose),
        Commands::Unpack(args) => unpack::run(args, cli.verbose),
        Commands::List(args) => list::run(args, cli.verbose),
        Commands::Verify(args) => verify::run(args, cli.verbose),
    }
}

/// Format bytes for human-readable display.
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB", "PB"];

    if bytes == 0 {
        return "0 B".to_string();
    }

    let exp = (bytes as f64).log(1024.0).min(UNITS.len() as f64 - 1.0) as usize;
    let value = bytes as f64 / 1024f64.powi(exp as i32);

    if exp == 0 {
        format!("{} {}", bytes, UNITS[0])
    } else {
        format!("{:.2} {}", value, UNITS[exp])
    }
}

/// Format a duration for display.
pub fn format_duration(duration: std::time::Duration) -> String {
    let secs = duration.as_secs();
    let millis = duration.subsec_millis();

    if secs == 0 {
        format!("{}ms", millis)
    } else if secs < 60 {
        format!("{}.{:03}s", secs, millis)
    } else {
        let mins = secs / 60;
        let secs = secs % 60;
        format!("{}m {}s", mins, secs)
    }
}

/// Print an error message.
pub fn print_error(msg: impl AsRef<str>) {
    eprintln!("Error: {}", msg.as_ref());
}

/// Print a warning message.
pub fn print_warning(msg: impl AsRef<str>) {
    eprintln!("Warning: {}", msg.as_ref());
}

/// Print verbose info.
pub fn print_verbose(verbose: bool, msg: impl AsRef<str>) {
    if verbose {
        println!("[verbose] {}", msg.as_ref());
    }
}
