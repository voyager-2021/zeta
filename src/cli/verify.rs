//! Verify command - check container integrity.

use crate::cli::{format_duration, print_verbose};
use crate::error::Result;
use crate::reader::verifier::{VerificationOptions, Verifier};
use crate::reader::{Reader, VerificationResult};
use clap::Args;
use indicatif::{ProgressBar, ProgressStyle};
use std::fs::File;
use std::path::PathBuf;
use std::time::Instant;

/// Arguments for the verify command.
#[derive(Args)]
pub struct VerifyArgs {
    /// ZETA file to verify
    #[arg(short, long)]
    input: PathBuf,

    /// Verify all chunks (slower)
    #[arg(short, long)]
    deep: bool,

    /// Verify signatures
    #[arg(long)]
    signatures: bool,

    /// Password for decryption
    #[arg(short, long)]
    password: Option<String>,

    /// Key file for decryption
    #[arg(long)]
    key_file: Option<PathBuf>,

    /// Maximum chunks to verify (0 = all)
    #[arg(long, default_value = "0")]
    max_chunks: usize,

    /// Exit with error code on warning
    #[arg(long)]
    strict: bool,

    /// Only verify header CRC (fast)
    #[arg(long)]
    quick: bool,
}

/// Run the verify command.
pub fn run(args: VerifyArgs, verbose: bool) -> Result<()> {
    let start = Instant::now();

    print_verbose(verbose, format!("Verifying: {}", args.input.display()));

    // Open the container
    let mut file = File::open(&args.input)?;
    let reader = Reader::open(&mut file)?;

    // Build verification options
    let mut options = VerificationOptions::new();
    options.verify_chunks = args.deep;
    options.verify_signatures = args.signatures;
    options.verify_file_hash = !args.quick;
    options.max_chunks = args.max_chunks;

    // Set key if encrypted
    if reader.is_encrypted() {
        let key = derive_key(&args)?;
        options.key = Some(key);
    }

    // Progress bar
    let progress = if verbose || args.quick {
        None
    } else {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} {msg}")
                .unwrap(),
        );
        pb.set_message("Verifying...");
        Some(pb)
    };

    // Run verification
    let mut result = if args.quick {
        // Quick verification - just header CRC
        let verifier = Verifier::new();
        verifier.quick_verify(reader.header())?
    } else {
        // Full verification
        let mut file = File::open(&args.input)?;
        let verifier = Verifier::new();

        if args.deep {
            verifier.verify_chunks(&mut file, reader.header(), &options)?
        } else {
            verifier.verify_container(&mut file, reader.header())?
        }
    };

    if let Some(pb) = progress {
        pb.finish_and_clear();
    }

    let duration = start.elapsed();

    // Print results
    print_results(&result, &args);

    println!("Time: {}", format_duration(duration));

    // Exit code
    if !result.valid {
        std::process::exit(1);
    }

    if args.strict && !result.warnings.is_empty() {
        std::process::exit(2);
    }

    Ok(())
}

/// Print verification results.
fn print_results(result: &VerificationResult, args: &VerifyArgs) {
    if result.valid && result.errors.is_empty() && result.warnings.is_empty() {
        println!("✓ Container is valid");
        return;
    }

    if !result.valid {
        println!("✗ Container is INVALID");
    } else {
        println!("! Container has warnings");
    }

    // Header
    if result.header_crc_valid {
        println!("  ✓ Header CRC: valid");
    } else {
        println!("  ✗ Header CRC: INVALID");
    }

    // File hash
    if args.deep || !args.quick {
        match result.file_hash_valid {
            Some(true) => println!("  ✓ File hash: valid"),
            Some(false) => println!("  ✗ File hash: INVALID"),
            None => println!("  - File hash: not checked"),
        }
    }

    // Signatures
    if args.signatures {
        match result.signatures_valid {
            Some(true) => println!("  ✓ Signatures: valid"),
            Some(false) => println!("  ✗ Signatures: INVALID"),
            None => println!("  - Signatures: not checked"),
        }
    }

    // Errors
    if !result.errors.is_empty() {
        println!();
        println!("Errors:");
        for error in &result.errors {
            println!("  - {}", error);
        }
    }

    // Warnings
    if !result.warnings.is_empty() {
        println!();
        println!("Warnings:");
        for warning in &result.warnings {
            println!("  - {}", warning);
        }
    }
}

/// Derive decryption key.
fn derive_key(args: &VerifyArgs) -> Result<Vec<u8>> {
    use crate::registry::{global_registry, KdfAlgorithm};
    use rand::RngCore;

    if let Some(ref key_file) = args.key_file {
        return Ok(std::fs::read(key_file)?);
    }

    if let Some(ref password) = args.password {
        let kdf = global_registry()
            .kdf
            .get(crate::registry::Kdf::Argon2id as u16)
            .ok_or_else(|| crate::Error::crypto("KDF not available"))?;

        let mut salt = vec![0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt);

        let params = crate::registry::KdfParams::argon2id_default();
        let key = kdf.derive(password.as_bytes(), &salt, 32, &params)?;

        return Ok(key);
    }

    Err(crate::Error::crypto(
        "Decryption requires password or key file",
    ))
}
