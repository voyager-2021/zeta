//! Unpack command - extract ZETA containers.

use crate::cli::{format_bytes, format_duration, print_error, print_verbose};
use crate::error::Result;
use crate::pipeline::PipelineConfig;
use crate::reader::{Reader, Verifier};
use crate::types::StreamId;
use clap::Args;
use indicatif::{ProgressBar, ProgressStyle};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Arguments for the unpack command.
#[derive(Args)]
pub struct UnpackArgs {
    /// Input ZETA file
    #[arg(short, long)]
    input: PathBuf,

    /// Output directory
    #[arg(short, long, default_value = ".")]
    output: PathBuf,

    /// Specific streams to extract (default: all)
    #[arg(short, long)]
    stream: Vec<String>,

    /// Password for decryption
    #[arg(short, long)]
    password: Option<String>,

    /// Key file for decryption
    #[arg(long)]
    key_file: Option<PathBuf>,

    /// Overwrite existing files
    #[arg(short, long)]
    force: bool,

    /// Preserve directory structure
    #[arg(long)]
    preserve_structure: bool,

    /// Flatten output (no subdirectories)
    #[arg(long)]
    flatten: bool,
}

/// Run the unpack command.
pub fn run(args: UnpackArgs, verbose: bool) -> Result<()> {
    let start = Instant::now();

    print_verbose(verbose, format!("Opening ZETA container: {}", args.input.display()));

    // Open the container
    let file = File::open(&args.input)?;
    let mut reader = Reader::open(file)?;

    print_verbose(verbose, format!("Found {} streams", reader.stream_count()));

    // Derive key if encrypted
    if reader.is_encrypted() {
        let key = derive_key(&args)?;
        reader = reader.with_key(key);
    }

    // Determine which streams to extract
    let streams_to_extract = if args.stream.is_empty() {
        reader.stream_ids()
    } else {
        args.stream
            .iter()
            .filter_map(|name| reader.get_stream_by_name(name).map(|s| s.id))
            .collect()
    };

    if streams_to_extract.is_empty() {
        return Err(crate::Error::custom("No streams to extract"));
    }

    // Create output directory
    fs::create_dir_all(&args.output)?;

    // Progress bar
    let progress = if verbose {
        None
    } else {
        let pb = ProgressBar::new(streams_to_extract.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
                .unwrap()
                .progress_chars("#>-"),
        );
        Some(pb)
    };

    let mut total_bytes = 0u64;
    let mut extracted_count = 0usize;

    // Extract each stream
    for (i, stream_id) in streams_to_extract.iter().enumerate() {
        let stream = reader
            .get_stream(*stream_id)
            .ok_or_else(|| crate::Error::StreamNotFound(stream_id.get()))?;

        if let Some(ref pb) = progress {
            pb.set_message(stream.name.clone());
        }

        print_verbose(verbose, format!("Extracting: {}", stream.name));

        match extract_stream(&args.input, &stream.name, stream.id, &args) {
            Ok(bytes) => {
                total_bytes += bytes;
                extracted_count += 1;
            }
            Err(e) => {
                print_error(format!("Failed to extract {}: {}", stream.name, e));
            }
        }

        if let Some(ref pb) = progress {
            pb.set_position((i + 1) as u64);
        }
    }

    if let Some(pb) = progress {
        pb.finish_with_message("Done");
    }

    let duration = start.elapsed();

    println!("Extracted: {} streams", extracted_count);
    println!("Total size: {}", format_bytes(total_bytes));
    println!("Time: {}", format_duration(duration));

    Ok(())
}

/// Get stream IDs from the reader.
trait ReaderExt {
    fn stream_ids(&self) -> Vec<StreamId>;
}

impl<R: std::io::Read + std::io::Seek> ReaderExt for Reader<R> {
    fn stream_ids(&self) -> Vec<StreamId> {
        self.streams().iter().map(|s| s.id).collect()
    }
}

/// Extract a single stream.
fn extract_stream(
    container_path: &Path,
    stream_name: &str,
    stream_id: StreamId,
    args: &UnpackArgs,
) -> Result<u64> {
    // Determine output path
    let output_path = if args.flatten {
        // Flatten: just use the filename
        let file_name = Path::new(stream_name)
            .file_name()
            .ok_or_else(|| crate::Error::custom("Invalid stream name"))?;
        args.output.join(file_name)
    } else if args.preserve_structure {
        // Preserve structure: use full path
        args.output.join(stream_name)
    } else {
        // Default: sanitize and use relative path
        let safe_name = sanitize_filename(stream_name);
        args.output.join(safe_name)
    };

    // Check for overwrite
    if output_path.exists() && !args.force {
        return Err(crate::Error::custom(format!(
            "File exists (use --force to overwrite): {}",
            output_path.display()
        )));
    }

    // Create parent directories
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Open the container and extract stream data
    let data = if args.key_file.is_some() {
        // Use indexed reader for random access
        let file = File::open(container_path)?;
        let reader = Reader::open(file)?;
        let mut indexed = reader.into_indexed()?;
        indexed.read_stream_full(stream_id)?
    } else {
        // Use streaming reader
        let file = File::open(container_path)?;
        let reader = Reader::open(file)?;
        let mut streaming = reader.into_streaming()?;
        streaming.read_stream(stream_id)?
    };

    // Write to file
    let mut output_file = File::create(&output_path)?;
    output_file.write_all(&data)?;

    Ok(data.len() as u64)
}

/// Sanitize a filename for safe extraction.
fn sanitize_filename(name: &str) -> String {
    // Remove or replace unsafe characters
    name.chars()
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '|' | '?' | '*' => '_',
            c if c.is_control() => '_',
            _ => c,
        })
        .collect()
}

/// Derive decryption key from password or key file.
fn derive_key(args: &UnpackArgs) -> Result<Vec<u8>> {
    use crate::registry::{global_registry, KdfAlgorithm};
    use rand::RngCore;

    if let Some(ref key_file) = args.key_file {
        return Ok(std::fs::read(key_file)?);
    }

    if let Some(ref password) = args.password {
        // In a real implementation, we'd need to store the KDF parameters
        // and salt in the container. For now, we use default parameters.
        let kdf = global_registry()
            .kdf
            .get(crate::registry::Kdf::Argon2id as u16)
            .ok_or_else(|| crate::Error::crypto("KDF not available"))?;

        // We'd need to retrieve the actual salt from the container
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
