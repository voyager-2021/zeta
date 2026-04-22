//! Pack command - create ZETA containers.

use crate::cli::{format_bytes, format_duration, print_error, print_verbose};
use crate::error::Result;
use crate::pipeline::PipelineConfig;
use crate::registry::{
    Compression, Encryption, Hash, Kdf, KdfAlgorithm, KdfParams, Signature,
};
use crate::types::ZetaFlags;
use crate::writer::{StreamWriter, Writer, WriterBuilder};
use clap::Args;
use indicatif::{ProgressBar, ProgressStyle};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Arguments for the pack command.
#[derive(Args)]
pub struct PackArgs {
    /// Output file
    #[arg(short, long)]
    output: PathBuf,

    /// Input files or directories
    #[arg(required = true)]
    inputs: Vec<PathBuf>,

    /// Compression algorithm
    #[arg(short, long, value_enum)]
    compression: Option<CompressionArg>,

    /// Compression level (if applicable)
    #[arg(long)]
    compression_level: Option<i32>,

    /// Encryption algorithm
    #[arg(short, long, value_enum)]
    encryption: Option<EncryptionArg>,

    /// Password for encryption
    #[arg(short, long)]
    password: Option<String>,

    /// Key file for encryption
    #[arg(long)]
    key_file: Option<PathBuf>,

    /// Hash algorithm for integrity
    #[arg(long, value_enum)]
    hash: Option<HashArg>,

    /// KDF algorithm for password derivation
    #[arg(long, value_enum, default_value = "argon2id")]
    kdf: KdfArg,

    /// Sign with Ed25519 key file
    #[arg(long)]
    sign: Option<PathBuf>,

    /// Create index for random access
    #[arg(long)]
    index: bool,

    /// Streaming mode (no footer)
    #[arg(long)]
    streaming: bool,

    /// Enable delta encoding
    #[arg(long)]
    delta: bool,

    /// Recursive for directories
    #[arg(short, long)]
    recursive: bool,

    /// Follow symlinks
    #[arg(long)]
    follow_links: bool,
}

/// Compression algorithm options.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum CompressionArg {
    None,
    Lzw,
    Rle,
    Zstd,
    Lz4,
    Brotli,
    Zlib,
    Gzip,
    Bzip2,
    Lzma,
    Snappy,
    Lzma2,
}

impl CompressionArg {
    fn to_id(self) -> u16 {
        match self {
            CompressionArg::None => Compression::None as u16,
            CompressionArg::Lzw => Compression::Lzw as u16,
            CompressionArg::Rle => Compression::Rle as u16,
            CompressionArg::Zstd => Compression::Zstd as u16,
            CompressionArg::Lz4 => Compression::Lz4 as u16,
            CompressionArg::Brotli => Compression::Brotli as u16,
            CompressionArg::Zlib => Compression::Zlib as u16,
            CompressionArg::Gzip => Compression::Gzip as u16,
            CompressionArg::Bzip2 => Compression::Bzip2 as u16,
            CompressionArg::Lzma => Compression::Lzma as u16,
            CompressionArg::Snappy => Compression::Snappy as u16,
            CompressionArg::Lzma2 => Compression::Lzma2 as u16,
        }
    }
}

/// Encryption algorithm options.
#[derive(Clone, Copy, Debug, PartialEq, clap::ValueEnum)]
pub enum EncryptionArg {
    None,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl EncryptionArg {
    fn to_id(self) -> u16 {
        match self {
            EncryptionArg::None => Encryption::None as u16,
            EncryptionArg::Aes256Gcm => Encryption::Aes256Gcm as u16,
            EncryptionArg::ChaCha20Poly1305 => Encryption::ChaCha20Poly1305 as u16,
        }
    }
}

/// Hash algorithm options.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum HashArg {
    None,
    Sha256,
    Blake2b,
    Sha512,
    Sha3_256,
    Sha3_512,
    Blake3,
}

impl HashArg {
    fn to_id(self) -> u16 {
        match self {
            HashArg::None => Hash::None as u16,
            HashArg::Sha256 => Hash::Sha256 as u16,
            HashArg::Blake2b => Hash::Blake2b as u16,
            HashArg::Sha512 => Hash::Sha512 as u16,
            HashArg::Sha3_256 => Hash::Sha3_256 as u16,
            HashArg::Sha3_512 => Hash::Sha3_512 as u16,
            HashArg::Blake3 => Hash::Blake3 as u16,
        }
    }
}

/// KDF algorithm options.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum KdfArg {
    None,
    Pbkdf2,
    Argon2id,
    Scrypt,
    Hkdf,
}

impl KdfArg {
    fn to_id(self) -> u16 {
        match self {
            KdfArg::None => Kdf::None as u16,
            KdfArg::Pbkdf2 => Kdf::Pbkdf2 as u16,
            KdfArg::Argon2id => Kdf::Argon2id as u16,
            KdfArg::Scrypt => Kdf::Scrypt as u16,
            KdfArg::Hkdf => Kdf::Hkdf as u16,
        }
    }
}

/// Run the pack command.
pub fn run(args: PackArgs, verbose: bool) -> Result<()> {
    let start = Instant::now();

    print_verbose(verbose, format!("Creating ZETA container: {}", args.output.display()));

    // Collect input files
    let files = collect_files(&args.inputs, args.recursive)?;
    if files.is_empty() {
        return Err(crate::Error::custom("No input files found"));
    }

    print_verbose(verbose, format!("Found {} files to pack", files.len()));

    // Build writer configuration
    let mut builder = WriterBuilder::new();

    if args.index {
        builder = builder.with_index();
    }
    if args.streaming {
        builder = builder.streaming_mode();
    }
    if args.delta {
        builder = builder.delta_encoding();
    }

    // Set compression
    if let Some(comp) = args.compression {
        builder = builder.compression_by_id(comp.to_id());
    }

    // Set encryption
    if let Some(enc) = args.encryption {
        if enc != EncryptionArg::None {
            let key = derive_key(&args, enc.to_id())?;
            builder = builder.encryption_by_id(enc.to_id(), key);
        }
    }

    // Create output file
    let file = File::create(&args.output)?;
    let mut writer = builder.create(file)?;

    // Create progress bar
    let progress = if verbose {
        None
    } else {
        let pb = ProgressBar::new(files.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
                .unwrap()
                .progress_chars("#>-"),
        );
        Some(pb)
    };

    // Pack each file
    for (i, path) in files.iter().enumerate() {
        if let Some(ref pb) = progress {
            pb.set_message(format!("{}", path.display()));
        }

        print_verbose(verbose, format!("Packing: {}", path.display()));

        pack_file(&mut writer, path)?;

        if let Some(ref pb) = progress {
            pb.set_position((i + 1) as u64);
        }
    }

    if let Some(pb) = progress {
        pb.finish_with_message("Done");
    }

    // Finish writing
    writer.finish()?;

    let duration = start.elapsed();
    let output_size = std::fs::metadata(&args.output)?.len();

    println!("Created: {}", args.output.display());
    println!("Files packed: {}", files.len());
    println!("Output size: {}", format_bytes(output_size));
    println!("Time: {}", format_duration(duration));

    Ok(())
}

/// Collect files from input paths.
fn collect_files(inputs: &[PathBuf], recursive: bool) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();

    for input in inputs {
        if input.is_file() {
            files.push(input.clone());
        } else if input.is_dir() {
            if recursive {
                collect_files_recursive(input, &mut files)?;
            } else {
                // Just add directory entries that are files
                for entry in std::fs::read_dir(input)? {
                    let entry = entry?;
                    let path = entry.path();
                    if path.is_file() {
                        files.push(path);
                    }
                }
            }
        }
    }

    Ok(files)
}

/// Recursively collect files.
fn collect_files_recursive(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() {
            files.push(path);
        } else if path.is_dir() {
            collect_files_recursive(&path, files)?;
        }
    }
    Ok(())
}

/// Pack a single file into the container.
fn pack_file<W: std::io::Write + std::io::Seek>(
    writer: &mut Writer<W>,
    path: &Path,
) -> Result<()> {
    // Create stream
    let stream_name = path.to_string_lossy().to_string();
    writer.create_stream(&stream_name)?;

    // Read and write file
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer)?;

    writer.write_all(&buffer)?;

    Ok(())
}

/// Derive encryption key from password or key file.
fn derive_key(args: &PackArgs, _encryption_id: u16) -> Result<Vec<u8>> {
    use crate::registry::{global_registry, KdfAlgorithm};
    use rand::RngCore;

    if let Some(ref key_file) = args.key_file {
        // Read key from file
        let key = std::fs::read(key_file)?;
        return Ok(key);
    }

    if let Some(ref password) = args.password {
        // Derive key from password
        let kdf = global_registry()
            .kdf
            .get(args.kdf.to_id())
            .ok_or_else(|| crate::Error::crypto("KDF not available"))?;

        // Generate random salt
        let mut salt = vec![0u8; kdf.min_salt_size().max(16)];
        rand::thread_rng().fill_bytes(&mut salt);

        // Derive key
        let params = KdfParams::argon2id_default();
        let key = kdf.derive(password.as_bytes(), &salt, 32, &params)?;

        return Ok(key);
    }

    Err(crate::Error::crypto(
        "Encryption requires password or key file",
    ))
}
