//! List command - display container contents.

use crate::cli::format_bytes;
use crate::error::Result;
use crate::reader::Reader;
use clap::Args;
use serde::Serialize;
use std::fs::File;
use std::path::PathBuf;

/// Arguments for the list command.
#[derive(Args)]
pub struct ListArgs {
    /// ZETA file to list
    #[arg(short, long)]
    input: PathBuf,

    /// Output format
    #[arg(short, long, value_enum, default_value = "table")]
    format: ListFormat,

    /// Show detailed information
    #[arg(short, long)]
    long: bool,

    /// Show chunk information
    #[arg(long)]
    chunks: bool,

    /// Sort by (name, size, chunks)
    #[arg(long, value_enum)]
    sort: Option<SortBy>,

    /// Reverse sort order
    #[arg(long)]
    reverse: bool,

    /// Only show stream names
    #[arg(long)]
    names_only: bool,
}

/// Output format options.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum ListFormat {
    Table,
    Json,
    Csv,
    Simple,
}

/// Sort options.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum SortBy {
    Name,
    Size,
    Chunks,
}

/// Run the list command.
pub fn run(args: ListArgs, _verbose: bool) -> Result<()> {
    // Open the container
    let file = File::open(&args.input)?;
    let reader = Reader::open(file)?;

    let mut streams: Vec<_> = reader.streams().iter().collect();

    // Sort if requested
    if let Some(sort) = args.sort {
        match sort {
            SortBy::Name => streams.sort_by(|a, b| a.name.cmp(&b.name)),
            SortBy::Size => {
                streams.sort_by(|a, b| a.total_uncompressed_size.cmp(&b.total_uncompressed_size))
            }
            SortBy::Chunks => streams.sort_by(|a, b| a.chunk_count.cmp(&b.chunk_count)),
        }
    }

    if args.reverse {
        streams.reverse();
    }

    // Output based on format
    match args.format {
        ListFormat::Table => print_table(&streams, &args, &reader),
        ListFormat::Json => print_json(&streams, &reader)?,
        ListFormat::Csv => print_csv(&streams, &args)?,
        ListFormat::Simple => print_simple(&streams, args.names_only),
    }

    // Print summary
    if !args.names_only {
        println!();
        println!(
            "Total: {} streams, {}, {} chunks",
            streams.len(),
            format_bytes(reader.total_uncompressed_size()),
            reader.total_chunk_count()
        );

        if reader.is_encrypted() {
            println!("Encryption: Yes");
        }
        if reader.has_index() {
            println!("Index: Yes");
        }
    }

    Ok(())
}

/// Print table format.
fn print_table<R: std::io::Read + std::io::Seek>(
    streams: &[&crate::format::stream_dir::StreamEntry],
    args: &ListArgs,
    reader: &Reader<R>,
) {
    if args.names_only {
        for stream in streams {
            println!("{}", stream.name);
        }
        return;
    }

    // Print header
    if args.long {
        println!(
            "{:>6} {:>10} {:>10} {:>8} {}",
            "Stream", "Size", "Chunks", "Type", "Name"
        );
        println!("{:-<80}", "");
    } else {
        println!("{:>10} {:>8} {}", "Size", "Chunks", "Name");
        println!("{:-<60}", "");
    }

    // Print rows
    for stream in streams {
        let size_str = format_bytes(stream.total_uncompressed_size);
        let chunks_str = stream.chunk_count.to_string();

        if args.long {
            let type_str = match stream.stream_type {
                crate::types::StreamType::Data => "data",
                crate::types::StreamType::Metadata => "meta",
                crate::types::StreamType::Index => "index",
                crate::types::StreamType::Reserved(_) => "other",
            };

            println!(
                "{:>6} {:>10} {:>10} {:>8} {}",
                stream.id.get(),
                size_str,
                chunks_str,
                type_str,
                stream.name
            );
        } else {
            println!("{:>10} {:>8} {}", size_str, chunks_str, stream.name);
        }
    }
}

/// Print JSON format.
fn print_json<R: std::io::Read + std::io::Seek>(
    streams: &[&crate::format::stream_dir::StreamEntry],
    reader: &Reader<R>,
) -> Result<()> {
    #[derive(Serialize)]
    struct FileInfo {
        version: String,
        encrypted: bool,
        indexed: bool,
        streaming: bool,
    }

    #[derive(Serialize)]
    struct StreamInfo {
        id: u32,
        name: String,
        #[serde(rename = "type")]
        stream_type: u8,
        size: u64,
        chunks: u64,
        offset: u64,
    }

    #[derive(Serialize)]
    struct Output {
        file: FileInfo,
        streams: Vec<StreamInfo>,
    }

    let output = Output {
        file: FileInfo {
            version: format!("{}.{}", reader.header().version_major, reader.header().version_minor),
            encrypted: reader.is_encrypted(),
            indexed: reader.has_index(),
            streaming: reader.is_streaming(),
        },
        streams: streams
            .iter()
            .map(|s| StreamInfo {
                id: s.id.get(),
                name: s.name.clone(),
                stream_type: s.stream_type.to_u8(),
                size: s.total_uncompressed_size,
                chunks: s.chunk_count,
                offset: s.first_chunk_offset,
            })
            .collect(),
    };

    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

/// Print CSV format.
fn print_csv(
    streams: &[&crate::format::stream_dir::StreamEntry],
    args: &ListArgs,
) -> Result<()> {
    let mut wtr = csv::Writer::from_writer(std::io::stdout());

    // Header
    if args.long {
        wtr.write_record(&["id", "name", "type", "size", "chunks", "offset"])?;
    } else {
        wtr.write_record(&["name", "size", "chunks"])?;
    }

    // Rows
    for stream in streams {
        if args.long {
            wtr.write_record(&[
                &stream.id.get().to_string(),
                &stream.name,
                &stream.stream_type.to_u8().to_string(),
                &stream.total_uncompressed_size.to_string(),
                &stream.chunk_count.to_string(),
                &stream.first_chunk_offset.to_string(),
            ])?;
        } else {
            wtr.write_record(&[
                &stream.name,
                &stream.total_uncompressed_size.to_string(),
                &stream.chunk_count.to_string(),
            ])?;
        }
    }

    wtr.flush()?;
    Ok(())
}

/// Print simple format (just names).
fn print_simple(
    streams: &[&crate::format::stream_dir::StreamEntry],
    names_only: bool,
) {
    for stream in streams {
        if names_only {
            println!("{}", stream.name);
        } else {
            println!("{} ({})", stream.name, format_bytes(stream.total_uncompressed_size));
        }
    }
}
