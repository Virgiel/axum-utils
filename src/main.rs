use std::{io::Write, path::PathBuf, time::Instant};

use clap::Parser;
use mimalloc::MiMalloc;

use axum_utils::static_opti::worker::optimize;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

/// Prepare static files for efficient serving
#[derive(Parser, Debug)]
#[clap(long_about = None)]
struct Args {
    /// The directory containing static files
    in_dir: PathBuf,
    /// The path where to put the output
    out: Option<PathBuf>,
}

fn main() {
    let start = Instant::now();
    let args = Args::parse();

    let (_, items) = optimize(&args.in_dir, args.out.as_deref());

    // Print stats
    let max = items.iter().map(|t| t.path.len()).max().unwrap_or(0);
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    writeln!(
        &mut stdout,
        "{:<2$}  Plain       Gzip        Brotli\n{:-<3$}",
        "Name",
        "",
        max,
        max + 34
    )
    .unwrap();
    let mut plain_total = 0;
    let mut gzip_total = 0;
    let mut brotli_total = 0;
    for item in &items {
        let plain = item.plain.1;
        plain_total += plain;
        write!(
            &mut stdout,
            "{:<2$} {:>7}  ",
            item.path,
            format_size(plain as f32),
            max
        )
        .unwrap();
        for (opt, size) in [
            (&item.gzip, &mut gzip_total),
            (&item.brotli, &mut brotli_total),
        ] {
            if let Some((_, len)) = opt {
                *size += *len;
                write!(
                    &mut stdout,
                    "{:>7} {}%  ",
                    format_size(*len as f32),
                    (100 - (len * 100 / plain)),
                )
                .unwrap();
            } else {
                *size += plain;
                write!(&mut stdout, "             ").unwrap();
            }
        }

        writeln!(&mut stdout).unwrap();
    }
    writeln!(
        &mut stdout,
        "{:-<10$}\nTotal{:<9$}{:>7}  {:>7} {}%  {:>7} {}%\nOptimized {} files in {:?}",
        "",
        "",
        format_size(plain_total as f32),
        format_size(gzip_total as f32),
        (100 - (gzip_total * 100 / plain_total)),
        format_size(brotli_total as f32),
        (100 - (brotli_total * 100 / plain_total)),
        items.len(),
        start.elapsed(),
        max - 4,
        max + 34,
    )
    .unwrap();
}

/// Format byte size in an human readable format
fn format_size(mut size: f32) -> String {
    for symbol in &[" B", "kB", "MB", "GB", "TB"] {
        if size < 1000. {
            return format!("{:.1}{}", size, symbol);
        } else {
            size /= 1024.;
        }
    }
    format!("{:.1}TB", size)
}
