use std::{fs::File, io::Write, net::SocketAddr, path::PathBuf, time::Instant};

use axum::{
    Router,
    body::Body,
    extract::Path,
    http::{HeaderMap, HeaderValue, Response, StatusCode, header},
    middleware,
    routing::get,
};
use clap::{Parser, Subcommand};
use mimalloc::MiMalloc;

use axum_utils::{
    shutdown_signal, static_files,
    static_opti::{FileService, worker::optimize},
};
use tokio::net::TcpListener;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[derive(Debug, Subcommand)]
enum Cmd {
    Opti {
        /// The directory containing static files
        in_dir: PathBuf,
        /// The path where to put the output
        out: Option<PathBuf>,
    },
    Serve {
        // The static optimized image
        image: PathBuf,
    },
}

/// Prepare static files for efficient serving
#[derive(Parser, Debug)]
#[clap(long_about = None)]
struct Args {
    #[clap(subcommand)]
    cmd: Cmd,
}

#[tokio::main]
async fn main() {
    let start = Instant::now();
    let args = Args::parse();

    match args.cmd {
        Cmd::Opti { in_dir, out } => {
            let (_, items) = optimize(&in_dir, out.as_deref());

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
        Cmd::Serve { image } => {
            let state: &'static FileService =
                Box::leak(Box::new(FileService::leak(File::open(image).unwrap())));

            let app = Router::new()
                .route("/", get(async move |h| route_files(&h, "/", &state)))
                .route(
                    "/{*path}",
                    get(async move |h, Path(p): Path<String>| route_files(&h, &p, state)),
                )
                .layer(middleware::from_fn(axum_utils::redirect_https_middle_ware))
                .into_make_service_with_connect_info::<SocketAddr>();
            let addr = "0.0.0.0:8080";
            let listener = TcpListener::bind(addr).await.unwrap();
            println!("Server listening on http://{addr}");
            axum::serve(listener, app)
                .with_graceful_shutdown(shutdown_signal())
                .await
                .unwrap();
        }
    }
}

fn route_files(h: &HeaderMap, path: &str, service: &'static FileService) -> Response<Body> {
    let mut response = static_files(h, path, service);
    println!("{path} {}", response.status());
    match response.status() {
        StatusCode::NOT_FOUND => {
            // Fallback
            response = static_files(h, "200.html", service);
        }
        StatusCode::OK | StatusCode::NOT_MODIFIED if path.starts_with("_app/immutable") => {
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("public,max-age=31536000,immutable"),
            );
        }
        _ => {}
    }
    response
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
