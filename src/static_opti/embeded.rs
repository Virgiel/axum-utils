use std::{
    io::{BufWriter, Write},
    path::Path,
};

use crate::static_opti::worker::compress_dir;

/// Generates code to load a static file directory
/// Intended use in build scripts
pub fn codegen(static_dir: &str, file_name: &str) {
    let out = std::env::var_os("OUT_DIR").unwrap();
    let out_dir: &Path = out.as_ref();
    println!("cargo:rerun-if-changed={}", static_dir);

    // Generate static file
    compress_dir(static_dir).persist(Some(&out_dir.join(format!("{file_name}.static"))));

    // Generate rust file
    let mut rust_file =
        BufWriter::new(std::fs::File::create(out_dir.join(format!("{file_name}.rs"))).unwrap());
    writeln!(
        &mut rust_file,
        "use axum_utils::static_opti::FileService;\n\npub fn static_load() -> FileService<'static> {{\n\tFileService::from_raw(include_bytes!(\"{file_name}.static\"))\n}}"
    )
    .unwrap();
    rust_file.into_inner().unwrap();
}
