//! Compiles in the dialect profiles the applications ship: every `*.yml` and
//! `*.groovy` of the repository's `dialects/` folder (rudbman's
//! `docs/dialect-profiles.md`, §12). `dialects::SHIPPED` includes the list
//! this writes.

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("set by cargo"));
    let dir = manifest.join("..").join("..").join("dialects");
    // A directory is watched as a whole: a file added, changed or removed in
    // it builds the list again.
    println!("cargo::rerun-if-changed={}", dir.display());

    let mut files: Vec<(String, PathBuf)> = Vec::new();
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let shipped = name.ends_with(".yml") || name.ends_with(".groovy");
            if shipped && path.is_file() {
                let path = path.canonicalize().expect("a file just listed");
                files.push((name.to_string(), path));
            }
        }
    }
    files.sort();

    let mut list = String::from("&[\n");
    for (name, path) in &files {
        let path = path.to_str().expect("a UTF-8 path to the repository");
        writeln!(
            list,
            "    Shipped {{ name: {name:?}, contents: include_bytes!({path:?}) }},"
        )
        .expect("writing to a string");
    }
    list.push(']');
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("set by cargo"));
    fs::write(out.join("shipped_dialects.rs"), list).expect("writing to OUT_DIR");
}
