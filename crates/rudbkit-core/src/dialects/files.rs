//! The profiles' directory: which files are profiles, what waits beside them,
//! the scripts the user has allowed, and the files the applications ship.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A profile file's extension.
pub const PROFILE_EXTENSION: &str = "yml";

/// What a script beside a profile is, when the profile names none.
pub const SCRIPT_EXTENSION: &str = "groovy";

/// Appended to a shipped file's name for its newer version, written beside a
/// file the user has changed.
pub const PENDING_SUFFIX: &str = ".new";

/// The record of the shipped files, in the profiles' directory.
pub const RECORD_FILE_NAME: &str = "shipped.json";

/// The scripts the user has allowed, in the profiles' directory (§6).
pub const ALLOWED_FILE_NAME: &str = "allowed.json";

/// The UTF-8 byte order mark an editor may have put in front of a file.
const UTF8_BOM: &[u8] = b"\xEF\xBB\xBF";

// --------------------------------------------------------------- the files

/// The `*.yml` files of `dir` by id, their stems, in id order.
///
/// # Errors
///
/// Fails when `dir` cannot be read; one that is not there is
/// [`io::ErrorKind::NotFound`], which holds no profiles.
pub fn profile_files(dir: &Path) -> io::Result<Vec<(String, PathBuf)>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some(PROFILE_EXTENSION) {
            continue;
        }
        let Some(id) = path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };
        if path.is_file() {
            files.push((id.to_string(), path.clone()));
        }
    }
    files.sort();
    Ok(files)
}

/// The `.new` files beside the profile `id` at `profile` and its script:
/// the one `script` names in `dir`, or `<id>.groovy` where it names none.
pub fn pending_beside(dir: &Path, profile: &Path, id: &str, script: Option<&str>) -> Vec<PathBuf> {
    let script = script
        .map(str::to_string)
        .unwrap_or_else(|| format!("{id}.{SCRIPT_EXTENSION}"));
    let mut pending = Vec::new();
    for file in [profile.to_path_buf(), dir.join(script)] {
        let candidate = pending_path(&file);
        if candidate.is_file() && !pending.contains(&candidate) {
            pending.push(candidate);
        }
    }
    pending
}

/// `<file>.new`.
pub fn pending_path(file: &Path) -> PathBuf {
    let mut name = file.as_os_str().to_os_string();
    name.push(PENDING_SUFFIX);
    PathBuf::from(name)
}

/// Every file of a directory with its size and time: what tells a reload
/// that nothing changed since the last.
pub type Listing = Vec<(PathBuf, u64, Option<std::time::SystemTime>)>;

/// The directory's [`Listing`], empty where it cannot be read.
pub fn listing(dir: &Path) -> Listing {
    let mut listing: Listing = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let meta = entry.metadata().ok()?;
            Some((entry.path(), meta.len(), meta.modified().ok()))
        })
        .collect();
    listing.sort();
    listing
}

/// A profile's or a script's text, without a byte order mark, with the
/// [`hash`] of the file as it is: what a script is allowed by.
///
/// # Errors
///
/// What to say of a file that cannot be read, or is not UTF-8.
pub fn read_text(path: &Path) -> std::result::Result<(String, String), String> {
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    let sha256 = hash(&bytes);
    String::from_utf8(strip_bom(&bytes).to_vec())
        .map(|text| (sha256, text))
        .map_err(|_| "the file is not UTF-8".to_string())
}

/// The SHA-256 of `bytes`, in lower-case hex.
pub fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn strip_bom(bytes: &[u8]) -> &[u8] {
    bytes.strip_prefix(UTF8_BOM).unwrap_or(bytes)
}

// ------------------------------------------------------------------- trust

/// A profile's script (§5), as it stands in the profiles' directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Script {
    /// Its name in the directory, as `bridge.script` gives it.
    pub name: String,
    /// The file.
    pub path: PathBuf,
    /// The SHA-256 of what the file holds, in lower-case hex: what
    /// `allowed.json` records of an allowed script.
    pub sha256: String,
    /// Whether sessions run it: the user has allowed this version of it, or
    /// the application wrote it as it is (§6, §12). Not allowed, the profile
    /// loads without it.
    pub allowed: bool,
}

/// `allowed.json`: each script the user has allowed, by its name in the
/// directory, with the SHA-256 of the version allowed (§6).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Allowed {
    #[serde(default)]
    scripts: BTreeMap<String, String>,
}

impl Allowed {
    /// Whether the script `name` is allowed as the version whose hash is
    /// `sha256`.
    pub fn allows(&self, name: &str, sha256: &str) -> bool {
        self.scripts
            .get(name)
            .is_some_and(|allowed| allowed == sha256)
    }

    /// The hash of the version of `name` allowed, if one is.
    pub fn version_of(&self, name: &str) -> Option<&str> {
        self.scripts.get(name).map(String::as_str)
    }
}

/// `dir`'s `allowed.json`; none allows nothing.
///
/// # Errors
///
/// Fails when the file cannot be read or is not the list.
pub fn read_allowed(dir: &Path) -> Result<Allowed> {
    let path = dir.join(ALLOWED_FILE_NAME);
    match read_optional(&path)? {
        None => Ok(Allowed::default()),
        Some(bytes) => serde_json::from_slice(strip_bom(&bytes))
            .with_context(|| format!("failed to parse {}", path.display())),
    }
}

fn write_allowed(dir: &Path, allowed: &Allowed) -> Result<()> {
    let json = serde_json::to_vec_pretty(allowed).context("failed to serialize the allow list")?;
    write_atomic(&dir.join(ALLOWED_FILE_NAME), &json)
}

/// Allows `script` as it was read — by the hash it had then, so that a file
/// changed since is still not run — in the profiles' directory `dir`.
///
/// # Errors
///
/// Fails when `allowed.json` cannot be read or written.
pub fn allow_in(dir: &Path, script: &Script) -> Result<()> {
    let mut allowed = read_allowed(dir)?;
    allowed
        .scripts
        .insert(script.name.clone(), script.sha256.clone());
    write_allowed(dir, &allowed)
}

/// Takes the script `name` off the allow list of `dir`: sessions open
/// without it until it is allowed again.
///
/// # Errors
///
/// Fails when `allowed.json` cannot be read or written.
pub fn disallow_in(dir: &Path, name: &str) -> Result<()> {
    let mut allowed = read_allowed(dir)?;
    if allowed.scripts.remove(name).is_some() {
        write_allowed(dir, &allowed)?;
    }
    Ok(())
}

// ----------------------------------------------------------- shipped files

/// A file an application ships into `<config>/dialects`.
#[derive(Debug, Clone, Copy)]
pub struct Shipped {
    /// Its name in the directory, `<id>.yml` or a script beside one.
    pub name: &'static str,
    /// What the application writes.
    pub contents: &'static [u8],
}

/// The files of this repository's `dialects/` folder, compiled in by the
/// build script: the profiles both applications ship.
pub const SHIPPED: &[Shipped] = include!(concat!(env!("OUT_DIR"), "/shipped_dialects.rs"));

/// `shipped.json`: for each shipped file, the hash of the version last
/// offered to the directory.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Record {
    #[serde(default)]
    files: BTreeMap<String, String>,
}

/// What [`sync_shipped`] did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Synced {
    /// Files written where there was none.
    pub written: Vec<String>,
    /// Files the user had not changed, replaced by a newer version.
    pub replaced: Vec<String>,
    /// Files the user has changed, whose newer version was written beside
    /// them as `<file>.new`.
    pub beside: Vec<String>,
}

/// Brings `shipped` into `dir` by the rules of §12.
///
/// For each file, `shipped.json` holds the hash of the version last offered:
///
/// 1. A file never offered is written. If the directory already holds a file
///    of that name — the user's own — it is left alone and the shipped one is
///    written beside it.
/// 2. A file offered and since deleted stays deleted.
/// 3. A file as it was offered is replaced by a newer version.
/// 4. A file the user has changed is left as it is, and the newer version is
///    written beside it as `<file>.new`.
///
/// A `.new` is removed once the file beside it is the shipped version or the
/// `.new` itself — the user has taken it.
///
/// A script the application writes is allowed by its hash as it is written
/// (§12): one written where there was none, and the newer version of one the
/// user had allowed as it was. A script the user has turned off stays off, and
/// one the user has changed is the user's, which asks (§6).
///
/// # Errors
///
/// Fails when the directory cannot be read or written, or `shipped.json` or
/// `allowed.json` cannot be read; nothing is decided from a record that
/// could not be read.
pub fn sync_shipped(dir: &Path, shipped: &[Shipped]) -> Result<Synced> {
    let record_path = dir.join(RECORD_FILE_NAME);
    let mut record: Record = match read_optional(&record_path)? {
        None => Record::default(),
        Some(bytes) => serde_json::from_slice(strip_bom(&bytes))
            .with_context(|| format!("failed to parse {}", record_path.display()))?,
    };
    let mut allowed = read_allowed(dir)?;
    let mut synced = Synced::default();
    let mut changed = false;
    let mut allow_changed = false;
    for file in shipped {
        let path = dir.join(file.name);
        let ours = hash(file.contents);
        let mut on_disk = read_optional(&path)?;
        let theirs = on_disk.as_deref().map(hash);
        let offered = record.files.get(file.name);
        let name = file.name.to_string();
        if offered == Some(&ours) {
            // Nothing newer than what the directory was offered.
        } else {
            match (offered, theirs) {
                (_, Some(theirs)) if theirs == ours => {}
                (None, None) => {
                    write_atomic(&path, file.contents)?;
                    on_disk = Some(file.contents.to_vec());
                    if is_script(file.name) {
                        allowed.scripts.insert(name.clone(), ours.clone());
                        allow_changed = true;
                    }
                    synced.written.push(name);
                }
                (Some(_), None) => {}
                (Some(offered), Some(theirs)) if theirs == *offered => {
                    write_atomic(&path, file.contents)?;
                    on_disk = Some(file.contents.to_vec());
                    if is_script(file.name) && allowed.scripts.get(&name) == Some(offered) {
                        allowed.scripts.insert(name.clone(), ours.clone());
                        allow_changed = true;
                    }
                    synced.replaced.push(name);
                }
                (_, Some(_)) => {
                    write_atomic(&pending_path(&path), file.contents)?;
                    synced.beside.push(name);
                }
            }
            record.files.insert(file.name.to_string(), ours.clone());
            changed = true;
        }
        if let Some(on_disk) = on_disk {
            tidy_pending(&path, &on_disk, file.contents)?;
        }
    }
    if allow_changed {
        write_allowed(dir, &allowed)?;
    }
    if changed {
        let json = serde_json::to_vec_pretty(&record).context("failed to serialize the record")?;
        write_atomic(&record_path, &json)?;
    }
    Ok(synced)
}

/// Whether a shipped file is a script rather than a profile.
fn is_script(name: &str) -> bool {
    !name.ends_with(&format!(".{PROFILE_EXTENSION}"))
}

/// Removes `<path>.new` once `path` holds the shipped version or the `.new`
/// itself.
fn tidy_pending(path: &Path, on_disk: &[u8], shipped: &[u8]) -> Result<()> {
    let pending = pending_path(path);
    let Some(waiting) = read_optional(&pending)? else {
        return Ok(());
    };
    if on_disk == shipped || on_disk == waiting.as_slice() {
        fs::remove_file(&pending)
            .with_context(|| format!("failed to remove {}", pending.display()))?;
    }
    Ok(())
}

/// A file's contents, or `None` when there is no file.
fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(data) => Ok(Some(data)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("failed to read {}", path.display())),
    }
}

/// Writes `contents` to `path` through a temporary sibling renamed over it,
/// so that a crash mid-write leaves the old file or the new one, never half
/// of either. Missing parent directories are created first.
fn write_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }
    let (temp, mut file) = loop {
        let temp = temp_sibling(path);
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
        {
            Ok(file) => break (temp, file),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("failed to create {}", temp.display()));
            }
        }
    };
    let written = file.write_all(contents).and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = written {
        let _ = fs::remove_file(&temp);
        return Err(error).with_context(|| format!("failed to write {}", temp.display()));
    }
    if let Err(error) = fs::rename(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(error).with_context(|| format!("failed to replace {}", path.display()));
    }
    Ok(())
}

/// A name beside `path` no other write of this process uses.
fn temp_sibling(path: &Path) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut name = path
        .file_name()
        .map(OsString::from)
        .unwrap_or_else(|| OsString::from("dialects"));
    name.push(format!(".{}.{seq}.tmp", std::process::id()));
    path.with_file_name(name)
}
