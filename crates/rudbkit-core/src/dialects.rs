//! Dialect profiles: the files rudbman and rudbgen both read from their
//! `<config>/dialects`, and the ones they ship there.
//!
//! The format is fixed in rudbman's `docs/dialect-profiles.md` (§4). A profile
//! names itself and the dialect it stands on (`base`), and has three parts:
//! an `sql` half that only rudbman's SQL layer reads, a `bridge` half that each
//! application's JDBC bridge reads as much of as it answers — rudbgen's its
//! names and comments — and a `driver` section, the driver definition the
//! profile brings. A file written for one application is read by the other.
//!
//! [`parse`] reads a file and checks every key it knows: the envelope, the
//! `bridge` half ([`bridge::BridgeSpec`]) and the driver section, each
//! unknown key an error with its line, since a typo silently ignored is a
//! setting silently lost. The `sql` half is the reader's to check: [`parse`]
//! takes its type, which rudbman spells key by key and rudbgen reads as
//! [`serde::de::IgnoredAny`].
//!
//! The rest is the directory ([`profile_files`], [`pending_beside`]), the
//! scripts the user has allowed to run (`allowed.json`: [`allow_in`]), and
//! the files the applications ship into it ([`SHIPPED`], [`sync_shipped`]).
//! The shipped profiles are the `dialects/` folder of this repository, so
//! both applications bring the same ones.

use std::fmt;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};

pub mod bridge;
mod files;

pub use files::{
    ALLOWED_FILE_NAME, Allowed, Listing, PENDING_SUFFIX, PROFILE_EXTENSION, RECORD_FILE_NAME,
    SCRIPT_EXTENSION, SHIPPED, Script, Shipped, Synced, allow_in, disallow_in, hash, listing,
    pending_beside, pending_path, profile_files, read_allowed, read_text, sync_shipped,
};

use bridge::BridgeSpec;

/// The version of the format this build reads and writes.
pub const API: u32 = 1;

/// The built-in dialects, as rudbman's SQL layer names them, each with the
/// other spellings it accepts: what a chain of `base`s ends in.
///
/// rudbman's tests hold this to its `Dialect::ALL` and each dialect's
/// aliases, so that a `base` one application reads is one the other does.
pub const BUILT_IN: &[(&str, &[&str])] = &[
    ("generic", &["sql", "ansi"]),
    ("h2", &[]),
    ("postgres", &["postgresql", "pgsql", "pg"]),
    ("mysql", &[]),
    ("mariadb", &[]),
    ("sqlite", &["sqlite3"]),
    ("oracle", &[]),
    ("mssql", &["sqlserver", "tsql"]),
    ("db2", &[]),
];

/// The built-in dialect `name` spells, by its name or an alias, ignoring
/// ASCII case and surrounding whitespace.
pub fn built_in(name: &str) -> Option<&'static str> {
    let name = name.trim();
    BUILT_IN
        .iter()
        .find(|(id, aliases)| {
            id.eq_ignore_ascii_case(name)
                || aliases.iter().any(|alias| alias.eq_ignore_ascii_case(name))
        })
        .map(|(id, _)| *id)
}

/// A profile file, read. `S` is the `sql` half as its reader spells it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    deny_unknown_fields,
    bound(serialize = "S: Serialize", deserialize = "S: Deserialize<'de>")
)]
pub struct ProfileFile<S> {
    /// The format's version, [`API`].
    pub api: u32,
    /// The name a picker shows.
    pub name: String,
    /// The profile or built-in dialect it stands on.
    pub base: String,
    /// Other names a driver's `dialect` may give it by.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    /// The `sql` half.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sql: Option<S>,
    /// The `bridge` half.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge: Option<BridgeSpec>,
    /// The driver definition the profile brings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver: Option<ProfileDriver>,
}

impl<S> ProfileFile<S> {
    /// A profile named `name` on `base`, saying nothing else.
    pub fn new(name: impl Into<String>, base: impl Into<String>) -> Self {
        Self {
            api: API,
            name: name.into(),
            base: base.into(),
            aliases: Vec::new(),
            sql: None,
            bridge: None,
            driver: None,
        }
    }

    /// The script `bridge.script` names, as the file spells it.
    pub fn script(&self) -> Option<&str> {
        self.bridge.as_ref()?.script.as_deref()
    }
}

/// A profile's `driver` section: what a driver definition of its product
/// starts as, so that the product reaches an application's driver manager
/// without a built-in definition in code.
///
/// The definition's id and `dialect` are the profile's id; the rest is here.
/// Each application makes its own definition of it, with what else its
/// definitions carry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileDriver {
    /// The definition's name, when it is not the profile's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The driver class.
    pub class: String,
    /// The Maven coordinate the downloader fetches, `group:artifact:version`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maven: Option<String>,
    /// The URL template, with the connection editor's `{holes}`.
    pub url_template: String,
    /// The port the connection editor fills in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_port: Option<u16>,
    /// The icon, an asset stem such as `mysql`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
}

impl ProfileDriver {
    /// The definition's name: the section's, or else `profile_name`.
    pub fn name_or<'a>(&'a self, profile_name: &'a str) -> &'a str {
        self.name.as_deref().unwrap_or(profile_name)
    }
}

/// Why a profile file could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// The profile's id.
    pub id: String,
    /// The line the error is on, from 1, where the parser knows it.
    pub line: Option<usize>,
    /// The column, from 1, with the line.
    pub column: Option<usize>,
    /// What is wrong.
    pub message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{PROFILE_EXTENSION}", self.id)?;
        if let Some(line) = self.line {
            write!(f, ":{line}")?;
            if let Some(column) = self.column {
                write!(f, ":{column}")?;
            }
        }
        write!(f, ": {}", self.message)
    }
}

impl std::error::Error for ParseError {}

/// Reads the profile `id` from `text`, its `sql` half as `S`.
///
/// # Errors
///
/// A [`ParseError`] for text that is not YAML, a key the format does not
/// have, a value of the wrong kind, a `bridge` value its key does not take,
/// or an `api` this build does not read. Whether the profile *loads* — its
/// base, its templates, its words — is the reading application's to say.
pub fn parse<S: DeserializeOwned>(id: &str, text: &str) -> Result<ProfileFile<S>, ParseError> {
    let error = |line: Option<usize>, column: Option<usize>, message: String| ParseError {
        id: id.to_string(),
        line,
        column,
        message,
    };
    let file: ProfileFile<S> = serde_norway::from_str(text).map_err(|e| {
        let location = e.location();
        error(
            location.as_ref().map(|at| at.line()),
            location.as_ref().map(|at| at.column()),
            e.to_string(),
        )
    })?;
    if file.api != API {
        return Err(error(
            None,
            None,
            format!(
                "api {} is not a version of the format this build reads, which is {API}",
                file.api
            ),
        ));
    }
    if let Some(Err((key, message))) = file.bridge.as_ref().map(BridgeSpec::check) {
        return Err(error(None, None, format!("{key}: {message}")));
    }
    Ok(file)
}

/// Writes `file` as YAML, every key it holds and none it does not.
pub fn to_yaml<S: Serialize>(file: &ProfileFile<S>) -> String {
    serde_norway::to_string(file).unwrap_or_else(|error| {
        // Every value of the format is a string, a number, a bool, a list or
        // a map of those.
        unreachable!("a profile always serializes: {error}")
    })
}

/// `Some(None)` for an explicit `null`, `None` for a key left out: for a
/// key whose `null` says something, as `deserialize_with` with
/// `#[serde(default)]`.
///
/// # Errors
///
/// Whatever the value's own deserialization fails with.
pub fn null_or<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

#[cfg(test)]
mod tests;
