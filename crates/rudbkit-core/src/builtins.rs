//! The built-in driver definitions of both applications, read from the
//! repository's `drivers.yml`.
//!
//! What a product and its usual JDBC driver are — the name, the driver's
//! class and Maven coordinate, the shape of its URL, its port, the dialect id
//! that `rudbman-sql` and the bridges know it by, and its icon — is written
//! there once, with the keys a dialect profile's `driver` section uses. Each
//! application's list says which of them it offers, in its picker's order,
//! under which id, and with what else its definitions carry: rudbgen's
//! connection properties, its custom queries and whether a product asks for
//! credentials at all.
//!
//! The file is compiled in; [`builtins`] reads it the first time it is asked.
//! This crate's tests read every entry, so a file that does not parse, or an
//! entry naming a product the file does not have, fails them rather than an
//! application.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::Deserialize;

/// The dialect id of a product the SQL layer has no rules of its own for.
pub const GENERIC_DIALECT: &str = "generic";

/// The file, as the repository has it.
const SOURCE: &str = include_str!("../../../drivers.yml");

/// An application with a list of built-ins in `drivers.yml`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum App {
    /// rudbman.
    Rudbman,
    /// rudbgen.
    Rudbgen,
}

/// One built-in driver definition of an application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Builtin {
    /// The id the application's `drivers.json` keys the definition by.
    pub id: String,
    /// The name the driver picker shows.
    pub name: String,
    /// The driver's `java.sql.Driver` class.
    pub class: String,
    /// The Maven coordinate the downloader fetches, `group:artifact:version`.
    pub maven: String,
    /// The connection URL, with `{host}`, `{port}` and one of
    /// [`CATALOG_PLACEHOLDERS`](crate::url::CATALOG_PLACEHOLDERS) as holes.
    pub url_template: String,
    /// The port the server listens on unless told otherwise; `None` for a
    /// product that is a file rather than a service.
    pub default_port: Option<u16>,
    /// The dialect id, as `drivers.json` spells it.
    pub dialect: String,
    /// The mark the application draws beside it.
    pub icon: String,
    /// Whether the product asks for no credentials (rudbgen).
    pub no_auth: bool,
    /// Connection properties every session of it is given (rudbgen).
    pub props: BTreeMap<String, String>,
    /// The custom queries the definition starts with (rudbgen).
    pub queries: Queries,
}

/// The custom queries a built-in starts with; one left out is no statement.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Queries {
    /// Replacement for the driver's table list.
    #[serde(default)]
    pub tables: Option<Query>,
    /// Replacement for the driver's column list.
    #[serde(default)]
    pub columns: Option<Query>,
    /// Table comments the driver leaves blank.
    #[serde(default)]
    pub table_comments: Option<Query>,
    /// Column comments the driver leaves blank.
    #[serde(default)]
    pub column_comments: Option<Query>,
}

impl Queries {
    /// Whether there is no statement at all.
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

/// One custom query: its statement, and whether it is sent.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Query {
    /// Whether the statement is sent. A statement shipped switched off is one
    /// the bridge answers better itself, kept for a user who needs it.
    pub enabled: bool,
    /// The statement, with the `${catalog}`, `${schema}` and `${table}` holes.
    pub sql: String,
}

/// The built-ins of `app`, in the order its driver picker shows them.
///
/// # Panics
///
/// When the compiled-in file does not parse or names a product it does not
/// have, which this crate's tests rule out.
pub fn builtins(app: App) -> Vec<Builtin> {
    let lists = parsed().unwrap_or_else(|error| panic!("drivers.yml: {error}"));
    match app {
        App::Rudbman => lists.rudbman.clone(),
        App::Rudbgen => lists.rudbgen.clone(),
    }
}

/// Both applications' lists, resolved.
struct Lists {
    rudbman: Vec<Builtin>,
    rudbgen: Vec<Builtin>,
}

/// [`SOURCE`], read once.
fn parsed() -> Result<&'static Lists, &'static str> {
    static LISTS: OnceLock<Result<Lists, String>> = OnceLock::new();
    LISTS
        .get_or_init(|| parse(SOURCE))
        .as_ref()
        .map_err(String::as_str)
}

/// The file's shape.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    products: BTreeMap<String, ProductSpec>,
    rudbman: Vec<Entry>,
    rudbgen: Vec<Entry>,
}

/// A product, with a profile `driver` section's keys and its dialect.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProductSpec {
    name: String,
    class: String,
    maven: String,
    url_template: String,
    #[serde(default)]
    default_port: Option<u16>,
    dialect: String,
    icon: String,
}

/// One entry of an application's list.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    product: String,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    no_auth: bool,
    #[serde(default)]
    props: BTreeMap<String, String>,
    #[serde(default)]
    queries: Queries,
}

/// Reads `text` as the file and resolves each list's products.
fn parse(text: &str) -> Result<Lists, String> {
    let file: File = serde_norway::from_str(text).map_err(|error| error.to_string())?;
    let resolve = |entries: Vec<Entry>| -> Result<Vec<Builtin>, String> {
        entries
            .into_iter()
            .map(|entry| {
                let product = file
                    .products
                    .get(&entry.product)
                    .ok_or_else(|| format!("no product `{}`", entry.product))?;
                Ok(Builtin {
                    id: entry.id.unwrap_or_else(|| entry.product.clone()),
                    name: entry.name.unwrap_or_else(|| product.name.clone()),
                    class: product.class.clone(),
                    maven: product.maven.clone(),
                    url_template: product.url_template.clone(),
                    default_port: product.default_port,
                    dialect: product.dialect.clone(),
                    icon: product.icon.clone(),
                    no_auth: entry.no_auth,
                    props: entry.props,
                    queries: entry.queries,
                })
            })
            .collect()
    };
    Ok(Lists {
        rudbman: resolve(file.rudbman)?,
        rudbgen: resolve(file.rudbgen)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::url::{CATALOG_PLACEHOLDERS, placeholders_of};

    fn every() -> Vec<Builtin> {
        let mut all = builtins(App::Rudbman);
        all.extend(builtins(App::Rudbgen));
        all
    }

    #[test]
    fn the_file_parses() {
        if let Err(error) = parsed() {
            panic!("drivers.yml: {error}");
        }
    }

    #[test]
    fn a_misspelt_key_or_product_is_an_error() {
        let product = "products:\n  p:\n    name: P\n    class: a.B\n    maven: a:b:1\n    url_template: \"jdbc:p:{file}\"\n    dialect: generic\n    icon: p\n";
        assert!(parse(&format!("{product}rudbman:\n  - product: p\nrudbgen: []\n")).is_ok());
        assert!(parse(&format!("{product}rudbman:\n  - product: q\nrudbgen: []\n")).is_err());
        assert!(
            parse(&format!(
                "{product}rudbman:\n  - product: p\n    prop: x\nrudbgen: []\n"
            ))
            .is_err()
        );
    }

    /// Every template's holes are ones a connection editor fills, a port is
    /// known exactly where the template has one, and one catalog field names
    /// what is connected to.
    #[test]
    fn templates_use_the_editors_holes() {
        for builtin in every() {
            let holes = placeholders_of(&builtin.url_template);
            for hole in &holes {
                assert!(
                    hole == "host"
                        || hole == "port"
                        || CATALOG_PLACEHOLDERS.contains(&hole.as_str()),
                    "{}: unknown hole {hole}",
                    builtin.id
                );
            }
            assert_eq!(
                holes.iter().any(|hole| hole == "port"),
                builtin.default_port.is_some(),
                "{}",
                builtin.id
            );
            assert_eq!(
                holes
                    .iter()
                    .filter(|hole| CATALOG_PLACEHOLDERS.contains(&hole.as_str()))
                    .count(),
                1,
                "{}",
                builtin.id
            );
            assert!(builtin.url_template.starts_with("jdbc:"), "{}", builtin.id);
        }
    }

    /// A coordinate is a group, an artifact and a version, and a driver has
    /// one version: both applications download the same one, for a built-in
    /// and for a shipped profile that uses the same driver.
    #[test]
    fn coordinates_are_complete_and_one_per_artifact() {
        let mut coordinates: Vec<(String, String)> = every()
            .into_iter()
            .map(|builtin| (builtin.id, builtin.maven))
            .collect();
        for file in crate::dialects::SHIPPED {
            let Some(id) = file.name.strip_suffix(".yml") else {
                continue;
            };
            let text = std::str::from_utf8(file.contents).expect("UTF-8");
            let profile = crate::dialects::parse::<serde::de::IgnoredAny>(id, text)
                .unwrap_or_else(|error| panic!("{error}"));
            if let Some(maven) = profile.driver.and_then(|driver| driver.maven) {
                coordinates.push((id.to_string(), maven));
            }
        }
        let mut versions: BTreeMap<String, String> = BTreeMap::new();
        for (id, maven) in coordinates {
            let parts: Vec<&str> = maven.split(':').collect();
            assert_eq!(parts.len(), 3, "{id}: {maven}");
            assert!(parts.iter().all(|part| !part.is_empty()), "{id}");
            let artifact = format!("{}:{}", parts[0], parts[1]);
            let version = versions
                .entry(artifact.clone())
                .or_insert_with(|| parts[2].to_string());
            assert_eq!(version, parts[2], "{id}: {artifact} in two versions");
        }
    }

    /// Within one application, no two definitions share an id or a name.
    #[test]
    fn ids_and_names_are_unique_per_application() {
        for app in [App::Rudbman, App::Rudbgen] {
            let list = builtins(app);
            for key in [|b: &Builtin| b.id.clone(), |b: &Builtin| b.name.clone()] {
                let mut keys: Vec<String> = list.iter().map(key).collect();
                keys.sort_unstable();
                let len = keys.len();
                keys.dedup();
                assert_eq!(keys.len(), len, "{app:?}");
            }
        }
    }

    /// Every dialect a built-in names is one a chain of profile bases can end
    /// in, and every product is offered by an application.
    #[test]
    fn dialects_are_built_in_and_products_are_used() {
        for builtin in every() {
            assert_eq!(
                crate::dialects::built_in(&builtin.dialect),
                Some(builtin.dialect.as_str()),
                "{}",
                builtin.id
            );
        }
        let file: File = serde_norway::from_str(SOURCE).expect("parses");
        for key in file.products.keys() {
            assert!(
                file.rudbman
                    .iter()
                    .chain(&file.rudbgen)
                    .any(|entry| &entry.product == key),
                "{key} is offered by neither application"
            );
        }
    }

    /// rudbman's definitions have nowhere to keep rudbgen's extra fields, so
    /// one written in its list would be lost without a word.
    #[test]
    fn rudbmans_entries_carry_only_what_it_reads() {
        for builtin in builtins(App::Rudbman) {
            assert!(!builtin.no_auth, "{}", builtin.id);
            assert!(builtin.props.is_empty(), "{}", builtin.id);
            assert!(builtin.queries.is_empty(), "{}", builtin.id);
        }
    }

    /// An anchor in the file reaches both entries that name it.
    #[test]
    fn h2s_table_query_reaches_both_of_rudbgens_h2_entries() {
        let list = builtins(App::Rudbgen);
        for id in ["h2-embedded", "h2-server"] {
            let h2 = list.iter().find(|b| b.id == id).expect(id);
            let tables = h2.queries.tables.as_ref().expect("a table query");
            assert!(tables.enabled, "{id}");
            assert!(tables.sql.contains("BASE TABLE"), "{id}");
        }
    }
}
