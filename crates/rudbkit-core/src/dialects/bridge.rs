//! A profile's `bridge` half: what the JDBC bridges answer from it (rudbman's
//! `docs/dialect-profiles.md`, §4.3). rudbman's bridge reads every key;
//! rudbgen's reads `detect`, `catalog_is_schema` and `comments`.
//!
//! Every key is one method of rudbman's bridge's `meta/Vendor.java`, and each
//! bridge's `ProfileVendor` reads them as this module writes them: the JSON of
//! [`BridgeSpec`], with a key left out absent and a `null` sent as `null`.
//! Nothing here runs a query; what is checked is the spelling — every key, every
//! value of a list, every template hole — so that a profile with a mistake in
//! it fails to load with its key named, rather than reaching a server.

use serde::{Deserialize, Serialize};

use super::null_or;

/// The `bridge` half of a profile.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeSpec {
    /// Words, any of which in the server's product name (lower-cased) makes a
    /// connection opened without a profile this one's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detect: Option<Vec<String>>,

    // Names and catalogs.
    /// Whether the JDBC catalog is the namespace a table sits in, as MySQL's database is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalog_is_schema: Option<bool>,
    /// Whether a result column's catalog is one the driver's own metadata calls recognize.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_catalogs_resolve: Option<bool>,
    /// Whether a session sees only the catalog it connected to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sees_only_its_catalog: Option<bool>,
    /// Whether a procedure's name carries a group number (`name;1`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub numbers_procedures: Option<bool>,

    // Catalog queries.
    /// Queries listing sequences, tried in order; the first the server
    /// answers is used. Their columns are read by label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequences: Option<Vec<String>>,
    /// The trigger catalog query, or `null` for a product that keeps none.
    #[serde(
        default,
        deserialize_with = "null_or",
        skip_serializing_if = "Option::is_none"
    )]
    pub triggers: Option<Option<TriggerQuery>>,
    /// Comments the driver leaves out, read from the catalog.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comments: Option<CommentsSpec>,
    /// The server's own text of each kind of object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub texts: Option<TextsSpec>,

    // DDL reconstruction.
    /// Whether a statement's object name includes its catalog.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qualifies_by_catalog: Option<bool>,
    /// Whether a foreign key can be `DEFERRABLE`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub defers_keys: Option<bool>,
    /// Whether comments are part of the `CREATE`, as `COMMENT=` and `COMMENT '…'`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comments_inline: Option<bool>,
    /// Whether comments are written as `COMMENT ON` after the `CREATE`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comments_on: Option<bool>,
    /// Whether a computed column is written without a type of its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub computed_has_no_type: Option<bool>,
    /// Whether an auto-increment column drawing on a sequence is a serial pseudo-type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial_columns: Option<bool>,
    /// The clause an auto-increment column is written with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_clause: Option<String>,
    /// Whether `NOT NULL` comes before `DEFAULT` and the identity clause.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_null_first: Option<bool>,
    /// Whether the server makes an index for every foreign key that has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub indexes_foreign_keys: Option<bool>,
    /// Whether a `CREATE` names its object without the database.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creates_without_catalog: Option<bool>,
    /// Whether `CREATE SEQUENCE` takes an `AS` type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub types_sequences: Option<bool>,
    /// Whether a sequence cache of one is written `NO CACHE`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_of_one_is_no_cache: Option<bool>,
    /// What a DDL script starts with, terminated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script_prologue: Option<Vec<String>>,
    /// What undoes `script_prologue`, terminated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script_epilogue: Option<Vec<String>>,
    /// What a data script runs before its rows, terminated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_prologue: Option<Vec<String>>,
    /// What undoes `data_prologue`, terminated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_epilogue: Option<Vec<String>>,

    // Literals and scripts.
    /// Whether a `BIT` wider than one bit holds a number, written `b'1010'`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bits_are_numbers: Option<bool>,
    /// Whether a truth value is written `1`/`0`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub booleans_are_numbers: Option<bool>,
    /// Whether a character literal is written `N'…'`. Given, it replaces the base's spelling of string literals with the standard quoting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub national_strings: Option<NationalStrings>,
    /// Holes: `hex`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hex_literal: Option<String>,
    /// Whose command-line client a script is written for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script_client: Option<ScriptClient>,
    /// Whether `DROP` takes `IF EXISTS`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drops_if_exists: Option<bool>,
    /// What follows a `DROP TABLE` to take the foreign keys that point at it along.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drop_table_cascade: Option<String>,
    /// Holes: `table`, `key`. `null` where no such step is needed.
    #[serde(
        default,
        deserialize_with = "null_or",
        skip_serializing_if = "Option::is_none"
    )]
    pub drop_foreign_key: Option<Option<String>>,
    /// Whether an `INSERT` takes several rows in one `VALUES`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multi_row_values: Option<bool>,
    /// How a row is written over one that may already be there.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upsert: Option<UpsertSpec>,

    // Backup.
    /// Holes: `catalog`, `schema`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_prologue: Option<Vec<BackupLine>>,
    /// Holes: `catalog`, `schema`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_epilogue: Option<Vec<BackupLine>>,
    /// Holes: `table`. `null` for nothing around a table's rows.
    #[serde(
        default,
        deserialize_with = "null_or",
        skip_serializing_if = "Option::is_none"
    )]
    pub identity_insert: Option<Option<IdentityInsert>>,
    /// Whether an `INSERT` needs `OVERRIDING SYSTEM VALUE` for a `GENERATED ALWAYS` identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overrides_system_value: Option<bool>,

    /// The Groovy script beside the profile (§5), named relative to the
    /// profiles' folder and inside it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script: Option<String>,
}

/// The trigger catalog query: nine columns — catalog, schema, name, table,
/// timing, event, level, enabled, comment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TriggerQuery {
    /// The statement, ending where `AND column = ?` may follow.
    pub sql: String,
    /// The column each filter compares.
    #[serde(default)]
    pub filters: TriggerFilters,
    /// What follows `ORDER BY`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order_by: Option<String>,
}

/// The columns a trigger query is filtered on.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TriggerFilters {
    /// The column the requested catalog is compared with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalog: Option<String>,
    /// The column the requested schema is compared with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    /// The column the requested trigger name is compared with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Comments the driver leaves out.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommentsSpec {
    /// Whether the driver leaves out comments the server holds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hides_comments: Option<bool>,
    /// Whether `getTables` reports a view's type in its `REMARKS`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub marks_views_in_remarks: Option<bool>,
    /// How a pattern filter's `LIKE` names its escape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub escape: Option<LikeEscape>,
    /// Owner, table, comment. `null` for none.
    #[serde(
        default,
        deserialize_with = "null_or",
        skip_serializing_if = "Option::is_none"
    )]
    pub tables: Option<Option<CommentQuery>>,
    /// Owner, table, column, comment. `null` for none.
    #[serde(
        default,
        deserialize_with = "null_or",
        skip_serializing_if = "Option::is_none"
    )]
    pub columns: Option<Option<CommentQuery>>,
}

/// `ESCAPE '\'` after a `LIKE`, or nothing — for a product whose string
/// literals read the backslash as an escape of their own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LikeEscape {
    /// `ESCAPE '\'`.
    Ansi,
    /// No escape clause.
    None,
}

/// A comment query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommentQuery {
    /// The statement, ending where `AND column = ?` may follow.
    pub sql: String,
    /// The column each filter compares.
    #[serde(default)]
    pub filters: CommentFilters,
}

/// The columns a comment query is filtered on.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommentFilters {
    /// The column the requested catalog is compared with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalog: Option<String>,
    /// The column the requested schema is compared with, by pattern where the request has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    /// The column the requested table is compared with, by pattern where the request has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub table: Option<String>,
    /// Columns only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<String>,
}

/// The server's own text of each kind of object; `null` for none.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TextsSpec {
    /// A table's `CREATE`, whole; given, the base's own way of reading it is not used.
    #[serde(
        default,
        deserialize_with = "null_or",
        skip_serializing_if = "Option::is_none"
    )]
    pub table: Option<Option<TextQuery>>,
    /// A view's.
    #[serde(
        default,
        deserialize_with = "null_or",
        skip_serializing_if = "Option::is_none"
    )]
    pub view: Option<Option<TextQuery>>,
    /// A routine's.
    #[serde(
        default,
        deserialize_with = "null_or",
        skip_serializing_if = "Option::is_none"
    )]
    pub routine: Option<Option<TextQuery>>,
    /// A trigger's.
    #[serde(
        default,
        deserialize_with = "null_or",
        skip_serializing_if = "Option::is_none"
    )]
    pub trigger: Option<Option<TextQuery>>,
    /// A sequence's.
    #[serde(
        default,
        deserialize_with = "null_or",
        skip_serializing_if = "Option::is_none"
    )]
    pub sequence: Option<Option<TextQuery>>,
}

/// A query answering one object's text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TextQuery {
    /// The statement. Holes: `qualified`, the object's name as a statement
    /// writes it.
    pub sql: String,
    /// What the statement's `?` are, in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub binds: Vec<Bind>,
    /// The column the text is in, from 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
}

/// A value bound to a text query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Bind {
    /// The object's catalog.
    Catalog,
    /// The object's schema.
    Schema,
    /// The object's name.
    Name,
}

/// Whether a character literal is written `N'…'`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NationalStrings {
    /// Every character literal.
    Always,
    /// A literal of a national character type (`NCHAR`, `NVARCHAR`, `NCLOB`).
    NationalTypes,
    /// None: the standard quoting.
    Never,
}

/// Whose command-line client a script is written for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScriptClient {
    /// Nothing to mark: a body is one token, or the client reads it whole.
    Plain,
    /// `mysql`: `DELIMITER ;;` around a body.
    Mysql,
    /// SQL*Plus and SQLcl: a `/` on its own line after PL/SQL.
    Sqlplus,
    /// `sqlcmd`: `GO` around a statement alone in its batch.
    Sqlcmd,
    /// Db2's command line processor: its `--#SET TERMINATOR`.
    Clp,
}

/// How a row is written over one that may already be there: a kind's name,
/// or `{ merge: { ... } }` for the standard `MERGE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "UpsertRepr", into = "UpsertRepr")]
pub enum UpsertSpec {
    /// No upsert: the product has none.
    None,
    /// `INSERT … ON CONFLICT … DO UPDATE`.
    OnConflict,
    /// `INSERT … ON DUPLICATE KEY UPDATE`.
    OnDuplicateKey,
    /// H2's `MERGE INTO … KEY (…)`.
    H2Merge,
    /// The standard `MERGE`.
    Merge(MergeSpec),
}

/// [`UpsertSpec`] as it is written. The YAML reader takes a variant with
/// data only as a tag (`!merge`), which the format does not use; a name or a
/// one-key map reads either way.
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(untagged)]
enum UpsertRepr {
    Kind(UpsertKind),
    Merge { merge: MergeSpec },
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum UpsertKind {
    None,
    OnConflict,
    OnDuplicateKey,
    H2Merge,
}

impl From<UpsertRepr> for UpsertSpec {
    fn from(repr: UpsertRepr) -> Self {
        match repr {
            UpsertRepr::Kind(UpsertKind::None) => Self::None,
            UpsertRepr::Kind(UpsertKind::OnConflict) => Self::OnConflict,
            UpsertRepr::Kind(UpsertKind::OnDuplicateKey) => Self::OnDuplicateKey,
            UpsertRepr::Kind(UpsertKind::H2Merge) => Self::H2Merge,
            UpsertRepr::Merge { merge } => Self::Merge(merge),
        }
    }
}

impl From<UpsertSpec> for UpsertRepr {
    fn from(spec: UpsertSpec) -> Self {
        match spec {
            UpsertSpec::None => Self::Kind(UpsertKind::None),
            UpsertSpec::OnConflict => Self::Kind(UpsertKind::OnConflict),
            UpsertSpec::OnDuplicateKey => Self::Kind(UpsertKind::OnDuplicateKey),
            UpsertSpec::H2Merge => Self::Kind(UpsertKind::H2Merge),
            UpsertSpec::Merge(merge) => Self::Merge { merge },
        }
    }
}

/// The standard `MERGE`'s two variations.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MergeSpec {
    /// Its source rows selected `FROM DUAL`.
    #[serde(default)]
    pub from_dual: bool,
    /// Ended with a `;` of its own, as SQL Server's must be.
    #[serde(default)]
    pub terminated: bool,
}

/// A line of a backup's prologue or epilogue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BackupLine {
    /// Always written.
    Always(String),
    /// Written only under `when`.
    When(BackupWhen),
}

/// A backup line written only when the backup has what it is about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupWhen {
    /// The line.
    pub sql: String,
    /// When it is written.
    pub when: Condition,
}

/// What a backup line is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Condition {
    /// The script creates routines.
    Routines,
    /// The script creates views, routines or triggers. Epilogue only.
    Code,
}

/// The statements around a table's rows that let its identity take them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityInsert {
    /// Written before the rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<String>,
    /// Written after them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
}

impl BridgeSpec {
    /// The first template hole a key does not take, or another value the
    /// format refuses, as `(key, message)`.
    pub fn check(&self) -> Result<(), (String, String)> {
        let template = |key: &str, text: &str, takes: &[&str]| {
            check_holes(text, takes).map_err(|message| (key.to_string(), message))
        };
        if let Some(script) = &self.script {
            check_script(script).map_err(|message| ("bridge.script".to_string(), message))?;
        }
        if let Some(text) = &self.hex_literal {
            template("bridge.hex_literal", text, &["hex"])?;
        }
        if let Some(Some(text)) = &self.drop_foreign_key {
            template("bridge.drop_foreign_key", text, &["table", "key"])?;
        }
        if let Some(Some(fence)) = &self.identity_insert {
            for (key, text) in [("before", &fence.before), ("after", &fence.after)] {
                if let Some(text) = text {
                    template(&format!("bridge.identity_insert.{key}"), text, &["table"])?;
                }
            }
        }
        for (key, lines) in [
            ("backup_prologue", &self.backup_prologue),
            ("backup_epilogue", &self.backup_epilogue),
        ] {
            for line in lines.iter().flatten() {
                let text = match line {
                    BackupLine::Always(text) => text,
                    BackupLine::When(when) => {
                        if key == "backup_prologue" && when.when == Condition::Code {
                            return Err((
                                format!("bridge.{key}"),
                                "`when: code` is known only once the script is written; \
                                 it belongs in backup_epilogue"
                                    .to_string(),
                            ));
                        }
                        &when.sql
                    }
                };
                template(&format!("bridge.{key}"), text, &["catalog", "schema"])?;
            }
        }
        if let Some(texts) = &self.texts {
            for (kind, query) in [
                ("table", &texts.table),
                ("view", &texts.view),
                ("routine", &texts.routine),
                ("trigger", &texts.trigger),
                ("sequence", &texts.sequence),
            ] {
                let Some(Some(query)) = query else {
                    continue;
                };
                let key = format!("bridge.texts.{kind}");
                template(&key, &query.sql, &["qualified"])?;
                if query.column == Some(0) {
                    return Err((key, "column counts from 1".to_string()));
                }
            }
        }
        if let Some(Some(tables)) = self.comments.as_ref().and_then(|c| c.tables.as_ref())
            && tables.filters.column.is_some()
        {
            return Err((
                "bridge.comments.tables.filters.column".to_string(),
                "a table comment has no column to filter on".to_string(),
            ));
        }
        Ok(())
    }
}

/// Checks that `text` names only `takes` as holes: `{name}`, with `{{` and
/// `}}` for braces of its own, as every template of the format is written.
fn check_holes(text: &str, takes: &[&str]) -> Result<(), String> {
    let mut rest = text;
    while let Some(at) = rest.find(['{', '}']) {
        let tail = &rest[at..];
        if tail.starts_with("{{") || tail.starts_with("}}") {
            rest = &tail[2..];
            continue;
        }
        if tail.starts_with('}') {
            return Err("a `}` that closes nothing; write `}}` for a brace".to_string());
        }
        let Some(close) = tail.find('}') else {
            return Err("a `{` that is never closed; write `{{` for a brace".to_string());
        };
        let hole = &tail[1..close];
        if !takes.contains(&hole) {
            let takes = takes
                .iter()
                .map(|hole| format!("{{{hole}}}"))
                .collect::<Vec<_>>()
                .join(", ");
            return Err(format!(
                "`{{{hole}}}` is not a hole this key takes: {takes}"
            ));
        }
        rest = &tail[close + 1..];
    }
    Ok(())
}

/// Checks that a script is named inside the profiles' folder: a relative
/// path that does not climb out of it (§6 — scripts are read from the
/// application's own configuration directory and nowhere else).
fn check_script(name: &str) -> Result<(), String> {
    use std::path::{Component, Path};
    let path = Path::new(name);
    let inside = !name.trim().is_empty()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)));
    if inside {
        Ok(())
    } else {
        Err(format!(
            "`{name}` is not a file of the profiles' folder; name the script relative to it, \
             without `..`"
        ))
    }
}

/// The merged `bridge` half of a profile over its base profile's: a key the
/// profile gives replaces the base's, except in `comments` and `texts`,
/// whose own keys replace one by one.
pub fn merged(base: &serde_json::Value, top: &serde_json::Value) -> serde_json::Value {
    let (Some(base), Some(top)) = (base.as_object(), top.as_object()) else {
        return top.clone();
    };
    let mut out = base.clone();
    for (key, value) in top {
        match (key.as_str(), out.get_mut(key)) {
            ("comments" | "texts", Some(serde_json::Value::Object(under))) if value.is_object() => {
                for (inner, value) in value.as_object().into_iter().flatten() {
                    under.insert(inner.clone(), value.clone());
                }
            }
            _ => {
                out.insert(key.clone(), value.clone());
            }
        }
    }
    serde_json::Value::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_script_is_named_inside_the_profiles_folder() {
        assert!(check_script("tidb.groovy").is_ok());
        assert!(check_script("scripts/tidb.groovy").is_ok());
        for outside in [
            "../tidb.groovy",
            "/etc/tidb.groovy",
            "scripts/../../x",
            "",
            "./",
        ] {
            assert!(check_script(outside).is_err(), "{outside}");
        }
    }

    #[test]
    fn holes_are_checked_and_braces_escape() {
        assert!(check_holes("X'{hex}'", &["hex"]).is_ok());
        assert!(check_holes("{{literal}} {hex}", &["hex"]).is_ok());
        let error = check_holes("{hx}", &["hex"]).expect_err("unknown hole");
        assert!(error.contains("{hx}") && error.contains("{hex}"), "{error}");
        assert!(check_holes("{hex", &["hex"]).is_err());
        assert!(check_holes("a } b", &["hex"]).is_err());
    }

    #[test]
    fn records_merge_by_key_and_the_rest_replaces() {
        let base = serde_json::json!({
            "hex_literal": "X'{hex}'",
            "script_prologue": ["a", "b"],
            "comments": { "hides_comments": true, "escape": "none" },
            "texts": { "table": { "sql": "SHOW CREATE TABLE {qualified}", "column": 2 } },
        });
        let top = serde_json::json!({
            "script_prologue": ["c"],
            "comments": { "hides_comments": false },
            "texts": { "view": null },
        });
        let merged = merged(&base, &top);
        assert_eq!(merged["hex_literal"], "X'{hex}'", "left out: the base's");
        assert_eq!(
            merged["script_prologue"],
            serde_json::json!(["c"]),
            "a list replaces"
        );
        assert_eq!(merged["comments"]["hides_comments"], false);
        assert_eq!(merged["comments"]["escape"], "none", "a record merges");
        assert_eq!(merged["texts"]["table"]["column"], 2);
        assert!(merged["texts"]["view"].is_null(), "null is kept as null");
    }
}
