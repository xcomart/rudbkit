use std::fs;
use std::path::{Path, PathBuf};

use serde::de::IgnoredAny;

use super::*;

fn write(dir: &Path, name: &str, text: &str) {
    fs::write(dir.join(name), text).expect("write");
}

fn read(dir: &Path, name: &str) -> Option<String> {
    fs::read_to_string(dir.join(name)).ok()
}

// ------------------------------------------------------------------ format

/// The `sql` half as a reader that checks it would spell it.
#[derive(Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Sql {
    page_clause: Option<String>,
}

const TIDB: &str = "\
api: 1
name: TiDB
base: mysql
aliases: [pingcap]
sql:
  page_clause: \"LIMIT {offset}, {limit}\"
  words: { keywords: [AUTO_RANDOM] }
bridge:
  detect: [tidb]
driver:
  class: com.mysql.cj.jdbc.Driver
  maven: com.mysql:mysql-connector-j:9.1.0
  url_template: \"jdbc:mysql://{host}:{port}/{database}\"
  default_port: 4000
  icon: mysql
";

/// The `sql` half is the reader's: one that ignores it reads any, and one
/// that spells it refuses a key it does not have, with its line.
#[test]
fn the_sql_half_is_read_as_its_reader_spells_it() {
    let file: ProfileFile<IgnoredAny> = parse("tidb", TIDB).expect("reads");
    assert_eq!(file.name, "TiDB");
    assert_eq!(file.base, "mysql");
    assert_eq!(file.aliases, ["pingcap"]);
    assert!(file.sql.is_some());
    let driver = file.driver.as_ref().expect("the driver section");
    assert_eq!(
        driver.name_or(&file.name),
        "TiDB",
        "named after the profile"
    );
    assert_eq!(driver.default_port, Some(4000));
    assert_eq!(driver.icon.as_deref(), Some("mysql"));

    let error = parse::<Sql>("tidb", TIDB).expect_err("words is no key of this half");
    assert_eq!(error.line, Some(7), "{error}");
    assert!(error.to_string().starts_with("tidb.yml:7:"), "{error}");
}

/// A key the envelope or the driver section does not have is an error with
/// its line, whoever reads the `sql` half.
#[test]
fn an_unknown_key_says_where() {
    let error = parse::<IgnoredAny>("typo", "api: 1\nname: X\nbase: mysql\nbaes: x\n")
        .expect_err("refused");
    assert_eq!(error.line, Some(4), "{error}");
    let text = "api: 1\nname: X\nbase: mysql\ndriver:\n  class: c\n  url: u\n";
    let error = parse::<IgnoredAny>("driver", text).expect_err("refused");
    assert!(error.message.contains("url"), "{error}");
}

/// The version is required and has to be this build's.
#[test]
fn the_api_version_is_checked() {
    assert!(parse::<IgnoredAny>("none", "name: X\nbase: mysql\n").is_err());
    let error =
        parse::<IgnoredAny>("later", "api: 2\nname: X\nbase: mysql\n").expect_err("refused");
    assert!(error.message.contains("api 2"), "{error}");
}

/// Every key of the `bridge` half, as §4.3 of the design writes them.
const BRIDGE: &str = "\
api: 1
name: Everything
base: mysql
bridge:
  detect: [tidb]
  catalog_is_schema: true
  result_catalogs_resolve: true
  sees_only_its_catalog: false
  numbers_procedures: false
  sequences: []
  triggers:
    sql: \"SELECT TRIGGER_SCHEMA, NULL, TRIGGER_NAME, EVENT_OBJECT_TABLE, ACTION_TIMING, EVENT_MANIPULATION, 'ROW', 'Y', NULL FROM information_schema.TRIGGERS WHERE 1 = 1\"
    filters: { catalog: TRIGGER_SCHEMA, schema: TRIGGER_SCHEMA, name: TRIGGER_NAME }
    order_by: \"1, 3\"
  comments:
    hides_comments: true
    marks_views_in_remarks: true
    escape: none
    tables: { sql: \"SELECT TABLE_SCHEMA, TABLE_NAME, TABLE_COMMENT FROM information_schema.TABLES WHERE 1 = 1\", filters: { catalog: TABLE_SCHEMA, table: TABLE_NAME } }
    columns: null
  texts:
    table: { sql: \"SHOW CREATE TABLE {qualified}\", column: 2 }
    view: { sql: \"SELECT VIEW_DEFINITION FROM information_schema.VIEWS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?\", binds: [catalog, name] }
    routine: null
    trigger: null
    sequence: null
  qualifies_by_catalog: true
  defers_keys: false
  comments_inline: true
  comments_on: false
  computed_has_no_type: false
  serial_columns: false
  identity_clause: AUTO_INCREMENT
  not_null_first: true
  indexes_foreign_keys: true
  creates_without_catalog: false
  types_sequences: true
  cache_of_one_is_no_cache: false
  script_prologue: [\"SET FOREIGN_KEY_CHECKS = 0;\"]
  script_epilogue: [\"SET FOREIGN_KEY_CHECKS = 1;\"]
  data_prologue: []
  data_epilogue: []
  bits_are_numbers: true
  booleans_are_numbers: true
  national_strings: never
  hex_literal: \"X'{hex}'\"
  script_client: mysql
  drops_if_exists: true
  drop_table_cascade: \"\"
  drop_foreign_key: null
  multi_row_values: true
  upsert: { merge: { from_dual: true } }
  backup_prologue: [\"USE {catalog};\", { sql: \"SET x = 1;\", when: routines }]
  backup_epilogue: [{ sql: \"CALL recompile({schema});\", when: code }]
  identity_insert:
    before: \"SET IDENTITY_INSERT {table} ON;\"
    after: \"SET IDENTITY_INSERT {table} OFF;\"
  overrides_system_value: false
  script: tidb.groovy
";

/// The whole `bridge` half reads, and goes to a bridge as the JSON its
/// `ProfileVendor` reads: a `null` sent as one, a key left out not sent.
#[test]
fn every_bridge_key_reads_and_writes_as_the_bridge_reads_it() {
    let file: ProfileFile<IgnoredAny> =
        parse("everything", BRIDGE).unwrap_or_else(|error| panic!("{error}"));
    let bridge = file.bridge.expect("the bridge half");
    let json = serde_json::to_value(&bridge).expect("serializes");
    assert_eq!(json["texts"]["table"]["column"], 2);
    assert!(json["texts"]["routine"].is_null());
    assert!(json["drop_foreign_key"].is_null());
    assert_eq!(json["upsert"]["merge"]["from_dual"], true);
    assert_eq!(json["upsert"]["merge"]["terminated"], false);
    assert_eq!(json["national_strings"], "never");
    assert_eq!(json["backup_prologue"][0], "USE {catalog};");
    assert_eq!(json["backup_prologue"][1]["when"], "routines");
    assert_eq!(json["comments"]["escape"], "none");
    assert!(json["comments"]["columns"].is_null());
    assert_eq!(json["triggers"]["filters"]["name"], "TRIGGER_NAME");

    let bare: ProfileFile<IgnoredAny> = parse(
        "bare",
        "api: 1\nname: B\nbase: mysql\nbridge:\n  upsert: none\n",
    )
    .expect("reads");
    let json = serde_json::to_value(bare.bridge.expect("bridge")).expect("serializes");
    assert_eq!(
        json,
        serde_json::json!({ "upsert": "none" }),
        "nothing else is sent"
    );
}

/// A key of the `bridge` half that is not one is an error with its line,
/// and so is a template hole its key does not take.
#[test]
fn a_bridge_mistake_says_where() {
    let text = "api: 1\nname: X\nbase: mysql\nbridge:\n  hex_literall: x\n";
    let error = parse::<IgnoredAny>("typo", text).expect_err("refused");
    assert_eq!(error.line, Some(5), "{error}");

    let text = "api: 1\nname: X\nbase: mysql\nbridge:\n  hex_literal: \"X'{hx}'\"\n";
    let error = parse::<IgnoredAny>("hole", text).expect_err("refused");
    assert!(error.message.starts_with("bridge.hex_literal:"), "{error}");

    let text = "api: 1\nname: X\nbase: mysql\nbridge:\n  backup_prologue:\n    \
                - { sql: x, when: code }\n";
    let error = parse::<IgnoredAny>("when", text).expect_err("refused");
    assert!(error.message.contains("backup_epilogue"), "{error}");
}

/// What a profile says is what it writes, and nothing it does not.
#[test]
fn a_profile_writes_only_what_it_holds() {
    let file: ProfileFile<()> = ProfileFile::new("Bare", "postgres");
    assert_eq!(to_yaml(&file), "api: 1\nname: Bare\nbase: postgres\n");
}

/// An icon is a file when it looks like one, from the profiles' folder when
/// relative, and otherwise the name of a mark.
#[test]
fn an_icon_is_a_mark_or_a_file() {
    let base = Path::new("/config/dialects");
    assert_eq!(icon_ref("mysql", base), IconRef::Mark("mysql"));
    assert_eq!(icon_ref(" tidb ", base), IconRef::Mark("tidb"));
    assert_eq!(
        icon_ref("logo.PNG", base),
        IconRef::File(base.join("logo.PNG"))
    );
    assert_eq!(
        icon_ref("icons/acme.svg", base),
        IconRef::File(base.join("icons/acme.svg"))
    );
    assert_eq!(
        icon_ref("/opt/acme/logo.webp", base),
        IconRef::File(PathBuf::from("/opt/acme/logo.webp"))
    );
    assert_eq!(
        icon_ref("acme/logo", base),
        IconRef::File(base.join("acme/logo")),
        "a path without an extension is still a path"
    );
}

/// A built-in is found by its name or an alias, in any case.
#[test]
fn a_built_in_is_found_by_any_of_its_spellings() {
    assert_eq!(built_in("postgres"), Some("postgres"));
    assert_eq!(built_in(" PostgreSQL "), Some("postgres"));
    assert_eq!(built_in("tsql"), Some("mssql"));
    assert_eq!(built_in("mariadb"), Some("mariadb"), "a dialect of its own");
    assert_eq!(built_in("tidb"), None, "a profile, not a built-in");
}

/// Every profile shipped here reads, names a script that is shipped beside it,
/// and stands on a built-in or another shipped profile.
#[test]
fn every_shipped_profile_reads() {
    let names: Vec<&str> = SHIPPED.iter().map(|file| file.name).collect();
    let profiles: Vec<(&str, ProfileFile<IgnoredAny>)> = SHIPPED
        .iter()
        .filter_map(|file| {
            let id = file.name.strip_suffix(".yml")?;
            let text = std::str::from_utf8(file.contents).expect("UTF-8");
            Some((
                id,
                parse(id, text).unwrap_or_else(|error| panic!("{error}")),
            ))
        })
        .collect();
    assert!(!profiles.is_empty(), "the folder is compiled in");
    for (id, file) in &profiles {
        if let Some(script) = file.script() {
            assert!(names.contains(&script), "{id}: {script} is not shipped");
        }
        assert!(
            built_in(&file.base).is_some() || profiles.iter().any(|(other, _)| *other == file.base),
            "{id}: base {} is neither a built-in nor shipped",
            file.base
        );
    }
}

// --------------------------------------------------------------- directory

#[test]
fn a_pending_update_is_found_beside_its_profile_and_script() {
    let dir = tempfile::tempdir().expect("tempdir");
    write(dir.path(), "tidb.yml", "x");
    write(dir.path(), "tidb.yml.new", "y");
    write(dir.path(), "tidb.groovy.new", "z");
    write(dir.path(), "other.groovy.new", "z");
    let pending: Vec<String> =
        pending_beside(dir.path(), &dir.path().join("tidb.yml"), "tidb", None)
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
    assert_eq!(pending, ["tidb.yml.new", "tidb.groovy.new"]);
    let named = pending_beside(
        dir.path(),
        &dir.path().join("tidb.yml"),
        "tidb",
        Some("other.groovy"),
    );
    assert_eq!(named.len(), 2, "{named:?}");
    let files = profile_files(dir.path()).expect("lists");
    assert_eq!(files.len(), 1, "a .new is no profile: {files:?}");
}

#[test]
fn a_text_is_read_without_its_byte_order_mark_and_hashed_with_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::write(dir.path().join("a.yml"), b"\xEF\xBB\xBFapi: 1").expect("write");
    let (sha256, text) = read_text(&dir.path().join("a.yml")).expect("reads");
    assert_eq!(text, "api: 1");
    assert_eq!(sha256, hash(b"\xEF\xBB\xBFapi: 1"));
    fs::write(dir.path().join("b.yml"), b"\xFF").expect("write");
    assert_eq!(
        read_text(&dir.path().join("b.yml")),
        Err("the file is not UTF-8".to_string())
    );
}

// --------------------------------------------------------------- shipping

const V1: Shipped = Shipped {
    name: "tidb.yml",
    contents: b"version 1",
};
const V2: Shipped = Shipped {
    name: "tidb.yml",
    contents: b"version 2",
};
const SCRIPT_V1: Shipped = Shipped {
    name: "tidb.groovy",
    contents: b"// 1",
};
const SCRIPT_V2: Shipped = Shipped {
    name: "tidb.groovy",
    contents: b"// 2",
};
const SCRIPT_V3: Shipped = Shipped {
    name: "tidb.groovy",
    contents: b"// 3",
};

fn allowed_hash(dir: &Path, name: &str) -> Option<String> {
    read_allowed(dir)
        .expect("reads")
        .version_of(name)
        .map(str::to_string)
}

#[test]
fn a_file_never_offered_is_written_and_recorded() {
    let dir = tempfile::tempdir().expect("tempdir");
    let dir = dir.path().join("dialects");
    let synced = sync_shipped(&dir, &[V1]).expect("sync");
    assert_eq!(synced.written, ["tidb.yml"]);
    assert_eq!(read(&dir, "tidb.yml").as_deref(), Some("version 1"));
    assert!(read(&dir, RECORD_FILE_NAME).is_some());

    let again = sync_shipped(&dir, &[V1]).expect("sync");
    assert_eq!(again, Synced::default(), "nothing more to do");
}

#[test]
fn nothing_shipped_writes_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let dir = dir.path().join("dialects");
    sync_shipped(&dir, &[]).expect("sync");
    assert!(!dir.exists(), "no directory made for nothing");
}

#[test]
fn a_deleted_file_stays_deleted() {
    let dir = tempfile::tempdir().expect("tempdir");
    sync_shipped(dir.path(), &[V1]).expect("sync");
    fs::remove_file(dir.path().join("tidb.yml")).expect("delete");
    let synced = sync_shipped(dir.path(), &[V2]).expect("sync");
    assert_eq!(synced, Synced::default());
    assert_eq!(read(dir.path(), "tidb.yml"), None, "a newer version too");
    assert_eq!(read(dir.path(), "tidb.yml.new"), None);
}

#[test]
fn an_unchanged_file_takes_the_newer_version() {
    let dir = tempfile::tempdir().expect("tempdir");
    sync_shipped(dir.path(), &[V1]).expect("sync");
    let synced = sync_shipped(dir.path(), &[V2]).expect("sync");
    assert_eq!(synced.replaced, ["tidb.yml"]);
    assert_eq!(read(dir.path(), "tidb.yml").as_deref(), Some("version 2"));
}

#[test]
fn a_changed_file_is_kept_and_the_newer_version_waits_beside_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    sync_shipped(dir.path(), &[V1]).expect("sync");
    write(dir.path(), "tidb.yml", "mine");
    let synced = sync_shipped(dir.path(), &[V2]).expect("sync");
    assert_eq!(synced.beside, ["tidb.yml"]);
    assert_eq!(read(dir.path(), "tidb.yml").as_deref(), Some("mine"));
    assert_eq!(
        read(dir.path(), "tidb.yml.new").as_deref(),
        Some("version 2")
    );

    // Offered once: the next start leaves both as they are.
    assert_eq!(
        sync_shipped(dir.path(), &[V2]).expect("sync"),
        Synced::default()
    );
    assert_eq!(
        read(dir.path(), "tidb.yml.new").as_deref(),
        Some("version 2")
    );

    // Taken: the `.new` has done its work.
    write(dir.path(), "tidb.yml", "version 2");
    sync_shipped(dir.path(), &[V2]).expect("sync");
    assert_eq!(read(dir.path(), "tidb.yml.new"), None);

    // And the file, now as offered, follows the next version again.
    let v3 = Shipped {
        name: "tidb.yml",
        contents: b"version 3",
    };
    assert_eq!(
        sync_shipped(dir.path(), &[v3]).expect("sync").replaced,
        ["tidb.yml"]
    );
}

#[test]
fn a_users_own_file_of_the_same_name_is_not_overwritten() {
    let dir = tempfile::tempdir().expect("tempdir");
    write(dir.path(), "tidb.yml", "mine from before");
    let synced = sync_shipped(dir.path(), &[V1]).expect("sync");
    assert_eq!(synced.beside, ["tidb.yml"]);
    assert_eq!(
        read(dir.path(), "tidb.yml").as_deref(),
        Some("mine from before")
    );
    assert_eq!(
        read(dir.path(), "tidb.yml.new").as_deref(),
        Some("version 1")
    );
}

#[test]
fn an_unreadable_record_decides_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    write(dir.path(), RECORD_FILE_NAME, "{ not json");
    assert!(sync_shipped(dir.path(), &[V1]).is_err());
    assert_eq!(read(dir.path(), "tidb.yml"), None);
}

#[test]
fn a_shipped_script_is_allowed_as_the_application_writes_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    sync_shipped(dir.path(), &[V1, SCRIPT_V1]).expect("sync");
    assert_eq!(
        allowed_hash(dir.path(), "tidb.groovy"),
        Some(hash(SCRIPT_V1.contents))
    );
    assert_eq!(
        allowed_hash(dir.path(), "tidb.yml"),
        None,
        "a profile is no script"
    );

    // A newer version replaces one the user left alone, and stays allowed.
    sync_shipped(dir.path(), &[V1, SCRIPT_V2]).expect("sync");
    assert_eq!(
        allowed_hash(dir.path(), "tidb.groovy"),
        Some(hash(SCRIPT_V2.contents))
    );

    // Edited, it is the user's: the update waits beside it, and the edit
    // needs allowing.
    write(dir.path(), "tidb.groovy", "// the user's");
    sync_shipped(dir.path(), &[V1, SCRIPT_V3]).expect("sync");
    assert_eq!(
        read(dir.path(), "tidb.groovy").as_deref(),
        Some("// the user's")
    );
    assert_eq!(
        allowed_hash(dir.path(), "tidb.groovy"),
        Some(hash(SCRIPT_V2.contents)),
        "what was allowed is not what is there"
    );
}

#[test]
fn a_shipped_script_the_user_turned_off_stays_off_across_an_update() {
    let dir = tempfile::tempdir().expect("tempdir");
    sync_shipped(dir.path(), &[SCRIPT_V1]).expect("sync");
    disallow_in(dir.path(), "tidb.groovy").expect("disallow");
    let synced = sync_shipped(dir.path(), &[SCRIPT_V2]).expect("sync");
    assert_eq!(synced.replaced, ["tidb.groovy"]);
    assert_eq!(allowed_hash(dir.path(), "tidb.groovy"), None);
}

#[test]
fn a_script_is_allowed_and_disallowed_by_its_hash() {
    let dir = tempfile::tempdir().expect("tempdir");
    let script = Script {
        name: "x.groovy".to_string(),
        path: dir.path().join("x.groovy"),
        sha256: hash(b"// x"),
        allowed: false,
    };
    allow_in(dir.path(), &script).expect("allow");
    let allowed = read_allowed(dir.path()).expect("reads");
    assert!(allowed.allows("x.groovy", &hash(b"// x")));
    assert!(
        !allowed.allows("x.groovy", &hash(b"// y")),
        "another version"
    );
    disallow_in(dir.path(), "x.groovy").expect("disallow");
    assert!(
        !read_allowed(dir.path())
            .expect("reads")
            .allows("x.groovy", &hash(b"// x"))
    );

    write(dir.path(), ALLOWED_FILE_NAME, "{ not json");
    assert!(
        read_allowed(dir.path()).is_err(),
        "a list that cannot be read"
    );
}
