//! Schema checks — the Python app (the bridge) owns the schema and its
//! migrations.
//!
//! The gateway only checks the database at startup: that it is not from a
//! newer bridge than this build knows ([`refuse_newer_schema`]), and which
//! of the bridge's tables it needs exist yet ([`verify_schema`]).

use crate::db::manager::SqliteConnectionManager;
use r2d2::PooledConnection;
use rusqlite::OptionalExtension as _;
use tracing::{info, warn};

/// The newest bridge migration (`_MIGRATIONS` in
/// `src/sigrift/bridge/storage/base.py`) this gateway release was built
/// against. The gateway refuses to start on a database that holds a newer
/// one ([`refuse_newer_schema`]).
///
/// When a bridge migration is added, check that the gateway still reads and
/// writes the bridge's tables correctly with it, then set this to the new
/// migration. Until then `newest_known_bridge_migration_matches_the_bridge`
/// (here) and `tests/bridge/test_gateway_schema_guard_parity.py` fail.
pub const NEWEST_KNOWN_BRIDGE_MIGRATION: i64 = 56;

/// Why [`refuse_newer_schema`] refused the database.
#[derive(Debug)]
pub enum SchemaRefusal {
    /// `schema_version` holds these migrations (ascending), all newer than
    /// `newest_known`: a newer bridge migrated the database.
    Newer {
        versions: Vec<i64>,
        newest_known: i64,
    },
    /// The check could not be made: `schema_version` could not be looked
    /// up or read (locked, damaged, an unexpected table shape).
    Unreadable(rusqlite::Error),
}

impl std::fmt::Display for SchemaRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SchemaRefusal::Newer {
                versions,
                newest_known,
            } => write!(
                f,
                "Database schema has migrations {versions:?} newer than this gateway build \
                 (newest known bridge migration {newest_known}); refusing to start. Run the \
                 gateway of the same release as the bridge that migrated this database, or \
                 repair forward. A full pre-upgrade restore is safe only when no RF summary \
                 stream, generation or component exists; see src/sigrift/bridge/UPGRADE.md \
                 (rollback) and docs/rf-summary-recovery.md ('Downgrade restriction')."
            ),
            SchemaRefusal::Unreadable(e) => write!(
                f,
                "Cannot read the database's schema_version to check that this gateway build \
                 knows its schema ({e}); refusing to start."
            ),
        }
    }
}

impl std::error::Error for SchemaRefusal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SchemaRefusal::Newer { .. } => None,
            SchemaRefusal::Unreadable(e) => Some(e),
        }
    }
}

/// Refuse a database that a newer bridge has migrated (PRE-68), as the
/// bridge's `_refuse_newer_schema` does: a gateway rolled back onto live
/// volumes would otherwise run against a schema it does not understand.
///
/// It only reads. Versions at or below [`NEWEST_KNOWN_BRIDGE_MIGRATION`]
/// are accepted, including the historical gaps in the bridge's list (39,
/// 44). Only a missing `schema_version` table means a fresh database (the
/// gateway may start before the bridge has migrated it); any other error
/// refuses, so startup fails closed.
pub fn refuse_newer_schema(conn: &rusqlite::Connection) -> Result<(), SchemaRefusal> {
    let exists = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_version'",
            [],
            |_| Ok(()),
        )
        .optional()
        .map_err(SchemaRefusal::Unreadable)?;
    if exists.is_none() {
        return Ok(()); // fresh database
    }
    let mut stmt = conn
        .prepare("SELECT version FROM schema_version")
        .map_err(SchemaRefusal::Unreadable)?;
    let mut versions = stmt
        .query_map([], |row| row.get::<_, i64>(0))
        .and_then(|rows| rows.collect::<Result<Vec<_>, _>>())
        .map_err(SchemaRefusal::Unreadable)?;
    versions.retain(|&v| v > NEWEST_KNOWN_BRIDGE_MIGRATION);
    if versions.is_empty() {
        return Ok(());
    }
    versions.sort_unstable();
    Err(SchemaRefusal::Newer {
        versions,
        newest_known: NEWEST_KNOWN_BRIDGE_MIGRATION,
    })
}

pub fn verify_schema(conn: &PooledConnection<SqliteConnectionManager>) -> Vec<String> {
    let required_tables = [
        // Core detection tables
        "detections",
        "rf_anomalies",
        "fhss_events",
        // Security tables (Phase 1a)
        "users",
        "sessions",
        "audit_log",
        "rate_limit_login",
        "account_lockout",
        "mfa_tokens",
        "mfa_backup_codes",
        "totp_replay_cache",
        "tenant_settings",
        "oidc_states",
    ];
    let mut missing = Vec::new();

    for table in &required_tables {
        let exists: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                [table],
                |row| row.get::<_, i64>(0),
            )
            .map(|count| count > 0)
            .unwrap_or(false);

        if exists {
            info!(table = table, "Table verified");
        } else {
            warn!(table = table, "Table missing");
            missing.push(table.to_string());
        }
    }

    missing
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use std::path::Path;

    /// The bridge's migration list, `_MIGRATIONS` in `storage/base.py`.
    const BRIDGE_BASE_PY: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../sigrift/bridge/storage/base.py"
    );

    /// The version of every entry of the bridge's `_MIGRATIONS` list, read
    /// from its Python source: the first element of each top-level tuple.
    /// Strings (also triple-quoted SQL) and comments are skipped, so
    /// parentheses and numbers inside them do not count. Panics on anything
    /// it cannot read, so the drift test fails instead of passing on a
    /// partial list.
    fn bridge_migration_versions(source: &str) -> Vec<i64> {
        let decl = source
            .find("\n_MIGRATIONS")
            .expect("no `_MIGRATIONS` assignment in the bridge source")
            + 1;
        let start = decl
            + source[decl..]
                .find("= [")
                .expect("no `= [` after `_MIGRATIONS`")
            + 3;
        let bytes = source.as_bytes();
        let mut versions = Vec::new();
        // Nesting below the list itself: 0 between entries, 1 inside one.
        let mut depth = 0usize;
        let mut want_version = false;
        let mut i = start;
        while i < bytes.len() {
            let b = bytes[i];
            match b {
                b'#' => {
                    while i < bytes.len() && bytes[i] != b'\n' {
                        i += 1;
                    }
                    continue;
                }
                b'"' | b'\'' => {
                    assert!(!want_version, "a migration entry starts with a string");
                    let triple = bytes[i..].starts_with(&[b, b, b]);
                    let close: &[u8] = if triple { &[b, b, b] } else { &[b] };
                    i += close.len();
                    loop {
                        assert!(i < bytes.len(), "unterminated string in _MIGRATIONS");
                        if bytes[i] == b'\\' {
                            i += 2;
                        } else if bytes[i..].starts_with(close) {
                            i += close.len();
                            break;
                        } else {
                            i += 1;
                        }
                    }
                    continue;
                }
                b'(' | b'[' | b'{' => {
                    assert!(!want_version, "a migration entry starts with a bracket");
                    depth += 1;
                    want_version = depth == 1 && b == b'(';
                    assert!(
                        depth != 1 || b == b'(',
                        "a _MIGRATIONS entry is not a tuple"
                    );
                }
                b')' | b']' | b'}' => {
                    if depth == 0 {
                        assert_eq!(b, b']', "unbalanced _MIGRATIONS list");
                        assert!(!versions.is_empty(), "_MIGRATIONS has no entries");
                        return versions;
                    }
                    depth -= 1;
                }
                b'0'..=b'9' if want_version => {
                    let end = bytes[i..]
                        .iter()
                        .position(|c| !c.is_ascii_digit())
                        .map_or(bytes.len(), |n| i + n);
                    versions.push(source[i..end].parse().unwrap());
                    want_version = false;
                    i = end;
                    continue;
                }
                c if want_version && !c.is_ascii_whitespace() => {
                    panic!(
                        "a _MIGRATIONS entry does not start with an integer version: {:?}",
                        &source[i..(i + 40).min(source.len())]
                    );
                }
                _ => {}
            }
            i += 1;
        }
        panic!("the _MIGRATIONS list is not closed");
    }

    /// The newest-known version must follow the bridge: a bridge migration
    /// added without bumping the gateway (or a gateway bumped past the
    /// bridge) fails here. `tests/bridge/test_gateway_schema_guard_parity.py`
    /// checks the same from the bridge suite.
    #[test]
    fn newest_known_bridge_migration_matches_the_bridge() {
        let source = std::fs::read_to_string(BRIDGE_BASE_PY)
            .unwrap_or_else(|e| panic!("{BRIDGE_BASE_PY}: {e}"));
        let versions = bridge_migration_versions(&source);
        let newest = *versions.iter().max().unwrap();
        assert_eq!(
            NEWEST_KNOWN_BRIDGE_MIGRATION, newest,
            "The bridge's newest migration is {newest}. Check that the gateway still reads \
             and writes the bridge's tables correctly with it, then set \
             NEWEST_KNOWN_BRIDGE_MIGRATION to it."
        );
        // The historical gaps are absent from the list, not unknown to it.
        for gap in [39, 44] {
            assert!(
                !versions.contains(&gap),
                "migration {gap} is now in the list"
            );
        }
    }

    #[test]
    fn the_migration_parser_reads_only_entry_versions() {
        let source = r#"
_OTHER = [(999, "x", "y")]

_MIGRATIONS: list[tuple[int, str, str]] = [
    # Migration 1: a comment with (77, "not an entry")
    (
        1,
        "one (with parens) and 88",
        "CREATE INDEX x ON t (a, b)",
    ),
    (2, 'two', '''
    (
        66,
        "inside a triple-quoted string"
    )
'''),
    (  # an entry-opening comment ) (
        12,
        "escaped \" quote (",
        """
CREATE TABLE t (a TEXT DEFAULT ')');
""",
    ),
]

_AFTER = [(1000, "x", "y")]
"#;
        assert_eq!(bridge_migration_versions(source), [1, 2, 12]);
    }

    /// A triple-quoted string ends only at three quotes of its kind: a lone
    /// quote of that kind inside it (a double-quoted SQL identifier, an
    /// apostrophe) neither ends it nor starts a new one.
    #[test]
    fn the_migration_parser_reads_lone_quotes_in_triple_quoted_strings() {
        let source = r#"
_MIGRATIONS = [
    (3, "quoted identifier", """
CREATE TABLE "order" (id INTEGER, note TEXT DEFAULT 'it"s (77, x)');
"""),
    (4, 'apostrophe', '''
-- the bridge's (88, "not an entry") table
'''),
    (5, "plain", "SELECT 1"),
]
"#;
        assert_eq!(bridge_migration_versions(source), [3, 4, 5]);
    }

    #[test]
    #[should_panic(expected = "does not start with an integer version")]
    fn the_migration_parser_rejects_an_entry_it_cannot_read() {
        bridge_migration_versions("\n_MIGRATIONS = [\n    (VERSION, \"x\", \"y\"),\n]\n");
    }

    /// A database as the bridge leaves it: `schema_version` with `versions`.
    fn bridge_database(versions: &[i64]) -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE schema_version (
                 version INTEGER PRIMARY KEY,
                 description TEXT NOT NULL,
                 applied_at TEXT NOT NULL
             );",
        )
        .unwrap();
        for v in versions {
            conn.execute(
                "INSERT INTO schema_version VALUES (?1, 'migration', datetime('now'))",
                [v],
            )
            .unwrap();
        }
        conn
    }

    fn sqlite_master(conn: &Connection) -> Vec<(String, String)> {
        let mut stmt = conn
            .prepare("SELECT type, name FROM sqlite_master ORDER BY type, name")
            .unwrap();
        let rows = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        rows
    }

    #[test]
    fn a_fresh_database_is_accepted_and_left_alone() {
        let conn = Connection::open_in_memory().unwrap();
        refuse_newer_schema(&conn).unwrap();
        assert!(sqlite_master(&conn).is_empty());
    }

    #[test]
    fn a_database_without_schema_version_is_accepted() {
        // Tables but no schema_version: the gateway started first, or a
        // database from before numbered migrations.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE detections (id INTEGER PRIMARY KEY);")
            .unwrap();
        refuse_newer_schema(&conn).unwrap();
    }

    #[test]
    fn an_empty_schema_version_is_accepted() {
        refuse_newer_schema(&bridge_database(&[])).unwrap();
    }

    #[test]
    fn the_current_schema_with_its_historical_gaps_is_accepted() {
        let current: Vec<i64> = (1..=NEWEST_KNOWN_BRIDGE_MIGRATION)
            .filter(|v| ![39, 44].contains(v))
            .collect();
        refuse_newer_schema(&bridge_database(&current)).unwrap();
        // A gap version recorded after all (a manual fix) is still known.
        for gap in [39, 44] {
            let mut with_gap = current.clone();
            with_gap.push(gap);
            refuse_newer_schema(&bridge_database(&with_gap)).unwrap();
        }
    }

    #[test]
    fn an_older_schema_is_accepted() {
        refuse_newer_schema(&bridge_database(&[1, 2, 3, 43])).unwrap();
    }

    #[test]
    fn newer_migrations_are_refused_and_named() {
        let newest = NEWEST_KNOWN_BRIDGE_MIGRATION;
        let conn = bridge_database(&[1, newest, newest + 25, newest + 1]);
        let before = sqlite_master(&conn);
        let refusal = refuse_newer_schema(&conn).unwrap_err();
        match &refusal {
            SchemaRefusal::Newer {
                versions,
                newest_known,
            } => {
                assert_eq!(versions, &[newest + 1, newest + 25]);
                assert_eq!(*newest_known, newest);
            }
            other => panic!("expected a newer-schema refusal, got {other:?}"),
        }
        let msg = refusal.to_string();
        assert!(
            msg.contains(&format!("[{}, {}]", newest + 1, newest + 25)),
            "{msg}"
        );
        assert!(
            msg.contains(&format!("newest known bridge migration {newest}")),
            "{msg}"
        );
        assert!(msg.contains("refusing to start"), "{msg}");
        assert!(msg.contains("UPGRADE.md"), "{msg}");
        assert_eq!(sqlite_master(&conn), before);
    }

    #[test]
    fn an_unexpected_schema_version_shape_fails_closed() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE schema_version (applied_at TEXT);")
            .unwrap();
        let refusal = refuse_newer_schema(&conn).unwrap_err();
        assert!(
            matches!(refusal, SchemaRefusal::Unreadable(_)),
            "{refusal:?}"
        );
        assert!(refusal.to_string().contains("version"), "{refusal}");
    }

    /// The versions are named in ascending order also when the table does
    /// not return them so (here `version` is not its rowid).
    #[test]
    fn newer_migrations_are_named_in_ascending_order() {
        let newest = NEWEST_KNOWN_BRIDGE_MIGRATION;
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE schema_version (version INTEGER, description TEXT, applied_at TEXT);",
        )
        .unwrap();
        for v in [newest + 9, 1, newest + 2, newest + 5] {
            conn.execute(
                "INSERT INTO schema_version VALUES (?1, 'migration', 'now')",
                [v],
            )
            .unwrap();
        }
        match refuse_newer_schema(&conn) {
            Err(SchemaRefusal::Newer { versions, .. }) => {
                assert_eq!(versions, [newest + 2, newest + 5, newest + 9]);
            }
            other => panic!("expected a newer-schema refusal, got {other:?}"),
        }
    }

    /// The lookup of `schema_version` itself failing is not a fresh
    /// database: the check refuses. Here the file is not a database.
    #[test]
    fn a_file_that_is_not_a_database_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("detections.db");
        std::fs::write(
            &path,
            b"not an SQLite database, but not empty either\n".repeat(100),
        )
        .unwrap();
        let conn = Connection::open(&path).unwrap();
        match refuse_newer_schema(&conn) {
            Err(SchemaRefusal::Unreadable(e)) => assert_eq!(
                e.sqlite_error_code(),
                Some(rusqlite::ErrorCode::NotADatabase),
                "{e}"
            ),
            other => panic!("expected an unreadable refusal, got {other:?}"),
        }
    }

    /// The same when the database is locked: another connection holds an
    /// exclusive lock, so even the lookup in `sqlite_master` is busy.
    #[test]
    fn a_locked_database_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("detections.db");
        let holder = Connection::open(&path).unwrap();
        holder
            .execute_batch(
                "CREATE TABLE schema_version (version INTEGER PRIMARY KEY,
                     description TEXT NOT NULL, applied_at TEXT NOT NULL);
                 BEGIN EXCLUSIVE;",
            )
            .unwrap();
        let conn = Connection::open(&path).unwrap();
        conn.busy_timeout(std::time::Duration::ZERO).unwrap();
        match refuse_newer_schema(&conn) {
            Err(SchemaRefusal::Unreadable(e)) => assert_eq!(
                e.sqlite_error_code(),
                Some(rusqlite::ErrorCode::DatabaseBusy),
                "{e}"
            ),
            other => panic!("expected an unreadable refusal, got {other:?}"),
        }
        holder.execute_batch("ROLLBACK").unwrap();
        refuse_newer_schema(&conn).unwrap();
    }

    #[test]
    fn a_non_integer_version_fails_closed() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE schema_version (version TEXT, description TEXT, applied_at TEXT);
             INSERT INTO schema_version VALUES ('57a', 'odd', 'now');",
        )
        .unwrap();
        assert!(matches!(
            refuse_newer_schema(&conn),
            Err(SchemaRefusal::Unreadable(_))
        ));
    }

    #[test]
    fn the_check_only_reads() {
        // A read-only connection is enough: the check cannot change the
        // schema of a database it refuses.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("detections.db");
        let newest = NEWEST_KNOWN_BRIDGE_MIGRATION;
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(&format!(
                "CREATE TABLE schema_version (version INTEGER PRIMARY KEY,
                     description TEXT NOT NULL, applied_at TEXT NOT NULL);
                 INSERT INTO schema_version VALUES ({newest}, 'x', 'now');"
            ))
            .unwrap();
        }
        let read_only = |p: &Path| {
            Connection::open_with_flags(p, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap()
        };
        refuse_newer_schema(&read_only(&path)).unwrap();
        Connection::open(&path)
            .unwrap()
            .execute(
                "INSERT INTO schema_version VALUES (?1, 'x', 'now')",
                [newest + 1],
            )
            .unwrap();
        assert!(matches!(
            refuse_newer_schema(&read_only(&path)),
            Err(SchemaRefusal::Newer { .. })
        ));
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;
    use rusqlite::Connection;
    use std::error::Error as _;

    /// A refusal because `schema_version` cannot be read carries the
    /// SQLite error as its source, so the startup error chain says what
    /// went wrong; a refusal of newer migrations has no underlying error.
    #[test]
    fn an_unreadable_schema_refusal_exposes_the_sqlite_error_as_its_source() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE schema_version (applied_at TEXT);")
            .unwrap();
        let refusal = refuse_newer_schema(&conn).unwrap_err();
        let source = refusal.source().expect("an unreadable schema has a source");
        let sqlite = source
            .downcast_ref::<rusqlite::Error>()
            .expect("the source is the SQLite error");
        assert!(sqlite.to_string().contains("version"), "{sqlite}");
        assert!(refusal.to_string().contains(&sqlite.to_string()));

        let newest = NEWEST_KNOWN_BRIDGE_MIGRATION;
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(&format!(
            "CREATE TABLE schema_version (version INTEGER PRIMARY KEY,
                 description TEXT NOT NULL, applied_at TEXT NOT NULL);
             INSERT INTO schema_version VALUES ({}, 'x', 'now');",
            newest + 1
        ))
        .unwrap();
        let refusal = refuse_newer_schema(&conn).unwrap_err();
        assert!(
            matches!(refusal, SchemaRefusal::Newer { .. }),
            "{refusal:?}"
        );
        assert!(refusal.source().is_none());
    }
}
