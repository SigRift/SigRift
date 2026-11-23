//! An r2d2 connection manager for rusqlite.
//!
//! It replaces the `r2d2_sqlite` crate, whose newest release (0.35) still
//! requires rusqlite 0.40 and so the bundled SQLite of libsqlite3-sys 0.38,
//! which RUSTSEC-2026-0459 (CVE-2026-119375, SQLite before 3.54.0) affects.
//! Keeping the manager here lets the gateway use rusqlite 0.41, which bundles
//! SQLite 3.54. The API and behaviour are those the gateway used:
//! [`SqliteConnectionManager::file`], [`SqliteConnectionManager::memory`]
//! (one shared-cache in-memory database per manager, kept alive while the
//! manager lives), [`SqliteConnectionManager::with_flags`] and
//! [`SqliteConnectionManager::with_init`], which runs on every new connection.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::{Connection, OpenFlags};

type InitFn = dyn Fn(&mut Connection) -> Result<(), rusqlite::Error> + Send + Sync + 'static;

#[derive(Debug)]
enum Source {
    File(PathBuf),
    /// A named shared-cache in-memory database (`file:<name>?mode=memory&cache=shared`).
    Memory(String),
}

/// Opens rusqlite connections for an r2d2 pool.
pub struct SqliteConnectionManager {
    source: Source,
    flags: OpenFlags,
    init: Option<Box<InitFn>>,
    /// For [`Source::Memory`]: one connection held open so the database
    /// survives while the pool has no connection checked out.
    keep_alive: Mutex<Option<Connection>>,
}

impl fmt::Debug for SqliteConnectionManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SqliteConnectionManager")
            .field("source", &self.source)
            .field("flags", &self.flags)
            .field("init", &self.init.as_ref().map(|_| "InitFn"))
            .finish()
    }
}

impl SqliteConnectionManager {
    /// Connections to the database file at `path`.
    pub fn file<P: AsRef<Path>>(path: P) -> Self {
        Self::new(Source::File(path.as_ref().to_path_buf()))
    }

    /// Connections to one in-memory database shared by every connection of
    /// this manager (and of no other manager).
    pub fn memory() -> Self {
        Self::new(Source::Memory(uuid::Uuid::new_v4().to_string()))
    }

    fn new(source: Source) -> Self {
        Self {
            source,
            flags: OpenFlags::default(),
            init: None,
            keep_alive: Mutex::new(None),
        }
    }

    /// Open connections with `flags` instead of [`OpenFlags::default`].
    pub fn with_flags(self, flags: OpenFlags) -> Self {
        Self { flags, ..self }
    }

    /// Run `init` on every new connection before the pool hands it out; an
    /// error refuses the connection.
    pub fn with_init<F>(self, init: F) -> Self
    where
        F: Fn(&mut Connection) -> Result<(), rusqlite::Error> + Send + Sync + 'static,
    {
        Self {
            init: Some(Box::new(init)),
            ..self
        }
    }

    fn open(&self) -> Result<Connection, rusqlite::Error> {
        match &self.source {
            Source::File(path) => Connection::open_with_flags(path, self.flags),
            Source::Memory(name) => {
                let open = || {
                    Connection::open_with_flags(
                        format!("file:{name}?mode=memory&cache=shared"),
                        self.flags,
                    )
                };
                let mut keep_alive = self
                    .keep_alive
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if keep_alive.is_none() {
                    *keep_alive = Some(open()?);
                }
                drop(keep_alive);
                open()
            }
        }
    }
}

impl r2d2::ManageConnection for SqliteConnectionManager {
    type Connection = Connection;
    type Error = rusqlite::Error;

    fn connect(&self) -> Result<Connection, rusqlite::Error> {
        let mut conn = self.open()?;
        if let Some(init) = &self.init {
            init(&mut conn)?;
        }
        Ok(conn)
    }

    fn is_valid(&self, conn: &mut Connection) -> Result<(), rusqlite::Error> {
        conn.execute_batch("")
    }

    fn has_broken(&self, _conn: &mut Connection) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(manager: SqliteConnectionManager) -> r2d2::Pool<SqliteConnectionManager> {
        r2d2::Pool::builder().max_size(2).build(manager).unwrap()
    }

    #[test]
    fn memory_connections_share_one_database_per_manager() {
        let a = pool(SqliteConnectionManager::memory());
        a.get()
            .unwrap()
            .execute_batch("CREATE TABLE t (x INTEGER); INSERT INTO t VALUES (7);")
            .unwrap();
        // Another connection of the same pool sees it, after the first is returned.
        let x: i64 = a
            .get()
            .unwrap()
            .query_row("SELECT x FROM t", [], |r| r.get(0))
            .unwrap();
        assert_eq!(x, 7);
        // Another manager has its own database.
        let b = pool(SqliteConnectionManager::memory());
        assert!(b
            .get()
            .unwrap()
            .query_row("SELECT x FROM t", [], |r| r.get::<_, i64>(0))
            .is_err());
    }

    #[test]
    fn init_runs_on_every_connection_and_its_error_refuses_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        let manager = SqliteConnectionManager::file(&path)
            .with_init(|c| c.execute_batch("PRAGMA busy_timeout = 1234;"));
        let pool = pool(manager);
        let (c1, c2) = (pool.get().unwrap(), pool.get().unwrap());
        for c in [&c1, &c2] {
            let t: i64 = c
                .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
                .unwrap();
            assert_eq!(t, 1234);
        }

        let refusing = SqliteConnectionManager::file(&path)
            .with_init(|c| c.execute_batch("SELECT * FROM no_such_table"));
        assert!(r2d2::Pool::builder()
            .max_size(1)
            .connection_timeout(std::time::Duration::from_millis(200))
            .build(refusing)
            .is_err());
    }

    #[test]
    fn flags_are_used_to_open_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.sqlite");
        let manager = SqliteConnectionManager::file(&missing)
            .with_flags(OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_URI);
        // Without SQLITE_OPEN_CREATE a missing file is not created.
        assert!(r2d2::ManageConnection::connect(&manager).is_err());
        assert!(!missing.exists());
    }
}
