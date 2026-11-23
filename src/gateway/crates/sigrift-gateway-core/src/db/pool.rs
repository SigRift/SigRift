//! SQLite connection pool with WAL mode.

use crate::db::manager::SqliteConnectionManager;
use r2d2::Pool;
use rusqlite::OpenFlags;
use std::path::Path;

pub type DbPool = Pool<SqliteConnectionManager>;
pub type PooledConn = r2d2::PooledConnection<SqliteConnectionManager>;

/// Run `f` against `conn` on tokio's blocking thread pool and hand the
/// connection back. Use this for PBKDF2 credential checks (600k
/// iterations — hundreds of ms of CPU) so they never stall an async
/// worker thread. Returns `None` (logged) if the blocking task failed.
pub async fn with_conn_blocking<T, F>(conn: PooledConn, f: F) -> Option<(PooledConn, T)>
where
    F: FnOnce(&PooledConn) -> T + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(move || {
        let out = f(&conn);
        (conn, out)
    })
    .await
    {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::warn!(error = %e, "Blocking credential task failed");
            None
        }
    }
}

pub fn create_pool(
    db_path: &Path,
    pool_size: u32,
    busy_timeout_ms: u32,
) -> Result<DbPool, Box<dyn std::error::Error>> {
    let pragmas = format!(
        "PRAGMA journal_mode = WAL;
         PRAGMA busy_timeout = {busy_timeout_ms};
         PRAGMA synchronous = NORMAL;
         PRAGMA foreign_keys = ON;
         PRAGMA cache_size = -64000;
         PRAGMA mmap_size = 268435456;
         PRAGMA wal_autocheckpoint = 1000;
         PRAGMA journal_size_limit = 67108864;"
    );
    let manager = SqliteConnectionManager::file(db_path)
        .with_flags(
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .with_init(move |conn| conn.execute_batch(&pragmas));

    let pool = Pool::builder().max_size(pool_size).build(manager)?;
    Ok(pool)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A new database is put in WAL mode (the bridge's writer and the
    /// gateway's readers never block each other), and a pooled connection
    /// waits `busy_timeout_ms` for a lock instead of failing at once. The
    /// other tests' helpers switch their files to WAL before opening a
    /// pool, so this test is the one that notices a pool that stops doing it.
    #[test]
    fn a_pooled_connection_uses_wal_and_waits_for_locks() {
        let dir = tempfile::tempdir().unwrap();
        let pool = create_pool(&dir.path().join("new.db"), 1, 1_234).unwrap();
        let conn = pool.get().unwrap();
        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        let busy_timeout: i64 = conn
            .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
            .unwrap();
        assert_eq!((mode.as_str(), busy_timeout), ("wal", 1_234));
    }
}
