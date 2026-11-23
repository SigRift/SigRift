//! Rate limiting and account lockout — matches Python's storage/security_state.py.
//!
//! Uses DB-backed sliding window counters with REAL (Unix float) timestamps.

use crate::db::manager::SqliteConnectionManager;
use r2d2::PooledConnection;
use rusqlite::params;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;

/// The longest account-lockout window (`UC_LOCKOUT_WINDOW`, the settings
/// API's `lockout_window_secs`) the gateway accepts, in seconds (24 h).
///
/// The `account_lockout` table is bridge-owned and shared: the bridge's
/// periodic cleanup prunes it too, and keeps failures for its
/// `LOCKOUT_RETENTION` (bridge/storage/security_state.py), which is at
/// least this long. A longer window would count failures that cleanup
/// has already deleted, so a locked account would be unlocked early.
pub const MAX_LOCKOUT_WINDOW_SECS: u64 = 86_400;

/// Configuration for rate limiting and account lockout.
#[derive(Debug, Clone)]
pub struct SecurityLimits {
    /// Max login attempts per IP within the rate limit window.
    pub rate_limit_max: u32,
    /// Rate limit window in seconds.
    pub rate_limit_window_secs: f64,
    /// Max failed attempts per account within the lockout window.
    pub lockout_max: u32,
    /// Lockout window in seconds.
    pub lockout_window_secs: f64,
}

impl Default for SecurityLimits {
    fn default() -> Self {
        Self {
            rate_limit_max: 5,
            rate_limit_window_secs: 60.0,
            lockout_max: 10,
            lockout_window_secs: 1800.0,
        }
    }
}

/// Result of cleanup_all.
#[derive(Debug, Default)]
pub struct CleanupCounts {
    pub login_attempts: usize,
    pub account_lockout: usize,
}

fn now_unix() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}

// ── Rate limiting (per IP) ─────────────────────────────────────────────

/// Count a login attempt from `client_ip`, if the IP is not rate limited.
///
/// Returns `false` (recording nothing) when `client_ip` already has
/// `rate_limit_max` attempts in the window, else records one and returns
/// `true`. That is the bridge's `_check_login_rate` (count, refuse at
/// `count >= RATE_LIMIT_MAX`, record only an attempt that passes): exactly
/// `rate_limit_max` attempts are allowed per window, and a refused attempt
/// does not keep the IP limited. Unlike the bridge's two statements, the
/// count and the insert are one autocommit `INSERT … SELECT` (as in
/// [`reserve_account_attempt`]), so N parallel attempts, also from other
/// connections or the bridge process, can never all see "below the
/// limit". Call it outside any transaction, so the row is committed (and
/// counted by every other attempt) at once.
pub fn reserve_login_attempt(
    conn: &PooledConnection<SqliteConnectionManager>,
    client_ip: &str,
    tenant_id: &str,
    rate_limit_max: u32,
    window_secs: f64,
) -> Result<bool, rusqlite::Error> {
    let now = now_unix();
    let cutoff = now - window_secs;
    let reserved = conn.execute(
        "INSERT INTO rate_limit_login (client_ip, attempt_at, tenant_id) \
         SELECT ?1, ?2, ?3 WHERE ( \
             SELECT COUNT(*) FROM rate_limit_login \
             WHERE client_ip = ?1 AND attempt_at > ?4 AND tenant_id = ?3) < ?5",
        params![client_ip, now, tenant_id, cutoff, rate_limit_max],
    )?;
    Ok(reserved == 1)
}

/// Record a login attempt from a client IP, unconditionally. The login
/// uses [`reserve_login_attempt`], which records only allowed attempts.
pub fn record_login_attempt(
    conn: &PooledConnection<SqliteConnectionManager>,
    client_ip: &str,
    tenant_id: &str,
) -> Result<(), rusqlite::Error> {
    conn.execute(
        "INSERT INTO rate_limit_login (client_ip, attempt_at, tenant_id) VALUES (?1, ?2, ?3)",
        params![client_ip, now_unix(), tenant_id],
    )?;
    Ok(())
}

/// Count recent login attempts from a client IP within the sliding window.
pub fn count_recent_login_attempts(
    conn: &PooledConnection<SqliteConnectionManager>,
    client_ip: &str,
    tenant_id: &str,
    window_secs: f64,
) -> Result<u32, rusqlite::Error> {
    let cutoff = now_unix() - window_secs;
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM rate_limit_login \
         WHERE client_ip = ?1 AND attempt_at > ?2 AND tenant_id = ?3",
        params![client_ip, cutoff, tenant_id],
        |row| row.get(0),
    )?;
    Ok(count as u32)
}

/// Delete expired rate limit entries. Returns count deleted.
pub fn cleanup_login_attempts(
    conn: &PooledConnection<SqliteConnectionManager>,
    tenant_id: &str,
    window_secs: f64,
) -> Result<usize, rusqlite::Error> {
    let cutoff = now_unix() - window_secs;
    let deleted = conn.execute(
        "DELETE FROM rate_limit_login WHERE attempt_at <= ?1 AND tenant_id = ?2",
        params![cutoff, tenant_id],
    )?;
    debug!(deleted, "Cleaned up login attempt records");
    Ok(deleted)
}

// ── Account lockout (per username) ─────────────────────────────────────

/// Count a login attempt for `username` as a failure, if it is not locked.
///
/// Returns `false` (recording nothing) when `username` already has
/// `lockout_max` failures in the window, else records one and returns
/// `true` — the bridge's `SecurityStateStore.reserve_account_attempt`. The
/// count and the insert are one autocommit `INSERT … SELECT`, so the check
/// and the reservation are atomic, also across connections and with the
/// bridge process sharing the table: N parallel attempts can never all see
/// "below the limit". Call it outside any transaction and before the
/// password check, so the row is committed (and visible to every other
/// attempt) while the check runs. A successful login clears it with
/// [`clear_account_failures`].
pub fn reserve_account_attempt(
    conn: &PooledConnection<SqliteConnectionManager>,
    username: &str,
    tenant_id: &str,
    lockout_max: u32,
    window_secs: f64,
) -> Result<bool, rusqlite::Error> {
    let now = now_unix();
    let cutoff = now - window_secs;
    let reserved = conn.execute(
        "INSERT INTO account_lockout (username, failure_at, tenant_id) \
         SELECT ?1, ?2, ?3 WHERE ( \
             SELECT COUNT(*) FROM account_lockout \
             WHERE username = ?1 AND failure_at > ?4 AND tenant_id = ?3) < ?5",
        params![username, now, tenant_id, cutoff, lockout_max],
    )?;
    Ok(reserved == 1)
}

/// Record a failed login attempt for a username.
pub fn record_account_failure(
    conn: &PooledConnection<SqliteConnectionManager>,
    username: &str,
    tenant_id: &str,
) -> Result<(), rusqlite::Error> {
    conn.execute(
        "INSERT INTO account_lockout (username, failure_at, tenant_id) VALUES (?1, ?2, ?3)",
        params![username, now_unix(), tenant_id],
    )?;
    Ok(())
}

/// Count recent failures for a username within the lockout window.
pub fn count_recent_failures(
    conn: &PooledConnection<SqliteConnectionManager>,
    username: &str,
    tenant_id: &str,
    window_secs: f64,
) -> Result<u32, rusqlite::Error> {
    let cutoff = now_unix() - window_secs;
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM account_lockout \
         WHERE username = ?1 AND failure_at > ?2 AND tenant_id = ?3",
        params![username, cutoff, tenant_id],
        |row| row.get(0),
    )?;
    Ok(count as u32)
}

/// Clear all failure records for a username (called on successful login).
pub fn clear_account_failures(
    conn: &PooledConnection<SqliteConnectionManager>,
    username: &str,
    tenant_id: &str,
) -> Result<usize, rusqlite::Error> {
    let deleted = conn.execute(
        "DELETE FROM account_lockout WHERE username = ?1 AND tenant_id = ?2",
        params![username, tenant_id],
    )?;
    Ok(deleted)
}

/// Delete expired lockout entries. Returns count deleted.
pub fn cleanup_account_lockout(
    conn: &PooledConnection<SqliteConnectionManager>,
    tenant_id: &str,
    window_secs: f64,
) -> Result<usize, rusqlite::Error> {
    let cutoff = now_unix() - window_secs;
    let deleted = conn.execute(
        "DELETE FROM account_lockout WHERE failure_at <= ?1 AND tenant_id = ?2",
        params![cutoff, tenant_id],
    )?;
    debug!(deleted, "Cleaned up account lockout records");
    Ok(deleted)
}

// ── Combined cleanup ───────────────────────────────────────────────────

/// Run all security state cleanups. Returns counts by type.
pub fn cleanup_all(
    conn: &PooledConnection<SqliteConnectionManager>,
    tenant_id: &str,
    config: &SecurityLimits,
) -> Result<CleanupCounts, rusqlite::Error> {
    let login_attempts = cleanup_login_attempts(conn, tenant_id, config.rate_limit_window_secs)?;
    let account_lockout = cleanup_account_lockout(conn, tenant_id, config.lockout_window_secs)?;
    Ok(CleanupCounts {
        login_attempts,
        account_lockout,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support;

    type Conn = PooledConnection<SqliteConnectionManager>;

    /// The bridge-owned tables (same DDL as the login tests use).
    const SECURITY_TABLES: &str =
        "CREATE TABLE rate_limit_login (id INTEGER PRIMARY KEY AUTOINCREMENT, \
         client_ip TEXT NOT NULL, attempt_at REAL NOT NULL, \
         tenant_id TEXT NOT NULL DEFAULT 'default'); \
         CREATE TABLE account_lockout (id INTEGER PRIMARY KEY AUTOINCREMENT, \
         username TEXT NOT NULL, failure_at REAL NOT NULL, \
         tenant_id TEXT NOT NULL DEFAULT 'default');";

    fn conn_with_tables(dir: &tempfile::TempDir) -> Conn {
        let state = test_support::app_state(dir);
        let conn = state.db_pool.get().unwrap();
        conn.execute_batch(SECURITY_TABLES).unwrap();
        conn
    }

    /// Insert a row dated `age_secs` ago (no sleeping to age records).
    fn backdate(conn: &Conn, table: &str, key_col: &str, key: &str, tenant: &str, age: f64) {
        let ts_col = if table == "rate_limit_login" {
            "attempt_at"
        } else {
            "failure_at"
        };
        conn.execute(
            &format!("INSERT INTO {table} ({key_col}, {ts_col}, tenant_id) VALUES (?1, ?2, ?3)"),
            params![key, now_unix() - age, tenant],
        )
        .unwrap();
    }

    /// The defaults are the bridge's policy (5 logins/min per IP, 10
    /// failures per 30 min per account): weakening them is a policy change.
    #[test]
    fn default_limits_match_the_bridge_policy() {
        let limits = SecurityLimits::default();
        assert_eq!(limits.rate_limit_max, 5);
        assert_eq!(limits.rate_limit_window_secs, 60.0);
        assert_eq!(limits.lockout_max, 10);
        assert_eq!(limits.lockout_window_secs, 1800.0);
    }

    #[test]
    fn login_attempts_are_counted_per_ip_and_tenant_within_the_window() {
        let dir = tempfile::tempdir().unwrap();
        let conn = conn_with_tables(&dir);
        for _ in 0..3 {
            record_login_attempt(&conn, "198.51.100.1", "default").unwrap();
        }
        record_login_attempt(&conn, "198.51.100.2", "default").unwrap();
        record_login_attempt(&conn, "198.51.100.1", "other").unwrap();
        backdate(
            &conn,
            "rate_limit_login",
            "client_ip",
            "198.51.100.1",
            "default",
            120.0,
        );

        assert_eq!(
            count_recent_login_attempts(&conn, "198.51.100.1", "default", 60.0).unwrap(),
            3,
            "other IPs, other tenants and attempts outside the window do not count"
        );
        assert_eq!(
            count_recent_login_attempts(&conn, "198.51.100.1", "default", 300.0).unwrap(),
            4,
            "a wider window includes the older attempt"
        );
        assert_eq!(
            count_recent_login_attempts(&conn, "198.51.100.2", "default", 60.0).unwrap(),
            1
        );
        assert_eq!(
            count_recent_login_attempts(&conn, "203.0.113.9", "default", 60.0).unwrap(),
            0
        );
    }

    /// A login reservation succeeds (and records one attempt) until the IP
    /// has `rate_limit_max` attempts in the window — exactly that many are
    /// allowed — and a refused one records nothing, so it does not keep
    /// the IP limited. Only that IP in that tenant within the window
    /// counts, the same `> cutoff` window as [`count_recent_login_attempts`].
    #[test]
    fn login_reservations_stop_at_the_rate_limit_and_record_nothing_beyond_it() {
        let dir = tempfile::tempdir().unwrap();
        let conn = conn_with_tables(&dir);
        let ip = "198.51.100.1";
        // Outside the window, another IP, another tenant: none count.
        backdate(&conn, "rate_limit_login", "client_ip", ip, "default", 120.0);
        for _ in 0..5 {
            record_login_attempt(&conn, "198.51.100.2", "default").unwrap();
            record_login_attempt(&conn, ip, "other").unwrap();
        }

        for n in 1..=3 {
            assert!(
                reserve_login_attempt(&conn, ip, "default", 3, 60.0).unwrap(),
                "attempt {n} is within the limit"
            );
            assert_eq!(
                count_recent_login_attempts(&conn, ip, "default", 60.0).unwrap(),
                n
            );
        }
        for _ in 0..2 {
            assert!(!reserve_login_attempt(&conn, ip, "default", 3, 60.0).unwrap());
        }
        assert_eq!(
            count_recent_login_attempts(&conn, ip, "default", 60.0).unwrap(),
            3,
            "a refused reservation records nothing"
        );
        assert!(
            !reserve_login_attempt(&conn, ip, "default", 4, 180.0).unwrap(),
            "a wider window includes the old attempt (3 recent + 1 old = 4)"
        );
        assert!(!reserve_login_attempt(&conn, "198.51.100.2", "default", 3, 60.0).unwrap());
        assert!(!reserve_login_attempt(&conn, ip, "other", 3, 60.0).unwrap());
        assert!(
            reserve_login_attempt(&conn, "203.0.113.9", "default", 1, 60.0).unwrap(),
            "a limit of one allows one attempt"
        );
        assert!(!reserve_login_attempt(&conn, "203.0.113.9", "default", 1, 60.0).unwrap());
        assert!(
            !reserve_login_attempt(&conn, "203.0.113.10", "default", 0, 60.0).unwrap(),
            "a zero limit refuses every attempt"
        );

        // Once the allowed attempts leave the window the IP is let in again
        // (the refused ones after them left nothing behind).
        conn.execute(
            "UPDATE rate_limit_login SET attempt_at = attempt_at - 61.0 \
             WHERE client_ip = ?1 AND tenant_id = 'default'",
            [ip],
        )
        .unwrap();
        assert!(reserve_login_attempt(&conn, ip, "default", 3, 60.0).unwrap());
    }

    /// Several connections reserving at once can never exceed the rate
    /// limit (the count and the insert are one statement, not a read then
    /// a write) and record exactly the attempts they allowed.
    #[test]
    fn concurrent_login_reservations_never_exceed_the_rate_limit() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        state
            .db_pool
            .get()
            .unwrap()
            .execute_batch(SECURITY_TABLES)
            .unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let (pool, barrier) = (state.db_pool.clone(), barrier.clone());
                std::thread::spawn(move || {
                    let conn = pool.get().unwrap();
                    barrier.wait();
                    (0..25)
                        .filter(|_| {
                            reserve_login_attempt(&conn, "198.51.100.1", "default", 10, 60.0)
                                .unwrap()
                        })
                        .count()
                })
            })
            .collect();
        let reserved: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(reserved, 10);
        let conn = state.db_pool.get().unwrap();
        assert_eq!(
            count_recent_login_attempts(&conn, "198.51.100.1", "default", 60.0).unwrap(),
            10
        );
    }

    /// The race of the test above, forced rather than hoped for: two
    /// connections reserve the last attempt (`rate_limit_max = 1`) while
    /// another one holds the write lock. The reservation is one statement
    /// that waits whole for the lock, so the second to get it counts the
    /// first one's row and is refused. A count then an insert (two
    /// statements, as in the bridge) would count 0 twice at once and record
    /// two attempts.
    #[test]
    fn login_reservations_queued_behind_a_writer_never_exceed_the_rate_limit() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        state
            .db_pool
            .get()
            .unwrap()
            .execute_batch(SECURITY_TABLES)
            .unwrap();
        let gate = test_support::WriteLockGate::<0>::close(&state.db_pool);
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let pool = state.db_pool.clone();
                std::thread::spawn(move || {
                    let conn = pool.get().unwrap();
                    reserve_login_attempt(&conn, "198.51.100.1", "default", 1, 60.0).unwrap()
                })
            })
            .collect();
        gate.open_when_queued(2);
        let reserved = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|&reserved| reserved)
            .count();
        assert_eq!(reserved, 1);
        let conn = state.db_pool.get().unwrap();
        assert_eq!(
            count_recent_login_attempts(&conn, "198.51.100.1", "default", 60.0).unwrap(),
            1
        );
    }

    #[test]
    fn account_failures_are_counted_per_user_and_tenant_within_the_window() {
        let dir = tempfile::tempdir().unwrap();
        let conn = conn_with_tables(&dir);
        for _ in 0..4 {
            record_account_failure(&conn, "alice", "default").unwrap();
        }
        record_account_failure(&conn, "bob", "default").unwrap();
        record_account_failure(&conn, "alice", "other").unwrap();
        backdate(
            &conn,
            "account_lockout",
            "username",
            "alice",
            "default",
            3600.0,
        );

        assert_eq!(
            count_recent_failures(&conn, "alice", "default", 1800.0).unwrap(),
            4
        );
        assert_eq!(
            count_recent_failures(&conn, "ALICE", "default", 1800.0).unwrap(),
            0,
            "usernames are matched exactly"
        );
        assert_eq!(
            count_recent_failures(&conn, "bob", "default", 1800.0).unwrap(),
            1
        );
        assert_eq!(
            count_recent_failures(&conn, "alice", "other", 1800.0).unwrap(),
            1
        );
    }

    /// A reservation succeeds (and records one failure) until the account
    /// has `lockout_max` failures in the window; a refused one records
    /// nothing. Only that account in that tenant within the window counts,
    /// the same `> cutoff` window as [`count_recent_failures`].
    #[test]
    fn reservations_stop_at_the_lockout_limit_and_record_nothing_beyond_it() {
        let dir = tempfile::tempdir().unwrap();
        let conn = conn_with_tables(&dir);
        // Outside the window, another account, another tenant: none count.
        backdate(
            &conn,
            "account_lockout",
            "username",
            "alice",
            "default",
            3600.0,
        );
        for _ in 0..5 {
            record_account_failure(&conn, "bob", "default").unwrap();
            record_account_failure(&conn, "alice", "other").unwrap();
        }

        for n in 1..=3 {
            assert!(
                reserve_account_attempt(&conn, "alice", "default", 3, 1800.0).unwrap(),
                "attempt {n} is below the limit"
            );
            assert_eq!(
                count_recent_failures(&conn, "alice", "default", 1800.0).unwrap(),
                n
            );
        }
        for _ in 0..2 {
            assert!(!reserve_account_attempt(&conn, "alice", "default", 3, 1800.0).unwrap());
        }
        assert_eq!(
            count_recent_failures(&conn, "alice", "default", 1800.0).unwrap(),
            3,
            "a refused reservation records nothing"
        );
        assert!(
            !reserve_account_attempt(&conn, "alice", "default", 4, 3660.0).unwrap(),
            "a wider window includes the old failure (3 recent + 1 old = 4)"
        );
        assert!(
            reserve_account_attempt(&conn, "ALICE", "default", 3, 1800.0).unwrap(),
            "usernames are matched exactly"
        );
        assert!(!reserve_account_attempt(&conn, "bob", "default", 3, 1800.0).unwrap());
        assert!(!reserve_account_attempt(&conn, "alice", "other", 3, 1800.0).unwrap());
        assert!(
            !reserve_account_attempt(&conn, "carol", "default", 0, 1800.0).unwrap(),
            "a zero limit refuses every attempt"
        );

        clear_account_failures(&conn, "alice", "default").unwrap();
        assert!(reserve_account_attempt(&conn, "alice", "default", 3, 1800.0).unwrap());
    }

    /// Two connections reserving at once can never exceed the limit (the
    /// count and the insert are one statement, not a read then a write).
    #[test]
    fn concurrent_reservations_never_exceed_the_limit() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        state
            .db_pool
            .get()
            .unwrap()
            .execute_batch(SECURITY_TABLES)
            .unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let (pool, barrier) = (state.db_pool.clone(), barrier.clone());
                std::thread::spawn(move || {
                    let conn = pool.get().unwrap();
                    barrier.wait();
                    (0..25)
                        .filter(|_| {
                            reserve_account_attempt(&conn, "alice", "default", 10, 1800.0).unwrap()
                        })
                        .count()
                })
            })
            .collect();
        let reserved: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(reserved, 10);
        let conn = state.db_pool.get().unwrap();
        assert_eq!(
            count_recent_failures(&conn, "alice", "default", 1800.0).unwrap(),
            10
        );
    }

    /// A successful login clears that account's failures only.
    #[test]
    fn clearing_failures_is_limited_to_one_account_in_one_tenant() {
        let dir = tempfile::tempdir().unwrap();
        let conn = conn_with_tables(&dir);
        for user in ["alice", "alice", "bob"] {
            record_account_failure(&conn, user, "default").unwrap();
        }
        record_account_failure(&conn, "alice", "other").unwrap();

        assert_eq!(
            clear_account_failures(&conn, "alice", "default").unwrap(),
            2
        );
        assert_eq!(
            count_recent_failures(&conn, "alice", "default", 1800.0).unwrap(),
            0
        );
        assert_eq!(
            count_recent_failures(&conn, "bob", "default", 1800.0).unwrap(),
            1
        );
        assert_eq!(
            count_recent_failures(&conn, "alice", "other", 1800.0).unwrap(),
            1
        );
        assert_eq!(
            clear_account_failures(&conn, "alice", "default").unwrap(),
            0
        );
    }

    /// Cleanup only drops records that can no longer affect a decision:
    /// a still-active lockout survives it, including failures that are
    /// late in the window (a cleanup cutting the window short would
    /// shorten every lockout).
    #[test]
    fn cleanup_drops_only_expired_records_of_the_tenant() {
        let dir = tempfile::tempdir().unwrap();
        let conn = conn_with_tables(&dir);
        let limits = SecurityLimits::default();
        record_login_attempt(&conn, "198.51.100.1", "default").unwrap();
        // Inside the window (60 s), near its end.
        backdate(
            &conn,
            "rate_limit_login",
            "client_ip",
            "198.51.100.1",
            "default",
            50.0,
        );
        // Inside the window (1800 s), near its end.
        backdate(
            &conn,
            "account_lockout",
            "username",
            "alice",
            "default",
            1740.0,
        );
        backdate(
            &conn,
            "rate_limit_login",
            "client_ip",
            "198.51.100.1",
            "default",
            61.0,
        );
        backdate(
            &conn,
            "rate_limit_login",
            "client_ip",
            "198.51.100.1",
            "other",
            61.0,
        );
        for _ in 0..limits.lockout_max {
            record_account_failure(&conn, "alice", "default").unwrap();
        }
        backdate(
            &conn,
            "account_lockout",
            "username",
            "alice",
            "default",
            1801.0,
        );
        backdate(
            &conn,
            "account_lockout",
            "username",
            "alice",
            "other",
            1801.0,
        );

        let counts = cleanup_all(&conn, "default", &limits).unwrap();
        assert_eq!(counts.login_attempts, 1, "only the attempt past the window");
        assert_eq!(
            counts.account_lockout, 1,
            "only the failure past the window"
        );
        assert_eq!(
            count_recent_failures(&conn, "alice", "default", limits.lockout_window_secs).unwrap(),
            limits.lockout_max + 1,
            "an active lockout is not cleaned away, not even its oldest failure"
        );
        assert_eq!(
            count_recent_login_attempts(
                &conn,
                "198.51.100.1",
                "default",
                limits.rate_limit_window_secs
            )
            .unwrap(),
            2,
            "attempts still inside the rate-limit window survive"
        );
        let other_rows: i64 = conn
            .query_row(
                "SELECT (SELECT COUNT(*) FROM rate_limit_login WHERE tenant_id = 'other') + \
                        (SELECT COUNT(*) FROM account_lockout WHERE tenant_id = 'other')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(other_rows, 2, "another tenant's records are untouched");

        let again = cleanup_all(&conn, "default", &limits).unwrap();
        assert_eq!((again.login_attempts, again.account_lockout), (0, 0));
    }

    /// The bridge's periodic cleanup keeps `account_lockout` failures for
    /// its `LOCKOUT_RETENTION` (bridge/storage/security_state.py). The
    /// longest lockout window the gateway accepts must not exceed it, or
    /// that cleanup deletes failures the gateway still counts and unlocks
    /// the account early.
    #[test]
    fn the_bridge_keeps_lockout_failures_for_the_longest_gateway_window() {
        let source_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../sigrift/bridge/storage/security_state.py");
        let source = std::fs::read_to_string(&source_path)
            .unwrap_or_else(|e| panic!("{}: {e}", source_path.display()));
        let line = source
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with("LOCKOUT_RETENTION: float = "))
            .expect("LOCKOUT_RETENTION in bridge/storage/security_state.py");
        let retention: f64 = line
            .trim_start_matches("LOCKOUT_RETENTION: float = ")
            .replace('_', "")
            .parse()
            .unwrap_or_else(|e| panic!("{line}: {e}"));
        assert!(
            retention >= MAX_LOCKOUT_WINDOW_SECS as f64,
            "the bridge keeps lockout failures {retention} s, the gateway \
             accepts a {MAX_LOCKOUT_WINDOW_SECS} s window"
        );
    }

    #[test]
    fn missing_tables_are_reported_as_errors() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        assert!(record_login_attempt(&conn, "198.51.100.1", "default").is_err());
        assert!(count_recent_login_attempts(&conn, "198.51.100.1", "default", 60.0).is_err());
        assert!(reserve_login_attempt(&conn, "198.51.100.1", "default", 5, 60.0).is_err());
        assert!(record_account_failure(&conn, "alice", "default").is_err());
        assert!(count_recent_failures(&conn, "alice", "default", 60.0).is_err());
        assert!(reserve_account_attempt(&conn, "alice", "default", 10, 60.0).is_err());
        assert!(cleanup_all(&conn, "default", &SecurityLimits::default()).is_err());
    }
}
