//! Session management — create, validate, delete, cleanup.
//! Matches Python's UserStore session methods in storage/users.py.

use crate::db::manager::SqliteConnectionManager;
use r2d2::PooledConnection;
use rusqlite::{params, OptionalExtension};
use serde::Serialize;
use tracing::debug;

use crate::auth::password;

/// Session validation result including joined user data.
#[derive(Debug, Clone, Serialize)]
pub struct ValidatedSession {
    pub session_id: i64,
    pub user_id: i64,
    pub username: String,
    pub role: String,
    pub display_name: String,
    pub email: String,
    pub enabled: bool,
    pub tenant_id: String,
    pub ip_address: String,
    pub user_agent: String,
    pub created_at: String,
    pub expires_at: String,
    pub last_active: Option<String>,
    pub mfa_enabled: bool,
    pub scope: String,
}

/// Configuration for session timeouts.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Absolute session timeout in hours (default 24).
    pub absolute_timeout_hours: i64,
    /// Idle timeout in minutes (default 30, per NIST 800-63B).
    pub idle_timeout_minutes: i64,
}

/// The largest absolute session timeout the gateway accepts, in hours:
/// 10,000,000 (about 1,141 years), the ceiling the bridge puts on an API
/// key's `expires_in_hours`. `PUT /api/admin/settings/security` refuses
/// a larger one. Session creation saturates whatever is set (see
/// [`session_expiry`]), so this keeps the expiry exact, not panic-free.
pub const MAX_ABSOLUTE_TIMEOUT_HOURS: i64 = 10_000_000;

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            absolute_timeout_hours: 24,
            idle_timeout_minutes: 30,
        }
    }
}

/// Format a UTC timestamp matching Python's `datetime.now(timezone.utc).isoformat()`.
fn utc_now_iso() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S+00:00")
        .to_string()
}

/// Parse a stored session timestamp, treating timezone-naive values as UTC
/// (as the bridge does).
///
/// Reads exactly one layout: `YYYY-MM-DD`, then `T` or one space, then
/// `HH:MM:SS`, an optional `.` with fraction digits, and an optional `Z` or
/// `±HH:MM` offset, every field at its full width. That covers every writer
/// of the sessions table: the gateway's `%Y-%m-%dT%H:%M:%S+00:00`, the
/// bridge's `isoformat()` (offset, optional microseconds; naive in legacy
/// rows) and SQLite's `datetime()` / `strftime('%f')`. Python's
/// `fromisoformat` reads every value those writers produce as the same
/// instant.
///
/// Anything else is `None`. That includes forms chrono's parsers take on
/// their own although `fromisoformat` refuses them (unpadded fields, a leap
/// second `:60`, a doubled separator or a leading space, a signed year, a
/// lowercase `z`), and forms no writer produces that `fromisoformat` reads
/// (`+0000` or `+02` offsets, a comma fraction, a lowercase `t` or another
/// separator, basic or date-only forms). Callers must treat `None` as a
/// failed check, never as "no limit".
pub(crate) fn parse_iso_datetime(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    use chrono::Timelike;
    if !has_stored_timestamp_layout(s) {
        return None;
    }
    // An offset or `Z` is RFC 3339 (with either separator); without one,
    // the time is naive UTC (`%.f` also matches no fraction at all).
    let parsed = chrono::DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .ok()
        .or_else(|| {
            ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%d %H:%M:%S%.f"]
                .into_iter()
                .find_map(|format| chrono::NaiveDateTime::parse_from_str(s, format).ok())
                .map(|naive| naive.and_utc())
        })?;
    // chrono reads a seconds field of 60 as a leap second (a nanosecond
    // count of a second or more); `fromisoformat` refuses it.
    (parsed.nanosecond() < 1_000_000_000).then_some(parsed)
}

/// Whether `s` has the layout [`parse_iso_datetime`] reads, where chrono's
/// parsers are lenient: the fixed-width date and time, and what may follow
/// them. Field values (month 13, hour 99), an empty fraction and the offset
/// after its sign are left to chrono, whose RFC 3339 parser reads only
/// `±HH:MM` there.
fn has_stored_timestamp_layout(s: &str) -> bool {
    /// In `layout`, `0` stands for an ASCII digit and `T` also for a space.
    fn fits(text: &[u8], layout: &[u8]) -> bool {
        text.len() == layout.len()
            && text.iter().zip(layout).all(|(&c, &l)| match l {
                b'0' => c.is_ascii_digit(),
                b'T' => c == b'T' || c == b' ',
                _ => c == l,
            })
    }
    const DATE_TIME: &[u8] = b"0000-00-00T00:00:00";
    let s = s.as_bytes();
    if s.len() < DATE_TIME.len() || !fits(&s[..DATE_TIME.len()], DATE_TIME) {
        return false;
    }
    let mut rest = &s[DATE_TIME.len()..];
    if let Some(fraction) = rest.strip_prefix(b".") {
        let digits = fraction.iter().take_while(|c| c.is_ascii_digit()).count();
        rest = &fraction[digits..];
    }
    matches!(rest, b"" | b"Z" | [b'+' | b'-', ..])
}

/// Why a session's stored times end it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TimeLimit {
    /// Past its absolute expiry.
    Expired,
    /// Idle for longer than the idle timeout.
    Idle,
    /// `expires_at`, or a non-NULL `last_active`, is not a timestamp, so
    /// its limit cannot be checked: the session fails closed.
    Unreadable,
}

/// Check a session's absolute expiry and idle timeout at `now`. `None`
/// means the session is within both limits.
///
/// A NULL `last_active` (sessions from before the column existed, or
/// inserted without it) carries no idle information, so only the absolute
/// limit applies. Any other value must parse — including `''`, which no
/// writer produces: treating it as "never active" would let it revive an
/// idle session with a fresh idle clock.
///
/// The bridge's `UserStore.get_session` applies the same rule in the same
/// order (`_session_time_limit` in storage/users.py): an unreadable
/// `expires_at` or non-NULL `last_active` refuses the session, and with
/// `touch` deletes it, as `validate_session` does here.
///
/// A huge `idle_timeout_minutes` saturates (no idle limit) instead of
/// overflowing. One below 1 would make every session idle:
/// `PUT /api/admin/settings/security` refuses it, and
/// `Config::session_config` reads such a
/// `BRIDGE_SESSION_IDLE_TIMEOUT_MINUTES` as the default.
pub(crate) fn session_time_limit(
    expires_at: &str,
    last_active: Option<&str>,
    idle_timeout_minutes: i64,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<TimeLimit> {
    let Some(expires_at) = parse_iso_datetime(expires_at) else {
        return Some(TimeLimit::Unreadable);
    };
    if now > expires_at {
        return Some(TimeLimit::Expired);
    }
    if let Some(last_active) = last_active {
        let Some(last_active) = parse_iso_datetime(last_active) else {
            return Some(TimeLimit::Unreadable);
        };
        if (now - last_active).num_seconds() > idle_timeout_minutes.saturating_mul(60) {
            return Some(TimeLimit::Idle);
        }
    }
    None
}

/// The latest expiry a session is given: the last second of year 9999.
/// The gateway's [`parse_iso_datetime`] and the bridge's
/// `datetime.fromisoformat` read four-digit years only, so a session that
/// expires later could not be read at its first use: the gateway would
/// delete it and the bridge refuse it.
fn latest_session_expiry() -> chrono::DateTime<chrono::Utc> {
    chrono::NaiveDate::from_ymd_opt(9999, 12, 31)
        .and_then(|day| day.and_hms_opt(23, 59, 59))
        .expect("9999-12-31T23:59:59 is a valid time")
        .and_utc()
}

/// When a session created at `now` expires: `absolute_timeout_hours`
/// later, but never after [`latest_session_expiry`]. This never panics.
/// A timeout too large for chrono saturates there too, and one too
/// negative for chrono gives `now`, a session that is already expired.
pub(crate) fn session_expiry(
    now: chrono::DateTime<chrono::Utc>,
    absolute_timeout_hours: i64,
) -> chrono::DateTime<chrono::Utc> {
    let latest = latest_session_expiry();
    match chrono::TimeDelta::try_hours(absolute_timeout_hours)
        .and_then(|lifetime| now.checked_add_signed(lifetime))
    {
        Some(expiry) => expiry.min(latest),
        None if absolute_timeout_hours > 0 => latest,
        None => now,
    }
}

/// Create a new full-scope session. Returns `(raw_token, session)`.
///
/// The raw token is returned to the client; its SHA-256 hash is stored in DB.
pub fn create_session(
    conn: &PooledConnection<SqliteConnectionManager>,
    user_id: i64,
    ip_address: &str,
    user_agent: &str,
    config: &SessionConfig,
) -> Result<(String, ValidatedSession), rusqlite::Error> {
    create_session_scoped(conn, user_id, ip_address, user_agent, "", config)
}

/// Create a new session with `scope` (`""` = full access, or a restricted
/// scope such as `mfa_setup_only` / `password_change_only`). The scope is
/// part of the INSERT, so a session never exists — not even briefly — with
/// more access than it was created for. Returns `(raw_token, session)`.
pub fn create_session_scoped(
    conn: &PooledConnection<SqliteConnectionManager>,
    user_id: i64,
    ip_address: &str,
    user_agent: &str,
    scope: &str,
    config: &SessionConfig,
) -> Result<(String, ValidatedSession), rusqlite::Error> {
    let token = password::generate_session_token();
    let hashed = password::hash_session_token(&token);
    let now = chrono::Utc::now();
    let expires_at = session_expiry(now, config.absolute_timeout_hours);
    let now_str = now.format("%Y-%m-%dT%H:%M:%S+00:00").to_string();
    let expires_str = expires_at.format("%Y-%m-%dT%H:%M:%S+00:00").to_string();

    conn.execute(
        "INSERT INTO sessions \
             (session_token, user_id, created_at, expires_at, ip_address, user_agent, \
              last_active, scope) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            hashed,
            user_id,
            now_str,
            expires_str,
            ip_address,
            user_agent,
            now_str,
            scope
        ],
    )?;
    let session_id = conn.last_insert_rowid();

    // Fetch joined user data for the response
    let session = conn.query_row(
        "SELECT s.id, s.user_id, u.username, u.role, u.display_name, u.email, \
                u.enabled, u.tenant_id, s.ip_address, s.user_agent, \
                s.created_at, s.expires_at, s.last_active, u.mfa_enabled, \
                COALESCE(s.scope, '') \
         FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.id = ?1",
        params![session_id],
        row_to_session,
    )?;

    Ok((token, session))
}

/// Set the scope of the session with this raw token. Returns true if the
/// session exists.
pub fn set_session_scope(
    conn: &PooledConnection<SqliteConnectionManager>,
    raw_token: &str,
    scope: &str,
) -> Result<bool, rusqlite::Error> {
    let updated = conn.execute(
        "UPDATE sessions SET scope = ?1 WHERE session_token = ?2",
        params![scope, password::hash_session_token(raw_token)],
    )?;
    Ok(updated > 0)
}

/// Refuse an existing foreign session before this instance can touch or expire
/// its record. Unknown tokens still follow the ordinary credential fallback.
pub fn session_belongs_to_instance(
    conn: &PooledConnection<SqliteConnectionManager>,
    raw_token: &str,
) -> Result<bool, rusqlite::Error> {
    let tenant = conn.query_row(
        "SELECT u.tenant_id FROM sessions s JOIN users u ON s.user_id=u.id WHERE s.session_token=?1",
        params![password::hash_session_token(raw_token)],
        |row| row.get::<_, rusqlite::types::Value>(0),
    ).optional()?;
    Ok(tenant.map_or(true, |value| {
        value == rusqlite::types::Value::Text(crate::auth::api_key::INSTANCE_TENANT.into())
    }))
}

/// Validate a session token. Returns the session with joined user data,
/// or `None` if invalid, expired, idle-timed-out, has an unreadable
/// expiry or last activity (see [`session_time_limit`]), or the user is
/// disabled. An expired, idle or unreadable session is deleted.
///
/// On success, and only then, touches `last_active`.
pub fn validate_session(
    conn: &PooledConnection<SqliteConnectionManager>,
    raw_token: &str,
    config: &SessionConfig,
) -> Result<Option<ValidatedSession>, rusqlite::Error> {
    let hashed = password::hash_session_token(raw_token);

    let session = match conn.query_row(
        "SELECT s.id, s.user_id, u.username, u.role, u.display_name, u.email, \
                u.enabled, u.tenant_id, s.ip_address, s.user_agent, \
                s.created_at, s.expires_at, s.last_active, u.mfa_enabled, \
                COALESCE(s.scope, '') \
         FROM sessions s JOIN users u ON s.user_id = u.id \
         WHERE s.session_token = ?1 AND u.tenant_id = ?2",
        params![hashed, crate::auth::api_key::INSTANCE_TENANT],
        row_to_session,
    ) {
        Ok(s) => s,
        Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
        Err(e) => return Err(e),
    };

    // Absolute expiry and idle timeout. A session past either, or whose
    // times cannot be read, is deleted — never kept without a limit.
    if let Some(limit) = session_time_limit(
        &session.expires_at,
        session.last_active.as_deref(),
        config.idle_timeout_minutes,
        chrono::Utc::now(),
    ) {
        debug!(
            session_id = session.session_id,
            ?limit,
            expires_at = %session.expires_at,
            last_active = ?session.last_active,
            idle_timeout_minutes = config.idle_timeout_minutes,
            "Session ended by its time limits"
        );
        conn.execute(
            "DELETE FROM sessions WHERE session_token = ?1",
            params![hashed],
        )?;
        return Ok(None);
    }

    // Check user is still enabled
    if !session.enabled {
        debug!(
            session_id = session.session_id,
            username = session.username,
            "Session rejected (user disabled)"
        );
        return Ok(None);
    }

    // Touch last_active
    let now_str = utc_now_iso();
    conn.execute(
        "UPDATE sessions SET last_active = ?1 WHERE session_token = ?2",
        params![now_str, hashed],
    )?;

    Ok(Some(session))
}

/// Delete a session (logout). Returns true if the session existed.
pub fn delete_session(
    conn: &PooledConnection<SqliteConnectionManager>,
    raw_token: &str,
) -> Result<bool, rusqlite::Error> {
    let hashed = password::hash_session_token(raw_token);
    let deleted = conn.execute(
        "DELETE FROM sessions WHERE session_token = ?1",
        params![hashed],
    )?;
    Ok(deleted > 0)
}

/// Delete all sessions for a user. Returns count deleted.
pub fn delete_user_sessions(
    conn: &PooledConnection<SqliteConnectionManager>,
    user_id: i64,
) -> Result<usize, rusqlite::Error> {
    let deleted = conn.execute("DELETE FROM sessions WHERE user_id = ?1", params![user_id])?;
    Ok(deleted)
}

/// Delete all sessions for a user except the one with the given token hash.
/// Used on password change to keep the current session alive.
pub fn delete_other_sessions(
    conn: &PooledConnection<SqliteConnectionManager>,
    user_id: i64,
    keep_token_hash: &str,
) -> Result<usize, rusqlite::Error> {
    let deleted = conn.execute(
        "DELETE FROM sessions WHERE user_id = ?1 AND session_token != ?2",
        params![user_id, keep_token_hash],
    )?;
    Ok(deleted)
}

/// Delete all expired sessions. Returns count deleted.
pub fn cleanup_expired_sessions(
    conn: &PooledConnection<SqliteConnectionManager>,
) -> Result<usize, rusqlite::Error> {
    let now_str = utc_now_iso();
    let deleted = conn.execute(
        "DELETE FROM sessions WHERE expires_at < ?1",
        params![now_str],
    )?;
    if deleted > 0 {
        debug!(deleted, "Cleaned up expired sessions");
    }
    Ok(deleted)
}

/// Admin-facing session metadata (includes username, excludes raw token hash).
#[derive(Debug, Clone, Serialize)]
pub struct SessionInfo {
    pub session_id: i64,
    pub username: String,
    pub role: String,
    pub ip_address: String,
    pub user_agent: String,
    pub created_at: String,
    pub expires_at: String,
    pub last_active: Option<String>,
    pub token_prefix: String,
}

/// Count active sessions for a user.
pub fn count_user_sessions(
    conn: &PooledConnection<SqliteConnectionManager>,
    user_id: i64,
) -> Result<i64, rusqlite::Error> {
    conn.query_row(
        "SELECT COUNT(*) FROM sessions WHERE user_id = ?1",
        params![user_id],
        |row| row.get(0),
    )
}

/// Delete oldest sessions for a user, keeping only `keep_count` most recent.
/// Returns the number of sessions deleted.
pub fn delete_oldest_sessions(
    conn: &PooledConnection<SqliteConnectionManager>,
    user_id: i64,
    keep_count: i64,
) -> Result<usize, rusqlite::Error> {
    let deleted = conn.execute(
        "DELETE FROM sessions WHERE user_id = ?1 AND id NOT IN \
         (SELECT id FROM sessions WHERE user_id = ?2 ORDER BY id DESC LIMIT ?3)",
        params![user_id, user_id, keep_count],
    )?;
    if deleted > 0 {
        debug!(user_id, deleted, keep_count, "Evicted oldest sessions");
    }
    Ok(deleted)
}

/// List all sessions for admin view (joined with users).
pub fn list_all_sessions(
    conn: &PooledConnection<SqliteConnectionManager>,
    tenant_id: &str,
) -> Result<Vec<SessionInfo>, rusqlite::Error> {
    let mut stmt = conn.prepare_cached(
        "SELECT s.id, u.username, u.role, s.ip_address, s.user_agent, \
                s.created_at, s.expires_at, s.last_active, s.session_token \
         FROM sessions s JOIN users u ON s.user_id = u.id \
         WHERE u.tenant_id = ?1 \
         ORDER BY s.created_at DESC",
    )?;
    let rows = stmt.query_map(params![tenant_id], |row| {
        let full_hash: String = row.get::<_, Option<String>>(8)?.unwrap_or_default();
        let prefix = if full_hash.len() >= 8 {
            full_hash[..8].to_string()
        } else {
            full_hash
        };
        Ok(SessionInfo {
            session_id: row.get(0)?,
            username: row.get(1)?,
            role: row.get(2)?,
            ip_address: row.get::<_, Option<String>>(3)?.unwrap_or_default(),
            user_agent: row.get::<_, Option<String>>(4)?.unwrap_or_default(),
            created_at: row.get(5)?,
            expires_at: row.get(6)?,
            last_active: row.get(7)?,
            token_prefix: prefix,
        })
    })?;
    rows.collect()
}

/// Shortest token-hash prefix accepted by [`delete_session_by_prefix`] —
/// the length the admin session listing shows.
pub const MIN_TOKEN_PREFIX_LEN: usize = 8;

/// Outcome of [`delete_session_by_prefix`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefixDelete {
    /// Exactly one session matched and was deleted.
    Deleted,
    /// No session matched.
    NotFound,
    /// More than one session matched; none was deleted.
    Ambiguous(usize),
    /// The prefix is not 8–64 hex characters; nothing was looked up.
    Invalid,
}

/// Delete the one session of a `tenant_id` user whose token hash starts
/// with `prefix`.
///
/// The prefix must be [`MIN_TOKEN_PREFIX_LEN`]–64 hex characters (session
/// tokens are stored as hex SHA-256), so it can never contain a `LIKE`
/// wildcard; it is escaped anyway. If the prefix matches several sessions
/// nothing is deleted — one admin action kills at most one session.
/// Sessions of other tenants' users (as [`list_all_sessions`] scopes them)
/// are invisible: never deleted and never counted, so a prefix matching
/// only those is [`PrefixDelete::NotFound`].
pub fn delete_session_by_prefix(
    conn: &PooledConnection<SqliteConnectionManager>,
    prefix: &str,
    tenant_id: &str,
) -> Result<PrefixDelete, rusqlite::Error> {
    let prefix = prefix.trim();
    if prefix.len() < MIN_TOKEN_PREFIX_LEN
        || prefix.len() > 64
        || !prefix.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Ok(PrefixDelete::Invalid);
    }
    let pattern = format!("{}%", escape_like(&prefix.to_ascii_lowercase()));
    // One statement: count and delete see the same rows.
    let deleted = conn.execute(
        "DELETE FROM sessions WHERE session_token LIKE ?1 ESCAPE '\\' \
           AND user_id IN (SELECT id FROM users WHERE tenant_id = ?2) \
           AND (SELECT COUNT(*) FROM sessions WHERE session_token LIKE ?1 ESCAPE '\\' \
                  AND user_id IN (SELECT id FROM users WHERE tenant_id = ?2)) = 1",
        params![pattern, tenant_id],
    )?;
    if deleted == 1 {
        return Ok(PrefixDelete::Deleted);
    }
    let matching: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sessions WHERE session_token LIKE ?1 ESCAPE '\\' \
           AND user_id IN (SELECT id FROM users WHERE tenant_id = ?2)",
        params![pattern, tenant_id],
        |row| row.get(0),
    )?;
    Ok(match matching {
        0 => PrefixDelete::NotFound,
        n => PrefixDelete::Ambiguous(n as usize),
    })
}

/// Escape `%`, `_` and the escape character itself for a `LIKE … ESCAPE '\'`.
fn escape_like(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn row_to_session(row: &rusqlite::Row<'_>) -> Result<ValidatedSession, rusqlite::Error> {
    Ok(ValidatedSession {
        session_id: row.get(0)?,
        user_id: row.get(1)?,
        username: row.get(2)?,
        role: row.get(3)?,
        display_name: row.get::<_, Option<String>>(4)?.unwrap_or_default(),
        email: row.get::<_, Option<String>>(5)?.unwrap_or_default(),
        enabled: row.get::<_, Option<bool>>(6)?.unwrap_or(true),
        tenant_id: row.get(7)?,
        ip_address: row.get::<_, Option<String>>(8)?.unwrap_or_default(),
        user_agent: row.get::<_, Option<String>>(9)?.unwrap_or_default(),
        created_at: row.get(10)?,
        expires_at: row.get(11)?,
        last_active: row.get(12)?,
        mfa_enabled: row.get::<_, Option<bool>>(13)?.unwrap_or(false),
        scope: row.get::<_, Option<String>>(14)?.unwrap_or_default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::api_key::INSTANCE_TENANT;
    use crate::storage::users::tests::insert_user;
    use crate::test_support;

    fn insert_raw_session(conn: &PooledConnection<SqliteConnectionManager>, user: i64, hash: &str) {
        conn.execute(
            "INSERT INTO sessions (session_token, user_id, created_at, expires_at) \
             VALUES (?1, ?2, '2026-01-01T00:00:00+00:00', '2099-01-01T00:00:00+00:00')",
            params![hash, user],
        )
        .unwrap();
    }

    fn count(conn: &PooledConnection<SqliteConnectionManager>) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0))
            .unwrap()
    }

    /// Regression (G13): the prefix went straight into LIKE, so `%`
    /// (`DELETE /api/admin/sessions/%25`) or `_` deleted every session.
    #[test]
    fn prefix_delete_rejects_wildcards_and_short_or_ambiguous_prefixes() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let user = insert_user(&conn, "alice", "viewer", true);
        insert_raw_session(&conn, user, &format!("aaaaaaaa1{}", "0".repeat(55)));
        insert_raw_session(&conn, user, &format!("aaaaaaaa2{}", "0".repeat(55)));
        insert_raw_session(&conn, user, &format!("bbbbbbbb{}", "0".repeat(56)));

        for bad in [
            "%", "%%%%%%%%", "________", "aaaaaaa", "aaaaaaa%", "zzzzzzzz", "",
        ] {
            assert_eq!(
                delete_session_by_prefix(&conn, bad, INSTANCE_TENANT).unwrap(),
                PrefixDelete::Invalid,
                "{bad:?}"
            );
        }
        assert_eq!(count(&conn), 3, "nothing deleted");

        assert_eq!(
            delete_session_by_prefix(&conn, "aaaaaaaa", INSTANCE_TENANT).unwrap(),
            PrefixDelete::Ambiguous(2)
        );
        assert_eq!(count(&conn), 3, "an ambiguous prefix deletes nothing");
        assert_eq!(
            delete_session_by_prefix(&conn, "cccccccc", INSTANCE_TENANT).unwrap(),
            PrefixDelete::NotFound
        );
        assert_eq!(
            delete_session_by_prefix(&conn, "AAAAAAAA2", INSTANCE_TENANT).unwrap(),
            PrefixDelete::Deleted
        );
        assert_eq!(
            delete_session_by_prefix(&conn, "bbbbbbbb", INSTANCE_TENANT).unwrap(),
            PrefixDelete::Deleted
        );
        assert_eq!(count(&conn), 1);
    }

    #[test]
    fn escape_like_escapes_wildcards() {
        assert_eq!(escape_like(r"a%b_c\d"), r"a\%b\_c\\d");
    }

    #[test]
    fn scoped_session_is_created_with_its_scope() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let user = insert_user(&conn, "alice", "viewer", true);
        let config = SessionConfig::default();
        let (token, session) = create_session_scoped(
            &conn,
            user,
            "1.2.3.4",
            "ua",
            "password_change_only",
            &config,
        )
        .unwrap();
        assert_eq!(session.scope, "password_change_only");
        assert_eq!(session.ip_address, "1.2.3.4");
        assert!(set_session_scope(&conn, &token, "").unwrap());
        let session = validate_session(&conn, &token, &config).unwrap().unwrap();
        assert_eq!(session.scope, "");
        let (_, full) = create_session(&conn, user, "", "", &config).unwrap();
        assert_eq!(full.scope, "");
    }

    // ── Security paths: creation, validation, expiry, revocation ──────

    type Conn = PooledConnection<SqliteConnectionManager>;

    fn hash(token: &str) -> String {
        password::hash_session_token(token)
    }

    /// Overwrite one column of the session with this raw token.
    fn set_session_column(conn: &Conn, token: &str, column: &str, value: &str) {
        let updated = conn
            .execute(
                &format!("UPDATE sessions SET {column} = ?1 WHERE session_token = ?2"),
                params![value, hash(token)],
            )
            .unwrap();
        assert_eq!(updated, 1, "session row exists");
    }

    fn session_row_exists(conn: &Conn, token: &str) -> bool {
        conn.query_row(
            "SELECT COUNT(*) FROM sessions WHERE session_token = ?1",
            params![hash(token)],
            |r| r.get::<_, i64>(0),
        )
        .unwrap()
            == 1
    }

    fn is_valid(conn: &Conn, token: &str) -> bool {
        validate_session(conn, token, &SessionConfig::default())
            .unwrap()
            .is_some()
    }

    fn timestamp_ago(minutes: i64) -> String {
        (chrono::Utc::now() - chrono::Duration::minutes(minutes))
            .format("%Y-%m-%dT%H:%M:%S+00:00")
            .to_string()
    }

    fn session(conn: &Conn, user: i64) -> String {
        create_session(conn, user, "", "", &SessionConfig::default())
            .unwrap()
            .0
    }

    /// A database leak must not yield usable sessions: the raw token is
    /// never stored, and presenting the stored hash does not authenticate.
    #[test]
    fn session_tokens_are_random_and_stored_only_hashed() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let user = insert_user(&conn, "alice", "viewer", true);
        let a = session(&conn, user);
        let b = session(&conn, user);

        assert_ne!(a, b, "every session gets a fresh token");
        for token in [&a, &b] {
            assert_eq!(token.len(), 64);
            assert!(token.bytes().all(|c| c.is_ascii_hexdigit()));
            let raw_rows: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sessions WHERE session_token = ?1",
                    params![token],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(raw_rows, 0, "raw token is never persisted");
            assert!(session_row_exists(&conn, token));
            assert!(is_valid(&conn, token));
            assert!(
                !is_valid(&conn, &hash(token)),
                "the stored hash is not itself a credential"
            );
        }
    }

    #[test]
    fn unknown_tokens_are_rejected_without_side_effects() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let user = insert_user(&conn, "alice", "viewer", true);
        let real = session(&conn, user);

        for bogus in ["", "nonexistent", &"0".repeat(64)] {
            assert!(!is_valid(&conn, bogus), "{bogus:?}");
            assert!(!delete_session(&conn, bogus).unwrap(), "{bogus:?}");
            assert!(!set_session_scope(&conn, bogus, "").unwrap(), "{bogus:?}");
        }
        assert_eq!(count(&conn), 1);
        assert!(is_valid(&conn, &real));
    }

    #[test]
    fn validation_refreshes_last_active() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let user = insert_user(&conn, "alice", "viewer", true);
        let token = session(&conn, user);
        let stale = timestamp_ago(10);
        set_session_column(&conn, &token, "last_active", &stale);

        let validated = validate_session(&conn, &token, &SessionConfig::default())
            .unwrap()
            .unwrap();
        assert_eq!(validated.user_id, user);
        assert_eq!(validated.username, "alice");
        let touched: String = conn
            .query_row(
                "SELECT last_active FROM sessions WHERE session_token = ?1",
                params![hash(&token)],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            parse_iso_datetime(&touched).unwrap() > parse_iso_datetime(&stale).unwrap(),
            "activity moves the idle clock forward: {touched}"
        );
    }

    /// Past the absolute lifetime a session is refused and removed, whatever
    /// format the expiry was written in (the bridge writes Python
    /// `isoformat()`, possibly naive or with microseconds).
    #[test]
    fn absolutely_expired_sessions_are_refused_and_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let user = insert_user(&conn, "alice", "viewer", true);

        for expiry in [
            "2020-01-01T00:00:00+00:00",
            "2020-01-01T00:00:00.123456+00:00",
            "2020-01-01T00:00:00",
            "2020-01-01T00:00:00.123456",
            &timestamp_ago(1),
        ] {
            let token = session(&conn, user);
            set_session_column(&conn, &token, "expires_at", expiry);
            assert!(!is_valid(&conn, &token), "expired at {expiry}");
            assert!(!session_row_exists(&conn, &token), "{expiry}: deleted");
        }
    }

    #[test]
    fn idle_sessions_are_refused_and_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let user = insert_user(&conn, "alice", "viewer", true);
        let idle = session(&conn, user);
        let active = session(&conn, user);
        set_session_column(&conn, &idle, "last_active", &timestamp_ago(31));
        set_session_column(&conn, &active, "last_active", &timestamp_ago(25));

        assert!(!is_valid(&conn, &idle), "31 min idle > 30 min default");
        assert!(!session_row_exists(&conn, &idle));
        assert!(is_valid(&conn, &active));

        // The configured idle timeout is the one enforced.
        let strict = SessionConfig {
            idle_timeout_minutes: 5,
            ..SessionConfig::default()
        };
        set_session_column(&conn, &active, "last_active", &timestamp_ago(6));
        assert!(validate_session(&conn, &active, &strict).unwrap().is_none());
        assert!(!session_row_exists(&conn, &active));
    }

    #[test]
    fn configured_absolute_lifetime_is_applied_at_creation() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let user = insert_user(&conn, "alice", "viewer", true);
        let config = SessionConfig {
            absolute_timeout_hours: 2,
            ..SessionConfig::default()
        };
        let (_, created) = create_session(&conn, user, "", "", &config).unwrap();
        let lifetime = parse_iso_datetime(&created.expires_at).unwrap()
            - parse_iso_datetime(&created.created_at).unwrap();
        assert_eq!(lifetime, chrono::Duration::hours(2));
    }

    /// Regression: `now + Duration::hours(absolute_timeout_hours)` panicked
    /// for a timeout of about 2.3e9 hours and more (`DateTime + TimeDelta`
    /// overflowed, or `TimeDelta::hours` out of bounds), so every login
    /// dropped its connection. From about 7e7 hours it wrote an expiry past
    /// year 9999 (`+10012-...`), which neither the gateway nor the bridge
    /// can read, so the session was deleted at its first use. The expiry
    /// now saturates at the last second of year 9999 and the session
    /// validates; a timeout too negative for chrono expires the session
    /// instead of panicking.
    #[test]
    fn a_huge_absolute_timeout_saturates_at_the_last_readable_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let user = insert_user(&conn, "alice", "viewer", true);
        let config = |absolute_timeout_hours| SessionConfig {
            absolute_timeout_hours,
            ..SessionConfig::default()
        };

        for hours in [
            70_000_000,
            100_000_000,
            2_300_000_000,
            2_562_047_788_015,
            2_562_047_788_016,
            i64::MAX,
        ] {
            let (token, created) = create_session(&conn, user, "", "", &config(hours)).unwrap();
            assert_eq!(created.expires_at, "9999-12-31T23:59:59+00:00", "{hours} h");
            assert!(
                validate_session(&conn, &token, &config(hours))
                    .unwrap()
                    .is_some(),
                "{hours} h"
            );
        }

        // Below the saturation point the timeout is applied as given.
        let (_, created) = create_session(&conn, user, "", "", &config(10_000_000)).unwrap();
        let lifetime = parse_iso_datetime(&created.expires_at).unwrap()
            - parse_iso_datetime(&created.created_at).unwrap();
        assert_eq!(lifetime, chrono::Duration::hours(10_000_000));

        for hours in [-2_562_047_788_016, i64::MIN] {
            let (token, _) = create_session(&conn, user, "", "", &config(hours)).unwrap();
            assert!(!is_valid(&conn, &token), "{hours} h");
        }
    }

    #[test]
    fn disabled_users_sessions_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let user = insert_user(&conn, "alice", "viewer", true);
        let token = session(&conn, user);
        conn.execute("UPDATE users SET enabled = 0 WHERE id = ?1", params![user])
            .unwrap();
        assert!(!is_valid(&conn, &token));
    }

    /// A malformed absolute expiry must fail closed (the bridge rejects
    /// such a session) instead of disabling the absolute timeout. The row
    /// is deleted like an expired one: the periodic cleanup compares
    /// strings and would never remove a value such as `never`.
    #[test]
    fn unparseable_expiry_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let user = insert_user(&conn, "alice", "viewer", true);
        for expiry in ["", "never", "2099-13-45T99:99:99+00:00"] {
            let token = session(&conn, user);
            set_session_column(&conn, &token, "expires_at", expiry);
            assert!(!is_valid(&conn, &token), "expires_at = {expiry:?}");
            assert!(!session_row_exists(&conn, &token), "{expiry:?}: deleted");
        }
    }

    /// The same for the idle timeout: a `last_active` that is present but
    /// unreadable (`''` included, which no writer produces) refuses and
    /// deletes the session — it must not be accepted and then revived by
    /// the touch with a fresh idle clock. A NULL `last_active` (sessions
    /// from before the column, or inserted without it) means "no idle
    /// information": only the absolute limit applies, and the touch then
    /// starts the idle clock.
    #[test]
    fn unparseable_last_active_fails_closed_and_null_has_no_idle_limit() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let user = insert_user(&conn, "alice", "viewer", true);
        for last_active in ["", " ", "garbage", "2099-13-45T99:99:99+00:00"] {
            let token = session(&conn, user);
            set_session_column(&conn, &token, "last_active", last_active);
            assert!(!is_valid(&conn, &token), "last_active = {last_active:?}");
            assert!(
                !session_row_exists(&conn, &token),
                "{last_active:?}: deleted"
            );
        }

        let token = session(&conn, user);
        conn.execute(
            "UPDATE sessions SET last_active = NULL WHERE session_token = ?1",
            params![hash(&token)],
        )
        .unwrap();
        assert!(is_valid(&conn, &token), "NULL last_active");
        let touched: Option<String> = conn
            .query_row(
                "SELECT last_active FROM sessions WHERE session_token = ?1",
                params![hash(&token)],
                |r| r.get(0),
            )
            .unwrap();
        assert!(touched.as_deref().and_then(parse_iso_datetime).is_some());
    }

    /// The time limits come before the disabled-user refusal: a disabled
    /// user's session with unreadable times is deleted like any other,
    /// while one within its limits is refused but kept (as the bridge
    /// does). No refusal touches `last_active`.
    #[test]
    fn disabled_users_sessions_are_refused_after_the_time_limits() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let user = insert_user(&conn, "alice", "viewer", true);
        let unreadable = session(&conn, user);
        set_session_column(&conn, &unreadable, "expires_at", "garbage");
        let kept = session(&conn, user);
        let stale = timestamp_ago(10);
        set_session_column(&conn, &kept, "last_active", &stale);
        conn.execute("UPDATE users SET enabled = 0 WHERE id = ?1", params![user])
            .unwrap();

        assert!(!is_valid(&conn, &unreadable));
        assert!(!session_row_exists(&conn, &unreadable), "deleted");
        assert!(!is_valid(&conn, &kept));
        let last_active: String = conn
            .query_row(
                "SELECT last_active FROM sessions WHERE session_token = ?1",
                params![hash(&kept)],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(last_active, stale, "kept, and not touched");
    }

    /// SQLite's own `datetime()` format (space separator, no offset) is a
    /// real timestamp — Python's `fromisoformat` reads it and the bridge
    /// expires such a session. The gateway must enforce it too: a past one
    /// is refused *as expired* (and its row deleted, like any expired
    /// session), while a future one stays valid, so the refusal is the
    /// expiry check and not a blanket rejection of the format.
    #[test]
    fn sqlite_datetime_expiry_is_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let user = insert_user(&conn, "alice", "viewer", true);
        for expiry in ["2020-01-01 00:00:00", "2020-01-01 00:00:00.123456"] {
            let token = session(&conn, user);
            set_session_column(&conn, &token, "expires_at", expiry);
            assert!(!is_valid(&conn, &token), "expired at {expiry:?}");
            assert!(!session_row_exists(&conn, &token), "{expiry:?}: deleted");
        }
        let live = session(&conn, user);
        set_session_column(&conn, &live, "expires_at", "2099-01-01 00:00:00");
        assert!(is_valid(&conn, &live), "a future expiry in this format");
    }

    /// The formats the gateway and the bridge write, and SQLite's, as
    /// stored timestamps. `strftime` patterns, so the tests below can write
    /// any instant in each.
    const STORED_FORMATS: [&str; 7] = [
        "%Y-%m-%dT%H:%M:%S+00:00",     // gateway
        "%Y-%m-%dT%H:%M:%S%.6f+00:00", // bridge isoformat(), aware
        "%Y-%m-%dT%H:%M:%SZ",          // RFC 3339 `Z`
        "%Y-%m-%dT%H:%M:%S",           // legacy naive isoformat()
        "%Y-%m-%dT%H:%M:%S%.6f",       // legacy naive, microseconds
        "%Y-%m-%d %H:%M:%S",           // SQLite datetime()
        "%Y-%m-%d %H:%M:%S%.6f",       // SQLite, fractional
    ];

    #[test]
    fn parse_iso_datetime_reads_every_stored_format_as_utc() {
        let at = chrono::DateTime::parse_from_rfc3339("2026-03-04T05:06:07.123456+00:00")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let whole = at - chrono::Duration::microseconds(123_456);
        for format in STORED_FORMATS {
            let text = at.format(format).to_string();
            let expected = if format.contains("%.6f") { at } else { whole };
            assert_eq!(parse_iso_datetime(&text), Some(expected), "{text:?}");
        }
        // An offset other than UTC is applied, whatever the separator.
        for text in [
            "2026-03-04T07:06:07+02:00",
            "2026-03-04 07:06:07+02:00",
            "2026-03-04T03:06:07-02:00",
            "2026-03-04T05:06:07-00:00",
            "2026-03-04 05:06:07Z",
        ] {
            assert_eq!(parse_iso_datetime(text), Some(whole), "{text:?}");
        }
        // A fraction of any length (SQLite's strftime('%f') writes 3
        // digits; fromisoformat, too, reads more than 6).
        for (text, micros) in [
            ("2026-03-04T05:06:07.1", 100_000),
            ("2026-03-04T05:06:07.123", 123_000),
            ("2026-03-04 05:06:07.123456789+00:00", 123_456),
            ("2026-03-04T05:06:07.1234567890", 123_456),
        ] {
            let parsed = parse_iso_datetime(text).unwrap();
            assert_eq!(
                (parsed - whole).num_microseconds(),
                Some(micros),
                "{text:?}"
            );
        }
        // Not a timestamp, or a form no writer produces: refused, which
        // the callers treat as a failed check.
        for text in [
            "",
            " ",
            "garbage",
            "never",
            "2026-13-45T99:99:99+00:00",
            "1772600767",
            "12026-03-04T05:06:07",
            "2026-03-04T05:06:07.",
            "2026-03-04T05:06:07 ",
            "2026-03-04T05:06:07Z+00:00",
            // chrono's parsers take these on their own, and fromisoformat
            // refuses them: unpadded or space-padded fields, a leap second,
            // a doubled separator, a signed year, lowercase `z`, a leading
            // space.
            "2026-3-4 5:6:7",
            "2026-03-04T 5:06:07",
            "2026-03-04T23:59:60",
            "2026-03-04T23:59:60+00:00",
            "2026-03-04  05:06:07",
            "+12026-03-04T05:06:07",
            "2026-03-04T05:06:07z",
            " 2026-03-04T05:06:07",
            // fromisoformat reads these: date-only, no seconds, basic
            // format, colon-less or short offsets, a comma fraction, other
            // separators (chrono's RFC 3339 parser also takes `t`).
            "2026-03-04",
            "2026-03-04T05:06",
            "20260304T050607",
            "2026-03-04T05:06:07+0000",
            "2026-03-04T05:06:07+02",
            "2026-03-04T05:06:07,5",
            "2026-03-04t05:06:07+00:00",
            "2026-03-04X05:06:07",
        ] {
            assert_eq!(parse_iso_datetime(text), None, "{text:?}");
        }
    }

    /// Both limits are enforced whichever stored format the time is in: a
    /// past expiry and a 31-minute idle are refused and deleted, a future
    /// expiry and a 25-minute idle are kept.
    #[test]
    fn both_limits_are_enforced_in_every_stored_format() {
        use chrono::Duration;
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let user = insert_user(&conn, "alice", "viewer", true);
        for format in STORED_FORMATS {
            for (column, offset, alive) in [
                ("expires_at", Duration::seconds(-60), false),
                ("expires_at", Duration::seconds(120), true),
                ("last_active", Duration::minutes(-31), false),
                ("last_active", Duration::minutes(-25), true),
            ] {
                let token = session(&conn, user);
                let value = (chrono::Utc::now() + offset).format(format).to_string();
                set_session_column(&conn, &token, column, &value);
                assert_eq!(is_valid(&conn, &token), alive, "{column} = {value:?}");
                assert_eq!(
                    session_row_exists(&conn, &token),
                    alive,
                    "{column} = {value:?}"
                );
            }
        }
    }

    #[test]
    fn session_time_limit_names_the_limit_and_fails_closed() {
        use chrono::Duration;
        let now = chrono::Utc::now();
        let at = |offset: Duration| (now + offset).format("%Y-%m-%dT%H:%M:%S+00:00").to_string();
        let future = at(Duration::hours(1));
        let past = at(Duration::seconds(-1));
        let recent = at(Duration::minutes(-29));
        let idle = at(Duration::minutes(-31));
        for (expires_at, last_active, expected) in [
            (future.as_str(), None, None),
            (future.as_str(), Some(recent.as_str()), None),
            (past.as_str(), None, Some(TimeLimit::Expired)),
            (future.as_str(), Some(idle.as_str()), Some(TimeLimit::Idle)),
            ("garbage", None, Some(TimeLimit::Unreadable)),
            ("", Some(recent.as_str()), Some(TimeLimit::Unreadable)),
            (future.as_str(), Some(""), Some(TimeLimit::Unreadable)),
            (
                future.as_str(),
                Some("garbage"),
                Some(TimeLimit::Unreadable),
            ),
            // The absolute limit is checked first.
            (past.as_str(), Some("garbage"), Some(TimeLimit::Expired)),
            (past.as_str(), Some(idle.as_str()), Some(TimeLimit::Expired)),
        ] {
            assert_eq!(
                session_time_limit(expires_at, last_active, 30, now),
                expected,
                "expires_at = {expires_at:?}, last_active = {last_active:?}"
            );
        }
    }

    /// An idle timeout too large to count in seconds is no idle limit. It
    /// must not overflow: that panics in a debug build, and in a release
    /// build wraps to a negative limit that makes every session idle (and
    /// `validate_session` then deletes them all).
    #[test]
    fn a_huge_idle_timeout_saturates_instead_of_overflowing() {
        use chrono::Duration;
        let now = chrono::Utc::now();
        let at = |offset: Duration| (now + offset).format("%Y-%m-%dT%H:%M:%S+00:00").to_string();
        let future = at(Duration::hours(1));
        for last_active in [at(Duration::minutes(-1)), "2000-01-01T00:00:00".into()] {
            for minutes in [i64::MAX / 60 + 1, i64::MAX] {
                assert_eq!(
                    session_time_limit(&future, Some(&last_active), minutes, now),
                    None,
                    "{minutes} min, last active {last_active}"
                );
            }
        }
    }

    /// A session of another tenant's user is not valid on this instance,
    /// and this instance neither touches nor expires its record.
    #[test]
    fn foreign_tenant_sessions_are_refused_and_left_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let local = insert_user(&conn, "alice", "viewer", true);
        let foreign = insert_user(&conn, "mallory", "admin", true);
        conn.execute(
            "UPDATE users SET tenant_id = 'other' WHERE id = ?1",
            params![foreign],
        )
        .unwrap();
        let local_token = session(&conn, local);
        let foreign_token = session(&conn, foreign);
        // Idle and expired: a local session in this state would be deleted.
        let stale = "2020-01-01T00:00:00+00:00";
        set_session_column(&conn, &foreign_token, "last_active", stale);
        set_session_column(&conn, &foreign_token, "expires_at", stale);

        assert!(session_belongs_to_instance(&conn, &local_token).unwrap());
        assert!(!session_belongs_to_instance(&conn, &foreign_token).unwrap());
        assert!(
            session_belongs_to_instance(&conn, "unknown-token").unwrap(),
            "unknown tokens fall through to other credentials"
        );

        assert!(!is_valid(&conn, &foreign_token));
        let (expires_at, last_active): (String, String) = conn
            .query_row(
                "SELECT expires_at, last_active FROM sessions WHERE session_token = ?1",
                params![hash(&foreign_token)],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            (expires_at.as_str(), last_active.as_str()),
            (stale, stale),
            "foreign record neither touched nor deleted"
        );
        assert!(is_valid(&conn, &local_token));
    }

    #[test]
    fn bulk_revocation_is_limited_to_the_named_user() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let alice = insert_user(&conn, "alice", "viewer", true);
        let bob = insert_user(&conn, "bob", "viewer", true);
        let keep = session(&conn, alice);
        let other = session(&conn, alice);
        let bobs = session(&conn, bob);

        assert_eq!(
            delete_other_sessions(&conn, alice, &hash(&keep)).unwrap(),
            1
        );
        assert!(is_valid(&conn, &keep), "the kept session survives");
        assert!(!is_valid(&conn, &other));
        assert!(is_valid(&conn, &bobs));

        assert_eq!(delete_user_sessions(&conn, alice).unwrap(), 1);
        assert!(!is_valid(&conn, &keep));
        assert!(is_valid(&conn, &bobs));
        assert_eq!(delete_user_sessions(&conn, alice).unwrap(), 0);
    }

    #[test]
    fn logout_deletes_only_the_presented_session() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let user = insert_user(&conn, "alice", "viewer", true);
        let gone = session(&conn, user);
        let kept = session(&conn, user);

        assert!(delete_session(&conn, &gone).unwrap());
        assert!(!is_valid(&conn, &gone));
        assert!(!delete_session(&conn, &gone).unwrap(), "already logged out");
        assert!(is_valid(&conn, &kept));
    }

    #[test]
    fn cleanup_removes_only_expired_sessions() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let user = insert_user(&conn, "alice", "viewer", true);
        let expired = session(&conn, user);
        let python_expired = session(&conn, user);
        let live = session(&conn, user);
        set_session_column(&conn, &expired, "expires_at", &timestamp_ago(1));
        set_session_column(
            &conn,
            &python_expired,
            "expires_at",
            "2020-01-01T00:00:00.123456+00:00",
        );

        assert_eq!(cleanup_expired_sessions(&conn).unwrap(), 2);
        assert!(!session_row_exists(&conn, &expired));
        assert!(!session_row_exists(&conn, &python_expired));
        assert!(is_valid(&conn, &live));
        assert_eq!(cleanup_expired_sessions(&conn).unwrap(), 0);
    }

    #[test]
    fn session_cap_evicts_the_oldest_sessions_of_that_user_only() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let alice = insert_user(&conn, "alice", "viewer", true);
        let bob = insert_user(&conn, "bob", "viewer", true);
        let bobs = session(&conn, bob);
        let tokens: Vec<String> = (0..4).map(|_| session(&conn, alice)).collect();

        assert_eq!(delete_oldest_sessions(&conn, alice, 2).unwrap(), 2);
        assert_eq!(count_user_sessions(&conn, alice).unwrap(), 2);
        assert!(!is_valid(&conn, &tokens[0]));
        assert!(!is_valid(&conn, &tokens[1]));
        assert!(is_valid(&conn, &tokens[2]));
        assert!(is_valid(&conn, &tokens[3]), "the newest session survives");
        assert!(is_valid(&conn, &bobs));
    }

    #[test]
    fn prefix_delete_accepts_up_to_the_full_hash_and_trims_whitespace() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let user = insert_user(&conn, "alice", "viewer", true);
        let a = session(&conn, user);
        let b = session(&conn, user);

        assert_eq!(
            delete_session_by_prefix(&conn, &format!("{}0", hash(&a)), INSTANCE_TENANT).unwrap(),
            PrefixDelete::Invalid,
            "longer than a SHA-256 hex digest"
        );
        assert_eq!(
            delete_session_by_prefix(&conn, &hash(&a), INSTANCE_TENANT).unwrap(),
            PrefixDelete::Deleted
        );
        assert!(!is_valid(&conn, &a));
        assert_eq!(
            delete_session_by_prefix(&conn, &format!("  {}\n", &hash(&b)[..10]), INSTANCE_TENANT)
                .unwrap(),
            PrefixDelete::Deleted
        );
        assert!(!is_valid(&conn, &b));
    }

    /// The prefix match sees the named tenant's sessions only (as the
    /// listing does): another tenant's are neither deleted nor counted, so
    /// a prefix matching only those is not found, never ambiguous.
    #[test]
    fn prefix_delete_is_scoped_to_the_tenant() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let local = insert_user(&conn, "alice", "viewer", true);
        let foreign = insert_user(&conn, "mallory", "admin", true);
        conn.execute(
            "UPDATE users SET tenant_id = 'other' WHERE id = ?1",
            params![foreign],
        )
        .unwrap();
        let local_hash = format!("aaaaaaaa1{}", "0".repeat(55));
        let foreign_hash = format!("aaaaaaaa2{}", "0".repeat(55));
        insert_raw_session(&conn, local, &local_hash);
        insert_raw_session(&conn, foreign, &foreign_hash);
        insert_raw_session(&conn, foreign, &format!("bbbbbbbb1{}", "0".repeat(55)));
        insert_raw_session(&conn, foreign, &format!("bbbbbbbb2{}", "0".repeat(55)));
        let exists = |hash: &str| {
            conn.query_row(
                "SELECT COUNT(*) FROM sessions WHERE session_token = ?1",
                params![hash],
                |r| r.get::<_, i64>(0),
            )
            .unwrap()
                == 1
        };

        for prefix in ["bbbbbbbb", "bbbbbbbb1", &foreign_hash] {
            assert_eq!(
                delete_session_by_prefix(&conn, prefix, INSTANCE_TENANT).unwrap(),
                PrefixDelete::NotFound,
                "{prefix}"
            );
        }
        assert_eq!(count(&conn), 4, "no foreign session deleted");

        // The tenant passed is the one matched, not a fixed one.
        assert_eq!(
            delete_session_by_prefix(&conn, "bbbbbbbb", "other").unwrap(),
            PrefixDelete::Ambiguous(2)
        );
        assert_eq!(
            delete_session_by_prefix(&conn, "aaaaaaaa", "other").unwrap(),
            PrefixDelete::Deleted
        );
        assert!(!exists(&foreign_hash));
        assert!(exists(&local_hash), "the other tenant's kill spares ours");
        assert_eq!(
            delete_session_by_prefix(&conn, "aaaaaaaa", INSTANCE_TENANT).unwrap(),
            PrefixDelete::Deleted
        );
        assert!(!exists(&local_hash));
        assert_eq!(count(&conn), 2);
    }

    /// The absolute expiry and the idle timeout apply once they are
    /// reached (the idle timeout is in minutes), an expired or idle
    /// session is deleted, and one inside both limits is kept and has its
    /// idle timer restarted.
    #[test]
    fn validate_session_applies_the_absolute_and_idle_limits_when_reached() {
        use chrono::Duration;
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let user = insert_user(&conn, "alice", "viewer", true);
        let config = SessionConfig {
            absolute_timeout_hours: 24,
            idle_timeout_minutes: 30,
        };
        let rows = |token: &str| -> i64 {
            conn.query_row(
                "SELECT COUNT(*) FROM sessions WHERE session_token = ?1",
                params![password::hash_session_token(token)],
                |r| r.get(0),
            )
            .unwrap()
        };
        for (column, offset, alive) in [
            ("expires_at", Duration::seconds(-60), false),
            ("expires_at", Duration::seconds(120), true),
            ("last_active", Duration::minutes(-31), false),
            ("last_active", Duration::minutes(-25), true),
        ] {
            let (token, _) = create_session(&conn, user, "", "", &config).unwrap();
            let value = (chrono::Utc::now() + offset)
                .format("%Y-%m-%dT%H:%M:%S+00:00")
                .to_string();
            conn.execute(
                &format!("UPDATE sessions SET {column} = ?1 WHERE session_token = ?2"),
                params![value, password::hash_session_token(&token)],
            )
            .unwrap();
            let session = validate_session(&conn, &token, &config).unwrap();
            assert_eq!(session.is_some(), alive, "{column} = {value}");
            assert_eq!(rows(&token), i64::from(alive), "{column} = {value}");
            if alive {
                let touched: String = conn
                    .query_row(
                        "SELECT last_active FROM sessions WHERE session_token = ?1",
                        params![password::hash_session_token(&token)],
                        |r| r.get(0),
                    )
                    .unwrap();
                let idle = chrono::Utc::now() - parse_iso_datetime(&touched).unwrap();
                assert!(idle < Duration::seconds(60), "{column}: {touched}");
            }
        }

        // A new session lasts the configured absolute timeout.
        let short = SessionConfig {
            absolute_timeout_hours: 2,
            idle_timeout_minutes: 30,
        };
        let (_, session) = create_session(&conn, user, "", "", &short).unwrap();
        let lifetime = parse_iso_datetime(&session.expires_at).unwrap()
            - parse_iso_datetime(&session.created_at).unwrap();
        assert_eq!(lifetime, Duration::hours(2));
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;
    use crate::storage::users::tests::insert_user;
    use crate::test_support;

    /// A session past its expiry stays refused when it cannot be deleted:
    /// validation reports the storage error (the middleware answers 503),
    /// never the session. Once the delete works it is deleted.
    #[test]
    fn an_expired_session_that_cannot_be_deleted_is_still_refused() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let config = SessionConfig::default();
        let user = insert_user(&conn, "alice", "viewer", true);
        let (token, _) = create_session(&conn, user, "", "", &config).unwrap();
        conn.execute_batch(
            "UPDATE sessions SET expires_at = '2020-01-01T00:00:00+00:00'; \
             CREATE TRIGGER keep_sessions BEFORE DELETE ON sessions \
             BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
        )
        .unwrap();

        assert!(validate_session(&conn, &token, &config).is_err());
        assert!(validate_session(&conn, &token, &config).is_err(), "again");
        conn.execute_batch("DROP TRIGGER keep_sessions").unwrap();
        assert!(validate_session(&conn, &token, &config).unwrap().is_none());
        assert_eq!(count_user_sessions(&conn, user).unwrap(), 0);
    }

    /// Session writes report a storage failure as an error, never as
    /// "nothing to change": a new session whose joined read-back fails is
    /// not handed out, and with the table unreadable the scope change, the
    /// expiry sweep and the session-cap eviction all fail.
    #[test]
    fn session_writes_report_storage_failures() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let config = SessionConfig::default();
        let user = insert_user(&conn, "alice", "viewer", true);
        let (token, _) = create_session(&conn, user, "", "", &config).unwrap();

        // A username stored as a blob: the joined user row cannot be read.
        conn.execute("UPDATE users SET username = X'00' WHERE id = ?1", [user])
            .unwrap();
        assert!(matches!(
            create_session(&conn, user, "", "", &config),
            Err(rusqlite::Error::InvalidColumnType(..))
        ));

        conn.execute_batch("ALTER TABLE sessions RENAME TO sessions_unavailable")
            .unwrap();
        assert!(set_session_scope(&conn, &token, "").is_err());
        assert!(cleanup_expired_sessions(&conn).is_err());
        assert!(delete_oldest_sessions(&conn, user, 1).is_err());
    }

    /// The admin listing shows at most the first eight characters of a
    /// stored token hash; a shorter stored value (a damaged row) is listed
    /// as it is rather than failing the listing.
    #[test]
    fn the_listing_shows_a_short_stored_token_as_it_is() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let user = insert_user(&conn, "alice", "viewer", true);
        for token in ["abc", "0123456789abcdef"] {
            conn.execute(
                "INSERT INTO sessions (session_token, user_id, created_at, expires_at) \
                 VALUES (?1, ?2, '2026-01-01T00:00:00+00:00', '2099-01-01T00:00:00+00:00')",
                params![token, user],
            )
            .unwrap();
        }
        let mut prefixes: Vec<String> = list_all_sessions(&conn, "default")
            .unwrap()
            .into_iter()
            .map(|s| s.token_prefix)
            .collect();
        prefixes.sort();
        assert_eq!(prefixes, ["01234567", "abc"]);
    }

    /// A kill by a prefix that matches several sessions deletes none of
    /// them, then counts them to say so. If that count cannot be read the
    /// outcome is the storage error, never "not found" (the admin would be
    /// told the session is gone while it lives on) nor an ambiguity count
    /// nobody read; the sessions are untouched.
    #[test]
    fn a_kill_whose_match_count_cannot_be_read_reports_the_error() {
        use rusqlite::hooks::{AuthContext, Authorization};
        use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
        use std::sync::Arc;

        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let mut conn = state.db_pool.get().unwrap();
        let user = insert_user(&conn, "alice", "viewer", true);
        for tail in ["1", "2"] {
            conn.execute(
                "INSERT INTO sessions (session_token, user_id, created_at, expires_at) \
                 VALUES (?1, ?2, '2026-01-01T00:00:00+00:00', '2099-01-01T00:00:00+00:00')",
                params![format!("abababab{tail}{}", "0".repeat(55)), user],
            )
            .unwrap();
        }
        assert_eq!(
            delete_session_by_prefix(&conn, "abababab", "default").unwrap(),
            PrefixDelete::Ambiguous(2),
            "control"
        );

        // Once the delete (which removes nothing) has committed, every
        // statement compiled on this connection is refused: only the count
        // that follows it is.
        let committed = Arc::new(AtomicBool::new(false));
        let on_commit = Arc::clone(&committed);
        conn.commit_hook(Some(move || {
            on_commit.store(true, SeqCst);
            false
        }))
        .unwrap();
        let after_commit = Arc::clone(&committed);
        conn.authorizer(Some(move |_: AuthContext<'_>| {
            if after_commit.load(SeqCst) {
                Authorization::Deny
            } else {
                Authorization::Allow
            }
        }))
        .unwrap();
        let outcome = delete_session_by_prefix(&conn, "abababab", "default");
        conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>)
            .unwrap();
        conn.commit_hook(None::<fn() -> bool>).unwrap();

        assert!(committed.load(SeqCst), "the delete ran");
        assert!(
            matches!(
                &outcome,
                Err(rusqlite::Error::SqliteFailure(e, _))
                    if e.code == rusqlite::ErrorCode::AuthorizationForStatementDenied
            ),
            "{outcome:?}"
        );
        assert_eq!(count_user_sessions(&conn, user).unwrap(), 2);
    }
}
