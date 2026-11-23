//! MFA storage operations — tokens, backup codes, replay cache, tenant settings.
//!
//! Functions use pooled SQLite connections and `prepare_cached` for repeated
//! queries. Atomic backup-code replacement requires a mutable connection.

use crate::db::manager::SqliteConnectionManager;
use r2d2::PooledConnection;
use rusqlite::params;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info};

use crate::auth::fernet_enc;
use crate::auth::password;
use crate::storage::users;

const TOTP_REUSE_TTL: f64 = 90.0; // 3 × 30-second periods

fn now_unix() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}

fn utc_now_iso() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S+00:00")
        .to_string()
}

// ── TOTP Secret Management (users table) ──────────────────────────────

/// Store an encrypted TOTP secret for a user.
///
/// In production (`production == true`) a missing or invalid `mfa_key`
/// is an error — the secret is never stored unencrypted.
pub fn set_totp_secret(
    conn: &PooledConnection<SqliteConnectionManager>,
    user_id: i64,
    secret: &str,
    mfa_key: &str,
    production: bool,
) -> Result<bool, rusqlite::Error> {
    let encrypted = encrypt_secret(secret, mfa_key, production)?;
    let updated = conn.execute(
        "UPDATE users SET totp_secret = ?1 WHERE id = ?2",
        params![encrypted, user_id],
    )?;
    Ok(updated > 0)
}

/// `secret` as stored ([`fernet_enc::encrypt_totp_secret`]).
fn encrypt_secret(
    secret: &str,
    mfa_key: &str,
    production: bool,
) -> Result<String, rusqlite::Error> {
    fernet_enc::encrypt_totp_secret(secret, mfa_key, production)
        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))
}

/// Outcome of [`store_pending_enrolment`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingEnrolment {
    /// The secret and backup codes are stored; MFA stays off until
    /// verify-setup.
    Stored,
    /// MFA is on: nothing was written.
    MfaEnabled,
    /// There is no such user: nothing was written.
    NoSuchUser,
}

/// Store a pending MFA enrolment for a user whose MFA is off: a new TOTP
/// secret (encrypted as by [`set_totp_secret`]) and its backup codes
/// (`(hash_hex, salt_bytes)` pairs, replacing any existing codes).
///
/// One IMMEDIATE transaction, whose secret update is conditional on MFA
/// being off (`UPDATE … WHERE COALESCE(mfa_enabled, 0) = 0`): either both
/// are written while MFA is off or nothing is. An earlier "already
/// enabled" check is not enough, since MFA can be enabled (verify-setup in
/// another tab) while the codes are hashed, and an enrolled secret and its
/// recovery codes must not be replaced by ones only this caller knows.
pub fn store_pending_enrolment(
    conn: &mut PooledConnection<SqliteConnectionManager>,
    user_id: i64,
    secret: &str,
    mfa_key: &str,
    production: bool,
    codes: &[(String, Vec<u8>)],
) -> Result<PendingEnrolment, rusqlite::Error> {
    let encrypted = encrypt_secret(secret, mfa_key, production)?;
    // Dropped without a commit (an early return, an error), it rolls back.
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let updated = tx.execute(
        "UPDATE users SET totp_secret = ?1 WHERE id = ?2 AND COALESCE(mfa_enabled, 0) = 0",
        params![encrypted, user_id],
    )?;
    if updated == 0 {
        let exists: bool = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM users WHERE id = ?1)",
            params![user_id],
            |row| row.get(0),
        )?;
        return Ok(if exists {
            PendingEnrolment::MfaEnabled
        } else {
            PendingEnrolment::NoSuchUser
        });
    }
    replace_backup_codes(&tx, user_id, codes)?;
    tx.commit()?;
    Ok(PendingEnrolment::Stored)
}

/// Retrieve and decrypt a user's TOTP secret.
pub fn get_totp_secret(
    conn: &PooledConnection<SqliteConnectionManager>,
    user_id: i64,
    mfa_key: &str,
) -> Result<Option<String>, rusqlite::Error> {
    let stored: Option<String> = conn
        .query_row(
            "SELECT totp_secret FROM users WHERE id = ?1",
            params![user_id],
            |row| row.get(0),
        )
        .ok()
        .flatten();

    match stored {
        Some(ref s) if !s.is_empty() => match fernet_enc::decrypt_totp_secret(s, mfa_key) {
            Ok(decrypted) => Ok(Some(decrypted)),
            Err(e) => {
                tracing::warn!(error = %e, "Failed to decrypt TOTP secret");
                Ok(None)
            }
        },
        _ => Ok(None),
    }
}

/// Enable MFA for a user.
pub fn enable_mfa(
    conn: &PooledConnection<SqliteConnectionManager>,
    user_id: i64,
) -> Result<bool, rusqlite::Error> {
    let updated = conn.execute(
        "UPDATE users SET mfa_enabled = 1 WHERE id = ?1",
        params![user_id],
    )?;
    if updated > 0 {
        info!(user_id, "MFA enabled");
    }
    Ok(updated > 0)
}

/// Disable MFA for a user — clears secret and backup codes.
pub fn disable_mfa(
    conn: &PooledConnection<SqliteConnectionManager>,
    user_id: i64,
) -> Result<bool, rusqlite::Error> {
    // Disabling the factor and removing its recovery codes are one change.
    // A failed cleanup must not leave MFA off with old backup codes present.
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
    let updated = conn.execute(
        "UPDATE users SET mfa_enabled = 0, totp_secret = NULL WHERE id = ?1",
        params![user_id],
    )?;
    conn.execute(
        "DELETE FROM mfa_backup_codes WHERE user_id = ?1",
        params![user_id],
    )?;
    tx.commit()?;
    if updated > 0 {
        info!(user_id, "MFA disabled");
    }
    Ok(updated > 0)
}

/// Get a user by ID (needed for MFA token → user lookup).
pub fn get_user_by_id(
    conn: &PooledConnection<SqliteConnectionManager>,
    user_id: i64,
) -> Result<Option<crate::storage::users::User>, rusqlite::Error> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, username, role, display_name, email, enabled, created_at, \
                last_login, tenant_id, mfa_enabled \
         FROM users WHERE id = ?1",
    )?;
    let result = stmt.query_row(params![user_id], |row| {
        Ok(crate::storage::users::User {
            id: row.get(0)?,
            username: row.get(1)?,
            role: row.get(2)?,
            display_name: row.get::<_, Option<String>>(3)?.unwrap_or_default(),
            email: row.get::<_, Option<String>>(4)?.unwrap_or_default(),
            enabled: row.get(5)?,
            created_at: row.get(6)?,
            last_login: row.get(7)?,
            tenant_id: row.get(8)?,
            mfa_enabled: row.get::<_, Option<bool>>(9)?.unwrap_or(false),
        })
    });
    match result {
        Ok(user) => Ok(Some(user)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e),
    }
}

// ── MFA Tokens (mfa_tokens table) ─────────────────────────────────────

/// Create a short-lived MFA token for the two-step login of the user whose
/// password check verified `credential`. Returns the raw token, or `None`
/// — with nothing created — when the password changed since that check
/// (the challenge would prove a password that is no longer valid).
///
/// The token is bound to the credential by its lifetime: every password
/// change the gateway makes (the change and the admin reset, both served
/// natively) deletes the user's tokens in the transaction that stores the
/// new hash (`users::set_password_hash`), and this insert happens only
/// while the stored hash is still the verified one, so a token that
/// exists was issued for the password stored now.
pub fn create_mfa_token(
    conn: &PooledConnection<SqliteConnectionManager>,
    credential: &users::VerifiedCredential,
    expires_minutes: i64,
) -> Result<Option<String>, rusqlite::Error> {
    let raw_token = password::generate_session_token();
    let (now_str, expires_str) = mfa_token_times(expires_minutes);
    let created = conn.execute(
        "INSERT INTO mfa_tokens (token, user_id, created_at, expires_at) \
         SELECT ?1, id, ?3, ?4 FROM users WHERE id = ?2 AND password_hash = ?5",
        params![
            password::hash_session_token(&raw_token),
            credential.user_id,
            now_str,
            expires_str,
            credential.password_hash
        ],
    )?;
    Ok((created > 0).then_some(raw_token))
}

/// A token for `user_id` whatever its password, as if just issued by a
/// login (for tests that start at the second step).
#[cfg(test)]
pub(crate) fn create_mfa_token_unchecked(
    conn: &PooledConnection<SqliteConnectionManager>,
    user_id: i64,
    expires_minutes: i64,
) -> Result<String, rusqlite::Error> {
    let raw_token = password::generate_session_token();
    let (now_str, expires_str) = mfa_token_times(expires_minutes);
    conn.execute(
        "INSERT INTO mfa_tokens (token, user_id, created_at, expires_at) \
         VALUES (?1, ?2, ?3, ?4)",
        params![
            password::hash_session_token(&raw_token),
            user_id,
            now_str,
            expires_str
        ],
    )?;
    Ok(raw_token)
}

/// `created_at` and `expires_at` of an MFA token issued now.
fn mfa_token_times(expires_minutes: i64) -> (String, String) {
    let now = chrono::Utc::now();
    let expires_at = now + chrono::Duration::minutes(expires_minutes);
    (
        now.format("%Y-%m-%dT%H:%M:%S+00:00").to_string(),
        expires_at.format("%Y-%m-%dT%H:%M:%S+00:00").to_string(),
    )
}

/// Consume an MFA token and return the credential its password step
/// verified, or `None` if the token is unknown, expired or already used.
///
/// Single-use even under concurrency: the token is claimed with one
/// `DELETE … RETURNING`, so of N parallel requests presenting the same
/// token exactly one gets it — each password login buys exactly one round
/// of second-factor guesses.
///
/// The claim and the read of the user's stored password hash are one
/// IMMEDIATE transaction. A token still present was issued for the stored
/// password ([`create_mfa_token`]), so the hash read is the credential the
/// password step verified; the session is then issued only while it is
/// still current, which refuses a reset committed during the second-factor
/// check as well.
pub fn verify_mfa_token(
    conn: &PooledConnection<SqliteConnectionManager>,
    raw_token: &str,
) -> Result<Option<users::VerifiedCredential>, rusqlite::Error> {
    let hashed = password::hash_session_token(raw_token);
    let now_str = utc_now_iso();

    // Dropped without a commit (an early return, an error), it rolls back.
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
    // An expired token is deleted too (it is useless), but yields nothing.
    let claimed = conn.query_row(
        "DELETE FROM mfa_tokens WHERE token = ?1 AND user_id IN \
         (SELECT id FROM users WHERE tenant_id = ?2) RETURNING user_id, expires_at",
        params![hashed, crate::auth::api_key::INSTANCE_TENANT],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
    );
    let (user_id, expires_at) = match claimed {
        Ok(claimed) => claimed,
        Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
        Err(e) => return Err(e),
    };
    let password_hash: String = conn.query_row(
        "SELECT password_hash FROM users WHERE id = ?1",
        params![user_id],
        |row| row.get(0),
    )?;
    tx.commit()?;
    Ok((expires_at > now_str).then_some(users::VerifiedCredential {
        user_id,
        password_hash,
    }))
}

/// Delete expired MFA tokens.
pub fn cleanup_expired_mfa_tokens(
    conn: &PooledConnection<SqliteConnectionManager>,
) -> Result<usize, rusqlite::Error> {
    let now_str = utc_now_iso();
    let deleted = conn.execute(
        "DELETE FROM mfa_tokens WHERE expires_at <= ?1",
        params![now_str],
    )?;
    if deleted > 0 {
        debug!(deleted, "Cleaned up expired MFA tokens");
    }
    Ok(deleted)
}

// ── Backup Codes (mfa_backup_codes table) ─────────────────────────────

/// Store backup codes for a user (replaces any existing codes).
///
/// `codes` is a list of `(hash_hex, salt_bytes)` pairs from `password::hash_credential`.
/// Replacement is atomic; an enclosing transaction remains owned by the caller.
pub fn store_backup_codes(
    conn: &mut PooledConnection<SqliteConnectionManager>,
    user_id: i64,
    codes: &[(String, Vec<u8>)],
) -> Result<(), rusqlite::Error> {
    // A savepoint rolls back partial replacement without committing or rolling
    // back an enclosing transaction, including an already-consumed factor.
    let savepoint = conn.savepoint()?;
    replace_backup_codes(&savepoint, user_id, codes)?;
    savepoint.commit()?;
    Ok(())
}

/// Replace `user_id`'s backup codes with `codes`, unused. Not atomic by
/// itself: the caller runs it in a transaction or savepoint.
fn replace_backup_codes(
    conn: &rusqlite::Connection,
    user_id: i64,
    codes: &[(String, Vec<u8>)],
) -> Result<(), rusqlite::Error> {
    let now = utc_now_iso();
    // Delete existing codes
    conn.execute(
        "DELETE FROM mfa_backup_codes WHERE user_id = ?1",
        params![user_id],
    )?;
    // Insert new codes
    let mut stmt = conn.prepare_cached(
        "INSERT INTO mfa_backup_codes (user_id, code_hash, salt, used, created_at) \
         VALUES (?1, ?2, ?3, 0, ?4)",
    )?;
    for (hash, salt) in codes {
        stmt.execute(params![user_id, hash, salt, now])?;
    }
    Ok(())
}

/// Verify a backup code (single-use). Returns true if valid and marks it used.
///
/// The code is marked used with `UPDATE … WHERE used = 0`; only the request
/// whose update changed the row succeeds, so one code cannot be spent twice
/// by parallel requests.
pub fn verify_backup_code(
    conn: &PooledConnection<SqliteConnectionManager>,
    user_id: i64,
    code: &str,
) -> Result<bool, rusqlite::Error> {
    let normalized = code.trim().to_lowercase();

    // Fetch all unused codes for this user
    let candidates: Vec<(i64, String, Vec<u8>)> = {
        let mut stmt = conn.prepare_cached(
            "SELECT id, code_hash, salt FROM mfa_backup_codes \
             WHERE user_id = ?1 AND used = 0",
        )?;
        let rows = stmt.query_map(params![user_id], |row| {
            let id: i64 = row.get(0)?;
            let hash: String = row.get(1)?;
            let salt_ref = row.get_ref(2)?;
            let salt = password::decode_salt(&salt_ref).unwrap_or_default();
            Ok((id, hash, salt))
        })?;
        rows.collect::<Result<_, _>>()?
    };

    for (id, hash, salt) in candidates {
        let (matches, _) = password::verify_credential(&normalized, &hash, &salt);
        if matches {
            // Claim it; a parallel request may have spent it meanwhile.
            let claimed = conn.execute(
                "UPDATE mfa_backup_codes SET used = 1 WHERE id = ?1 AND used = 0",
                params![id],
            )?;
            return Ok(claimed == 1);
        }
    }

    Ok(false)
}

/// Count remaining (unused) backup codes.
pub fn get_backup_code_count(
    conn: &PooledConnection<SqliteConnectionManager>,
    user_id: i64,
) -> Result<usize, rusqlite::Error> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM mfa_backup_codes WHERE user_id = ?1 AND used = 0",
        params![user_id],
        |row| row.get(0),
    )?;
    Ok(count as usize)
}

// ── TOTP Replay Cache ─────────────────────────────────────────────────

/// Check if a TOTP code has been used recently (within 90s).
///
/// Read-only. To *use* a code call [`claim_totp_code`], which checks and
/// records in one step.
pub fn is_totp_reused(
    conn: &PooledConnection<SqliteConnectionManager>,
    username: &str,
    code: &str,
    tenant_id: &str,
) -> Result<bool, rusqlite::Error> {
    let cutoff = now_unix() - TOTP_REUSE_TTL;
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM totp_replay_cache \
         WHERE username = ?1 AND totp_code = ?2 AND used_at > ?3 AND tenant_id = ?4",
        params![username, code, cutoff, tenant_id],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

/// Record a TOTP code use unconditionally. Handlers use
/// [`claim_totp_code`] instead, which refuses a replay atomically.
pub fn record_totp_use(
    conn: &PooledConnection<SqliteConnectionManager>,
    username: &str,
    code: &str,
    tenant_id: &str,
) -> Result<(), rusqlite::Error> {
    conn.execute(
        "INSERT INTO totp_replay_cache (username, totp_code, used_at, tenant_id) \
         VALUES (?1, ?2, ?3, ?4)",
        params![username, code, now_unix(), tenant_id],
    )?;
    Ok(())
}

/// Use a (verified) TOTP code: record it in the replay cache unless it was
/// already used within the replay window. Returns `true` if this call
/// claimed the code, `false` if it is a replay.
///
/// Insert-or-fail in one statement (`INSERT … SELECT … WHERE NOT EXISTS`):
/// SQLite runs a writing statement under the database write lock, so the
/// check and the insert cannot interleave with another claim — from this
/// process or from the bridge — and of N parallel requests presenting the
/// same code exactly one succeeds. The cache table belongs to the bridge,
/// which inserts into it with a plain INSERT, so uniqueness is enforced by
/// this statement rather than by a UNIQUE index: an index would turn a
/// code that legitimately recurs before the bridge's cleanup into a
/// bridge-side IntegrityError (a failed login).
pub fn claim_totp_code(
    conn: &PooledConnection<SqliteConnectionManager>,
    username: &str,
    code: &str,
    tenant_id: &str,
) -> Result<bool, rusqlite::Error> {
    let now = now_unix();
    let inserted = conn.execute(
        "INSERT INTO totp_replay_cache (username, totp_code, used_at, tenant_id) \
         SELECT ?1, ?2, ?3, ?4 WHERE NOT EXISTS ( \
             SELECT 1 FROM totp_replay_cache \
             WHERE username = ?1 AND totp_code = ?2 AND used_at > ?5 AND tenant_id = ?4)",
        params![username, code, now, tenant_id, now - TOTP_REUSE_TTL],
    )?;
    Ok(inserted == 1)
}

/// Clean up expired replay cache entries.
pub fn cleanup_totp_replay(
    conn: &PooledConnection<SqliteConnectionManager>,
    tenant_id: &str,
) -> Result<usize, rusqlite::Error> {
    let cutoff = now_unix() - TOTP_REUSE_TTL;
    let deleted = conn.execute(
        "DELETE FROM totp_replay_cache WHERE used_at <= ?1 AND tenant_id = ?2",
        params![cutoff, tenant_id],
    )?;
    Ok(deleted)
}

// ── MFA attempt limiting (mfa_attempts table, owned by the gateway) ───

/// Create the `mfa_attempts` table if it does not exist. Idempotent and
/// cheap; [`reserve_mfa_attempt`] and [`clear_mfa_attempts`] call it.
pub fn ensure_mfa_attempts_table(
    conn: &PooledConnection<SqliteConnectionManager>,
) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS mfa_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            attempt_at REAL NOT NULL,
            tenant_id TEXT NOT NULL DEFAULT 'default'
        );
        CREATE INDEX IF NOT EXISTS idx_mfa_attempts_user
            ON mfa_attempts (user_id, tenant_id, attempt_at);",
    )
}

/// Reserve one second-factor check (TOTP or backup code) for `user_id`.
///
/// The attempt is counted as a failure up front, unless the user already
/// has `max_failures` of them within the last `window_secs` — then nothing
/// is recorded and `false` is returned (locked out). Count and insert are
/// one `INSERT … SELECT`, so parallel requests cannot all see "below the
/// limit". A successful check clears the reservations with
/// [`clear_mfa_attempts`]. Entries older than the window are dropped here,
/// so the table never holds more than `max_failures` rows per user.
pub fn reserve_mfa_attempt(
    conn: &PooledConnection<SqliteConnectionManager>,
    user_id: i64,
    tenant_id: &str,
    max_failures: u32,
    window_secs: f64,
) -> Result<bool, rusqlite::Error> {
    ensure_mfa_attempts_table(conn)?;
    let now = now_unix();
    let cutoff = now - window_secs;
    conn.execute(
        "DELETE FROM mfa_attempts WHERE user_id = ?1 AND tenant_id = ?2 AND attempt_at <= ?3",
        params![user_id, tenant_id, cutoff],
    )?;
    let reserved = conn.execute(
        "INSERT INTO mfa_attempts (user_id, attempt_at, tenant_id) \
         SELECT ?1, ?2, ?3 WHERE ( \
             SELECT COUNT(*) FROM mfa_attempts \
             WHERE user_id = ?1 AND tenant_id = ?3 AND attempt_at > ?4) < ?5",
        params![user_id, now, tenant_id, cutoff, max_failures],
    )?;
    Ok(reserved == 1)
}

/// Forget a user's counted MFA attempts (after a successful check).
pub fn clear_mfa_attempts(
    conn: &PooledConnection<SqliteConnectionManager>,
    user_id: i64,
    tenant_id: &str,
) -> Result<usize, rusqlite::Error> {
    ensure_mfa_attempts_table(conn)?;
    conn.execute(
        "DELETE FROM mfa_attempts WHERE user_id = ?1 AND tenant_id = ?2",
        params![user_id, tenant_id],
    )
}

// ── Tenant Settings ───────────────────────────────────────────────────

/// Check if MFA is required for a tenant.
pub fn get_tenant_mfa_required(
    conn: &PooledConnection<SqliteConnectionManager>,
    tenant_id: &str,
) -> Result<bool, rusqlite::Error> {
    let result = conn.query_row(
        "SELECT mfa_required FROM tenant_settings WHERE tenant_id = ?1",
        params![tenant_id],
        |row| row.get::<_, bool>(0),
    );
    match result {
        Ok(required) => Ok(required),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Set whether MFA is required for a tenant.
pub fn set_tenant_mfa_required(
    conn: &PooledConnection<SqliteConnectionManager>,
    tenant_id: &str,
    required: bool,
) -> Result<(), rusqlite::Error> {
    let now = utc_now_iso();
    conn.execute(
        "INSERT INTO tenant_settings (tenant_id, mfa_required, updated_at) \
         VALUES (?1, ?2, ?3) \
         ON CONFLICT(tenant_id) DO UPDATE SET mfa_required = ?2, updated_at = ?3",
        params![tenant_id, required, now],
    )?;
    Ok(())
}

// ── Session Scope ─────────────────────────────────────────────────────

/// Set the scope on a session (e.g., "mfa_setup_only"). Logins create the
/// session with its scope instead
/// ([`create_session_scoped`](crate::storage::sessions::create_session_scoped)).
pub fn set_session_scope(
    conn: &PooledConnection<SqliteConnectionManager>,
    raw_token: &str,
    scope: &str,
) -> Result<bool, rusqlite::Error> {
    crate::storage::sessions::set_session_scope(conn, raw_token, scope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support;
    use std::sync::{Arc, Barrier};

    /// Threads per round: no more than the test pool's connections (4), so
    /// every thread holds its connection before the barrier releases them.
    const CLAIMERS: usize = 4;

    /// Regression (G5): the replay check (`is_totp_reused`) and the record
    /// (`record_totp_use`) were separate statements, so requests presenting
    /// one TOTP code at the same moment could all read "unused" and all
    /// record it — a replayed code logged in again. Driven at the storage
    /// level, with the claimers released together, so nothing upstream
    /// (token claim, attempt reservation) spreads them apart: every round
    /// must have exactly one winner.
    #[test]
    fn concurrent_claims_of_one_totp_code_have_one_winner() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        for round in 0..50 {
            let code = format!("{:06}", 100_000 + round);
            let barrier = Arc::new(Barrier::new(CLAIMERS));
            let handles: Vec<_> = (0..CLAIMERS)
                .map(|_| {
                    let (state, barrier, code) =
                        (Arc::clone(&state), Arc::clone(&barrier), code.clone());
                    std::thread::spawn(move || {
                        let conn = state.db_pool.get().unwrap();
                        barrier.wait();
                        claim_totp_code(&conn, "alice", &code, "default").unwrap()
                    })
                })
                .collect();
            let winners = handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .filter(|&claimed| claimed)
                .count();
            assert_eq!(winners, 1, "round {round}: one TOTP code, one claim");
        }
    }

    /// A claimed code is refused for the same user and tenant within the
    /// replay window, and stays usable for another user or tenant.
    #[test]
    fn claimed_code_is_refused_only_for_its_user_and_tenant() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        assert!(claim_totp_code(&conn, "alice", "123456", "default").unwrap());
        assert!(!claim_totp_code(&conn, "alice", "123456", "default").unwrap());
        assert!(is_totp_reused(&conn, "alice", "123456", "default").unwrap());
        assert!(claim_totp_code(&conn, "bob", "123456", "default").unwrap());
        assert!(claim_totp_code(&conn, "alice", "123456", "other").unwrap());
        assert!(claim_totp_code(&conn, "alice", "654321", "default").unwrap());

        // An entry older than the replay window no longer blocks the code.
        conn.execute(
            "UPDATE totp_replay_cache SET used_at = used_at - ?1 \
             WHERE username = 'alice' AND totp_code = '123456' AND tenant_id = 'default'",
            [TOTP_REUSE_TTL + 1.0],
        )
        .unwrap();
        assert!(claim_totp_code(&conn, "alice", "123456", "default").unwrap());
    }
    type BackupRow = (i64, String, Vec<u8>, bool, String);

    fn backup_rows(
        conn: &PooledConnection<SqliteConnectionManager>,
        user_id: i64,
    ) -> Vec<BackupRow> {
        conn.prepare("SELECT id, code_hash, salt, used, created_at FROM mfa_backup_codes WHERE user_id=?1 ORDER BY id")
            .unwrap()
            .query_map([user_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    fn seed_recovery_codes(conn: &mut PooledConnection<SqliteConnectionManager>) -> i64 {
        let user_id = crate::storage::users::tests::insert_user(conn, "alice", "viewer", true);
        store_backup_codes(
            conn,
            user_id,
            &[
                ("old-used".into(), vec![1, 2]),
                ("old-unused".into(), vec![3, 4]),
            ],
        )
        .unwrap();
        conn.execute(
            "UPDATE mfa_backup_codes SET used=1 WHERE user_id=?1 AND code_hash='old-used'",
            [user_id],
        )
        .unwrap();
        user_id
    }

    fn reject_replacement(conn: &PooledConnection<SqliteConnectionManager>, hash: &str) {
        assert!(matches!(hash, "new-first" | "new-second"));
        conn.execute_batch(&format!(
            "CREATE TRIGGER reject_replacement BEFORE INSERT ON mfa_backup_codes
             WHEN NEW.code_hash='{hash}'
             BEGIN SELECT RAISE(ABORT, 'fixture replacement failure'); END"
        ))
        .unwrap();
    }

    fn replacement_codes() -> Vec<(String, Vec<u8>)> {
        vec![
            ("new-first".into(), vec![5, 6]),
            ("new-second".into(), vec![7, 8]),
        ]
    }

    #[test]
    fn replacement_insert_failures_preserve_all_original_recovery_rows() {
        for rejected in ["new-first", "new-second"] {
            let dir = tempfile::tempdir().unwrap();
            let state = test_support::app_state(&dir);
            let mut conn = state.db_pool.get().unwrap();
            let user_id = seed_recovery_codes(&mut conn);
            let original = backup_rows(&conn, user_id);
            reject_replacement(&conn, rejected);
            let error = store_backup_codes(&mut conn, user_id, &replacement_codes()).unwrap_err();
            assert!(error.to_string().contains("fixture replacement failure"));
            assert_eq!(
                backup_rows(&conn, user_id),
                original,
                "failure on {rejected}"
            );
            assert!(
                conn.is_autocommit(),
                "failed replacement must close its transaction"
            );
        }
    }

    #[test]
    fn replacement_failure_preserves_the_enclosing_transaction_and_consumed_state() {
        for rejected in ["new-first", "new-second"] {
            let dir = tempfile::tempdir().unwrap();
            let state = test_support::app_state(&dir);
            let mut conn = state.db_pool.get().unwrap();
            let user_id = seed_recovery_codes(&mut conn);
            let original = backup_rows(&conn, user_id);
            reject_replacement(&conn, rejected);
            conn.execute_batch("BEGIN IMMEDIATE").unwrap();
            conn.execute("UPDATE users SET role='admin' WHERE id=?1", [user_id])
                .unwrap();
            assert!(claim_totp_code(&conn, "alice", "123456", "default").unwrap());
            let error = store_backup_codes(&mut conn, user_id, &replacement_codes()).unwrap_err();
            assert!(error.to_string().contains("fixture replacement failure"));
            assert!(
                !conn.is_autocommit(),
                "the caller still owns its transaction"
            );
            assert_eq!(backup_rows(&conn, user_id), original);
            assert!(!claim_totp_code(&conn, "alice", "123456", "default").unwrap());
            conn.execute_batch("COMMIT").unwrap();
            assert_eq!(
                conn.query_row("SELECT role FROM users WHERE id=?1", [user_id], |row| {
                    row.get::<_, String>(0)
                })
                .unwrap(),
                "admin"
            );
            assert_eq!(backup_rows(&conn, user_id), original);
        }
    }

    #[test]
    fn successful_replacement_publishes_only_new_unused_codes() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let mut conn = state.db_pool.get().unwrap();
        let user_id = seed_recovery_codes(&mut conn);
        let original = backup_rows(&conn, user_id);
        let codes = replacement_codes();
        store_backup_codes(&mut conn, user_id, &codes).unwrap();
        let updated = backup_rows(&conn, user_id);
        assert!(conn.is_autocommit());
        assert_eq!(updated.len(), codes.len());
        for (row, (hash, salt)) in updated.iter().zip(codes.iter()) {
            assert!(
                row.0 > original.last().unwrap().0,
                "old claims cannot address replacement rows"
            );
            assert_eq!((&row.1, &row.2, row.3), (hash, salt, false));
        }
    }

    #[test]
    fn successful_replacement_can_be_rolled_back_by_the_enclosing_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let mut conn = state.db_pool.get().unwrap();
        let user_id = seed_recovery_codes(&mut conn);
        let original = backup_rows(&conn, user_id);
        conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        conn.execute("UPDATE users SET role='admin' WHERE id=?1", [user_id])
            .unwrap();
        store_backup_codes(&mut conn, user_id, &replacement_codes()).unwrap();
        assert!(
            !conn.is_autocommit(),
            "replacement cannot commit the caller's transaction"
        );
        assert_ne!(backup_rows(&conn, user_id), original);
        conn.execute_batch("ROLLBACK").unwrap();
        assert_eq!(backup_rows(&conn, user_id), original);
        assert_eq!(
            conn.query_row("SELECT role FROM users WHERE id=?1", [user_id], |row| {
                row.get::<_, String>(0)
            })
            .unwrap(),
            "viewer"
        );
    }

    // ── Security paths: secrets at rest, factor lifecycle, challenges ──

    const SECRET: &str = "JBSWY3DPEHPK3PXP";

    fn fernet_key(byte: u8) -> String {
        data_encoding::BASE64.encode(&[byte; 32])
    }

    fn stored_secret(
        conn: &PooledConnection<SqliteConnectionManager>,
        user_id: i64,
    ) -> Option<String> {
        conn.query_row(
            "SELECT totp_secret FROM users WHERE id=?1",
            [user_id],
            |row| row.get(0),
        )
        .unwrap()
    }

    fn mfa_enabled(conn: &PooledConnection<SqliteConnectionManager>, user_id: i64) -> bool {
        get_user_by_id(conn, user_id).unwrap().unwrap().mfa_enabled
    }

    fn count(conn: &PooledConnection<SqliteConnectionManager>, sql: &str) -> i64 {
        conn.query_row(sql, [], |row| row.get(0)).unwrap()
    }

    /// With a valid key the secret is stored Fernet-encrypted, never in the
    /// clear, and only that key reads it back; another or a missing key
    /// yields no secret (not garbage that could verify a code).
    #[test]
    fn totp_secret_is_encrypted_at_rest_and_readable_only_with_its_key() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let user_id = crate::storage::users::tests::insert_user(&conn, "alice", "viewer", true);
        let key = fernet_key(0x11);

        assert!(set_totp_secret(&conn, user_id, SECRET, &key, true).unwrap());
        let stored = stored_secret(&conn, user_id).unwrap();
        assert!(stored.starts_with("fernet:"), "{stored}");
        assert!(!stored.contains(SECRET));
        assert!(!stored.contains(&data_encoding::BASE64.encode(SECRET.as_bytes())));

        assert_eq!(
            get_totp_secret(&conn, user_id, &key).unwrap().as_deref(),
            Some(SECRET)
        );
        assert_eq!(
            get_totp_secret(&conn, user_id, &fernet_key(0x22)).unwrap(),
            None
        );
        assert_eq!(get_totp_secret(&conn, user_id, "").unwrap(), None);

        // An unknown user has nothing to store into or read from.
        assert!(!set_totp_secret(&conn, 9999, SECRET, &key, true).unwrap());
        assert_eq!(get_totp_secret(&conn, 9999, &key).unwrap(), None);
    }

    /// Production with a missing, malformed or merely repairable (43-char)
    /// key refuses to store the secret at all — the previous value stays.
    #[test]
    fn production_never_stores_a_totp_secret_unencrypted() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let user_id = crate::storage::users::tests::insert_user(&conn, "alice", "viewer", true);
        let key = fernet_key(0x11);
        set_totp_secret(&conn, user_id, SECRET, &key, true).unwrap();
        let before = stored_secret(&conn, user_id);

        let repairable = data_encoding::BASE64URL_NOPAD.encode(&[0x33; 32]);
        assert_eq!(repairable.len(), 43);
        for bad_key in ["", "   ", "not-a-fernet-key", repairable.as_str()] {
            assert!(
                set_totp_secret(&conn, user_id, "NEWSECRETNEWSECR", bad_key, true).is_err(),
                "key {bad_key:?}"
            );
            assert_eq!(stored_secret(&conn, user_id), before, "key {bad_key:?}");
        }
        assert_eq!(
            get_totp_secret(&conn, user_id, &key).unwrap().as_deref(),
            Some(SECRET)
        );
    }

    /// A pending enrolment is written only while MFA is off. With MFA on
    /// (any value but 0 or NULL, as `get_user_by_id` reads it, or one it
    /// cannot read) or for an unknown user nothing is written; otherwise the
    /// new secret and unused backup codes replace the old ones, and MFA
    /// stays off.
    #[test]
    fn a_pending_enrolment_is_stored_only_while_mfa_is_off() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let mut conn = state.db_pool.get().unwrap();
        let user_id = seed_recovery_codes(&mut conn);
        set_totp_secret(&conn, user_id, SECRET, "", false).unwrap();
        let original = backup_rows(&conn, user_id);
        let enrol = |conn: &mut PooledConnection<SqliteConnectionManager>, user_id| {
            store_pending_enrolment(
                conn,
                user_id,
                "NEWSECRETNEWSECR",
                "",
                false,
                &replacement_codes(),
            )
            .unwrap()
        };

        for enabled in ["1", "2", "'yes'"] {
            conn.execute(
                &format!("UPDATE users SET mfa_enabled = {enabled} WHERE id = ?1"),
                [user_id],
            )
            .unwrap();
            assert_eq!(
                enrol(&mut conn, user_id),
                PendingEnrolment::MfaEnabled,
                "{enabled}"
            );
            assert_eq!(
                get_totp_secret(&conn, user_id, "").unwrap().as_deref(),
                Some(SECRET)
            );
            assert_eq!(backup_rows(&conn, user_id), original, "{enabled}");
            assert!(conn.is_autocommit());
        }

        assert_eq!(enrol(&mut conn, 9999), PendingEnrolment::NoSuchUser);
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM mfa_backup_codes"), 2);
        assert!(conn.is_autocommit());

        conn.execute("UPDATE users SET mfa_enabled = 0 WHERE id = ?1", [user_id])
            .unwrap();
        assert_eq!(enrol(&mut conn, user_id), PendingEnrolment::Stored);
        assert!(conn.is_autocommit());
        assert_eq!(
            get_totp_secret(&conn, user_id, "").unwrap().as_deref(),
            Some("NEWSECRETNEWSECR")
        );
        let rows = backup_rows(&conn, user_id);
        let stored: Vec<_> = rows
            .iter()
            .map(|row| (row.1.clone(), row.2.clone(), row.3))
            .collect();
        let expected: Vec<_> = replacement_codes()
            .into_iter()
            .map(|(hash, salt)| (hash, salt, false))
            .collect();
        assert_eq!(stored, expected);
        assert!(!mfa_enabled(&conn, user_id));
    }

    /// A pending enrolment is one change: when the backup codes cannot be
    /// stored, or the secret cannot be encrypted (production without a
    /// valid key), the old secret and codes stay and the transaction ends.
    #[test]
    fn a_failed_pending_enrolment_changes_nothing() {
        for (rejected, key, production) in [
            (Some("new-first"), "", false),
            (Some("new-second"), "", false),
            (None, "not-a-fernet-key", true),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let state = test_support::app_state(&dir);
            let mut conn = state.db_pool.get().unwrap();
            let user_id = seed_recovery_codes(&mut conn);
            set_totp_secret(&conn, user_id, SECRET, "", false).unwrap();
            let before = (stored_secret(&conn, user_id), backup_rows(&conn, user_id));
            if let Some(hash) = rejected {
                reject_replacement(&conn, hash);
            }
            let result = store_pending_enrolment(
                &mut conn,
                user_id,
                "NEWSECRETNEWSECR",
                key,
                production,
                &replacement_codes(),
            );
            assert!(result.is_err(), "{rejected:?}");
            assert_eq!(
                (stored_secret(&conn, user_id), backup_rows(&conn, user_id)),
                before,
                "{rejected:?}"
            );
            assert!(conn.is_autocommit(), "{rejected:?}");
        }
    }

    /// Disabling removes the factor and every recovery code (used or not) of
    /// that user only.
    #[test]
    fn disable_mfa_removes_the_factor_and_codes_of_that_user_only() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let mut conn = state.db_pool.get().unwrap();
        let alice = seed_recovery_codes(&mut conn);
        let bob = crate::storage::users::tests::insert_user(&conn, "bob", "viewer", true);
        for user_id in [alice, bob] {
            set_totp_secret(&conn, user_id, SECRET, "", false).unwrap();
            assert!(enable_mfa(&conn, user_id).unwrap());
        }
        store_backup_codes(&mut conn, bob, &replacement_codes()).unwrap();

        assert!(disable_mfa(&conn, alice).unwrap());
        assert!(!mfa_enabled(&conn, alice));
        assert_eq!(stored_secret(&conn, alice), None);
        assert!(backup_rows(&conn, alice).is_empty(), "used codes go too");

        assert!(mfa_enabled(&conn, bob));
        assert_eq!(
            get_totp_secret(&conn, bob, "").unwrap().as_deref(),
            Some(SECRET)
        );
        assert_eq!(backup_rows(&conn, bob).len(), 2);

        // Unknown users: nothing to enable, disable or look up.
        assert!(!enable_mfa(&conn, 9999).unwrap());
        assert!(!disable_mfa(&conn, 9999).unwrap());
        assert!(get_user_by_id(&conn, 9999).unwrap().is_none());
        assert!(conn.is_autocommit());
    }

    /// The challenge is stored only as its SHA-256: a leaked stored value is
    /// not itself a challenge, a wrong presentation consumes nothing, and the
    /// real one is bound to its user and works once.
    #[test]
    fn mfa_challenges_are_stored_hashed_bound_to_their_user_and_single_use() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let alice = crate::storage::users::tests::insert_user(&conn, "alice", "viewer", true);
        let bob = crate::storage::users::tests::insert_user(&conn, "bob", "viewer", true);
        let alice_token = create_mfa_token_unchecked(&conn, alice, 5).unwrap();
        let bob_token = create_mfa_token_unchecked(&conn, bob, 5).unwrap();
        assert_ne!(alice_token, bob_token);

        let stored: String = conn
            .query_row(
                "SELECT token FROM mfa_tokens WHERE user_id=?1",
                [alice],
                |row| row.get(0),
            )
            .unwrap();
        assert_ne!(stored, alice_token);
        assert_eq!(stored, password::hash_session_token(&alice_token));

        for wrong in [stored.as_str(), "", "not-a-token"] {
            assert_eq!(verify_mfa_token(&conn, wrong).unwrap(), None, "{wrong:?}");
        }
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM mfa_tokens"), 2);

        assert_eq!(
            verify_mfa_token(&conn, &bob_token)
                .unwrap()
                .map(|c| c.user_id),
            Some(bob)
        );
        assert_eq!(
            verify_mfa_token(&conn, &alice_token)
                .unwrap()
                .map(|c| c.user_id),
            Some(alice)
        );
        assert_eq!(verify_mfa_token(&conn, &alice_token).unwrap(), None);
        assert_eq!(verify_mfa_token(&conn, &bob_token).unwrap(), None);
    }

    /// A challenge is issued only for the password stored now, a password
    /// change ends the user's pending challenges (and no one else's), and
    /// a claim yields the credential the session is then bound to.
    #[test]
    fn mfa_challenges_are_bound_to_the_password_they_were_issued_for() {
        use crate::storage::users::{self, VerifiedCredential};
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let alice = users::tests::insert_user(&conn, "alice", "viewer", true);
        let bob = users::tests::insert_user(&conn, "bob", "viewer", true);
        let verified = |user_id| VerifiedCredential {
            user_id,
            password_hash: "00".repeat(32),
        };

        let alice_token = create_mfa_token(&conn, &verified(alice), 5)
            .unwrap()
            .unwrap();
        let bob_token = create_mfa_token(&conn, &verified(bob), 5).unwrap().unwrap();
        let stale = VerifiedCredential {
            user_id: alice,
            password_hash: "ab".repeat(32),
        };
        assert_eq!(create_mfa_token(&conn, &stale, 5).unwrap(), None);
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM mfa_tokens"), 2);

        let tx = conn.unchecked_transaction().unwrap();
        assert!(
            users::set_password_hash(&conn, "alice", &"cd".repeat(32), &[3; 32], "default")
                .unwrap()
        );
        tx.commit().unwrap();
        assert_eq!(verify_mfa_token(&conn, &alice_token).unwrap(), None);
        assert_eq!(
            verify_mfa_token(&conn, &bob_token).unwrap(),
            Some(verified(bob)),
            "a bystander's pending login is untouched"
        );
    }

    #[test]
    fn cleanup_removes_only_expired_mfa_challenges() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let user_id = crate::storage::users::tests::insert_user(&conn, "alice", "viewer", true);
        let expired = create_mfa_token_unchecked(&conn, user_id, -1).unwrap();
        let presented_expired = create_mfa_token_unchecked(&conn, user_id, -1).unwrap();
        let live = create_mfa_token_unchecked(&conn, user_id, 5).unwrap();
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM mfa_tokens"), 3);

        // Still stored, yet refused: the expiry check itself, not cleanup.
        assert_eq!(verify_mfa_token(&conn, &presented_expired).unwrap(), None);
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM mfa_tokens"), 2);

        assert_eq!(cleanup_expired_mfa_tokens(&conn).unwrap(), 1);
        assert_eq!(cleanup_expired_mfa_tokens(&conn).unwrap(), 0);
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM mfa_tokens"), 1);
        assert_eq!(verify_mfa_token(&conn, &expired).unwrap(), None);
        assert_eq!(
            verify_mfa_token(&conn, &live).unwrap().map(|c| c.user_id),
            Some(user_id)
        );
    }

    /// A backup code is checked only against its owner's unused codes,
    /// matches after trimming and lowercasing, and is spent by its first use.
    #[test]
    fn backup_codes_are_per_user_normalised_and_single_use() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let mut conn = state.db_pool.get().unwrap();
        let alice = crate::storage::users::tests::insert_user(&conn, "alice", "viewer", true);
        let bob = crate::storage::users::tests::insert_user(&conn, "bob", "viewer", true);
        store_backup_codes(
            &mut conn,
            alice,
            &[password::hash_credential("abcd1234", None)],
        )
        .unwrap();
        store_backup_codes(&mut conn, bob, &[("unrelated".into(), vec![9; 32])]).unwrap();

        assert!(
            !verify_backup_code(&conn, bob, "abcd1234").unwrap(),
            "another user's code"
        );
        assert_eq!(get_backup_code_count(&conn, alice).unwrap(), 1);
        assert_eq!(get_backup_code_count(&conn, bob).unwrap(), 1);

        assert!(verify_backup_code(&conn, alice, "  ABCD1234\n").unwrap());
        assert_eq!(get_backup_code_count(&conn, alice).unwrap(), 0);
        assert!(!verify_backup_code(&conn, alice, "abcd1234").unwrap());
        assert_eq!(get_backup_code_count(&conn, bob).unwrap(), 1);
    }

    /// Replay entries block a code for the replay window only, are recorded
    /// per tenant, and cleanup of one tenant leaves the others' entries.
    #[test]
    fn replay_entries_expire_with_the_window_and_cleanup_is_per_tenant() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        record_totp_use(&conn, "alice", "111111", "default").unwrap();
        record_totp_use(&conn, "alice", "111111", "other").unwrap();
        record_totp_use(&conn, "alice", "222222", "default").unwrap();
        assert!(is_totp_reused(&conn, "alice", "111111", "default").unwrap());
        assert!(!is_totp_reused(&conn, "bob", "111111", "default").unwrap());
        assert!(!is_totp_reused(&conn, "alice", "333333", "default").unwrap());

        conn.execute(
            "UPDATE totp_replay_cache SET used_at = used_at - ?1 WHERE totp_code = '111111'",
            [TOTP_REUSE_TTL + 1.0],
        )
        .unwrap();
        assert!(!is_totp_reused(&conn, "alice", "111111", "default").unwrap());
        assert!(is_totp_reused(&conn, "alice", "222222", "default").unwrap());

        assert_eq!(cleanup_totp_replay(&conn, "default").unwrap(), 1);
        assert_eq!(
            count(
                &conn,
                "SELECT COUNT(*) FROM totp_replay_cache WHERE tenant_id = 'other'"
            ),
            1
        );
        assert!(
            is_totp_reused(&conn, "alice", "222222", "default").unwrap(),
            "a live entry survives cleanup"
        );
        assert!(!claim_totp_code(&conn, "alice", "222222", "default").unwrap());
    }

    /// Handlers verify with window 1 at a 30 s period: a code is accepted
    /// from the start of step T-1 to the end of step T+1, 90 s in all, so
    /// its replay entry must block it at least that long. Checked in
    /// absolute seconds, not relative to `TOTP_REUSE_TTL`: a code claimed
    /// 88 s ago is still a replay, for the claim, the read-only check and
    /// cleanup alike.
    #[test]
    // A runtime check, so a shorter window fails this test, not the build.
    #[allow(clippy::assertions_on_constants)]
    fn a_claimed_code_stays_blocked_while_it_can_still_verify() {
        assert!(TOTP_REUSE_TTL >= 3.0 * 30.0, "window 1 x 30 s period");
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        assert!(claim_totp_code(&conn, "alice", "123456", "default").unwrap());
        // 88 rather than 89 s: slack for a slow machine between statements.
        conn.execute("UPDATE totp_replay_cache SET used_at = used_at - 88", [])
            .unwrap();

        assert!(!claim_totp_code(&conn, "alice", "123456", "default").unwrap());
        assert!(is_totp_reused(&conn, "alice", "123456", "default").unwrap());
        assert_eq!(cleanup_totp_replay(&conn, "default").unwrap(), 0);
        assert!(!claim_totp_code(&conn, "alice", "123456", "default").unwrap());
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM totp_replay_cache"), 1);
    }

    /// The lockout counts per user and tenant, records nothing once
    /// reached, and ends when the counted attempts leave the window.
    #[test]
    fn mfa_lockout_is_per_user_and_tenant_and_ends_with_its_window() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        for _ in 0..3 {
            assert!(reserve_mfa_attempt(&conn, 1, "default", 3, 60.0).unwrap());
        }
        assert!(!reserve_mfa_attempt(&conn, 1, "default", 3, 60.0).unwrap());
        let counted =
            "SELECT COUNT(*) FROM mfa_attempts WHERE user_id = 1 AND tenant_id = 'default'";
        assert_eq!(count(&conn, counted), 3, "a refused check is not recorded");

        assert!(reserve_mfa_attempt(&conn, 2, "default", 3, 60.0).unwrap());
        assert!(reserve_mfa_attempt(&conn, 1, "other", 3, 60.0).unwrap());

        conn.execute(
            "UPDATE mfa_attempts SET attempt_at = attempt_at - 61 \
             WHERE user_id = 1 AND tenant_id = 'default'",
            [],
        )
        .unwrap();
        assert!(reserve_mfa_attempt(&conn, 1, "default", 3, 60.0).unwrap());
        assert_eq!(count(&conn, counted), 1, "expired attempts are dropped");

        // Clearing one user's attempts leaves the others counted.
        assert_eq!(clear_mfa_attempts(&conn, 1, "default").unwrap(), 1);
        assert_eq!(
            count(&conn, "SELECT COUNT(*) FROM mfa_attempts"),
            2,
            "user 2 and tenant 'other' keep their counts"
        );
    }

    /// The tenant policy is per tenant and defaults to "not required"; a
    /// missing table is reported as a missing-schema error (which login
    /// treats as "no policy"), not silently as `false`.
    #[test]
    fn tenant_mfa_policy_is_per_tenant_and_missing_schema_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let missing = get_tenant_mfa_required(&conn, "default").unwrap_err();
        assert!(crate::storage::users::is_missing_schema(&missing));

        conn.execute_batch(
            "CREATE TABLE tenant_settings (tenant_id TEXT PRIMARY KEY, \
             mfa_required BOOLEAN NOT NULL, updated_at TEXT NOT NULL)",
        )
        .unwrap();
        assert!(!get_tenant_mfa_required(&conn, "default").unwrap());
        set_tenant_mfa_required(&conn, "default", true).unwrap();
        assert!(get_tenant_mfa_required(&conn, "default").unwrap());
        assert!(!get_tenant_mfa_required(&conn, "other").unwrap());
        set_tenant_mfa_required(&conn, "default", false).unwrap();
        assert!(!get_tenant_mfa_required(&conn, "default").unwrap());
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM tenant_settings"), 1);
    }

    /// Restricting a session's scope applies to that session only, and an
    /// unknown token restricts nothing.
    #[test]
    fn session_scope_is_set_on_the_presented_session_only() {
        use crate::storage::sessions::{self, SessionConfig};
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let user_id = crate::storage::users::tests::insert_user(&conn, "alice", "viewer", true);
        let config = SessionConfig::default();
        let (restricted, _) = sessions::create_session(&conn, user_id, "", "", &config).unwrap();
        let (other, _) = sessions::create_session(&conn, user_id, "", "", &config).unwrap();

        assert!(set_session_scope(&conn, &restricted, "mfa_setup_only").unwrap());
        assert!(!set_session_scope(&conn, "unknown-token", "").unwrap());
        let scope = |token: &str| {
            sessions::validate_session(&conn, token, &config)
                .unwrap()
                .unwrap()
                .scope
        };
        assert_eq!(scope(&restricted), "mfa_setup_only");
        assert_eq!(scope(&other), "");
    }

    /// An empty stored TOTP secret is no secret: it reads as none (as a
    /// NULL one does), never as an empty key whose codes anyone can
    /// compute. A legacy plaintext secret still reads as itself.
    #[test]
    fn an_empty_stored_totp_secret_is_no_secret() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let user_id = crate::storage::users::tests::insert_user(&conn, "alice", "viewer", true);
        let set_stored = |value: Option<&str>| {
            conn.execute(
                "UPDATE users SET totp_secret = ?1 WHERE id = ?2",
                params![value, user_id],
            )
            .unwrap();
        };
        for key in [String::new(), fernet_key(0x11)] {
            set_stored(Some(""));
            assert_eq!(get_totp_secret(&conn, user_id, &key).unwrap(), None);
            set_stored(None);
            assert_eq!(get_totp_secret(&conn, user_id, &key).unwrap(), None);
            set_stored(Some(SECRET));
            assert_eq!(
                get_totp_secret(&conn, user_id, &key).unwrap().as_deref(),
                Some(SECRET)
            );
        }
    }
}
