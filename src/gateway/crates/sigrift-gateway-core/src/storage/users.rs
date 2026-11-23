//! User account storage — CRUD operations matching Python's storage/users.py.

use crate::db::manager::SqliteConnectionManager;
use r2d2::PooledConnection;
use rusqlite::params;
use serde::Serialize;
use tracing::info;

use crate::auth::password;

/// User record (public fields, no secrets). Safe to serialize to JSON.
#[derive(Debug, Clone, Serialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub role: String,
    pub display_name: String,
    pub email: String,
    pub enabled: bool,
    pub created_at: String,
    pub last_login: Option<String>,
    pub tenant_id: String,
    pub mfa_enabled: bool,
}

/// Internal user record including password hash and salt (never serialized).
#[allow(dead_code)]
pub(crate) struct UserFull {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub salt_raw: Vec<u8>,
    pub role: String,
    pub enabled: bool,
    pub tenant_id: String,
    pub mfa_enabled: bool,
}

/// Get a user by username (public fields only).
pub fn get_user_by_username(
    conn: &PooledConnection<SqliteConnectionManager>,
    username: &str,
    tenant_id: &str,
) -> Result<Option<User>, rusqlite::Error> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, username, role, display_name, email, enabled, created_at, \
                last_login, tenant_id, mfa_enabled \
         FROM users WHERE username = ?1 AND tenant_id = ?2",
    )?;
    let result = stmt.query_row(params![username, tenant_id], |row| {
        Ok(User {
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

/// Get a user with password hash and salt for internal auth verification.
pub(crate) fn get_user_full(
    conn: &PooledConnection<SqliteConnectionManager>,
    username: &str,
    tenant_id: &str,
) -> Result<Option<UserFull>, rusqlite::Error> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, username, password_hash, salt, role, enabled, tenant_id, mfa_enabled \
         FROM users WHERE username = ?1 AND tenant_id = ?2",
    )?;
    let result = stmt.query_row(params![username, tenant_id], |row| {
        let salt_ref = row.get_ref(3)?;
        let salt_raw = password::decode_salt(&salt_ref).unwrap_or_default();
        Ok(UserFull {
            id: row.get(0)?,
            username: row.get(1)?,
            password_hash: row.get(2)?,
            salt_raw,
            role: row.get(4)?,
            enabled: row.get::<_, Option<bool>>(5)?.unwrap_or(true),
            tenant_id: row.get(6)?,
            mfa_enabled: row.get::<_, Option<bool>>(7)?.unwrap_or(false),
        })
    });
    match result {
        Ok(user) => Ok(Some(user)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Stand-in credential checked when the user does not exist or is
/// disabled, so those cases cost the same PBKDF2 as a wrong password and
/// response timing does not reveal which usernames exist. No password
/// matches it: the result is discarded either way.
const DUMMY_PASSWORD_HASH: &str =
    "5f1d9c3b7a0e4f62c8b1a9d7e3f0c5b2a8d4e6f1c3b5a7d9e2f4c6b8a0d1e3f5";
const DUMMY_PASSWORD_SALT: [u8; 32] = [0x5a; 32];

/// The credential a password check verified: the account, and the stored
/// password hash the password matched. That hash identifies the password
/// version, since every password change stores a hash under a fresh salt
/// (a reset to the same password included). A request that checked the
/// password and then commits something on its strength — a login session,
/// an MFA challenge, a password change — commits only while the stored
/// hash is still this one ([`credential_is_current`]), so a reset or
/// change committed in between refuses it.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedCredential {
    pub user_id: i64,
    pub(crate) password_hash: String,
}

impl std::fmt::Debug for VerifiedCredential {
    // The hash stays out of logs and panic messages.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedCredential")
            .field("user_id", &self.user_id)
            .finish_non_exhaustive()
    }
}

/// Whether `credential` is still the user's stored password (the account
/// still exists and its password has not changed since the check).
pub fn credential_is_current(
    conn: &PooledConnection<SqliteConnectionManager>,
    credential: &VerifiedCredential,
) -> Result<bool, rusqlite::Error> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM users WHERE id = ?1 AND password_hash = ?2)",
        params![credential.user_id, credential.password_hash],
        |row| row.get(0),
    )
}

/// Verify a user's password.
///
/// Returns `Ok(Some(user_id))` on success, `Ok(None)` on failure (see
/// [`verify_password_credential`]).
pub fn verify_password(
    conn: &PooledConnection<SqliteConnectionManager>,
    username: &str,
    password_input: &str,
    tenant_id: &str,
) -> Result<Option<i64>, rusqlite::Error> {
    Ok(verify_password_credential(conn, username, password_input, tenant_id)?.map(|c| c.user_id))
}

/// Verify a user's password and return the credential it matched.
///
/// `Ok(None)` on failure: a wrong password, a user not found or disabled,
/// or a legacy credential replaced while it was checked. Every outcome
/// runs one PBKDF2, so timing does not distinguish an unknown or disabled
/// user from a wrong password. A legacy SHA-256 hash is transparently
/// upgraded to PBKDF2, and the credential returned is the upgraded one.
pub fn verify_password_credential(
    conn: &PooledConnection<SqliteConnectionManager>,
    username: &str,
    password_input: &str,
    tenant_id: &str,
) -> Result<Option<VerifiedCredential>, rusqlite::Error> {
    verify_password_with(
        conn,
        username,
        password_input,
        tenant_id,
        password::verify_credential,
    )
}

/// [`verify_password_credential`] with the credential check injectable
/// (tests count the PBKDF2 runs with it, or act while it runs).
fn verify_password_with(
    conn: &PooledConnection<SqliteConnectionManager>,
    username: &str,
    password_input: &str,
    tenant_id: &str,
    verify: impl Fn(&str, &str, &[u8]) -> (bool, bool),
) -> Result<Option<VerifiedCredential>, rusqlite::Error> {
    let user = match get_user_full(conn, username, tenant_id)? {
        Some(u) if u.enabled => u,
        _ => {
            // Unknown or disabled: do the same work, then fail.
            let _ = verify(password_input, DUMMY_PASSWORD_HASH, &DUMMY_PASSWORD_SALT);
            return Ok(None);
        }
    };

    let (matches, is_legacy) = verify(password_input, &user.password_hash, &user.salt_raw);

    if !matches {
        return Ok(None);
    }

    // Transparent upgrade: re-hash legacy SHA-256 credentials with PBKDF2.
    // Only the credential just checked is replaced: a reset or change
    // committed while it was checked stands, and refuses this login.
    if is_legacy {
        let (new_hash, new_salt) = password::hash_credential(password_input, None);
        let upgraded = conn.execute(
            "UPDATE users SET password_hash = ?1, salt = ?2 WHERE id = ?3 AND password_hash = ?4",
            params![new_hash, new_salt, user.id, user.password_hash],
        )?;
        if upgraded == 0 {
            info!(
                username = username,
                "Login refused: the password changed while it was checked"
            );
            return Ok(None);
        }
        info!(
            username = username,
            "Upgraded legacy SHA-256 hash to PBKDF2"
        );
        return Ok(Some(VerifiedCredential {
            user_id: user.id,
            password_hash: new_hash,
        }));
    }

    Ok(Some(VerifiedCredential {
        user_id: user.id,
        password_hash: user.password_hash,
    }))
}

/// Create a new user account. Returns the new user's ID.
pub fn create_user(
    conn: &PooledConnection<SqliteConnectionManager>,
    username: &str,
    password_input: &str,
    role: &str,
    display_name: &str,
    email: &str,
    tenant_id: &str,
) -> Result<i64, rusqlite::Error> {
    let (hash_hex, salt) = password::hash_credential(password_input, None);
    let now = chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S+00:00")
        .to_string();

    conn.execute(
        "INSERT INTO users (username, password_hash, salt, role, display_name, email, \
                            enabled, created_at, tenant_id) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7, ?8)",
        params![
            username,
            hash_hex,
            salt,
            role,
            display_name,
            email,
            now,
            tenant_id
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Set a new password for a user. Returns true if the user was found.
///
/// Hashes with PBKDF2 on the calling thread; async callers hash on the
/// blocking pool and store the result with [`set_password_hash`].
pub fn set_password(
    conn: &PooledConnection<SqliteConnectionManager>,
    username: &str,
    new_password: &str,
    tenant_id: &str,
) -> Result<bool, rusqlite::Error> {
    let (hash_hex, salt) = password::hash_credential(new_password, None);
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
    let updated = set_password_hash(conn, username, &hash_hex, &salt, tenant_id)?;
    tx.commit()?;
    Ok(updated)
}

/// Reset a password and revoke the user's sessions as one operation.
/// Hash before acquiring the write lock; async callers must use a blocking task.
pub fn set_password_and_revoke_sessions(
    conn: &PooledConnection<SqliteConnectionManager>,
    username: &str,
    new_password: &str,
    tenant_id: &str,
) -> Result<bool, rusqlite::Error> {
    let (hash_hex, salt) = password::hash_credential(new_password, None);
    change_and_revoke_sessions(conn, username, tenant_id, || {
        set_password_hash(conn, username, &hash_hex, &salt, tenant_id)
    })
}

/// Commit both changes or neither. A pre-existing transaction is rejected
/// before any mutation; raw setters remain available to transaction-owning callers.
fn change_and_revoke_sessions(
    conn: &PooledConnection<SqliteConnectionManager>,
    username: &str,
    tenant_id: &str,
    change: impl FnOnce() -> Result<bool, rusqlite::Error>,
) -> Result<bool, rusqlite::Error> {
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
    let updated = change()?;
    if updated {
        tx.execute(
            "DELETE FROM sessions WHERE user_id IN \
             (SELECT id FROM users WHERE username = ?1 AND tenant_id = ?2)",
            params![username, tenant_id],
        )?;
    }
    tx.commit()?;
    Ok(updated)
}

/// Store an already computed password hash (`password::hash_credential`
/// output) and end the user's pending MFA logins: an `mfa_tokens`
/// challenge proves only the password it was issued for, so it must not
/// complete a login under the new one (the claim reads the credential
/// it then binds the session to, see `mfa::verify_mfa_token`). Returns
/// true if the user was found. Two writes: callers run it in their
/// transaction, as [`set_password_and_revoke_sessions`] does.
pub fn set_password_hash(
    conn: &PooledConnection<SqliteConnectionManager>,
    username: &str,
    hash_hex: &str,
    salt: &[u8],
    tenant_id: &str,
) -> Result<bool, rusqlite::Error> {
    let updated = conn.execute(
        "UPDATE users SET password_hash = ?1, salt = ?2 \
         WHERE username = ?3 AND tenant_id = ?4",
        params![hash_hex, salt, username, tenant_id],
    )?;
    if updated > 0 {
        conn.execute(
            "DELETE FROM mfa_tokens WHERE user_id IN \
             (SELECT id FROM users WHERE username = ?1 AND tenant_id = ?2)",
            params![username, tenant_id],
        )?;
    }
    Ok(updated > 0)
}

/// Update user's last_login timestamp.
pub fn touch_last_login(
    conn: &PooledConnection<SqliteConnectionManager>,
    user_id: i64,
) -> Result<(), rusqlite::Error> {
    let now = chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S+00:00")
        .to_string();
    conn.execute(
        "UPDATE users SET last_login = ?1 WHERE id = ?2",
        params![now, user_id],
    )?;
    Ok(())
}

/// True when the error says the schema lacks a table or column — the bridge
/// adds some columns lazily (e.g. `users.must_change_password`), so their
/// absence means "never set", not a failure.
pub(crate) fn is_missing_schema(e: &rusqlite::Error) -> bool {
    let msg = e.to_string();
    msg.contains("no such column") || msg.contains("no such table")
}

/// Whether the user must change their password before doing anything else
/// (the bridge sets `users.must_change_password` for bootstrapped accounts).
/// `false` when the column does not exist yet; other errors are returned so
/// a login fails rather than skip the restriction.
pub fn must_change_password(
    conn: &PooledConnection<SqliteConnectionManager>,
    user_id: i64,
) -> Result<bool, rusqlite::Error> {
    match conn.query_row(
        "SELECT COALESCE(must_change_password, 0) FROM users WHERE id = ?1",
        params![user_id],
        |row| row.get::<_, i64>(0),
    ) {
        Ok(flag) => Ok(flag != 0),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
        Err(e) if is_missing_schema(&e) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Clear the forced-password-change flag (a no-op when the column does not
/// exist).
pub fn clear_must_change_password(
    conn: &PooledConnection<SqliteConnectionManager>,
    user_id: i64,
) -> Result<(), rusqlite::Error> {
    match conn.execute(
        "UPDATE users SET must_change_password = 0 WHERE id = ?1",
        params![user_id],
    ) {
        Ok(_) => Ok(()),
        Err(e) if is_missing_schema(&e) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Disable a user account (soft-delete). Returns true if the user was found.
pub fn disable_user(
    conn: &PooledConnection<SqliteConnectionManager>,
    username: &str,
    tenant_id: &str,
) -> Result<bool, rusqlite::Error> {
    let updated = conn.execute(
        "UPDATE users SET enabled = 0 WHERE username = ?1 AND tenant_id = ?2",
        params![username, tenant_id],
    )?;
    Ok(updated > 0)
}

/// Update user fields dynamically. Only `Some` fields are modified.
/// Returns true if the user was found and updated.
pub fn update_user(
    conn: &PooledConnection<SqliteConnectionManager>,
    username: &str,
    tenant_id: &str,
    role: Option<&str>,
    display_name: Option<&str>,
    email: Option<&str>,
    enabled: Option<bool>,
) -> Result<bool, rusqlite::Error> {
    let mut set_clauses = Vec::new();
    let mut params_vec: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
    let mut idx = 1;

    if let Some(r) = role {
        set_clauses.push(format!("role = ?{}", idx));
        params_vec.push(Box::new(r.to_string()));
        idx += 1;
    }
    if let Some(dn) = display_name {
        set_clauses.push(format!("display_name = ?{}", idx));
        params_vec.push(Box::new(dn.to_string()));
        idx += 1;
    }
    if let Some(em) = email {
        set_clauses.push(format!("email = ?{}", idx));
        params_vec.push(Box::new(em.to_string()));
        idx += 1;
    }
    if let Some(en) = enabled {
        set_clauses.push(format!("enabled = ?{}", idx));
        params_vec.push(Box::new(en));
        idx += 1;
    }

    if set_clauses.is_empty() {
        // Nothing to update — check if user exists
        return Ok(get_user_by_username(conn, username, tenant_id)?.is_some());
    }

    let sql = format!(
        "UPDATE users SET {} WHERE username = ?{} AND tenant_id = ?{}",
        set_clauses.join(", "),
        idx,
        idx + 1
    );
    params_vec.push(Box::new(username.to_string()));
    params_vec.push(Box::new(tenant_id.to_string()));

    let params_refs: Vec<&dyn rusqlite::types::ToSql> =
        params_vec.iter().map(|p| p.as_ref()).collect();
    let updated = conn.execute(&sql, params_refs.as_slice())?;
    Ok(updated > 0)
}

/// Update account fields and revoke existing sessions atomically.
/// Administrative disable operations use this instead of the mutation-only setter.
pub fn update_user_and_revoke_sessions(
    conn: &PooledConnection<SqliteConnectionManager>,
    username: &str,
    tenant_id: &str,
    role: Option<&str>,
    display_name: Option<&str>,
    email: Option<&str>,
    enabled: Option<bool>,
) -> Result<bool, rusqlite::Error> {
    change_and_revoke_sessions(conn, username, tenant_id, || {
        update_user(
            conn,
            username,
            tenant_id,
            role,
            display_name,
            email,
            enabled,
        )
    })
}

/// List all users (public fields, no secrets).
pub fn list_users(
    conn: &PooledConnection<SqliteConnectionManager>,
    tenant_id: &str,
) -> Result<Vec<User>, rusqlite::Error> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, username, role, display_name, email, enabled, created_at, \
                last_login, tenant_id, mfa_enabled \
         FROM users WHERE tenant_id = ?1 ORDER BY username",
    )?;
    let rows = stmt.query_map(params![tenant_id], |row| {
        Ok(User {
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
    })?;
    rows.collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::test_support;
    use sha2::Digest as _;
    use std::cell::Cell;

    /// Insert a user directly with a placeholder hash (no PBKDF2).
    pub(crate) fn insert_user(
        conn: &PooledConnection<SqliteConnectionManager>,
        username: &str,
        role: &str,
        enabled: bool,
    ) -> i64 {
        conn.execute(
            "INSERT INTO users (username, password_hash, salt, role, enabled, created_at, tenant_id) \
             VALUES (?1, ?2, ?3, ?4, ?5, '2026-01-01T00:00:00+00:00', 'default')",
            params![username, "00".repeat(32), vec![1u8; 32], role, enabled],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    #[test]
    fn atomic_revocation_missing_user_preserves_other_sessions() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let id = insert_user(&conn, "alice", "viewer", true);
        let config = crate::storage::sessions::SessionConfig::default();
        let (token, _) =
            crate::storage::sessions::create_session(&conn, id, "", "", &config).unwrap();

        assert!(!update_user_and_revoke_sessions(
            &conn,
            "missing",
            "default",
            None,
            None,
            None,
            Some(false),
        )
        .unwrap());
        assert!(conn.is_autocommit());
        assert_eq!(
            crate::storage::sessions::validate_session(&conn, &token, &config)
                .unwrap()
                .unwrap()
                .user_id,
            id
        );
    }

    fn new_session(conn: &PooledConnection<SqliteConnectionManager>, user: i64) -> String {
        let config = crate::storage::sessions::SessionConfig::default();
        crate::storage::sessions::create_session(conn, user, "", "", &config)
            .unwrap()
            .0
    }

    /// The revoking setters (admin disable, admin password reset) delete
    /// every session of the changed user and no other user's.
    #[test]
    fn revoking_changes_delete_that_users_sessions_only() {
        use crate::storage::sessions::count_user_sessions;
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let alice = insert_user(&conn, "alice", "viewer", true);
        let bob = insert_user(&conn, "bob", "viewer", true);
        let carol = insert_user(&conn, "carol", "viewer", true);
        for user in [alice, alice, bob, carol] {
            new_session(&conn, user);
        }

        assert!(update_user_and_revoke_sessions(
            &conn,
            "alice",
            "default",
            None,
            None,
            None,
            Some(false),
        )
        .unwrap());
        assert_eq!(count_user_sessions(&conn, alice).unwrap(), 0);
        assert!(
            !get_user_by_username(&conn, "alice", "default")
                .unwrap()
                .unwrap()
                .enabled
        );

        let old_hash = get_user_full(&conn, "bob", "default")
            .unwrap()
            .unwrap()
            .password_hash;
        assert!(set_password_and_revoke_sessions(&conn, "bob", "N3w-passw0rd", "default").unwrap());
        assert_eq!(count_user_sessions(&conn, bob).unwrap(), 0);
        assert_ne!(
            get_user_full(&conn, "bob", "default")
                .unwrap()
                .unwrap()
                .password_hash,
            old_hash,
            "the new password is stored"
        );

        assert_eq!(
            count_user_sessions(&conn, carol).unwrap(),
            1,
            "a bystander keeps its session"
        );
        assert!(conn.is_autocommit());
    }

    #[test]
    fn atomic_revocation_rejects_an_outer_transaction_without_ending_it() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        insert_user(&conn, "alice", "viewer", true);
        let outer = conn.unchecked_transaction().unwrap();
        update_user(&conn, "alice", "default", None, Some("pending"), None, None).unwrap();

        assert!(update_user_and_revoke_sessions(
            &conn,
            "alice",
            "default",
            None,
            None,
            None,
            Some(false),
        )
        .is_err());
        assert!(
            !conn.is_autocommit(),
            "the caller still owns its transaction"
        );
        let user = get_user_by_username(&conn, "alice", "default")
            .unwrap()
            .unwrap();
        assert!(user.enabled);
        assert_eq!(user.display_name, "pending");
        drop(outer);
        assert!(conn.is_autocommit());
        assert_eq!(
            get_user_by_username(&conn, "alice", "default")
                .unwrap()
                .unwrap()
                .display_name,
            ""
        );
    }

    /// Regression (G10): an unknown or disabled user returned before any
    /// PBKDF2 (~0 ms against ~300 ms), so timing revealed which usernames
    /// exist. Every outcome must run exactly one credential check.
    #[test]
    fn every_outcome_costs_one_credential_check() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        insert_user(&conn, "alice", "viewer", true);
        insert_user(&conn, "mallory", "viewer", false);

        let runs = Cell::new(0);
        let counting = |_: &str, _: &str, _: &[u8]| {
            runs.set(runs.get() + 1);
            (false, false)
        };
        for user in ["alice", "mallory", "nobody"] {
            runs.set(0);
            let out = verify_password_with(&conn, user, "pw", "default", counting).unwrap();
            assert_eq!(out, None, "{user}");
            assert_eq!(runs.get(), 1, "{user}: exactly one credential check");
        }

        // A disabled user is refused even with the right password.
        let accept_all = |_: &str, _: &str, _: &[u8]| (true, false);
        assert_eq!(
            verify_password_with(&conn, "mallory", "pw", "default", accept_all).unwrap(),
            None
        );
        assert!(
            verify_password_with(&conn, "alice", "pw", "default", accept_all)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn must_change_password_tolerates_missing_column() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let id = insert_user(&conn, "alice", "admin", true);

        // The bridge adds the column lazily; before that the flag is unset.
        assert!(!must_change_password(&conn, id).unwrap());
        clear_must_change_password(&conn, id).unwrap();

        conn.execute_batch(
            "ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0",
        )
        .unwrap();
        assert!(!must_change_password(&conn, id).unwrap());
        conn.execute(
            "UPDATE users SET must_change_password = 1 WHERE id = ?1",
            params![id],
        )
        .unwrap();
        assert!(must_change_password(&conn, id).unwrap());
        clear_must_change_password(&conn, id).unwrap();
        assert!(!must_change_password(&conn, id).unwrap());
        assert!(
            !must_change_password(&conn, id + 100).unwrap(),
            "unknown user"
        );
    }

    fn stored_credential(
        conn: &PooledConnection<SqliteConnectionManager>,
        username: &str,
    ) -> (String, Vec<u8>) {
        conn.query_row(
            "SELECT password_hash, salt FROM users WHERE username = ?1",
            params![username],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
    }

    fn session_count(conn: &PooledConnection<SqliteConnectionManager>, user_id: i64) -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM sessions WHERE user_id = ?1",
            params![user_id],
            |row| row.get(0),
        )
        .unwrap()
    }

    fn user(conn: &PooledConnection<SqliteConnectionManager>, username: &str) -> User {
        get_user_by_username(conn, username, "default")
            .unwrap()
            .unwrap()
    }

    /// Independent legacy golden (see `password::tests`):
    /// SHA-256(0xbb * 32 || "legacy_pass").
    const LEGACY_HASH: &str = "226a301654835f8b229491de1c4bcdfb5c6f0fc3372d49550247adf47e909230";
    const LEGACY_SALT: [u8; 32] = [0xbb; 32];

    /// A legacy salted-SHA-256 credential is replaced by a PBKDF2 hash with
    /// a fresh salt on a successful login, and left untouched by a failed
    /// one (a wrong password must not rewrite the stored credential).
    #[test]
    fn legacy_hash_is_upgraded_only_on_successful_login() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let id = insert_user(&conn, "alice", "viewer", true);
        conn.execute(
            "UPDATE users SET password_hash = ?1, salt = ?2 WHERE id = ?3",
            params![LEGACY_HASH, LEGACY_SALT.to_vec(), id],
        )
        .unwrap();

        assert_eq!(
            verify_password(&conn, "alice", "wrong_pass", "default").unwrap(),
            None
        );
        assert_eq!(
            stored_credential(&conn, "alice"),
            (LEGACY_HASH.to_string(), LEGACY_SALT.to_vec())
        );

        assert_eq!(
            verify_password(&conn, "alice", "legacy_pass", "default").unwrap(),
            Some(id)
        );
        let (hash, salt) = stored_credential(&conn, "alice");
        assert_ne!(hash, LEGACY_HASH);
        assert_eq!(salt.len(), 32);
        assert_ne!(salt, LEGACY_SALT.to_vec(), "the upgrade uses a fresh salt");
        assert_eq!(
            password::verify_credential("legacy_pass", &hash, &salt),
            (true, false),
            "the stored credential is now PBKDF2, not legacy"
        );
    }

    /// Regression: the legacy upgrade rewrote the credential unconditionally,
    /// so a password reset committed while the legacy check ran was
    /// overwritten with the old password, hashed anew. The upgrade applies
    /// only to the credential it checked; one replaced meanwhile refuses
    /// the login, as on the bridge.
    #[test]
    fn legacy_upgrade_never_overwrites_a_concurrent_reset() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let id = insert_user(&conn, "alice", "viewer", true);
        conn.execute(
            "UPDATE users SET password_hash = ?1, salt = ?2 WHERE id = ?3",
            params![LEGACY_HASH, LEGACY_SALT.to_vec(), id],
        )
        .unwrap();
        let reset_hash = "cd".repeat(32);

        let reset_during_check = |input: &str, hash: &str, salt: &[u8]| {
            let admin = state.db_pool.get().unwrap();
            assert!(set_password_hash(&admin, "alice", &reset_hash, &[3; 32], "default").unwrap());
            password::verify_credential(input, hash, salt)
        };
        assert_eq!(
            verify_password_with(&conn, "alice", "legacy_pass", "default", reset_during_check)
                .unwrap(),
            None,
            "the checked credential is gone"
        );
        assert_eq!(
            stored_credential(&conn, "alice"),
            (reset_hash, vec![3; 32]),
            "the reset stands"
        );
    }

    /// Every lookup and write is scoped to its tenant: an account of another
    /// tenant cannot be authenticated, re-keyed, disabled, re-roled, listed
    /// or have its sessions revoked through this one. (Here the foreign
    /// name is unknown in this tenant, so the revoking calls stop before
    /// their session DELETE; its own tenant scope is exercised by
    /// `session_revocation_is_scoped_to_the_tenant_when_names_repeat`.)
    #[test]
    fn accounts_are_scoped_to_their_tenant() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let pw = "Other-Tenant-Passw0rd";
        let carol = create_user(&conn, "carol", pw, "admin", "Carol", "", "other").unwrap();
        insert_user(&conn, "alice", "viewer", true);
        let config = crate::storage::sessions::SessionConfig::default();
        crate::storage::sessions::create_session(&conn, carol, "", "", &config).unwrap();
        let credential = stored_credential(&conn, "carol");

        assert!(get_user_by_username(&conn, "carol", "default")
            .unwrap()
            .is_none());
        assert!(get_user_full(&conn, "carol", "default").unwrap().is_none());
        assert_eq!(
            verify_password(&conn, "carol", pw, "default").unwrap(),
            None
        );
        assert!(!set_password_hash(&conn, "carol", &"ff".repeat(32), &[2; 32], "default").unwrap());
        assert!(
            !set_password_and_revoke_sessions(&conn, "carol", "Attacker-Passw0rd", "default")
                .unwrap()
        );
        assert!(!disable_user(&conn, "carol", "default").unwrap());
        assert!(!update_user(
            &conn,
            "carol",
            "default",
            Some("viewer"),
            None,
            None,
            Some(false)
        )
        .unwrap());
        assert!(!update_user(&conn, "carol", "default", None, None, None, None).unwrap());
        assert!(!update_user_and_revoke_sessions(
            &conn,
            "carol",
            "default",
            None,
            None,
            None,
            Some(false)
        )
        .unwrap());
        let listed: Vec<String> = list_users(&conn, "default")
            .unwrap()
            .into_iter()
            .map(|u| u.username)
            .collect();
        assert_eq!(listed, ["alice"]);

        assert_eq!(stored_credential(&conn, "carol"), credential);
        assert_eq!(session_count(&conn, carol), 1);
        let other = get_user_by_username(&conn, "carol", "other")
            .unwrap()
            .unwrap();
        assert_eq!((other.role.as_str(), other.enabled), ("admin", true));
        assert_eq!(
            verify_password(&conn, "carol", pw, "other").unwrap(),
            Some(carol)
        );
    }

    /// Passwords are stored only as salted PBKDF2 hashes with a unique salt
    /// per account; new accounts start enabled with the requested role. A
    /// duplicate username fails with the UNIQUE error the admin handler
    /// maps to 409, and leaves the existing account untouched.
    #[test]
    fn create_user_hashes_and_refuses_duplicates() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let pw = "Shared-Passw0rd";
        let alice = create_user(
            &conn, "alice", pw, "analyst", "Alice", "a@x.test", "default",
        )
        .unwrap();
        let bob = create_user(&conn, "bob", pw, "viewer", "", "", "default").unwrap();
        assert_ne!(alice, bob);

        let (a_hash, a_salt) = stored_credential(&conn, "alice");
        let (b_hash, b_salt) = stored_credential(&conn, "bob");
        assert_ne!(a_hash, password::sha256_hex(pw), "unsalted SHA-256");
        let mut legacy = sha2::Sha256::new();
        legacy.update(&a_salt);
        legacy.update(pw);
        assert_ne!(a_hash, hex::encode(legacy.finalize()), "legacy SHA-256");
        assert_eq!(a_hash.len(), 64);
        assert!(a_hash.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(a_salt.len(), 32);
        assert_ne!(a_salt, b_salt);
        assert_ne!(a_hash, b_hash, "equal passwords, different stored hashes");
        assert_eq!(
            password::verify_credential(pw, &a_hash, &a_salt),
            (true, false)
        );
        let created = user(&conn, "alice");
        assert_eq!(
            (created.id, created.role.as_str(), created.enabled),
            (alice, "analyst", true)
        );
        assert!(!created.mfa_enabled);
        assert_eq!(created.last_login, None);

        let err =
            create_user(&conn, "alice", "Other-Passw0rd", "admin", "", "", "default").unwrap_err();
        assert!(err.to_string().contains("UNIQUE constraint"), "{err}");
        assert_eq!(stored_credential(&conn, "alice"), (a_hash, a_salt));
        assert_eq!(user(&conn, "alice").role, "analyst");
        assert_eq!(list_users(&conn, "default").unwrap().len(), 2);
    }

    /// Setting a password replaces the credential: the previous password
    /// stops working and the new one works. An unknown user is not found.
    #[test]
    fn set_password_replaces_the_credential() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let id = insert_user(&conn, "alice", "viewer", true);

        assert!(set_password(&conn, "alice", "First-Passw0rd", "default").unwrap());
        assert!(set_password(&conn, "alice", "Second-Passw0rd", "default").unwrap());
        assert_eq!(
            verify_password(&conn, "alice", "First-Passw0rd", "default").unwrap(),
            None
        );
        assert_eq!(
            verify_password(&conn, "alice", "Second-Passw0rd", "default").unwrap(),
            Some(id)
        );
        assert!(
            !set_password_hash(&conn, "nobody", &"ff".repeat(32), &[2; 32], "default").unwrap()
        );
    }

    /// A disabled account cannot authenticate even with its correct
    /// password; re-enabling restores it. Disabling an unknown user reports
    /// not-found.
    #[test]
    fn disabled_account_cannot_authenticate() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let pw = "Correct-Passw0rd";
        let id = create_user(&conn, "alice", pw, "viewer", "", "", "default").unwrap();

        assert!(disable_user(&conn, "alice", "default").unwrap());
        assert!(!user(&conn, "alice").enabled);
        assert!(
            !get_user_full(&conn, "alice", "default")
                .unwrap()
                .unwrap()
                .enabled
        );
        assert_eq!(
            verify_password(&conn, "alice", pw, "default").unwrap(),
            None
        );
        assert!(!disable_user(&conn, "nobody", "default").unwrap());

        assert!(update_user(&conn, "alice", "default", None, None, None, Some(true)).unwrap());
        assert_eq!(
            verify_password(&conn, "alice", pw, "default").unwrap(),
            Some(id)
        );
    }

    /// `update_user` binds every value: a crafted username matches no row,
    /// and a crafted role is stored verbatim without touching other columns
    /// or accounts. Being no known role, it then ranks as KEYMASTER for
    /// ceiling checks. With no fields it only reports whether the account
    /// exists.
    #[test]
    fn update_user_binds_values_and_touches_only_the_named_account() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        insert_user(&conn, "alice", "viewer", true);
        insert_user(&conn, "bob", "viewer", true);

        for crafted in ["alice' OR '1'='1", "x\" OR 1=1 --", "%"] {
            assert!(
                !update_user(&conn, crafted, "default", Some("admin"), None, None, None).unwrap(),
                "{crafted}"
            );
        }
        assert_eq!(user(&conn, "alice").role, "viewer");
        assert_eq!(user(&conn, "bob").role, "viewer");

        let crafted_role = "viewer', enabled = 0, role = 'admin";
        assert!(update_user(
            &conn,
            "alice",
            "default",
            Some(crafted_role),
            Some("Alice A."),
            Some("alice@x.test"),
            None,
        )
        .unwrap());
        let alice = user(&conn, "alice");
        assert_eq!(alice.role, crafted_role);
        assert!(alice.enabled);
        assert_eq!(
            (alice.display_name.as_str(), alice.email.as_str()),
            ("Alice A.", "alice@x.test")
        );
        assert_eq!(
            crate::auth::rbac::Role::parse_stored_for_ceiling(&alice.role),
            crate::auth::rbac::Role::Keymaster
        );
        let bob = user(&conn, "bob");
        assert_eq!(
            (bob.role.as_str(), bob.display_name.as_str(), bob.enabled),
            ("viewer", "", true)
        );

        assert!(update_user(&conn, "bob", "default", None, None, None, None).unwrap());
        assert!(!update_user(&conn, "nobody", "default", None, None, None, None).unwrap());
    }

    /// The public `User` record never carries credentials: serializing a
    /// listed or looked-up user exposes no hash, salt or TOTP secret.
    #[test]
    fn user_records_never_serialize_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let id = insert_user(&conn, "alice", "admin", true);
        insert_user(&conn, "bob", "viewer", true);
        let hash = format!("{}abcd", "c0ffee".repeat(10));
        let totp = "JBSWY3DPEHPK3PXP";
        conn.execute(
            "UPDATE users SET password_hash = ?1, salt = ?2, totp_secret = ?3, \
             mfa_enabled = 1 WHERE id = ?4",
            params![hash, b"pepper-pepper-pepper-pepper-0123".to_vec(), totp, id],
        )
        .unwrap();

        let listed = list_users(&conn, "default").unwrap();
        let names: Vec<&str> = listed.iter().map(|u| u.username.as_str()).collect();
        assert_eq!(names, ["alice", "bob"]);
        assert!(listed[0].mfa_enabled);
        let one = user(&conn, "alice");
        for json in [
            serde_json::to_string(&listed).unwrap(),
            serde_json::to_string(&one).unwrap(),
        ] {
            for needle in [hash.as_str(), totp, "pepper", "password", "salt", "totp"] {
                assert!(!json.contains(needle), "{needle} leaked: {json}");
            }
        }
    }

    #[test]
    fn touch_last_login_records_only_that_user() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let alice = insert_user(&conn, "alice", "viewer", true);
        insert_user(&conn, "bob", "viewer", true);

        touch_last_login(&conn, alice).unwrap();
        let last = user(&conn, "alice").last_login.expect("login recorded");
        assert!(
            chrono::DateTime::parse_from_rfc3339(&last).is_ok(),
            "{last}"
        );
        assert_eq!(user(&conn, "bob").last_login, None);
    }

    /// The forced-change flag fails closed: an unreadable flag or a refused
    /// clear is an error (so the login fails) rather than "no change
    /// needed", and a refused clear leaves the flag set.
    #[test]
    fn must_change_password_errors_are_not_swallowed() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let id = insert_user(&conn, "alice", "admin", true);
        conn.execute_batch("ALTER TABLE users ADD COLUMN must_change_password INTEGER DEFAULT 0")
            .unwrap();

        conn.execute(
            "UPDATE users SET must_change_password = 'yes' WHERE id = ?1",
            params![id],
        )
        .unwrap();
        assert!(must_change_password(&conn, id).is_err());

        conn.execute(
            "UPDATE users SET must_change_password = 1 WHERE id = ?1",
            params![id],
        )
        .unwrap();
        conn.execute_batch(
            "CREATE TRIGGER keep_flag BEFORE UPDATE OF must_change_password ON users \
             BEGIN SELECT RAISE(ABORT, 'flag locked'); END;",
        )
        .unwrap();
        assert!(clear_must_change_password(&conn, id).is_err());
        assert!(must_change_password(&conn, id).unwrap());
    }

    /// An account row that cannot be decoded is an error for the login,
    /// never a success and never mistaken for an unknown user.
    #[test]
    fn undecodable_account_row_fails_the_login() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let id = insert_user(&conn, "alice", "admin", true);
        conn.execute(
            "UPDATE users SET enabled = 'corrupt' WHERE id = ?1",
            params![id],
        )
        .unwrap();

        assert!(get_user_full(&conn, "alice", "default").is_err());
        let accept_all = |_: &str, _: &str, _: &[u8]| (true, false);
        assert!(verify_password_with(&conn, "alice", "pw", "default", accept_all).is_err());
    }

    /// A salt stored as hex TEXT (the Rust API-key path) is decoded before
    /// hashing, so the account authenticates exactly as with a BLOB salt,
    /// and only with its own password.
    #[test]
    fn hex_text_salt_authenticates_only_the_right_password() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let pw = "Text-Salt-Passw0rd";
        let salt = [0x11u8; 32];
        let (hash, _) = password::hash_credential(pw, Some(&salt));
        let id = insert_user(&conn, "alice", "viewer", true);
        conn.execute(
            "UPDATE users SET password_hash = ?1, salt = ?2 WHERE id = ?3",
            params![hash, hex::encode(salt), id],
        )
        .unwrap();

        assert_eq!(
            get_user_full(&conn, "alice", "default")
                .unwrap()
                .unwrap()
                .salt_raw,
            salt.to_vec()
        );
        assert_eq!(
            verify_password(&conn, "alice", pw, "default").unwrap(),
            Some(id)
        );
        assert_eq!(
            verify_password(&conn, "alice", "Wrong-Passw0rd", "default").unwrap(),
            None
        );
    }

    /// Session revocation is scoped to the account's tenant, not only its
    /// name. The shipped schemas make `username` globally UNIQUE, so today
    /// two tenants cannot both hold a name and the DELETE's tenant filter
    /// is defense in depth. To exercise it, this test rebuilds `users` with
    /// per-tenant uniqueness (the shape a multi-tenant schema takes):
    /// disabling or resetting "carol" in one tenant must leave the other
    /// tenant's "carol", her credential and her sessions alone.
    #[test]
    fn session_revocation_is_scoped_to_the_tenant_when_names_repeat() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let ddl: String = conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'users'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let per_tenant = ddl.replacen("username TEXT UNIQUE NOT NULL", "username TEXT NOT NULL", 1);
        assert_ne!(per_tenant, ddl, "users schema changed: update this test");
        let per_tenant = format!(
            "{}, UNIQUE (username, tenant_id))",
            per_tenant.trim_end().strip_suffix(')').unwrap()
        );
        conn.execute_batch(&format!("DROP TABLE users; {per_tenant};"))
            .unwrap();

        let here = insert_user(&conn, "carol", "viewer", true);
        conn.execute(
            "INSERT INTO users (username, password_hash, salt, role, enabled, created_at, tenant_id) \
             VALUES ('carol', ?1, ?2, 'admin', 1, '2026-01-01T00:00:00+00:00', 'other')",
            params!["ee".repeat(32), vec![3u8; 32]],
        )
        .unwrap();
        let there = conn.last_insert_rowid();
        let config = crate::storage::sessions::SessionConfig::default();
        let new_session = |id| crate::storage::sessions::create_session(&conn, id, "", "", &config);
        new_session(here).unwrap();
        new_session(there).unwrap();
        let credential_of = |id: i64| -> (String, Vec<u8>) {
            conn.query_row(
                "SELECT password_hash, salt FROM users WHERE id = ?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap()
        };
        let there_credential = credential_of(there);

        assert!(update_user_and_revoke_sessions(
            &conn,
            "carol",
            "default",
            None,
            None,
            None,
            Some(false)
        )
        .unwrap());
        assert_eq!(session_count(&conn, here), 0);
        assert_eq!(session_count(&conn, there), 1, "disable crossed tenants");

        new_session(here).unwrap();
        assert!(set_password_and_revoke_sessions(
            &conn,
            "carol",
            "Replacement-Passw0rd",
            "default"
        )
        .unwrap());
        assert_eq!(session_count(&conn, here), 0);
        assert_eq!(session_count(&conn, there), 1, "reset crossed tenants");
        assert_ne!(credential_of(here), credential_of(there));
        assert_eq!(credential_of(there), there_credential);
        let other = get_user_by_username(&conn, "carol", "other")
            .unwrap()
            .unwrap();
        assert_eq!(
            (other.id, other.role.as_str(), other.enabled),
            (there, "admin", true)
        );
    }

    /// Usernames match exactly: a case or padding variant of an existing
    /// name is another (unknown) account, so it never authenticates as,
    /// resolves to, re-keys or changes the original, even if every
    /// credential check passed. As in the bridge (a BINARY-collated
    /// UNIQUE), a case variant may be created as a separate account, which
    /// leaves the original untouched.
    #[test]
    fn usernames_match_exactly() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let alice = insert_user(&conn, "alice", "admin", true);
        let before = stored_credential(&conn, "alice");
        let accept_all = |_: &str, _: &str, _: &[u8]| (true, false);

        for variant in ["Alice", "ALICE", "alice ", " alice", "alice\0"] {
            assert!(
                get_user_by_username(&conn, variant, "default")
                    .unwrap()
                    .is_none(),
                "{variant:?}"
            );
            assert_eq!(
                verify_password_with(&conn, variant, "pw", "default", accept_all).unwrap(),
                None,
                "{variant:?}"
            );
            assert!(
                !set_password_hash(&conn, variant, &"ff".repeat(32), &[2; 32], "default").unwrap()
            );
            assert!(!update_user(
                &conn,
                variant,
                "default",
                Some("viewer"),
                None,
                None,
                Some(false)
            )
            .unwrap());
        }

        let upper = insert_user(&conn, "Alice", "viewer", true);
        assert_ne!(upper, alice);
        assert_eq!(
            verify_password_with(&conn, "alice", "pw", "default", accept_all)
                .unwrap()
                .map(|c| c.user_id),
            Some(alice)
        );
        let original = user(&conn, "alice");
        assert_eq!((original.role.as_str(), original.enabled), ("admin", true));
        assert_eq!(stored_credential(&conn, "alice"), before);
    }

    /// A verified credential carries the stored password hash; printing
    /// it (a log line, a panic message, `{:?}` in a test failure) shows the
    /// account only, never the hash.
    #[test]
    fn a_verified_credential_never_prints_its_hash() {
        let hash = "c23370bdfca8944baf8868776098f74c72a43de350d49fc65c0d3000ab9d7669";
        let credential = VerifiedCredential {
            user_id: 42,
            password_hash: hash.into(),
        };
        for shown in [format!("{credential:?}"), format!("{credential:#?}")] {
            assert!(shown.contains("VerifiedCredential"), "{shown}");
            assert!(shown.contains("42"), "{shown}");
            assert!(!shown.contains(hash), "{shown}");
            assert!(!shown.contains(&hash[..16]), "{shown}");
        }
    }
}
