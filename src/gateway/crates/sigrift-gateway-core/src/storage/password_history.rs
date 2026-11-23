//! Password history storage — prevents reuse of recent passwords.

use crate::db::manager::SqliteConnectionManager;
use r2d2::PooledConnection;
use rusqlite::params;

use crate::auth::password;

/// Create the password_history table if it doesn't exist.
pub fn ensure_password_history_table(
    conn: &PooledConnection<SqliteConnectionManager>,
) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS password_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            password_hash TEXT NOT NULL,
            salt BLOB NOT NULL,
            changed_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )",
    )?;
    Ok(())
}

/// Record an old password hash before overwriting it.
pub fn add_password_history(
    conn: &PooledConnection<SqliteConnectionManager>,
    user_id: i64,
    hash: &str,
    salt: &[u8],
) -> Result<(), rusqlite::Error> {
    let now = chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S+00:00")
        .to_string();
    conn.execute(
        "INSERT INTO password_history (user_id, password_hash, salt, changed_at) \
         VALUES (?1, ?2, ?3, ?4)",
        params![user_id, hash, salt, now],
    )?;
    Ok(())
}

/// Check whether `new_password` matches any of the last `check_count` passwords
/// for this user. Returns `true` if the password has been used recently (reuse
/// detected).
pub fn check_password_reuse(
    conn: &PooledConnection<SqliteConnectionManager>,
    user_id: i64,
    new_password: &str,
    check_count: usize,
) -> Result<bool, rusqlite::Error> {
    let mut stmt = conn.prepare_cached(
        "SELECT password_hash, salt FROM password_history \
         WHERE user_id = ?1 \
         ORDER BY changed_at DESC \
         LIMIT ?2",
    )?;

    let rows = stmt.query_map(params![user_id, check_count as i64], |row| {
        let hash: String = row.get(0)?;
        let salt_ref = row.get_ref(1)?;
        let salt = password::decode_salt(&salt_ref).unwrap_or_default();
        Ok((hash, salt))
    })?;

    for entry in rows {
        let (hash, salt) = entry?;
        let (matches, _) = password::verify_credential(new_password, &hash, &salt);
        if matches {
            return Ok(true);
        }
    }

    Ok(false)
}

/// Delete password history entries beyond the most recent `keep_count` for a
/// user. Returns the number of rows deleted.
pub fn cleanup_password_history(
    conn: &PooledConnection<SqliteConnectionManager>,
    user_id: i64,
    keep_count: usize,
) -> Result<usize, rusqlite::Error> {
    let deleted = conn.execute(
        "DELETE FROM password_history WHERE user_id = ?1 AND id NOT IN (
            SELECT id FROM password_history WHERE user_id = ?1
            ORDER BY changed_at DESC LIMIT ?2
        )",
        params![user_id, keep_count as i64],
    )?;
    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::users::tests::insert_user;
    use crate::test_support;
    use sha2::{Digest, Sha256};

    type Conn = PooledConnection<SqliteConnectionManager>;

    /// A legacy salted SHA-256 credential (`SHA-256(salt || password)`):
    /// `verify_credential` accepts it like any stored hash, and building
    /// it costs no PBKDF2.
    fn legacy_hash(password: &str, salt: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(salt);
        hasher.update(password.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Insert a history entry with an explicit `changed_at`.
    fn add_dated(conn: &Conn, user: i64, password: &str, changed_at: &str) {
        let salt = [password.len() as u8; 32];
        conn.execute(
            "INSERT INTO password_history (user_id, password_hash, salt, changed_at) \
             VALUES (?1, ?2, ?3, ?4)",
            params![
                user,
                legacy_hash(password, &salt),
                salt.to_vec(),
                changed_at
            ],
        )
        .unwrap();
    }

    fn setup(dir: &tempfile::TempDir) -> (Conn, i64, i64) {
        let state = test_support::app_state(dir);
        let conn = state.db_pool.get().unwrap();
        ensure_password_history_table(&conn).unwrap();
        let alice = insert_user(&conn, "alice", "viewer", true);
        let bob = insert_user(&conn, "bob", "viewer", true);
        (conn, alice, bob)
    }

    fn rows(conn: &Conn, user: i64) -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM password_history WHERE user_id = ?1",
            params![user],
            |r| r.get(0),
        )
        .unwrap()
    }

    /// The gateway creates the table at every start: doing so again must
    /// keep the recorded history (or reuse checks would silently reset).
    #[test]
    fn ensuring_the_table_again_keeps_the_history() {
        let dir = tempfile::tempdir().unwrap();
        let (conn, alice, _) = setup(&dir);
        add_password_history(
            &conn,
            alice,
            &legacy_hash("Old-passw0rd", &[1; 32]),
            &[1; 32],
        )
        .unwrap();
        ensure_password_history_table(&conn).unwrap();
        assert_eq!(rows(&conn, alice), 1);
    }

    /// A password in the user's history is detected (salt stored as BLOB,
    /// as Python writes it, or as hex TEXT); another user's history does
    /// not apply. (Each entry checked costs one PBKDF2, so few entries.)
    #[test]
    fn recent_password_is_detected_for_its_user_only() {
        let dir = tempfile::tempdir().unwrap();
        let (conn, alice, bob) = setup(&dir);
        let blob_salt = [0x11u8; 32];
        add_password_history(
            &conn,
            alice,
            &legacy_hash("Blob-salt-passw0rd", &blob_salt),
            &blob_salt,
        )
        .unwrap();
        let text_salt = [0x22u8; 32];
        conn.execute(
            "INSERT INTO password_history (user_id, password_hash, salt, changed_at) \
             VALUES (?1, ?2, ?3, '2026-01-01T00:00:00+00:00')",
            params![
                bob,
                legacy_hash("Text-salt-passw0rd", &text_salt),
                hex::encode(text_salt)
            ],
        )
        .unwrap();

        assert!(check_password_reuse(&conn, alice, "Blob-salt-passw0rd", 5).unwrap());
        assert!(check_password_reuse(&conn, bob, "Text-salt-passw0rd", 5).unwrap());
        assert!(
            !check_password_reuse(&conn, alice, "Text-salt-passw0rd", 5).unwrap(),
            "bob's history does not constrain alice"
        );
    }

    /// Only the last `check_count` passwords are refused; older ones fall
    /// out of the window.
    #[test]
    fn only_the_most_recent_passwords_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (conn, alice, _) = setup(&dir);
        add_dated(&conn, alice, "Oldest-pw1", "2024-01-01T00:00:00+00:00");
        add_dated(
            &conn,
            alice,
            "Newest-password-1",
            "2026-01-01T00:00:00+00:00",
        );

        assert!(
            !check_password_reuse(&conn, alice, "Oldest-pw1", 1).unwrap(),
            "outside a 1-entry window"
        );
        assert!(check_password_reuse(&conn, alice, "Oldest-pw1", 2).unwrap());
        assert!(
            !check_password_reuse(&conn, alice, "Newest-password-1", 0).unwrap(),
            "a zero-length history checks nothing"
        );
    }

    #[test]
    fn cleanup_keeps_the_most_recent_entries_of_that_user_only() {
        let dir = tempfile::tempdir().unwrap();
        let (conn, alice, bob) = setup(&dir);
        add_dated(&conn, alice, "Oldest-pw1", "2024-01-01T00:00:00+00:00");
        add_dated(&conn, alice, "Middle-passw0rd", "2025-01-01T00:00:00+00:00");
        add_dated(
            &conn,
            alice,
            "Newest-password-1",
            "2026-01-01T00:00:00+00:00",
        );
        add_dated(&conn, bob, "Bobs-passw0rd", "2020-01-01T00:00:00+00:00");

        assert_eq!(cleanup_password_history(&conn, alice, 2).unwrap(), 1);
        assert_eq!(rows(&conn, bob), 1, "other users' history untouched");
        let kept: Vec<String> = conn
            .prepare("SELECT changed_at FROM password_history WHERE user_id = ?1 ORDER BY id")
            .unwrap()
            .query_map(params![alice], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            kept,
            ["2025-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00"],
            "the oldest entry is the one removed"
        );
    }

    #[test]
    fn reuse_check_without_the_table_is_an_error_not_a_pass() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        assert!(check_password_reuse(&conn, 1, "Any-passw0rd", 5).is_err());
    }
}
