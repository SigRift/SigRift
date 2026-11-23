//! Leftovers of the gateway's former API key table.
//!
//! Older gateways served `/api/admin/keys*` themselves and stored keys in
//! an `api_keys` table in detections.db. Authentication never read that
//! table — the gateway's [`KeyStore`](crate::auth::api_key::KeyStore) and
//! the bridge both authenticate against `keys.json`, which only the bridge
//! writes — so a key created there never worked, and the dashboard could
//! neither list nor revoke, rotate or re-role the keys that did. Key
//! management is now proxied to the bridge's `/api/admin/keys*` routes.
//!
//! The table is left in place (never read for auth, never written); this
//! module only finds rows in it so start-up can tell the operator.

use rusqlite::Connection;

/// Key ids in the legacy `api_keys` table, oldest first; empty when the
/// table does not exist.
pub fn legacy_gateway_key_ids(conn: &Connection) -> Result<Vec<String>, rusqlite::Error> {
    let exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'api_keys')",
        [],
        |row| row.get(0),
    )?;
    if !exists {
        return Ok(Vec::new());
    }
    let mut stmt = conn.prepare("SELECT key_id FROM api_keys ORDER BY id")?;
    let ids = stmt
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::legacy_gateway_key_ids;

    /// The schema older gateways created.
    const OLDER_GATEWAY_SCHEMA: &str = "CREATE TABLE api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key_id TEXT UNIQUE NOT NULL,
        hash TEXT NOT NULL,
        salt BLOB NOT NULL,
        role TEXT NOT NULL DEFAULT 'viewer',
        description TEXT DEFAULT '',
        created_at TEXT NOT NULL,
        expires_at TEXT,
        node_id TEXT,
        enabled BOOLEAN DEFAULT 1,
        tenant_id TEXT DEFAULT 'default'
    );";

    #[test]
    fn no_table_means_no_legacy_keys() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        assert!(legacy_gateway_key_ids(&conn).unwrap().is_empty());
    }

    #[test]
    fn rows_written_by_an_older_gateway_are_reported() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(OLDER_GATEWAY_SCHEMA).unwrap();
        conn.execute_batch(
            "INSERT INTO api_keys (key_id, hash, salt, created_at)
                VALUES ('key_b', 'h', x'00', '2026-01-02'), ('key_a', 'h', x'00', '2026-01-01');",
        )
        .unwrap();
        assert_eq!(legacy_gateway_key_ids(&conn).unwrap(), ["key_b", "key_a"]);
    }

    /// A key that exists only in the legacy table is reported, never
    /// authenticated. In an auth-enabled gateway state whose database (the
    /// one start-up checks for the table) holds an admin key row, that key
    /// is refused by the auth middleware with 401, while a key stored in
    /// keys.json in the same credential format authenticates.
    #[tokio::test]
    async fn a_key_only_in_the_legacy_table_does_not_authenticate() {
        use crate::auth::api_key::Role;
        use crate::middleware::auth::{self as mw, AuthInfo};
        use axum::http::StatusCode;
        use axum::response::IntoResponse as _;
        use sha2::Digest as _;
        use std::sync::Arc;
        use tower::ServiceExt as _;

        // Legacy SHA-256(salt bytes + key): what the older gateway stored,
        // and a format keys.json entries still verify with.
        let salt = [5u8; 32];
        let salted = |raw: &str| {
            let mut hasher = sha2::Sha256::new();
            hasher.update(salt);
            hasher.update(raw.as_bytes());
            hex::encode(hasher.finalize())
        };
        let (in_keys_json, in_table) = ("sk-current-keys-json", "sk-legacy-table-only");
        let keys_json = format!(
            r#"{{"keys": {{"current": {{"hash": "{}", "salt": "{}", "lookup_hash": "{}",
                "role": "admin"}}}}}}"#,
            salted(in_keys_json),
            hex::encode(salt),
            hex::encode(sha2::Sha256::digest(in_keys_json.as_bytes())),
        );
        let dir = tempfile::tempdir().unwrap();
        let state = crate::ws::test_harness::state(&dir, "http://bridge.invalid", &keys_json, None);
        {
            let conn = state.db_pool.get().unwrap();
            conn.execute_batch(OLDER_GATEWAY_SCHEMA).unwrap();
            conn.execute(
                "INSERT INTO api_keys (key_id, hash, salt, role, created_at) \
                 VALUES ('old_admin', ?1, ?2, 'admin', '2026-01-01')",
                rusqlite::params![salted(in_table), salt.to_vec()],
            )
            .unwrap();
            assert_eq!(legacy_gateway_key_ids(&conn).unwrap(), ["old_admin"]);
        }

        let app = axum::Router::new()
            .route(
                "/probe",
                axum::routing::get(|req: axum::extract::Request| async move {
                    match mw::require_auth(&req, Role::Viewer) {
                        Ok(AuthInfo::ApiKey { key_id, .. }) => key_id.into_response(),
                        Ok(_) => StatusCode::IM_A_TEAPOT.into_response(),
                        Err(status) => status.into_response(),
                    }
                }),
            )
            .layer(axum::middleware::from_fn_with_state(
                Arc::clone(&state),
                mw::auth_middleware,
            ));
        for (key, expected) in [
            (in_table, (StatusCode::UNAUTHORIZED, "")),
            (in_keys_json, (StatusCode::OK, "current")),
        ] {
            let req = axum::http::Request::get("/probe")
                .header("x-api-key", key)
                .body(axum::body::Body::empty())
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            let status = resp.status();
            let body = axum::body::to_bytes(resp.into_body(), 1 << 16)
                .await
                .unwrap();
            assert_eq!(
                (status, String::from_utf8_lossy(&body).as_ref()),
                expected,
                "{key}"
            );
        }
    }

    /// A legacy table that exists but cannot be read is an error, not an
    /// empty list, so start-up does not wrongly report "no leftover keys".
    #[test]
    fn an_unreadable_legacy_table_is_an_error() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE api_keys (id INTEGER PRIMARY KEY, name TEXT)")
            .unwrap();
        assert!(legacy_gateway_key_ids(&conn).is_err());
    }
}
