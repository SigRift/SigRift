//! Admin session management handlers.
//!
//! List all sessions, kill individual sessions by token prefix.

use axum::{
    body::Body,
    extract::{Path, State},
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;
use tracing::{info, warn};

use crate::audit::{chain as audit_chain, store as audit_store};
use crate::auth::api_key::INSTANCE_TENANT;
use crate::auth::rbac::Role;
use crate::middleware::auth::{require_auth, AuthInfo};
use crate::storage::sessions::{self, PrefixDelete};
use crate::AppState;

/// Best-effort audit logging -- never fails the operation.
fn audit_event(
    state: &AppState,
    conn: &r2d2::PooledConnection<crate::db::manager::SqliteConnectionManager>,
    action: &str,
    target: &str,
    operator: &str,
) {
    if let Ok(secret) =
        audit_chain::get_audit_secret(&state.config.audit_key, &state.config.bridge_env)
    {
        if let Err(e) =
            audit_store::log_auth_event(conn, &secret, action, target, operator, "", "default")
        {
            warn!(error = %e, action, "Failed to log audit event");
        }
    }
}

fn operator_name(auth: &AuthInfo) -> String {
    match auth {
        AuthInfo::Session { username, .. } => username.clone(),
        AuthInfo::ApiKey { key_id, .. } => key_id.clone(),
        AuthInfo::Unauthenticated => String::new(),
    }
}

/// GET /api/admin/sessions -- list all active sessions.
pub async fn list_sessions_handler(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
) -> Response {
    if let Err(status) = require_auth(&req, Role::Admin) {
        return status.into_response();
    }

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };

    match sessions::list_all_sessions(&conn, INSTANCE_TENANT) {
        Ok(list) => (StatusCode::OK, Json(list)).into_response(),
        Err(e) => {
            warn!(error = %e, "Failed to list sessions");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// DELETE /api/admin/sessions/{token_prefix} -- kill a session by hash prefix.
///
/// The prefix must be 8–64 hex characters (as `GET /api/admin/sessions`
/// shows them) and must match exactly one of this instance's sessions: 400
/// otherwise for a malformed prefix, 409 when it matches several sessions
/// (none is deleted), 404 when it matches none. Other tenants' sessions are
/// neither killed nor counted.
pub async fn kill_session_handler(
    State(state): State<Arc<AppState>>,
    Path(token_prefix): Path<String>,
    req: Request<Body>,
) -> Response {
    let auth = match require_auth(&req, Role::Admin) {
        Ok(a) => a,
        Err(status) => return status.into_response(),
    };
    let operator = operator_name(&auth);

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };

    // Scoped like the listing: this instance's sessions only.
    match sessions::delete_session_by_prefix(&conn, &token_prefix, INSTANCE_TENANT) {
        Ok(PrefixDelete::Invalid) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "detail": format!(
                    "Session prefix must be {}-64 hex characters",
                    sessions::MIN_TOKEN_PREFIX_LEN
                )
            })),
        )
            .into_response(),
        Ok(PrefixDelete::Ambiguous(n)) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "detail": format!("Prefix matches {n} sessions; give more characters")
            })),
        )
            .into_response(),
        Ok(PrefixDelete::Deleted) => {
            audit_event(
                &state,
                &conn,
                "admin_session_kill",
                &token_prefix,
                &operator,
            );
            info!(
                token_prefix = token_prefix,
                operator = operator,
                "Admin killed session"
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({"status": "killed"})),
            )
                .into_response()
        }
        Ok(PrefixDelete::NotFound) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"detail": "Session not found"})),
        )
            .into_response(),
        Err(e) => {
            warn!(error = %e, "Failed to kill session");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::users::tests::insert_user;
    use crate::test_support;

    fn admin_request() -> Request<Body> {
        let mut req = Request::delete("/api/admin/sessions/x")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(AuthInfo::ApiKey {
            key_id: "admin-key".into(),
            role: Role::Admin,
        });
        req
    }

    /// Regression (G13): `DELETE /api/admin/sessions/%25` (path value `%`)
    /// matched every session in the LIKE and logged everybody out.
    #[tokio::test]
    async fn wildcard_prefix_kills_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let user = insert_user(&conn, "alice", "viewer", true);
        let config = sessions::SessionConfig::default();
        let (token, _) = sessions::create_session(&conn, user, "", "", &config).unwrap();
        sessions::create_session(&conn, user, "", "", &config).unwrap();
        drop(conn);

        for prefix in ["%", "_", "%%%%%%%%"] {
            let resp = kill_session_handler(
                State(Arc::clone(&state)),
                Path(prefix.to_string()),
                admin_request(),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{prefix:?}");
        }
        let conn = state.db_pool.get().unwrap();
        assert_eq!(sessions::count_user_sessions(&conn, user).unwrap(), 2);
        drop(conn);

        let hash = crate::auth::password::hash_session_token(&token);
        let resp = kill_session_handler(
            State(Arc::clone(&state)),
            Path(hash[..8].to_string()),
            admin_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let conn = state.db_pool.get().unwrap();
        assert_eq!(sessions::count_user_sessions(&conn, user).unwrap(), 1);
    }

    // ── Authorization, outcomes, tenant boundary ──────────────────────

    /// Callers below admin, and nobody at all.
    fn non_admin_callers() -> Vec<Option<AuthInfo>> {
        vec![
            None,
            Some(AuthInfo::Unauthenticated),
            Some(AuthInfo::Session {
                username: "victor".into(),
                user_id: 99,
                role: Role::Viewer,
                session_token: "t".into(),
                expires_at: String::new(),
                tenant_id: "default".into(),
                scope: String::new(),
            }),
            Some(AuthInfo::ApiKey {
                key_id: "analyst-key".into(),
                role: Role::Analyst,
            }),
        ]
    }

    fn request_as(auth: Option<AuthInfo>) -> Request<Body> {
        let mut req = Request::get("/api/admin/sessions")
            .body(Body::empty())
            .unwrap();
        if let Some(auth) = auth {
            req.extensions_mut().insert(auth);
        }
        req
    }

    fn expected_refusal(auth: &Option<AuthInfo>) -> StatusCode {
        match auth {
            None | Some(AuthInfo::Unauthenticated) => StatusCode::UNAUTHORIZED,
            Some(_) => StatusCode::FORBIDDEN,
        }
    }

    fn is_valid(state: &AppState, token: &str) -> bool {
        let conn = state.db_pool.get().unwrap();
        sessions::validate_session(&conn, token, &sessions::SessionConfig::default())
            .unwrap()
            .is_some()
    }

    fn new_session(state: &AppState, user: i64) -> String {
        let conn = state.db_pool.get().unwrap();
        sessions::create_session(&conn, user, "", "", &sessions::SessionConfig::default())
            .unwrap()
            .0
    }

    fn prefix_of(token: &str) -> String {
        crate::auth::password::hash_session_token(token)[..sessions::MIN_TOKEN_PREFIX_LEN]
            .to_string()
    }

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn listing_sessions_requires_admin() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user = insert_user(&state.db_pool.get().unwrap(), "alice", "viewer", true);
        let token = new_session(&state, user);

        for auth in non_admin_callers() {
            let expected = expected_refusal(&auth);
            let resp = list_sessions_handler(State(Arc::clone(&state)), request_as(auth)).await;
            assert_eq!(resp.status(), expected);
            let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
                .await
                .unwrap();
            assert!(
                !String::from_utf8_lossy(&bytes).contains(&prefix_of(&token)),
                "a refused caller learns nothing"
            );
        }

        let resp = list_sessions_handler(State(Arc::clone(&state)), admin_request()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let listed = body_json(resp).await;
        assert_eq!(listed.as_array().unwrap().len(), 1);
        assert_eq!(listed[0]["username"], "alice");
        assert_eq!(listed[0]["token_prefix"], prefix_of(&token));
    }

    /// The admin listing shows this instance's sessions only, and only a
    /// prefix of each token hash.
    #[tokio::test]
    async fn listing_is_instance_scoped_and_exposes_no_token_material() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let (alice, mallory) = {
            let conn = state.db_pool.get().unwrap();
            let alice = insert_user(&conn, "alice", "viewer", true);
            let mallory = insert_user(&conn, "mallory", "admin", true);
            conn.execute(
                "UPDATE users SET tenant_id = 'other' WHERE id = ?1",
                [mallory],
            )
            .unwrap();
            (alice, mallory)
        };
        let local = new_session(&state, alice);
        let foreign = new_session(&state, mallory);

        let resp = list_sessions_handler(State(Arc::clone(&state)), admin_request()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(text.contains(&prefix_of(&local)));
        assert!(!text.contains(&local), "raw token leaked");
        assert!(
            !text.contains(&crate::auth::password::hash_session_token(&local)),
            "full token hash leaked"
        );
        assert!(!text.contains("mallory"), "foreign tenant session listed");
        assert!(!text.contains(&prefix_of(&foreign)));
    }

    #[tokio::test]
    async fn killing_a_session_requires_admin_and_refusals_delete_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user = insert_user(&state.db_pool.get().unwrap(), "alice", "viewer", true);
        let token = new_session(&state, user);

        for auth in non_admin_callers() {
            let expected = expected_refusal(&auth);
            let resp = kill_session_handler(
                State(Arc::clone(&state)),
                Path(prefix_of(&token)),
                request_as(auth),
            )
            .await;
            assert_eq!(resp.status(), expected);
        }
        assert!(is_valid(&state, &token), "no refused caller killed it");
        assert_eq!(test_support::audit_count(&state, "admin_session_kill"), 0);
    }

    /// One admin action kills exactly the one session it names, is audited
    /// with the operator, and the killed token stops working at once.
    #[tokio::test]
    async fn kill_outcomes_conflict_not_found_and_audited_success() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user = insert_user(&state.db_pool.get().unwrap(), "alice", "viewer", true);
        let victim = new_session(&state, user);
        let bystander = new_session(&state, user);
        {
            // Two sessions sharing an 8-char hash prefix.
            let conn = state.db_pool.get().unwrap();
            for tail in ["1", "2"] {
                conn.execute(
                    "INSERT INTO sessions (session_token, user_id, created_at, expires_at) \
                     VALUES (?1, ?2, '2026-01-01T00:00:00+00:00', '2099-01-01T00:00:00+00:00')",
                    rusqlite::params![format!("dddddddd{tail}{}", "0".repeat(55)), user],
                )
                .unwrap();
            }
        }
        let kill = |prefix: &str| {
            kill_session_handler(
                State(Arc::clone(&state)),
                Path(prefix.to_string()),
                admin_request(),
            )
        };

        assert_eq!(kill("dddddddd").await.status(), StatusCode::CONFLICT);
        assert_eq!(kill("eeeeeeee").await.status(), StatusCode::NOT_FOUND);
        let conn = state.db_pool.get().unwrap();
        assert_eq!(sessions::count_user_sessions(&conn, user).unwrap(), 4);
        drop(conn);
        assert_eq!(test_support::audit_count(&state, "admin_session_kill"), 0);

        let resp = kill(&prefix_of(&victim)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp).await["status"], "killed");
        assert!(!is_valid(&state, &victim));
        assert!(is_valid(&state, &bystander));
        assert_eq!(test_support::audit_count(&state, "admin_session_kill"), 1);
        let (target, operator): (String, String) = state
            .db_pool
            .get()
            .unwrap()
            .query_row(
                "SELECT target_id, operator FROM audit_log WHERE action = 'admin_session_kill'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(target, prefix_of(&victim));
        assert_eq!(operator, "admin-key");

        assert_eq!(
            kill(&prefix_of(&victim)).await.status(),
            StatusCode::NOT_FOUND,
            "already killed"
        );
    }

    /// A storage failure is reported as such (500), never as an empty
    /// listing, a "not found" or a successful kill.
    #[tokio::test]
    async fn storage_failure_is_not_reported_as_an_outcome() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        state
            .db_pool
            .get()
            .unwrap()
            .execute_batch("ALTER TABLE sessions RENAME TO sessions_unavailable")
            .unwrap();

        let resp = list_sessions_handler(State(Arc::clone(&state)), admin_request()).await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let resp = kill_session_handler(
            State(Arc::clone(&state)),
            Path("abcdef0123".into()),
            admin_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(test_support::audit_count(&state, "admin_session_kill"), 0);
    }

    /// The admin may kill this instance's sessions only: a session of
    /// another tenant's user is outside its reach (as for logout, the
    /// foreign record must be left untouched), so the listing never shows
    /// it and the kill reports 404.
    #[tokio::test]
    async fn tenant_boundary_admin_cannot_kill_a_foreign_session() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let mallory = {
            let conn = state.db_pool.get().unwrap();
            let id = insert_user(&conn, "mallory", "admin", true);
            conn.execute("UPDATE users SET tenant_id = 'other' WHERE id = ?1", [id])
                .unwrap();
            id
        };
        let foreign = new_session(&state, mallory);

        let resp = kill_session_handler(
            State(Arc::clone(&state)),
            Path(prefix_of(&foreign)),
            admin_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let conn = state.db_pool.get().unwrap();
        assert_eq!(
            sessions::count_user_sessions(&conn, mallory).unwrap(),
            1,
            "foreign session deleted across the tenant boundary"
        );
        drop(conn);
        assert_eq!(test_support::audit_count(&state, "admin_session_kill"), 0);
    }

    /// Another tenant's sessions are invisible to the prefix match as a
    /// whole — not just to the delete: a foreign session sharing a prefix
    /// with a local one neither blocks the kill of the local session nor
    /// shows up in the ambiguity count (which would reveal it).
    #[tokio::test]
    async fn tenant_boundary_foreign_sessions_do_not_make_a_local_prefix_ambiguous() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let (alice, mallory) = {
            let conn = state.db_pool.get().unwrap();
            let alice = insert_user(&conn, "alice", "viewer", true);
            let mallory = insert_user(&conn, "mallory", "admin", true);
            conn.execute(
                "UPDATE users SET tenant_id = 'other' WHERE id = ?1",
                [mallory],
            )
            .unwrap();
            (alice, mallory)
        };
        let raw_session = |hash: String, user: i64| {
            state
                .db_pool
                .get()
                .unwrap()
                .execute(
                    "INSERT INTO sessions (session_token, user_id, created_at, expires_at) \
                     VALUES (?1, ?2, '2026-01-01T00:00:00+00:00', '2099-01-01T00:00:00+00:00')",
                    rusqlite::params![hash, user],
                )
                .unwrap();
        };
        let session_exists = |hash: &str| {
            state
                .db_pool
                .get()
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM sessions WHERE session_token = ?1",
                    [hash],
                    |r| r.get::<_, i64>(0),
                )
                .unwrap()
                == 1
        };
        let kill = |prefix: &str| {
            kill_session_handler(
                State(Arc::clone(&state)),
                Path(prefix.to_string()),
                admin_request(),
            )
        };

        // One local and one foreign session share the prefix: the local
        // one is the only match.
        let local = format!("abababab1{}", "0".repeat(55));
        let foreign = format!("abababab2{}", "0".repeat(55));
        raw_session(local.clone(), alice);
        raw_session(foreign.clone(), mallory);
        let resp = kill("abababab").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(!session_exists(&local), "the local session is killed");
        assert!(session_exists(&foreign), "the foreign session is untouched");
        assert_eq!(test_support::audit_count(&state, "admin_session_kill"), 1);

        // Two local and one foreign: ambiguous, and the count is the local one.
        let locals = [
            format!("cdcdcdcd1{}", "0".repeat(55)),
            format!("cdcdcdcd2{}", "0".repeat(55)),
        ];
        let foreign = format!("cdcdcdcd3{}", "0".repeat(55));
        for hash in &locals {
            raw_session(hash.clone(), alice);
        }
        raw_session(foreign.clone(), mallory);
        let resp = kill("cdcdcdcd").await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let detail = body_json(resp).await["detail"].to_string();
        assert!(
            detail.contains("matches 2 sessions"),
            "the foreign session is not counted: {detail}"
        );
        assert!(locals.iter().all(|h| session_exists(h)));
        assert!(session_exists(&foreign));

        // Several foreign sessions only: not found, not ambiguous (a 409
        // would reveal that they exist).
        let foreigns = [
            format!("efefefef1{}", "0".repeat(55)),
            format!("efefefef2{}", "0".repeat(55)),
        ];
        for hash in &foreigns {
            raw_session(hash.clone(), mallory);
        }
        assert_eq!(kill("efefefef").await.status(), StatusCode::NOT_FOUND);
        assert!(foreigns.iter().all(|h| session_exists(h)));
        assert_eq!(test_support::audit_count(&state, "admin_session_kill"), 1);
    }
}

#[cfg(test)]
mod coverage_tests {
    //! Session-admin paths the main suite leaves untaken: best-effort audit
    //! and no database connection.

    use super::*;
    use crate::db::pool::DbPool;
    use crate::storage::users::tests::insert_user;
    use crate::test_support;
    use std::time::Duration;

    fn admin_request() -> Request<Body> {
        let mut req = Request::delete("/api/admin/sessions/x")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(AuthInfo::ApiKey {
            key_id: "admin-key".into(),
            role: Role::Admin,
        });
        req
    }

    /// A new session of a new user `alice`.
    fn alice_session(pool: &DbPool) -> String {
        let conn = pool.get().unwrap();
        let user = insert_user(&conn, "alice", "viewer", true);
        sessions::create_session(&conn, user, "", "", &sessions::SessionConfig::default())
            .unwrap()
            .0
    }

    fn prefix_of(token: &str) -> String {
        crate::auth::password::hash_session_token(token)[..sessions::MIN_TOKEN_PREFIX_LEN]
            .to_string()
    }

    fn session_exists(pool: &DbPool, token: &str) -> bool {
        pool.get()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM sessions WHERE session_token = ?1",
                [crate::auth::password::hash_session_token(token)],
                |row| row.get::<_, i64>(0),
            )
            .unwrap()
            == 1
    }

    async fn kill(state: &Arc<AppState>, token: &str) -> Response {
        kill_session_handler(
            State(Arc::clone(state)),
            Path(prefix_of(token)),
            admin_request(),
        )
        .await
    }

    async fn assert_kill_with_audit_records(state: &Arc<AppState>, records: i64) {
        let token = alice_session(&state.db_pool);
        assert_eq!(kill(state, &token).await.status(), StatusCode::OK);
        assert!(
            !session_exists(&state.db_pool, &token),
            "the session is gone"
        );
        assert_eq!(
            test_support::audit_count(state, "admin_session_kill"),
            records
        );
    }

    /// Audit logging is best effort: a kill whose record cannot be signed
    /// (production without an audit key) or cannot be written still ends
    /// the session.
    #[tokio::test]
    async fn a_kill_ends_the_session_when_its_audit_record_cannot_be_kept() {
        // Without a configured key, production signs with a legacy
        // fallback from the environment if one is set (CI sets none).
        let signed_without_key = i64::from(audit_chain::get_audit_secret("", "production").is_ok());
        let dir = tempfile::tempdir().unwrap();
        let mut unsigned =
            Arc::into_inner(test_support::app_state(&dir)).expect("a fresh state has one owner");
        unsigned.config.bridge_env = "production".into();
        unsigned.config.audit_key = String::new();
        assert_kill_with_audit_records(&Arc::new(unsigned), signed_without_key).await;

        let dir = tempfile::tempdir().unwrap();
        let unwritable = test_support::app_state(&dir);
        unwritable
            .db_pool
            .get()
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER no_audit BEFORE INSERT ON audit_log \
                 BEGIN SELECT RAISE(ABORT, 'audit log unavailable'); END;",
            )
            .unwrap();
        assert_kill_with_audit_records(&unwritable, 0).await;
    }

    /// Without a database connection the listing and the kill answer 503
    /// (never an empty list, a "not found" or a success), and the session
    /// lives on.
    #[tokio::test]
    async fn session_admin_answers_503_when_the_database_is_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let token = alice_session(&state.db_pool);
        let mut state = Arc::into_inner(state).expect("a fresh state has one owner");
        let refusing = crate::db::manager::SqliteConnectionManager::file(&state.config.db_path)
            .with_init(|_| Err(rusqlite::Error::InvalidQuery));
        // No connection can ever be established: the timeout only bounds
        // each wait.
        let unavailable = r2d2::Pool::builder()
            .max_size(1)
            .connection_timeout(Duration::from_millis(50))
            .build_unchecked(refusing);
        let database = std::mem::replace(&mut state.db_pool, unavailable);
        let state = Arc::new(state);

        let resp = list_sessions_handler(State(Arc::clone(&state)), admin_request()).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            kill(&state, &token).await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(session_exists(&database, &token));
    }

    /// A kill by an admin's own session (not an API key) is audited under
    /// that admin's username.
    #[tokio::test]
    async fn a_kill_by_an_admin_session_is_audited_under_its_username() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let token = alice_session(&state.db_pool);
        let mut req = Request::delete("/api/admin/sessions/x")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(AuthInfo::Session {
            username: "root-admin".into(),
            user_id: 1,
            role: Role::Admin,
            session_token: "admin-session".into(),
            expires_at: String::new(),
            tenant_id: "default".into(),
            scope: String::new(),
        });

        let resp =
            kill_session_handler(State(Arc::clone(&state)), Path(prefix_of(&token)), req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(!session_exists(&state.db_pool, &token));
        let operator: String = state
            .db_pool
            .get()
            .unwrap()
            .query_row(
                "SELECT operator FROM audit_log WHERE action = 'admin_session_kill'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(operator, "root-admin");
    }
}
