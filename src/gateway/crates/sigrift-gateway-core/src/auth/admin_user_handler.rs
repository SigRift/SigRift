//! Admin user management handlers.
//!
//! All endpoints require `Role::Admin` and audit-log their operations.
//! Role ceilings (contract K5): a caller can create a user or give one a
//! role only up to its own role (KEYMASTER only as a KEYMASTER), and can
//! update, disable or reset the password of only users whose current role
//! it could have granted — otherwise an admin could take over a KEYMASTER
//! account by resetting its password. Password hashing (PBKDF2) runs on
//! the blocking pool.
//!
//! The username rule, the display_name and email length limits and the
//! role rule follow the bridge's request models (`CreateUserRequest` /
//! `UpdateUserRequest` in `routers/auth.py`) and are refused with the
//! bridge's status, 422: every refused role (an unknown name and the
//! machine roles alike) is 422, as every role outside the bridge's
//! `^(viewer|analyst|admin)$` is there. The gateway's own password policy
//! stays 400, as on every gateway route that sets a password (the
//! bridge only checks the length), and so does a body that is not the
//! expected JSON. Only new values are checked: accounts whose stored name
//! or role predates the rules stay listed and manageable through the
//! `{username}` routes.

use axum::{
    body::Body,
    extract::{Path, State},
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, warn};

use crate::audit::{chain as audit_chain, store as audit_store};
use crate::auth::password;
use crate::auth::rbac::Role;
use crate::db::pool::{with_conn_blocking, PooledConn};
use crate::middleware::auth::{require_auth, require_may_grant, require_may_manage, AuthInfo};
use crate::storage::{security_state, users};
use crate::AppState;

fn user_not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"detail": "User not found"})),
    )
        .into_response()
}

/// A request field the bridge's request model refuses: 422, as the bridge
/// answers, with the gateway's string `detail`.
fn unprocessable(detail: &str) -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(serde_json::json!({"detail": detail})),
    )
        .into_response()
}

const USERNAME_MAX_CHARS: usize = 64;

/// Bridge contract (`CreateUserRequest.username`, pattern
/// `^[a-zA-Z0-9_\-\.]+$` with 1 to 64 characters): every character is an
/// ASCII letter or digit, '_', '-' or '.'. The whole name is checked
/// untrimmed (the bridge's `$` is end of text), so a trailing newline or a
/// NUL is refused.
///
/// One deliberate tightening of the bridge rule: the names "." and ".."
/// are refused too. The K9 path guard (`middleware::path`) refuses a `.`
/// or `..` path segment, `%2E` spellings included, before routing, so no
/// `{username}` route (update, disable, password reset, MFA disable) could
/// ever reach such an account: an admin could create one, even with the
/// admin role, that nobody could disable, demote or reset through the API.
/// Every other name the rule accepts ("...", ".x", "a.b") is an ordinary
/// path segment.
fn validate_new_username(name: &str) -> Result<(), String> {
    let allowed = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.');
    let routable = !matches!(name, "." | "..");
    if (1..=USERNAME_MAX_CHARS).contains(&name.chars().count())
        && name.chars().all(allowed)
        && routable
    {
        Ok(())
    } else {
        Err(format!(
            "Invalid username: use 1 to {USERNAME_MAX_CHARS} characters from \
             A-Z, a-z, 0-9, '_', '-' and '.' (but not \".\" or \"..\")"
        ))
    }
}

const DISPLAY_NAME_MAX_CHARS: usize = 128;
const EMAIL_MAX_CHARS: usize = 256;

/// Bridge contract (`max_length` of `display_name` and `email` on
/// `CreateUserRequest` and `UpdateUserRequest`): at most 128 and 256
/// characters. Counted in characters (code points, as Pydantic counts),
/// not bytes. `None` is a field the request leaves out; an empty string is
/// valid.
fn validate_profile_lengths(display_name: Option<&str>, email: Option<&str>) -> Result<(), String> {
    for (field, value, max) in [
        ("display_name", display_name, DISPLAY_NAME_MAX_CHARS),
        ("email", email, EMAIL_MAX_CHARS),
    ] {
        if value.is_some_and(|v| v.chars().count() > max) {
            return Err(format!("{field} must be at most {max} characters"));
        }
    }
    Ok(())
}

/// Parse a role requested for a user account (create, or an update's new
/// role). The parse stays case-insensitive and KEYMASTER stays a user role
/// (the gateway's K5 extension; the grant ceiling still applies). The
/// Err is the response to return, always 422 as the bridge answers for
/// any role its pattern refuses: an unknown name is "Invalid role"; the
/// machine roles SENSOR and NODE, which belong to API keys and node
/// certificates, are refused by parsed role so that every spelling is
/// caught.
#[allow(clippy::result_large_err)] // the Err is the ready-made response
fn parse_user_role(requested: &str) -> Result<Role, Response> {
    match requested.parse::<Role>() {
        Ok(role @ (Role::Sensor | Role::Node)) => Err(unprocessable(&format!(
            "Invalid role: {role} is a machine role and cannot be given to a user account"
        ))),
        Ok(role) => Ok(role),
        Err(_) => Err(unprocessable("Invalid role")),
    }
}

/// K5 manage ceiling for an existing user. The Err is the response to
/// return: 404 if the user does not exist, 403 if its role is above what
/// the caller may manage, 500 on a database error.
#[allow(clippy::result_large_err)] // the Err is the ready-made response
fn require_may_manage_user(
    conn: &PooledConn,
    auth: &AuthInfo,
    username: &str,
) -> Result<users::User, Response> {
    match users::get_user_by_username(conn, username, "default") {
        Ok(Some(user)) => {
            require_may_manage(auth, Role::parse_stored_for_ceiling(&user.role), "user")?;
            Ok(user)
        }
        Ok(None) => Err(user_not_found()),
        Err(e) => {
            warn!(error = %e, "User lookup error");
            Err(StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
    }
}

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

// -- Request / Response types -------------------------------------------------

#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    pub role: Option<String>,
    pub display_name: Option<String>,
    pub email: Option<String>,
}

#[derive(Deserialize)]
pub struct UpdateUserRequest {
    pub role: Option<String>,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Deserialize)]
pub struct ResetPasswordRequest {
    pub new_password: String,
}

#[derive(Serialize)]
pub struct UserCreatedResponse {
    pub id: i64,
    pub username: String,
    pub role: String,
}

// -- Handlers -----------------------------------------------------------------

/// POST /api/admin/users -- create a new user account.
pub async fn create_user_handler(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
) -> Response {
    let auth = match require_auth(&req, Role::Admin) {
        Ok(a) => a,
        Err(status) => return status.into_response(),
    };
    let operator = operator_name(&auth);

    let body_bytes = match axum::body::to_bytes(req.into_body(), 4096).await {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let body: CreateUserRequest = match serde_json::from_slice(&body_bytes) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"detail": "Invalid request body"})),
            )
                .into_response()
        }
    };

    // Only a new name is checked; the {username} routes take any stored one.
    if let Err(e) = validate_new_username(&body.username) {
        return unprocessable(&e);
    }
    if let Err(e) = validate_profile_lengths(body.display_name.as_deref(), body.email.as_deref()) {
        return unprocessable(&e);
    }

    if let Err(e) = password::validate_password_strength(&body.password) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"detail": e})),
        )
            .into_response();
    }

    let role = match parse_user_role(body.role.as_deref().unwrap_or("viewer")) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if let Err(resp) = require_may_grant(&auth, role, "user") {
        return resp;
    }
    let role = role.as_str();

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };

    // create_user hashes the password (PBKDF2): run it on the blocking pool.
    let (username, password) = (body.username.clone(), body.password.clone());
    let display_name = body.display_name.clone().unwrap_or_default();
    let email = body.email.clone().unwrap_or_default();
    let Some((conn, created)) = with_conn_blocking(conn, move |conn| {
        users::create_user(
            conn,
            &username,
            &password,
            role,
            &display_name,
            &email,
            "default",
        )
    })
    .await
    else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };

    match created {
        Ok(id) => {
            audit_event(
                &state,
                &conn,
                "admin_create_user",
                &body.username,
                &operator,
            );
            info!(
                username = body.username,
                role,
                operator = operator,
                "Admin created user"
            );
            (
                StatusCode::CREATED,
                Json(UserCreatedResponse {
                    id,
                    username: body.username,
                    role: role.to_string(),
                }),
            )
                .into_response()
        }
        Err(e) => {
            if e.to_string().contains("UNIQUE constraint") {
                (
                    StatusCode::CONFLICT,
                    Json(serde_json::json!({"detail": "Username already exists"})),
                )
                    .into_response()
            } else {
                warn!(error = %e, "Failed to create user");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

/// GET /api/admin/users -- list all users.
pub async fn list_users_handler(
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

    match users::list_users(&conn, "default") {
        Ok(list) => (StatusCode::OK, Json(list)).into_response(),
        Err(e) => {
            warn!(error = %e, "Failed to list users");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// PUT /api/admin/users/{username} -- update user fields.
pub async fn update_user_handler(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
    req: Request<Body>,
) -> Response {
    let auth = match require_auth(&req, Role::Admin) {
        Ok(a) => a,
        Err(status) => return status.into_response(),
    };
    let operator = operator_name(&auth);

    let body_bytes = match axum::body::to_bytes(req.into_body(), 4096).await {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let body: UpdateUserRequest = match serde_json::from_slice(&body_bytes) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"detail": "Invalid request body"})),
            )
                .into_response()
        }
    };

    // Before the account lookup, the write and any session revocation.
    if let Err(e) = validate_profile_lengths(body.display_name.as_deref(), body.email.as_deref()) {
        return unprocessable(&e);
    }

    // Validate role if provided
    let new_role = match body.role.as_deref().map(parse_user_role) {
        None => None,
        Some(Ok(r)) => Some(r),
        Some(Err(resp)) => return resp,
    };
    if let Some(role) = new_role {
        if let Err(resp) = require_may_grant(&auth, role, "user") {
            return resp;
        }
    }

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    if let Err(resp) = require_may_manage_user(&conn, &auth, &username) {
        return resp;
    }

    let update = if body.enabled == Some(false) {
        users::update_user_and_revoke_sessions
    } else {
        users::update_user
    };
    match update(
        &conn,
        &username,
        "default",
        new_role.map(|r| r.as_str()),
        body.display_name.as_deref(),
        body.email.as_deref(),
        body.enabled,
    ) {
        Ok(true) => {
            audit_event(&state, &conn, "admin_update_user", &username, &operator);
            info!(
                username = username,
                operator = operator,
                "Admin updated user"
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({"status": "updated"})),
            )
                .into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"detail": "User not found"})),
        )
            .into_response(),
        Err(e) => {
            warn!(error = %e, "Failed to update user");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// DELETE /api/admin/users/{username} -- disable user and invalidate sessions.
pub async fn disable_user_handler(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
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
    if let Err(resp) = require_may_manage_user(&conn, &auth, &username) {
        return resp;
    }

    match users::update_user_and_revoke_sessions(
        &conn,
        &username,
        "default",
        None,
        None,
        None,
        Some(false),
    ) {
        Ok(true) => {
            audit_event(&state, &conn, "admin_disable_user", &username, &operator);
            info!(
                username = username,
                operator = operator,
                "Admin disabled user"
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({"status": "disabled"})),
            )
                .into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"detail": "User not found"})),
        )
            .into_response(),
        Err(e) => {
            warn!(error = %e, "Failed to disable user");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// POST /api/admin/users/{username}/reset-password -- admin password reset.
pub async fn reset_password_handler(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
    req: Request<Body>,
) -> Response {
    let auth = match require_auth(&req, Role::Admin) {
        Ok(a) => a,
        Err(status) => return status.into_response(),
    };
    let operator = operator_name(&auth);

    let body_bytes = match axum::body::to_bytes(req.into_body(), 4096).await {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let body: ResetPasswordRequest = match serde_json::from_slice(&body_bytes) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"detail": "Invalid request body"})),
            )
                .into_response()
        }
    };

    if let Err(e) = password::validate_password_strength(&body.new_password) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"detail": e})),
        )
            .into_response();
    }

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    if let Err(resp) = require_may_manage_user(&conn, &auth, &username) {
        return resp;
    }

    // set_password hashes (PBKDF2): run it on the blocking pool.
    let (target, new_password) = (username.clone(), body.new_password.clone());
    let Some((conn, updated)) = with_conn_blocking(conn, move |conn| {
        users::set_password_and_revoke_sessions(conn, &target, &new_password, "default")
    })
    .await
    else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };

    match updated {
        Ok(true) => {
            // The new password ends the account lockout too: the failures
            // counted guesses at the old one, and the user is to log in
            // with the new one now, not once the window has passed. On
            // error they stay counted; the reset itself has committed.
            if let Err(e) = security_state::clear_account_failures(
                &conn,
                &username,
                crate::auth::api_key::INSTANCE_TENANT,
            ) {
                warn!(
                    error = %e,
                    username = username,
                    "Password reset: failed to clear account lockout failures"
                );
            }
            audit_event(&state, &conn, "admin_password_reset", &username, &operator);
            info!(
                username = username,
                operator = operator,
                "Admin reset password"
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({"status": "password_reset"})),
            )
                .into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"detail": "User not found"})),
        )
            .into_response(),
        Err(e) => {
            warn!(error = %e, "Failed to reset password");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::sessions;
    use crate::storage::users::tests::insert_user;
    use crate::test_support;
    use sha2::Digest as _;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn request(method: &str, body: serde_json::Value, caller: Role) -> Request<Body> {
        let mut req = Request::builder()
            .method(method)
            .uri("/api/admin/users")
            .body(Body::from(body.to_string()))
            .unwrap();
        req.extensions_mut().insert(AuthInfo::ApiKey {
            key_id: format!("{caller}-key"),
            role: caller,
        });
        req
    }

    fn role_of(state: &AppState, username: &str) -> String {
        let conn = state.db_pool.get().unwrap();
        users::get_user_by_username(&conn, username, "default")
            .unwrap()
            .unwrap()
            .role
    }

    fn user_session(state: &AppState, username: &str) -> (i64, String) {
        user_session_with_role(state, username, "viewer")
    }

    fn user_session_with_role(state: &AppState, username: &str, role: &str) -> (i64, String) {
        let conn = state.db_pool.get().unwrap();
        let id = insert_user(&conn, username, role, true);
        let (token, _) = sessions::create_session(
            &conn,
            id,
            "127.0.0.1",
            "revocation-regression",
            &sessions::SessionConfig::default(),
        )
        .unwrap();
        assert!(
            sessions::validate_session(&conn, &token, &sessions::SessionConfig::default(),)
                .unwrap()
                .is_some()
        );
        (id, token)
    }

    fn reject_session_deletion(state: &AppState) {
        state
            .db_pool
            .get()
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER reject_session_deletion BEFORE DELETE ON sessions \
                 BEGIN SELECT RAISE(ABORT, 'session revocation unavailable'); END;",
            )
            .unwrap();
    }

    fn session_user_id(state: &AppState, token: &str) -> Option<i64> {
        sessions::validate_session(
            &state.db_pool.get().unwrap(),
            token,
            &sessions::SessionConfig::default(),
        )
        .unwrap()
        .map(|session| session.user_id)
    }

    #[tokio::test]
    async fn disable_rolls_back_when_session_revocation_fails() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let (id, token) = user_session(&state, "bob");
        reject_session_deletion(&state);

        let response = disable_user_handler(
            State(Arc::clone(&state)),
            Path("bob".into()),
            request("DELETE", serde_json::json!({}), Role::Admin),
        )
        .await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let user = users::get_user_by_username(&state.db_pool.get().unwrap(), "bob", "default")
            .unwrap()
            .unwrap();
        assert!(user.enabled, "a failed operation must preserve the account");
        assert_eq!(session_user_id(&state, &token), Some(id));
        assert_eq!(test_support::audit_count(&state, "admin_disable_user"), 0);
    }

    #[tokio::test]
    async fn update_disable_rolls_back_all_fields_when_session_revocation_fails() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let (id, token) = user_session(&state, "bob");
        reject_session_deletion(&state);

        let response = update_user_handler(
            State(Arc::clone(&state)),
            Path("bob".into()),
            request(
                "PUT",
                serde_json::json!({"enabled": false, "display_name": "Changed", "role": "admin"}),
                Role::Admin,
            ),
        )
        .await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let user = users::get_user_by_username(&state.db_pool.get().unwrap(), "bob", "default")
            .unwrap()
            .unwrap();
        assert!(user.enabled);
        assert_eq!(user.display_name, "");
        assert_eq!(user.role, "viewer");
        assert_eq!(session_user_id(&state, &token), Some(id));
        assert_eq!(test_support::audit_count(&state, "admin_update_user"), 0);
    }

    #[tokio::test]
    async fn update_disable_then_enable_does_not_revive_old_sessions() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let (_, token) = user_session(&state, "bob");

        for enabled in [false, true] {
            let response = update_user_handler(
                State(Arc::clone(&state)),
                Path("bob".into()),
                request("PUT", serde_json::json!({"enabled": enabled}), Role::Admin),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(session_user_id(&state, &token), None);
        }
        assert_eq!(test_support::audit_count(&state, "admin_update_user"), 2);
    }

    #[tokio::test]
    async fn password_reset_rolls_back_when_session_revocation_fails() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let old_password = "Original-Str0ng-Passw0rd";
        let (id, token, original_hash, original_salt) = {
            let conn = state.db_pool.get().unwrap();
            let id = users::create_user(&conn, "bob", old_password, "viewer", "", "", "default")
                .unwrap();
            let (token, _) = sessions::create_session(
                &conn,
                id,
                "127.0.0.1",
                "revocation-regression",
                &sessions::SessionConfig::default(),
            )
            .unwrap();
            let (hash, salt): (String, Vec<u8>) = conn
                .query_row(
                    "SELECT password_hash, salt FROM users WHERE id = ?1",
                    [id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            (id, token, hash, salt)
        };
        reject_session_deletion(&state);

        let response = reset_password_handler(
            State(Arc::clone(&state)),
            Path("bob".into()),
            request(
                "POST",
                serde_json::json!({"new_password": "Replacement-Str0ng-Passw0rd"}),
                Role::Admin,
            ),
        )
        .await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let conn = state.db_pool.get().unwrap();
        let stored: (String, Vec<u8>) = conn
            .query_row(
                "SELECT password_hash, salt FROM users WHERE id = ?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(stored, (original_hash, original_salt));
        assert_eq!(
            users::verify_password(&conn, "bob", old_password, "default").unwrap(),
            Some(id)
        );
        drop(conn);
        assert_eq!(session_user_id(&state, &token), Some(id));
        assert_eq!(test_support::audit_count(&state, "admin_password_reset"), 0);
    }

    #[tokio::test]
    async fn successful_reset_revokes_only_target_sessions_and_persists_password() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let (id, token) = user_session(&state, "bob");
        let (other_id, other_token) = user_session(&state, "other");
        let new_password = "Replacement-Str0ng-Passw0rd";

        let response = reset_password_handler(
            State(Arc::clone(&state)),
            Path("bob".into()),
            request(
                "POST",
                serde_json::json!({"new_password": new_password}),
                Role::Admin,
            ),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(session_user_id(&state, &token), None);
        assert_eq!(session_user_id(&state, &other_token), Some(other_id));
        let conn = state.db_pool.get().unwrap();
        assert_eq!(
            users::verify_password(&conn, "bob", new_password, "default").unwrap(),
            Some(id)
        );
        drop(conn);
        let reopened = rusqlite::Connection::open(&state.config.db_path).unwrap();
        let remaining: i64 = reopened
            .query_row(
                "SELECT COUNT(*) FROM sessions WHERE user_id = ?1",
                [id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remaining, 0, "revocation must be committed before success");
        assert_eq!(test_support::audit_count(&state, "admin_password_reset"), 1);
    }

    #[tokio::test]
    async fn successful_delete_revokes_sessions_permanently_without_touching_other_users() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let (id, token) = user_session(&state, "bob");
        let (other_id, other_token) = user_session(&state, "other");

        let response = disable_user_handler(
            State(Arc::clone(&state)),
            Path("bob".into()),
            request("DELETE", serde_json::json!({}), Role::Admin),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let reopened = rusqlite::Connection::open(&state.config.db_path).unwrap();
        let persisted: (bool, i64) = reopened
            .query_row(
                "SELECT enabled, (SELECT COUNT(*) FROM sessions WHERE user_id = users.id) \
                 FROM users WHERE id = ?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(persisted, (false, 0));
        let response = update_user_handler(
            State(Arc::clone(&state)),
            Path("bob".into()),
            request("PUT", serde_json::json!({"enabled": true}), Role::Admin),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(session_user_id(&state, &token), None);
        assert_eq!(session_user_id(&state, &other_token), Some(other_id));
        assert_eq!(test_support::audit_count(&state, "admin_disable_user"), 1);
    }

    #[tokio::test]
    async fn account_write_failure_keeps_sessions_and_does_not_audit_success() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let (id, token) = user_session(&state, "bob");
        state
            .db_pool
            .get()
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER reject_account_write BEFORE UPDATE OF enabled ON users \
             BEGIN SELECT RAISE(ABORT, 'account write unavailable'); END;",
            )
            .unwrap();

        let response = disable_user_handler(
            State(Arc::clone(&state)),
            Path("bob".into()),
            request("DELETE", serde_json::json!({}), Role::Admin),
        )
        .await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(session_user_id(&state, &token), Some(id));
        assert_eq!(test_support::audit_count(&state, "admin_disable_user"), 0);
        assert!(state.db_pool.get().unwrap().is_autocommit());
    }

    #[tokio::test]
    async fn missing_admin_targets_do_not_revoke_unrelated_sessions() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let (id, token) = user_session(&state, "bob");
        let response = disable_user_handler(
            State(Arc::clone(&state)),
            Path("nobody".into()),
            request("DELETE", serde_json::json!({}), Role::Admin),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let response = reset_password_handler(
            State(Arc::clone(&state)),
            Path("nobody".into()),
            request(
                "POST",
                serde_json::json!({"new_password": "Replacement-Str0ng-Passw0rd"}),
                Role::Admin,
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(session_user_id(&state, &token), Some(id));
        assert_eq!(test_support::audit_count(&state, "admin_disable_user"), 0);
        assert_eq!(test_support::audit_count(&state, "admin_password_reset"), 0);
    }

    /// Regression (G8 / K5): any Admin could create or promote a user to
    /// KEYMASTER, and could reset a KEYMASTER's password (taking the
    /// account over).
    #[tokio::test]
    async fn admin_cannot_grant_or_take_over_keymaster() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        {
            let conn = state.db_pool.get().unwrap();
            insert_user(&conn, "root", "keymaster", true);
            insert_user(&conn, "bob", "viewer", true);
        }
        let s = || State(Arc::clone(&state));
        let new_user = serde_json::json!({
            "username": "eve", "password": "Str0ng-Passw0rd", "role": "keymaster"
        });
        let resp = create_user_handler(s(), request("POST", new_user, Role::Admin)).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let promote = serde_json::json!({"role": "keymaster"});
        let resp = update_user_handler(
            s(),
            Path("bob".into()),
            request("PUT", promote.clone(), Role::Admin),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(role_of(&state, "bob"), "viewer");

        let demote = serde_json::json!({"role": "viewer"});
        let resp = update_user_handler(
            s(),
            Path("root".into()),
            request("PUT", demote, Role::Admin),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(role_of(&state, "root"), "keymaster");

        let reset = serde_json::json!({"new_password": "Str0ng-Passw0rd"});
        let resp = reset_password_handler(
            s(),
            Path("root".into()),
            request("POST", reset, Role::Admin),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let resp = disable_user_handler(
            s(),
            Path("root".into()),
            request("DELETE", serde_json::json!({}), Role::Admin),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // Within its ceiling an admin still manages users, and a KEYMASTER
        // may grant KEYMASTER.
        let resp = update_user_handler(
            s(),
            Path("bob".into()),
            request("PUT", serde_json::json!({"role": "admin"}), Role::Admin),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = update_user_handler(
            s(),
            Path("bob".into()),
            request("PUT", promote, Role::Keymaster),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(role_of(&state, "bob"), "keymaster");
        let resp = update_user_handler(
            s(),
            Path("nobody".into()),
            request("PUT", serde_json::json!({}), Role::Admin),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// Regression (Residual-A): the admin password reset ran PBKDF2 on an
    /// async worker. On a single-threaded runtime that stalls every other
    /// task for the whole hash; a ticker must keep ticking meanwhile.
    #[tokio::test(flavor = "current_thread")]
    async fn password_reset_hashes_off_the_async_runtime() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        insert_user(&state.db_pool.get().unwrap(), "bob", "viewer", true);

        let ticks = Arc::new(AtomicUsize::new(0));
        let ticker = {
            let ticks = Arc::clone(&ticks);
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                    ticks.fetch_add(1, Ordering::Relaxed);
                }
            })
        };
        tokio::task::yield_now().await;
        let start = std::time::Instant::now();
        let reset = serde_json::json!({"new_password": "Str0ng-Passw0rd"});
        let resp = reset_password_handler(
            State(Arc::clone(&state)),
            Path("bob".into()),
            request("POST", reset, Role::Admin),
        )
        .await;
        let elapsed = start.elapsed();
        ticker.abort();
        assert_eq!(resp.status(), StatusCode::OK);
        let ticks = ticks.load(Ordering::Relaxed);
        assert!(
            ticks >= 5,
            "only {ticks} ticks in {elapsed:?}: PBKDF2 blocked the runtime"
        );
    }

    /// Regression: a reset left the account's lockout failures counted, so
    /// a user locked out by failed logins or password changes still got
    /// 429 with the new password (and on a password change), until the
    /// failures aged out of `UC_LOCKOUT_WINDOW`, while the reset had also
    /// ended their sessions. A reset now clears that user's failures, and
    /// only that user's; a reset that changes nothing clears nothing.
    #[tokio::test]
    async fn a_password_reset_clears_the_account_lockout() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let failures = |username: &str| -> i64 {
            state
                .db_pool
                .get()
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM account_lockout WHERE username = ?1",
                    [username],
                    |r| r.get(0),
                )
                .unwrap()
        };
        {
            let conn = state.db_pool.get().unwrap();
            conn.execute_batch(
                "CREATE TABLE account_lockout (id INTEGER PRIMARY KEY AUTOINCREMENT, \
                 username TEXT NOT NULL, failure_at REAL NOT NULL, \
                 tenant_id TEXT NOT NULL DEFAULT 'default');",
            )
            .unwrap();
            insert_user(&conn, "bob", "viewer", true);
            insert_user(&conn, "carol", "viewer", true);
            for username in ["bob", "carol", "nobody"] {
                for _ in 0..3 {
                    security_state::record_account_failure(&conn, username, "default").unwrap();
                }
            }
        }
        let reset = |username: &str, password: &str| {
            reset_password_handler(
                State(Arc::clone(&state)),
                Path(username.into()),
                request(
                    "POST",
                    serde_json::json!({"new_password": password}),
                    Role::Admin,
                ),
            )
        };

        let weak = reset("bob", "weak").await;
        assert_eq!(weak.status(), StatusCode::BAD_REQUEST);
        let unknown = reset("nobody", STRONG).await;
        assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            [failures("bob"), failures("carol"), failures("nobody")],
            [3, 3, 3],
            "nothing was reset"
        );

        let resp = reset("bob", STRONG).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            [failures("bob"), failures("carol"), failures("nobody")],
            [0, 3, 3]
        );
    }

    const STRONG: &str = "Str0ng-Passw0rd";
    const ADMIN_ACTIONS: [&str; 4] = [
        "admin_create_user",
        "admin_update_user",
        "admin_disable_user",
        "admin_password_reset",
    ];

    fn request_as(method: &str, body: impl Into<Body>, auth: Option<AuthInfo>) -> Request<Body> {
        let mut req = Request::builder()
            .method(method)
            .uri("/api/admin/users")
            .body(body.into())
            .unwrap();
        if let Some(auth) = auth {
            req.extensions_mut().insert(auth);
        }
        req
    }

    fn session_auth(username: &str, role: Role) -> AuthInfo {
        AuthInfo::Session {
            username: username.to_string(),
            user_id: 0,
            role,
            session_token: String::new(),
            expires_at: String::new(),
            tenant_id: "default".to_string(),
            scope: String::new(),
        }
    }

    fn admin_key() -> Option<AuthInfo> {
        Some(AuthInfo::ApiKey {
            key_id: "admin-key".to_string(),
            role: Role::Admin,
        })
    }

    fn user(state: &AppState, username: &str) -> users::User {
        users::get_user_by_username(&state.db_pool.get().unwrap(), username, "default")
            .unwrap()
            .unwrap()
    }

    fn credential(state: &AppState, username: &str) -> (String, Vec<u8>) {
        state
            .db_pool
            .get()
            .unwrap()
            .query_row(
                "SELECT password_hash, salt FROM users WHERE username = ?1",
                [username],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap()
    }

    fn user_count(state: &AppState) -> i64 {
        state
            .db_pool
            .get()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
            .unwrap()
    }

    /// (target_id, operator) of each audit row with this action.
    fn audit_entries(state: &AppState, action: &str) -> Vec<(String, String)> {
        let conn = state.db_pool.get().unwrap();
        let mut stmt = conn
            .prepare("SELECT target_id, operator FROM audit_log WHERE action = ?1 ORDER BY id")
            .unwrap();
        let rows = stmt
            .query_map([action], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap();
        rows.map(Result::unwrap).collect()
    }

    fn no_admin_audits(state: &AppState) {
        for action in ADMIN_ACTIONS {
            assert_eq!(test_support::audit_count(state, action), 0, "{action}");
        }
    }

    async fn body_text(resp: Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    async fn detail(resp: Response) -> String {
        let json: serde_json::Value = serde_json::from_str(&body_text(resp).await).unwrap();
        json["detail"].as_str().unwrap_or_default().to_string()
    }

    /// Every admin user endpoint refuses an unauthenticated caller (401) and
    /// any authenticated role below ADMIN, by API key or session (403),
    /// before it touches the database: nothing is created, listed, changed,
    /// revoked or audited.
    #[tokio::test]
    async fn non_admin_callers_are_refused_by_every_endpoint() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let (bob, token) = user_session(&state, "bob");
        let bob_credential = credential(&state, "bob");
        let s = || State(Arc::clone(&state));

        let mut callers = vec![
            (None, StatusCode::UNAUTHORIZED),
            (Some(AuthInfo::Unauthenticated), StatusCode::UNAUTHORIZED),
        ];
        for role in [Role::Sensor, Role::Node, Role::Viewer, Role::Analyst] {
            callers.push((
                Some(AuthInfo::ApiKey {
                    key_id: format!("{role}-key"),
                    role,
                }),
                StatusCode::FORBIDDEN,
            ));
            callers.push((Some(session_auth("mallory", role)), StatusCode::FORBIDDEN));
        }

        let create = serde_json::json!({"username": "eve", "password": STRONG, "role": "viewer"});
        // The first update carries no role, so only the endpoint's own ADMIN
        // check can refuse it (with a role, the grant ceiling would refuse a
        // sub-admin caller anyway and hide a weakened endpoint check). The
        // second is a promotion attempt.
        let updates = [
            serde_json::json!({"display_name": "pwned", "email": "x@evil.test", "enabled": false}),
            serde_json::json!({"role": "admin"}),
        ];
        let reset = serde_json::json!({"new_password": "Replacement-Str0ng-Passw0rd"});
        for (auth, expected) in callers {
            let who = format!("{auth:?}");
            let resp =
                create_user_handler(s(), request_as("POST", create.to_string(), auth.clone()))
                    .await;
            assert_eq!(resp.status(), expected, "create by {who}");
            let resp =
                list_users_handler(s(), request_as("GET", Body::empty(), auth.clone())).await;
            assert_eq!(resp.status(), expected, "list by {who}");
            assert!(!body_text(resp).await.contains("bob"), "list by {who}");
            for update in &updates {
                let resp = update_user_handler(
                    s(),
                    Path("bob".into()),
                    request_as("PUT", update.to_string(), auth.clone()),
                )
                .await;
                assert_eq!(resp.status(), expected, "update {update} by {who}");
            }
            let resp = disable_user_handler(
                s(),
                Path("bob".into()),
                request_as("DELETE", Body::empty(), auth.clone()),
            )
            .await;
            assert_eq!(resp.status(), expected, "disable by {who}");
            let resp = reset_password_handler(
                s(),
                Path("bob".into()),
                request_as("POST", reset.to_string(), auth.clone()),
            )
            .await;
            assert_eq!(resp.status(), expected, "reset by {who}");
        }

        assert_eq!(user_count(&state), 1);
        let bob_now = user(&state, "bob");
        assert_eq!(
            (
                bob_now.role.as_str(),
                bob_now.enabled,
                bob_now.display_name.as_str(),
                bob_now.email.as_str()
            ),
            ("viewer", true, "", "")
        );
        assert_eq!(credential(&state, "bob"), bob_credential);
        assert_eq!(session_user_id(&state, &token), Some(bob));
        no_admin_audits(&state);
    }

    /// Malformed, oversized or policy-violating create requests are refused
    /// and create nothing: a body that is not the expected JSON and the
    /// gateway's password policy with 400, an unknown role with 422 (the
    /// bridge's status for any role its pattern refuses, and the status of
    /// every other refused user field here).
    #[tokio::test]
    async fn create_rejects_invalid_requests_without_creating_anything() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let bad = StatusCode::BAD_REQUEST;
        let unprocessable = StatusCode::UNPROCESSABLE_ENTITY;
        let cases = [
            ("not json".to_string(), bad, "Invalid request body"),
            (
                serde_json::json!({"username": "eve"}).to_string(),
                bad,
                "Invalid request body",
            ),
            (
                serde_json::json!({"username": "eve", "password": 12345678}).to_string(),
                bad,
                "Invalid request body",
            ),
            (
                serde_json::json!({"username": "eve", "password": "Sh0rt"}).to_string(),
                bad,
                "at least 8",
            ),
            (
                serde_json::json!({"username": "eve", "password": "password1"}).to_string(),
                bad,
                "uppercase",
            ),
            (
                serde_json::json!({"username": "eve", "password": STRONG, "role": "superuser"})
                    .to_string(),
                unprocessable,
                "Invalid role",
            ),
            (
                serde_json::json!({"username": "eve", "password": STRONG, "role": " admin"})
                    .to_string(),
                unprocessable,
                "Invalid role",
            ),
            (
                serde_json::json!({"username": "eve", "password": STRONG, "role": ""}).to_string(),
                unprocessable,
                "Invalid role",
            ),
        ];
        for (body, status, expected) in cases {
            let resp = create_user_handler(
                State(Arc::clone(&state)),
                request_as("POST", body.clone(), admin_key()),
            )
            .await;
            assert_eq!(resp.status(), status, "{body}");
            let got = detail(resp).await;
            assert!(got.contains(expected), "{body}: {got}");
        }
        // Over the 4 KiB body limit.
        let oversized = serde_json::json!({
            "username": "eve", "password": STRONG, "display_name": "x".repeat(5000)
        });
        let resp = create_user_handler(
            State(Arc::clone(&state)),
            request_as("POST", oversized.to_string(), admin_key()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        assert_eq!(user_count(&state), 0);
        no_admin_audits(&state);
    }

    /// A successful create stores the requested role, defaults to VIEWER,
    /// never echoes the password, persists a working salted credential that
    /// is neither unsalted nor legacy salted SHA-256, and audits the acting
    /// session's username.
    #[tokio::test]
    async fn create_persists_a_hashed_account_and_audits_the_operator() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let op = Some(session_auth("ops-admin", Role::Admin));
        let body = serde_json::json!({
            "username": "eve", "password": STRONG, "role": "analyst", "display_name": "Eve"
        });
        let resp = create_user_handler(
            State(Arc::clone(&state)),
            request_as("POST", body.to_string(), op.clone()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let text = body_text(resp).await;
        assert!(!text.contains(STRONG), "{text}");
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            (json["username"].as_str(), json["role"].as_str()),
            (Some("eve"), Some("analyst"))
        );
        let id = json["id"].as_i64().unwrap();

        let eve = user(&state, "eve");
        assert_eq!(
            (
                eve.id,
                eve.role.as_str(),
                eve.enabled,
                eve.display_name.as_str()
            ),
            (id, "analyst", true, "Eve")
        );
        let (hash, salt) = credential(&state, "eve");
        assert_ne!(hash, password::sha256_hex(STRONG), "unsalted SHA-256");
        let mut legacy = sha2::Sha256::new();
        legacy.update(&salt);
        legacy.update(STRONG);
        assert_ne!(hash, hex::encode(legacy.finalize()), "legacy SHA-256");
        assert_eq!(
            users::verify_password(&state.db_pool.get().unwrap(), "eve", STRONG, "default")
                .unwrap(),
            Some(id)
        );
        assert_eq!(
            audit_entries(&state, "admin_create_user"),
            [("eve".to_string(), "ops-admin".to_string())]
        );

        let resp = create_user_handler(
            State(Arc::clone(&state)),
            request_as(
                "POST",
                serde_json::json!({"username": "frank", "password": STRONG}).to_string(),
                op,
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert_eq!(role_of(&state, "frank"), "viewer", "default role");
    }

    /// A create the database refuses for another reason than a duplicate is
    /// a 500, not reported or audited as a success (and not as a 409).
    #[tokio::test]
    async fn failed_create_is_not_reported_or_audited_as_success() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        state
            .db_pool
            .get()
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER reject_account_insert BEFORE INSERT ON users \
                 BEGIN SELECT RAISE(ABORT, 'account store unavailable'); END;",
            )
            .unwrap();

        let body = serde_json::json!({"username": "eve", "password": STRONG});
        let resp = create_user_handler(
            State(Arc::clone(&state)),
            request("POST", body, Role::Admin),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(user_count(&state), 0);
        no_admin_audits(&state);
    }

    /// Re-creating an existing username is refused with 409: the existing
    /// account keeps its credential, role and sessions (no takeover by
    /// re-creation), and nothing is audited.
    #[tokio::test]
    async fn duplicate_create_is_409_and_keeps_the_existing_account() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let (bob, token) = user_session(&state, "bob");
        let before = credential(&state, "bob");

        let body = serde_json::json!({
            "username": "bob", "password": "Takeover-Passw0rd", "role": "admin"
        });
        let resp = create_user_handler(
            State(Arc::clone(&state)),
            request("POST", body, Role::Admin),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        assert_eq!(detail(resp).await, "Username already exists");

        assert_eq!(credential(&state, "bob"), before);
        assert_eq!(role_of(&state, "bob"), "viewer");
        assert_eq!(user_count(&state), 1);
        assert_eq!(session_user_id(&state, &token), Some(bob));
        no_admin_audits(&state);
    }

    /// The K5 grant ceiling applies to the role a spelling parses as, so it
    /// holds for every spelling of KEYMASTER, on create and on update:
    /// other cases, and the Unicode spellings that case-map to it as they
    /// do in the bridge (long s U+017F, the "st" ligature U+FB06). A
    /// KEYMASTER may grant it, and only the canonical name is stored, so a
    /// look-alike never persists.
    #[tokio::test]
    async fn keymaster_ceiling_holds_for_any_spelling() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        insert_user(&state.db_pool.get().unwrap(), "bob", "viewer", true);
        let s = || State(Arc::clone(&state));

        for spelling in [
            "KEYMASTER",
            "KeyMaster",
            "keyma\u{17f}ter",
            "KEYMA\u{17f}TER",
            "keyma\u{fb06}er",
        ] {
            let create =
                serde_json::json!({"username": "eve", "password": STRONG, "role": spelling});
            let resp = create_user_handler(s(), request("POST", create, Role::Admin)).await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{spelling}");
            let resp = update_user_handler(
                s(),
                Path("bob".into()),
                request("PUT", serde_json::json!({"role": spelling}), Role::Admin),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{spelling}");
        }
        assert_eq!(user_count(&state), 1);
        assert_eq!(role_of(&state, "bob"), "viewer");
        no_admin_audits(&state);

        let create =
            serde_json::json!({"username": "root", "password": STRONG, "role": "KEYMASTER"});
        let resp = create_user_handler(s(), request("POST", create, Role::Keymaster)).await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert_eq!(role_of(&state, "root"), "keymaster");
        let resp = update_user_handler(
            s(),
            Path("bob".into()),
            request(
                "PUT",
                serde_json::json!({"role": "keyma\u{17f}ter"}),
                Role::Keymaster,
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(role_of(&state, "bob"), "keymaster");
    }

    /// An account whose stored role is no known role fails closed: it ranks
    /// as KEYMASTER, so an admin may not update, disable or reset it (and
    /// its session survives), while a KEYMASTER may. A known role stored in
    /// another case keeps its own level.
    #[tokio::test]
    async fn unknown_stored_role_is_managed_only_by_keymaster() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let (odd, token) = user_session(&state, "odd");
        state
            .db_pool
            .get()
            .unwrap()
            .execute("UPDATE users SET role = 'superuser' WHERE id = ?1", [odd])
            .unwrap();
        let before = credential(&state, "odd");
        let s = || State(Arc::clone(&state));

        let resp = update_user_handler(
            s(),
            Path("odd".into()),
            request(
                "PUT",
                serde_json::json!({"display_name": "Changed"}),
                Role::Admin,
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let resp = disable_user_handler(
            s(),
            Path("odd".into()),
            request("DELETE", serde_json::json!({}), Role::Admin),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let resp = reset_password_handler(
            s(),
            Path("odd".into()),
            request(
                "POST",
                serde_json::json!({"new_password": STRONG}),
                Role::Admin,
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let odd_now = user(&state, "odd");
        assert_eq!(
            (
                odd_now.role.as_str(),
                odd_now.display_name.as_str(),
                odd_now.enabled
            ),
            ("superuser", "", true)
        );
        assert_eq!(credential(&state, "odd"), before);
        assert_eq!(session_user_id(&state, &token), Some(odd));
        no_admin_audits(&state);

        let resp = update_user_handler(
            s(),
            Path("odd".into()),
            request(
                "PUT",
                serde_json::json!({"display_name": "Odd"}),
                Role::Keymaster,
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(user(&state, "odd").display_name, "Odd");

        insert_user(&state.db_pool.get().unwrap(), "shout", "ADMIN", true);
        let resp = update_user_handler(
            s(),
            Path("shout".into()),
            request(
                "PUT",
                serde_json::json!({"display_name": "Loud"}),
                Role::Admin,
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// A role change applies to the account's existing sessions at once
    /// (sessions read the role from the account), so a demoted admin loses
    /// admin rights without having to log out.
    #[tokio::test]
    async fn role_changes_apply_to_existing_sessions() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let (_, token) = user_session(&state, "bob");
        let session_role = || {
            sessions::validate_session(
                &state.db_pool.get().unwrap(),
                &token,
                &sessions::SessionConfig::default(),
            )
            .unwrap()
            .unwrap()
            .role
        };

        for role in ["admin", "viewer"] {
            let resp = update_user_handler(
                State(Arc::clone(&state)),
                Path("bob".into()),
                request("PUT", serde_json::json!({"role": role}), Role::Admin),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(session_role(), role);
        }
    }

    /// Malformed or invalid update requests are refused before any change,
    /// revocation or audit: a body that is not the expected JSON (or is
    /// over the 4 KiB limit) with 400, an unknown role with 422 (the
    /// bridge's status for any role its pattern refuses).
    #[tokio::test]
    async fn update_rejects_invalid_requests_without_changes() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let (bob, token) = user_session(&state, "bob");
        let bad = StatusCode::BAD_REQUEST;
        let unprocessable = StatusCode::UNPROCESSABLE_ENTITY;
        let bodies = [
            ("not json".to_string(), bad, "Invalid request body"),
            (
                serde_json::json!({"role": "superuser", "enabled": false}).to_string(),
                unprocessable,
                "Invalid role",
            ),
            (
                serde_json::json!({"role": ""}).to_string(),
                unprocessable,
                "Invalid role",
            ),
            (
                serde_json::json!({"role": "admin ", "enabled": false}).to_string(),
                unprocessable,
                "Invalid role",
            ),
            (
                serde_json::json!({"enabled": "false"}).to_string(),
                bad,
                "Invalid request body",
            ),
            (
                serde_json::json!({"enabled": false, "display_name": "x".repeat(5000)}).to_string(),
                bad,
                "",
            ),
        ];
        for (body, status, expected) in bodies {
            let resp = update_user_handler(
                State(Arc::clone(&state)),
                Path("bob".into()),
                request_as("PUT", body.clone(), admin_key()),
            )
            .await;
            assert_eq!(resp.status(), status, "{body:.80}");
            let got = body_text(resp).await;
            assert!(got.contains(expected), "{body:.80}: {got}");
        }
        let bob_now = user(&state, "bob");
        assert_eq!(
            (
                bob_now.role.as_str(),
                bob_now.enabled,
                bob_now.display_name.as_str()
            ),
            ("viewer", true, "")
        );
        assert_eq!(session_user_id(&state, &token), Some(bob));
        no_admin_audits(&state);
    }

    /// An admin reset must meet the password policy; a refused reset keeps
    /// the old credential and the user's sessions.
    #[tokio::test]
    async fn reset_enforces_the_password_policy() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let (bob, token) = user_session(&state, "bob");
        let before = credential(&state, "bob");
        let bodies = [
            "not json".to_string(),
            serde_json::json!({}).to_string(),
            serde_json::json!({"new_password": "Sh0rt"}).to_string(),
            serde_json::json!({"new_password": "alllowercase1"}).to_string(),
            serde_json::json!({"new_password": "NoDigitsHere"}).to_string(),
            serde_json::json!({"new_password": format!("Aa1{}", "x".repeat(200))}).to_string(),
            // A valid password in a body over the 4 KiB limit.
            serde_json::json!({"new_password": STRONG, "pad": "x".repeat(5000)}).to_string(),
        ];
        for body in bodies {
            let resp = reset_password_handler(
                State(Arc::clone(&state)),
                Path("bob".into()),
                request_as("POST", body.clone(), admin_key()),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{body:.80}");
        }
        assert_eq!(credential(&state, "bob"), before);
        assert_eq!(session_user_id(&state, &token), Some(bob));
        no_admin_audits(&state);
    }

    /// The admin listing returns this tenant's accounts only, and never
    /// their password hashes, salts or TOTP secrets.
    #[tokio::test]
    async fn list_returns_tenant_accounts_without_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let hash = format!("{}abcd", "c0ffee".repeat(10));
        let totp = "JBSWY3DPEHPK3PXP";
        {
            let conn = state.db_pool.get().unwrap();
            let alice = insert_user(&conn, "alice", "admin", true);
            insert_user(&conn, "bob", "viewer", false);
            conn.execute(
                "UPDATE users SET password_hash = ?1, salt = ?2, totp_secret = ?3, \
                 mfa_enabled = 1 WHERE id = ?4",
                rusqlite::params![
                    hash,
                    b"pepper-pepper-pepper-pepper-0123".to_vec(),
                    totp,
                    alice
                ],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO users (username, password_hash, salt, role, created_at, tenant_id) \
                 VALUES ('carol', 'x', 'y', 'admin', '2026-01-01T00:00:00+00:00', 'other')",
                [],
            )
            .unwrap();
        }

        let resp = list_users_handler(
            State(Arc::clone(&state)),
            request("GET", serde_json::json!({}), Role::Admin),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let text = body_text(resp).await;
        for needle in [
            hash.as_str(),
            totp,
            "pepper",
            "password",
            "salt",
            "totp",
            "carol",
        ] {
            assert!(!text.contains(needle), "{needle} leaked: {text}");
        }
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        let names: Vec<&str> = json
            .as_array()
            .unwrap()
            .iter()
            .map(|u| u["username"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["alice", "bob"]);
    }

    /// Each successful change is audited once, naming the target and the
    /// acting principal (session username, or API key id).
    #[tokio::test]
    async fn changes_are_audited_with_target_and_operator() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        user_session(&state, "bob");
        let op = Some(session_auth("ops-admin", Role::Admin));
        let s = || State(Arc::clone(&state));

        let update = serde_json::json!({"display_name": "Bob"}).to_string();
        let resp = update_user_handler(
            s(),
            Path("bob".into()),
            request_as("PUT", update, op.clone()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let reset = serde_json::json!({"new_password": STRONG}).to_string();
        let resp = reset_password_handler(
            s(),
            Path("bob".into()),
            request_as("POST", reset, admin_key()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = disable_user_handler(
            s(),
            Path("bob".into()),
            request_as("DELETE", Body::empty(), op),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let bob = |operator: &str| vec![("bob".to_string(), operator.to_string())];
        assert_eq!(audit_entries(&state, "admin_update_user"), bob("ops-admin"));
        assert_eq!(
            audit_entries(&state, "admin_password_reset"),
            bob("admin-key")
        );
        assert_eq!(
            audit_entries(&state, "admin_disable_user"),
            bob("ops-admin")
        );
        assert_eq!(test_support::audit_count(&state, "admin_create_user"), 0);
    }

    /// When the account behind a request cannot be read, the ceiling check
    /// fails closed: update, disable and reset answer 500 and change,
    /// revoke and audit nothing, and the listing answers 500 rather than a
    /// partial list.
    #[tokio::test]
    async fn unreadable_account_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let (bob, token) = user_session(&state, "bob");
        let before = credential(&state, "bob");
        // Not a boolean: the account lookup fails to decode the row.
        state
            .db_pool
            .get()
            .unwrap()
            .execute("UPDATE users SET enabled = 'corrupt' WHERE id = ?1", [bob])
            .unwrap();
        let s = || State(Arc::clone(&state));

        let resp = update_user_handler(
            s(),
            Path("bob".into()),
            request(
                "PUT",
                serde_json::json!({"display_name": "Changed"}),
                Role::Admin,
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let resp = disable_user_handler(
            s(),
            Path("bob".into()),
            request("DELETE", serde_json::json!({}), Role::Admin),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let resp = reset_password_handler(
            s(),
            Path("bob".into()),
            request(
                "POST",
                serde_json::json!({"new_password": STRONG}),
                Role::Admin,
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let resp =
            list_users_handler(s(), request("GET", serde_json::json!({}), Role::Admin)).await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let persisted: (String, String, i64) = state
            .db_pool
            .get()
            .unwrap()
            .query_row(
                "SELECT display_name, enabled, \
                 (SELECT COUNT(*) FROM sessions WHERE session_token = ?2) \
                 FROM users WHERE id = ?1",
                rusqlite::params![bob, password::hash_session_token(&token)],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(persisted, (String::new(), "corrupt".to_string(), 1));
        assert_eq!(credential(&state, "bob"), before);
        no_admin_audits(&state);
    }

    /// The bridge contract (`CreateUserRequest`: 1-64 characters of
    /// `[A-Za-z0-9_.-]`) refuses malformed usernames; the gateway's native
    /// route must refuse them too instead of creating blank, oversized or
    /// markup- and control-character-bearing accounts, with the bridge's
    /// 422. A trailing newline (the `$`-anchor pitfall) and NUL are refused
    /// too, while a name of exactly 64 allowed characters is still accepted.
    ///
    /// "." and ".." are refused although the bridge pattern allows them (a
    /// deliberate gateway-side tightening): the K9 path guard refuses those
    /// path segments, so no `{username}` route could ever disable, demote
    /// or reset such an account, even one created with the admin role.
    /// Other names made of or holding dots are ordinary path segments and
    /// stay accepted.
    #[tokio::test]
    async fn create_rejects_malformed_usernames() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let long = "a".repeat(65);
        for (username, role) in [
            ("", "viewer"),
            (" ", "viewer"),
            (long.as_str(), "viewer"),
            ("eve admin", "viewer"),
            ("eve\nadmin", "viewer"),
            ("eve\n", "viewer"),
            ("eve\u{0}", "viewer"),
            ("<img src=x onerror=alert(1)>", "viewer"),
            ("../root", "viewer"),
            (".", "viewer"),
            ("..", "viewer"),
            (".", "admin"),
            ("..", "admin"),
        ] {
            let body = serde_json::json!({"username": username, "password": STRONG, "role": role});
            let resp = create_user_handler(
                State(Arc::clone(&state)),
                request("POST", body, Role::Admin),
            )
            .await;
            assert_eq!(
                resp.status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "{username:?} as {role}"
            );
            assert!(
                detail(resp).await.starts_with("Invalid username"),
                "{username:?} as {role}"
            );
        }
        assert_eq!(user_count(&state), 0);
        no_admin_audits(&state);

        // Every other dotted name passes (checked directly: each create
        // below costs a PBKDF2 hash, slow in debug builds).
        for username in ["...", "....", ".x", "x.", "..x", "x..", ".-", "_.", "a.b"] {
            assert_eq!(validate_new_username(username), Ok(()), "{username:?}");
        }
        for username in [
            "a".repeat(64),
            "eve.o-k_1".to_string(),
            "...".to_string(),
            "a.b".to_string(),
        ] {
            let body = serde_json::json!({"username": username, "password": STRONG});
            let resp = create_user_handler(
                State(Arc::clone(&state)),
                request("POST", body, Role::Admin),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::CREATED, "{username:?}");
        }
    }

    /// The username rule is exactly the bridge's ASCII class (apart from
    /// the names "." and "..", see `create_rejects_malformed_usernames`):
    /// letters and digits outside ASCII (including ones that case-map or
    /// look like ASCII), other punctuation and every whitespace or control character
    /// are refused wherever they sit, with a string detail, before the
    /// password is hashed, stored or audited. Length counts characters, so
    /// 65 allowed characters are refused whatever their mix. Every allowed
    /// character class is accepted, alone and at the 64-character limit,
    /// and the stored name is the one sent (no trimming or case folding).
    #[tokio::test]
    async fn username_rule_matches_the_bridge_character_class() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let full_64: String = "Az09_-.".repeat(10).chars().take(64).collect();
        let mixed_65 = format!("{full_64}x");
        assert_eq!(mixed_65.chars().count(), 65);
        for username in [
            "\u{e9}ve",
            "\u{212a}elvin", // KELVIN SIGN, case-maps to 'k'
            "eve\u{17f}",    // LONG S, upper-cases to 'S'
            "\u{ff45}ve",    // fullwidth 'e'
            "eve\u{661}",    // ARABIC-INDIC DIGIT ONE
            "eve\u{a0}",
            "eve\u{200b}",
            "eve@x.test",
            "eve/root",
            "eve\\root",
            "eve%2e",
            "eve;admin",
            "eve'",
            "eve\"",
            "eve+1",
            "eve\t",
            "eve\r",
            "\neve",
            "\u{0}eve",
            "eve\u{7f}",
            " eve",
            mixed_65.as_str(),
        ] {
            let body = serde_json::json!({"username": username, "password": STRONG});
            let resp = create_user_handler(
                State(Arc::clone(&state)),
                request("POST", body, Role::Admin),
            )
            .await;
            assert_eq!(
                resp.status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "{username:?}"
            );
            assert!(
                detail(resp).await.starts_with("Invalid username"),
                "{username:?}"
            );
        }
        assert_eq!(user_count(&state), 0);
        no_admin_audits(&state);

        for username in ["a", "Z", "7", "_x", "-x", "x.y", "AZaz09", full_64.as_str()] {
            let body = serde_json::json!({"username": username, "password": STRONG});
            let resp = create_user_handler(
                State(Arc::clone(&state)),
                request("POST", body, Role::Admin),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::CREATED, "{username:?}");
            let json: serde_json::Value = serde_json::from_str(&body_text(resp).await).unwrap();
            assert_eq!(json["username"], username);
            assert_eq!(user(&state, username).username, username);
        }
        assert_eq!(test_support::audit_count(&state, "admin_create_user"), 8);
    }

    /// The username check keeps the gateway's auth-first order: a caller
    /// below ADMIN, or none, gets 403 / 401 for a malformed name, not a
    /// 422 that would tell it the body was looked at. A KEYMASTER and an
    /// admin session are held to the same rule as an admin API key.
    #[tokio::test]
    async fn username_check_runs_after_auth_for_every_caller() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let body = serde_json::json!({"username": "eve admin", "password": STRONG}).to_string();
        for (auth, expected) in [
            (None, StatusCode::UNAUTHORIZED),
            (
                Some(AuthInfo::ApiKey {
                    key_id: "viewer-key".into(),
                    role: Role::Viewer,
                }),
                StatusCode::FORBIDDEN,
            ),
            (
                Some(session_auth("ana", Role::Analyst)),
                StatusCode::FORBIDDEN,
            ),
            (
                Some(session_auth("ops-admin", Role::Admin)),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                Some(AuthInfo::ApiKey {
                    key_id: "km-key".into(),
                    role: Role::Keymaster,
                }),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
        ] {
            let who = format!("{auth:?}");
            let resp = create_user_handler(
                State(Arc::clone(&state)),
                request_as("POST", body.clone(), auth),
            )
            .await;
            assert_eq!(resp.status(), expected, "{who}");
        }
        assert_eq!(user_count(&state), 0);
        no_admin_audits(&state);
    }

    /// Only a new name is checked. Accounts whose stored name breaks the
    /// rule (created before it, or by the bridge's bootstrap admin, which
    /// does not validate the name) stay listed and can still be updated,
    /// have their password reset and be disabled through the `{username}`
    /// routes.
    #[tokio::test]
    async fn legacy_usernames_stay_manageable() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let long = "a".repeat(65);
        let legacy = [
            "legacy user",
            "\u{e9}ve",
            "<b>odd</b>",
            "eve@x.test",
            long.as_str(),
        ];
        let mut tokens = Vec::new();
        for name in legacy {
            tokens.push(user_session(&state, name).1);
        }
        let s = || State(Arc::clone(&state));

        let resp =
            list_users_handler(s(), request("GET", serde_json::json!({}), Role::Admin)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body_text(resp).await).unwrap();
        let mut listed: Vec<&str> = json
            .as_array()
            .unwrap()
            .iter()
            .map(|u| u["username"].as_str().unwrap())
            .collect();
        listed.sort_unstable();
        let mut expected = legacy.to_vec();
        expected.sort_unstable();
        assert_eq!(listed, expected);

        for (name, token) in legacy.into_iter().zip(&tokens) {
            let resp = update_user_handler(
                s(),
                Path(name.to_string()),
                request(
                    "PUT",
                    serde_json::json!({"display_name": "Kept", "role": "analyst"}),
                    Role::Admin,
                ),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK, "update {name:?}");
            let now = user(&state, name);
            assert_eq!(
                (now.display_name.as_str(), now.role.as_str()),
                ("Kept", "analyst")
            );
            let resp = reset_password_handler(
                s(),
                Path(name.to_string()),
                request(
                    "POST",
                    serde_json::json!({"new_password": "Replacement-Str0ng-Passw0rd"}),
                    Role::Admin,
                ),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK, "reset {name:?}");
            assert_eq!(session_user_id(&state, token), None, "reset {name:?}");
            let resp = disable_user_handler(
                s(),
                Path(name.to_string()),
                request("DELETE", serde_json::json!({}), Role::Admin),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK, "disable {name:?}");
            assert!(!user(&state, name).enabled, "disable {name:?}");
        }
        assert_eq!(test_support::audit_count(&state, "admin_update_user"), 5);
        assert_eq!(test_support::audit_count(&state, "admin_password_reset"), 5);
        assert_eq!(test_support::audit_count(&state, "admin_disable_user"), 5);
    }

    /// Decision, pinned (no lockout guard, as in the bridge): an admin may
    /// disable its own account, which revokes its own sessions at once, and
    /// the sole KEYMASTER may demote itself, after which no account holds
    /// KEYMASTER and no remaining principal may grant it again. Neither the
    /// gateway nor the bridge has a last-admin or last-KEYMASTER guard; if
    /// one is added, this test must change to expect the refusal.
    #[tokio::test]
    async fn self_disable_and_sole_keymaster_self_demotion_are_not_guarded() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let (_, ops_token) = user_session_with_role(&state, "ops-admin", "admin");
        let (root, root_token) = user_session_with_role(&state, "root", "keymaster");
        insert_user(&state.db_pool.get().unwrap(), "bob", "viewer", true);
        let s = || State(Arc::clone(&state));

        let resp = disable_user_handler(
            s(),
            Path("ops-admin".into()),
            request_as(
                "DELETE",
                Body::empty(),
                Some(session_auth("ops-admin", Role::Admin)),
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(!user(&state, "ops-admin").enabled);
        assert_eq!(
            session_user_id(&state, &ops_token),
            None,
            "a disabled admin keeps no live session"
        );
        assert_eq!(
            audit_entries(&state, "admin_disable_user"),
            [("ops-admin".to_string(), "ops-admin".to_string())]
        );

        let resp = update_user_handler(
            s(),
            Path("root".into()),
            request_as(
                "PUT",
                serde_json::json!({"role": "viewer"}).to_string(),
                Some(session_auth("root", Role::Keymaster)),
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(role_of(&state, "root"), "viewer");
        assert_eq!(session_user_id(&state, &root_token), Some(root));
        let keymasters: i64 = state
            .db_pool
            .get()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM users WHERE role = 'keymaster'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(keymasters, 0);
        let resp = update_user_handler(
            s(),
            Path("bob".into()),
            request("PUT", serde_json::json!({"role": "keymaster"}), Role::Admin),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    /// The bridge contract for these routes (`CreateUserRequest` /
    /// `UpdateUserRequest`) caps display_name at 128 and email at 256
    /// characters; the native route must refuse longer values (bodies well
    /// under the 4 KiB cap) with the bridge's 422 and change nothing, on
    /// create and on update. Limits count characters, so a 128-character
    /// multibyte display_name is still accepted.
    #[tokio::test]
    async fn create_and_update_enforce_field_length_limits() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        insert_user(&state.db_pool.get().unwrap(), "bob", "viewer", true);
        let s = || State(Arc::clone(&state));
        let long_name = "\u{e9}".repeat(129);
        let long_email = format!("{}@x.test", "a".repeat(250));
        assert_eq!(long_email.chars().count(), 257);

        for (field, value) in [("display_name", &long_name), ("email", &long_email)] {
            let mut create = serde_json::json!({"username": "eve", "password": STRONG});
            create[field] = serde_json::json!(value);
            let resp = create_user_handler(s(), request("POST", create, Role::Admin)).await;
            assert_eq!(
                resp.status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "create {field}"
            );
            let resp = update_user_handler(
                s(),
                Path("bob".into()),
                request("PUT", serde_json::json!({ field: value }), Role::Admin),
            )
            .await;
            assert_eq!(
                resp.status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "update {field}"
            );
        }
        assert_eq!(user_count(&state), 1);
        let bob = user(&state, "bob");
        assert_eq!((bob.display_name.as_str(), bob.email.as_str()), ("", ""));
        no_admin_audits(&state);

        let create = serde_json::json!({
            "username": "eve", "password": STRONG,
            "display_name": "\u{e9}".repeat(128),
            "email": format!("{}@x.test", "a".repeat(249)),
        });
        let resp = create_user_handler(s(), request("POST", create, Role::Admin)).await;
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    /// The length limits on update: an over-long field refuses the whole
    /// update before the account lookup, so a missing or out-of-ceiling
    /// target answers 422 too, and a disabling update (enabled: false) with
    /// an over-long field neither disables, revokes, changes another field
    /// nor audits. Every caller is held to the limits (a KEYMASTER and an
    /// admin session included), and the detail names the field.
    #[tokio::test]
    async fn over_long_update_changes_and_revokes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let (bob, token) = user_session(&state, "bob");
        insert_user(&state.db_pool.get().unwrap(), "root", "keymaster", true);
        let s = || State(Arc::clone(&state));
        let long_name = "x".repeat(129);
        let long_email = "\u{1f600}".repeat(257);

        let cases = [
            (
                "bob",
                serde_json::json!({"enabled": false, "display_name": long_name}),
                admin_key(),
                "display_name must be at most 128 characters",
            ),
            (
                "bob",
                serde_json::json!({"enabled": false, "role": "admin", "email": long_email}),
                Some(session_auth("ops-admin", Role::Admin)),
                "email must be at most 256 characters",
            ),
            (
                "bob",
                serde_json::json!({"display_name": "Fine", "email": long_email}),
                Some(AuthInfo::ApiKey {
                    key_id: "km-key".into(),
                    role: Role::Keymaster,
                }),
                "email must be at most 256 characters",
            ),
            (
                "nobody",
                serde_json::json!({"display_name": long_name}),
                admin_key(),
                "display_name",
            ),
            (
                "root",
                serde_json::json!({"enabled": false, "email": long_email}),
                admin_key(),
                "email",
            ),
        ];
        for (target, body, auth, expected) in cases {
            let resp = update_user_handler(
                s(),
                Path(target.into()),
                request_as("PUT", body.to_string(), auth),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY, "{target}");
            let got = detail(resp).await;
            assert!(got.contains(expected), "{target}: {got}");
        }
        let bob_now = user(&state, "bob");
        assert_eq!(
            (
                bob_now.role.as_str(),
                bob_now.enabled,
                bob_now.display_name.as_str(),
                bob_now.email.as_str()
            ),
            ("viewer", true, "", "")
        );
        assert!(user(&state, "root").enabled);
        assert_eq!(session_user_id(&state, &token), Some(bob));
        no_admin_audits(&state);
    }

    /// The limits are inclusive and count characters, never bytes: exactly
    /// 128 four-byte characters (512 bytes) and 256 multibyte characters
    /// are stored as sent, on update and on create, and empty strings stay
    /// valid (clearing a field on update). No email format is imposed, as
    /// in the bridge.
    #[tokio::test]
    async fn length_limits_are_inclusive_character_counts() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        insert_user(&state.db_pool.get().unwrap(), "bob", "viewer", true);
        let s = || State(Arc::clone(&state));
        let name_128 = "\u{1f600}".repeat(128);
        let email_256 = "\u{e9}".repeat(256);
        assert_eq!(name_128.len(), 512);

        let resp = update_user_handler(
            s(),
            Path("bob".into()),
            request(
                "PUT",
                serde_json::json!({"display_name": name_128, "email": email_256}),
                Role::Admin,
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bob = user(&state, "bob");
        assert_eq!(
            (bob.display_name.as_str(), bob.email.as_str()),
            (name_128.as_str(), email_256.as_str())
        );

        let resp = update_user_handler(
            s(),
            Path("bob".into()),
            request(
                "PUT",
                serde_json::json!({"display_name": "", "email": ""}),
                Role::Admin,
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bob = user(&state, "bob");
        assert_eq!((bob.display_name.as_str(), bob.email.as_str()), ("", ""));

        for (username, display_name, email) in [
            ("eve", name_128.as_str(), email_256.as_str()),
            ("frank", "", ""),
        ] {
            let create = serde_json::json!({
                "username": username, "password": STRONG,
                "display_name": display_name, "email": email,
            });
            let resp = create_user_handler(s(), request("POST", create, Role::Admin)).await;
            assert_eq!(resp.status(), StatusCode::CREATED, "{username}");
            let created = user(&state, username);
            assert_eq!(
                (created.display_name.as_str(), created.email.as_str()),
                (display_name, email)
            );
        }
        assert_eq!(test_support::audit_count(&state, "admin_update_user"), 2);
        assert_eq!(test_support::audit_count(&state, "admin_create_user"), 2);
    }

    /// The bridge contract allows only viewer, analyst and admin as user
    /// roles (KEYMASTER is the gateway's K5 extension, tested above). The
    /// machine roles SENSOR and NODE belong to API keys and certificates;
    /// a user account must not be created with, or moved to, either (422,
    /// as the bridge's role pattern answers).
    #[tokio::test]
    async fn machine_roles_are_not_user_roles() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        insert_user(&state.db_pool.get().unwrap(), "bob", "viewer", true);
        let s = || State(Arc::clone(&state));

        for role in ["sensor", "node"] {
            let create = serde_json::json!({"username": "eve", "password": STRONG, "role": role});
            let resp = create_user_handler(s(), request("POST", create, Role::Admin)).await;
            assert_eq!(
                resp.status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "create {role}"
            );
            let resp = update_user_handler(
                s(),
                Path("bob".into()),
                request("PUT", serde_json::json!({"role": role}), Role::Admin),
            )
            .await;
            assert_eq!(
                resp.status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "update {role}"
            );
        }
        assert_eq!(user_count(&state), 1);
        assert_eq!(role_of(&state, "bob"), "viewer");
        no_admin_audits(&state);
    }

    /// The machine-role refusal goes by the role a spelling parses as, so
    /// it holds for every spelling (other cases, and LONG S U+017F, which
    /// upper-cases to 'S') and for every caller that may manage users,
    /// KEYMASTER included, whose grant ceiling would otherwise allow it.
    /// On update it runs before the account lookup and any revocation: a
    /// missing target answers 422, and a disabling update that asks for a
    /// machine role disables, revokes and audits nothing.
    #[tokio::test]
    async fn machine_roles_are_refused_in_any_spelling_for_any_caller() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let (bob, token) = user_session(&state, "bob");
        let s = || State(Arc::clone(&state));
        let callers = [
            admin_key(),
            Some(session_auth("ops-admin", Role::Admin)),
            Some(AuthInfo::ApiKey {
                key_id: "km-key".into(),
                role: Role::Keymaster,
            }),
            Some(session_auth("root", Role::Keymaster)),
        ];

        for spelling in ["SENSOR", "Sensor", "\u{17f}ensor", "NODE", "Node", "nOdE"] {
            for auth in &callers {
                let who = format!("{spelling} by {auth:?}");
                let create = serde_json::json!({
                    "username": "eve", "password": STRONG, "role": spelling
                });
                let resp =
                    create_user_handler(s(), request_as("POST", create.to_string(), auth.clone()))
                        .await;
                assert_eq!(
                    resp.status(),
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "create {who}"
                );
                assert!(detail(resp).await.contains("machine role"), "create {who}");
                for (target, body) in [
                    ("bob", serde_json::json!({"role": spelling})),
                    (
                        "bob",
                        serde_json::json!({"role": spelling, "enabled": false}),
                    ),
                    ("nobody", serde_json::json!({"role": spelling})),
                ] {
                    let resp = update_user_handler(
                        s(),
                        Path(target.into()),
                        request_as("PUT", body.to_string(), auth.clone()),
                    )
                    .await;
                    assert_eq!(
                        resp.status(),
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "update {target} {body} {who}"
                    );
                }
            }
        }
        assert_eq!(user_count(&state), 1);
        let bob_now = user(&state, "bob");
        assert_eq!((bob_now.role.as_str(), bob_now.enabled), ("viewer", true));
        assert_eq!(session_user_id(&state, &token), Some(bob));
        no_admin_audits(&state);

        // The user roles, KEYMASTER included for a KEYMASTER, are still
        // granted in any case and stored canonically.
        for (role, stored) in [
            ("VIEWER", "viewer"),
            ("Analyst", "analyst"),
            ("ADMIN", "admin"),
        ] {
            let resp = update_user_handler(
                s(),
                Path("bob".into()),
                request("PUT", serde_json::json!({"role": role}), Role::Admin),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK, "{role}");
            assert_eq!(role_of(&state, "bob"), stored);
        }
        let create = serde_json::json!({"username": "km", "password": STRONG, "role": "keymaster"});
        let resp = create_user_handler(s(), request("POST", create, Role::Keymaster)).await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert_eq!(role_of(&state, "km"), "keymaster");
    }

    /// Only a requested new role is checked. An account already stored as
    /// SENSOR or NODE (from before the check) stays listed, can be updated
    /// without a role change, have its password reset, be disabled, and be
    /// moved to a user role; it cannot be moved to the other machine role.
    #[tokio::test]
    async fn existing_machine_role_accounts_stay_manageable() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let s = || State(Arc::clone(&state));
        let accounts = [
            ("probe", "sensor", "node", "viewer"),
            ("relay", "node", "sensor", "admin"),
        ];
        for (name, stored, _, _) in accounts {
            user_session_with_role(&state, name, stored);
        }

        let resp =
            list_users_handler(s(), request("GET", serde_json::json!({}), Role::Admin)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body_text(resp).await).unwrap();
        let listed: Vec<(&str, &str)> = json
            .as_array()
            .unwrap()
            .iter()
            .map(|u| (u["username"].as_str().unwrap(), u["role"].as_str().unwrap()))
            .collect();
        assert_eq!(listed, [("probe", "sensor"), ("relay", "node")]);

        for (name, stored, other_machine, user_role) in accounts {
            let resp = update_user_handler(
                s(),
                Path(name.into()),
                request(
                    "PUT",
                    serde_json::json!({"display_name": "Legacy", "enabled": true}),
                    Role::Admin,
                ),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK, "{name}");
            assert_eq!(
                (
                    user(&state, name).display_name.as_str(),
                    role_of(&state, name)
                ),
                ("Legacy", stored.to_string())
            );
            let resp = update_user_handler(
                s(),
                Path(name.into()),
                request(
                    "PUT",
                    serde_json::json!({"role": other_machine}),
                    Role::Admin,
                ),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY, "{name}");
            assert_eq!(role_of(&state, name), stored);
            let resp = reset_password_handler(
                s(),
                Path(name.into()),
                request(
                    "POST",
                    serde_json::json!({"new_password": "Replacement-Str0ng-Passw0rd"}),
                    Role::Admin,
                ),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK, "{name}");
            let resp = disable_user_handler(
                s(),
                Path(name.into()),
                request("DELETE", serde_json::json!({}), Role::Admin),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK, "{name}");
            assert!(!user(&state, name).enabled);
            let resp = update_user_handler(
                s(),
                Path(name.into()),
                request("PUT", serde_json::json!({"role": user_role}), Role::Admin),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK, "{name}");
            assert_eq!(role_of(&state, name), user_role);
        }
        assert_eq!(test_support::audit_count(&state, "admin_update_user"), 4);
        assert_eq!(test_support::audit_count(&state, "admin_password_reset"), 2);
        assert_eq!(test_support::audit_count(&state, "admin_disable_user"), 2);
    }
}

#[cfg(test)]
mod coverage_tests {
    //! Paths of the user-admin endpoints that the main suite leaves
    //! untaken: no database connection, a write that lands on no row, and
    //! best-effort audit.

    use super::*;
    use crate::db::pool::DbPool;
    use crate::storage::sessions;
    use crate::storage::users::tests::insert_user;
    use crate::test_support;
    use std::time::Duration;

    const NEW_PASSWORD: &str = "Replacement-Str0ng-Passw0rd";

    fn sql(state: &AppState, statements: &str) {
        state
            .db_pool
            .get()
            .unwrap()
            .execute_batch(statements)
            .unwrap();
    }

    fn count(pool: &DbPool, query: &str) -> i64 {
        pool.get()
            .unwrap()
            .query_row(query, [], |row| row.get(0))
            .unwrap()
    }

    fn admin(method: &str, body: serde_json::Value) -> Request<Body> {
        let mut req = Request::builder()
            .method(method)
            .uri("/api/admin/users")
            .body(Body::from(body.to_string()))
            .unwrap();
        req.extensions_mut().insert(AuthInfo::ApiKey {
            key_id: "admin-key".into(),
            role: Role::Admin,
        });
        req
    }

    /// `bob`, an enabled viewer, signed in once; his session token.
    fn bob(state: &AppState) -> String {
        let conn = state.db_pool.get().unwrap();
        let id = insert_user(&conn, "bob", "viewer", true);
        sessions::create_session(&conn, id, "", "", &sessions::SessionConfig::default())
            .unwrap()
            .0
    }

    /// `bob`'s enabled flag, role, display name and password hash.
    fn bob_row(pool: &DbPool) -> (bool, String, String, String) {
        pool.get()
            .unwrap()
            .query_row(
                "SELECT enabled, role, COALESCE(display_name, ''), password_hash \
                 FROM users WHERE username = 'bob'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap()
    }

    fn session_alive(pool: &DbPool, token: &str) -> bool {
        sessions::validate_session(
            &pool.get().unwrap(),
            token,
            &sessions::SessionConfig::default(),
        )
        .unwrap()
        .is_some()
    }

    async fn update_bob(state: &Arc<AppState>) -> Response {
        let body = serde_json::json!({"display_name": "Changed", "role": "analyst"});
        update_user_handler(
            State(Arc::clone(state)),
            Path("bob".into()),
            admin("PUT", body),
        )
        .await
    }

    async fn disable_bob(state: &Arc<AppState>) -> Response {
        disable_user_handler(
            State(Arc::clone(state)),
            Path("bob".into()),
            admin("DELETE", serde_json::json!({})),
        )
        .await
    }

    async fn reset_bob(state: &Arc<AppState>) -> Response {
        let body = serde_json::json!({"new_password": NEW_PASSWORD});
        reset_password_handler(
            State(Arc::clone(state)),
            Path("bob".into()),
            admin("POST", body),
        )
        .await
    }

    /// `state` with a pool that can open no connection (a database file
    /// that cannot be opened), and the pool it had, to inspect the database
    /// with. Every `db_pool.get()` fails: the 50 ms timeout only bounds the
    /// wait, as no connection can ever be established.
    fn without_database(state: Arc<AppState>) -> (Arc<AppState>, DbPool) {
        let mut state = Arc::into_inner(state).expect("a fresh state has one owner");
        let refusing = crate::db::manager::SqliteConnectionManager::file(&state.config.db_path)
            .with_init(|_| Err(rusqlite::Error::InvalidQuery));
        let unavailable = r2d2::Pool::builder()
            .max_size(1)
            .connection_timeout(Duration::from_millis(50))
            .build_unchecked(refusing);
        let database = std::mem::replace(&mut state.db_pool, unavailable);
        (Arc::new(state), database)
    }

    /// Without a database connection every user-admin endpoint answers 503
    /// and changes nothing: no account is created, `bob` keeps his role,
    /// profile, password and session, and nothing is audited.
    #[tokio::test]
    async fn user_admin_endpoints_answer_503_when_the_database_is_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let token = bob(&state);
        let before = bob_row(&state.db_pool);
        let (state, database) = without_database(state);
        let unavailable = StatusCode::SERVICE_UNAVAILABLE;

        let carol = serde_json::json!({"username": "carol", "password": NEW_PASSWORD});
        let resp = create_user_handler(State(Arc::clone(&state)), admin("POST", carol)).await;
        assert_eq!(resp.status(), unavailable, "create");
        let req = admin("GET", serde_json::json!({}));
        let resp = list_users_handler(State(Arc::clone(&state)), req).await;
        assert_eq!(resp.status(), unavailable, "list");
        assert_eq!(update_bob(&state).await.status(), unavailable, "update");
        assert_eq!(disable_bob(&state).await.status(), unavailable, "disable");
        assert_eq!(reset_bob(&state).await.status(), unavailable, "reset");

        assert_eq!(bob_row(&database), before);
        assert!(session_alive(&database, &token));
        assert_eq!(
            count(
                &database,
                "SELECT COUNT(*) FROM users WHERE username = 'carol'"
            ),
            0
        );
        assert_eq!(count(&database, "SELECT COUNT(*) FROM audit_log"), 0);
    }

    /// A write that lands on no row — the account went away between the
    /// role-ceiling check and the write, emulated by a trigger that skips
    /// the row — is answered 404, never reported as done: nothing changes,
    /// nothing is audited, and the disable revokes no session as it
    /// disabled nothing.
    #[tokio::test]
    async fn account_writes_that_land_on_no_row_are_not_reported_as_done() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let token = bob(&state);
        let before = bob_row(&state.db_pool);
        sql(
            &state,
            "CREATE TRIGGER account_gone BEFORE UPDATE ON users \
             BEGIN SELECT RAISE(IGNORE); END;",
        );

        assert_eq!(update_bob(&state).await.status(), StatusCode::NOT_FOUND);
        assert_eq!(disable_bob(&state).await.status(), StatusCode::NOT_FOUND);
        assert_eq!(reset_bob(&state).await.status(), StatusCode::NOT_FOUND);

        assert_eq!(bob_row(&state.db_pool), before);
        assert!(session_alive(&state.db_pool, &token));
        assert_eq!(count(&state.db_pool, "SELECT COUNT(*) FROM audit_log"), 0);
    }

    async fn assert_disable_with_audit_records(state: &Arc<AppState>, records: i64) {
        let token = bob(state);
        assert_eq!(disable_bob(state).await.status(), StatusCode::OK);
        assert!(!bob_row(&state.db_pool).0, "bob is disabled");
        assert!(!session_alive(&state.db_pool, &token), "and signed out");
        assert_eq!(
            test_support::audit_count(state, "admin_disable_user"),
            records
        );
    }

    /// Audit logging is best effort: an admin's disable whose record cannot
    /// be signed (production without an audit key) or cannot be written
    /// still disables the account and ends its sessions.
    #[tokio::test]
    async fn an_admin_disable_applies_when_its_audit_record_cannot_be_kept() {
        // Without a configured key, production signs with a legacy
        // fallback from the environment if one is set (CI sets none).
        let signed_without_key = i64::from(audit_chain::get_audit_secret("", "production").is_ok());
        let dir = tempfile::tempdir().unwrap();
        let mut unsigned =
            Arc::into_inner(test_support::app_state(&dir)).expect("a fresh state has one owner");
        unsigned.config.bridge_env = "production".into();
        unsigned.config.audit_key = String::new();
        assert_disable_with_audit_records(&Arc::new(unsigned), signed_without_key).await;

        let dir = tempfile::tempdir().unwrap();
        let unwritable = test_support::app_state(&dir);
        sql(
            &unwritable,
            "CREATE TRIGGER no_audit BEFORE INSERT ON audit_log \
             BEGIN SELECT RAISE(ABORT, 'audit log unavailable'); END;",
        );
        assert_disable_with_audit_records(&unwritable, 0).await;
    }
}
