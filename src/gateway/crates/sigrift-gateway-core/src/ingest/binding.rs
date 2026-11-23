//! Node binding of ingested batches (contracts K4, K7, K7b and K10,
//! gateway side).
//!
//! Who may submit a batch for node `N`:
//!
//! * an API key bound to a node (`node_id` in keys.json): only for that
//!   node, whatever its role (K4);
//! * an unbound SENSOR or NODE key (a node key): it is bound to `N` on its
//!   first batch ("trust on first use"). The gateway asks the bridge to do
//!   it — `POST {UC_PYTHON_URL}/api/internal/bind-node-key` with
//!   `{"key_id", "node_id"}`, authenticated by `X-Rust-Proxy` — so the
//!   binding is made by the same atomic keys.json update the bridge's own
//!   node routes use (it also applies the bridge's rule that a key named
//!   after a registered node is that node's key). The bridge answers 200
//!   when the key is now bound to `N` (newly or already); 409 when it is
//!   bound to another node, or when another key already holds `N` (the
//!   first key to claim a node wins; K7b), and 404 for an unknown key, all
//!   refused here with 403; anything else, or no answer within
//!   [`BIND_TIMEOUT`], is 503 (fail closed). A 409 or 403 saying the key
//!   is not a node key (the bridge's stored role for it is not a node
//!   role, e.g. the key was re-roled after the gateway last read
//!   keys.json) is refused with 403 `Node endpoints require a node API
//!   key`. Both layers read a keys.json entry without a role, or with an
//!   unknown one, as VIEWER
//!   ([`effective_role`](crate::auth::api_key::effective_role)), so such
//!   a key is refused as a VIEWER key, below. Without a usable
//!   `UC_PROXY_SECRET` (development only) the bridge refuses the binding
//!   endpoint, so instead of answering 503 to every first batch the
//!   gateway leaves node keys unbound, as `BRIDGE_ALLOW_UNBOUND_NODE_KEYS`
//!   does (K10);
//! * an unbound VIEWER key: refused (403 `Node endpoints require a node API
//!   key`), with or without `BRIDGE_ALLOW_UNBOUND_NODE_KEYS` — a dashboard
//!   key is not a node credential and is never bound automatically (K7b);
//!   an admin can still bind it to a node explicitly. This refusal needs
//!   no request to the bridge, so it also holds without a usable
//!   `UC_PROXY_SECRET`, as on a bridge without the setting;
//! * an unbound ANALYST key (operator tooling, K7b), or ADMIN or KEYMASTER
//!   key: any node, and it stays unbound;
//! * with `BRIDGE_ALLOW_UNBOUND_NODE_KEYS` set, as on the bridge
//!   (`enforce_node_binding`), unbound NODE/SENSOR keys stay unbound and
//!   may submit for any node, as before K7b (VIEWER keys stay refused);
//! * the bridge's legacy rule holds for every unbound key below ADMIN,
//!   also with that setting: a key whose id is a node registered with the
//!   bridge (its `nodes.json`, next to keys.json) is that node's key, so
//!   it may submit only for that node
//!   ([`KeyStore::is_registered_node`](crate::auth::api_key::KeyStore::is_registered_node)).
//!   No binding request is made for a VIEWER or ANALYST key, so for them
//!   the rule rests on the gateway's copy of nodes.json alone, which lags
//!   the bridge's registry until the bridge next saves it: a VIEWER key
//!   (a role-less one included) named after a node registered since then
//!   is refused as a VIEWER key until the file is saved, or until the
//!   bridge's own node routes bind the key in keys.json;
//! * a client certificate below ADMIN: only the node its identity names
//!   (the certificate identity is the node id; no trust on first use); an
//!   ADMIN-or-above certificate: any node;
//! * a user session of ANALYST or above: any node; below ANALYST (VIEWER,
//!   or a SENSOR/NODE user): refused — a session is not a node credential.

use std::time::Duration;

use axum::http::StatusCode;
use tracing::{error, info, warn};

use crate::auth::rbac::Role;
use crate::middleware::auth::AuthInfo;
use crate::proxy::handler::proxy_secret_header;
use crate::AppState;

/// The bridge's binding endpoint.
pub const BIND_PATH: &str = "/api/internal/bind-node-key";
/// How long the bridge may take to bind a key.
pub const BIND_TIMEOUT: Duration = Duration::from_secs(2);

/// The 403 for a key the bridge would not bind to the batch's node.
pub const BOUND_ELSEWHERE: &str = "API key is bound to a different node";

/// The 403 for a credential that is not a node credential: a session
/// below ANALYST, or an unbound VIEWER key (K7b). The bridge's node routes
/// answer the same.
pub const NOT_A_NODE_KEY: &str = "Node endpoints require a node API key";

/// Who submitted a batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Submitter {
    /// Authentication is disabled (`UC_ALLOW_NO_AUTH`).
    Unchecked,
    Session {
        role: Role,
    },
    ApiKey {
        key_id: String,
        role: Role,
    },
    ClientCert {
        identity: String,
        role: Role,
    },
}

impl Submitter {
    /// From the middleware's [`AuthInfo`]. A principal resolved from a
    /// verified client certificate is an `ApiKey` whose request carries no
    /// API key (the middleware prefers a presented key over a cert).
    pub fn of(auth: Option<&AuthInfo>, api_key_presented: bool) -> Self {
        match auth {
            Some(AuthInfo::Session { role, .. }) => Self::Session { role: *role },
            Some(AuthInfo::ApiKey { key_id, role }) if api_key_presented => Self::ApiKey {
                key_id: key_id.clone(),
                role: *role,
            },
            Some(AuthInfo::ApiKey { key_id, role }) => Self::ClientCert {
                identity: key_id.clone(),
                role: *role,
            },
            Some(AuthInfo::Unauthenticated) | None => Self::Unchecked,
        }
    }
}

/// Why a batch may not be submitted for its node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub status: StatusCode,
    pub detail: String,
}

fn refusal(status: StatusCode, detail: impl Into<String>) -> Refusal {
    Refusal {
        status,
        detail: detail.into(),
    }
}

/// What the bridge answered to a binding request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindOutcome {
    /// 200: the key is bound to the requested node.
    Bound,
    /// 409 (bound to another node) or 404 (unknown key), or a 200 naming
    /// another node.
    Refused(u16),
    /// 409 naming the requested node itself: the key is unbound, but
    /// another key is already bound to that node, and only an admin may
    /// bind a second one (K7b).
    NodeClaimed,
    /// 409 (what the bridge sends: a 403 there would read as a refused
    /// proxy secret) or 403 with detail `Node endpoints require a node API
    /// key`: the bridge's stored role for the key is not a node role
    /// (K7b), whatever the gateway read from keys.json.
    NotANodeKey,
    /// Anything else: unreachable, timed out, 403 (the proxy secret), 5xx…
    Unavailable(String),
}

/// Ask the bridge to bind `key_id` to `node_id` (see the module docs).
pub async fn bind_node_key(
    client: &reqwest::Client,
    python_url: &str,
    proxy_secret: &str,
    key_id: &str,
    node_id: &str,
    timeout: Duration,
) -> BindOutcome {
    let url = format!("{}{BIND_PATH}", python_url.trim_end_matches('/'));
    let sent = client
        .post(&url)
        .timeout(timeout)
        .header("x-rust-proxy", proxy_secret_header(proxy_secret))
        .json(&serde_json::json!({ "key_id": key_id, "node_id": node_id }))
        .send()
        .await;
    let resp = match sent {
        Ok(resp) => resp,
        Err(e) if e.is_timeout() => return BindOutcome::Unavailable("timed out".into()),
        Err(e) => return BindOutcome::Unavailable(e.to_string()),
    };
    let status = resp.status().as_u16();
    if !matches!(status, 200 | 403 | 404 | 409) {
        return BindOutcome::Unavailable(format!("HTTP {status}"));
    }
    let body: serde_json::Value = resp.json().await.unwrap_or_default();
    let named = body.get("node_id").and_then(|v| v.as_str());
    let detail = body.get("detail").and_then(|v| v.as_str());
    match status {
        // {"node_id": "<bound node>", "bound": true}
        200 => match named {
            Some(bound) if bound != node_id => BindOutcome::Refused(200),
            _ => BindOutcome::Bound,
        },
        // {"node_id": "<requested node>", "detail": "Node endpoints require
        // a node API key"} (K7b): checked before the claimed-node answer,
        // which names the requested node too.
        409 | 403 if detail == Some(NOT_A_NODE_KEY) => BindOutcome::NotANodeKey,
        // {"node_id": "<requested node>", "detail": "node already has a
        // bound key"} (K7b); {"node_id": "<other node>"} is below (K7).
        409 if named == Some(node_id) => BindOutcome::NodeClaimed,
        403 => BindOutcome::Unavailable(
            "HTTP 403 — the bridge refused the proxy secret (UC_PROXY_SECRET must be \
             the bridge's)"
                .into(),
        ),
        status => BindOutcome::Refused(status),
    }
}

/// The bridge's legacy rule for an unbound key, which it applies before
/// trust on first use and before `BRIDGE_ALLOW_UNBOUND_NODE_KEYS`
/// (`existing_node_binding`): a key named after a registered node is that
/// node's key, so it may submit only for that node. `None` when `key_id`
/// is not named after a registered node.
fn legacy_binding(state: &AppState, key_id: &str, node_id: &str) -> Option<Result<(), Refusal>> {
    let legacy = state
        .key_store
        .as_ref()
        .is_some_and(|store| store.is_registered_node(key_id));
    if !legacy {
        return None;
    }
    if key_id != node_id {
        warn!(
            key_id,
            batch_node = node_id,
            "Batch rejected: the API key is named after a registered node and may only \
             submit for it"
        );
        return Some(Err(refusal(
            StatusCode::FORBIDDEN,
            format!("API key is bound to node '{key_id}'"),
        )));
    }
    Some(Ok(()))
}

/// SENSOR and NODE: the roles of node keys, the only keys bound on first
/// use (K7b).
pub fn is_node_role(role: Role) -> bool {
    matches!(role, Role::Sensor | Role::Node)
}

/// May `who` submit a batch for `node_id`? Binds an unbound node key on
/// first use (see the module docs).
pub async fn authorize_batch(
    state: &AppState,
    who: &Submitter,
    node_id: &str,
) -> Result<(), Refusal> {
    match who {
        Submitter::Unchecked => Ok(()),
        Submitter::Session { role } if role.has_at_least(Role::Analyst) => Ok(()),
        Submitter::Session { role } => {
            warn!(%role, node_id, "Batch refused: a session below ANALYST is not a node credential");
            Err(refusal(StatusCode::FORBIDDEN, NOT_A_NODE_KEY))
        }
        Submitter::ClientCert { role, .. } if role.has_at_least(Role::Admin) => Ok(()),
        Submitter::ClientCert { identity, .. } if identity == node_id => Ok(()),
        Submitter::ClientCert { identity, .. } => {
            warn!(
                identity,
                node_id, "Batch refused: a client certificate may only submit for its own node"
            );
            Err(refusal(
                StatusCode::FORBIDDEN,
                format!(
                    "Client certificate '{identity}' may only submit batches for node '{identity}'"
                ),
            ))
        }
        Submitter::ApiKey { key_id, role } => {
            let bound = state
                .key_store
                .as_ref()
                .and_then(|store| store.node_binding(key_id));
            if let Some(bound) = bound {
                if bound == node_id {
                    return Ok(());
                }
                warn!(
                    key_id,
                    bound_node = %bound,
                    batch_node = node_id,
                    "Batch rejected: the API key is bound to another node"
                );
                return Err(refusal(
                    StatusCode::FORBIDDEN,
                    format!("API key is bound to node '{bound}'"),
                ));
            }
            if role.has_at_least(Role::Admin) {
                return Ok(());
            }
            // K7b: only node keys are bound on first use. An unbound
            // ANALYST key is operator tooling and acts for any node,
            // unbound; an unbound VIEWER key is a dashboard key, refused.
            // Either is still bound by its name, by the bridge's legacy
            // rule (no request to the bridge is made for them).
            if !is_node_role(*role) {
                if let Some(legacy) = legacy_binding(state, key_id, node_id) {
                    return legacy;
                }
                if role.has_at_least(Role::Analyst) {
                    return Ok(());
                }
                warn!(
                    key_id,
                    %role,
                    node_id,
                    "Batch refused: an unbound API key that is neither a node key \
                     (SENSOR/NODE) nor ANALYST or above is not a node credential"
                );
                return Err(refusal(StatusCode::FORBIDDEN, NOT_A_NODE_KEY));
            }
            // BRIDGE_ALLOW_UNBOUND_NODE_KEYS keeps unbound NODE/SENSOR keys
            // unbound (any node, except by the legacy rule), as the bridge's
            // enforce_node_binding does. It never makes a VIEWER key a node
            // credential: that refusal above comes first on both layers.
            if state.config.unbound_node_keys_allowed() {
                return legacy_binding(state, key_id, node_id).unwrap_or(Ok(()));
            }
            // K10: without a usable proxy secret the bridge refuses the
            // binding endpoint. Node keys stay unbound, as with the setting
            // (the startup error says so), instead of every first batch of
            // a new key getting 503.
            if !state.config.proxy_secret_usable() {
                return legacy_binding(state, key_id, node_id).unwrap_or(Ok(()));
            }
            match bind_node_key(
                &state.proxy_client,
                &state.config.python_url,
                &state.config.proxy_secret,
                key_id,
                node_id,
                BIND_TIMEOUT,
            )
            .await
            {
                BindOutcome::Bound => {
                    info!(
                        key_id,
                        node_id, "API key bound to node on first use (trust on first use)"
                    );
                    Ok(())
                }
                BindOutcome::Refused(status) => {
                    warn!(
                        key_id,
                        node_id,
                        status,
                        "Batch rejected: the bridge would not bind the API key to this node"
                    );
                    Err(refusal(StatusCode::FORBIDDEN, BOUND_ELSEWHERE))
                }
                BindOutcome::NodeClaimed => {
                    warn!(
                        key_id,
                        node_id,
                        "Batch rejected: another API key is already bound to this node; an \
                         admin must bind this key to it explicitly (key create or update \
                         with node_id)"
                    );
                    Err(refusal(
                        StatusCode::FORBIDDEN,
                        format!(
                            "Node '{node_id}' already has a bound API key; an admin must bind \
                             this key to it explicitly"
                        ),
                    ))
                }
                BindOutcome::NotANodeKey => {
                    warn!(
                        key_id,
                        node_id, "Batch rejected: the bridge says the API key is not a node key"
                    );
                    Err(refusal(StatusCode::FORBIDDEN, NOT_A_NODE_KEY))
                }
                BindOutcome::Unavailable(reason) => {
                    error!(
                        key_id,
                        node_id,
                        reason,
                        "Batch refused: cannot bind the unbound API key (bridge unavailable)"
                    );
                    Err(refusal(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Node binding is unavailable; try again later",
                    ))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{extract::State, routing::post, Json, Router};
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Seen(Arc<Mutex<Vec<SeenRequest>>>);

    /// X-Rust-Proxy, Content-Type and JSON body of one bind request.
    type SeenRequest = (Option<String>, Option<String>, serde_json::Value);

    /// A bridge whose bind endpoint answers `status` with `body` after
    /// `delay`.
    async fn bridge(status: u16, body: serde_json::Value, delay: Duration) -> (String, Seen) {
        let seen = Seen::default();
        let record = seen.clone();
        let app = Router::new()
            .route(
                BIND_PATH,
                post(
                    move |State(seen): State<Seen>,
                          headers: axum::http::HeaderMap,
                          Json(req): Json<serde_json::Value>| {
                        let body = body.clone();
                        async move {
                            let h =
                                |n: &str| headers.get(n).map(|v| v.to_str().unwrap().to_string());
                            seen.0.lock().unwrap().push((
                                h("x-rust-proxy"),
                                h("content-type"),
                                req,
                            ));
                            tokio::time::sleep(delay).await;
                            (StatusCode::from_u16(status).unwrap(), Json(body))
                        }
                    },
                ),
            )
            .with_state(record);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (url, seen)
    }

    async fn bind(url: &str, timeout: Duration) -> BindOutcome {
        bind_node_key(
            &reqwest::Client::new(),
            url,
            "s3cret",
            "k1",
            "edge-1",
            timeout,
        )
        .await
    }

    #[tokio::test]
    async fn the_bridge_answer_decides() {
        let quick = Duration::ZERO;
        let (url, seen) = bridge(
            200,
            serde_json::json!({"node_id": "edge-1", "bound": true}),
            quick,
        )
        .await;
        assert_eq!(bind(&url, BIND_TIMEOUT).await, BindOutcome::Bound);
        let (secret, content_type, body) = seen.0.lock().unwrap()[0].clone();
        assert_eq!(secret.as_deref(), Some("s3cret"));
        assert_eq!(content_type.as_deref(), Some("application/json"));
        assert_eq!(
            body,
            serde_json::json!({"key_id": "k1", "node_id": "edge-1"})
        );

        let (url, _) = bridge(409, serde_json::json!({"node_id": "edge-2"}), quick).await;
        assert_eq!(bind(&url, BIND_TIMEOUT).await, BindOutcome::Refused(409));
        let (url, _) = bridge(404, serde_json::json!({"detail": "unknown key"}), quick).await;
        assert_eq!(bind(&url, BIND_TIMEOUT).await, BindOutcome::Refused(404));
        // A 200 for another node is not a binding to this one.
        let (url, _) = bridge(
            200,
            serde_json::json!({"node_id": "edge-2", "bound": true}),
            quick,
        )
        .await;
        assert_eq!(bind(&url, BIND_TIMEOUT).await, BindOutcome::Refused(200));
        for status in [403, 500, 503, 422] {
            let (url, _) = bridge(status, serde_json::json!({}), quick).await;
            assert!(
                matches!(bind(&url, BIND_TIMEOUT).await, BindOutcome::Unavailable(_)),
                "{status}"
            );
        }
        // K7b: another key already holds the node (the 409 names the
        // requested node itself), and a key the bridge says is no node key.
        let (url, _) = bridge(
            409,
            serde_json::json!({"node_id": "edge-1", "detail": "node already has a bound key"}),
            quick,
        )
        .await;
        assert_eq!(bind(&url, BIND_TIMEOUT).await, BindOutcome::NodeClaimed);
        let (url, _) = bridge(403, serde_json::json!({"detail": NOT_A_NODE_KEY}), quick).await;
        assert_eq!(bind(&url, BIND_TIMEOUT).await, BindOutcome::NotANodeKey);
        // GW5-R2 regression: what the bridge really sends for a key it
        // does not consider a node key is a 409 that names the requested
        // node, like the claimed-node answer — it read as NodeClaimed.
        let (url, _) = bridge(
            409,
            serde_json::json!({"node_id": "edge-1", "detail": NOT_A_NODE_KEY}),
            quick,
        )
        .await;
        assert_eq!(bind(&url, BIND_TIMEOUT).await, BindOutcome::NotANodeKey);
        // The proxy secret refused: still unavailable (503), not a refusal.
        let (url, _) = bridge(
            403,
            serde_json::json!({"detail": "Internal endpoint: only the gateway may call it"}),
            quick,
        )
        .await;
        assert!(matches!(
            bind(&url, BIND_TIMEOUT).await,
            BindOutcome::Unavailable(_)
        ));
    }

    #[test]
    fn only_sensor_and_node_are_node_roles() {
        assert!(is_node_role(Role::Sensor));
        assert!(is_node_role(Role::Node));
        for role in [Role::Viewer, Role::Analyst, Role::Admin, Role::Keymaster] {
            assert!(!is_node_role(role), "{role}");
        }
    }

    #[tokio::test]
    async fn a_slow_or_absent_bridge_is_unavailable() {
        let (url, _) = bridge(
            200,
            serde_json::json!({"node_id": "edge-1"}),
            Duration::from_secs(5),
        )
        .await;
        let started = std::time::Instant::now();
        assert_eq!(
            bind(&url, Duration::from_millis(200)).await,
            BindOutcome::Unavailable("timed out".into())
        );
        assert!(started.elapsed() < Duration::from_secs(2));

        let addr = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        assert!(matches!(
            bind(&format!("http://{addr}"), BIND_TIMEOUT).await,
            BindOutcome::Unavailable(_)
        ));
    }

    #[test]
    fn the_submitter_follows_the_resolved_principal() {
        let key = AuthInfo::ApiKey {
            key_id: "edge-7".into(),
            role: Role::Node,
        };
        assert_eq!(
            Submitter::of(Some(&key), true),
            Submitter::ApiKey {
                key_id: "edge-7".into(),
                role: Role::Node
            }
        );
        assert_eq!(
            Submitter::of(Some(&key), false),
            Submitter::ClientCert {
                identity: "edge-7".into(),
                role: Role::Node
            }
        );
        assert_eq!(Submitter::of(None, true), Submitter::Unchecked);
    }
}
