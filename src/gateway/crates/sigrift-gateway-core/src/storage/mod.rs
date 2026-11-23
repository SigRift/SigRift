//! Persistent storage for auth state — users, sessions, security state.
//!
//! All functions take a `&PooledConnection<SqliteConnectionManager>` and use
//! `prepare_cached` for repeated queries. Write operations use transactions
//! for atomicity.

pub mod api_keys;
pub mod mfa;
pub mod nodes;
pub mod password_history;
pub mod security_state;
pub mod sessions;
pub mod users;
