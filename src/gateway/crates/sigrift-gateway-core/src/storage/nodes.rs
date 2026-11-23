//! Node management storage — registration, heartbeat, command queue.

use crate::db::manager::SqliteConnectionManager;
use r2d2::PooledConnection;
use rusqlite::{params, Connection, Transaction, TransactionBehavior};
use serde::Serialize;

/// Node record (safe to serialize to JSON).
#[derive(Debug, Clone, Serialize)]
pub struct NodeRecord {
    pub node_id: String,
    pub host: String,
    pub port: i64,
    pub status: String,
    pub capabilities: String,
    pub registered_at: String,
    pub last_seen: Option<String>,
    pub cpu_percent: f64,
    pub memory_mb: f64,
    pub classifications_per_sec: f64,
    pub current_frequency_hz: f64,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub altitude_m: Option<f64>,
    pub location_name: String,
    pub tenant_id: String,
}

/// Pending command record.
#[derive(Debug, Clone, Serialize)]
pub struct CommandRecord {
    pub command_id: String,
    pub node_id: String,
    pub command: String,
    pub params: String,
    pub status: String,
    pub queued_at: String,
}

/// Create the nodes and pending_commands tables if they don't exist.
pub fn ensure_node_tables(
    conn: &PooledConnection<SqliteConnectionManager>,
) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS nodes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id TEXT UNIQUE NOT NULL,
            host TEXT NOT NULL,
            port INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'offline',
            capabilities TEXT NOT NULL DEFAULT '{}',
            registered_at TEXT NOT NULL,
            last_seen TEXT,
            cpu_percent REAL NOT NULL DEFAULT 0,
            memory_mb REAL NOT NULL DEFAULT 0,
            classifications_per_sec REAL NOT NULL DEFAULT 0,
            current_frequency_hz REAL NOT NULL DEFAULT 0,
            latitude REAL,
            longitude REAL,
            altitude_m REAL,
            location_name TEXT NOT NULL DEFAULT '',
            tenant_id TEXT NOT NULL DEFAULT 'default'
        );
        CREATE TABLE IF NOT EXISTS pending_commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            command_id TEXT UNIQUE NOT NULL,
            node_id TEXT NOT NULL,
            command TEXT NOT NULL,
            params TEXT NOT NULL DEFAULT '{}',
            status TEXT NOT NULL DEFAULT 'queued',
            queued_at TEXT NOT NULL,
            lease_expires_at TEXT,
            dispatched_at TEXT,
            acked_at TEXT
        );",
    )
}

/// Register (or re-register) a node. Returns true if the registration was
/// stored, false if another tenant owns `node_id`.
///
/// Re-registration by the owning tenant updates host, port, capabilities
/// and last_seen in place and keeps registered_at. Node ids are unique
/// across tenants, so an id another tenant already owns is refused with
/// `Ok(false)` and its record is left unchanged: the first tenant to
/// register an id keeps it until it deletes the node. Tenant ids must
/// match exactly (byte for byte, so case and trailing spaces count).
///
/// Callers must answer `Ok(false)` with a refusal (for example 409
/// Conflict), never with success, and must gate heartbeats and command
/// polling on [`get_node`] for the caller's tenant (those functions are
/// keyed by node id alone). Because the namespace is shared, the refusal
/// also tells the caller that some other tenant holds the id.
///
/// The `'default'` tenant is no exception: a node stored under it (for
/// example by a single-tenant setup) is not moved by registering it under
/// another tenant. Migrate such a node's `tenant_id` with an admin step
/// instead; deleting it to re-register drops its queued commands,
/// heartbeat metrics and location.
pub fn register_node(
    conn: &PooledConnection<SqliteConnectionManager>,
    node_id: &str,
    host: &str,
    port: i64,
    capabilities_json: &str,
    tenant_id: &str,
) -> Result<bool, rusqlite::Error> {
    let now = chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S+00:00")
        .to_string();
    // One statement, so the ownership check and the write cannot interleave
    // with another registration. A refused update changes no row.
    let changed = conn.execute(
        "INSERT INTO nodes (node_id, host, port, capabilities, registered_at, last_seen, tenant_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6)
         ON CONFLICT(node_id) DO UPDATE SET
            host = excluded.host,
            port = excluded.port,
            capabilities = excluded.capabilities,
            last_seen = excluded.last_seen
         WHERE nodes.tenant_id = excluded.tenant_id",
        params![node_id, host, port, capabilities_json, now, tenant_id],
    )?;
    Ok(changed > 0)
}

/// Update heartbeat metrics and last_seen. Returns true if the node was found.
///
/// Keyed by node id alone, in any tenant: check [`get_node`] for the
/// caller's tenant first.
pub fn update_heartbeat(
    conn: &PooledConnection<SqliteConnectionManager>,
    node_id: &str,
    cpu: f64,
    memory: f64,
    cls_per_sec: f64,
    freq_hz: f64,
) -> Result<bool, rusqlite::Error> {
    let now = chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S+00:00")
        .to_string();
    let updated = conn.execute(
        "UPDATE nodes SET last_seen = ?1, cpu_percent = ?2, memory_mb = ?3,
                          classifications_per_sec = ?4, current_frequency_hz = ?5
         WHERE node_id = ?6",
        params![now, cpu, memory, cls_per_sec, freq_hz, node_id],
    )?;
    Ok(updated > 0)
}

/// List all nodes for a tenant, computing status from last_seen.
pub fn list_nodes(
    conn: &PooledConnection<SqliteConnectionManager>,
    tenant_id: &str,
) -> Result<Vec<NodeRecord>, rusqlite::Error> {
    let mut stmt = conn.prepare_cached(
        "SELECT node_id, host, port, capabilities, registered_at, last_seen,
                cpu_percent, memory_mb, classifications_per_sec, current_frequency_hz,
                latitude, longitude, altitude_m, location_name, tenant_id
         FROM nodes WHERE tenant_id = ?1 ORDER BY node_id",
    )?;
    let rows = stmt.query_map(params![tenant_id], |row| {
        let last_seen: Option<String> = row.get(5)?;
        let status = compute_status(last_seen.as_deref()).to_string();
        Ok(NodeRecord {
            node_id: row.get(0)?,
            host: row.get(1)?,
            port: row.get(2)?,
            status,
            capabilities: row.get(3)?,
            registered_at: row.get(4)?,
            last_seen,
            cpu_percent: row.get(6)?,
            memory_mb: row.get(7)?,
            classifications_per_sec: row.get(8)?,
            current_frequency_hz: row.get(9)?,
            latitude: row.get(10)?,
            longitude: row.get(11)?,
            altitude_m: row.get(12)?,
            location_name: row.get::<_, Option<String>>(13)?.unwrap_or_default(),
            tenant_id: row.get(14)?,
        })
    })?;
    rows.collect()
}

/// Get a single node by node_id + tenant_id.
pub fn get_node(
    conn: &PooledConnection<SqliteConnectionManager>,
    node_id: &str,
    tenant_id: &str,
) -> Result<Option<NodeRecord>, rusqlite::Error> {
    let mut stmt = conn.prepare_cached(
        "SELECT node_id, host, port, capabilities, registered_at, last_seen,
                cpu_percent, memory_mb, classifications_per_sec, current_frequency_hz,
                latitude, longitude, altitude_m, location_name, tenant_id
         FROM nodes WHERE node_id = ?1 AND tenant_id = ?2",
    )?;
    let result = stmt.query_row(params![node_id, tenant_id], |row| {
        let last_seen: Option<String> = row.get(5)?;
        let status = compute_status(last_seen.as_deref()).to_string();
        Ok(NodeRecord {
            node_id: row.get(0)?,
            host: row.get(1)?,
            port: row.get(2)?,
            status,
            capabilities: row.get(3)?,
            registered_at: row.get(4)?,
            last_seen,
            cpu_percent: row.get(6)?,
            memory_mb: row.get(7)?,
            classifications_per_sec: row.get(8)?,
            current_frequency_hz: row.get(9)?,
            latitude: row.get(10)?,
            longitude: row.get(11)?,
            altitude_m: row.get(12)?,
            location_name: row.get::<_, Option<String>>(13)?.unwrap_or_default(),
            tenant_id: row.get(14)?,
        })
    });
    match result {
        Ok(node) => Ok(Some(node)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Delete a node by node_id + tenant_id. Returns true if the node was found.
///
/// The node's pending commands are dropped with it, so they cannot reach a
/// node registered later under the same id. A delete that finds no node in
/// `tenant_id` (unregistered, or owned by another tenant) changes nothing;
/// stray commands for such an id are left to `reap_expired_commands`.
///
/// Both deletes commit together or not at all. Inside a transaction the
/// caller already holds they run in a savepoint of it (see [`write_tx`]).
pub fn delete_node(
    conn: &PooledConnection<SqliteConnectionManager>,
    node_id: &str,
    tenant_id: &str,
) -> Result<bool, rusqlite::Error> {
    write_tx(conn, |conn| {
        let deleted = conn.execute(
            "DELETE FROM nodes WHERE node_id = ?1 AND tenant_id = ?2",
            params![node_id, tenant_id],
        )?;
        if deleted > 0 {
            conn.execute(
                "DELETE FROM pending_commands WHERE node_id = ?1",
                params![node_id],
            )?;
        }
        Ok(deleted > 0)
    })
}

/// Run `f` as one write transaction and commit it.
///
/// At top level this is `BEGIN IMMEDIATE`, so the write lock is held before
/// `f` runs. Inside a transaction the caller already opened, `f` runs in a
/// savepoint instead: an error rolls back only `f`'s changes, and the
/// caller's transaction stays open for the caller to commit or roll back.
fn write_tx<T>(
    conn: &Connection,
    f: impl FnOnce(&Connection) -> Result<T, rusqlite::Error>,
) -> Result<T, rusqlite::Error> {
    if !conn.is_autocommit() {
        conn.execute_batch("SAVEPOINT sigrift_nodes")?;
        return match f(conn) {
            Ok(value) => {
                conn.execute_batch("RELEASE sigrift_nodes")?;
                Ok(value)
            }
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK TO sigrift_nodes; RELEASE sigrift_nodes");
                Err(e)
            }
        };
    }
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)?;
    let value = f(&tx)?;
    tx.commit()?;
    Ok(value)
}

/// Queue a command for a node. Returns the command_id (UUID v4).
///
/// Keyed by node id alone, in any tenant: check [`get_node`] for the
/// caller's tenant first.
pub fn queue_command(
    conn: &PooledConnection<SqliteConnectionManager>,
    node_id: &str,
    command: &str,
    params_json: &str,
) -> Result<String, rusqlite::Error> {
    let command_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S+00:00")
        .to_string();
    // Lease expires in 5 minutes
    let lease_expires = (chrono::Utc::now() + chrono::Duration::minutes(5))
        .format("%Y-%m-%dT%H:%M:%S+00:00")
        .to_string();
    conn.execute(
        "INSERT INTO pending_commands (command_id, node_id, command, params, queued_at, lease_expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![command_id, node_id, command, params_json, now, lease_expires],
    )?;
    Ok(command_id)
}

/// Get pending (queued) commands for a node and mark them as dispatched.
///
/// Keyed by node id alone, in any tenant: check [`get_node`] for the
/// caller's tenant first, or a refused registrant could poll the owner's
/// commands.
pub fn get_pending_commands(
    conn: &PooledConnection<SqliteConnectionManager>,
    node_id: &str,
) -> Result<Vec<CommandRecord>, rusqlite::Error> {
    let mut stmt = conn.prepare_cached(
        "SELECT command_id, node_id, command, params, status, queued_at
         FROM pending_commands
         WHERE node_id = ?1 AND status = 'queued'
         ORDER BY queued_at ASC",
    )?;
    let rows: Vec<CommandRecord> = stmt
        .query_map(params![node_id], |row| {
            Ok(CommandRecord {
                command_id: row.get(0)?,
                node_id: row.get(1)?,
                command: row.get(2)?,
                params: row.get(3)?,
                status: row.get(4)?,
                queued_at: row.get(5)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    // Mark them as dispatched
    if !rows.is_empty() {
        let now = chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S+00:00")
            .to_string();
        for cmd in &rows {
            conn.execute(
                "UPDATE pending_commands SET status = 'dispatched', dispatched_at = ?1
                 WHERE command_id = ?2",
                params![now, cmd.command_id],
            )?;
        }
    }

    Ok(rows)
}

/// Remove commands with expired leases. Returns count deleted.
pub fn reap_expired_commands(
    conn: &PooledConnection<SqliteConnectionManager>,
) -> Result<usize, rusqlite::Error> {
    let now = chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S+00:00")
        .to_string();
    let deleted = conn.execute(
        "DELETE FROM pending_commands WHERE lease_expires_at < ?1",
        params![now],
    )?;
    Ok(deleted)
}

/// Compute node status from last_seen timestamp.
///
/// - Within 60s: "online"
/// - Within 300s: "degraded"
/// - Older or missing: "offline"
pub fn compute_status(last_seen: Option<&str>) -> &'static str {
    let last_seen_str = match last_seen {
        Some(s) => s,
        None => return "offline",
    };

    let dt = match parse_iso_datetime(last_seen_str) {
        Some(dt) => dt,
        None => return "offline",
    };

    let elapsed = chrono::Utc::now().signed_duration_since(dt).num_seconds();
    if elapsed <= 60 {
        "online"
    } else if elapsed <= 300 {
        "degraded"
    } else {
        "offline"
    }
}

/// Parse an ISO 8601 timestamp, treating timezone-naive values as UTC.
fn parse_iso_datetime(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&chrono::Utc));
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return Some(naive.and_utc());
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f") {
        return Some(naive.and_utc());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support;
    use std::collections::BTreeSet;

    type Conn = PooledConnection<SqliteConnectionManager>;

    fn conn_with_tables(dir: &tempfile::TempDir) -> Conn {
        let state = test_support::app_state(dir);
        let conn = state.db_pool.get().unwrap();
        ensure_node_tables(&conn).unwrap();
        conn
    }

    fn iso_ago(secs: i64) -> String {
        (chrono::Utc::now() - chrono::Duration::seconds(secs))
            .format("%Y-%m-%dT%H:%M:%S+00:00")
            .to_string()
    }

    fn command_ids(conn: &Conn) -> BTreeSet<String> {
        conn.prepare("SELECT command_id FROM pending_commands")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    fn set_lease(conn: &Conn, command_id: &str, lease: &str) {
        conn.execute(
            "UPDATE pending_commands SET lease_expires_at = ?1 WHERE command_id = ?2",
            params![lease, command_id],
        )
        .unwrap();
    }

    /// `builder` runs this at every start: rerunning it must neither fail
    /// nor drop registered nodes or queued commands.
    #[test]
    fn ensuring_the_tables_again_keeps_nodes_and_commands() {
        let dir = tempfile::tempdir().unwrap();
        let conn = conn_with_tables(&dir);
        register_node(&conn, "node-a", "10.0.0.1", 9000, "{}", "default").unwrap();
        let cmd = queue_command(&conn, "node-a", "retune", r#"{"hz":1}"#).unwrap();

        ensure_node_tables(&conn).unwrap();
        assert!(get_node(&conn, "node-a", "default").unwrap().is_some());
        assert_eq!(command_ids(&conn), BTreeSet::from([cmd]));
    }

    /// The periodic reaper drops every command whose lease has run out,
    /// dispatched or not, and keeps live ones deliverable.
    #[test]
    fn reaper_removes_only_commands_whose_lease_expired() {
        let dir = tempfile::tempdir().unwrap();
        let conn = conn_with_tables(&dir);
        let live = queue_command(&conn, "node-a", "retune", "{}").unwrap();
        let stale_queued = queue_command(&conn, "node-a", "reboot", "{}").unwrap();
        let stale_dispatched = queue_command(&conn, "node-b", "reboot", "{}").unwrap();
        set_lease(&conn, &stale_queued, &iso_ago(1));
        set_lease(&conn, &stale_dispatched, "2020-01-01T00:00:00+00:00");
        conn.execute(
            "UPDATE pending_commands SET status = 'dispatched' WHERE command_id = ?1",
            params![stale_dispatched],
        )
        .unwrap();

        assert_eq!(reap_expired_commands(&conn).unwrap(), 2);
        assert_eq!(command_ids(&conn), BTreeSet::from([live.clone()]));
        assert_eq!(reap_expired_commands(&conn).unwrap(), 0);

        let delivered = get_pending_commands(&conn, "node-a").unwrap();
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].command_id, live);
        assert_eq!(delivered[0].command, "retune");
    }

    /// A new command's lease is five minutes, so the reaper does not drop
    /// it before the node can poll.
    #[test]
    fn a_freshly_queued_command_survives_the_reaper() {
        let dir = tempfile::tempdir().unwrap();
        let conn = conn_with_tables(&dir);
        let cmd = queue_command(&conn, "node-a", "retune", "{}").unwrap();
        let (queued, lease): (String, String) = conn
            .query_row(
                "SELECT queued_at, lease_expires_at FROM pending_commands WHERE command_id = ?1",
                params![cmd],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        let lease_secs = (parse_iso_datetime(&lease).unwrap()
            - parse_iso_datetime(&queued).unwrap())
        .num_seconds();
        assert!((299..=301).contains(&lease_secs), "{lease_secs}");
        assert_eq!(reap_expired_commands(&conn).unwrap(), 0);
        assert_eq!(command_ids(&conn), BTreeSet::from([cmd]));
    }

    /// Commands reach only the node they were queued for, and each is
    /// handed out once: a second poll does not replay it.
    #[test]
    fn pending_commands_are_delivered_once_and_only_to_their_node() {
        let dir = tempfile::tempdir().unwrap();
        let conn = conn_with_tables(&dir);
        let a1 = queue_command(&conn, "node-a", "retune", r#"{"hz":433000000}"#).unwrap();
        let a2 = queue_command(&conn, "node-a", "reboot", "{}").unwrap();
        let b1 = queue_command(&conn, "node-b", "reboot", "{}").unwrap();
        assert_ne!(a1, a2, "command ids are unique");

        let first = get_pending_commands(&conn, "node-a").unwrap();
        let ids: BTreeSet<String> = first.iter().map(|c| c.command_id.clone()).collect();
        assert_eq!(ids, BTreeSet::from([a1.clone(), a2.clone()]));
        assert!(first.iter().all(|c| c.node_id == "node-a"));
        let retune = first.iter().find(|c| c.command_id == a1).unwrap();
        assert_eq!(retune.params, r#"{"hz":433000000}"#);

        assert!(
            get_pending_commands(&conn, "node-a").unwrap().is_empty(),
            "dispatched commands are not delivered again"
        );
        let dispatched: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pending_commands \
                 WHERE node_id = 'node-a' AND status = 'dispatched' AND dispatched_at IS NOT NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(dispatched, 2);

        let b = get_pending_commands(&conn, "node-b").unwrap();
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].command_id, b1);
        assert!(get_pending_commands(&conn, "node-c").unwrap().is_empty());
    }

    #[test]
    fn nodes_are_visible_and_deletable_only_within_their_tenant() {
        let dir = tempfile::tempdir().unwrap();
        let conn = conn_with_tables(&dir);
        register_node(&conn, "node-a", "10.0.0.1", 9000, "{}", "t1").unwrap();
        register_node(&conn, "node-b", "10.0.0.2", 9000, "{}", "t2").unwrap();

        let t1: Vec<String> = list_nodes(&conn, "t1")
            .unwrap()
            .into_iter()
            .map(|n| n.node_id)
            .collect();
        assert_eq!(t1, ["node-a"]);
        assert!(get_node(&conn, "node-a", "t2").unwrap().is_none());
        assert!(!delete_node(&conn, "node-a", "t2").unwrap());
        assert!(
            get_node(&conn, "node-a", "t1").unwrap().is_some(),
            "a wrong-tenant delete removes nothing"
        );

        assert!(delete_node(&conn, "node-a", "t1").unwrap());
        assert!(get_node(&conn, "node-a", "t1").unwrap().is_none());
        assert!(get_node(&conn, "node-b", "t2").unwrap().is_some());
    }

    /// Deleting a node drops its queued commands (they must not reach a
    /// node later registered under the same id), and only its own.
    #[test]
    fn deleting_a_node_drops_its_commands_only() {
        let dir = tempfile::tempdir().unwrap();
        let conn = conn_with_tables(&dir);
        register_node(&conn, "node-a", "10.0.0.1", 9000, "{}", "default").unwrap();
        register_node(&conn, "node-b", "10.0.0.2", 9000, "{}", "default").unwrap();
        queue_command(&conn, "node-a", "reboot", "{}").unwrap();
        let kept = queue_command(&conn, "node-b", "reboot", "{}").unwrap();

        assert!(delete_node(&conn, "node-a", "default").unwrap());
        assert_eq!(command_ids(&conn), BTreeSet::from([kept]));
        register_node(&conn, "node-a", "10.0.0.9", 9000, "{}", "default").unwrap();
        assert!(get_pending_commands(&conn, "node-a").unwrap().is_empty());
    }

    /// A delete refused for the wrong tenant must have no side effects on
    /// the owning tenant's node — including its queued commands.
    #[test]
    fn wrong_tenant_delete_keeps_the_nodes_commands() {
        let dir = tempfile::tempdir().unwrap();
        let conn = conn_with_tables(&dir);
        register_node(&conn, "node-a", "10.0.0.1", 9000, "{}", "t1").unwrap();
        let cmd = queue_command(&conn, "node-a", "retune", "{}").unwrap();

        assert!(!delete_node(&conn, "node-a", "t2").unwrap());
        assert_eq!(
            command_ids(&conn),
            BTreeSet::from([cmd]),
            "another tenant's queued command was deleted"
        );
    }

    /// A delete that finds no node (an id nobody registered) has no side
    /// effects either: commands queued for that id stay until their lease
    /// runs out, and the connection is left outside any transaction.
    #[test]
    fn deleting_an_unregistered_node_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let conn = conn_with_tables(&dir);
        register_node(&conn, "node-a", "10.0.0.1", 9000, "{}", "default").unwrap();
        let stray = queue_command(&conn, "ghost", "retune", "{}").unwrap();
        let kept = queue_command(&conn, "node-a", "retune", "{}").unwrap();

        assert!(!delete_node(&conn, "ghost", "default").unwrap());
        assert!(conn.is_autocommit());
        assert_eq!(command_ids(&conn), BTreeSet::from([stray, kept]));
        assert!(get_node(&conn, "node-a", "default").unwrap().is_some());

        assert!(delete_node(&conn, "node-a", "default").unwrap());
        assert!(conn.is_autocommit(), "the delete is committed");
    }

    /// Fails every delete from pending_commands, standing in for an I/O or
    /// lock error between delete_node's two statements.
    fn fail_command_deletes(conn: &Conn) {
        conn.execute_batch(
            "CREATE TRIGGER fail_command_delete BEFORE DELETE ON pending_commands
             BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
        )
        .unwrap();
    }

    /// If the command cleanup fails, the node delete is rolled back too: a
    /// node gone with its commands still queued would hand them to the next
    /// node registered under the same id.
    #[test]
    fn a_failed_command_cleanup_keeps_the_node() {
        let dir = tempfile::tempdir().unwrap();
        let conn = conn_with_tables(&dir);
        register_node(&conn, "node-a", "10.0.0.1", 9000, "{}", "default").unwrap();
        let cmd = queue_command(&conn, "node-a", "retune", "{}").unwrap();
        fail_command_deletes(&conn);

        assert!(delete_node(&conn, "node-a", "default").is_err());
        assert!(conn.is_autocommit(), "the failed transaction is closed");
        assert!(get_node(&conn, "node-a", "default").unwrap().is_some());
        assert_eq!(command_ids(&conn), BTreeSet::from([cmd]));
    }

    /// Inside a transaction the caller holds, delete_node joins it: the
    /// caller's commit or rollback decides for the node and its commands
    /// alike, and a failed delete undoes only its own changes.
    #[test]
    fn delete_node_runs_inside_a_callers_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let conn = conn_with_tables(&dir);
        register_node(&conn, "node-a", "10.0.0.1", 9000, "{}", "default").unwrap();
        register_node(&conn, "node-b", "10.0.0.2", 9000, "{}", "default").unwrap();
        let a_cmd = queue_command(&conn, "node-a", "retune", "{}").unwrap();
        let b_cmd = queue_command(&conn, "node-b", "retune", "{}").unwrap();

        let outer = conn.unchecked_transaction().unwrap();
        assert!(delete_node(&conn, "node-a", "default").unwrap());
        assert!(
            !conn.is_autocommit(),
            "the caller still owns its transaction"
        );
        assert!(get_node(&conn, "node-a", "default").unwrap().is_none());
        drop(outer);
        assert!(get_node(&conn, "node-a", "default").unwrap().is_some());
        assert_eq!(
            command_ids(&conn),
            BTreeSet::from([a_cmd.clone(), b_cmd.clone()]),
            "the caller's rollback restores the commands with the node"
        );

        let outer = conn.unchecked_transaction().unwrap();
        assert!(delete_node(&conn, "node-a", "default").unwrap());
        outer.commit().unwrap();
        assert!(get_node(&conn, "node-a", "default").unwrap().is_none());
        assert_eq!(command_ids(&conn), BTreeSet::from([b_cmd.clone()]));

        fail_command_deletes(&conn);
        let outer = conn.unchecked_transaction().unwrap();
        let earlier = queue_command(&conn, "node-b", "reboot", "{}").unwrap();
        assert!(delete_node(&conn, "node-b", "default").is_err());
        assert!(
            !conn.is_autocommit(),
            "the caller still owns its transaction"
        );
        assert!(
            get_node(&conn, "node-b", "default").unwrap().is_some(),
            "the failed delete is undone"
        );
        outer.commit().unwrap();
        assert_eq!(
            command_ids(&conn),
            BTreeSet::from([b_cmd, earlier]),
            "the caller's own earlier write survives"
        );
    }

    /// At top level write_tx holds the write lock before its body runs, so
    /// no other connection can commit between the body's first read and
    /// its first write. A deferred transaction would let one in, and in WAL
    /// mode the body's write would then fail with SQLITE_BUSY_SNAPSHOT,
    /// which the busy timeout does not retry.
    #[test]
    fn write_tx_holds_the_write_lock_before_its_body_runs() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        ensure_node_tables(&conn).unwrap();
        let other = state.db_pool.get().unwrap();
        other.busy_timeout(std::time::Duration::ZERO).unwrap();

        let raced = write_tx(&conn, |tx| {
            tx.query_row("SELECT COUNT(*) FROM nodes", [], |r| r.get::<_, i64>(0))?;
            let raced = queue_command(&other, "node-b", "retune", "{}");
            tx.execute("DELETE FROM pending_commands WHERE node_id = 'node-a'", [])?;
            Ok(raced)
        })
        .expect("the body's write after its read succeeds");
        assert!(
            matches!(
                &raced,
                Err(rusqlite::Error::SqliteFailure(e, _))
                    if e.code == rusqlite::ErrorCode::DatabaseBusy
            ),
            "another connection wrote inside write_tx: {raced:?}"
        );
        assert!(conn.is_autocommit());
        assert!(command_ids(&conn).is_empty());
        queue_command(&other, "node-b", "retune", "{}").expect("the commit releases the lock");
    }

    #[test]
    fn heartbeat_updates_only_a_registered_node() {
        let dir = tempfile::tempdir().unwrap();
        let conn = conn_with_tables(&dir);
        assert!(!update_heartbeat(&conn, "ghost", 1.0, 2.0, 3.0, 4.0).unwrap());
        assert!(list_nodes(&conn, "default").unwrap().is_empty());

        register_node(
            &conn,
            "node-a",
            "10.0.0.1",
            9000,
            r#"{"sdr":true}"#,
            "default",
        )
        .unwrap();
        conn.execute(
            "UPDATE nodes SET last_seen = ?1 WHERE node_id = 'node-a'",
            params![iso_ago(3600)],
        )
        .unwrap();
        assert_eq!(
            get_node(&conn, "node-a", "default")
                .unwrap()
                .unwrap()
                .status,
            "offline"
        );
        assert!(update_heartbeat(&conn, "node-a", 12.5, 256.0, 40.0, 433.92e6).unwrap());
        let node = get_node(&conn, "node-a", "default").unwrap().unwrap();
        assert_eq!(node.status, "online", "a heartbeat brings it back online");
        assert_eq!(node.cpu_percent, 12.5);
        assert_eq!(node.memory_mb, 256.0);
        assert_eq!(node.classifications_per_sec, 40.0);
        assert_eq!(node.current_frequency_hz, 433.92e6);
        assert_eq!(node.capabilities, r#"{"sdr":true}"#);
    }

    #[test]
    fn reregistration_updates_the_node_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let conn = conn_with_tables(&dir);
        register_node(&conn, "node-a", "10.0.0.1", 9000, "{}", "default").unwrap();
        conn.execute(
            "UPDATE nodes SET registered_at = '2026-01-01T00:00:00+00:00'",
            [],
        )
        .unwrap();
        register_node(&conn, "node-a", "10.0.0.7", 9100, r#"{"v":2}"#, "default").unwrap();

        let nodes = list_nodes(&conn, "default").unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].host, "10.0.0.7");
        assert_eq!(nodes[0].port, 9100);
        assert_eq!(nodes[0].capabilities, r#"{"v":2}"#);
        assert_eq!(nodes[0].registered_at, "2026-01-01T00:00:00+00:00");
        assert_eq!(nodes[0].status, "online");
    }

    /// Re-registering a node id that another tenant owns must not move the
    /// node into the caller's tenant: that would hand the caller the node's
    /// record and, since commands are keyed by node id alone, its queued
    /// commands. The registration is refused and the owner's node is left
    /// as it was.
    #[test]
    fn tenant_boundary_reregistration_cannot_move_a_node_to_another_tenant() {
        let dir = tempfile::tempdir().unwrap();
        let conn = conn_with_tables(&dir);
        register_node(&conn, "node-a", "10.0.0.1", 9000, r#"{"sdr":true}"#, "t1").unwrap();
        let cmd = queue_command(&conn, "node-a", "retune", "{}").unwrap();

        let hijack = register_node(&conn, "node-a", "203.0.113.66", 9999, "{}", "t2");
        assert!(
            !matches!(hijack, Ok(true)),
            "a foreign tenant's registration is reported as success"
        );
        let owned = get_node(&conn, "node-a", "t1")
            .unwrap()
            .expect("the node still belongs to t1");
        assert_eq!(owned.host, "10.0.0.1");
        assert_eq!(owned.port, 9000);
        assert_eq!(owned.capabilities, r#"{"sdr":true}"#);
        assert!(get_node(&conn, "node-a", "t2").unwrap().is_none());
        assert!(list_nodes(&conn, "t2").unwrap().is_empty());
        assert_eq!(command_ids(&conn), BTreeSet::from([cmd]));
    }

    /// Every column of a node's row, for before/after comparisons.
    fn node_row(conn: &Conn, node_id: &str) -> Vec<rusqlite::types::Value> {
        let mut stmt = conn
            .prepare("SELECT * FROM nodes WHERE node_id = ?1")
            .unwrap();
        let width = stmt.column_count();
        stmt.query_row(params![node_id], |r| {
            (0..width).map(|i| r.get(i)).collect::<Result<_, _>>()
        })
        .unwrap()
    }

    /// A refused registration writes nothing at all: not last_seen (which
    /// would mark a stale node online), registered_at or the heartbeat
    /// metrics either. The default tenant gets no exemption in either
    /// direction, and tenant ids must match exactly: a tenant whose id
    /// differs only in case, extends or shortens the owner's, adds a
    /// trailing space or matches it as a LIKE pattern is another tenant.
    #[test]
    fn a_refused_registration_changes_no_column() {
        let dir = tempfile::tempdir().unwrap();
        let conn = conn_with_tables(&dir);
        for (owner, other) in [
            ("t1", "t2"),
            ("default", "t1"),
            ("t1", "default"),
            ("t1", "T1"),
            ("T1", "t1"),
            ("t1", "t10"),
            ("t10", "t1"),
            ("t1", "t1 "),
            ("t_", "t1"),
        ] {
            let node = format!("node-{owner}");
            assert!(
                register_node(&conn, &node, "10.0.0.1", 9000, r#"{"sdr":true}"#, owner).unwrap()
            );
            assert!(update_heartbeat(&conn, &node, 12.5, 256.0, 40.0, 433.92e6).unwrap());
            conn.execute(
                "UPDATE nodes SET last_seen = ?1, registered_at = '2026-01-01T00:00:00+00:00',
                                  latitude = 1.5, location_name = 'roof'
                 WHERE node_id = ?2",
                params![iso_ago(3600), node],
            )
            .unwrap();
            let before = node_row(&conn, &node);

            for (host, port, caps) in [
                ("203.0.113.66", 9999, "{}"),
                ("10.0.0.1", 9000, r#"{"sdr":true}"#),
            ] {
                assert!(
                    !register_node(&conn, &node, host, port, caps, other).unwrap(),
                    "{other:?} took over {owner:?}'s node with {host}:{port}"
                );
                assert_eq!(
                    node_row(&conn, &node),
                    before,
                    "{other:?} changed {owner:?}'s node"
                );
            }
            assert!(get_node(&conn, &node, other).unwrap().is_none());
            assert_eq!(
                get_node(&conn, &node, owner).unwrap().unwrap().status,
                "offline",
                "a refused registration does not refresh the owner's node"
            );
            conn.execute("DELETE FROM nodes", []).unwrap();
        }
    }

    /// The owning tenant's registrations report success: the first one,
    /// one that changes the record and one that repeats it unchanged (which
    /// still refreshes last_seen).
    #[test]
    fn the_owners_registrations_report_success() {
        let dir = tempfile::tempdir().unwrap();
        let conn = conn_with_tables(&dir);
        assert!(register_node(&conn, "node-a", "10.0.0.1", 9000, "{}", "t1").unwrap());
        assert!(register_node(&conn, "node-a", "10.0.0.7", 9100, r#"{"v":2}"#, "t1").unwrap());

        conn.execute(
            "UPDATE nodes SET last_seen = ?1 WHERE node_id = 'node-a'",
            params![iso_ago(3600)],
        )
        .unwrap();
        assert!(register_node(&conn, "node-a", "10.0.0.7", 9100, r#"{"v":2}"#, "t1").unwrap());
        let node = get_node(&conn, "node-a", "t1").unwrap().unwrap();
        assert_eq!(
            node.status, "online",
            "an identical re-registration refreshes last_seen"
        );
        assert_eq!((node.host.as_str(), node.port), ("10.0.0.7", 9100));
        assert_eq!(node.capabilities, r#"{"v":2}"#);
        assert_eq!(list_nodes(&conn, "t1").unwrap().len(), 1);
    }

    /// A node id changes tenant only after its owner deletes the node, and
    /// the new owner then starts without the old owner's queued commands.
    #[test]
    fn a_node_id_moves_tenant_only_after_its_owner_deletes_it() {
        let dir = tempfile::tempdir().unwrap();
        let conn = conn_with_tables(&dir);
        assert!(register_node(&conn, "node-a", "10.0.0.1", 9000, "{}", "t1").unwrap());
        queue_command(&conn, "node-a", "retune", "{}").unwrap();
        assert!(!register_node(&conn, "node-a", "10.0.0.2", 9000, "{}", "t2").unwrap());

        assert!(delete_node(&conn, "node-a", "t1").unwrap());
        assert!(register_node(&conn, "node-a", "10.0.0.2", 9000, "{}", "t2").unwrap());
        let moved = get_node(&conn, "node-a", "t2").unwrap().unwrap();
        assert_eq!(moved.host, "10.0.0.2");
        assert!(get_node(&conn, "node-a", "t1").unwrap().is_none());
        assert!(get_pending_commands(&conn, "node-a").unwrap().is_empty());
        assert!(
            !register_node(&conn, "node-a", "10.0.0.1", 9000, "{}", "t1").unwrap(),
            "the former owner cannot take it back"
        );
    }

    #[test]
    fn status_follows_last_seen_age() {
        assert_eq!(compute_status(Some(&iso_ago(5))), "online");
        assert_eq!(compute_status(Some(&iso_ago(120))), "degraded");
        assert_eq!(compute_status(Some(&iso_ago(600))), "offline");
        assert_eq!(compute_status(Some("2020-01-01T00:00:00")), "offline");
        assert_eq!(compute_status(Some("2020-01-01T00:00:00.5")), "offline");
        assert_eq!(compute_status(Some("not a timestamp")), "offline");
        assert_eq!(compute_status(None), "offline");
    }
}
