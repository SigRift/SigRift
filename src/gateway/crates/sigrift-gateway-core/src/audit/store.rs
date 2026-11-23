//! Audit log DB operations — log, query, verify, archive, purge, export,
//! severity.
//!
//! All entries are chained via HMAC-SHA256 for tamper detection. The chain
//! is scoped per tenant and shared with the bridge, which appends to the
//! same `audit_log` table (`sigrift/bridge/storage/audit.py`): every entry's
//! HMAC covers the HMAC of the tenant's previous entry.
//!
//! * **Records**: new entries are written as v3 ([`chain::compute_hmac_v3`],
//!   which also covers `target_ids` and `tenant_id`); [`verify_chain`]
//!   accepts each row's v3, v2 or v1 HMAC, since no version is stored and
//!   older rows are never rewritten. Both writers sign every entry, so a
//!   row without an HMAC is accepted only before the chain's first signed
//!   row (a row written before the chain existed); after it, one is
//!   reported, as on the bridge.
//! * **Writes** take the SQLite write lock up front (`BEGIN IMMEDIATE`), so
//!   reading the previous HMAC and inserting the new row are atomic with
//!   respect to every other writer, gateway or bridge. A busy database is
//!   retried a bounded number of times; a final failure is logged at
//!   `error` (callers that ignore the `Result` no longer lose events
//!   silently). Every entry written is also published to the `/ws/audit`
//!   feed ([`set_event_sink`]).
//! * **Archiving** moves the oldest *contiguous* prefix of a tenant's chain
//!   into `audit_log_archive` and records an **archive anchor** in
//!   `audit_anchor`: the id and HMAC of the last archived row, sealed with
//!   its own HMAC. [`verify_chain`] starts from the anchor, so the chain
//!   stays verifiable after an archive, while a removed or edited anchor,
//!   or a removed row after it, is reported. The archive also appends an
//!   `archive_marker` entry whose details carry `terminal_hmac`, which is
//!   what the bridge's own verifier uses to bridge an archived prefix.
//!   A prefix that fails verification is never archived (that would hide
//!   the tampering behind a fresh anchor).
//! * **Retention**: rows younger than the minimum retention
//!   ([`min_retention_days`], `UC_AUDIT_MIN_RETENTION_DAYS`, default 7) can
//!   be neither archived nor purged, purging only ever deletes archived
//!   rows at or before the anchor, and archive and purge are themselves
//!   audit entries.

use std::sync::{OnceLock, RwLock};
use std::time::{Duration, Instant};

use rusqlite::types::Value;
use rusqlite::{
    params, params_from_iter, Connection, ErrorCode, OptionalExtension, Transaction,
    TransactionBehavior,
};
use serde::Serialize;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

use super::chain::{self, LEGACY_NO_HMAC_SENTINEL};

// ── Severity classification ───────────────────────────────────────────

/// Auto-classify action severity for audit entries.
pub fn classify_severity(action: &str) -> &'static str {
    match action {
        "auth_failure"
        | "mfa_disable"
        | "admin_disable_mfa"
        | "password_change"
        | "password_reset"
        | "master_key_rotated"
        | "security_settings_changed"
        | "archive_marker"
        | "audit_archive"
        | "audit_purge" => "warning",
        _ => "info",
    }
}

// ── Retention ─────────────────────────────────────────────────────────

/// Default for `UC_AUDIT_MIN_RETENTION_DAYS`.
pub const DEFAULT_MIN_RETENTION_DAYS: u32 = 7;

/// Minimum age in days of audit rows that may be archived or purged:
/// `UC_AUDIT_MIN_RETENTION_DAYS` (default 7; 0 is raised to 1, so no
/// request can empty the log of the current day).
pub fn min_retention_days() -> u32 {
    static DAYS: OnceLock<u32> = OnceLock::new();
    *DAYS.get_or_init(|| {
        parse_min_retention(std::env::var("UC_AUDIT_MIN_RETENTION_DAYS").ok().as_deref())
    })
}

fn parse_min_retention(raw: Option<&str>) -> u32 {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return DEFAULT_MIN_RETENTION_DAYS;
    };
    match raw.parse::<u32>() {
        Ok(0) => {
            warn!("UC_AUDIT_MIN_RETENTION_DAYS=0 is not allowed — using 1");
            1
        }
        Ok(days) => days,
        Err(_) => {
            warn!(
                value = raw,
                default = DEFAULT_MIN_RETENTION_DAYS,
                "UC_AUDIT_MIN_RETENTION_DAYS is not a number of days — using the default"
            );
            DEFAULT_MIN_RETENTION_DAYS
        }
    }
}

// ── Event sink (/ws/audit) ────────────────────────────────────────────

static EVENT_SINK: RwLock<Option<broadcast::Sender<String>>> = RwLock::new(None);

/// Publish every audit entry the gateway writes, as JSON, to `tx` — the
/// channel behind `/ws/audit`. Called once at startup; a later call
/// replaces the sink.
pub fn set_event_sink(tx: broadcast::Sender<String>) {
    *EVENT_SINK.write().unwrap_or_else(|e| e.into_inner()) = Some(tx);
}

fn publish(entry: &AuditEntry) {
    let sink = EVENT_SINK.read().unwrap_or_else(|e| e.into_inner());
    if let Some(tx) = sink.as_ref() {
        if tx.receiver_count() > 0 {
            if let Ok(json) = serde_json::to_string(entry) {
                let _ = tx.send(json);
            }
        }
    }
}

// ── Write transactions ────────────────────────────────────────────────

/// Attempts at a write transaction before giving up on a busy database.
const WRITE_ATTEMPTS: u32 = 5;
/// No retry is started once this much time has gone by (the connection's
/// own `busy_timeout` already waited inside the failed attempt).
const WRITE_RETRY_BUDGET: Duration = Duration::from_secs(2);

fn is_busy(e: &rusqlite::Error) -> bool {
    matches!(
        e,
        rusqlite::Error::SqliteFailure(f, _)
            if matches!(f.code, ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
    )
}

/// Run `f` in a write transaction and commit.
///
/// At top level this is `BEGIN IMMEDIATE`: the write lock is held before
/// `f` reads anything, so a read-then-insert cannot interleave with another
/// writer (a `DEFERRED` transaction would read a snapshot and then fail
/// with `SQLITE_BUSY` when upgrading to write after a concurrent commit).
/// A busy database is retried with backoff. Inside a transaction the caller
/// already opened, `f` runs in a savepoint instead.
fn write_tx<T>(
    conn: &Connection,
    mut f: impl FnMut(&Connection) -> rusqlite::Result<T>,
) -> rusqlite::Result<T> {
    if !conn.is_autocommit() {
        conn.execute_batch("SAVEPOINT sigrift_audit")?;
        return match f(conn) {
            Ok(value) => {
                conn.execute_batch("RELEASE sigrift_audit")?;
                Ok(value)
            }
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK TO sigrift_audit; RELEASE sigrift_audit");
                Err(e)
            }
        };
    }
    let started = Instant::now();
    let mut attempt = 1;
    loop {
        let result =
            Transaction::new_unchecked(conn, TransactionBehavior::Immediate).and_then(|tx| {
                let value = f(&tx)?;
                tx.commit()?;
                Ok(value)
            });
        match result {
            Err(e)
                if is_busy(&e)
                    && attempt < WRITE_ATTEMPTS
                    && started.elapsed() < WRITE_RETRY_BUDGET =>
            {
                warn!(attempt, error = %e, "Audit database busy — retrying the write");
                std::thread::sleep(Duration::from_millis(25 << attempt));
                attempt += 1;
            }
            other => return other,
        }
    }
}

// ── Core write ────────────────────────────────────────────────────────

fn utc_now_iso() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S+00:00")
        .to_string()
}

/// Merge `"severity"` into a details JSON object (string form, as stored).
fn with_severity(details_json: &str, severity: &str) -> String {
    if details_json.is_empty() || details_json == "{}" {
        format!("{{\"severity\":\"{}\"}}", severity)
    } else if let Some(rest) = details_json.strip_prefix('{') {
        format!("{{\"severity\":\"{}\",{}", severity, rest)
    } else {
        format!("{{\"severity\":\"{}\"}}", severity)
    }
}

/// One entry to append to the chain. `details` and `target_ids` are the
/// stored strings (`target_ids` is a JSON list, or `""` like the bridge
/// writes for a non-bulk entry).
struct NewEntry<'a> {
    action: &'a str,
    target_id: &'a str,
    target_ids: &'a str,
    operator: &'a str,
    note: &'a str,
    details: String,
    signal_class: &'a str,
    freq_hz: f64,
    node_id: &'a str,
    tenant_id: &'a str,
}

/// The HMAC the next entry of `tenant_id` chains from: the newest row's
/// HMAC (the legacy sentinel for a row without one, as the bridge does);
/// with no live row, the archive anchor's terminal HMAC; else `""`.
fn chain_head(conn: &Connection, tenant_id: &str) -> rusqlite::Result<String> {
    let newest: Option<Option<String>> = conn
        .query_row(
            "SELECT hmac_chain FROM audit_log WHERE tenant_id = ?1 ORDER BY id DESC LIMIT 1",
            params![tenant_id],
            |row| row.get(0),
        )
        .optional()?;
    Ok(match newest {
        Some(Some(h)) if !h.is_empty() => h,
        Some(_) => LEGACY_NO_HMAC_SENTINEL.to_string(),
        None => load_anchor(conn, tenant_id)?
            .map(|a| a.terminal_hmac)
            .unwrap_or_default(),
    })
}

/// Append `entry` to the chain at `timestamp`. Caller holds the write lock.
fn append_entry_at(
    conn: &Connection,
    secret: &[u8],
    entry: &NewEntry,
    timestamp: &str,
) -> rusqlite::Result<AuditEntry> {
    let previous_hmac = chain_head(conn, entry.tenant_id)?;
    let freq_str = chain::python_float_str(entry.freq_hz);
    let hmac = chain::compute_hmac_v3(
        secret,
        &previous_hmac,
        entry.action,
        entry.target_id,
        entry.operator,
        timestamp,
        &entry.details,
        entry.note,
        entry.signal_class,
        &freq_str,
        entry.node_id,
        entry.target_ids,
        entry.tenant_id,
    );
    conn.execute(
        "INSERT INTO audit_log (timestamp, action, target_id, target_ids, operator, note, \
                                details, signal_class, freq_hz, node_id, tenant_id, \
                                hmac_chain) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            timestamp,
            entry.action,
            entry.target_id,
            entry.target_ids,
            entry.operator,
            entry.note,
            entry.details,
            entry.signal_class,
            entry.freq_hz,
            entry.node_id,
            entry.tenant_id,
            hmac
        ],
    )?;
    Ok(AuditEntry {
        id: conn.last_insert_rowid(),
        timestamp: timestamp.to_string(),
        action: entry.action.to_string(),
        target_id: entry.target_id.to_string(),
        operator: entry.operator.to_string(),
        note: entry.note.to_string(),
        details: parse_details(&entry.details),
        signal_class: entry.signal_class.to_string(),
        freq_hz: entry.freq_hz,
        node_id: entry.node_id.to_string(),
        tenant_id: entry.tenant_id.to_string(),
        hmac_chain: hmac,
    })
}

fn append_entry(
    conn: &Connection,
    secret: &[u8],
    entry: &NewEntry,
) -> rusqlite::Result<AuditEntry> {
    append_entry_at(conn, secret, entry, &utc_now_iso())
}

/// Log an audit entry with HMAC chain.
///
/// The previous-HMAC read and the insert run in one `BEGIN IMMEDIATE`
/// transaction (retried while the database is busy). A failure is logged
/// here as well as returned, so a caller that ignores the result does not
/// lose the event silently.
#[allow(clippy::too_many_arguments)]
pub fn log_audit(
    conn: &Connection,
    secret: &[u8],
    action: &str,
    target_id: &str,
    operator: &str,
    note: &str,
    details_json: &str,
    signal_class: &str,
    freq_hz: f64,
    node_id: &str,
    tenant_id: &str,
) -> Result<i64, rusqlite::Error> {
    let entry = NewEntry {
        action,
        target_id,
        target_ids: "",
        operator,
        note,
        details: with_severity(details_json, classify_severity(action)),
        signal_class,
        freq_hz,
        node_id,
        tenant_id,
    };
    match write_tx(conn, |tx| append_entry(tx, secret, &entry)) {
        Ok(saved) => {
            debug!(
                id = saved.id,
                action, target_id, tenant_id, "Audit entry logged"
            );
            publish(&saved);
            Ok(saved.id)
        }
        Err(e) => {
            error!(
                error = %e,
                action,
                target_id,
                tenant_id,
                "Audit entry could not be written — this event is NOT in the audit log"
            );
            Err(e)
        }
    }
}

/// Convenience wrapper for auth events (common fields pre-filled).
pub fn log_auth_event(
    conn: &Connection,
    secret: &[u8],
    action: &str,
    target_id: &str,
    operator: &str,
    client_ip: &str,
    tenant_id: &str,
) -> Result<i64, rusqlite::Error> {
    let note = if client_ip.is_empty() || client_ip == "unknown" {
        String::new()
    } else {
        format!("From {}", client_ip)
    };
    log_audit(
        conn, secret, action, target_id, operator, &note, "", "", 0.0, "", tenant_id,
    )
}

// ── Read/Query ────────────────────────────────────────────────────────

/// Audit log entry for API responses.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    pub id: i64,
    pub timestamp: String,
    pub action: String,
    pub target_id: String,
    pub operator: String,
    pub note: String,
    pub details: serde_json::Value,
    pub signal_class: String,
    pub freq_hz: f64,
    pub node_id: String,
    pub tenant_id: String,
    pub hmac_chain: String,
}

fn parse_details(details: &str) -> serde_json::Value {
    serde_json::from_str(details).unwrap_or(serde_json::Value::Object(serde_json::Map::new()))
}

fn entry_from_row(row: &rusqlite::Row) -> rusqlite::Result<AuditEntry> {
    let details_str: String = row.get::<_, Option<String>>(6)?.unwrap_or_default();
    Ok(AuditEntry {
        id: row.get(0)?,
        timestamp: row.get(1)?,
        action: row.get(2)?,
        target_id: row.get::<_, Option<String>>(3)?.unwrap_or_default(),
        operator: row.get::<_, Option<String>>(4)?.unwrap_or_default(),
        note: row.get::<_, Option<String>>(5)?.unwrap_or_default(),
        details: parse_details(&details_str),
        signal_class: row.get::<_, Option<String>>(7)?.unwrap_or_default(),
        freq_hz: row.get::<_, Option<f64>>(8)?.unwrap_or(0.0),
        node_id: row.get::<_, Option<String>>(9)?.unwrap_or_default(),
        tenant_id: row.get(10)?,
        hmac_chain: row.get::<_, Option<String>>(11)?.unwrap_or_default(),
    })
}

/// The severity a row's details JSON object records, or NULL. Entries the
/// bridge logs without details store `''` (and older or tampered rows may
/// hold NULL or invalid JSON), which `json_extract` rejects as malformed,
/// failing the whole query, so only valid JSON is read. `CASE` evaluates
/// lazily; `AND`/`OR` are not guaranteed to short-circuit. Identical to the
/// bridge's `_DETAILS_SEVERITY` (sigrift/bridge/storage/audit.py).
const DETAILS_SEVERITY: &str =
    "(CASE WHEN json_valid(details) THEN json_extract(details, '$.severity') END)";

/// The filters of `GET /api/admin/audit`; `None` filters nothing.
///
/// The listing ([`get_audit_log`]) and its total ([`count_audit_log`]) are
/// built from the same [`AuditFilter::where_clause`], so the total always
/// counts exactly the entries the listing pages through, as on the bridge
/// (`get_audit_log` and `count_audit_log` in sigrift/bridge/storage/audit.py).
#[derive(Debug, Default, Clone, Copy)]
pub struct AuditFilter<'a> {
    pub action: Option<&'a str>,
    pub target_id: Option<&'a str>,
    pub operator: Option<&'a str>,
    pub node_id: Option<&'a str>,
    /// Substring of the note, the target id or the action, matched
    /// literally (`%`, `_` and `\` are not wildcards).
    pub search: Option<&'a str>,
    /// Inclusive lower bound on the timestamp.
    pub start: Option<&'a str>,
    /// Inclusive upper bound on the timestamp.
    pub end: Option<&'a str>,
    /// `info` also matches entries that record no severity (no details, no
    /// `severity` key, or details that are not valid JSON); any other
    /// severity is an exact match.
    pub severity: Option<&'a str>,
}

impl AuditFilter<'_> {
    /// The `WHERE` condition selecting `tenant_id`'s entries that pass
    /// every filter, with its parameters in placeholder order. Every value
    /// is bound (`?`), never spliced into the SQL.
    fn where_clause(&self, tenant_id: &str) -> (String, Vec<Value>) {
        let mut clauses = vec!["tenant_id = ?".to_string()];
        let mut values = vec![Value::Text(tenant_id.to_string())];
        let exact = [
            ("action", self.action),
            ("target_id", self.target_id),
            ("operator", self.operator),
            ("node_id", self.node_id),
        ];
        for (column, value) in exact {
            if let Some(v) = value {
                clauses.push(format!("{column} = ?"));
                values.push(Value::Text(v.to_string()));
            }
        }
        if let Some(s) = self.search {
            // A literal substring, as on the bridge: `\`, `%` and `_` in the
            // term are escaped, so they match only themselves.
            let escaped = s
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_");
            clauses.push(
                "(note LIKE ? ESCAPE '\\' OR target_id LIKE ? ESCAPE '\\' \
                 OR action LIKE ? ESCAPE '\\')"
                    .to_string(),
            );
            let pattern = format!("%{escaped}%");
            for _ in 0..3 {
                values.push(Value::Text(pattern.clone()));
            }
        }
        if let Some(s) = self.start {
            clauses.push("timestamp >= ?".to_string());
            values.push(Value::Text(s.to_string()));
        }
        if let Some(e) = self.end {
            clauses.push("timestamp <= ?".to_string());
            values.push(Value::Text(e.to_string()));
        }
        if let Some(sev) = self.severity {
            if sev == "info" {
                // Entries without a severity count as info, as on the bridge.
                clauses.push(format!(
                    "({DETAILS_SEVERITY} IS NULL OR {DETAILS_SEVERITY} = 'info')"
                ));
            } else {
                clauses.push(format!("{DETAILS_SEVERITY} = ?"));
                values.push(Value::Text(sev.to_string()));
            }
        }
        (clauses.join(" AND "), values)
    }
}

/// One page of `tenant_id`'s audit entries passing `filter`, newest first.
pub fn get_audit_log(
    conn: &Connection,
    tenant_id: &str,
    filter: &AuditFilter,
    limit: i64,
    offset: i64,
) -> Result<Vec<AuditEntry>, rusqlite::Error> {
    let (condition, mut values) = filter.where_clause(tenant_id);
    let sql = format!(
        "SELECT id, timestamp, action, target_id, operator, note, details, \
                signal_class, freq_hz, node_id, tenant_id, hmac_chain \
         FROM audit_log WHERE {condition} ORDER BY id DESC LIMIT ? OFFSET ?"
    );
    values.push(Value::Integer(limit));
    values.push(Value::Integer(offset));
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params_from_iter(values), entry_from_row)?;
    rows.collect()
}

/// The number of `tenant_id`'s audit entries passing `filter`: the entries
/// [`get_audit_log`] pages through with the same filter.
pub fn count_audit_log(
    conn: &Connection,
    tenant_id: &str,
    filter: &AuditFilter,
) -> Result<i64, rusqlite::Error> {
    let (condition, values) = filter.where_clause(tenant_id);
    conn.query_row(
        &format!("SELECT COUNT(*) FROM audit_log WHERE {condition}"),
        params_from_iter(values),
        |row| row.get(0),
    )
}

/// One page of the audit log ([`get_audit_log`]) and the number of entries
/// `filter` selects over all pages ([`count_audit_log`]), both read from the
/// same snapshot of the database, so an entry written in between cannot
/// make the two disagree.
pub fn get_audit_page(
    conn: &Connection,
    tenant_id: &str,
    filter: &AuditFilter,
    limit: i64,
    offset: i64,
) -> Result<(Vec<AuditEntry>, i64), rusqlite::Error> {
    // A deferred read transaction: no lock is taken, and it is rolled back
    // (there is nothing to undo) when dropped.
    let tx = conn.unchecked_transaction()?;
    let entries = get_audit_log(&tx, tenant_id, filter, limit, offset)?;
    let total = count_audit_log(&tx, tenant_id, filter)?;
    Ok((entries, total))
}

/// Get distinct action types.
pub fn get_audit_actions(
    conn: &Connection,
    tenant_id: &str,
) -> Result<Vec<String>, rusqlite::Error> {
    let mut stmt =
        conn.prepare("SELECT DISTINCT action FROM audit_log WHERE tenant_id = ?1 ORDER BY action")?;
    let rows = stmt.query_map(params![tenant_id], |row| row.get(0))?;
    rows.collect()
}

/// Get distinct operators.
pub fn get_audit_operators(
    conn: &Connection,
    tenant_id: &str,
) -> Result<Vec<String>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT operator FROM audit_log WHERE tenant_id = ?1 AND operator != '' ORDER BY operator",
    )?;
    let rows = stmt.query_map(params![tenant_id], |row| row.get(0))?;
    rows.collect()
}

/// Get distinct node IDs.
pub fn get_audit_node_ids(
    conn: &Connection,
    tenant_id: &str,
) -> Result<Vec<String>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT node_id FROM audit_log WHERE tenant_id = ?1 AND node_id != '' ORDER BY node_id",
    )?;
    let rows = stmt.query_map(params![tenant_id], |row| row.get(0))?;
    rows.collect()
}

// ── Archive anchor ────────────────────────────────────────────────────

/// Columns copied into `audit_log_archive`, in the bridge's `audit_log`
/// order (spelled out: the two tables need not share a column order).
const ARCHIVE_COLUMNS: &str = "id, timestamp, action, target_id, target_ids, signal_class, \
                               freq_hz, node_id, operator, note, details, tenant_id, hmac_chain";

/// Where the live chain of one tenant starts after an archive.
#[derive(Debug, Clone, PartialEq)]
pub struct ArchiveAnchor {
    pub tenant_id: String,
    /// Id of the last row moved to `audit_log_archive`.
    pub last_archived_id: i64,
    /// The HMAC the first live row chains from (the last archived row's
    /// HMAC, or the legacy sentinel if that row had none).
    pub terminal_hmac: String,
    /// Rows archived so far, over all archives.
    pub archived_total: i64,
    pub updated_at: String,
    /// HMAC over the fields above, so the anchor cannot be edited or
    /// forged without the audit key.
    pub anchor_hmac: String,
}

impl ArchiveAnchor {
    fn payload(&self) -> String {
        format!(
            "anchor-v1|{}|{}|{}|{}|{}",
            self.tenant_id,
            self.last_archived_id,
            self.terminal_hmac,
            self.archived_total,
            self.updated_at
        )
    }

    fn sealed(mut self, secret: &[u8]) -> Self {
        self.anchor_hmac = chain::hmac_hex(secret, &self.payload());
        self
    }

    /// True if `anchor_hmac` matches the anchor's fields under `secret`.
    pub fn is_authentic(&self, secret: &[u8]) -> bool {
        let expected = chain::hmac_hex(secret, &self.payload());
        constant_time_eq::constant_time_eq(expected.as_bytes(), self.anchor_hmac.as_bytes())
    }
}

fn table_exists(conn: &Connection, name: &str) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        params![name],
        |row| row.get(0),
    )
}

/// The archive anchor of `tenant_id`, if anything was ever archived.
pub fn load_anchor(conn: &Connection, tenant_id: &str) -> rusqlite::Result<Option<ArchiveAnchor>> {
    if !table_exists(conn, "audit_anchor")? {
        return Ok(None);
    }
    conn.query_row(
        "SELECT tenant_id, last_archived_id, terminal_hmac, archived_total, updated_at, \
                anchor_hmac \
         FROM audit_anchor WHERE tenant_id = ?1",
        params![tenant_id],
        |row| {
            Ok(ArchiveAnchor {
                tenant_id: row.get(0)?,
                last_archived_id: row.get(1)?,
                terminal_hmac: row.get(2)?,
                archived_total: row.get(3)?,
                updated_at: row.get(4)?,
                anchor_hmac: row.get(5)?,
            })
        },
    )
    .optional()
}

fn store_anchor(conn: &Connection, anchor: &ArchiveAnchor) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO audit_anchor (tenant_id, last_archived_id, terminal_hmac, archived_total, \
                                   updated_at, anchor_hmac) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
         ON CONFLICT(tenant_id) DO UPDATE SET \
             last_archived_id = excluded.last_archived_id, \
             terminal_hmac = excluded.terminal_hmac, \
             archived_total = excluded.archived_total, \
             updated_at = excluded.updated_at, \
             anchor_hmac = excluded.anchor_hmac",
        params![
            anchor.tenant_id,
            anchor.last_archived_id,
            anchor.terminal_hmac,
            anchor.archived_total,
            anchor.updated_at,
            anchor.anchor_hmac
        ],
    )?;
    Ok(())
}

/// Create the gateway-owned audit tables. An archive table created by an
/// older gateway lacks `target_ids`; it is added.
fn ensure_archive_tables(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS audit_log_archive ( \
            id INTEGER PRIMARY KEY, timestamp TEXT, action TEXT, target_id TEXT, \
            target_ids TEXT DEFAULT '', signal_class TEXT, freq_hz REAL, node_id TEXT, \
            operator TEXT, note TEXT, details TEXT, tenant_id TEXT, hmac_chain TEXT \
         ); \
         CREATE TABLE IF NOT EXISTS audit_anchor ( \
            tenant_id TEXT PRIMARY KEY, \
            last_archived_id INTEGER NOT NULL, \
            terminal_hmac TEXT NOT NULL, \
            archived_total INTEGER NOT NULL DEFAULT 0, \
            updated_at TEXT NOT NULL, \
            anchor_hmac TEXT NOT NULL \
         );",
    )?;
    let has_target_ids = {
        let mut stmt = conn.prepare("PRAGMA table_info(audit_log_archive)")?;
        let names = stmt.query_map([], |row| row.get::<_, String>(1))?;
        let mut found = false;
        for name in names {
            if name? == "target_ids" {
                found = true;
            }
        }
        found
    };
    if !has_target_ids {
        conn.execute_batch("ALTER TABLE audit_log_archive ADD COLUMN target_ids TEXT DEFAULT ''")?;
    }
    Ok(())
}

// ── Chain verification ────────────────────────────────────────────────

/// Chain verification result.
#[derive(Debug, Serialize)]
pub struct ChainVerification {
    pub valid: bool,
    pub total: i64,
    pub checked: i64,
    pub errors: Vec<ChainError>,
    pub gaps: Vec<ChainGap>,
    /// The archive anchor verification started from (`null` if nothing
    /// was ever archived).
    pub anchor: Option<AnchorReport>,
}

/// One entry that fails verification. `expected` describes what was
/// expected; it never holds a computed HMAC (see [`HMAC_MISMATCH`]).
#[derive(Debug, Serialize)]
pub struct ChainError {
    pub id: i64,
    pub expected: String,
    pub actual: String,
}

/// `expected` of an entry whose stored HMAC does not match. The digest the
/// verifier computed is not reported: it is the valid HMAC of the entry's
/// current, possibly tampered, content, so anyone who can write the
/// database and read `GET /api/admin/audit/verify` could store it and
/// re-sign the chain, entry by entry. Same text as the bridge's verifier.
pub const HMAC_MISMATCH: &str = "HMAC of the entry's fields chained from its predecessor";

/// `expected` of an entry without an HMAC that comes after a signed entry
/// (its `actual` is the empty stored HMAC). Both writers sign every entry,
/// so only rows written before the chain existed, which come before its
/// first signed entry, may have none; an unsigned entry after that is an
/// entry appended, or rewritten and its HMAC blanked, by someone without
/// the key. Same text as the bridge's verifier.
pub const HMAC_MISSING: &str =
    "an HMAC: only entries before the chain's first signed entry may have none";

/// True for a real HMAC: not empty and not [`LEGACY_NO_HMAC_SENTINEL`],
/// which is what an archived prefix ending in an unsigned row hands on.
fn is_signed(hmac: &str) -> bool {
    !hmac.is_empty() && hmac != LEGACY_NO_HMAC_SENTINEL
}

#[derive(Debug, Serialize)]
pub struct ChainGap {
    pub after_id: i64,
    pub before_id: i64,
    pub missing: i64,
}

#[derive(Debug, Serialize)]
pub struct AnchorReport {
    pub last_archived_id: i64,
    pub archived_total: i64,
    pub updated_at: String,
    pub authentic: bool,
}

/// One audit row as read for chain verification.
struct ChainRow {
    id: i64,
    timestamp: String,
    action: String,
    target_id: String,
    operator: String,
    note: String,
    details: String,
    signal_class: String,
    freq_hz: f64,
    node_id: String,
    hmac_chain: String,
    target_ids: String,
}

const CHAIN_ROWS_SQL: &str = "SELECT id, timestamp, action, target_id, operator, note, details, \
                                     signal_class, freq_hz, node_id, hmac_chain, target_ids \
                              FROM audit_log WHERE tenant_id = ?1 ORDER BY id ASC";

impl ChainRow {
    fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            timestamp: row.get::<_, Option<String>>(1)?.unwrap_or_default(),
            action: row.get::<_, Option<String>>(2)?.unwrap_or_default(),
            target_id: row.get::<_, Option<String>>(3)?.unwrap_or_default(),
            operator: row.get::<_, Option<String>>(4)?.unwrap_or_default(),
            note: row.get::<_, Option<String>>(5)?.unwrap_or_default(),
            details: row.get::<_, Option<String>>(6)?.unwrap_or_default(),
            signal_class: row.get::<_, Option<String>>(7)?.unwrap_or_default(),
            freq_hz: row.get::<_, Option<f64>>(8)?.unwrap_or(0.0),
            node_id: row.get::<_, Option<String>>(9)?.unwrap_or_default(),
            hmac_chain: row.get::<_, Option<String>>(10)?.unwrap_or_default(),
            target_ids: row.get::<_, Option<String>>(11)?.unwrap_or_default(),
        })
    }
}

/// Walks one tenant's rows in id order, checking each HMAC against its
/// predecessor and looking for unexplained id gaps.
struct ChainWalker<'a> {
    secret: &'a [u8],
    tenant_id: &'a str,
    previous_hmac: String,
    previous_id: Option<i64>,
    /// Accepted as the predecessor of the first row only. Used when there
    /// is no anchor: the `terminal_hmac`s of `archive_marker` rows (a
    /// prefix archived by the bridge, which records no anchor).
    first_row_roots: Vec<String>,
    /// Whether the chain is signed by now: a signed row has been walked, or
    /// the walk starts after an archived prefix whose last row was signed
    /// (the anchor's terminal HMAC, or that of a bridge `archive_marker`).
    /// From then on a row without an HMAC is reported ([`HMAC_MISSING`]);
    /// before it, such a row predates the chain and is skipped.
    signed: bool,
    rows: i64,
    checked: i64,
    errors: Vec<ChainError>,
    gaps: Vec<ChainGap>,
}

impl<'a> ChainWalker<'a> {
    fn new(secret: &'a [u8], tenant_id: &'a str) -> Self {
        Self {
            secret,
            tenant_id,
            previous_hmac: String::new(),
            previous_id: None,
            first_row_roots: Vec::new(),
            signed: false,
            rows: 0,
            checked: 0,
            errors: Vec::new(),
            gaps: Vec::new(),
        }
    }

    /// Start after `anchor` (or at the beginning of the chain). Without an
    /// anchor, an `archive_marker` written by the gateway means the anchor
    /// was removed — an error, since the anchor is what proves where the
    /// archived prefix ended.
    fn start(&mut self, conn: &Connection, anchor: Option<&ArchiveAnchor>) -> rusqlite::Result<()> {
        match anchor {
            Some(a) => {
                if !a.is_authentic(self.secret) {
                    self.errors.push(ChainError {
                        id: a.last_archived_id,
                        expected: "authentic archive anchor".into(),
                        actual: "archive anchor HMAC mismatch".into(),
                    });
                }
                self.previous_hmac = a.terminal_hmac.clone();
                self.previous_id = Some(a.last_archived_id);
                self.signed = is_signed(&a.terminal_hmac);
            }
            None => {
                if has_archived_rows(conn, self.tenant_id)? {
                    self.errors.push(ChainError {
                        id: 0,
                        expected: "archive anchor for the archived entries".into(),
                        actual: "archived entries exist but the archive anchor is missing".into(),
                    });
                }
                let markers = archive_markers(conn, self.tenant_id)?;
                if let Some((marker_id, last_archived_id)) = markers.gateway_marker {
                    self.errors.push(ChainError {
                        id: marker_id,
                        expected: format!("archive anchor for rows up to id {last_archived_id}"),
                        actual: "archive anchor missing".into(),
                    });
                }
                self.signed = markers.terminal_hmacs.iter().any(|h| is_signed(h));
                self.first_row_roots = markers.terminal_hmacs;
            }
        }
        Ok(())
    }

    /// The row's v3 HMAC chained from `previous_hmac`.
    fn v3(&self, row: &ChainRow, previous_hmac: &str) -> String {
        chain::compute_hmac_v3(
            self.secret,
            previous_hmac,
            &row.action,
            &row.target_id,
            &row.operator,
            &row.timestamp,
            &row.details,
            &row.note,
            &row.signal_class,
            &chain::python_float_str(row.freq_hz),
            &row.node_id,
            &row.target_ids,
            self.tenant_id,
        )
    }

    /// True if the row's stored HMAC is its v3, v2 or v1 HMAC chained from
    /// `previous_hmac` (no version is stored; bridge and gateway rows of any
    /// version share the chain).
    fn matches(&self, row: &ChainRow, previous_hmac: &str) -> bool {
        if self.v3(row, previous_hmac) == row.hmac_chain {
            return true;
        }
        let freq_str = chain::python_float_str(row.freq_hz);
        let v2 = chain::compute_hmac_v2(
            self.secret,
            previous_hmac,
            &row.action,
            &row.target_id,
            &row.operator,
            &row.timestamp,
            &row.details,
            &row.note,
            &row.signal_class,
            &freq_str,
            &row.node_id,
        );
        if v2 == row.hmac_chain {
            return true;
        }
        chain::compute_hmac_v1(
            self.secret,
            previous_hmac,
            &row.action,
            &row.target_id,
            &row.operator,
            &row.timestamp,
        ) == row.hmac_chain
    }

    fn step(&mut self, conn: &Connection, row: &ChainRow) -> rusqlite::Result<()> {
        let first = self.rows == 0;
        self.rows += 1;

        // Gap detection (and rows that predate the anchor).
        if let Some(prev_id) = self.previous_id {
            if row.id <= prev_id {
                self.errors.push(ChainError {
                    id: row.id,
                    expected: format!("id after the archive anchor ({prev_id})"),
                    actual: "row predates the archive anchor".into(),
                });
            } else if row.id - prev_id > 1 {
                let other_tenants = count_other_tenants(conn, prev_id, row.id, self.tenant_id)?;
                let unexplained = row.id - prev_id - 1 - other_tenants;
                if unexplained > 0 {
                    self.gaps.push(ChainGap {
                        after_id: prev_id,
                        before_id: row.id,
                        missing: unexplained,
                    });
                }
            }
        }
        self.previous_id = Some(self.previous_id.map_or(row.id, |p| p.max(row.id)));

        // An entry without an HMAC: skipped before the chain's first signed
        // entry (a row that predates the chain), reported after it. Either
        // way the next one chains from the sentinel, as the writers do.
        if row.hmac_chain.is_empty() {
            if self.signed {
                self.checked += 1;
                self.errors.push(ChainError {
                    id: row.id,
                    expected: HMAC_MISSING.into(),
                    actual: String::new(),
                });
            }
            self.previous_hmac = LEGACY_NO_HMAC_SENTINEL.to_string();
            return Ok(());
        }
        self.signed = true;
        self.checked += 1;
        let ok = self.matches(row, &self.previous_hmac)
            || (first
                && self
                    .first_row_roots
                    .iter()
                    .any(|root| self.matches(row, root)));
        if !ok {
            self.errors.push(ChainError {
                id: row.id,
                expected: HMAC_MISMATCH.into(),
                actual: row.hmac_chain.clone(),
            });
        }
        self.previous_hmac = row.hmac_chain.clone();
        Ok(())
    }
}

/// Rows of other tenants strictly between two ids, live or archived.
fn count_other_tenants(
    conn: &Connection,
    after_id: i64,
    before_id: i64,
    tenant_id: &str,
) -> rusqlite::Result<i64> {
    let mut count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM audit_log WHERE id > ?1 AND id < ?2 AND tenant_id != ?3",
        params![after_id, before_id, tenant_id],
        |row| row.get(0),
    )?;
    if table_exists(conn, "audit_log_archive")? {
        count += conn.query_row(
            "SELECT COUNT(*) FROM audit_log_archive WHERE id > ?1 AND id < ?2 AND tenant_id != ?3",
            params![after_id, before_id, tenant_id],
            |row| row.get::<_, i64>(0),
        )?;
    }
    Ok(count)
}

fn has_archived_rows(conn: &Connection, tenant_id: &str) -> rusqlite::Result<bool> {
    if !table_exists(conn, "audit_log_archive")? {
        return Ok(false);
    }
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM audit_log_archive WHERE tenant_id = ?1)",
        params![tenant_id],
        |row| row.get(0),
    )
}

struct ArchiveMarkers {
    terminal_hmacs: Vec<String>,
    /// (marker id, last_archived_id) of the newest marker written by the
    /// gateway (only the gateway records `last_archived_id`).
    gateway_marker: Option<(i64, i64)>,
}

fn archive_markers(conn: &Connection, tenant_id: &str) -> rusqlite::Result<ArchiveMarkers> {
    let mut stmt = conn.prepare(
        "SELECT id, details FROM audit_log \
         WHERE tenant_id = ?1 AND action = 'archive_marker' ORDER BY id ASC",
    )?;
    let rows = stmt.query_map(params![tenant_id], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, Option<String>>(1)?))
    })?;
    let mut markers = ArchiveMarkers {
        terminal_hmacs: Vec::new(),
        gateway_marker: None,
    };
    for row in rows {
        let (id, details) = row?;
        let details = parse_details(details.as_deref().unwrap_or(""));
        if let Some(th) = details.get("terminal_hmac").and_then(|v| v.as_str()) {
            if !th.is_empty() {
                markers.terminal_hmacs.push(th.to_string());
            }
        }
        if let Some(last) = details.get("last_archived_id").and_then(|v| v.as_i64()) {
            markers.gateway_marker = Some((id, last));
        }
    }
    Ok(markers)
}

/// Verify the HMAC chain integrity for a tenant, starting from its archive
/// anchor when there is one.
pub fn verify_chain(
    conn: &Connection,
    tenant_id: &str,
    secret: &[u8],
) -> Result<ChainVerification, rusqlite::Error> {
    let anchor = load_anchor(conn, tenant_id)?;
    let mut walker = ChainWalker::new(secret, tenant_id);
    walker.start(conn, anchor.as_ref())?;

    let mut stmt = conn.prepare(CHAIN_ROWS_SQL)?;
    let mut rows = stmt.query(params![tenant_id])?;
    while let Some(row) = rows.next()? {
        walker.step(conn, &ChainRow::from_row(row)?)?;
    }

    if !walker.gaps.is_empty() {
        warn!(
            gaps = walker.gaps.len(),
            tenant_id, "Audit chain verification found ID gap(s) — possible row deletion"
        );
    }
    Ok(ChainVerification {
        valid: walker.errors.is_empty() && walker.gaps.is_empty(),
        total: walker.rows,
        checked: walker.checked,
        errors: walker.errors,
        gaps: walker.gaps,
        anchor: anchor.map(|a| AnchorReport {
            authentic: a.is_authentic(secret),
            last_archived_id: a.last_archived_id,
            archived_total: a.archived_total,
            updated_at: a.updated_at,
        }),
    })
}

// ── Archive / purge ───────────────────────────────────────────────────

/// Why an archive or purge did not happen.
#[derive(Debug)]
pub enum AuditOpError {
    /// The request itself is invalid (HTTP 400).
    Invalid(String),
    /// Refused to protect the log, e.g. the chain fails verification (409).
    Refused(String),
    Db(rusqlite::Error),
}

impl std::fmt::Display for AuditOpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditOpError::Invalid(m) | AuditOpError::Refused(m) => f.write_str(m),
            AuditOpError::Db(e) => write!(f, "database error: {e}"),
        }
    }
}

impl std::error::Error for AuditOpError {}

impl From<rusqlite::Error> for AuditOpError {
    fn from(e: rusqlite::Error) -> Self {
        AuditOpError::Db(e)
    }
}

/// Result of [`archive_audit_log`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveOutcome {
    pub moved: usize,
    /// The new anchor's id (`None` when nothing was moved).
    pub last_archived_id: Option<i64>,
    /// Id of the audit entry recording this archive.
    pub event_id: i64,
}

/// Result of [`purge_archived`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgeOutcome {
    pub deleted: usize,
    /// Id of the audit entry recording this purge.
    pub event_id: i64,
}

fn cutoff_for(days: u32) -> String {
    (chrono::Utc::now() - chrono::Duration::days(i64::from(days)))
        .format("%Y-%m-%dT%H:%M:%S+00:00")
        .to_string()
}

fn check_days(days: u32, min_days: u32) -> Result<(), AuditOpError> {
    if days < min_days {
        return Err(AuditOpError::Invalid(format!(
            "days must be at least {min_days}: audit entries younger than that cannot be \
             archived or purged (UC_AUDIT_MIN_RETENTION_DAYS)"
        )));
    }
    Ok(())
}

/// Run an archive/purge body in a write transaction; refusals pass through.
fn run_op<T>(
    conn: &Connection,
    what: &str,
    mut body: impl FnMut(&Connection) -> rusqlite::Result<Result<(T, AuditEntry), AuditOpError>>,
) -> Result<T, AuditOpError> {
    match write_tx(conn, |tx| body(tx)) {
        Ok(Ok((outcome, entry))) => {
            publish(&entry);
            Ok(outcome)
        }
        Ok(Err(refusal)) => {
            warn!(operation = what, reason = %refusal, "Audit operation refused");
            Err(refusal)
        }
        Err(e) => {
            error!(operation = what, error = %e, "Audit operation failed — nothing changed");
            Err(AuditOpError::Db(e))
        }
    }
}

/// Archive the oldest entries of `tenant_id`: the longest prefix of the
/// chain (in id order) whose rows are all older than `days` days.
///
/// The prefix is verified first and is not archived if it fails. The rows
/// move to `audit_log_archive`, the anchor is advanced to the last of them,
/// and an `archive_marker` entry (operator, count, `terminal_hmac`,
/// `last_archived_id`) is appended — all in one transaction. With nothing
/// to move, an `audit_archive` entry records the attempt.
pub fn archive_audit_log(
    conn: &Connection,
    tenant_id: &str,
    days: u32,
    min_days: u32,
    secret: &[u8],
    operator: &str,
) -> Result<ArchiveOutcome, AuditOpError> {
    check_days(days, min_days)?;
    let cutoff = cutoff_for(days);
    let outcome = run_op(conn, "archive", |tx| {
        archive_in_tx(tx, tenant_id, days, &cutoff, secret, operator)
    })?;
    info!(
        moved = outcome.moved,
        last_archived_id = ?outcome.last_archived_id,
        tenant_id,
        operator,
        "Audit entries archived"
    );
    Ok(outcome)
}

fn archive_in_tx(
    conn: &Connection,
    tenant_id: &str,
    days: u32,
    cutoff: &str,
    secret: &[u8],
    operator: &str,
) -> rusqlite::Result<Result<(ArchiveOutcome, AuditEntry), AuditOpError>> {
    ensure_archive_tables(conn)?;
    let anchor = load_anchor(conn, tenant_id)?;
    if let Some(a) = &anchor {
        if !a.is_authentic(secret) {
            return Ok(Err(AuditOpError::Refused(
                "the archive anchor fails verification; refusing to archive past it. \
                 Check GET /api/admin/audit/verify."
                    .into(),
            )));
        }
    }

    // Walk (and verify) the prefix older than the cutoff.
    let mut walker = ChainWalker::new(secret, tenant_id);
    walker.start(conn, anchor.as_ref())?;
    let mut moved = 0usize;
    let mut last_id = 0i64;
    let mut first_ts = String::new();
    let mut last_ts = String::new();
    {
        let mut stmt = conn.prepare(CHAIN_ROWS_SQL)?;
        let mut rows = stmt.query(params![tenant_id])?;
        while let Some(row) = rows.next()? {
            let row = ChainRow::from_row(row)?;
            if row.timestamp.as_str() >= cutoff {
                break;
            }
            walker.step(conn, &row)?;
            if moved == 0 {
                first_ts = row.timestamp.clone();
            }
            moved += 1;
            last_id = row.id;
            last_ts = row.timestamp;
        }
    }
    if !walker.errors.is_empty() || !walker.gaps.is_empty() {
        return Ok(Err(AuditOpError::Refused(format!(
            "the audit chain fails verification in the range to be archived ({} error(s), \
             {} gap(s)); nothing was archived. Check GET /api/admin/audit/verify.",
            walker.errors.len(),
            walker.gaps.len()
        ))));
    }

    let mut details = serde_json::json!({
        "archived_count": moved,
        "days": days,
        "cutoff": cutoff,
    });
    let action = if moved > 0 {
        conn.execute(
            &format!(
                "INSERT INTO audit_log_archive ({ARCHIVE_COLUMNS}) \
                 SELECT {ARCHIVE_COLUMNS} FROM audit_log WHERE tenant_id = ?1 AND id <= ?2"
            ),
            params![tenant_id, last_id],
        )?;
        conn.execute(
            "DELETE FROM audit_log WHERE tenant_id = ?1 AND id <= ?2",
            params![tenant_id, last_id],
        )?;
        let new_anchor = ArchiveAnchor {
            tenant_id: tenant_id.to_string(),
            last_archived_id: last_id,
            terminal_hmac: walker.previous_hmac.clone(),
            archived_total: anchor.as_ref().map_or(0, |a| a.archived_total) + moved as i64,
            updated_at: utc_now_iso(),
            anchor_hmac: String::new(),
        }
        .sealed(secret);
        store_anchor(conn, &new_anchor)?;
        details["terminal_hmac"] = new_anchor.terminal_hmac.into();
        details["last_archived_id"] = last_id.into();
        details["date_range"] = format!("{first_ts} — {last_ts}").into();
        "archive_marker"
    } else {
        "audit_archive"
    };
    let note = format!("Archived {moved} entries older than {days} days");
    let entry = append_entry(
        conn,
        secret,
        &NewEntry {
            action,
            target_id: "",
            target_ids: "",
            operator,
            note: &note,
            details: with_severity(&details.to_string(), classify_severity(action)),
            signal_class: "",
            freq_hz: 0.0,
            node_id: "",
            tenant_id,
        },
    )?;
    let outcome = ArchiveOutcome {
        moved,
        last_archived_id: (moved > 0).then_some(last_id),
        event_id: entry.id,
    };
    Ok(Ok((outcome, entry)))
}

/// Delete archived entries older than `days` days.
///
/// Only rows in `audit_log_archive` at or before the (authentic) anchor are
/// ever deleted — never a live row, never one that was not archived under
/// an anchor. `days` must be at least `min_days`. The purge is recorded as
/// an `audit_purge` entry in the same transaction.
pub fn purge_archived(
    conn: &Connection,
    tenant_id: &str,
    days: u32,
    min_days: u32,
    secret: &[u8],
    operator: &str,
) -> Result<PurgeOutcome, AuditOpError> {
    check_days(days, min_days)?;
    let cutoff = cutoff_for(days);
    let outcome = run_op(conn, "purge", |tx| {
        ensure_archive_tables(tx)?;
        let deleted = match load_anchor(tx, tenant_id)? {
            Some(a) if !a.is_authentic(secret) => {
                return Ok(Err(AuditOpError::Refused(
                    "the archive anchor fails verification; refusing to purge. \
                     Check GET /api/admin/audit/verify."
                        .into(),
                )));
            }
            Some(a) => tx.execute(
                "DELETE FROM audit_log_archive \
                 WHERE tenant_id = ?1 AND timestamp < ?2 AND id <= ?3",
                params![tenant_id, cutoff, a.last_archived_id],
            )?,
            None => 0,
        };
        let details = serde_json::json!({
            "deleted": deleted,
            "days": days,
            "cutoff": cutoff,
        });
        let note = format!("Purged {deleted} archived entries older than {days} days");
        let entry = append_entry(
            tx,
            secret,
            &NewEntry {
                action: "audit_purge",
                target_id: "",
                target_ids: "",
                operator,
                note: &note,
                details: with_severity(&details.to_string(), classify_severity("audit_purge")),
                signal_class: "",
                freq_hz: 0.0,
                node_id: "",
                tenant_id,
            },
        )?;
        Ok(Ok((
            PurgeOutcome {
                deleted,
                event_id: entry.id,
            },
            entry,
        )))
    })?;
    if outcome.deleted > 0 {
        info!(
            deleted = outcome.deleted,
            tenant_id, operator, "Archived audit entries purged"
        );
    }
    Ok(outcome)
}

// ── Export ─────────────────────────────────────────────────────────────

/// Export audit entries in a date range.
pub fn export_audit_log(
    conn: &Connection,
    tenant_id: &str,
    start: Option<&str>,
    end: Option<&str>,
) -> Result<Vec<AuditEntry>, rusqlite::Error> {
    let mut sql = String::from(
        "SELECT id, timestamp, action, target_id, operator, note, details, \
                signal_class, freq_hz, node_id, tenant_id, hmac_chain \
         FROM audit_log WHERE tenant_id = ?1",
    );
    let mut params_vec: Vec<Box<dyn rusqlite::types::ToSql>> =
        vec![Box::new(tenant_id.to_string())];
    let mut idx = 2;

    if let Some(s) = start {
        sql.push_str(&format!(" AND timestamp >= ?{}", idx));
        params_vec.push(Box::new(s.to_string()));
        idx += 1;
    }
    if let Some(e) = end {
        sql.push_str(&format!(" AND timestamp <= ?{}", idx));
        params_vec.push(Box::new(e.to_string()));
    }
    sql.push_str(" ORDER BY id ASC");

    let params_refs: Vec<&dyn rusqlite::types::ToSql> =
        params_vec.iter().map(|p| p.as_ref()).collect();
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params_refs.as_slice(), entry_from_row)?;
    rows.collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::db::pool::{create_pool, DbPool};

    /// The bridge's `audit_log` (sigrift/bridge/storage/base.py + migrations).
    pub(crate) const AUDIT_SCHEMA: &str = "
        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            action TEXT NOT NULL,
            target_id TEXT NOT NULL,
            target_ids TEXT DEFAULT '',
            signal_class TEXT DEFAULT '',
            freq_hz REAL DEFAULT 0.0,
            node_id TEXT DEFAULT '',
            operator TEXT DEFAULT '',
            note TEXT DEFAULT '',
            details TEXT DEFAULT '',
            tenant_id TEXT NOT NULL DEFAULT 'default',
            hmac_chain TEXT NOT NULL DEFAULT ''
        );";
    const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";
    const T: &str = "default";

    fn db() -> (tempfile::TempDir, DbPool) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        // The pool opens its connections at once, and each puts the file in
        // WAL mode: on a new file all but one then wait out SQLite's busy
        // backoff (about 0.4 s). Switching it first makes theirs a no-op.
        Connection::open(&path)
            .unwrap()
            .execute_batch("PRAGMA journal_mode = WAL")
            .unwrap();
        let pool = create_pool(&path, 4, 5_000).unwrap();
        pool.get().unwrap().execute_batch(AUDIT_SCHEMA).unwrap();
        (dir, pool)
    }

    fn days_ago(days: i64) -> String {
        (chrono::Utc::now() - chrono::Duration::days(days))
            .format("%Y-%m-%dT%H:%M:%S+00:00")
            .to_string()
    }

    /// Append a correctly chained entry with a chosen timestamp.
    fn entry_at(conn: &Connection, action: &str, timestamp: &str) -> AuditEntry {
        tenant_entry_at(conn, T, action, timestamp)
    }

    /// [`entry_at`] for the chain of `tenant_id`.
    fn tenant_entry_at(
        conn: &Connection,
        tenant_id: &str,
        action: &str,
        timestamp: &str,
    ) -> AuditEntry {
        write_tx(conn, |tx| {
            append_entry_at(
                tx,
                SECRET,
                &NewEntry {
                    action,
                    target_id: "target",
                    target_ids: "",
                    operator: "alice",
                    note: "note",
                    details: with_severity("", "info"),
                    signal_class: "",
                    freq_hz: 433_920_000.0,
                    node_id: "node-1",
                    tenant_id,
                },
                timestamp,
            )
        })
        .unwrap()
    }

    fn log(conn: &Connection, action: &str) -> i64 {
        log_audit(conn, SECRET, action, "t", "op", "", "", "", 0.0, "", T).unwrap()
    }

    fn count(conn: &Connection, sql: &str) -> i64 {
        conn.query_row(sql, [], |row| row.get(0)).unwrap()
    }

    fn latest(conn: &Connection, action: &str) -> AuditEntry {
        let filter = AuditFilter {
            action: Some(action),
            ..Default::default()
        };
        get_audit_log(conn, T, &filter, 1, 0).unwrap().remove(0)
    }

    fn assert_valid(conn: &Connection) -> ChainVerification {
        let v = verify_chain(conn, T, SECRET).unwrap();
        assert!(v.valid, "chain should verify: {v:?}");
        v
    }

    /// The bridge's verifier (`AuditStore.verify_chain` in
    /// sigrift/bridge/storage/audit.py): starts from "" and accepts the
    /// `terminal_hmac` of any `archive_marker` as an alternative
    /// predecessor; flags any id gap between consecutive rows, and a row
    /// without an HMAC once the chain is signed (after a signed row, or
    /// from the start when a marker carries a signed terminal HMAC).
    /// Returns the ids it reports (errors, and the row after each gap).
    fn bridge_verifier_findings(conn: &Connection) -> Vec<i64> {
        let markers = archive_markers(conn, T).unwrap();
        let walker = ChainWalker::new(SECRET, T);
        let mut stmt = conn.prepare(CHAIN_ROWS_SQL).unwrap();
        let rows: Vec<ChainRow> = stmt
            .query_map(params![T], ChainRow::from_row)
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        let mut findings = Vec::new();
        let mut previous = String::new();
        let mut previous_id: Option<i64> = None;
        let mut signed = markers.terminal_hmacs.iter().any(|h| is_signed(h));
        for row in &rows {
            if previous_id.is_some_and(|p| row.id != p + 1) {
                findings.push(row.id);
            }
            previous_id = Some(row.id);
            if row.hmac_chain.is_empty() {
                if signed {
                    findings.push(row.id);
                }
                previous = LEGACY_NO_HMAC_SENTINEL.to_string();
                continue;
            }
            signed = true;
            let ok = walker.matches(row, &previous)
                || markers
                    .terminal_hmacs
                    .iter()
                    .any(|th| walker.matches(row, th));
            if !ok {
                findings.push(row.id);
            }
            previous = row.hmac_chain.clone();
        }
        findings
    }

    /// 5 entries 30 days old, then 3 current ones, archived at 7 days.
    fn archived_db() -> (tempfile::TempDir, DbPool, Vec<AuditEntry>) {
        let (dir, pool) = db();
        let conn = pool.get().unwrap();
        let old: Vec<AuditEntry> = (0..5)
            .map(|i| entry_at(&conn, &format!("old_{i}"), &days_ago(30)))
            .collect();
        for i in 0..3 {
            log(&conn, &format!("new_{i}"));
        }
        let outcome = archive_audit_log(&conn, T, 7, 7, SECRET, "admin").unwrap();
        assert_eq!(outcome.moved, 5);
        assert_eq!(outcome.last_archived_id, Some(old[4].id));
        drop(conn);
        (dir, pool, old)
    }

    #[test]
    fn log_audit_chains_entries() {
        let (_dir, pool) = db();
        let conn = pool.get().unwrap();
        for i in 0..4 {
            log(&conn, &format!("a{i}"));
        }
        let v = assert_valid(&conn);
        assert_eq!((v.total, v.checked), (4, 4));
        assert!(v.anchor.is_none());
    }

    /// Insert a row signed as v1 or v2, as an older bridge or gateway wrote.
    fn insert_old_version(conn: &Connection, version: u8, target_id: &str, note: &str) -> i64 {
        let previous = chain_head(conn, T).unwrap();
        let ts = utc_now_iso();
        let hmac = match version {
            1 => chain::compute_hmac_v1(SECRET, &previous, "old", target_id, "alice", &ts),
            _ => chain::compute_hmac_v2(
                SECRET, &previous, "old", target_id, "alice", &ts, "", note, "", "0.0", "",
            ),
        };
        conn.execute(
            "INSERT INTO audit_log (timestamp, action, target_id, target_ids, operator, note, \
             tenant_id, hmac_chain) VALUES (?1, 'old', ?2, '[\"x\"]', 'alice', ?3, ?4, ?5)",
            params![ts, target_id, note, T, hmac],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    #[test]
    fn new_entries_are_v3_and_chain_after_v1_and_v2_rows() {
        let (_dir, pool) = db();
        let conn = pool.get().unwrap();
        let v1 = insert_old_version(&conn, 1, "t1", "");
        let v2 = insert_old_version(&conn, 2, "t2", "v2 note");
        let id = log(&conn, "gateway");
        let v = assert_valid(&conn);
        assert_eq!((v.total, v.checked), (3, 3));
        assert!(bridge_verifier_findings(&conn).is_empty());

        let entry = latest(&conn, "gateway");
        assert_eq!(entry.id, id);
        let previous: String = conn
            .query_row(
                "SELECT hmac_chain FROM audit_log WHERE id = ?1",
                params![v2],
                |r| r.get(0),
            )
            .unwrap();
        let details: String = conn
            .query_row(
                "SELECT details FROM audit_log WHERE id = ?1",
                params![id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            entry.hmac_chain,
            chain::compute_hmac_v3(
                SECRET,
                &previous,
                "gateway",
                "t",
                "op",
                &entry.timestamp,
                &details,
                "",
                "",
                "0.0",
                "",
                "",
                T,
            )
        );

        // Older rows keep the protection of their own version.
        conn.execute(
            "UPDATE audit_log SET note = 'rewritten' WHERE id = ?1",
            params![v2],
        )
        .unwrap();
        let v = verify_chain(&conn, T, SECRET).unwrap();
        assert_eq!(v.errors.iter().map(|e| e.id).collect::<Vec<_>>(), [v2]);
        conn.execute(
            "UPDATE audit_log SET note = 'v2 note' WHERE id = ?1",
            params![v2],
        )
        .unwrap();
        // v1 does not cover the note, but it does cover the operator.
        conn.execute(
            "UPDATE audit_log SET note = 'unprotected', operator = 'mallory' WHERE id = ?1",
            params![v1],
        )
        .unwrap();
        let v = verify_chain(&conn, T, SECRET).unwrap();
        assert_eq!(v.errors.iter().map(|e| e.id).collect::<Vec<_>>(), [v1]);
    }

    #[test]
    fn rewriting_target_ids_tenant_or_field_boundaries_of_a_v3_row_is_detected() {
        let tampering = [
            "UPDATE audit_log SET target_ids = '[\"1\"]' WHERE action = 'bulk'",
            "UPDATE audit_log SET note = 'approved', signal_class = 'signed-off|wifi' \
             WHERE action = 'bulk'",
            "UPDATE audit_log SET tenant_id = 'tenant-b'",
        ];
        for statement in tampering {
            let (_dir, pool) = db();
            let conn = pool.get().unwrap();
            let bulk = write_tx(&conn, |tx| {
                append_entry_at(
                    tx,
                    SECRET,
                    &NewEntry {
                        action: "bulk",
                        target_id: "1",
                        target_ids: "[\"1\",\"2\",\"3\"]",
                        operator: "alice",
                        note: "approved|signed-off",
                        details: String::new(),
                        signal_class: "wifi",
                        freq_hz: 0.0,
                        node_id: "",
                        tenant_id: T,
                    },
                    &utc_now_iso(),
                )
            })
            .unwrap();
            assert_valid(&conn);
            conn.execute(statement, []).unwrap();
            // Moved to another tenant: that tenant's chain starts from "" too.
            let tenant = if statement.contains("tenant-b") {
                "tenant-b"
            } else {
                T
            };
            let v = verify_chain(&conn, tenant, SECRET).unwrap();
            assert!(!v.valid, "{statement}");
            assert_eq!(v.errors.iter().map(|e| e.id).collect::<Vec<_>>(), [bulk.id]);
        }
    }

    fn by_severity(conn: &Connection, severity: &str) -> Vec<String> {
        let filter = AuditFilter {
            severity: Some(severity),
            ..Default::default()
        };
        let actions: Vec<String> = get_audit_log(conn, T, &filter, 100, 0)
            .unwrap()
            .into_iter()
            .map(|e| e.action)
            .collect();
        assert_eq!(
            count_audit_log(conn, T, &filter).unwrap(),
            actions.len() as i64,
            "{severity}"
        );
        actions
    }

    #[test]
    fn severity_filter_tolerates_entries_without_valid_details() {
        let (_dir, pool) = db();
        let conn = pool.get().unwrap();
        // A warning, written by the gateway.
        log(&conn, "password_change");
        // The bridge stores '' for an entry logged without details (a
        // dismiss, account audits, bulk RF actions); older or tampered rows
        // may hold NULL or invalid JSON. json_extract rejects all but NULL.
        for (action, details) in [
            ("bridge_dismiss", Some("")),
            ("null_details", None),
            ("broken_details", Some("{broken")),
            ("array_details", Some("[1, 2]")),
            ("no_severity_key", Some("{\"reason\":\"fp\"}")),
            ("null_severity", Some("{\"severity\":null}")),
            ("critical", Some("{\"severity\":\"critical\"}")),
        ] {
            conn.execute(
                "INSERT INTO audit_log (timestamp, action, target_id, details, tenant_id) \
                 VALUES (?1, ?2, 't', ?3, ?4)",
                params![utc_now_iso(), action, details, T],
            )
            .unwrap();
        }
        // An info entry, written by the gateway.
        log(&conn, "login");

        assert_eq!(by_severity(&conn, "warning"), ["password_change"]);
        assert_eq!(by_severity(&conn, "critical"), ["critical"]);
        // Like the bridge: no severity counts as info.
        assert_eq!(
            by_severity(&conn, "info"),
            [
                "login",
                "null_severity",
                "no_severity_key",
                "array_details",
                "broken_details",
                "null_details",
                "bridge_dismiss",
            ]
        );
        // The value is bound, never spliced into the SQL.
        assert!(by_severity(&conn, "' OR '1'='1").is_empty());
        assert!(by_severity(&conn, "x') OR 1=1 --").is_empty());
    }

    /// Audit rows as the bridge stores them, oldest first: details that are
    /// `''`, NULL, invalid JSON or record no severity, notes holding LIKE
    /// wildcards and a backslash, and a target id holding `_` (`det_42`,
    /// which no note or action contains). (timestamp, action, target_id,
    /// operator, node_id, note, details)
    #[allow(clippy::type_complexity)]
    pub(crate) const BRIDGE_AUDIT_ROWS: [(&str, &str, &str, &str, &str, &str, Option<&str>); 8] = [
        (
            "2026-01-01T00:00:00+00:00",
            "login",
            "t1",
            "alice",
            "n1",
            "hello",
            Some(r#"{"severity":"info"}"#),
        ),
        (
            "2026-02-01T00:00:00+00:00",
            "dismiss",
            "t2",
            "bob",
            "n2",
            "false positive",
            Some(""),
        ),
        (
            "2026-03-01T00:00:00+00:00",
            "password_change",
            "t3",
            "alice",
            "n1",
            "pw",
            Some(r#"{"severity":"warning"}"#),
        ),
        (
            "2026-04-01T00:00:00+00:00",
            "critical_thing",
            "t1",
            "carol",
            "n3",
            "crit",
            Some(r#"{"severity":"critical"}"#),
        ),
        (
            "2026-05-01T00:00:00+00:00",
            "broken",
            "t4",
            "bob",
            "n2",
            "x",
            Some("{broken"),
        ),
        (
            "2026-06-01T00:00:00+00:00",
            "login",
            "t5",
            "alice",
            "n1",
            "100% done",
            None,
        ),
        (
            "2026-07-01T00:00:00+00:00",
            "dismiss",
            "t1",
            "bob",
            "n2",
            "a_b",
            Some(r#"{"reason":"fp"}"#),
        ),
        (
            "2026-08-01T00:00:00+00:00",
            "export",
            "det_42",
            "carol",
            "n3",
            "C:\\temp",
            Some(r#"{"severity":"info"}"#),
        ),
    ];

    /// Insert [`BRIDGE_AUDIT_ROWS`] for tenant `default`, and an entry of
    /// tenant `tenant-b` that passes the filters the tests use, all but the
    /// tenant: no listing or total of `default` may include it.
    pub(crate) fn insert_bridge_audit_rows(conn: &Connection) {
        for (ts, action, target, operator, node, note, details) in BRIDGE_AUDIT_ROWS {
            conn.execute(
                "INSERT INTO audit_log (timestamp, action, target_id, operator, node_id, note, \
                 details, tenant_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'default')",
                params![ts, action, target, operator, node, note, details],
            )
            .unwrap();
        }
        conn.execute(
            "INSERT INTO audit_log (timestamp, action, target_id, operator, node_id, note, \
             details, tenant_id) VALUES ('2026-03-01T00:00:00+00:00', 'login', 't1', 'alice', \
             'n1', 'hello pw', '{\"severity\":\"info\"}', 'tenant-b')",
            [],
        )
        .unwrap();
    }

    /// A filter on one field.
    fn only<'a>(field: &str, value: &'a str) -> AuditFilter<'a> {
        let mut f = AuditFilter::default();
        let slot = match field {
            "action" => &mut f.action,
            "target_id" => &mut f.target_id,
            "operator" => &mut f.operator,
            "node_id" => &mut f.node_id,
            "search" => &mut f.search,
            "start" => &mut f.start,
            "end" => &mut f.end,
            "severity" => &mut f.severity,
            _ => unreachable!("{field}"),
        };
        *slot = Some(value);
        f
    }

    #[test]
    fn count_audit_log_counts_what_get_audit_log_lists_for_every_filter() {
        let (_dir, pool) = db();
        let conn = pool.get().unwrap();
        insert_bridge_audit_rows(&conn);

        let every = AuditFilter {
            action: Some("login"),
            target_id: Some("t1"),
            operator: Some("alice"),
            node_id: Some("n1"),
            search: Some("hell"),
            start: Some("2026-01-01T00:00:00+00:00"),
            end: Some("2026-12-31T00:00:00+00:00"),
            severity: Some("info"),
        };
        // The bridge's counts over the same rows.
        let cases = [
            (AuditFilter::default(), 8),
            (only("action", "login"), 2),
            (only("target_id", "t1"), 3),
            (only("operator", "alice"), 3),
            (only("node_id", "n2"), 3),
            (only("search", "pw"), 1),
            (only("search", "%"), 1),
            (only("search", "_"), 4),
            (only("search", "\\t"), 1),
            // Only the target id holds it: each LIKE escapes its pattern.
            (only("search", "det_42"), 1),
            (only("start", "2026-03-01T00:00:00+00:00"), 6),
            (only("end", "2026-03-01T00:00:00+00:00"), 3),
            (only("severity", "info"), 6),
            (only("severity", "warning"), 1),
            (only("severity", "critical"), 1),
            (only("severity", "' OR '1'='1"), 0),
            (every, 1),
        ];
        for (filter, expected) in cases {
            let listed = get_audit_log(&conn, T, &filter, 1000, 0).unwrap();
            assert_eq!(listed.len() as i64, expected, "{filter:?}");
            let total = count_audit_log(&conn, T, &filter).unwrap();
            assert_eq!(total, expected, "{filter:?}");
            // A page of it reports the filtered total, not the page size.
            let (page, total) = get_audit_page(&conn, T, &filter, 1, 0).unwrap();
            assert_eq!((page.len() as i64, total), (expected.min(1), expected));
        }
    }

    /// [`get_audit_page`] reads the page and the total from one snapshot:
    /// an entry another connection (the bridge, another request) commits
    /// between the two reads is in neither, so `total` never counts an
    /// entry the pages do not hold.
    #[test]
    fn get_audit_page_reads_the_page_and_the_total_from_one_snapshot() {
        use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let (dir, pool) = db();
        let mut conn = pool.get().unwrap();
        insert_bridge_audit_rows(&conn);
        // SQLite asks the authorizer about a statement while it compiles
        // it. When the count query is compiled (it alone calls count()), the
        // page query has run: another connection then commits an entry the
        // filter selects. (Counting SELECT callbacks instead depends on how
        // often a SQLite release asks about them.)
        let path = dir.path().join("audit.db");
        let writes = Arc::new(AtomicUsize::new(0));
        let hook_writes = Arc::clone(&writes);
        let mut written_once = false;
        conn.authorizer(Some(move |ctx: AuthContext<'_>| {
            if let AuthAction::Function { function_name } = ctx.action {
                if function_name.eq_ignore_ascii_case("count") && !written_once {
                    written_once = true;
                    let written = Connection::open(&path).and_then(|writer| {
                        writer.execute(
                            "INSERT INTO audit_log (timestamp, action, target_id, tenant_id) \
                             VALUES ('2026-09-01T00:00:00+00:00', 'login', 't7', 'default')",
                            [],
                        )
                    });
                    if matches!(written, Ok(1)) {
                        hook_writes.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
            Authorization::Allow
        }))
        .unwrap();
        let (page, total) = get_audit_page(&conn, T, &AuditFilter::default(), 100, 0).unwrap();
        conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>)
            .unwrap();
        assert_eq!(
            writes.load(Ordering::SeqCst),
            1,
            "no entry was written between the reads"
        );
        assert_eq!((page.len() as i64, total), (8, 8));

        // The next page and total both hold it.
        let (page, total) = get_audit_page(&conn, T, &AuditFilter::default(), 100, 0).unwrap();
        assert_eq!((page.len() as i64, total), (9, 9));
    }

    #[test]
    fn verify_does_not_report_the_digest_that_would_re_sign_a_tampered_entry() {
        let (_dir, pool) = db();
        let conn = pool.get().unwrap();
        let first = log(&conn, "first");
        log(&conn, "second");
        log(&conn, "third");
        conn.execute(
            "UPDATE audit_log SET note = 'forged' WHERE id = ?1",
            params![first],
        )
        .unwrap();

        let v = verify_chain(&conn, T, SECRET).unwrap();
        assert_eq!(v.errors.iter().map(|e| e.id).collect::<Vec<_>>(), [first]);
        assert_eq!(v.errors[0].expected, HMAC_MISMATCH);
        // The HMAC the tampered row would need appears nowhere in the report.
        let walker = ChainWalker::new(SECRET, T);
        let mut stmt = conn.prepare(CHAIN_ROWS_SQL).unwrap();
        let row = stmt.query_row(params![T], ChainRow::from_row).unwrap();
        let resigned = walker.v3(&row, "");
        let report = serde_json::to_string(&v).unwrap();
        assert!(!report.contains(&resigned), "{report}");

        // Storing what the report says is expected, entry by entry, does
        // not launder the tampering.
        for _ in 0..3 {
            for error in verify_chain(&conn, T, SECRET).unwrap().errors {
                conn.execute(
                    "UPDATE audit_log SET hmac_chain = ?1 WHERE id = ?2",
                    params![error.expected, error.id],
                )
                .unwrap();
            }
        }
        assert!(!verify_chain(&conn, T, SECRET).unwrap().valid);
    }

    #[test]
    fn archive_keeps_the_chain_verifiable_for_gateway_and_bridge() {
        let (_dir, pool, old) = archived_db();
        let conn = pool.get().unwrap();

        // Before the fix verification restarted from "" and reported the
        // oldest remaining entry as tampered forever.
        let v = assert_valid(&conn);
        assert_eq!(v.total, 4, "3 live entries + the archive marker");
        let anchor = v.anchor.expect("anchor reported");
        assert!(anchor.authentic);
        assert_eq!(anchor.last_archived_id, old[4].id);
        assert_eq!(anchor.archived_total, 5);
        assert!(
            bridge_verifier_findings(&conn).is_empty(),
            "the bridge's verifier must accept the archived chain too"
        );

        // The archived rows are kept, complete, in the archive table.
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM audit_log_archive"), 5);
        assert_eq!(
            count(
                &conn,
                "SELECT COUNT(*) FROM audit_log WHERE action LIKE 'old_%'"
            ),
            0
        );

        // The marker records who archived what, with the terminal HMAC.
        let marker = latest(&conn, "archive_marker");
        assert_eq!(marker.operator, "admin");
        assert_eq!(marker.details["archived_count"], 5);
        assert_eq!(marker.details["terminal_hmac"], old[4].hmac_chain.as_str());
        assert_eq!(marker.details["last_archived_id"], old[4].id);
        assert_eq!(marker.details["severity"], "warning");

        // Writers keep chaining after the archive.
        log(&conn, "after_archive");
        assert_valid(&conn);
        assert!(bridge_verifier_findings(&conn).is_empty());
    }

    #[test]
    fn repeated_archives_advance_the_anchor() {
        let (_dir, pool) = db();
        let conn = pool.get().unwrap();
        for i in 0..3 {
            entry_at(&conn, &format!("oldest_{i}"), &days_ago(60));
        }
        let middle: Vec<AuditEntry> = (0..3)
            .map(|i| entry_at(&conn, &format!("older_{i}"), &days_ago(30)))
            .collect();
        log(&conn, "recent");

        let first = archive_audit_log(&conn, T, 45, 7, SECRET, "admin").unwrap();
        assert_eq!(first.moved, 3);
        assert_valid(&conn);
        let second = archive_audit_log(&conn, T, 20, 7, SECRET, "admin").unwrap();
        assert_eq!(second.moved, 3);
        assert_eq!(second.last_archived_id, Some(middle[2].id));

        let v = assert_valid(&conn);
        assert_eq!(v.anchor.as_ref().unwrap().archived_total, 6);
        assert!(bridge_verifier_findings(&conn).is_empty());
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM audit_log_archive"), 6);
    }

    #[test]
    fn archive_and_purge_refuse_entries_younger_than_the_minimum_retention() {
        let (_dir, pool) = db();
        let conn = pool.get().unwrap();
        for i in 0..3 {
            log(&conn, &format!("e{i}"));
        }
        // The wipe: archive {"days":0} then DELETE ?days=0.
        assert!(matches!(
            archive_audit_log(&conn, T, 0, 7, SECRET, "admin"),
            Err(AuditOpError::Invalid(_))
        ));
        assert!(matches!(
            archive_audit_log(&conn, T, 6, 7, SECRET, "admin"),
            Err(AuditOpError::Invalid(_))
        ));
        assert!(matches!(
            purge_archived(&conn, T, 0, 7, SECRET, "admin"),
            Err(AuditOpError::Invalid(_))
        ));
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM audit_log"), 3);

        // At the minimum, nothing this recent moves; the attempt is audited.
        let outcome = archive_audit_log(&conn, T, 7, 7, SECRET, "admin").unwrap();
        assert_eq!((outcome.moved, outcome.last_archived_id), (0, None));
        assert_eq!(latest(&conn, "audit_archive").id, outcome.event_id);
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM audit_log"), 4);
        assert_valid(&conn);
    }

    #[test]
    fn purge_deletes_only_old_archived_rows_and_is_audited() {
        let (_dir, pool) = db();
        let conn = pool.get().unwrap();
        for i in 0..3 {
            entry_at(&conn, &format!("forty_{i}"), &days_ago(40));
        }
        for i in 0..2 {
            entry_at(&conn, &format!("ten_{i}"), &days_ago(10));
        }
        log(&conn, "now");
        let archived = archive_audit_log(&conn, T, 7, 7, SECRET, "admin").unwrap();
        assert_eq!(archived.moved, 5);

        let purged = purge_archived(&conn, T, 30, 7, SECRET, "root").unwrap();
        assert_eq!(purged.deleted, 3);
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM audit_log_archive"), 2);
        assert_eq!(
            count(&conn, "SELECT COUNT(*) FROM audit_log WHERE action = 'now'"),
            1
        );

        let event = latest(&conn, "audit_purge");
        assert_eq!(event.id, purged.event_id);
        assert_eq!(event.operator, "root");
        assert_eq!(event.details["deleted"], 3);
        assert_eq!(event.details["severity"], "warning");
        assert_valid(&conn);
    }

    #[test]
    fn purge_never_deletes_rows_not_archived_under_an_anchor() {
        let (_dir, pool) = db();
        let conn = pool.get().unwrap();
        ensure_archive_tables(&conn).unwrap();
        conn.execute(
            "INSERT INTO audit_log_archive (id, timestamp, action, target_id, tenant_id, \
             hmac_chain) VALUES (1, ?1, 'x', '', 'default', '')",
            params![days_ago(90)],
        )
        .unwrap();
        let purged = purge_archived(&conn, T, 30, 7, SECRET, "admin").unwrap();
        assert_eq!(purged.deleted, 0);
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM audit_log_archive"), 1);
    }

    #[test]
    fn removing_the_oldest_live_entry_after_an_archive_is_detected() {
        let (_dir, pool, old) = archived_db();
        let conn = pool.get().unwrap();
        conn.execute(
            "DELETE FROM audit_log WHERE id = ?1",
            params![old[4].id + 1],
        )
        .unwrap();
        let v = verify_chain(&conn, T, SECRET).unwrap();
        assert!(!v.valid);
        assert_eq!(v.gaps.len(), 1, "{v:?}");
        assert_eq!(v.errors.len(), 1, "{v:?}");
    }

    #[test]
    fn an_edited_anchor_is_detected_and_blocks_archive_and_purge() {
        let (_dir, pool, _old) = archived_db();
        let conn = pool.get().unwrap();
        conn.execute("UPDATE audit_anchor SET archived_total = 1", [])
            .unwrap();
        let v = verify_chain(&conn, T, SECRET).unwrap();
        assert!(!v.valid);
        assert!(!v.anchor.unwrap().authentic);
        assert!(matches!(
            archive_audit_log(&conn, T, 7, 7, SECRET, "admin"),
            Err(AuditOpError::Refused(_))
        ));
        assert!(matches!(
            purge_archived(&conn, T, 7, 7, SECRET, "admin"),
            Err(AuditOpError::Refused(_))
        ));
    }

    #[test]
    fn a_removed_anchor_is_detected() {
        let (_dir, pool, _old) = archived_db();
        let conn = pool.get().unwrap();
        conn.execute("DELETE FROM audit_anchor", []).unwrap();
        let v = verify_chain(&conn, T, SECRET).unwrap();
        assert!(!v.valid, "{v:?}");
        assert!(v
            .errors
            .iter()
            .any(|e| e.actual.contains("anchor is missing")));
        assert!(v
            .errors
            .iter()
            .any(|e| e.actual == "archive anchor missing"));

        // With the archived rows gone too, the marker still gives it away.
        conn.execute("DELETE FROM audit_log_archive", []).unwrap();
        assert!(!verify_chain(&conn, T, SECRET).unwrap().valid);
    }

    #[test]
    fn archive_refuses_a_prefix_that_fails_verification() {
        let (_dir, pool) = db();
        let conn = pool.get().unwrap();
        let old: Vec<AuditEntry> = (0..3)
            .map(|i| entry_at(&conn, &format!("old_{i}"), &days_ago(30)))
            .collect();
        conn.execute(
            "UPDATE audit_log SET note = 'rewritten' WHERE id = ?1",
            params![old[1].id],
        )
        .unwrap();
        assert!(matches!(
            archive_audit_log(&conn, T, 7, 7, SECRET, "admin"),
            Err(AuditOpError::Refused(_))
        ));
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM audit_log"), 3);
        assert!(load_anchor(&conn, T).unwrap().is_none());
    }

    /// The newest entry deleted, and the chain then going on from the one
    /// before it, leaves every HMAC valid: only the id gap shows it. A
    /// prefix holding such a gap is not archived either, which would move
    /// the gap out of the live log and seal the rest under a fresh anchor,
    /// hiding the deletion for good.
    #[test]
    fn archive_refuses_a_prefix_with_a_deleted_entry() {
        let (_dir, pool) = db();
        let conn = pool.get().unwrap();
        let first = entry_at(&conn, "old_0", &days_ago(30));
        let deleted = entry_at(&conn, "old_1", &days_ago(30));
        conn.execute("DELETE FROM audit_log WHERE id = ?1", params![deleted.id])
            .unwrap();
        let after = entry_at(&conn, "old_2", &days_ago(30));
        log(&conn, "recent");
        let v = verify_chain(&conn, T, SECRET).unwrap();
        assert!(v.errors.is_empty(), "{v:?}");
        let gaps: Vec<(i64, i64, i64)> = v
            .gaps
            .iter()
            .map(|g| (g.after_id, g.before_id, g.missing))
            .collect();
        assert_eq!(gaps, [(first.id, after.id, 1)]);

        let refused = archive_audit_log(&conn, T, 7, 7, SECRET, "admin");
        let Err(AuditOpError::Refused(reason)) = &refused else {
            panic!("archived past a gap: {refused:?}")
        };
        assert!(reason.contains("(0 error(s), 1 gap(s))"), "{reason}");
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM audit_log"), 3);
        assert!(load_anchor(&conn, T).unwrap().is_none());
        assert_eq!(verify_chain(&conn, T, SECRET).unwrap().gaps.len(), 1);
    }

    #[test]
    fn archive_accepts_an_archive_table_from_an_older_gateway() {
        let (_dir, pool) = db();
        let conn = pool.get().unwrap();
        // The layout the previous gateway created (no target_ids, other order).
        conn.execute_batch(
            "CREATE TABLE audit_log_archive (id INTEGER PRIMARY KEY, timestamp TEXT, \
             action TEXT, target_id TEXT, operator TEXT, note TEXT, details TEXT, \
             signal_class TEXT, freq_hz REAL, node_id TEXT, tenant_id TEXT, hmac_chain TEXT)",
        )
        .unwrap();
        // target_ids is authenticated (v3), so it is set when written.
        let old = write_tx(&conn, |tx| {
            append_entry_at(
                tx,
                SECRET,
                &NewEntry {
                    action: "old",
                    target_id: "a",
                    target_ids: "[\"a\",\"b\"]",
                    operator: "alice",
                    note: "note",
                    details: with_severity("", "info"),
                    signal_class: "",
                    freq_hz: 0.0,
                    node_id: "",
                    tenant_id: T,
                },
                &days_ago(30),
            )
        })
        .unwrap();
        let outcome = archive_audit_log(&conn, T, 7, 7, SECRET, "admin").unwrap();
        assert_eq!(outcome.moved, 1);
        let (note, target_ids, hmac): (String, String, String) = conn
            .query_row(
                "SELECT note, target_ids, hmac_chain FROM audit_log_archive WHERE id = ?1",
                params![old.id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(note, "note");
        assert_eq!(target_ids, "[\"a\",\"b\"]");
        assert_eq!(hmac, old.hmac_chain);
        assert_valid(&conn);
    }

    #[test]
    fn a_writer_holding_the_write_lock_neither_loses_nor_forks_the_entry() {
        let (_dir, pool) = db();
        let holder = pool.get().unwrap();
        let mut writer = pool.get().unwrap();
        log(&holder, "first");

        // Another writer (the bridge, say) holds the write lock while the
        // gateway logs. With a DEFERRED transaction the gateway read the
        // chain head from its snapshot, then failed with SQLITE_BUSY when
        // upgrading to write after the other writer committed — the entry
        // was lost, and the callers swallowed the error.
        holder.execute_batch("BEGIN IMMEDIATE").unwrap();
        append_entry(
            &holder,
            SECRET,
            &NewEntry {
                action: "concurrent",
                target_id: "",
                target_ids: "",
                operator: "",
                note: "",
                details: with_severity("", "info"),
                signal_class: "",
                freq_hz: 0.0,
                node_id: "",
                tenant_id: T,
            },
        )
        .unwrap();

        // Deterministic, without sleeping: the gateway's busy handler
        // reports that it waits for the lock, and the other writer commits
        // only then. A gateway that gives up instead of waiting reports its
        // result first, while the lock is still held.
        enum Event {
            Waiting,
            Done(rusqlite::Result<i64>),
        }
        let (events, event) = std::sync::mpsc::channel();
        let (go, wait_for_go) = std::sync::mpsc::channel::<()>();
        let waiting = events.clone();
        writer
            .busy_handler(Some(move |_retries: i32| {
                let _ = waiting.send(Event::Waiting);
                wait_for_go.recv().is_ok()
            }))
            .unwrap();
        let gateway = std::thread::spawn(move || {
            let logged = log_audit(
                &writer, SECRET, "gateway", "t", "op", "", "", "", 0.0, "", T,
            );
            writer.busy_handler(None::<fn(i32) -> bool>).unwrap();
            let _ = events.send(Event::Done(logged));
        });
        let mut next = event.recv().unwrap();
        holder.execute_batch("COMMIT").unwrap();
        let _ = go.send(());
        // Any later wait fails at once instead of blocking the test.
        drop(go);
        let logged = loop {
            if let Event::Done(logged) = next {
                break logged;
            }
            next = event.recv().unwrap();
        };
        gateway.join().unwrap();

        assert!(logged.is_ok(), "the entry must be written: {logged:?}");
        let v = assert_valid(&holder);
        assert_eq!(v.total, 3);
    }

    #[test]
    fn log_audit_inside_a_caller_transaction_uses_a_savepoint() {
        let (_dir, pool) = db();
        let conn = pool.get().unwrap();
        conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        log(&conn, "rolled_back");
        conn.execute_batch("ROLLBACK").unwrap();
        conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        log(&conn, "committed");
        conn.execute_batch("COMMIT").unwrap();
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM audit_log"), 1);
        assert_valid(&conn);
    }

    /// The process-wide sink, set once for every test that needs it.
    pub(crate) fn test_sink() -> broadcast::Sender<String> {
        static SINK: OnceLock<broadcast::Sender<String>> = OnceLock::new();
        SINK.get_or_init(|| {
            let (tx, _) = broadcast::channel(4096);
            set_event_sink(tx.clone());
            tx
        })
        .clone()
    }

    #[test]
    fn written_entries_are_published_to_the_event_sink() {
        let mut rx = test_sink().subscribe();
        let (_dir, pool) = db();
        let conn = pool.get().unwrap();
        let action = format!("sink_probe_{}", uuid::Uuid::new_v4().simple());
        let id = log(&conn, &action);
        let published = std::iter::from_fn(|| rx.try_recv().ok())
            .map(|m| serde_json::from_str::<serde_json::Value>(&m).unwrap())
            .find(|m| m["action"] == action.as_str())
            .expect("entry published");
        assert_eq!(published["id"], id);
    }

    #[test]
    fn min_retention_parsing() {
        assert_eq!(parse_min_retention(None), DEFAULT_MIN_RETENTION_DAYS);
        assert_eq!(parse_min_retention(Some("")), DEFAULT_MIN_RETENTION_DAYS);
        assert_eq!(parse_min_retention(Some(" 30 ")), 30);
        assert_eq!(parse_min_retention(Some("0")), 1);
        assert_eq!(parse_min_retention(Some("-3")), DEFAULT_MIN_RETENTION_DAYS);
        assert_eq!(
            parse_min_retention(Some("week")),
            DEFAULT_MIN_RETENTION_DAYS
        );
    }

    #[test]
    fn new_admin_actions_are_warnings() {
        for action in [
            "security_settings_changed",
            "archive_marker",
            "audit_archive",
            "audit_purge",
        ] {
            assert_eq!(classify_severity(action), "warning", "{action}");
        }
        assert_eq!(classify_severity("login"), "info");
    }

    /// The ids between two entries of one tenant that another tenant holds,
    /// in the live log or in the archive, are not missing rows; one of the
    /// tenant's own that disappears is, net of the other tenant's ids.
    #[test]
    fn ids_held_by_other_tenants_live_or_archived_are_not_gaps() {
        const B: &str = "tenant-b";
        let (_dir, pool) = db();
        let conn = pool.get().unwrap();
        // Ids 1..6 alternate between the two tenants.
        let mut own = Vec::new();
        for i in 0..2 {
            own.push(entry_at(&conn, &format!("a_old_{i}"), &days_ago(30)).id);
            tenant_entry_at(&conn, B, &format!("b_old_{i}"), &days_ago(30));
        }
        own.push(log(&conn, "a_new"));
        log_audit(&conn, SECRET, "b_new", "t", "op", "", "", "", 0.0, "", B).unwrap();
        for tenant in [T, B] {
            let v = verify_chain(&conn, tenant, SECRET).unwrap();
            assert!(v.valid && v.gaps.is_empty(), "{tenant}: {v:?}");
        }

        // tenant-b's old entries move to the archive: their ids still
        // account for the holes in the other chain.
        let outcome = archive_audit_log(&conn, B, 7, 7, SECRET, "admin").unwrap();
        assert_eq!(outcome.moved, 2);
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM audit_log_archive"), 2);
        assert_valid(&conn);
        assert!(verify_chain(&conn, B, SECRET).unwrap().valid);

        conn.execute("DELETE FROM audit_log WHERE id = ?1", params![own[1]])
            .unwrap();
        let v = verify_chain(&conn, T, SECRET).unwrap();
        assert!(!v.valid);
        let gaps: Vec<(i64, i64, i64)> = v
            .gaps
            .iter()
            .map(|g| (g.after_id, g.before_id, g.missing))
            .collect();
        assert_eq!(gaps, [(own[0], own[2], 1)]);
    }

    /// A row put back into the live log with an id at or below the archive
    /// anchor (restored from the archive, or forged into a free id) is
    /// reported as such, and the anchor still marks where the chain goes on.
    #[test]
    fn an_entry_restored_below_the_archive_anchor_is_reported() {
        let (_dir, pool, old) = archived_db();
        let conn = pool.get().unwrap();
        let restored = old[2].id;
        conn.execute(
            &format!(
                "INSERT INTO audit_log ({ARCHIVE_COLUMNS}) \
                 SELECT {ARCHIVE_COLUMNS} FROM audit_log_archive WHERE id = ?1"
            ),
            params![restored],
        )
        .unwrap();

        let v = verify_chain(&conn, T, SECRET).unwrap();
        assert!(!v.valid);
        assert!(v.anchor.as_ref().unwrap().authentic);
        let predates: Vec<(i64, &str)> = v
            .errors
            .iter()
            .filter(|e| e.actual == "row predates the archive anchor")
            .map(|e| (e.id, e.expected.as_str()))
            .collect();
        let expected = format!("id after the archive anchor ({})", old[4].id);
        assert_eq!(predates, [(restored, expected.as_str())], "{v:?}");
        // The live entries after the anchor are not "missing" because of it.
        assert!(v.gaps.is_empty(), "{v:?}");
    }

    /// Rows written before the HMAC chain existed carry no HMAC; the next
    /// entry chains from the legacy sentinel (as on the bridge), never from
    /// "" — so blanking a signed entry's HMAC does not pass it off as one.
    #[test]
    fn entries_after_rows_that_predate_the_chain_chain_from_the_sentinel() {
        let (_dir, pool) = db();
        let conn = pool.get().unwrap();
        for action in ["legacy_1", "legacy_2"] {
            conn.execute(
                "INSERT INTO audit_log (timestamp, action, target_id, tenant_id) \
                 VALUES ('2023-01-01T00:00:00+00:00', ?1, 't', ?2)",
                params![action, T],
            )
            .unwrap();
        }
        let first_signed = log(&conn, "signed_1");
        let second_signed = log(&conn, "signed_2");
        let v = assert_valid(&conn);
        assert_eq!((v.total, v.checked), (4, 2));
        assert!(bridge_verifier_findings(&conn).is_empty());

        conn.execute(
            "UPDATE audit_log SET hmac_chain = '' WHERE id = ?1",
            params![first_signed],
        )
        .unwrap();
        let v = verify_chain(&conn, T, SECRET).unwrap();
        assert_eq!(
            v.errors.iter().map(|e| e.id).collect::<Vec<_>>(),
            [second_signed]
        );
    }

    /// Both writers sign every entry they write, so rows that predate the
    /// chain come before its first signed row, and an entry without an HMAC
    /// after signed ones can only have been written by someone without the
    /// key: a forged entry appended to the chain, or the newest entry
    /// rewritten and its HMAC blanked (blanking every HMAC from an entry on
    /// hides a rewrite of any of them). Neither may verify as intact. The
    /// bridge's verifier (`verify_chain` in sigrift/bridge/storage/audit.py)
    /// reports such rows in the same way.
    #[test]
    fn an_unsigned_entry_after_signed_entries_is_reported() {
        let (_dir, pool) = db();
        let conn = pool.get().unwrap();
        log(&conn, "first");
        let second = log(&conn, "second");
        let newest = log(&conn, "third");
        conn.execute(
            "INSERT INTO audit_log (timestamp, action, target_id, operator, tenant_id) \
             VALUES (?1, 'user_login', 'admin', 'admin', ?2)",
            params![utc_now_iso(), T],
        )
        .unwrap();
        let forged = conn.last_insert_rowid();
        let mut passed_as_intact = Vec::new();
        if verify_chain(&conn, T, SECRET).unwrap().valid {
            passed_as_intact.push(format!("forged unsigned entry {forged}"));
        }
        conn.execute("DELETE FROM audit_log WHERE id = ?1", params![forged])
            .unwrap();
        assert_valid(&conn);

        for (rewritten, what) in [(newest, "the newest entry"), (second, "an older entry")] {
            conn.execute(
                "UPDATE audit_log SET note = 'rewritten' WHERE id = ?1",
                params![rewritten],
            )
            .unwrap();
            // Blank the HMAC of the rewritten entry and of every later one.
            conn.execute(
                "UPDATE audit_log SET hmac_chain = '' WHERE id >= ?1",
                params![rewritten],
            )
            .unwrap();
            if verify_chain(&conn, T, SECRET).unwrap().valid {
                passed_as_intact.push(format!("{what} ({rewritten}) rewritten"));
            }
        }
        assert!(passed_as_intact.is_empty(), "{passed_as_intact:?}");
    }

    /// The ids of the entries reported as unsigned after signed ones.
    fn missing_hmac_ids(v: &ChainVerification) -> Vec<i64> {
        // Same text as the bridge's `_HMAC_MISSING` (its tests pin it too).
        assert_eq!(
            HMAC_MISSING,
            "an HMAC: only entries before the chain's first signed entry may have none"
        );
        v.errors
            .iter()
            .filter(|e| e.expected == HMAC_MISSING)
            .inspect(|e| assert_eq!(e.actual, ""))
            .map(|e| e.id)
            .collect()
    }

    /// Every unsigned entry after the first signed one is reported as such,
    /// counted as checked, and found by the bridge's verifier too. A signed
    /// entry after it chains from the sentinel, as the writers chain it.
    #[test]
    fn each_unsigned_entry_after_a_signed_one_is_reported_by_both_verifiers() {
        let (_dir, pool) = db();
        let conn = pool.get().unwrap();
        log(&conn, "first");
        let blanked = log(&conn, "blanked");
        log(&conn, "third");
        conn.execute(
            "UPDATE audit_log SET hmac_chain = '' WHERE id = ?1",
            params![blanked],
        )
        .unwrap();
        // The writers chain the next entry from the sentinel.
        conn.execute(
            "INSERT INTO audit_log (timestamp, action, target_id, tenant_id) \
             VALUES (?1, 'forged', 't', ?2)",
            params![utc_now_iso(), T],
        )
        .unwrap();
        let forged = conn.last_insert_rowid();
        let after_forged = log(&conn, "after_forged");

        let v = verify_chain(&conn, T, SECRET).unwrap();
        assert!(!v.valid);
        assert_eq!((v.total, v.checked), (5, 5));
        assert_eq!(missing_hmac_ids(&v), [blanked, forged], "{v:?}");
        // "third" was chained from the blanked HMAC; "after_forged" chains
        // from the sentinel and verifies.
        let mismatched: Vec<i64> = v
            .errors
            .iter()
            .filter(|e| e.expected == HMAC_MISMATCH)
            .map(|e| e.id)
            .collect();
        assert_eq!(mismatched, [blanked + 1]);
        assert!(!mismatched.contains(&after_forged));
        assert_eq!(
            bridge_verifier_findings(&conn),
            [blanked, blanked + 1, forged]
        );
    }

    /// An archived prefix that ended with a signed entry counts as the
    /// chain's signed start: blanking the HMAC of every live entry after a
    /// gateway archive (anchor) or a bridge archive (marker) is reported,
    /// though the walk then meets no signed row.
    #[test]
    fn unsigned_entries_after_an_archived_signed_prefix_are_reported() {
        let (_dir, pool, _old) = archived_db();
        let conn = pool.get().unwrap();
        conn.execute("UPDATE audit_log SET hmac_chain = ''", [])
            .unwrap();
        let live: Vec<i64> = conn
            .prepare("SELECT id FROM audit_log ORDER BY id")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        let v = verify_chain(&conn, T, SECRET).unwrap();
        assert!(!v.valid);
        assert!(v.anchor.as_ref().unwrap().authentic);
        assert_eq!(missing_hmac_ids(&v), live, "{v:?}");

        let (_dir, pool) = db();
        let conn = pool.get().unwrap();
        for i in 0..3 {
            entry_at(&conn, &format!("old_{i}"), &days_ago(60));
        }
        log(&conn, "live");
        bridge_archive(&conn, &days_ago(45));
        assert_valid(&conn);
        conn.execute("UPDATE audit_log SET hmac_chain = ''", [])
            .unwrap();
        let live: Vec<i64> = conn
            .prepare("SELECT id FROM audit_log ORDER BY id")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        let v = verify_chain(&conn, T, SECRET).unwrap();
        assert_eq!(missing_hmac_ids(&v), live, "{v:?}");
        assert_eq!(bridge_verifier_findings(&conn), live);
    }

    /// Rows that predate the chain stay accepted across an archive of
    /// them: the anchor (or bridge marker) of a prefix that ended unsigned
    /// does not make the chain signed, so the unsigned rows still before
    /// the first signed one verify on both sides.
    #[test]
    fn rows_that_predate_the_chain_still_verify_after_an_archive_of_some() {
        let insert_legacy = |conn: &Connection, ts: &str| {
            conn.execute(
                "INSERT INTO audit_log (timestamp, action, target_id, tenant_id) \
                 VALUES (?1, 'legacy', 't', ?2)",
                params![ts, T],
            )
            .unwrap();
        };
        let (_dir, pool) = db();
        let conn = pool.get().unwrap();
        insert_legacy(&conn, &days_ago(60));
        insert_legacy(&conn, &days_ago(60));
        insert_legacy(&conn, &utc_now_iso());
        log(&conn, "signed");
        let outcome = archive_audit_log(&conn, T, 7, 7, SECRET, "admin").unwrap();
        assert_eq!(outcome.moved, 2);
        let anchor = load_anchor(&conn, T).unwrap().unwrap();
        assert_eq!(anchor.terminal_hmac, LEGACY_NO_HMAC_SENTINEL);
        let v = assert_valid(&conn);
        assert_eq!((v.total, v.checked), (3, 2));

        let (_dir, pool) = db();
        let conn = pool.get().unwrap();
        insert_legacy(&conn, &days_ago(60));
        insert_legacy(&conn, &utc_now_iso());
        log(&conn, "signed");
        let marker = bridge_archive(&conn, &days_ago(45));
        assert_eq!(marker.details["terminal_hmac"], "");
        let v = assert_valid(&conn);
        assert_eq!((v.total, v.checked), (3, 2));
        assert!(bridge_verifier_findings(&conn).is_empty());
    }

    /// The archive verifies the prefix it moves, so it refuses one with an
    /// unsigned entry after a signed one instead of sealing it behind a
    /// fresh anchor.
    #[test]
    fn an_unsigned_entry_after_a_signed_one_is_never_archived() {
        let (_dir, pool) = db();
        let conn = pool.get().unwrap();
        entry_at(&conn, "old_signed", &days_ago(30));
        conn.execute(
            "INSERT INTO audit_log (timestamp, action, target_id, tenant_id) \
             VALUES (?1, 'forged', 't', ?2)",
            params![days_ago(30), T],
        )
        .unwrap();
        log(&conn, "recent");
        let refused = archive_audit_log(&conn, T, 7, 7, SECRET, "admin");
        assert!(
            matches!(refused, Err(AuditOpError::Refused(_))),
            "{refused:?}"
        );
        assert!(load_anchor(&conn, T).unwrap().is_none());
    }

    /// What the bridge's `archive_audit_log` (sigrift/bridge/storage/
    /// audit.py) does: delete the tenant's entries older than `cutoff`
    /// (markers excepted) without copying them or recording an anchor, and
    /// append an `archive_marker` whose details carry the terminal HMAC of
    /// the deleted block and no `last_archived_id`. Returns the marker.
    fn bridge_archive(conn: &Connection, cutoff: &str) -> AuditEntry {
        const OLD: &str = "FROM audit_log \
                           WHERE tenant_id = ?1 AND timestamp < ?2 AND action != 'archive_marker'";
        let (archived, terminal): (i64, Option<String>) = conn
            .query_row(
                &format!(
                    "SELECT COUNT(*), (SELECT hmac_chain {OLD} ORDER BY id DESC LIMIT 1) {OLD}"
                ),
                params![T, cutoff],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        conn.execute(&format!("DELETE {OLD}"), params![T, cutoff])
            .unwrap();
        let details = serde_json::json!({
            "archived_count": archived,
            "terminal_hmac": terminal.unwrap_or_default(),
            "date_range": "",
        })
        .to_string();
        write_tx(conn, |tx| {
            append_entry_at(
                tx,
                SECRET,
                &NewEntry {
                    action: "archive_marker",
                    target_id: "",
                    target_ids: "",
                    operator: "",
                    note: "",
                    details: details.clone(),
                    signal_class: "",
                    freq_hz: 0.0,
                    node_id: "",
                    tenant_id: T,
                },
                &utc_now_iso(),
            )
        })
        .unwrap()
    }

    /// A prefix the bridge archived (no anchor, a marker carrying the
    /// terminal HMAC) verifies on the gateway, and the gateway can archive
    /// past it: the marker roots its walk, then its own anchor takes over.
    #[test]
    fn a_prefix_the_bridge_archived_verifies_and_can_be_archived_further() {
        let (_dir, pool) = db();
        let conn = pool.get().unwrap();
        let oldest: Vec<AuditEntry> = (0..3)
            .map(|i| entry_at(&conn, &format!("oldest_{i}"), &days_ago(60)))
            .collect();
        let older: Vec<AuditEntry> = (0..2)
            .map(|i| entry_at(&conn, &format!("older_{i}"), &days_ago(30)))
            .collect();
        log(&conn, "recent");

        let marker = bridge_archive(&conn, &days_ago(45));
        assert_eq!(marker.details["archived_count"], 3);
        assert_eq!(
            marker.details["terminal_hmac"],
            oldest[2].hmac_chain.as_str()
        );
        let v = assert_valid(&conn);
        assert_eq!((v.total, v.checked), (4, 4));
        assert!(v.anchor.is_none());
        assert!(bridge_verifier_findings(&conn).is_empty());

        let outcome = archive_audit_log(&conn, T, 7, 7, SECRET, "admin").unwrap();
        assert_eq!(
            (outcome.moved, outcome.last_archived_id),
            (2, Some(older[1].id))
        );
        let v = assert_valid(&conn);
        assert_eq!(v.anchor.unwrap().archived_total, 2);
        assert!(bridge_verifier_findings(&conn).is_empty());
    }

    /// The terminal HMAC of a bridge archive vouches only for the first
    /// entry after it: a copy of that entry appended later in the chain is
    /// reported, not accepted because it chains from the marker's HMAC.
    #[test]
    fn a_replayed_copy_of_the_first_entry_after_a_bridge_archive_is_reported() {
        let (_dir, pool) = db();
        let conn = pool.get().unwrap();
        for i in 0..3 {
            entry_at(&conn, &format!("old_{i}"), &days_ago(60));
        }
        let first_live = log(&conn, "first_live");
        log(&conn, "second_live");
        bridge_archive(&conn, &days_ago(45));
        assert_valid(&conn);

        conn.execute(
            &format!(
                "INSERT INTO audit_log ({0}) SELECT {0} FROM audit_log WHERE id = ?1",
                ARCHIVE_COLUMNS.replacen("id, ", "", 1)
            ),
            params![first_live],
        )
        .unwrap();
        let replay = conn.last_insert_rowid();
        let v = verify_chain(&conn, T, SECRET).unwrap();
        assert!(!v.valid);
        assert_eq!(v.errors.iter().map(|e| e.id).collect::<Vec<_>>(), [replay]);
    }

    /// A write that fails inside a transaction the caller opened is undone
    /// alone: what it wrote before failing is rolled back (an archive whose
    /// marker cannot be appended has already moved the old entries and
    /// sealed an anchor), while the caller's transaction, and the entries
    /// already logged in it, go on, and the chain continues from them.
    #[test]
    fn a_failed_write_inside_a_caller_transaction_is_undone_alone() {
        let (_dir, pool) = db();
        let conn = pool.get().unwrap();
        for i in 0..3 {
            entry_at(&conn, &format!("old_{i}"), &days_ago(30));
        }
        conn.execute_batch(
            "CREATE TRIGGER refuse_writes BEFORE INSERT ON audit_log \
             WHEN NEW.action IN ('doomed', 'archive_marker') \
             BEGIN SELECT RAISE(ABORT, 'audit write unavailable'); END;",
        )
        .unwrap();
        conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        log(&conn, "kept");
        assert!(log_audit(&conn, SECRET, "doomed", "t", "op", "", "", "", 0.0, "", T).is_err());
        let archived = archive_audit_log(&conn, T, 7, 7, SECRET, "admin");
        assert!(matches!(archived, Err(AuditOpError::Db(_))), "{archived:?}");
        log(&conn, "after");
        conn.execute_batch("COMMIT").unwrap();

        let actions: Vec<String> = get_audit_log(&conn, T, &AuditFilter::default(), 10, 0)
            .unwrap()
            .into_iter()
            .map(|e| e.action)
            .collect();
        assert_eq!(actions, ["after", "kept", "old_2", "old_1", "old_0"]);
        assert!(load_anchor(&conn, T).unwrap().is_none());
        assert!(!table_exists(&conn, "audit_log_archive").unwrap());
        assert_valid(&conn);
    }

    /// An entry whose write finds the database busy (another writer, the
    /// bridge say, holds the write lock past `busy_timeout`) is retried,
    /// not lost. Deterministic: the busy handler lets the other writer go
    /// and still reports the attempt busy, so only a retry writes it.
    #[test]
    fn an_entry_whose_write_finds_the_database_busy_is_retried() {
        use std::sync::{Arc, Mutex};
        let (dir, pool) = db();
        let mut conn = pool.get().unwrap();
        log(&conn, "before");
        let other = Connection::open(dir.path().join("audit.db")).unwrap();
        other.execute_batch("BEGIN IMMEDIATE").unwrap();
        let other = Arc::new(Mutex::new(Some(other)));
        conn.busy_handler(Some({
            let other = Arc::clone(&other);
            move |_retries: i32| {
                // Closing the connection rolls its transaction back.
                drop(other.lock().unwrap().take());
                false
            }
        }))
        .unwrap();

        let logged = log_audit(&conn, SECRET, "during", "t", "op", "", "", "", 0.0, "", T);
        conn.busy_handler(None::<fn(i32) -> bool>).unwrap();
        // The handler ran, so the first attempt found the database busy.
        assert!(other.lock().unwrap().is_none());
        logged.expect("the retry writes the entry");
        let actions: Vec<String> = get_audit_log(&conn, T, &AuditFilter::default(), 10, 0)
            .unwrap()
            .into_iter()
            .map(|e| e.action)
            .collect();
        assert_eq!(actions, ["during", "before"]);
        assert_valid(&conn);
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;
    use crate::test_support::logs_of;

    const SECRET: &[u8] = b"coverage-audit-secret-0123456789";
    const T: &str = "default";

    /// A database holding the bridge's `audit_log`, on a plain connection
    /// (with rusqlite's default busy timeout).
    fn db() -> (tempfile::TempDir, Connection) {
        let dir = tempfile::tempdir().unwrap();
        let conn = Connection::open(dir.path().join("audit.db")).unwrap();
        conn.execute_batch(super::tests::AUDIT_SCHEMA).unwrap();
        (dir, conn)
    }

    fn days_ago(days: i64) -> String {
        (chrono::Utc::now() - chrono::Duration::days(days))
            .format("%Y-%m-%dT%H:%M:%S+00:00")
            .to_string()
    }

    /// Append a correctly chained entry of tenant `T` at `timestamp`.
    fn entry_at(conn: &Connection, action: &str, timestamp: &str) -> AuditEntry {
        append_entry_at(
            conn,
            SECRET,
            &NewEntry {
                action,
                target_id: "target",
                target_ids: "",
                operator: "alice",
                note: "note",
                details: with_severity("", "info"),
                signal_class: "",
                freq_hz: 433_920_000.0,
                node_id: "node-1",
                tenant_id: T,
            },
            timestamp,
        )
        .unwrap()
    }

    fn log(conn: &Connection, action: &str) -> rusqlite::Result<i64> {
        log_audit(conn, SECRET, action, "t", "op", "", "", "", 0.0, "", T)
    }

    fn count(conn: &Connection, sql: &str) -> i64 {
        conn.query_row(sql, [], |row| row.get(0)).unwrap()
    }

    /// The live rows of tenant `T`: id and HMAC, in id order.
    fn live(conn: &Connection) -> Vec<(i64, String)> {
        let mut stmt = conn
            .prepare("SELECT id, hmac_chain FROM audit_log WHERE tenant_id = ?1 ORDER BY id")
            .unwrap();
        stmt.query_map([T], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    fn actions(conn: &Connection) -> Vec<String> {
        get_audit_log(conn, T, &AuditFilter::default(), 50, 0)
            .unwrap()
            .into_iter()
            .map(|e| e.action)
            .collect()
    }

    fn assert_valid(conn: &Connection) {
        let v = verify_chain(conn, T, SECRET).unwrap();
        assert!(v.valid, "chain should verify: {v:?}");
    }

    /// A write that finds the database busy on every attempt (another
    /// writer, the bridge say, holds the write lock the whole time) is
    /// retried a bounded number of times and then fails: nothing is
    /// written, and the failure is logged at error with the action, so a
    /// caller that ignores the result does not lose the event silently.
    /// Once the lock is free the next entry chains as if the failed one had
    /// never been tried.
    #[test]
    fn a_write_busy_on_every_attempt_fails_after_bounded_retries_and_is_logged() {
        let (dir, conn) = db();
        log(&conn, "before").unwrap();
        conn.busy_timeout(Duration::ZERO).unwrap();
        let holder = Connection::open(dir.path().join("audit.db")).unwrap();
        holder.execute_batch("BEGIN IMMEDIATE").unwrap();

        let (logged, logs) = logs_of(|| log(&conn, "blocked_event"));
        let err = logged.unwrap_err();
        assert!(is_busy(&err), "{err}");
        assert!(
            logs.contains("this event is NOT in the audit log"),
            "{logs}"
        );
        assert!(logs.contains("blocked_event"), "{logs}");
        // Retried (the first attempt fails at once, well inside the retry
        // budget), but never more than the attempts allow.
        let retries = logs.matches("retrying the write").count();
        assert!(
            (1..WRITE_ATTEMPTS as usize).contains(&retries),
            "{retries} retries: {logs}"
        );

        holder.execute_batch("ROLLBACK").unwrap();
        log(&conn, "after").unwrap();
        assert_eq!(actions(&conn), ["after", "before"]);
        assert_valid(&conn);
    }

    /// An archive that fails at any of its writes (the copy into the
    /// archive table, the deletion from the live log, the new anchor)
    /// changes nothing: the rows stay live with their HMACs, no anchor and
    /// no marker is left, the archive table holds none of them, the error is
    /// a database error (a 500, not a refusal) and is logged, and the chain
    /// still verifies.
    #[test]
    fn an_archive_that_fails_at_any_write_changes_nothing() {
        let sabotage = [
            // A row already archived under the first live id.
            "INSERT INTO audit_log_archive (id, timestamp, action, target_id, tenant_id, \
             hmac_chain) VALUES (1, '2000-01-01T00:00:00+00:00', 'stray', '', 'other', '')",
            "CREATE TRIGGER keep_live BEFORE DELETE ON audit_log \
             BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END",
            "CREATE TRIGGER no_anchor BEFORE INSERT ON audit_anchor \
             BEGIN SELECT RAISE(ABORT, 'anchor store unavailable'); END",
        ];
        for sql in sabotage {
            let (_dir, conn) = db();
            for i in 0..3 {
                entry_at(&conn, &format!("old_{i}"), &days_ago(30));
            }
            let before = live(&conn);
            ensure_archive_tables(&conn).unwrap();
            conn.execute_batch(sql).unwrap();
            let archived_before = count(&conn, "SELECT COUNT(*) FROM audit_log_archive");

            let (outcome, logs) = logs_of(|| archive_audit_log(&conn, T, 7, 7, SECRET, "admin"));
            let err = outcome.unwrap_err();
            assert!(matches!(err, AuditOpError::Db(_)), "{sql}: {err:?}");
            assert!(
                err.to_string().starts_with("database error: "),
                "{sql}: {err}"
            );
            assert!(
                logs.contains("Audit operation failed — nothing changed"),
                "{sql}: {logs}"
            );

            assert_eq!(live(&conn), before, "{sql}");
            assert_eq!(
                count(&conn, "SELECT COUNT(*) FROM audit_log_archive"),
                archived_before,
                "{sql}"
            );
            assert!(load_anchor(&conn, T).unwrap().is_none(), "{sql}");
            assert_eq!(
                count(
                    &conn,
                    "SELECT COUNT(*) FROM audit_log WHERE action = 'archive_marker'"
                ),
                0,
                "{sql}"
            );
            assert_valid(&conn);
        }
    }

    /// A purge whose deletion fails deletes nothing and records nothing (no
    /// `audit_purge` entry claims rows were purged). Inside a transaction
    /// the caller opened, the failed purge is undone alone: the caller's
    /// entries before and after it are kept. Once the deletion works again
    /// the purge goes through, and archive and purge are logged with their
    /// counts.
    #[test]
    fn a_purge_whose_deletion_fails_deletes_and_records_nothing() {
        let (_dir, conn) = db();
        for i in 0..3 {
            entry_at(&conn, &format!("old_{i}"), &days_ago(40));
        }
        let (archived, logs) = logs_of(|| archive_audit_log(&conn, T, 7, 7, SECRET, "admin"));
        assert_eq!(archived.unwrap().moved, 3);
        assert!(logs.contains("Audit entries archived"), "{logs}");
        assert!(logs.contains("moved=3"), "{logs}");
        conn.execute_batch(
            "CREATE TRIGGER keep_archive BEFORE DELETE ON audit_log_archive \
             BEGIN SELECT RAISE(ABORT, 'the archive is write-once'); END",
        )
        .unwrap();

        let purged = purge_archived(&conn, T, 30, 7, SECRET, "root");
        assert!(matches!(purged, Err(AuditOpError::Db(_))), "{purged:?}");
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM audit_log_archive"), 3);
        assert_eq!(actions(&conn), ["archive_marker"]);

        conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        log(&conn, "kept").unwrap();
        let purged = purge_archived(&conn, T, 30, 7, SECRET, "root");
        assert!(matches!(purged, Err(AuditOpError::Db(_))), "{purged:?}");
        log(&conn, "after").unwrap();
        conn.execute_batch("COMMIT").unwrap();
        assert_eq!(actions(&conn), ["after", "kept", "archive_marker"]);
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM audit_log_archive"), 3);
        assert_valid(&conn);

        conn.execute_batch("DROP TRIGGER keep_archive").unwrap();
        let (purged, logs) = logs_of(|| purge_archived(&conn, T, 30, 7, SECRET, "root"));
        assert_eq!(purged.unwrap().deleted, 3);
        assert!(logs.contains("Archived audit entries purged"), "{logs}");
        assert!(logs.contains("deleted=3"), "{logs}");
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM audit_log_archive"), 0);
        assert_valid(&conn);
    }

    /// Details that are not a JSON object are not stored as given: the
    /// entry gets details holding only its severity, so stored details are
    /// always a valid object the severity filter can read. An object keeps
    /// its fields, with the severity added.
    #[test]
    fn details_that_are_not_a_json_object_are_stored_as_the_severity_alone() {
        let (_dir, conn) = db();
        for (action, details) in [
            ("list", "[1,2]"),
            ("text", "not json"),
            ("empty", "{}"),
            ("object", "{\"ip\":\"10.0.0.1\"}"),
        ] {
            log_audit(
                &conn, SECRET, action, "t", "op", "", details, "", 0.0, "", T,
            )
            .unwrap();
        }
        let stored = |action: &str| -> serde_json::Value {
            let details: String = conn
                .query_row(
                    "SELECT details FROM audit_log WHERE action = ?1",
                    [action],
                    |row| row.get(0),
                )
                .unwrap();
            serde_json::from_str(&details).unwrap()
        };
        let severity_only = serde_json::json!({"severity": "info"});
        assert_eq!(stored("list"), severity_only);
        assert_eq!(stored("text"), severity_only);
        assert_eq!(stored("empty"), severity_only);
        assert_eq!(
            stored("object"),
            serde_json::json!({"severity": "info", "ip": "10.0.0.1"})
        );
        let info = AuditFilter {
            severity: Some("info"),
            ..Default::default()
        };
        assert_eq!(count_audit_log(&conn, T, &info).unwrap(), 4);
        assert_valid(&conn);
    }

    /// A row deleted from the middle of the chain is reported as a gap of
    /// one, the chain as invalid, and the verifier warns about a possible
    /// deletion.
    #[test]
    fn a_deleted_row_is_reported_as_a_gap_and_logged() {
        let (_dir, conn) = db();
        let ids: Vec<i64> = (0..4)
            .map(|i| log(&conn, &format!("e{i}")).unwrap())
            .collect();
        conn.execute("DELETE FROM audit_log WHERE id = ?1", [ids[1]])
            .unwrap();
        let (v, logs) = logs_of(|| verify_chain(&conn, T, SECRET).unwrap());
        assert!(!v.valid);
        assert_eq!(v.gaps.len(), 1, "{v:?}");
        let gap = &v.gaps[0];
        assert_eq!(
            (gap.after_id, gap.before_id, gap.missing),
            (ids[0], ids[2], 1)
        );
        assert!(logs.contains("possible row deletion"), "{logs}");
        assert!(logs.contains("gaps=1"), "{logs}");
    }

    /// A retention setting that is not a number of days keeps the default,
    /// and the operator is told which value was ignored.
    #[test]
    fn a_retention_setting_that_is_not_a_number_warns_and_keeps_the_default() {
        let (days, logs) = logs_of(|| parse_min_retention(Some(" two weeks ")));
        assert_eq!(days, DEFAULT_MIN_RETENTION_DAYS);
        assert!(
            logs.contains("UC_AUDIT_MIN_RETENTION_DAYS is not a number of days"),
            "{logs}"
        );
        assert!(logs.contains("two weeks"), "{logs}");
    }

    /// The distinct-value lookups behind the filter lists report a log that
    /// cannot be read as an error: they never answer it with an empty list
    /// themselves.
    #[test]
    fn the_distinct_value_lookups_fail_on_an_unreadable_log() {
        let (_dir, conn) = db();
        log(&conn, "seen").unwrap();
        assert_eq!(get_audit_actions(&conn, T).unwrap(), ["seen"]);
        conn.execute_batch("DROP TABLE audit_log").unwrap();
        assert!(get_audit_actions(&conn, T).is_err());
        assert!(get_audit_operators(&conn, T).is_err());
        assert!(get_audit_node_ids(&conn, T).is_err());
    }

    /// A database error converts to the `Db` variant (a 500 at the
    /// handlers), whose text names it as a database error.
    #[test]
    fn a_database_error_converts_to_a_db_audit_op_error() {
        let e = AuditOpError::from(rusqlite::Error::QueryReturnedNoRows);
        assert!(matches!(
            e,
            AuditOpError::Db(rusqlite::Error::QueryReturnedNoRows)
        ));
        assert_eq!(
            e.to_string(),
            format!("database error: {}", rusqlite::Error::QueryReturnedNoRows)
        );
    }

    /// An archive marker vouches for an archived prefix only through the
    /// `terminal_hmac` it names. With the HMAC of the removed head of the
    /// chain (as the bridge's archive writes it) the rest verifies; a
    /// marker that names none (the key missing, null or not a string)
    /// roots nothing, so the head removed behind it is still found: the
    /// new first entry fails verification.
    #[test]
    fn an_archive_marker_without_a_terminal_hmac_hides_no_removed_head() {
        /// The marker's details, from the HMAC of the removed head.
        type DetailsOf = fn(&str) -> serde_json::Value;
        let names_the_head = |head: &str| serde_json::json!({ "terminal_hmac": head });
        let cases: [(DetailsOf, bool); 4] = [
            (names_the_head, true),
            (|_| serde_json::json!({ "archived_count": 1 }), false),
            (|_| serde_json::json!({ "terminal_hmac": null }), false),
            (|_| serde_json::json!({ "terminal_hmac": 7 }), false),
        ];
        for (details_of, verifies) in cases {
            let (_dir, conn) = db();
            for i in 0..3 {
                log(&conn, &format!("e{i}")).unwrap();
            }
            let rows = live(&conn);
            let (head_id, head_hmac) = &rows[0];
            conn.execute("DELETE FROM audit_log WHERE id = ?1", [head_id])
                .unwrap();
            let details = details_of(head_hmac).to_string();
            log_audit(
                &conn,
                SECRET,
                "archive_marker",
                "",
                "",
                "",
                &details,
                "",
                0.0,
                "",
                T,
            )
            .unwrap();

            let v = verify_chain(&conn, T, SECRET).unwrap();
            assert_eq!(v.valid, verifies, "{details}: {v:?}");
            assert!(v.gaps.is_empty(), "{details}: {v:?}");
            let failed: Vec<(i64, &str)> = v
                .errors
                .iter()
                .map(|e| (e.id, e.expected.as_str()))
                .collect();
            if verifies {
                assert!(failed.is_empty(), "{details}: {v:?}");
            } else {
                assert_eq!(failed, [(rows[1].0, HMAC_MISMATCH)], "{details}");
            }
        }
    }
}
