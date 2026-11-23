//! Post-ingest hooks (contract K8, gateway side).
//!
//! The gateway serves `POST /api/detections/batch` (and `/batch`) itself,
//! so the bridge's post-ingest work — condition alert rules, watch-band
//! alerts, rule trigger counts, webhooks, storing edge-decoded messages,
//! queueing protocol decodes — would never run for the detections edges
//! send. After a batch is committed, its newly inserted detections are
//! handed to the bridge's `POST /api/internal/ingest-hook`:
//!
//! * through a bounded in-memory queue ([`QUEUE_CAPACITY`] detections, and
//!   [`QUEUE_CAPACITY_BYTES`] bytes of payload), so ingest never waits for
//!   the bridge. When it is full the oldest queued batch is dropped and
//!   counted, with a warning on the first drop and every
//!   [`DROP_LOG_EVERY`] drops after it;
//! * by one background task, in order. An item is sent at most
//!   [`ATTEMPTS`] times: after a 5xx or a connection error the task waits
//!   0.5 s, then 1 s, and tries again; after the last failure it gives the
//!   item up and pauses 2 s before the next one, so a bridge that is down
//!   does not empty the queue at once. A 2xx is done; a 4xx is logged and
//!   the item dropped;
//! * authenticated by `X-Rust-Proxy` only. The gateway never proxies a
//!   client request to `/api/internal/` (see [`crate::middleware::path`]).
//!   Without a usable `UC_PROXY_SECRET` (development only) the bridge
//!   refuses every hook, so none is queued: the detections are counted in
//!   `hooks_disabled` instead (contract K10);
//! * across a restart (contract K8b): when the gateway stops, the task
//!   stops, and what is still queued gets [`SHUTDOWN_DRAIN`] to be
//!   delivered — one attempt per item, no pause, stopping at the first
//!   failure ([`IngestHooks::drain`]). Whatever is left is saved to the
//!   spool file (`UC_HOOK_SPOOL_PATH`, by default
//!   `gateway-post-ingest-hooks.spool` next to the baselines file; mode
//!   0600, at most [`SPOOL_MAX_BYTES`]; [`IngestHooks::spool`]). At the
//!   next start it is queued again before anything new, and deleted
//!   ([`IngestHooks::restore`]). The bridge ignores a detection it has
//!   already hooked, so sending one twice is safe. Hooks still queued when
//!   the gateway is killed (no shutdown signal) are lost.
//!
//! Alerts for gateway-ingested batches are therefore created
//! asynchronously; the ingest response's `alerts_created` stays 0.
//!
//! Payload of one item (a batch of more than [`CHUNK_DETECTIONS`]
//! detections is sent as several):
//!
//! ```json
//! {"node_id": "<batch node>",
//!  "detections": [<each newly inserted detection, as stored>],
//!  "decoded_messages": [<each message the edge attached to one of those
//!                        detections, with its "detection_id" and "node_id">],
//!  "received_at": "<ISO 8601 UTC>"}
//! ```
//!
//! Edge-decoded messages are bounded like the bridge bounds them
//! ([`MAX_DECODED_PER_DETECTION`], [`MAX_DECODED_PER_BATCH`]); entries that
//! are not objects, or larger than [`MAX_DECODED_MESSAGE_BYTES`], are
//! dropped and counted. The counters are in `GET /health`
//! (`post_ingest_hooks`).

use std::collections::VecDeque;
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use serde::Serialize;
use tokio::sync::{watch, Notify};
use tracing::{debug, error, info, warn};

use crate::models::detection::DetectionRecord;
use crate::proxy::handler::proxy_secret_header;

/// The bridge's post-ingest endpoint.
pub const HOOK_PATH: &str = "/api/internal/ingest-hook";
/// Most detections queued at once.
pub const QUEUE_CAPACITY: usize = 10_000;
/// Most payload bytes queued at once.
pub const QUEUE_CAPACITY_BYTES: usize = 64 << 20;
/// Most detections in one hook request.
pub const CHUNK_DETECTIONS: usize = 500;
/// Sends of one item before it is given up.
pub const ATTEMPTS: usize = 3;
/// A warning is logged on the first drop and every this many after it.
pub const DROP_LOG_EVERY: u64 = 100;
/// Edge-decoded messages forwarded per detection (the bridge's
/// `_EDGE_DECODED_MAX_PER_DETECTION`).
pub const MAX_DECODED_PER_DETECTION: usize = 50;
/// Edge-decoded messages forwarded per batch (the bridge's
/// `_EDGE_DECODED_MAX_PER_BATCH`).
pub const MAX_DECODED_PER_BATCH: usize = 1000;
/// Largest edge-decoded message forwarded, serialized.
pub const MAX_DECODED_MESSAGE_BYTES: usize = 16 << 10;
/// How long queued hooks get to be delivered when the gateway stops,
/// before the rest is spooled (K8b). With the 3 s the listener gets to
/// finish its requests, this stays under Docker's 10 s stop timeout.
pub const SHUTDOWN_DRAIN: Duration = Duration::from_secs(5);
/// Largest spool file written, or read back (K8b).
pub const SPOOL_MAX_BYTES: usize = QUEUE_CAPACITY_BYTES;

/// One hook request waiting to be sent.
#[derive(Debug, Clone)]
pub struct HookItem {
    pub node_id: String,
    pub detections: usize,
    pub body: Bytes,
}

#[derive(Debug, Default)]
struct Queue {
    items: VecDeque<HookItem>,
    detections: usize,
    bytes: usize,
}

#[derive(Debug, Default)]
struct Counters {
    enqueued_batches: AtomicU64,
    enqueued_detections: AtomicU64,
    delivered_batches: AtomicU64,
    delivered_detections: AtomicU64,
    dropped_batches: AtomicU64,
    dropped_detections: AtomicU64,
    failed_batches: AtomicU64,
    failed_detections: AtomicU64,
    retries: AtomicU64,
    decoded_messages_dropped: AtomicU64,
    hooks_disabled: AtomicU64,
    restored_batches: AtomicU64,
    restored_detections: AtomicU64,
}

/// The hook counters, as `GET /health` reports them. A "batch" is one hook
/// request (a chunk of an ingested batch).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct HookStats {
    pub queued_batches: usize,
    pub queued_detections: usize,
    pub queued_bytes: usize,
    pub capacity_detections: usize,
    pub enqueued_batches: u64,
    pub enqueued_detections: u64,
    pub delivered_batches: u64,
    pub delivered_detections: u64,
    /// Dropped from a full queue, or at shutdown because the spool was
    /// full or could not be written.
    pub dropped_batches: u64,
    pub dropped_detections: u64,
    /// Given up after the retries, or refused by the bridge (4xx).
    pub failed_batches: u64,
    pub failed_detections: u64,
    pub retries: u64,
    pub decoded_messages_dropped: u64,
    /// Detections not handed to the bridge because the hooks are disabled
    /// (no usable `UC_PROXY_SECRET`; contract K10).
    pub hooks_disabled: u64,
    /// Queued again at startup from the shutdown spool (K8b).
    pub restored_batches: u64,
    pub restored_detections: u64,
}

/// What [`IngestHooks::drain`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DrainReport {
    pub delivered_batches: usize,
    /// Refused by the bridge (4xx) and dropped.
    pub refused_batches: usize,
    /// Why draining stopped early: the bridge failed (5xx, connection
    /// error, timeout) — the item is back at the front of the queue.
    pub bridge_failure: Option<String>,
    /// The time ran out with items still queued.
    pub timed_out: bool,
}

/// What [`IngestHooks::spool`] wrote.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpoolReport {
    pub batches: usize,
    pub detections: usize,
    pub bytes: usize,
    /// Left out to keep the file within [`SPOOL_MAX_BYTES`] (the oldest).
    pub dropped_batches: usize,
    pub dropped_detections: usize,
}

/// What [`IngestHooks::restore`] queued again.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RestoreReport {
    pub batches: usize,
    pub detections: usize,
    /// Lines that are not a hook payload (skipped).
    pub skipped_lines: usize,
    /// The file was larger than [`SPOOL_MAX_BYTES`]; the rest was not read.
    pub truncated: bool,
}

/// How [`IngestHooks::deliver`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookOutcome {
    Delivered,
    /// The bridge refused it (4xx); dropped.
    Refused,
    /// Given up after [`ATTEMPTS`] failures; dropped.
    Failed,
}

/// The bounded queue of hook requests, and its counters.
#[derive(Debug)]
pub struct IngestHooks {
    queue: Mutex<Queue>,
    notify: Notify,
    capacity: usize,
    capacity_bytes: usize,
    counters: Counters,
    /// Set once the shutdown spool is written: nothing queued after it
    /// could be delivered or saved.
    closed: AtomicBool,
    /// Largest spool written or read ([`SPOOL_MAX_BYTES`]).
    spool_limit: usize,
}

impl Default for IngestHooks {
    fn default() -> Self {
        Self::new(QUEUE_CAPACITY, QUEUE_CAPACITY_BYTES)
    }
}

/// `received_at` for a batch received now.
pub fn received_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, false)
}

#[derive(Serialize)]
struct Payload<'a> {
    node_id: &'a str,
    detections: &'a [&'a DetectionRecord],
    decoded_messages: Vec<serde_json::Value>,
    received_at: &'a str,
}

impl IngestHooks {
    /// A queue holding at most `capacity` detections and `capacity_bytes`
    /// bytes of payload.
    pub fn new(capacity: usize, capacity_bytes: usize) -> Self {
        Self {
            queue: Mutex::new(Queue::default()),
            notify: Notify::new(),
            capacity: capacity.max(1),
            capacity_bytes: capacity_bytes.max(1),
            counters: Counters::default(),
            closed: AtomicBool::new(false),
            spool_limit: SPOOL_MAX_BYTES,
        }
    }

    /// The same queue, with spool files of at most `bytes` (instead of
    /// [`SPOOL_MAX_BYTES`]).
    pub fn with_spool_limit(mut self, bytes: usize) -> Self {
        self.spool_limit = bytes;
        self
    }

    /// Count `detections` newly stored detections that are not handed to
    /// the bridge because the hooks are disabled (K10).
    pub fn count_disabled(&self, detections: usize) {
        self.counters
            .hooks_disabled
            .fetch_add(detections as u64, Ordering::Relaxed);
    }

    /// Queue the hook requests for `detections` (the newly inserted ones of
    /// a batch from `node_id`). Never blocks on the bridge.
    pub fn enqueue_batch(&self, node_id: &str, detections: &[&DetectionRecord], received_at: &str) {
        let mut budget = MAX_DECODED_PER_BATCH;
        let mut dropped_messages = 0usize;
        for chunk in detections.chunks(CHUNK_DETECTIONS) {
            let decoded_messages: Vec<serde_json::Value> = chunk
                .iter()
                .flat_map(|det| decoded_messages_of(det, &mut budget, &mut dropped_messages))
                .collect();
            let payload = Payload {
                node_id,
                detections: chunk,
                decoded_messages,
                received_at,
            };
            let body = match serde_json::to_vec(&payload) {
                Ok(body) => Bytes::from(body),
                Err(e) => {
                    warn!(error = %e, node_id, "Cannot serialize a post-ingest hook");
                    continue;
                }
            };
            self.push(HookItem {
                node_id: node_id.to_string(),
                detections: chunk.len(),
                body,
            });
        }
        if dropped_messages > 0 {
            self.counters
                .decoded_messages_dropped
                .fetch_add(dropped_messages as u64, Ordering::Relaxed);
            warn!(
                node_id,
                dropped = dropped_messages,
                max_per_detection = MAX_DECODED_PER_DETECTION,
                max_per_batch = MAX_DECODED_PER_BATCH,
                max_bytes = MAX_DECODED_MESSAGE_BYTES,
                "Edge-decoded messages dropped (not objects, too large or too many)"
            );
        }
    }

    /// Append `item`, dropping the oldest items while it does not fit.
    pub fn push(&self, item: HookItem) {
        let mut dropped: Vec<HookItem> = Vec::new();
        {
            let mut q = self.queue.lock().unwrap_or_else(|e| e.into_inner());
            // Checked under the queue lock, which the spool holds while it
            // closes the queue and takes its items: an item is either
            // spooled or reported here, never lost unnoticed.
            if self.closed.load(Ordering::SeqCst) {
                drop(q);
                self.count_failure(item.detections as u64);
                error!(
                    node_id = %item.node_id,
                    detections = item.detections,
                    "Post-ingest hook queued after the shutdown spool was written — it is \
                     lost (a request was still being served when the gateway stopped)"
                );
                return;
            }
            self.counters
                .enqueued_detections
                .fetch_add(item.detections as u64, Ordering::Relaxed);
            while !q.items.is_empty()
                && (q.detections + item.detections > self.capacity
                    || q.bytes + item.body.len() > self.capacity_bytes)
            {
                let Some(old) = q.items.pop_front() else {
                    break;
                };
                q.detections -= old.detections;
                q.bytes -= old.body.len();
                dropped.push(old);
            }
            q.detections += item.detections;
            q.bytes += item.body.len();
            q.items.push_back(item);
        }
        self.counters
            .enqueued_batches
            .fetch_add(1, Ordering::Relaxed);
        for old in dropped {
            let n = self
                .counters
                .dropped_batches
                .fetch_add(1, Ordering::Relaxed)
                + 1;
            let detections = self
                .counters
                .dropped_detections
                .fetch_add(old.detections as u64, Ordering::Relaxed)
                + old.detections as u64;
            if (n - 1) % DROP_LOG_EVERY == 0 {
                warn!(
                    dropped_batches = n,
                    dropped_detections = detections,
                    node_id = %old.node_id,
                    capacity = self.capacity,
                    "Post-ingest hook queue full — dropped the oldest batch (the \
                     bridge is not keeping up or is unreachable)"
                );
            }
        }
        self.notify.notify_one();
    }

    fn pop(&self) -> Option<HookItem> {
        let mut q = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        let item = q.items.pop_front()?;
        q.detections -= item.detections;
        q.bytes -= item.body.len();
        Some(item)
    }

    /// Put back an item taken from the queue but not delivered, as the
    /// next one to send. It was counted when it was first queued.
    fn push_front(&self, item: HookItem) {
        let mut q = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        q.detections += item.detections;
        q.bytes += item.body.len();
        q.items.push_front(item);
        drop(q);
        self.notify.notify_one();
    }

    /// Take every queued item, oldest first; with `close`, nothing can be
    /// queued afterwards ([`IngestHooks::push`]).
    fn take_all(&self, close: bool) -> Vec<HookItem> {
        let mut q = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        if close {
            self.closed.store(true, Ordering::SeqCst);
        }
        q.detections = 0;
        q.bytes = 0;
        q.items.drain(..).collect()
    }

    /// The next item, waiting for one if the queue is empty.
    pub async fn next(&self) -> HookItem {
        loop {
            if let Some(item) = self.pop() {
                return item;
            }
            self.notify.notified().await;
        }
    }

    pub fn stats(&self) -> HookStats {
        let (queued_batches, queued_detections, queued_bytes) = {
            let q = self.queue.lock().unwrap_or_else(|e| e.into_inner());
            (q.items.len(), q.detections, q.bytes)
        };
        let c = &self.counters;
        let get = |a: &AtomicU64| a.load(Ordering::Relaxed);
        HookStats {
            queued_batches,
            queued_detections,
            queued_bytes,
            capacity_detections: self.capacity,
            enqueued_batches: get(&c.enqueued_batches),
            enqueued_detections: get(&c.enqueued_detections),
            delivered_batches: get(&c.delivered_batches),
            delivered_detections: get(&c.delivered_detections),
            dropped_batches: get(&c.dropped_batches),
            dropped_detections: get(&c.dropped_detections),
            failed_batches: get(&c.failed_batches),
            failed_detections: get(&c.failed_detections),
            retries: get(&c.retries),
            decoded_messages_dropped: get(&c.decoded_messages_dropped),
            hooks_disabled: get(&c.hooks_disabled),
            restored_batches: get(&c.restored_batches),
            restored_detections: get(&c.restored_detections),
        }
    }

    /// Send one item (with retries) and count the outcome. After
    /// [`HookOutcome::Failed`] the worker pauses (`RetryTiming::cooldown`).
    pub async fn deliver(&self, target: &HookTarget, item: HookItem) -> HookOutcome {
        match send_with_retries(target, &item.body, &self.counters.retries).await {
            Delivery::Delivered => {
                self.count_delivered(&item);
                HookOutcome::Delivered
            }
            Delivery::Refused(status) => {
                self.count_refused(&item, status);
                HookOutcome::Refused
            }
            Delivery::Failed(reason) => {
                let n = item.detections as u64;
                let failed = self.count_failure(n);
                if (failed - 1) % DROP_LOG_EVERY == 0 {
                    warn!(
                        reason,
                        node_id = %item.node_id,
                        detections = n,
                        failed_batches = failed,
                        attempts = ATTEMPTS,
                        "Post-ingest hook failed after retries — dropped"
                    );
                }
                HookOutcome::Failed
            }
        }
    }

    fn count_delivered(&self, item: &HookItem) {
        let n = item.detections as u64;
        self.counters
            .delivered_batches
            .fetch_add(1, Ordering::Relaxed);
        self.counters
            .delivered_detections
            .fetch_add(n, Ordering::Relaxed);
        debug!(node_id = %item.node_id, detections = n, "Post-ingest hook delivered");
    }

    fn count_refused(&self, item: &HookItem, status: reqwest::StatusCode) {
        let n = item.detections as u64;
        let failed = self.count_failure(n);
        if (failed - 1) % DROP_LOG_EVERY == 0 {
            warn!(
                %status,
                node_id = %item.node_id,
                detections = n,
                failed_batches = failed,
                "The bridge refused a post-ingest hook — dropped (403: \
                 UC_PROXY_SECRET differs from the bridge's; 404: the \
                 bridge predates /api/internal/ingest-hook)"
            );
        }
    }

    /// Deliver what is queued for at most `budget` (the shutdown drain,
    /// K8b): one attempt per item, no pause between items, and no attempt
    /// outlasting the budget. Stops at the first failure (5xx, connection
    /// error, timeout), putting that item back at the front: a bridge that
    /// is down will not answer the next one either. A 4xx drops the item,
    /// as usual.
    pub async fn drain(&self, target: &HookTarget, budget: Duration) -> DrainReport {
        let deadline = tokio::time::Instant::now() + budget;
        let mut report = DrainReport::default();
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                report.timed_out = !self.is_empty();
                break;
            }
            let Some(item) = self.pop() else {
                break;
            };
            match send_once(target, &item.body, target.timing.timeout.min(left)).await {
                Attempt::Delivered => {
                    self.count_delivered(&item);
                    report.delivered_batches += 1;
                }
                Attempt::Refused(status) => {
                    self.count_refused(&item, status);
                    report.refused_batches += 1;
                }
                Attempt::Retryable(reason) => {
                    self.push_front(item);
                    report.bridge_failure = Some(reason);
                    break;
                }
            }
        }
        report
    }

    fn is_empty(&self) -> bool {
        self.queue
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .items
            .is_empty()
    }

    /// Save every queued item to `path` and empty the queue (K8b). Nothing
    /// queued afterwards is kept ([`IngestHooks::push`] logs and counts it
    /// as failed). The file holds one hook payload per line, oldest first,
    /// within [`SPOOL_MAX_BYTES`] (the oldest items are left out first); it
    /// is written to a temporary file with mode 0600 and renamed over
    /// `path`. With nothing queued, `path` is left as it is.
    pub fn spool(&self, path: &Path) -> io::Result<SpoolReport> {
        let mut items = self.take_all(true);
        let mut report = SpoolReport::default();
        // One payload per line: serialized JSON never holds a raw line
        // feed, but an item that does could not be read back.
        items.retain(|item| {
            let ok = !item.body.contains(&b'\n') && !item.body.is_empty();
            if !ok {
                report.dropped_batches += 1;
                report.dropped_detections += item.detections;
            }
            ok
        });
        let mut size: usize = items.iter().map(|item| item.body.len() + 1).sum();
        let mut skip = 0;
        while size > self.spool_limit {
            size -= items[skip].body.len() + 1;
            report.dropped_batches += 1;
            report.dropped_detections += items[skip].detections;
            skip += 1;
        }
        let items = &items[skip..];
        if report.dropped_batches > 0 {
            self.counters
                .dropped_batches
                .fetch_add(report.dropped_batches as u64, Ordering::Relaxed);
            self.counters
                .dropped_detections
                .fetch_add(report.dropped_detections as u64, Ordering::Relaxed);
        }
        if items.is_empty() {
            return Ok(report);
        }
        if let Err(e) = write_spool(path, items) {
            // Taken from the queue and not saved: lost, and counted.
            self.counters
                .dropped_batches
                .fetch_add(items.len() as u64, Ordering::Relaxed);
            self.counters.dropped_detections.fetch_add(
                items.iter().map(|item| item.detections as u64).sum(),
                Ordering::Relaxed,
            );
            return Err(e);
        }
        report.batches = items.len();
        report.detections = items.iter().map(|item| item.detections).sum();
        report.bytes = size;
        Ok(report)
    }

    /// Queue again what [`IngestHooks::spool`] saved to `path`, and delete
    /// the file (K8b). Call it before the listener starts, so the saved
    /// items go before anything new. The file is deleted before anything is
    /// queued: one that cannot be deleted would be replayed at every start,
    /// so it is then left alone and the error returned. No file: nothing to
    /// do. At most [`SPOOL_MAX_BYTES`] are read; lines that are not a hook
    /// payload are skipped.
    pub fn restore(&self, path: &Path) -> io::Result<RestoreReport> {
        let Some((data, truncated)) = read_spool(path, self.spool_limit)? else {
            return Ok(RestoreReport::default());
        };
        std::fs::remove_file(path)?;
        let mut report = RestoreReport {
            truncated,
            ..RestoreReport::default()
        };
        for line in data.split(|&b| b == b'\n') {
            if line.is_empty() {
                continue;
            }
            match spooled_item(line) {
                Some(item) => {
                    report.batches += 1;
                    report.detections += item.detections;
                    self.push(item);
                }
                None => report.skipped_lines += 1,
            }
        }
        self.counters
            .restored_batches
            .fetch_add(report.batches as u64, Ordering::Relaxed);
        self.counters
            .restored_detections
            .fetch_add(report.detections as u64, Ordering::Relaxed);
        Ok(report)
    }

    /// At shutdown, once the listener and the worker have stopped: drain
    /// the queue for at most `drain_for`, then spool what is left to
    /// `spool_path` (K8b). Logs the outcome, ending with
    /// [`IngestHooks::log_summary`]; returns the final counters.
    pub async fn shutdown(
        &self,
        target: &HookTarget,
        spool_path: &Path,
        drain_for: Duration,
    ) -> HookStats {
        let queued = self.stats();
        if queued.queued_batches > 0 {
            info!(
                queued_batches = queued.queued_batches,
                queued_detections = queued.queued_detections,
                drain_secs = drain_for.as_secs_f64(),
                "Delivering the queued post-ingest hooks before exiting"
            );
        }
        let drained = self.drain(target, drain_for).await;
        if let Some(reason) = &drained.bridge_failure {
            warn!(
                reason,
                delivered = drained.delivered_batches,
                "The bridge did not take a post-ingest hook at shutdown; saving the rest"
            );
        }
        let left = self.stats();
        let mut saved_batches = 0;
        match self.spool(spool_path) {
            Ok(spooled) => {
                saved_batches = spooled.batches;
                if spooled.batches > 0 {
                    warn!(
                        path = %spool_path.display(),
                        batches = spooled.batches,
                        detections = spooled.detections,
                        bytes = spooled.bytes,
                        "Post-ingest hooks not delivered at shutdown were saved; they are \
                         sent at the next start"
                    );
                }
                if spooled.dropped_batches > 0 {
                    error!(
                        path = %spool_path.display(),
                        dropped_batches = spooled.dropped_batches,
                        dropped_detections = spooled.dropped_detections,
                        max_bytes = self.spool_limit,
                        "Post-ingest hooks lost at shutdown: they did not fit in the spool"
                    );
                }
            }
            Err(e) => error!(
                path = %spool_path.display(),
                error = %e,
                queued_batches = left.queued_batches,
                queued_detections = left.queued_detections,
                "Post-ingest hooks not delivered at shutdown are LOST: cannot write the \
                 spool (set UC_HOOK_SPOOL_PATH to a writable file)"
            ),
        }
        self.log_summary(saved_batches)
    }

    /// The last word on the hooks before the process exits, from the
    /// counters (`GET /health` is gone afterwards). A WARN with the totals
    /// when any hook was lost since the start — the per-item warnings are
    /// rate-limited, and the worker keeps delivering, and can give items
    /// up, during the shutdown grace period — and an INFO otherwise.
    /// `saved_batches` is what the spool just took.
    fn log_summary(&self, saved_batches: usize) -> HookStats {
        let s = self.stats();
        if s.failed_batches > 0 || s.dropped_batches > 0 {
            warn!(
                failed_batches = s.failed_batches,
                failed_detections = s.failed_detections,
                dropped_batches = s.dropped_batches,
                dropped_detections = s.dropped_detections,
                delivered_batches = s.delivered_batches,
                saved_batches,
                decoded_messages_dropped = s.decoded_messages_dropped,
                "Post-ingest hooks were lost while the gateway ran, so their alert rules, \
                 watch bands, webhooks and decode jobs did not run (failed: given up after \
                 the retries or refused by the bridge; dropped: the queue or the shutdown \
                 spool was full or could not be written)"
            );
        } else if saved_batches == 0 {
            info!(
                delivered_batches = s.delivered_batches,
                delivered_detections = s.delivered_detections,
                decoded_messages_dropped = s.decoded_messages_dropped,
                "No post-ingest hooks left to deliver at shutdown, and none was lost since \
                 the start"
            );
        } else {
            info!(
                delivered_batches = s.delivered_batches,
                saved_batches,
                decoded_messages_dropped = s.decoded_messages_dropped,
                "No post-ingest hook was lost since the start (the undelivered ones were \
                 saved for the next start)"
            );
        }
        s
    }

    fn count_failure(&self, detections: u64) -> u64 {
        self.counters
            .failed_detections
            .fetch_add(detections, Ordering::Relaxed);
        self.counters.failed_batches.fetch_add(1, Ordering::Relaxed) + 1
    }
}

/// The edge-decoded messages of `det` to forward, each tagged with its
/// detection and node. `budget` is what is left of the batch's allowance.
fn decoded_messages_of(
    det: &DetectionRecord,
    budget: &mut usize,
    dropped: &mut usize,
) -> Vec<serde_json::Value> {
    let list = match &det.decoded_messages {
        None | Some(serde_json::Value::Null) => return Vec::new(),
        Some(serde_json::Value::Array(list)) => list,
        Some(_) => {
            *dropped += 1;
            return Vec::new();
        }
    };
    let mut out = Vec::new();
    for msg in list {
        let serde_json::Value::Object(fields) = msg else {
            *dropped += 1;
            continue;
        };
        let too_big = serde_json::to_vec(msg).map_or(true, |v| v.len() > MAX_DECODED_MESSAGE_BYTES);
        if too_big || out.len() >= MAX_DECODED_PER_DETECTION || *budget == 0 {
            *dropped += 1;
            continue;
        }
        let mut fields = fields.clone();
        fields.insert("detection_id".into(), det.detection_id.clone().into());
        fields.insert("node_id".into(), det.node_id.clone().into());
        out.push(serde_json::Value::Object(fields));
        *budget -= 1;
    }
    out
}

// ── Delivery ──────────────────────────────────────────────────────────

/// Waits of the delivery task.
#[derive(Debug, Clone, Copy)]
pub struct RetryTiming {
    /// Before the 2nd and the 3rd attempt.
    pub backoff: [Duration; ATTEMPTS - 1],
    /// After an item was given up, before the next one.
    pub cooldown: Duration,
    /// Per attempt.
    pub timeout: Duration,
}

impl Default for RetryTiming {
    fn default() -> Self {
        Self {
            backoff: [Duration::from_millis(500), Duration::from_secs(1)],
            cooldown: Duration::from_secs(2),
            timeout: Duration::from_secs(10),
        }
    }
}

/// Where hooks go.
#[derive(Debug, Clone)]
pub struct HookTarget {
    pub client: reqwest::Client,
    /// `{UC_PYTHON_URL}/api/internal/ingest-hook`.
    pub url: String,
    pub proxy_secret: String,
    pub timing: RetryTiming,
}

impl HookTarget {
    pub fn new(client: reqwest::Client, python_url: &str, proxy_secret: &str) -> Self {
        Self {
            client,
            url: format!("{}{HOOK_PATH}", python_url.trim_end_matches('/')),
            proxy_secret: proxy_secret.to_string(),
            timing: RetryTiming::default(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Delivery {
    Delivered,
    /// 4xx: not retried.
    Refused(reqwest::StatusCode),
    /// 5xx / connection error / timeout on every attempt.
    Failed(String),
}

/// One send of one hook request.
#[derive(Debug, PartialEq, Eq)]
enum Attempt {
    Delivered,
    /// 4xx: not retried.
    Refused(reqwest::StatusCode),
    /// 5xx / connection error / timeout.
    Retryable(String),
}

async fn send_once(target: &HookTarget, body: &Bytes, timeout: Duration) -> Attempt {
    let sent = target
        .client
        .post(&target.url)
        .timeout(timeout)
        .header("x-rust-proxy", proxy_secret_header(&target.proxy_secret))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body.clone())
        .send()
        .await;
    match sent {
        Ok(resp) if resp.status().is_success() => Attempt::Delivered,
        Ok(resp) if resp.status().is_client_error() => Attempt::Refused(resp.status()),
        Ok(resp) => Attempt::Retryable(format!("HTTP {}", resp.status())),
        Err(e) if e.is_timeout() => Attempt::Retryable("timed out".to_string()),
        Err(e) => Attempt::Retryable(e.to_string()),
    }
}

async fn send_with_retries(target: &HookTarget, body: &Bytes, retries: &AtomicU64) -> Delivery {
    let mut last = String::new();
    for attempt in 0..ATTEMPTS {
        if attempt > 0 {
            retries.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(target.timing.backoff[attempt - 1]).await;
        }
        match send_once(target, body, target.timing.timeout).await {
            Attempt::Delivered => return Delivery::Delivered,
            Attempt::Refused(status) => return Delivery::Refused(status),
            Attempt::Retryable(reason) => last = reason,
        }
    }
    Delivery::Failed(last)
}

/// Run the delivery task for `hooks` until the runtime shuts down.
pub fn spawn_worker(hooks: Arc<IngestHooks>, target: HookTarget) -> tokio::task::JoinHandle<()> {
    // A stop signal whose sender is gone never fires.
    let (_, never) = watch::channel(false);
    spawn_worker_until(hooks, target, never)
}

/// Run the delivery task for `hooks` until `stop` becomes true. An item
/// being delivered then is put back at the front of the queue (the
/// shutdown drain or the spool takes it from there; the bridge ignores a
/// detection it already hooked, should the interrupted send have reached
/// it).
pub fn spawn_worker_until(
    hooks: Arc<IngestHooks>,
    target: HookTarget,
    mut stop: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let item = tokio::select! {
                biased;
                () = stopped(&mut stop) => return,
                item = hooks.next() => item,
            };
            let outcome = tokio::select! {
                biased;
                () = stopped(&mut stop) => {
                    hooks.push_front(item);
                    return;
                }
                outcome = hooks.deliver(&target, item.clone()) => outcome,
            };
            if outcome == HookOutcome::Failed {
                tokio::select! {
                    biased;
                    () = stopped(&mut stop) => return,
                    () = tokio::time::sleep(target.timing.cooldown) => {}
                }
            }
        }
    })
}

/// Resolves once `stop` is true; never, if its sender is gone unset.
async fn stopped(stop: &mut watch::Receiver<bool>) {
    if stop.wait_for(|&stop| stop).await.is_err() {
        std::future::pending::<()>().await;
    }
}

// ── Spool ─────────────────────────────────────────────────────────────

fn spool_tmp_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".tmp");
    PathBuf::from(name)
}

/// Write `items` to `path` (one body per line), atomically, mode 0600.
fn write_spool(path: &Path, items: &[HookItem]) -> io::Result<()> {
    if let Some(dir) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = spool_tmp_path(path);
    // A leftover from an interrupted write: start over, so the new file
    // is created with our mode.
    match std::fs::remove_file(&tmp) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let written = (|| {
        let mut out = io::BufWriter::new(options.open(&tmp)?);
        for item in items {
            out.write_all(&item.body)?;
            out.write_all(b"\n")?;
        }
        let file = out.into_inner().map_err(io::IntoInnerError::into_error)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written
}

/// The spool at `path` (at most `limit` bytes, cut back to the last whole
/// line), and whether it was longer. `None` when there is none.
fn read_spool(path: &Path, limit: usize) -> io::Result<Option<(Vec<u8>, bool)>> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("the hook spool is not a regular file"));
    }
    let mut data = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut data)?;
    let truncated = data.len() > limit;
    if truncated {
        data.truncate(limit);
        let whole = data.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
        data.truncate(whole);
    }
    Ok(Some((data, truncated)))
}

/// A spooled line as a hook item: a JSON object with a string `node_id`
/// and a non-empty `detections` array.
fn spooled_item(line: &[u8]) -> Option<HookItem> {
    let payload: serde_json::Value = serde_json::from_slice(line).ok()?;
    let node_id = payload.get("node_id")?.as_str()?.to_string();
    let detections = payload.get("detections")?.as_array()?.len();
    if detections == 0 {
        return None;
    }
    Some(HookItem {
        node_id,
        detections,
        body: Bytes::copy_from_slice(line),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{extract::State, http::StatusCode, routing::post, Router};
    use std::sync::atomic::AtomicUsize;

    fn item(node: &str, detections: usize, bytes: usize) -> HookItem {
        HookItem {
            node_id: node.into(),
            detections,
            body: Bytes::from(vec![b'x'; bytes]),
        }
    }

    fn det(id: &str, decoded: Option<serde_json::Value>) -> DetectionRecord {
        let mut d: DetectionRecord = serde_json::from_value(serde_json::json!({
            "detection_id": id, "node_id": "edge-1", "signal_class": "lora-css",
            "confidence": 0.9, "freq_hz": 868e6, "timestamp": "2026-11-06T00:00:00+00:00",
        }))
        .unwrap();
        d.decoded_messages = decoded;
        d
    }

    #[test]
    fn the_queue_is_bounded_and_drops_the_oldest_batch() {
        let hooks = IngestHooks::new(10, 1 << 20);
        hooks.push(item("a", 4, 10));
        hooks.push(item("b", 4, 10));
        hooks.push(item("c", 4, 10)); // 12 > 10: "a" goes
        let stats = hooks.stats();
        assert_eq!((stats.queued_batches, stats.queued_detections), (2, 8));
        assert_eq!((stats.dropped_batches, stats.dropped_detections), (1, 4));
        assert_eq!(stats.enqueued_batches, 3);
        assert_eq!(hooks.pop().unwrap().node_id, "b");
        assert_eq!(hooks.pop().unwrap().node_id, "c");
        assert!(hooks.pop().is_none());

        // Bytes are bounded too.
        let hooks = IngestHooks::new(1000, 100);
        hooks.push(item("a", 1, 60));
        hooks.push(item("b", 1, 60));
        assert_eq!(hooks.stats().dropped_batches, 1);
        assert_eq!(hooks.stats().queued_bytes, 60);

        // Many drops are all counted (and logged every DROP_LOG_EVERY).
        let hooks = IngestHooks::new(1, 1 << 20);
        for i in 0..250 {
            hooks.push(item(&format!("n{i}"), 1, 1));
        }
        let stats = hooks.stats();
        assert_eq!((stats.dropped_batches, stats.queued_batches), (249, 1));
        assert_eq!(hooks.pop().unwrap().node_id, "n249");
    }

    #[test]
    fn a_large_batch_is_chunked_and_decoded_messages_follow_their_detection() {
        let hooks = IngestHooks::default();
        let mut dets: Vec<DetectionRecord> = (0..CHUNK_DETECTIONS + 2)
            .map(|i| det(&format!("d{i}"), None))
            .collect();
        dets[1].decoded_messages = Some(serde_json::json!([
            {"protocol": "meshtastic", "text": "hello", "detection_id": "forged"},
            "not-an-object",
        ]));
        dets[CHUNK_DETECTIONS + 1].decoded_messages =
            Some(serde_json::json!([{"protocol": "adsb", "icao": "abc123"}]));
        dets[2].decoded_messages = Some(serde_json::json!([{"blob": "z".repeat(20_000)}]));
        let refs: Vec<&DetectionRecord> = dets.iter().collect();
        hooks.enqueue_batch("edge-1", &refs, "2026-11-06T00:00:01.000000+00:00");

        let first: serde_json::Value = serde_json::from_slice(&hooks.pop().unwrap().body).unwrap();
        let second: serde_json::Value = serde_json::from_slice(&hooks.pop().unwrap().body).unwrap();
        assert_eq!(first["node_id"], "edge-1");
        assert_eq!(first["received_at"], "2026-11-06T00:00:01.000000+00:00");
        assert_eq!(
            first["detections"].as_array().unwrap().len(),
            CHUNK_DETECTIONS
        );
        assert_eq!(second["detections"].as_array().unwrap().len(), 2);
        assert_eq!(first["detections"][1]["detection_id"], "d1");
        assert!(first["detections"][1].get("decoded_messages").is_none());
        assert_eq!(
            first["decoded_messages"],
            serde_json::json!([{"protocol": "meshtastic", "text": "hello",
                                "detection_id": "d1", "node_id": "edge-1"}])
        );
        assert_eq!(
            second["decoded_messages"][0]["detection_id"],
            format!("d{}", CHUNK_DETECTIONS + 1)
        );
        // The string entry and the oversized message.
        assert_eq!(hooks.stats().decoded_messages_dropped, 2);
    }

    #[test]
    fn decoded_messages_are_bounded_per_detection_and_per_batch() {
        let many: Vec<serde_json::Value> = (0..80).map(|i| serde_json::json!({"n": i})).collect();
        let d = det("d", Some(serde_json::Value::Array(many)));
        let (mut budget, mut dropped) = (MAX_DECODED_PER_BATCH, 0);
        assert_eq!(
            decoded_messages_of(&d, &mut budget, &mut dropped).len(),
            MAX_DECODED_PER_DETECTION
        );
        assert_eq!(dropped, 80 - MAX_DECODED_PER_DETECTION);
        let (mut budget, mut dropped) = (3, 0);
        assert_eq!(decoded_messages_of(&d, &mut budget, &mut dropped).len(), 3);
        assert_eq!((budget, dropped), (0, 77));
    }

    /// X-Rust-Proxy, Content-Type and body of one hook request.
    type SeenHook = (Option<String>, Option<String>, Vec<u8>);

    #[derive(Clone)]
    struct Bridge {
        /// Status to answer for each request, in order (then 200).
        script: Arc<Mutex<VecDeque<u16>>>,
        hits: Arc<AtomicUsize>,
        seen: Arc<Mutex<Vec<SeenHook>>>,
    }

    async fn hook(
        State(b): State<Bridge>,
        headers: axum::http::HeaderMap,
        body: Bytes,
    ) -> StatusCode {
        b.hits.fetch_add(1, Ordering::SeqCst);
        let h = |n: &str| headers.get(n).map(|v| v.to_str().unwrap().to_string());
        b.seen
            .lock()
            .unwrap()
            .push((h("x-rust-proxy"), h("content-type"), body.to_vec()));
        let status = b.script.lock().unwrap().pop_front().unwrap_or(200);
        StatusCode::from_u16(status).unwrap()
    }

    async fn bridge(script: &[u16]) -> (String, Bridge) {
        let b = Bridge {
            script: Arc::new(Mutex::new(script.iter().copied().collect())),
            hits: Arc::default(),
            seen: Arc::default(),
        };
        let app = Router::new()
            .route(HOOK_PATH, post(hook))
            .with_state(b.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (url, b)
    }

    fn target(url: &str) -> HookTarget {
        let mut t = HookTarget::new(reqwest::Client::new(), url, "hook-secret");
        t.timing = RetryTiming {
            backoff: [Duration::from_millis(10), Duration::from_millis(20)],
            cooldown: Duration::from_millis(1),
            timeout: Duration::from_secs(2),
        };
        t
    }

    #[tokio::test]
    async fn a_5xx_is_retried_and_a_2xx_is_done() {
        let (url, b) = bridge(&[500, 503]).await;
        let hooks = IngestHooks::default();
        hooks.deliver(&target(&url), item("a", 3, 4)).await;
        let stats = hooks.stats();
        assert_eq!(b.hits.load(Ordering::SeqCst), 3);
        assert_eq!(
            (stats.delivered_batches, stats.delivered_detections),
            (1, 3)
        );
        assert_eq!((stats.retries, stats.failed_batches), (2, 0));
        let seen = b.seen.lock().unwrap()[0].clone();
        assert_eq!(seen.0.as_deref(), Some("hook-secret"));
        assert_eq!(seen.1.as_deref(), Some("application/json"));
        assert_eq!(seen.2, b"xxxx");
    }

    #[tokio::test]
    async fn an_item_is_given_up_after_three_failed_attempts() {
        let (url, b) = bridge(&[500, 502, 503, 500]).await;
        let hooks = IngestHooks::default();
        hooks.deliver(&target(&url), item("a", 2, 1)).await;
        let stats = hooks.stats();
        assert_eq!(b.hits.load(Ordering::SeqCst), ATTEMPTS);
        assert_eq!((stats.failed_batches, stats.failed_detections), (1, 2));
        assert_eq!(stats.delivered_batches, 0);
    }

    #[tokio::test]
    async fn a_4xx_is_dropped_without_retrying() {
        let (url, b) = bridge(&[403]).await;
        let hooks = IngestHooks::default();
        hooks.deliver(&target(&url), item("a", 1, 1)).await;
        assert_eq!(b.hits.load(Ordering::SeqCst), 1);
        let stats = hooks.stats();
        assert_eq!((stats.failed_batches, stats.retries), (1, 0));
    }

    #[tokio::test]
    async fn an_unreachable_bridge_is_retried_then_given_up() {
        // Nothing listens on this port once the listener is dropped.
        let addr = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let hooks = IngestHooks::default();
        hooks
            .deliver(&target(&format!("http://{addr}")), item("a", 1, 1))
            .await;
        let stats = hooks.stats();
        assert_eq!((stats.failed_batches, stats.retries), (1, 2));
    }

    #[tokio::test]
    async fn the_worker_delivers_queued_items_in_order() {
        let (url, b) = bridge(&[]).await;
        let hooks = Arc::new(IngestHooks::default());
        let worker = spawn_worker(Arc::clone(&hooks), target(&url));
        hooks.push(item("first", 1, 1));
        hooks.push(HookItem {
            node_id: "second".into(),
            detections: 1,
            body: Bytes::from_static(b"2"),
        });
        for _ in 0..100 {
            if hooks.stats().delivered_batches == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(hooks.stats().delivered_batches, 2);
        let bodies: Vec<Vec<u8>> = b.seen.lock().unwrap().iter().map(|s| s.2.clone()).collect();
        assert_eq!(bodies, [b"x".to_vec(), b"2".to_vec()]);
        worker.abort();
    }

    // ── K8b: shutdown drain, spool and replay ─────────────────────────

    /// Hook items as `enqueue_batch` makes them: one per node, each with
    /// `per` detections.
    fn payload_items(nodes: &[&str], per: usize) -> Vec<HookItem> {
        let staging = IngestHooks::default();
        for node in nodes {
            let dets: Vec<DetectionRecord> = (0..per)
                .map(|i| det(&format!("{node}-d{i}"), None))
                .collect();
            let refs: Vec<&DetectionRecord> = dets.iter().collect();
            staging.enqueue_batch(node, &refs, "2026-11-06T00:00:01.000000+00:00");
        }
        staging.take_all(false)
    }

    fn queued(hooks: &IngestHooks) -> Vec<HookItem> {
        std::iter::from_fn(|| hooks.pop()).collect()
    }

    fn node_ids(items: &[HookItem]) -> Vec<String> {
        items.iter().map(|i| i.node_id.clone()).collect()
    }

    /// A bridge that answers 200 after `delay`, counting requests.
    async fn slow_bridge(delay: Duration) -> (String, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        let app = Router::new().route(
            HOOK_PATH,
            post(move || {
                let counter = Arc::clone(&counter);
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(delay).await;
                    StatusCode::OK
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (url, hits)
    }

    async fn dead_bridge() -> String {
        let addr = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn the_shutdown_drain_tries_each_item_once_and_stops_at_a_failure() {
        // 200 for "a", then 500 for "b": no retry, no pause; "b" and "c"
        // stay queued, "b" first.
        let (url, b) = bridge(&[200, 500]).await;
        let hooks = IngestHooks::default();
        for node in ["a", "b", "c"] {
            hooks.push(item(node, 1, 1));
        }
        let mut t = target(&url);
        t.timing.cooldown = Duration::from_secs(30);
        t.timing.backoff = [Duration::from_secs(30), Duration::from_secs(30)];
        let started = std::time::Instant::now();
        let report = hooks.drain(&t, SHUTDOWN_DRAIN).await;
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(report.delivered_batches, 1);
        assert_eq!(
            report.bridge_failure.as_deref(),
            Some("HTTP 500 Internal Server Error")
        );
        assert_eq!(b.hits.load(Ordering::SeqCst), 2);
        assert_eq!(hooks.stats().retries, 0);
        assert_eq!(node_ids(&queued(&hooks)), ["b", "c"]);

        // A 4xx is dropped as usual and the drain goes on.
        let (url, _) = bridge(&[403, 200]).await;
        let hooks = IngestHooks::default();
        hooks.push(item("a", 1, 1));
        hooks.push(item("b", 1, 1));
        let report = hooks.drain(&target(&url), SHUTDOWN_DRAIN).await;
        assert_eq!((report.refused_batches, report.delivered_batches), (1, 1));
        assert_eq!(hooks.stats().queued_batches, 0);
    }

    #[tokio::test]
    async fn the_shutdown_drain_never_outlasts_its_budget() {
        let (url, hits) = slow_bridge(Duration::from_secs(10)).await;
        let hooks = IngestHooks::default();
        hooks.push(item("a", 1, 1));
        hooks.push(item("b", 1, 1));
        let started = std::time::Instant::now();
        let report = hooks.drain(&target(&url), Duration::from_millis(300)).await;
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(report.bridge_failure.as_deref(), Some("timed out"));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(node_ids(&queued(&hooks)), ["a", "b"]);
    }

    /// V2 regression: queued hooks were lost when the gateway stopped (the
    /// edge already had its 200, and a resend is a duplicate that is never
    /// hooked). They are saved, private, and queued again — first — at the
    /// next start, and the spool is deleted.
    #[tokio::test]
    async fn undelivered_hooks_survive_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("data").join("hooks.spool");
        let hooks = IngestHooks::default();
        for item in payload_items(&["edge-1", "edge-2"], 3) {
            hooks.push(item);
        }
        let before: Vec<Bytes> = {
            let q = hooks.queue.lock().unwrap();
            q.items.iter().map(|i| i.body.clone()).collect()
        };
        // The bridge is down: one attempt, then everything is spooled.
        hooks
            .shutdown(&target(&dead_bridge().await), &spool, SHUTDOWN_DRAIN)
            .await;
        assert_eq!(hooks.stats().queued_batches, 0);
        let text = std::fs::read_to_string(&spool).unwrap();
        assert_eq!(text.lines().count(), 2);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&spool).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "{mode:o}");
        }
        assert!(!spool_tmp_path(&spool).exists());

        // The next start: restored before anything new, and deleted.
        let next = IngestHooks::default();
        let report = next.restore(&spool).unwrap();
        assert_eq!(
            (report.batches, report.detections, report.skipped_lines),
            (2, 6, 0)
        );
        assert!(!spool.exists());
        next.push(item("new", 1, 1));
        let stats = next.stats();
        assert_eq!((stats.restored_batches, stats.restored_detections), (2, 6));
        let items = queued(&next);
        assert_eq!(node_ids(&items), ["edge-1", "edge-2", "new"]);
        assert_eq!(items[0].detections, 3);
        let after: Vec<Bytes> = items[..2].iter().map(|i| i.body.clone()).collect();
        assert_eq!(after, before, "the bodies are sent as they were queued");
        // Nothing to restore any more.
        assert_eq!(next.restore(&spool).unwrap(), RestoreReport::default());
    }

    #[tokio::test]
    async fn a_live_bridge_gets_everything_at_shutdown_and_no_spool_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("hooks.spool");
        let (url, b) = bridge(&[]).await;
        let hooks = IngestHooks::default();
        for item in payload_items(&["edge-1", "edge-2", "edge-3"], 2) {
            hooks.push(item);
        }
        hooks.shutdown(&target(&url), &spool, SHUTDOWN_DRAIN).await;
        assert_eq!(b.hits.load(Ordering::SeqCst), 3);
        assert_eq!(hooks.stats().delivered_detections, 6);
        assert!(!spool.exists());

        // An empty queue leaves an existing spool alone (hooks disabled
        // keep an earlier run's spool for later; K10).
        std::fs::write(&spool, b"kept\n").unwrap();
        IngestHooks::default().spool(&spool).unwrap();
        assert_eq!(std::fs::read(&spool).unwrap(), b"kept\n");
    }

    /// Everything logged (INFO and above) from now until the guard drops,
    /// on this thread (a `#[tokio::test]` runs its tasks on it).
    fn capture_logs() -> (Arc<Mutex<Vec<u8>>>, tracing::subscriber::DefaultGuard) {
        #[derive(Clone)]
        struct Buffer(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Buffer {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let writer = Buffer(Arc::clone(&buffer));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::INFO)
            .finish();
        crate::test_support::keep_log_capture_reliable();
        (buffer, tracing::subscriber::set_default(subscriber))
    }

    fn text(buffer: &Arc<Mutex<Vec<u8>>>) -> String {
        String::from_utf8(buffer.lock().unwrap().clone()).unwrap()
    }

    /// GW5-R3 regression: with nothing left to spool, the shutdown logged
    /// "Every post-ingest hook was delivered before exiting" — also when
    /// the worker had just given items up during the shutdown grace
    /// period, whose own warning is rate-limited (first and every 100th),
    /// so that false line was often the only one. The summary now comes
    /// from the counters: a WARN with the totals when anything was lost.
    #[tokio::test]
    async fn the_shutdown_summary_reports_hooks_lost_while_running() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("hooks.spool");
        let (url, _) = bridge(&[500; 6]).await;
        let hooks = IngestHooks::default();
        // The worker gives two items up (the first one's warning is
        // logged, the second one's is not: rate-limited).
        for node in ["a", "b"] {
            assert_eq!(
                hooks.deliver(&target(&url), item(node, 2, 1)).await,
                HookOutcome::Failed
            );
        }
        let (logs, guard) = capture_logs();
        let end = hooks.shutdown(&target(&url), &spool, SHUTDOWN_DRAIN).await;
        drop(guard);
        let logs = text(&logs);
        assert!(!spool.exists());
        assert_eq!((end.failed_batches, end.failed_detections), (2, 4));
        assert!(
            !logs.contains("Every post-ingest hook was delivered"),
            "{logs}"
        );
        let summary: Vec<&str> = logs
            .lines()
            .filter(|l| l.contains("Post-ingest hooks were lost while the gateway ran"))
            .collect();
        assert_eq!(summary.len(), 1, "{logs}");
        assert!(summary[0].contains("WARN"), "{}", summary[0]);
        for field in [
            "failed_batches=2",
            "failed_detections=4",
            "dropped_batches=0",
        ] {
            assert!(summary[0].contains(field), "{field}: {}", summary[0]);
        }

        // Nothing lost: an INFO that says so, no warning.
        let (url, _) = bridge(&[]).await;
        let hooks = IngestHooks::default();
        hooks.push(item("a", 1, 1));
        let (logs, guard) = capture_logs();
        hooks.shutdown(&target(&url), &spool, SHUTDOWN_DRAIN).await;
        drop(guard);
        let logs = text(&logs);
        assert!(
            logs.contains("No post-ingest hooks left to deliver at shutdown"),
            "{logs}"
        );
        assert!(!logs.contains("WARN"), "{logs}");
    }

    /// The items a spool that cannot be written took from the queue are
    /// lost: counted as dropped, so the shutdown summary reports them.
    #[tokio::test]
    async fn hooks_an_unwritable_spool_could_not_save_are_counted_as_dropped() {
        let dir = tempfile::tempdir().unwrap();
        // A directory where the spool's file should be: it cannot be
        // renamed over.
        let spool = dir.path().join("hooks.spool");
        std::fs::create_dir(&spool).unwrap();
        std::fs::write(spool.join("x"), b"x").unwrap();
        let hooks = IngestHooks::default();
        hooks.push(item("a", 3, 1));
        let (logs, guard) = capture_logs();
        let end = hooks
            .shutdown(&target(&dead_bridge().await), &spool, SHUTDOWN_DRAIN)
            .await;
        drop(guard);
        let logs = text(&logs);
        assert_eq!((end.dropped_batches, end.dropped_detections), (1, 3));
        assert_eq!(end.queued_batches, 0);
        assert!(logs.contains("cannot write the spool"), "{logs}");
        assert!(
            logs.contains("Post-ingest hooks were lost while the gateway ran"),
            "{logs}"
        );
    }

    #[test]
    fn the_spool_is_bounded_and_drops_the_oldest_first() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("hooks.spool");
        let items = payload_items(&["n0", "n1", "n2", "n3"], 1);
        let line = items[0].body.len() + 1;
        assert!(items.iter().all(|i| i.body.len() + 1 == line));
        // Room for two lines and a half.
        let hooks = IngestHooks::default().with_spool_limit(line * 5 / 2);
        for item in items {
            hooks.push(item);
        }
        let report = hooks.spool(&spool).unwrap();
        assert_eq!((report.batches, report.dropped_batches), (2, 2));
        assert_eq!(hooks.stats().dropped_batches, 2);
        let restored = IngestHooks::default();
        restored.restore(&spool).unwrap();
        assert_eq!(node_ids(&queued(&restored)), ["n2", "n3"]);
    }

    #[test]
    fn a_spool_is_read_back_within_its_bound_and_garbage_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("hooks.spool");
        let items = payload_items(&["n0", "n1", "n2"], 1);
        let mut data = Vec::new();
        data.extend_from_slice(&items[0].body);
        data.extend_from_slice(b"\nnot json\n{\"node_id\": 7, \"detections\": [1]}\n");
        data.extend_from_slice(b"{\"node_id\": \"x\", \"detections\": []}\n\n");
        data.extend_from_slice(&items[1].body);
        data.push(b'\n');
        let within = data.len();
        data.extend_from_slice(&items[2].body);
        data.push(b'\n');
        std::fs::write(&spool, &data).unwrap();

        // Read at most `within` bytes and a bit: the third payload is cut
        // and left out, as a partial last line.
        let hooks = IngestHooks::default().with_spool_limit(within + 10);
        let report = hooks.restore(&spool).unwrap();
        assert_eq!(
            report,
            RestoreReport {
                batches: 2,
                detections: 2,
                skipped_lines: 3,
                truncated: true,
            }
        );
        assert_eq!(node_ids(&queued(&hooks)), ["n0", "n1"]);
        assert!(!spool.exists());

        // A directory where the spool should be is an error, not a hang
        // or a replay.
        std::fs::create_dir(&spool).unwrap();
        assert!(IngestHooks::default().restore(&spool).is_err());
    }

    #[test]
    fn hooks_queued_after_the_spool_was_written_are_counted_as_lost() {
        let dir = tempfile::tempdir().unwrap();
        let hooks = IngestHooks::default();
        hooks.spool(&dir.path().join("hooks.spool")).unwrap();
        hooks.push(item("late", 4, 1));
        let stats = hooks.stats();
        assert_eq!((stats.queued_batches, stats.failed_detections), (0, 4));
    }

    #[test]
    fn disabled_hooks_are_counted() {
        let hooks = IngestHooks::default();
        hooks.count_disabled(3);
        hooks.count_disabled(2);
        let stats = hooks.stats();
        assert_eq!((stats.hooks_disabled, stats.enqueued_batches), (5, 0));
    }

    /// Stopping the worker mid-delivery puts the item back first in line,
    /// for the drain or the spool.
    #[tokio::test]
    async fn a_stopped_worker_puts_back_the_item_it_was_sending() {
        let (url, hits) = slow_bridge(Duration::from_secs(30)).await;
        let hooks = Arc::new(IngestHooks::default());
        let (stop, stopped) = watch::channel(false);
        let worker = spawn_worker_until(Arc::clone(&hooks), target(&url), stopped);
        hooks.push(item("first", 1, 1));
        hooks.push(item("second", 1, 1));
        for _ in 0..100 {
            if hits.load(Ordering::SeqCst) == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        stop.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), worker)
            .await
            .expect("the worker stops at once")
            .unwrap();
        assert_eq!(node_ids(&queued(&hooks)), ["first", "second"]);
        assert_eq!(hooks.stats().delivered_batches, 0);

        // An idle worker stops too, and one without a stop signal does not.
        let (stop, stopped) = watch::channel(false);
        let idle = spawn_worker_until(Arc::new(IngestHooks::default()), target(&url), stopped);
        stop.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), idle)
            .await
            .unwrap()
            .unwrap();
        let forever = spawn_worker(Arc::new(IngestHooks::default()), target(&url));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!forever.is_finished());
        forever.abort();
    }

    /// Wait (at most 10 s) until `done` holds.
    async fn wait_until(mut done: impl FnMut() -> bool) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while !done() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("condition not reached");
    }

    /// The spool holds one payload per line and its lines are replayed
    /// with the proxy secret: an item whose body holds a line feed (it
    /// would be read back as several items, a forged one among them) or
    /// is empty is never written, and is counted as lost.
    #[test]
    fn an_item_that_would_not_read_back_as_itself_is_never_spooled() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("hooks.spool");
        let hooks = IngestHooks::default();
        for item in payload_items(&["edge-1"], 2) {
            hooks.push(item);
        }
        hooks.push(HookItem {
            node_id: "edge-2".into(),
            detections: 1,
            body: Bytes::from_static(
                b"{\"node_id\": \"edge-2\", \"detections\": [{}]}\n\
                  {\"node_id\": \"forged\", \"detections\": [{\"detection_id\": \"x\"}]}",
            ),
        });
        hooks.push(HookItem {
            node_id: "edge-3".into(),
            detections: 4,
            body: Bytes::new(),
        });
        let report = hooks.spool(&spool).unwrap();
        assert_eq!((report.batches, report.detections), (1, 2), "{report:?}");
        assert_eq!((report.dropped_batches, report.dropped_detections), (2, 5));
        assert_eq!(
            (
                hooks.stats().dropped_batches,
                hooks.stats().dropped_detections
            ),
            (2, 5)
        );
        assert_eq!(std::fs::read_to_string(&spool).unwrap().lines().count(), 1);

        let next = IngestHooks::default();
        let restored = next.restore(&spool).unwrap();
        assert_eq!((restored.batches, restored.skipped_lines), (1, 0));
        assert_eq!(node_ids(&queued(&next)), ["edge-1"]);
    }

    /// Only a JSON object with a string `node_id` and a non-empty
    /// `detections` array is queued again from the spool.
    #[test]
    fn spooled_lines_without_a_node_or_detections_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("hooks.spool");
        let good = &payload_items(&["edge-1"], 1)[0];
        let mut data = Vec::new();
        for bad in [
            &br#"{"detections": [{}]}"#[..],
            br#"{"node_id": "x"}"#,
            br#"{"node_id": "x", "detections": []}"#,
            br#"{"node_id": "x", "detections": {"0": {}}}"#,
            br#"{"node_id": null, "detections": [{}]}"#,
            br#"["x", [{}]]"#,
        ] {
            data.extend_from_slice(bad);
            data.push(b'\n');
        }
        data.extend_from_slice(&good.body);
        data.push(b'\n');
        std::fs::write(&spool, &data).unwrap();
        let hooks = IngestHooks::default();
        let report = hooks.restore(&spool).unwrap();
        assert_eq!(
            (report.batches, report.detections, report.skipped_lines),
            (1, 1, 6)
        );
        let items = queued(&hooks);
        assert_eq!(node_ids(&items), ["edge-1"]);
        assert_eq!(items[0].body, good.body);
    }

    /// A leftover temporary spool (an interrupted write, or something
    /// planted there) is removed and the spool created afresh, mode 0600:
    /// a symlink at that path is not followed, and a looser mode is not
    /// kept.
    #[cfg(unix)]
    #[test]
    fn a_leftover_temporary_spool_is_replaced_not_followed() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("hooks.spool");
        let tmp = spool_tmp_path(&spool);
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"victim").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).unwrap();

        for leftover in ["symlink", "loose file"] {
            if leftover == "symlink" {
                std::os::unix::fs::symlink(&victim, &tmp).unwrap();
            } else {
                std::fs::write(&tmp, b"stale\n").unwrap();
                std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o666)).unwrap();
            }
            let hooks = IngestHooks::default();
            let item = payload_items(&["edge-1"], 1).remove(0);
            let body = item.body.clone();
            hooks.push(item);
            let report = hooks.spool(&spool).unwrap();
            assert_eq!(report.batches, 1, "{leftover}");
            let mut expected = body.to_vec();
            expected.push(b'\n');
            assert_eq!(std::fs::read(&spool).unwrap(), expected, "{leftover}");
            let meta = std::fs::symlink_metadata(&spool).unwrap();
            assert!(meta.file_type().is_file(), "{leftover}");
            assert_eq!(meta.permissions().mode() & 0o777, 0o600, "{leftover}");
            assert!(std::fs::symlink_metadata(&tmp).is_err(), "{leftover}");
            assert_eq!(std::fs::read(&victim).unwrap(), b"victim", "{leftover}");
            let mode = std::fs::metadata(&victim).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o644, "{leftover}");
        }
    }

    /// A spool that cannot be deleted is left alone and nothing is queued
    /// from it: queued, it would be replayed at every start.
    #[cfg(unix)]
    #[test]
    fn a_spool_that_cannot_be_deleted_is_not_replayed() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        std::fs::create_dir(&data).unwrap();
        let spool = data.join("hooks.spool");
        let staging = IngestHooks::default();
        for item in payload_items(&["edge-1"], 1) {
            staging.push(item);
        }
        staging.spool(&spool).unwrap();
        let before = std::fs::read(&spool).unwrap();
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o500)).unwrap();
        // Permissions do not bind root: then a spool cannot be made
        // undeletable this way.
        let enforced = std::fs::File::create(data.join("probe")).is_err();
        let hooks = IngestHooks::default();
        let restored = enforced.then(|| hooks.restore(&spool));
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
        let Some(restored) = restored else {
            // CI runs as an unprivileged user (GitHub's runners do): a CI
            // job running as root must not pass this without testing it.
            assert!(
                std::env::var_os("CI").is_none(),
                "directory permissions are not enforced for this CI user, \
                 so this test cannot run: run the suite as a non-root user"
            );
            eprintln!("skipped: directory permissions are not enforced for this user");
            return;
        };
        assert!(restored.is_err(), "{restored:?}");
        assert_eq!(hooks.stats().queued_batches, 0);
        assert_eq!(hooks.stats().restored_batches, 0);
        assert_eq!(std::fs::read(&spool).unwrap(), before);
    }

    /// With no time left, the shutdown drain sends nothing and says so;
    /// everything stays queued, in order, for the spool.
    #[tokio::test]
    async fn a_drain_with_no_time_left_sends_nothing() {
        let (url, b) = bridge(&[]).await;
        let hooks = IngestHooks::default();
        hooks.push(item("a", 1, 1));
        hooks.push(item("b", 1, 1));
        let report = hooks.drain(&target(&url), Duration::ZERO).await;
        assert_eq!(
            report,
            DrainReport {
                timed_out: true,
                ..DrainReport::default()
            }
        );
        assert_eq!(b.hits.load(Ordering::SeqCst), 0);
        assert_eq!(node_ids(&queued(&hooks)), ["a", "b"]);
        // An empty queue has not timed out.
        assert_eq!(
            IngestHooks::default()
                .drain(&target(&url), Duration::ZERO)
                .await,
            DrainReport::default()
        );
    }

    /// After giving an item up, the worker pauses before the next one (a
    /// bridge that is down does not empty the queue at once); a stop
    /// signal cuts the pause short, leaving the next item queued.
    #[tokio::test]
    async fn the_worker_pauses_after_giving_an_item_up_until_stopped() {
        let (url, b) = bridge(&[500; 6]).await;
        let hooks = Arc::new(IngestHooks::default());
        let mut t = target(&url);
        t.timing.cooldown = Duration::from_secs(60);
        let (stop, stopped) = watch::channel(false);
        hooks.push(item("first", 1, 1));
        hooks.push(item("second", 1, 1));
        let worker = spawn_worker_until(Arc::clone(&hooks), t, stopped);
        wait_until(|| hooks.stats().failed_batches == 1).await;
        stop.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(5), worker)
            .await
            .expect("the stop signal ends the pause")
            .unwrap();
        assert_eq!(b.hits.load(Ordering::SeqCst), ATTEMPTS);
        assert_eq!(node_ids(&queued(&hooks)), ["second"]);
    }

    /// Edge-supplied `decoded_messages` that are not a list are dropped
    /// and counted, not forwarded.
    #[test]
    fn decoded_messages_that_are_not_a_list_are_dropped() {
        let hooks = IngestHooks::default();
        let dets = [
            det("d1", Some(serde_json::json!("hello"))),
            det("d2", Some(serde_json::json!({"protocol": "adsb"}))),
            det("d3", Some(serde_json::Value::Null)),
        ];
        let refs: Vec<&DetectionRecord> = dets.iter().collect();
        hooks.enqueue_batch("edge-1", &refs, "2026-11-06T00:00:01.000000+00:00");
        let payload: serde_json::Value =
            serde_json::from_slice(&hooks.pop().unwrap().body).unwrap();
        assert_eq!(payload["decoded_messages"], serde_json::json!([]));
        assert_eq!(payload["detections"].as_array().unwrap().len(), 3);
        assert_eq!(hooks.stats().decoded_messages_dropped, 2);
    }

    /// A proxy secret that is not a valid header value (CR/LF) is sent as
    /// an empty X-Rust-Proxy, which the bridge refuses: it never injects a
    /// header, and the item is dropped as refused.
    #[tokio::test]
    async fn a_secret_that_is_no_header_value_is_never_sent() {
        let (url, b) = bridge(&[403]).await;
        let mut t = target(&url);
        t.proxy_secret = "s3cret\r\nX-Injected: 1".into();
        let hooks = IngestHooks::default();
        assert_eq!(
            hooks.deliver(&t, item("a", 1, 1)).await,
            HookOutcome::Refused
        );
        let seen = b.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0.as_deref(), Some(""));
        assert_eq!(hooks.stats().failed_batches, 1);
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;
    use crate::test_support::{logs_of, REFUSED_URL};

    /// A hook item for `node` with `detections` detections, as queued.
    fn item(node: &str, detections: usize) -> HookItem {
        let payload = serde_json::json!({
            "node_id": node,
            "detections": vec![serde_json::json!({"detection_id": "d"}); detections],
        });
        HookItem {
            node_id: node.into(),
            detections,
            body: Bytes::from(serde_json::to_vec(&payload).unwrap()),
        }
    }

    /// Hooks to `url`, without waits between attempts.
    fn target(url: &str) -> HookTarget {
        let mut target = HookTarget::new(reqwest::Client::new(), url, "hook-secret");
        target.timing = RetryTiming {
            backoff: [Duration::ZERO; ATTEMPTS - 1],
            cooldown: Duration::ZERO,
            timeout: Duration::from_secs(10),
        };
        target
    }

    /// Run `future` to completion on a runtime of this thread, so that
    /// [`logs_of`] sees everything it logs.
    fn on_this_thread<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(future)
    }

    fn shutdown_logged(hooks: &IngestHooks, spool: &Path) -> (HookStats, String) {
        logs_of(|| {
            on_this_thread(hooks.shutdown(&target(REFUSED_URL), spool, Duration::from_secs(10)))
        })
    }

    /// A shutdown with nothing queued and nothing lost since the start says
    /// so (at INFO, no warning) and leaves no spool behind.
    #[test]
    fn a_shutdown_with_nothing_queued_or_lost_says_so_and_writes_no_spool() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("hooks.spool");
        let hooks = IngestHooks::new(100, 1 << 20);
        let (stats, logs) = shutdown_logged(&hooks, &spool);
        assert_eq!(stats, hooks.stats());
        assert_eq!(
            (
                stats.failed_batches,
                stats.dropped_batches,
                stats.queued_batches
            ),
            (0, 0, 0)
        );
        assert!(
            logs.contains("No post-ingest hooks left to deliver at shutdown, and none was lost"),
            "{logs}"
        );
        assert!(!logs.contains(" WARN "), "{logs}");
        assert!(!spool.exists());
    }

    /// Hooks the bridge does not take at shutdown (it is down) are saved
    /// for the next start, oldest first, and every step is reported: the
    /// drain, the bridge failure, what was saved, and a summary saying
    /// nothing was lost. The next start queues them again.
    #[test]
    fn hooks_the_bridge_does_not_take_at_shutdown_are_saved_and_reported() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("hooks.spool");
        let hooks = IngestHooks::new(100, 1 << 20);
        hooks.push(item("edge-1", 2));
        hooks.push(item("edge-2", 3));
        let (stats, logs) = shutdown_logged(&hooks, &spool);
        assert_eq!(
            (
                stats.queued_batches,
                stats.failed_batches,
                stats.dropped_batches
            ),
            (0, 0, 0)
        );
        for expected in [
            "Delivering the queued post-ingest hooks before exiting",
            "queued_batches=2",
            "The bridge did not take a post-ingest hook at shutdown",
            "were saved; they are sent at the next start",
            "detections=5",
            "No post-ingest hook was lost since the start",
        ] {
            assert!(logs.contains(expected), "{expected:?} missing: {logs}");
        }
        let saved = std::fs::read_to_string(&spool).unwrap();
        let nodes: Vec<String> = saved
            .lines()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line).unwrap()["node_id"].to_string()
            })
            .collect();
        assert_eq!(nodes, ["\"edge-1\"", "\"edge-2\""]);

        let next = IngestHooks::new(100, 1 << 20);
        let restored = next.restore(&spool).unwrap();
        assert_eq!((restored.batches, restored.detections), (2, 5));
        assert_eq!(next.stats().queued_detections, 5);
        assert!(!spool.exists());
    }

    /// Hooks that do not fit in the spool at shutdown (the oldest first)
    /// are lost: they are counted as dropped, an error says so, and the
    /// summary warns that hooks were lost, with the totals.
    #[test]
    fn hooks_that_do_not_fit_in_the_spool_are_counted_and_reported_as_lost() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("hooks.spool");
        let (oldest, newest) = (item("edge-1", 1), item("edge-2", 2));
        let hooks = IngestHooks::new(100, 1 << 20).with_spool_limit(newest.body.len() + 1);
        hooks.push(oldest);
        hooks.push(newest);
        let (stats, logs) = shutdown_logged(&hooks, &spool);
        assert_eq!(
            (
                stats.dropped_batches,
                stats.dropped_detections,
                stats.queued_batches
            ),
            (1, 1, 0)
        );
        for expected in [
            "Post-ingest hooks lost at shutdown: they did not fit in the spool",
            "dropped_batches=1",
            "Post-ingest hooks were lost while the gateway ran",
        ] {
            assert!(logs.contains(expected), "{expected:?} missing: {logs}");
        }
        let saved = std::fs::read_to_string(&spool).unwrap();
        assert_eq!(saved.lines().count(), 1);
        assert!(saved.contains("edge-2"), "{saved}");
    }

    /// A spool that cannot be written (its directory is a file) loses what
    /// was queued: the hooks are counted as dropped, an error names the
    /// setting to fix, the summary warns, and the file in the way is left
    /// alone.
    #[test]
    fn hooks_are_reported_lost_when_the_spool_cannot_be_written() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("not-a-directory");
        std::fs::write(&blocker, b"keep me").unwrap();
        let hooks = IngestHooks::new(100, 1 << 20);
        hooks.push(item("edge-1", 3));
        let (stats, logs) = shutdown_logged(&hooks, &blocker.join("hooks.spool"));
        assert_eq!(
            (
                stats.dropped_batches,
                stats.dropped_detections,
                stats.queued_batches
            ),
            (1, 3, 0)
        );
        for expected in [
            "are LOST: cannot write the spool",
            "UC_HOOK_SPOOL_PATH",
            "Post-ingest hooks were lost while the gateway ran",
        ] {
            assert!(logs.contains(expected), "{expected:?} missing: {logs}");
        }
        assert_eq!(std::fs::read(&blocker).unwrap(), b"keep me");
    }

    /// A temporary spool path taken by a directory (not a leftover file) is
    /// not removed: the spool fails, nothing is written, the taken items
    /// are counted as dropped, and the queue stays closed (a later hook is
    /// counted as failed, not queued).
    #[test]
    fn a_spool_whose_temporary_path_is_a_directory_is_not_written() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("hooks.spool");
        let tmp = dir.path().join("hooks.spool.tmp");
        std::fs::create_dir(&tmp).unwrap();
        let hooks = IngestHooks::new(100, 1 << 20);
        hooks.push(item("edge-1", 4));
        let err = hooks.spool(&spool).unwrap_err();
        assert_ne!(err.kind(), io::ErrorKind::NotFound, "{err}");
        assert!(!spool.exists());
        assert!(tmp.is_dir());
        let stats = hooks.stats();
        assert_eq!(
            (
                stats.dropped_batches,
                stats.dropped_detections,
                stats.queued_batches
            ),
            (1, 4, 0)
        );

        let ((), logs) = logs_of(|| hooks.push(item("late", 1)));
        let stats = hooks.stats();
        assert_eq!((stats.queued_batches, stats.failed_batches), (0, 1));
        assert!(
            logs.contains("Post-ingest hook queued after the shutdown spool was written"),
            "{logs}"
        );
        assert!(logs.contains("node_id=late"), "{logs}");
    }

    /// A full queue drops its oldest batch for each new one: every drop is
    /// counted, only the first and every [`DROP_LOG_EVERY`]-th are logged,
    /// and the newest batch is the one left.
    #[test]
    fn a_full_queue_drops_the_oldest_and_logs_only_every_100th_drop() {
        let hooks = IngestHooks::new(1, 1 << 20);
        let pushes = DROP_LOG_EVERY as usize + 2;
        let ((), logs) = logs_of(|| {
            for i in 0..pushes {
                hooks.push(item(&format!("edge-{i}"), 1));
            }
        });
        let stats = hooks.stats();
        assert_eq!(
            (
                stats.queued_batches,
                stats.dropped_batches,
                stats.enqueued_batches
            ),
            (1, pushes as u64 - 1, pushes as u64)
        );
        assert_eq!(
            logs.matches("Post-ingest hook queue full — dropped the oldest batch")
                .count(),
            2,
            "{logs}"
        );
        assert!(logs.contains("dropped_batches=101 "), "{logs}");
        let left = on_this_thread(hooks.next());
        assert_eq!(left.node_id, format!("edge-{}", pushes - 1));
    }

    /// A hook the bridge cannot be reached for is tried [`ATTEMPTS`] times,
    /// then given up: counted as failed, with its retries, and logged.
    #[test]
    fn a_hook_given_up_after_its_attempts_is_counted_and_logged() {
        let hooks = IngestHooks::new(100, 1 << 20);
        let (outcome, logs) =
            logs_of(|| on_this_thread(hooks.deliver(&target(REFUSED_URL), item("edge-1", 2))));
        assert_eq!(outcome, HookOutcome::Failed);
        let stats = hooks.stats();
        assert_eq!(
            (stats.failed_batches, stats.failed_detections, stats.retries),
            (1, 2, ATTEMPTS as u64 - 1)
        );
        assert!(
            logs.contains("Post-ingest hook failed after retries — dropped"),
            "{logs}"
        );
        assert!(logs.contains("attempts=3"), "{logs}");
    }

    /// A spool path that cannot be opened for another reason than being
    /// absent (here its directory is a file) is an error, not "nothing to
    /// restore", and nothing is queued.
    #[test]
    fn a_spool_that_cannot_be_opened_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("file");
        std::fs::write(&blocker, b"x").unwrap();
        let hooks = IngestHooks::new(100, 1 << 20);
        let err = hooks.restore(&blocker.join("hooks.spool")).unwrap_err();
        assert_ne!(err.kind(), io::ErrorKind::NotFound, "{err}");
        let stats = hooks.stats();
        assert_eq!((stats.queued_batches, stats.restored_batches), (0, 0));
    }

    /// Every hook the bridge refuses (4xx) is counted, but only the first
    /// refusal and every [`DROP_LOG_EVERY`]-th after it are logged, so a
    /// bridge refusing every hook does not flood the log.
    #[test]
    fn every_refused_hook_is_counted_and_only_every_100th_is_logged() {
        let hooks = IngestHooks::new(1_000, 1 << 20);
        let refusals = DROP_LOG_EVERY as usize + 1;
        let (outcomes, logs) = logs_of(|| {
            on_this_thread(async {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let url = format!("http://{}", listener.local_addr().unwrap());
                let bridge = axum::Router::new().route(
                    HOOK_PATH,
                    axum::routing::post(|| async { axum::http::StatusCode::FORBIDDEN }),
                );
                tokio::spawn(async move { axum::serve(listener, bridge).await.unwrap() });
                let target = target(&url);
                let mut outcomes = Vec::new();
                for i in 0..refusals {
                    outcomes.push(hooks.deliver(&target, item(&format!("edge-{i}"), 1)).await);
                }
                outcomes
            })
        });
        assert!(
            outcomes.iter().all(|o| *o == HookOutcome::Refused),
            "{outcomes:?}"
        );
        let stats = hooks.stats();
        assert_eq!(
            (stats.failed_batches, stats.failed_detections, stats.retries),
            (refusals as u64, refusals as u64, 0)
        );
        assert_eq!(
            logs.matches("The bridge refused a post-ingest hook")
                .count(),
            2,
            "{logs}"
        );
        assert!(logs.contains("failed_batches=1\n"), "{logs}");
        assert!(logs.contains("failed_batches=101\n"), "{logs}");
    }

    /// Edge-decoded messages a hook does not carry (an entry that is not an
    /// object, one larger than [`MAX_DECODED_MESSAGE_BYTES`]) are counted
    /// and reported in one warning for the batch, with the node, how many
    /// were dropped and the limits, and never with their content. The
    /// message that fits is carried, stamped with its detection and node.
    #[test]
    fn dropped_edge_decoded_messages_are_counted_and_reported_without_content() {
        let mut det: DetectionRecord = serde_json::from_value(serde_json::json!({
            "detection_id": "d1", "node_id": "edge-1", "signal_class": "lora-css",
            "confidence": 0.9, "freq_hz": 868e6, "timestamp": "2026-11-06T00:00:00+00:00",
        }))
        .unwrap();
        det.decoded_messages = Some(serde_json::json!([
            "not-an-object",
            {"blob": "confidential-payload".repeat(1_000)},
            {"protocol": "adsb", "icao": "abc123"},
        ]));
        let hooks = IngestHooks::new(100, 1 << 20);
        let ((), logs) =
            logs_of(|| hooks.enqueue_batch("edge-1", &[&det], "2026-11-06T00:00:01.000000+00:00"));
        assert_eq!(hooks.stats().decoded_messages_dropped, 2);
        let warned: Vec<&str> = logs
            .lines()
            .filter(|l| l.contains("Edge-decoded messages dropped"))
            .collect();
        assert_eq!(warned.len(), 1, "{logs}");
        for named in [
            " WARN ",
            "node_id=\"edge-1\"",
            "dropped=2",
            "max_per_detection=50",
            "max_per_batch=1000",
            "max_bytes=16384",
        ] {
            assert!(warned[0].contains(named), "{named:?} missing: {logs}");
        }
        assert!(!logs.contains("confidential-payload"), "{logs}");
        assert!(!logs.contains("not-an-object"), "{logs}");

        let queued: serde_json::Value = serde_json::from_slice(&hooks.pop().unwrap().body).unwrap();
        assert_eq!(
            queued["decoded_messages"],
            serde_json::json!([{"protocol": "adsb", "icao": "abc123",
                                "detection_id": "d1", "node_id": "edge-1"}])
        );
    }
}
