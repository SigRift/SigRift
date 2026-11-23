# Durable RF hourly summaries

RF summary mode (`MLRF_SUMMARIZE=1`) keeps each accepted observation in a local
SQLite journal before `DetectionReporter.report()` returns `True`. It retains
acknowledged cumulative statistics for the current and recent UTC hours, so a
restart or a late observation cannot replace an earlier count with a smaller one.
Raw mode keeps its existing buffering contract; this journal is not a raw-upload
or alert outbox.

## Storage and ownership

Set `MLRF_DATA_DIR` to persistent storage. The standard Compose `scan` service
already mounts the named `edge_data` volume at `/app/data` and sets this variable.
A container filesystem path alone is insufficient. The journal is under
`MLRF_DATA_DIR/summary-journal`, with a private SQLite file and a single-writer
process lock. Keep that directory with the scanner's backups. Stop the scanner
before copying it, or use SQLite's online backup facility; do not copy only the
main database while its WAL may contain committed observations.

One journal belongs to one node ID and canonical Bridge destination. A second
live writer, changed node/destination, corrupt journal or incompatible retained
state fails clearly without replacing the old state. Recover the original
journal and original identity, or provision a deliberately separate node and
persistent directory. Deleting a journal does not reset the receiver: a new
stream for an already registered node is rejected. No automatic stream reset or
merging of unknown histories is provided.

`stop()` flushes and stops background work while preserving state for a later
`start()` or retry. Integrations must call `close()` on final disposal; this also
releases the writer lock. `close()` refuses to release ownership while an owned
worker is still alive. The RF scanner and standalone reporter do this during
shutdown and exceptional exits. Abrupt process termination releases the OS lock;
the next process recovers committed observations from SQLite.

## Upgrade and query contract

The first versioned snapshot atomically registers the stream, freezes existing
legacy summary rows for that tenant/node, and accepts the new contribution.
There is no wait for the hour to end and no discarded upgrade interval.

Summary storage queries return separate components for registered nodes:

| Component | Meaning |
| --- | --- |
| `legacy_base` | Existing legacy values, preserved exactly until normal retention |
| `stream_summary` | The journal's cumulative low-anomaly observations for one UTC hour |
| `raw_rollup` | The receiver's separately grouped raw records |

`stream_id` identifies the versioned component. `legacy_overlap` is `unknown`:
registration cannot establish which observations an older writer included.
Consumers must not add these components into a purported unique total or pool
their rounded means. Unregistered legacy nodes retain their original query shape.
Raw detections remain available separately. The setup checklist reads the latest
summary hour across both legacy and new components; it does not add their counts.

High-anomaly observations keep stable raw IDs and use the existing authenticated
raw ingestion and alert-hook path. A lost response can cause a replay; already
stored raw IDs use the existing deduplication behavior. This does not make the
post-commit analysis/hooks crash-durable or exactly once.

The receiver acknowledges only the exact stream, hour, generation and body digest.
Conflicting or older generations, a replacement stream, and snapshots for a
retired hour are rejected. A generic response from an older Bridge is not a valid
acknowledgement: the scanner preserves its pending journal for repair or upgrade.

## Limits and failures

The journal retains 24 contiguous observation hours by default, up to 8 MiB of
encoded envelopes, 512 KiB per hour, 16,384 entries overall and 4,096 per hour.
These are encoded-data limits, not total SQLite or Python memory sizes. Retention
can remove only acknowledged hours. Capacity, disk failures and invalid input
return `False`, leave prior accepted state intact, and increment the reason in
`summary_rejections`. `summary_retained_bytes` includes the protocol envelopes.
An unacknowledged expired hour applies backpressure rather than disappearing.

The server retains small stream/generation fences after normal summary retention,
so delayed requests cannot recreate a retired component. Back up the Bridge
SQLite database as well as the scanner journal; restoring inconsistent snapshots
can require operator reconciliation. No automatic history reconstruction is claimed.

## Downgrade restriction

Do not run an older Bridge or scanner against a node with a registered versioned
stream. Additive SQLite triggers reject legacy inserts/updates for protected nodes;
they prevent silent overwrites, but old code does not understand the separate
components and can fail its rollup operations. Unregistered nodes remain writable
under current code. Preserve the upgraded database and journal and repair forward;
removing the fences or restoring only part of the state is not a safe rollback.
