# SigRift Bridge Capacity Planning Guide

## Scaling Model

```
                    Ingest Rate (detections/sec)
                    │
  1000 ─────────────┤                              ╔═══════════════╗
                    │                              ║  PostgreSQL   ║
                    │                              ║  migration    ║
   500 ─────────────┤                    ┌─────────║  recommended  ║
                    │                    │         ╚═══════════════╝
                    │              ┌─────┘
   200 ─────────────┤         ┌────┘    ← Write contention zone
                    │    ┌────┘
   100 ─────────────┤────┘    SQLite sweet spot
                    │         (batched writes, WAL mode)
    50 ─────────────┤
                    │
    10 ─────────────┤  Single-node, minimal resources
                    │
                    └────┬────┬────┬────┬────┬────┬──── Nodes
                         1    5   10   20   50  100
```

```
┌────────────────────────────────────────────────────────────┐
│              Data Flow & Storage Tiers                      │
│                                                            │
│  Edge Node                  Bridge                         │
│  ┌──────────┐               ┌──────────────────────────┐  │
│  │ SDR      │  HTTP POST    │ WriteQueue               │  │
│  │ Scanner  ├──────────────►│ (batch=100, flush=500ms) │  │
│  │          │               │         │                │  │
│  │ SAF      │◄─── retry ───│         ▼                │  │
│  │ Buffer   │               │ detections table (raw)   │  │
│  └──────────┘               │         │                │  │
│                             │         ▼ (hourly)       │  │
│                             │ detection_aggregates     │  │
│                             │         │                │  │
│                             │         ▼ (90-day)       │  │
│                             │ cleanup (configurable)   │  │
│                             └──────────────────────────┘  │
│                                                            │
│  Storage growth:  ~43 MB/day/node (raw)                   │
│                   ~1 MB/day/node (aggregated)              │
│                   Retention: BRIDGE_RETENTION_DAYS (90)    │
└────────────────────────────────────────────────────────────┘
```

## Deployment Sizing

### Assumptions

- Each edge node generates 1-10 detections/second during active scanning.
- Detection records average ~500 bytes each.
- Hourly aggregation reduces long-term storage by ~60x.
- Data retention default is 90 days (`BRIDGE_RETENTION_DAYS`).
- The `spectrum_materialized` table is the largest on disk and is pruned
  on its own knob, `BRIDGE_SPECTRUM_RETENTION_DAYS` (defaults to
  `BRIDGE_RETENTION_DAYS`). At ~180K rows/day a 90-day window holds
  ~16M rows / ~1.5 GB; lower it on disk-constrained hosts. Without a
  retention policy this table grows unbounded.
- IQ captures (optional) are 10-100 KB each, stored on filesystem.

### Sizing Table

| Nodes | Det/sec (peak) | CPU Cores | RAM | Disk (90-day) | Network | Workers |
|-------|----------------|-----------|-----|---------------|---------|---------|
| 1 | 10 | 1 | 1 GB | 5 GB | 1 Mbps | 1 |
| 5 | 50 | 2 | 2 GB | 25 GB | 5 Mbps | 2 |
| 10 | 100 | 4 | 4 GB | 50 GB | 10 Mbps | 4 |
| 50 | 500 | 8 | 8 GB | 250 GB | 50 Mbps | 4* |
| 100 | 1000 | 16 | 16 GB | 500 GB | 100 Mbps | 4* |

*SQLite single-writer limits throughput regardless of worker count beyond ~4. See PostgreSQL migration threshold below.

### Resource Estimates

**CPU**: The bridge is I/O-bound under normal loads. CPU demand scales with:
- Anomaly scoring (Tier 1 statistical: negligible; Tier 2 Isolation Forest: ~1 ms/detection; Tier 3 autoencoder: ~5 ms/detection)
- WebSocket broadcast fan-out
- Write queue batch commits

**RAM**:
- SQLite page cache: `BRIDGE_SQLITE_CACHE_SIZE` (default 64 MB)
- Memory-mapped I/O: `BRIDGE_SQLITE_MMAP_SIZE` (default 256 MB, maps DB file pages into process address space)
- Baseline manager: ~2 KB per frequency bin. 1000 active frequencies = ~2 MB
- PartitionedCache: 2048 entries, ~1-5 MB depending on payload
- Write queue buffer: `BRIDGE_WQ_BATCH_SIZE` * ~500 bytes
- Per-worker overhead: ~50-100 MB (Python + FastAPI + loaded modules)

**Disk I/O**:
- WAL mode: reads never block writes, writes never block reads
- Typical write throughput: 1000-5000 inserts/second (batched)
- Auto-checkpoint every ~4 MB of WAL writes
- Scheduled PASSIVE checkpoint every 5 minutes

**Storage Growth**:
- Raw detections: ~43 MB/day per node at 1 det/sec
- Hourly aggregates: ~1 MB/day per node
- Audit log: ~10 KB/day per active operator
- IQ captures: highly variable, 0-1 GB/day depending on capture policy

---

## SQLite Performance Envelope

### Strengths

- Zero deployment overhead (embedded, single-file database)
- Excellent read performance (concurrent readers via WAL)
- MMAP + page cache deliver sub-millisecond reads for hot data
- Built-in backup via `.backup` command (online, consistent)

### Limitations

- **Single writer**: Only one write transaction at a time. Write queue batching mitigates this but cannot eliminate it.
- **WAL checkpoint blocking**: TRUNCATE/RESTART checkpoints briefly block readers. PASSIVE checkpoints (used by the bridge) never block.
- **No horizontal scaling**: Cannot distribute writes across servers.
- **File size**: Performance degrades beyond ~100 GB without careful index management.

### Measured Throughput (Reference)

> **SQLCipher is not supported in this release** (see
> [DEPLOYMENT.md](DEPLOYMENT.md#data-at-rest-encryption)). The SQLCipher
> columns and the tuning notes below are reference measurements only.

| Operation | Throughput (plain) | Throughput (SQLCipher) | Notes |
|-----------|-------------------|----------------------|-------|
| Batched inserts (100/batch) | 3000-5000 rows/sec | 2500-4500 rows/sec | WAL mode, `synchronous=NORMAL` |
| Single inserts | 500-1000 rows/sec | 400-850 rows/sec | Write lock contention |
| Point queries (by PK) | 50,000+/sec | 40,000+/sec | With page cache |
| Range queries (indexed) | 10,000-30,000 rows/sec | 8,000-25,000 rows/sec | Depends on result set size |
| Aggregate queries | Varies | ~10-15% slower | Use `detection_aggregates` for dashboard queries |

### SQLCipher Performance Impact

SQLCipher adds AES-256 encryption/decryption on every page read/write. Typical overhead:

| KDF Iterations | Overhead | Security | Use Case |
|----------------|----------|----------|----------|
| 256000 (default) | ~15% | Maximum | High-security / compliance |
| 64000 | ~5% | Strong | Recommended balance |
| 16000 | ~2% | Adequate | Performance-critical |

Tuning: set `BRIDGE_SQLCIPHER_KDF_ITER` to reduce KDF iterations. The KDF cost is per-connection (not per-query), so impact is most visible on connection-heavy patterns.

MMAP (`BRIDGE_SQLITE_MMAP_SIZE`) works with SQLCipher but encrypted pages must be decrypted on access — the performance benefit of mmap is reduced compared to plaintext.

---

## PostgreSQL Migration Threshold

Consider migrating to PostgreSQL when:

| Signal | Threshold | Reason |
|--------|-----------|--------|
| Node count | >10 active nodes | Write contention under sustained ingest |
| Ingest rate | >200 sustained det/sec | Single-writer bottleneck |
| Database size | >50 GB | Query planner, backup time, VACUUM cost |
| Availability requirement | HA / failover needed | SQLite has no built-in replication |
| Write queue depth | Consistently >500 | Writers waiting faster than DB can flush |
| Concurrent users | >20 dashboard users | Read contention during checkpoints |

### Migration Path

The bridge uses `SQLDialect` enum and parameterized queries. PostgreSQL migration requires:

1. Schema translation (SQLite-specific PRAGMAs, `AUTOINCREMENT` -> `SERIAL`, `datetime('now')` -> `NOW()`)
2. Connection pooling (replace thread-local `sqlite3.Connection` with `asyncpg` pool)
3. Write lock removal (PostgreSQL handles concurrency internally)
4. Migration runner adaptation (use Alembic or equivalent)
5. Tenant isolation (consider schema-per-tenant for strong isolation)

---

## Monitoring Thresholds

### Alerting Rules

| Metric | Source | Warning | Critical | Action |
|--------|--------|---------|----------|--------|
| Disk usage | `GET /api/health` `disk_usage_pct` | >= 80% | >= 90% | Archive old data, expand disk |
| WAL size | `GET /api/metrics` `database.wal_size_mb` | >= 32 MB | >= 64 MB | Check for stuck readers, force checkpoint |
| DB size | `GET /api/metrics` `database.db_size_mb` | >= 10 GB | >= 50 GB | Review retention, consider PostgreSQL |
| Ingest rate | `GET /api/metrics` `ingest.detections_per_second` | < expected | 0 for 5 min | Check edge nodes, network |
| Active anomalies | `GET /api/status` `active_anomalies` | > 100 | > 500 | Review scoring thresholds, possible RF event |
| Stale nodes | `GET /api/status` `stale_nodes` | >= 1 | >= 3 | Check edge node connectivity |
| Write queue depth | `GET /api/metrics` `write_queue.pending` | >= 500 | >= 2000 | Increase batch size, check disk I/O |
| Tenant row usage | `GET /api/status` `tenant_usage.usage_pct` | >= 80% | >= 95% | Increase limit or archive data |

### Prometheus/Grafana Integration

Poll `GET /api/metrics` at 15-30 second intervals. Key fields:

```
bridge_uptime_seconds
bridge_ingest_detections_1h
bridge_ingest_detections_per_second
bridge_ws_clients_total
bridge_database_db_size_mb
bridge_database_wal_size_mb
bridge_database_row_count
bridge_cache_hits (from cache stats)
bridge_cache_misses
```

---

## Network Bandwidth per Edge Node

### Upstream (edge -> bridge)

| Component | Bandwidth | Notes |
|-----------|-----------|-------|
| Detection batches | 5-50 KB/s | Gzip-compressed JSON. 1-10 det/sec * ~500 bytes * 0.3 compression |
| Heartbeats | < 1 KB/s | Every 30 seconds |
| IQ uploads | 0-500 KB/s | Optional, depends on capture policy |
| Total per node | 10-500 KB/s | Without IQ: 10-50 KB/s |

### Downstream (bridge -> consumers)

| Component | Bandwidth | Notes |
|-----------|-----------|-------|
| WebSocket detections | 1-10 KB/s per client | JSON-encoded detection events |
| WebSocket anomalies | 0.5-5 KB/s per client | Filtered anomaly-only stream |
| WebSocket spectrum | 5-50 KB/s per client | Spectrum snapshot updates |
| Dashboard API queries | Bursty, 10-100 KB/request | Cached, infrequent |

### Network Requirements

| Deployment | Min Bandwidth | Recommended |
|------------|--------------|-------------|
| 1 node, local | 1 Mbps | 10 Mbps |
| 5 nodes, LAN | 5 Mbps | 100 Mbps |
| 10 nodes, WAN | 10 Mbps | 50 Mbps |
| 50 nodes, WAN | 50 Mbps | 100 Mbps |
| 100 nodes, WAN | 100 Mbps | 1 Gbps |

Edge nodes with SAF buffering tolerate intermittent connectivity. Buffered data replays automatically when connection restores (up to 72 hours of buffer).

---

## Docker Resource Limits

### Compose Resource Constraints

```yaml
services:
  bridge:
    build:
      context: .
      dockerfile: src/sigrift/bridge/Dockerfile
    deploy:
      resources:
        limits:
          cpus: "4.0"
          memory: 4G
        reservations:
          cpus: "1.0"
          memory: 1G
    # ...
```

### Sizing by Deployment Scale

| Nodes | CPU Limit | Memory Limit | Memory Reservation | Notes |
|-------|-----------|-------------|-------------------|-------|
| 1 | 1.0 | 1G | 512M | Minimal deployment |
| 5 | 2.0 | 2G | 1G | Small team / single site |
| 10 | 4.0 | 4G | 2G | Multi-site |
| 50 | 8.0 | 8G | 4G | Enterprise — consider PostgreSQL |

### Memory Breakdown Inside Container

| Component | Typical Usage | Controlled By |
|-----------|--------------|---------------|
| Python + FastAPI + modules | 80-120 MB | Fixed overhead |
| SQLite page cache | 64 MB (default) | `BRIDGE_SQLITE_CACHE_SIZE` |
| SQLite mmap window | Up to 256 MB | `BRIDGE_SQLITE_MMAP_SIZE` |
| PartitionedCache | 1-5 MB | 2048 entries fixed |
| Baseline manager | 1-5 MB | Scales with frequency bins |
| Write queue buffer | <1 MB | `BRIDGE_WQ_BATCH_SIZE` |
| PyTorch models (if loaded) | 50-200 MB | Optional (fingerprint/family models) |

**Key tuning for containers**: If memory-limited, reduce `BRIDGE_SQLITE_MMAP_SIZE` first (e.g., `67108864` = 64 MB) and `BRIDGE_SQLITE_CACHE_SIZE` (e.g., `-16000` = 16 MB). These are the largest variable consumers.

### Docker Volume I/O

SQLite performance depends on volume driver I/O latency:

| Volume Type | Performance | Notes |
|-------------|-------------|-------|
| Named volume (local) | Best | Default `local` driver, native filesystem |
| Bind mount | Best | Direct host filesystem access |
| NFS mount | Poor | Network latency kills SQLite WAL performance |
| Cloud block storage (EBS, etc.) | Good | Provision IOPS for write-heavy workloads |

**Do not use NFS or network-attached storage for the SQLite database.** SQLite file locking does not work reliably over NFS and WAL mode requires shared-memory (`-shm` file), which NFS does not support.
