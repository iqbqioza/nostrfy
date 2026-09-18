//! Shared counters reported by `nostrfy stats` and the NIP-11
//! information document.

use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::util::unix_now;

#[derive(Debug, Default)]
pub struct Stats {
    pub started_at: AtomicU64,
    pub connections_total: AtomicU64,
    pub connections_active: AtomicU64,
    pub subscriptions_total: AtomicU64,
    pub subscriptions_active: AtomicU64,
    pub events_received: AtomicU64,
    pub events_accepted: AtomicU64,
    pub events_rejected: AtomicU64,
    pub events_duplicate: AtomicU64,
    pub events_deleted: AtomicU64,
    pub messages_in: AtomicU64,
    pub messages_out: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub buffers_dropped: AtomicU64,
    pub db_errors: AtomicU64,
    pub db_size_bytes: AtomicU64,
    /// Recorded NIP-29 group purges still pending after the startup resume:
    /// a non-zero value means a purge could not be completed, so the group
    /// stays fail-closed (ghosted) until it is retried. A startup snapshot,
    /// not a live count.
    pub pending_purges: AtomicU64,
    /// Completed NIP-62 vanish markers. The table grows permanently by
    /// design (a vanished identity stays barred), so this gauge exists to
    /// observe growth rather than to bound it.
    pub vanish_markers: AtomicU64,
    /// NIP-62 vanishes recorded but not yet completed: non-zero right after
    /// a crash means the writer thread is resuming them at startup.
    pub pending_vanishes: AtomicU64,
    /// Blossom upload spool files removed by the startup sweep (orphans
    /// from a previous process). A growing value on every restart means
    /// uploads are being interrupted before publication.
    pub blossom_orphan_spools_swept: AtomicU64,
    /// Blob lookups where the sha→owner mapping exists but the object is
    /// gone from every owning location (a definitive NotFound / S3 404).
    /// Incremented best effort; reconciliation is intentionally lazy (a
    /// re-upload heals the blob), so the counter is a signal, not a queue.
    pub blossom_missing_objects: AtomicU64,
    /// Connections refused by the global `limits.max_connections` cap.
    pub conn_refused_global: AtomicU64,
    /// Connections refused by the per-IP concurrent cap.
    pub conn_refused_per_ip: AtomicU64,
    /// Connections refused by the per-IP connection rate limit.
    pub conn_refused_rate: AtomicU64,
    /// Trusted-proxy requests refused with `429` (per-IP rate/concurrent cap
    /// evaluated under the forwarded client address).
    pub conn_refused_proxy: AtomicU64,
    /// Requests refused with `403` because the client IP is NIP-86 blocked.
    pub conn_refused_blocked: AtomicU64,
    /// `accept()` failures on the listener (e.g. EMFILE): the relay backs off
    /// and keeps serving, so a growing value means the host is out of file
    /// descriptors or otherwise unable to accept.
    pub accept_errors: AtomicU64,
    /// Database queue depth gauges, polled from the database accessors by
    /// the stats writer (see `docs/TROUBLESHOOTING.md`).
    pub db_pending_msgs: AtomicU64,
    pub db_pending_events: AtomicU64,
    pub db_pending_bytes: AtomicU64,
    pub db_pending_reads: AtomicU64,
    pub db_pending_read_bytes: AtomicU64,
    pub db_api_pending: AtomicU64,
    pub db_api_pending_bytes: AtomicU64,
    /// Fail-fast admissions caused by a queue cap (overload), distinct from
    /// database faults ([`Self::db_errors`]). A growing value means the relay
    /// is shedding load on purpose; the database itself is healthy.
    pub db_overloaded: AtomicU64,
    /// Whether the database is refusing writes for lack of space (disk full
    /// or the LMDB map exhausted): `1` while refused, `0` otherwise.
    pub db_disk_full: AtomicU64,
    /// Free bytes on the database filesystem when the store can report it;
    /// the last known value is kept while the read fails.
    pub db_free_bytes: AtomicU64,
    /// Runtime NIP-29/NIP-43 derived-state rebuild failures after startup
    /// (a failed scan leaves the corresponding store fail-closed). A growth
    /// signal for monitoring; the startup rebuild is fatal and never counted.
    pub rebuild_failures: AtomicU64,
    /// Bookkeeping-table row counts (`DbClient::table_counts`): permanent
    /// removals live here too, so the gauges make deliberate growth
    /// observable. `None` reads keep the last value (never flip to zero).
    pub db_table_deleted: AtomicU64,
    pub db_table_first_seen: AtomicU64,
    pub db_table_purged_groups: AtomicU64,
    pub db_table_vanish: AtomicU64,
    pub db_table_vanish_pending: AtomicU64,
    pub db_table_purge_pending: AtomicU64,
    pub db_table_delete_pending: AtomicU64,
}

impl Stats {
    pub fn new() -> Arc<Stats> {
        let stats = Stats::default();
        stats.started_at.store(unix_now(), Ordering::Relaxed);
        Arc::new(stats)
    }

    pub fn bump(&self, counter: &AtomicU64, delta: u64) {
        // Saturate instead of wrapping: a counter that wrapped to a small
        // value would make the metrics lie. The load is relaxed and the
        // branch is never taken in practice.
        let current = counter.load(Ordering::Relaxed);
        if current > u64::MAX - delta {
            counter.store(u64::MAX, Ordering::Relaxed);
        } else {
            counter.fetch_add(delta, Ordering::Relaxed);
        }
    }

    pub fn as_json(&self) -> Value {
        json!({
            // When this snapshot was generated (Unix seconds). `nostrfy
            // stats` compares it against `daemon.stats_interval_secs` to
            // reject a stale file instead of printing old counters as live
            // data; stats files written before the field existed simply
            // lack it.
            "written_at": unix_now(),
            "started_at": self.started_at.load(Ordering::Relaxed),
            "uptime_secs": unix_now().saturating_sub(self.started_at.load(Ordering::Relaxed)),
            "connections": {
                "active": self.connections_active.load(Ordering::Relaxed),
                "total": self.connections_total.load(Ordering::Relaxed),
            },
            "subscriptions": {
                "active": self.subscriptions_active.load(Ordering::Relaxed),
                "total": self.subscriptions_total.load(Ordering::Relaxed),
            },
            "events": {
                "received": self.events_received.load(Ordering::Relaxed),
                "accepted": self.events_accepted.load(Ordering::Relaxed),
                "rejected": self.events_rejected.load(Ordering::Relaxed),
                "duplicate": self.events_duplicate.load(Ordering::Relaxed),
                "deleted": self.events_deleted.load(Ordering::Relaxed),
            },
            "messages": {
                "in": self.messages_in.load(Ordering::Relaxed),
                "out": self.messages_out.load(Ordering::Relaxed),
            },
            "bytes": {
                "in": self.bytes_in.load(Ordering::Relaxed),
                "out": self.bytes_out.load(Ordering::Relaxed),
            },
            "buffers_dropped": self.buffers_dropped.load(Ordering::Relaxed),
            "db_errors": self.db_errors.load(Ordering::Relaxed),
            "db_size_bytes": self.db_size_bytes.load(Ordering::Relaxed),
            // NIP-29 group purges still pending after the startup resume
            // (see the Prometheus metric of the same name).
            "pending_purges": self.pending_purges.load(Ordering::Relaxed),
            // NIP-62 bookkeeping gauges (see the Prometheus metrics below).
            "vanish_markers": self.vanish_markers.load(Ordering::Relaxed),
            "pending_vanishes": self.pending_vanishes.load(Ordering::Relaxed),
            // Every bookkeeping table that grows with removals (see
            // `DbClient::table_counts`): the deliberate permanent markers
            // and the pending recovery queues in one place.
            "db_tables": {
                "deleted": self.db_table_deleted.load(Ordering::Relaxed),
                "first_seen": self.db_table_first_seen.load(Ordering::Relaxed),
                "purged_groups": self.db_table_purged_groups.load(Ordering::Relaxed),
                "vanish": self.db_table_vanish.load(Ordering::Relaxed),
                "vanish_pending": self.db_table_vanish_pending.load(Ordering::Relaxed),
                "purge_pending": self.db_table_purge_pending.load(Ordering::Relaxed),
                "delete_pending": self.db_table_delete_pending.load(Ordering::Relaxed),
            },
            "blossom_orphan_spools_swept": self
                .blossom_orphan_spools_swept
                .load(Ordering::Relaxed),
            // Mapped-but-missing blobs (see the Prometheus metric of the
            // same name): the mapping exists but the object is gone.
            "blossom_missing_objects": self.blossom_missing_objects.load(Ordering::Relaxed),
            // Connection/limit refusals, split by reason so an operator can
            // tell a connection-cap from a rate-limit or blockip refusal.
            "connection_refusals": {
                "global_cap": self.conn_refused_global.load(Ordering::Relaxed),
                "per_ip_cap": self.conn_refused_per_ip.load(Ordering::Relaxed),
                "rate_limit": self.conn_refused_rate.load(Ordering::Relaxed),
                "trusted_proxy": self.conn_refused_proxy.load(Ordering::Relaxed),
                "blocked_ip": self.conn_refused_blocked.load(Ordering::Relaxed),
            },
            "accept_errors": self.accept_errors.load(Ordering::Relaxed),
            // Database queue depth and storage health (see the Prometheus
            // metrics of the same names).
            "db_queue": {
                "pending_msgs": self.db_pending_msgs.load(Ordering::Relaxed),
                "pending_events": self.db_pending_events.load(Ordering::Relaxed),
                "pending_bytes": self.db_pending_bytes.load(Ordering::Relaxed),
                "pending_reads": self.db_pending_reads.load(Ordering::Relaxed),
                "pending_read_bytes": self.db_pending_read_bytes.load(Ordering::Relaxed),
                "api_pending": self.db_api_pending.load(Ordering::Relaxed),
                "api_pending_bytes": self.db_api_pending_bytes.load(Ordering::Relaxed),
            },
            "db_overloaded": self.db_overloaded.load(Ordering::Relaxed),
            "db_disk_full": self.db_disk_full.load(Ordering::Relaxed),
            "db_free_bytes": self.db_free_bytes.load(Ordering::Relaxed),
            "rebuild_failures": self.rebuild_failures.load(Ordering::Relaxed),
            // Logger write/rotation failures: a nonzero value means log
            // records are being lost (the log file is not the source of
            // truth for these counters).
            "log_errors": crate::logging::log_errors(),
        })
    }

    /// The counters in Prometheus text exposition format (`text/plain;
    /// version=0.0.4`), served on `/metrics` for scraping by monitoring
    /// systems. No external dependency: the format is simple enough to emit
    /// by hand.
    pub fn as_prometheus(&self) -> String {
        let mut out = String::new();
        let mut metric = |name: &str, help: &str, typ: &str, value: u64| {
            out.push_str(&format!("# HELP {name} {help}\n"));
            out.push_str(&format!("# TYPE {name} {typ}\n"));
            out.push_str(&format!("{name} {value}\n"));
        };
        metric(
            "nostrfy_uptime_seconds",
            "Seconds since the relay started.",
            "gauge",
            unix_now().saturating_sub(self.started_at.load(Ordering::Relaxed)),
        );
        metric(
            "nostrfy_connections_active",
            "Currently open WebSocket connections.",
            "gauge",
            self.connections_active.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_connections_total",
            "WebSocket connections accepted since start.",
            "counter",
            self.connections_total.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_subscriptions_active",
            "Active subscription filters.",
            "gauge",
            self.subscriptions_active.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_subscriptions_total",
            "Subscriptions created since start.",
            "counter",
            self.subscriptions_total.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_events_received",
            "EVENT messages received since start.",
            "counter",
            self.events_received.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_events_accepted",
            "Events accepted and stored since start.",
            "counter",
            self.events_accepted.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_events_rejected",
            "Events rejected since start.",
            "counter",
            self.events_rejected.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_events_duplicate",
            "Duplicate events dropped since start.",
            "counter",
            self.events_duplicate.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_events_deleted",
            "Events deleted (NIP-09) since start.",
            "counter",
            self.events_deleted.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_messages_in",
            "WebSocket messages received since start.",
            "counter",
            self.messages_in.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_messages_out",
            "WebSocket messages sent since start.",
            "counter",
            self.messages_out.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_bytes_in",
            "WebSocket bytes received since start.",
            "counter",
            self.bytes_in.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_bytes_out",
            "WebSocket bytes sent since start.",
            "counter",
            self.bytes_out.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_buffers_dropped",
            "Outgoing messages dropped for slow readers since start.",
            "counter",
            self.buffers_dropped.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_db_errors",
            "Database errors since start.",
            "counter",
            self.db_errors.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_db_size_bytes",
            "Database size on disk in bytes.",
            "gauge",
            self.db_size_bytes.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_pending_purges",
            "Recorded NIP-29 group purges still pending after the startup resume.",
            "gauge",
            self.pending_purges.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_vanish_markers",
            "Completed NIP-62 vanish markers (grows permanently by design).",
            "gauge",
            self.vanish_markers.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_pending_vanishes",
            "NIP-62 vanish requests recorded but not yet completed (resumed at startup).",
            "gauge",
            self.pending_vanishes.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_db_table_deleted",
            "Rows in the deleted-events bookkeeping table.",
            "gauge",
            self.db_table_deleted.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_db_table_first_seen",
            "Rows in the pubkey first-seen table (reaped once past the new-pubkey gate).",
            "gauge",
            self.db_table_first_seen.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_db_table_purged_groups",
            "Permanent NIP-29 group-purge tombstones (never expired by design).",
            "gauge",
            self.db_table_purged_groups.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_db_table_vanish",
            "Permanent NIP-62 vanish markers (never expired by design).",
            "gauge",
            self.db_table_vanish.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_db_table_vanish_pending",
            "NIP-62 vanishes recorded but not yet completed.",
            "gauge",
            self.db_table_vanish_pending.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_db_table_purge_pending",
            "NIP-29 group purges recorded but not yet completed.",
            "gauge",
            self.db_table_purge_pending.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_db_table_delete_pending",
            "NIP-09 deletions recorded but not yet completed (resumed at startup).",
            "gauge",
            self.db_table_delete_pending.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_blossom_orphan_spools_swept",
            "Blossom upload spool files removed by the startup sweep.",
            "counter",
            self.blossom_orphan_spools_swept.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_blossom_missing_objects",
            "Blob lookups where the mapping exists but the object is missing from every owner.",
            "counter",
            self.blossom_missing_objects.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_conn_refused_global",
            "Connections refused by the global connection cap.",
            "counter",
            self.conn_refused_global.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_conn_refused_per_ip",
            "Connections refused by the per-IP concurrent connection cap.",
            "counter",
            self.conn_refused_per_ip.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_conn_refused_rate",
            "Connections refused by the per-IP connection rate limit.",
            "counter",
            self.conn_refused_rate.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_conn_refused_proxy",
            "Trusted-proxy requests refused with 429 under the forwarded client address.",
            "counter",
            self.conn_refused_proxy.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_conn_refused_blocked",
            "Requests refused with 403 because the client IP is NIP-86 blocked.",
            "counter",
            self.conn_refused_blocked.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_accept_errors",
            "accept() failures on the listener (the relay backs off and keeps serving).",
            "counter",
            self.accept_errors.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_db_pending_msgs",
            "Messages queued for the database writer.",
            "gauge",
            self.db_pending_msgs.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_db_pending_events",
            "Events inside the messages queued for the database writer.",
            "gauge",
            self.db_pending_events.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_db_pending_bytes",
            "Estimated payload bytes queued for the database writer.",
            "gauge",
            self.db_pending_bytes.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_db_pending_reads",
            "Read-only messages queued for the database readers.",
            "gauge",
            self.db_pending_reads.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_db_pending_read_bytes",
            "Estimated payload bytes queued for the database readers.",
            "gauge",
            self.db_pending_read_bytes.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_db_api_pending",
            "REST API queries queued for the dedicated database reader.",
            "gauge",
            self.db_api_pending.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_db_api_pending_bytes",
            "Estimated payload bytes in queued REST API queries.",
            "gauge",
            self.db_api_pending_bytes.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_db_overloaded",
            "Requests failed fast because a database queue cap was reached (not a fault).",
            "counter",
            self.db_overloaded.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_db_disk_full",
            "1 while the database is refusing writes for lack of space (disk or map full).",
            "gauge",
            self.db_disk_full.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_db_free_bytes",
            "Free bytes on the database filesystem (0 when the store cannot report it).",
            "gauge",
            self.db_free_bytes.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_rebuild_failures",
            "Runtime NIP-29/NIP-43 derived-state rebuild failures since start.",
            "counter",
            self.rebuild_failures.load(Ordering::Relaxed),
        );
        metric(
            "nostrfy_log_errors",
            "Log file write/rotation failures since start (log records are being lost).",
            "counter",
            crate::logging::log_errors(),
        );
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_snapshot_carries_a_written_at_marker() {
        // Without the marker the CLI cannot tell a stale file from a live
        // one and would print hours-old counters as current.
        let stats = Stats::new();
        let before = unix_now();
        let json = stats.as_json();
        let written_at = json
            .get("written_at")
            .and_then(Value::as_u64)
            .expect("written_at must be present");
        assert!(
            written_at >= before && written_at <= unix_now(),
            "written_at must be the snapshot time (got {written_at})"
        );
    }

    #[test]
    fn prometheus_output_is_well_formed() {
        let stats = Stats::new();
        stats.bump(&stats.events_accepted, 3);
        stats.bump(&stats.blossom_missing_objects, 2);
        let text = stats.as_prometheus();
        assert!(text.contains("nostrfy_events_accepted 3\n"));
        assert!(text.contains("# TYPE nostrfy_events_accepted counter\n"));
        assert!(text.contains("# TYPE nostrfy_uptime_seconds gauge\n"));
        assert!(
            text.contains("# TYPE nostrfy_blossom_missing_objects counter\n")
                && text.contains("nostrfy_blossom_missing_objects 2\n"),
            "the mapped-but-missing Blossom counter must be exposed"
        );
        assert!(
            text.contains("# TYPE nostrfy_log_errors counter\n"),
            "the logger failure counter must be exposed for alerting"
        );
        assert!(
            text.contains("# TYPE nostrfy_pending_purges gauge\n"),
            "the pending-purge gauge must be exposed for alerting"
        );
        assert!(
            text.contains("# TYPE nostrfy_db_overloaded counter\n")
                && text.contains("# TYPE nostrfy_db_pending_msgs gauge\n")
                && text.contains("# TYPE nostrfy_db_disk_full gauge\n")
                && text.contains("# TYPE nostrfy_conn_refused_global counter\n")
                && text.contains("# TYPE nostrfy_accept_errors counter\n")
                && text.contains("# TYPE nostrfy_rebuild_failures counter\n")
                && text.contains("# TYPE nostrfy_db_table_deleted gauge\n"),
            "the queue, disk, refusal and rebuild metrics must be exposed"
        );
        // Every line is either a comment, a blank, or `name value`.
        for line in text.lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (name, value) = line.rsplit_once(' ').expect("metric line has a value");
            assert!(value.parse::<f64>().is_ok(), "value parses: {line}");
            assert!(!name.contains(' '), "name has no spaces: {line}");
        }
    }

    #[test]
    fn json_snapshot_carries_the_blossom_missing_objects_counter() {
        let stats = Stats::new();
        stats.bump(&stats.blossom_missing_objects, 4);
        let json = stats.as_json();
        assert_eq!(
            json.get("blossom_missing_objects").and_then(Value::as_u64),
            Some(4),
            "the mapped-but-missing Blossom counter must be in the JSON snapshot"
        );
    }

    #[test]
    fn json_snapshot_carries_connection_refusals_and_db_gauges() {
        let stats = Stats::new();
        stats.bump(&stats.conn_refused_global, 1);
        stats.bump(&stats.conn_refused_per_ip, 2);
        stats.bump(&stats.conn_refused_rate, 3);
        stats.bump(&stats.conn_refused_proxy, 4);
        stats.bump(&stats.conn_refused_blocked, 5);
        stats.bump(&stats.accept_errors, 6);
        stats.db_pending_msgs.store(7, Ordering::Relaxed);
        stats.db_pending_events.store(8, Ordering::Relaxed);
        stats.db_pending_bytes.store(9, Ordering::Relaxed);
        stats.db_pending_reads.store(10, Ordering::Relaxed);
        stats.db_pending_read_bytes.store(11, Ordering::Relaxed);
        stats.db_api_pending.store(12, Ordering::Relaxed);
        stats.db_api_pending_bytes.store(13, Ordering::Relaxed);
        stats.bump(&stats.db_overloaded, 14);
        stats.db_disk_full.store(1, Ordering::Relaxed);
        stats.db_free_bytes.store(15, Ordering::Relaxed);
        stats.bump(&stats.rebuild_failures, 16);
        stats.db_table_deleted.store(17, Ordering::Relaxed);
        stats.db_table_first_seen.store(18, Ordering::Relaxed);
        stats.db_table_purged_groups.store(19, Ordering::Relaxed);
        stats.db_table_vanish.store(20, Ordering::Relaxed);
        stats.db_table_vanish_pending.store(21, Ordering::Relaxed);
        stats.db_table_purge_pending.store(22, Ordering::Relaxed);
        stats.db_table_delete_pending.store(23, Ordering::Relaxed);
        let json = stats.as_json();
        let refusals = &json["connection_refusals"];
        assert_eq!(refusals["global_cap"].as_u64(), Some(1));
        assert_eq!(refusals["per_ip_cap"].as_u64(), Some(2));
        assert_eq!(refusals["rate_limit"].as_u64(), Some(3));
        assert_eq!(refusals["trusted_proxy"].as_u64(), Some(4));
        assert_eq!(refusals["blocked_ip"].as_u64(), Some(5));
        assert_eq!(json["accept_errors"].as_u64(), Some(6));
        let queue = &json["db_queue"];
        assert_eq!(queue["pending_msgs"].as_u64(), Some(7));
        assert_eq!(queue["pending_events"].as_u64(), Some(8));
        assert_eq!(queue["pending_bytes"].as_u64(), Some(9));
        assert_eq!(queue["pending_reads"].as_u64(), Some(10));
        assert_eq!(queue["pending_read_bytes"].as_u64(), Some(11));
        assert_eq!(queue["api_pending"].as_u64(), Some(12));
        assert_eq!(queue["api_pending_bytes"].as_u64(), Some(13));
        assert_eq!(json["db_overloaded"].as_u64(), Some(14));
        assert_eq!(json["db_disk_full"].as_u64(), Some(1));
        assert_eq!(json["db_free_bytes"].as_u64(), Some(15));
        assert_eq!(json["rebuild_failures"].as_u64(), Some(16));
        let tables = &json["db_tables"];
        assert_eq!(tables["deleted"].as_u64(), Some(17));
        assert_eq!(tables["first_seen"].as_u64(), Some(18));
        assert_eq!(tables["purged_groups"].as_u64(), Some(19));
        assert_eq!(tables["vanish"].as_u64(), Some(20));
        assert_eq!(tables["vanish_pending"].as_u64(), Some(21));
        assert_eq!(tables["purge_pending"].as_u64(), Some(22));
        assert_eq!(tables["delete_pending"].as_u64(), Some(23));
    }

    #[test]
    fn log_errors_is_reported_in_the_json_snapshot() {
        let stats = Stats::new();
        let json = stats.as_json();
        assert!(
            json.get("log_errors").and_then(Value::as_u64).is_some(),
            "the JSON snapshot must carry the logger failure counter"
        );
    }
}
