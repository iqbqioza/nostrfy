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
            "blossom_orphan_spools_swept": self
                .blossom_orphan_spools_swept
                .load(Ordering::Relaxed),
            // Mapped-but-missing blobs (see the Prometheus metric of the
            // same name): the mapping exists but the object is gone.
            "blossom_missing_objects": self.blossom_missing_objects.load(Ordering::Relaxed),
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
    fn log_errors_is_reported_in_the_json_snapshot() {
        let stats = Stats::new();
        let json = stats.as_json();
        assert!(
            json.get("log_errors").and_then(Value::as_u64).is_some(),
            "the JSON snapshot must carry the logger failure counter"
        );
    }
}
