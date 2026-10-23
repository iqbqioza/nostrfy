//! Rate-limited audit log for the management operations (NIP-86 JSON-RPC
//! and the NIP-86 management API).
//!
//! Admin operations are rare, but a runaway admin script (or a bug) must
//! not be able to flood the log: entries beyond the per-window budget are
//! dropped and summarized once per window. A bounded ring of the recent
//! entries is kept for tests and for a quick operational look at what
//! changed.
//!
//! Entries bypass the `RUST_LOG` level/target filters (see
//! [`crate::logging::write_audit_entry`]): raising the log level hides
//! routine output, never the record of what an admin changed.

use std::collections::VecDeque;
use std::sync::Mutex;

use crate::util::unix_now;

/// Maximum audit entries logged per window (a ban-list import bursts
/// well above this; the summary line keeps the trail visible without the
/// flood).
const MAX_PER_WINDOW: u32 = 600;
/// Per-identity cap: one low-privilege grantee must not consume the whole
/// global window and starve an admin's entries.
const MAX_PER_IDENTITY: u32 = 100;
/// Entries reserved above the global cap for admins. A grantee flood can
/// suppress other grantees, but not the audit record of an admin mutation.
const ADMIN_RESERVE: u32 = 100;
/// Window length in seconds.
const WINDOW_SECS: u64 = 60;
/// Recent entries kept in the ring (also the test surface).
const RING_CAP: usize = 32;

struct AuditState {
    window_start: u64,
    count: u32,
    suppressed: u32,
    per_identity: std::collections::HashMap<String, u32>,
    recent: VecDeque<String>,
}

/// The relay's audit log: rate-limited `log` writes plus a bounded ring
/// of the recent entries.
#[derive(Default)]
pub(crate) struct AuditLog {
    state: Mutex<AuditState>,
}

impl Default for AuditState {
    fn default() -> Self {
        AuditState {
            window_start: unix_now(),
            count: 0,
            suppressed: 0,
            per_identity: std::collections::HashMap::new(),
            recent: VecDeque::new(),
        }
    }
}

impl AuditLog {
    /// Records an audit entry. Within the budget the entry is written to
    /// the log and kept in the ring; beyond it the entry is only counted,
    /// and once per window a single summary line reports how many entries
    /// were suppressed.
    #[cfg(test)]
    pub(crate) fn log(&self, entry: String) {
        self.log_for("test".to_string(), false, entry);
    }

    /// Records an entry for `identity`; admins may use the reserved tail of
    /// the window so a grantee cannot hide an admin mutation by exhausting
    /// the global budget first.
    pub(crate) fn log_for(&self, identity: String, admin: bool, entry: String) {
        // Hex pubkeys are case-insensitive and the grant/replay checks
        // compare them that way. Keying the per-identity budget by the raw
        // spelling let one grantee alternate the case of its hex pubkey and
        // multiply its quota (suppressing other grantees' entries), so
        // canonicalize the key here. The entry text keeps the spelling the
        // caller used.
        let identity = identity.to_ascii_lowercase();
        // A poisoned mutex (a thread panicked while holding it) must not
        // take the audit log down: the state is still valid, so the
        // guard is recovered with `into_inner`.
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let now = unix_now();
        // A clock that moved backwards must not freeze the window (the
        // saturating subtraction would stay below WINDOW_SECS until the
        // wall clock catches up, suppressing entries indefinitely).
        if now < state.window_start || now.saturating_sub(state.window_start) >= WINDOW_SECS {
            if state.suppressed > 0 {
                // Bypass the level/target filter: the summary is part of
                // the audit trail, not routine logging.
                crate::logging::write_audit_entry(format_args!(
                    "admin audit log throttled: {} management entries suppressed since the last summary",
                    state.suppressed
                ));
            }
            state.window_start = now;
            state.count = 0;
            state.suppressed = 0;
            state.per_identity.clear();
        }
        let own = state.per_identity.get(&identity).copied().unwrap_or(0);
        let limit = if admin {
            MAX_PER_WINDOW.saturating_add(ADMIN_RESERVE)
        } else {
            MAX_PER_WINDOW
        };
        if own < MAX_PER_IDENTITY && state.count < limit {
            state.count += 1;
            *state.per_identity.entry(identity).or_insert(0) += 1;
            // Bypasses the `log` level/target filters: a raised `RUST_LOG`
            // must not drop the management trail (see
            // `logging::write_audit_entry`).
            crate::logging::write_audit_entry(format_args!("admin {entry}"));
            if state.recent.len() >= RING_CAP {
                state.recent.pop_front();
            }
            state.recent.push_back(entry);
        } else {
            state.suppressed += 1;
        }
    }

    /// Emits the pending throttling summary, if any, without waiting for
    /// the next window roll. The stats writer calls this periodically so a
    /// grantee flood that stops is still accounted for (the summary used to
    /// appear only on the next audit call).
    pub(crate) fn flush_suppressed(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.suppressed == 0 {
            return;
        }
        let suppressed = std::mem::take(&mut state.suppressed);
        // Do not hold the audit mutex across the logging backend.
        drop(state);
        crate::logging::write_audit_entry(format_args!(
            "admin audit log throttled: {suppressed} management entries suppressed since the last summary"
        ));
    }

    /// The recent audit entries (oldest first), for tests.
    #[cfg(test)]
    pub(crate) fn recent(&self) -> Vec<String> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .recent
            .iter()
            .cloned()
            .collect()
    }

    /// Clears the ring (tests).
    #[cfg(test)]
    pub(crate) fn clear(&self) {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .recent
            .clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_keeps_recent_entries_and_drops_oldest() {
        let audit = AuditLog::default();
        audit.clear();
        for i in 0..(RING_CAP + 5) {
            audit.log(format!("op {i}"));
        }
        let recent = audit.recent();
        assert_eq!(recent.len(), RING_CAP);
        assert_eq!(recent[0], format!("op {}", 5));
        assert_eq!(recent[RING_CAP - 1], format!("op {}", RING_CAP + 4));
    }

    #[test]
    fn per_identity_cap_and_admin_reserve() {
        let audit = AuditLog::default();
        audit.clear();
        // One grantee cannot consume more than MAX_PER_IDENTITY entries.
        for i in 0..(MAX_PER_IDENTITY + 5) {
            audit.log_for("grantee".into(), false, format!("op {i}"));
        }
        assert_eq!(
            audit.state.lock().unwrap().suppressed,
            5,
            "the per-identity cap must suppress only the overflow"
        );
        // Fill the global window with six grantees; an admin still gets
        // the reserved tail, so a management mutation is never hidden by a
        // grantee flood.
        for id in 0..6 {
            for i in 0..MAX_PER_IDENTITY {
                audit.log_for(format!("grantee-{id}"), false, format!("op {i}"));
            }
        }
        audit.log_for("admin".into(), true, "admin mutation".into());
        assert!(
            audit.recent().iter().any(|entry| entry == "admin mutation"),
            "an admin entry must survive a full grantee window"
        );
    }

    #[test]
    fn per_identity_cap_is_case_insensitive() {
        let audit = AuditLog::default();
        audit.clear();
        let upper = "AA".repeat(32);
        let lower = "aa".repeat(32);
        for i in 0..MAX_PER_IDENTITY {
            audit.log_for(upper.clone(), false, format!("upper {i}"));
        }
        audit.log_for(lower.clone(), false, "lower".into());
        assert_eq!(
            audit.state.lock().unwrap().suppressed,
            1,
            "alternating hex case must not multiply the per-identity budget"
        );
        assert!(
            audit
                .state
                .lock()
                .unwrap()
                .per_identity
                .contains_key(&lower),
            "the canonical key is lowercase"
        );
    }

    #[test]
    fn flush_reports_and_clears_suppressed_entries() {
        let audit = AuditLog::default();
        audit.clear();
        for i in 0..(MAX_PER_IDENTITY + 2) {
            audit.log_for("flood".into(), false, format!("op {i}"));
        }
        assert_eq!(audit.state.lock().unwrap().suppressed, 2);
        audit.flush_suppressed();
        assert_eq!(
            audit.state.lock().unwrap().suppressed,
            0,
            "the periodic flush must emit and clear the suppressed count"
        );
    }

    #[test]
    fn audit_log_recovers_from_poisoned_mutex() {
        let audit = std::sync::Arc::new(AuditLog::default());
        audit.clear();
        let audit_for_thread = std::sync::Arc::clone(&audit);
        let handle = std::thread::spawn(move || {
            let _g = audit_for_thread.state.lock().unwrap();
            panic!("poison");
        });
        handle.join().unwrap_err();
        audit.log("after poison".into());
        assert_eq!(
            audit.recent(),
            vec!["after poison".to_string()],
            "the audit log must recover and record"
        );
    }

    #[test]
    fn budget_suppresses_and_summarizes() {
        let audit = AuditLog::default();
        audit.clear();
        // The budget is per-window: beyond it entries are not logged (the
        // ring holds at most RING_CAP, so the budget is inferred from the
        // ring + the suppressed count on the next window roll).
        for i in 0..(MAX_PER_WINDOW + 10) {
            // Distinct identities exercise the global budget; the
            // per-identity cap is covered separately.
            audit.log_for(format!("id{i}"), false, format!("op {i}"));
        }
        assert_eq!(audit.recent().len(), RING_CAP);
        assert_eq!(
            audit.state.lock().unwrap().suppressed,
            10,
            "the overflow must be counted, not logged"
        );
        // A fresh window (the state's window is 60s; force a roll) resets the
        // budget and the suppressed count, and logs again.
        audit.state.lock().unwrap().window_start = 0;
        audit.log("after roll".into());
        assert_eq!(audit.recent().len(), RING_CAP);
        assert_eq!(audit.state.lock().unwrap().suppressed, 0);
    }
}
