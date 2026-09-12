//! Rate-limited audit log for the management operations (NIP-86 JSON-RPC
//! and the NIP-86 management API).
//!
//! Admin operations are rare, but a runaway admin script (or a bug) must
//! not be able to flood the log: entries beyond the per-window budget are
//! dropped and summarized once per window. A bounded ring of the recent
//! entries is kept for tests and for a quick operational look at what
//! changed.

use std::collections::VecDeque;
use std::sync::Mutex;

use crate::util::unix_now;

/// Maximum audit entries logged per window (a ban-list import bursts
/// well above this; the summary line keeps the trail visible without the
/// flood).
const MAX_PER_WINDOW: u32 = 600;
/// Window length in seconds.
const WINDOW_SECS: u64 = 60;
/// Recent entries kept in the ring (also the test surface).
const RING_CAP: usize = 32;

struct AuditState {
    window_start: u64,
    count: u32,
    suppressed: u32,
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
            recent: VecDeque::new(),
        }
    }
}

impl AuditLog {
    /// Records an audit entry. Within the budget the entry is written to
    /// the log and kept in the ring; beyond it the entry is only counted,
    /// and once per window a single summary line reports how many entries
    /// were suppressed.
    pub(crate) fn log(&self, entry: String) {
        // A poisoned mutex (a thread panicked while holding it) must not
        // take the audit log down: the state is still valid, so the
        // guard is recovered with `into_inner`.
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let now = unix_now();
        if now.saturating_sub(state.window_start) >= WINDOW_SECS {
            if state.suppressed > 0 {
                log::warn!(
                    "audit log throttled: {} management entries suppressed in the last {}s",
                    state.suppressed,
                    WINDOW_SECS
                );
            }
            state.window_start = now;
            state.count = 0;
            state.suppressed = 0;
        }
        if state.count < MAX_PER_WINDOW {
            state.count += 1;
            log::info!("admin {entry}");
            if state.recent.len() >= RING_CAP {
                state.recent.pop_front();
            }
            state.recent.push_back(entry);
        } else {
            state.suppressed += 1;
        }
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
            audit.log(format!("op {i}"));
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
