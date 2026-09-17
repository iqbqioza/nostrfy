//! Accept-layer connection accounting shared with the WebSocket layer.
//!
//! The accept loop reserves one slot per TCP connection (the global
//! `limits.max_connections` count and the per-IP `limits.max_connections_per_ip`
//! count). A WebSocket connection outlives the HTTP connection that carried
//! the upgrade: hyper hands the socket to a detached task and the accept task
//! ends. Its slot must therefore move to the WebSocket task instead of being
//! released, otherwise the connection would be counted twice while the WS
//! layer registered it again — or not at all once the accept layer released
//! it. [`ConnSlot`] is that slot and [`ConnSlot::handover`] transfers the
//! release responsibility exactly once.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// Per-IP concurrent connection accounting at the accept layer. The
/// WebSocket handler only sees upgrades, so without this a single host could
/// open every one of `limits.max_connections` as plain HTTP and hold them
/// (pinning file descriptors and the connection budget). `max == 0`
/// disables the cap, mirroring the global connection cap.
#[derive(Default)]
pub(crate) struct IpConnCounter {
    counts: Mutex<std::collections::HashMap<IpAddr, usize>>,
}

impl IpConnCounter {
    /// Reserves a connection slot for `ip`; `false` means the per-IP cap is
    /// reached and the connection must be dropped at the socket level.
    pub(crate) fn try_acquire(&self, ip: IpAddr, max: usize) -> bool {
        if max == 0 {
            return true;
        }
        // Recover from a poisoned lock instead of panicking: a panic while
        // holding the map would otherwise kill every later connection.
        let mut counts = self.counts.lock().unwrap_or_else(|p| p.into_inner());
        let count = counts.entry(ip).or_insert(0);
        if *count >= max {
            return false;
        }
        *count += 1;
        true
    }

    /// Releases one slot; the entry is removed when the last connection of
    /// that IP closes, so the map never grows beyond the live connections.
    pub(crate) fn release(&self, ip: IpAddr) {
        let mut counts = self.counts.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(count) = counts.get_mut(&ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&ip);
            }
        }
    }
}

/// Slot states: the accept task still owns the release (`PENDING`), an
/// upgraded WebSocket owns it (`OWNED`), or the slot is already accounted
/// (`RELEASED`). Only the `PENDING → X` transition carries the release
/// responsibility, so two racing owners can never release twice.
const PENDING: u8 = 0;
const OWNED: u8 = 1;
const RELEASED: u8 = 2;

/// One accepted TCP connection's reserved slot: the global connection count
/// plus the per-IP count. `ConnSlot` itself is only shared state; the
/// release happens through [`AcceptSlotGuard`] (accept task) or
/// [`ConnSlotGuard`] (handed-over WebSocket).
pub(crate) struct ConnSlot {
    active: Arc<AtomicUsize>,
    ip_counter: Arc<IpConnCounter>,
    ip: IpAddr,
    state: AtomicU8,
}

impl ConnSlot {
    pub(crate) fn new(
        active: Arc<AtomicUsize>,
        ip_counter: Arc<IpConnCounter>,
        ip: IpAddr,
    ) -> Arc<Self> {
        Arc::new(Self {
            active,
            ip_counter,
            ip,
            state: AtomicU8::new(PENDING),
        })
    }

    /// Claims the slot for an upgraded connection. The returned guard
    /// releases the slot when the WebSocket connection ends; `None` means
    /// another owner already released it (the connection is then not
    /// counted, which can only happen after the accept task ended without
    /// the upgrade completing).
    pub(crate) fn handover(self: &Arc<Self>) -> Option<ConnSlotGuard> {
        if self
            .state
            .compare_exchange(PENDING, OWNED, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            Some(ConnSlotGuard {
                slot: Arc::clone(self),
            })
        } else {
            None
        }
    }

    /// Releases the slot when the HTTP connection task ends without a
    /// handover. The compare-exchange makes the handover win the race: the
    /// side that flips `PENDING` is the one that releases.
    fn release_unless_handed_over(&self) {
        if self
            .state
            .compare_exchange(PENDING, RELEASED, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.release();
        }
    }

    fn release(&self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
        self.ip_counter.release(self.ip);
    }
}

/// Releases an accepted connection's slot on every exit path of the accept
/// task (including a panic), unless the connection upgraded and the slot
/// was handed over to the WebSocket task.
pub(crate) struct AcceptSlotGuard(Arc<ConnSlot>);

impl AcceptSlotGuard {
    pub(crate) fn new(slot: Arc<ConnSlot>) -> Self {
        Self(slot)
    }
}

impl Drop for AcceptSlotGuard {
    fn drop(&mut self) {
        self.0.release_unless_handed_over();
    }
}

/// Owns a handed-over slot for the whole WebSocket lifetime and releases it
/// exactly once, however the connection ends (including a panic).
pub(crate) struct ConnSlotGuard {
    slot: Arc<ConnSlot>,
}

impl Drop for ConnSlotGuard {
    fn drop(&mut self) {
        if self.slot.state.swap(RELEASED, Ordering::AcqRel) == OWNED {
            self.slot.release();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn ip_counter_enforces_the_cap_and_releases() {
        let counter = IpConnCounter::default();
        let addr = ip("198.51.100.9");
        assert!(counter.try_acquire(addr, 0), "max 0 = unlimited");
        assert!(counter.try_acquire(addr, 2));
        assert!(counter.try_acquire(addr, 2));
        assert!(!counter.try_acquire(addr, 2), "the per-IP cap holds");
        // Releasing one slot admits the next connection again.
        counter.release(addr);
        assert!(counter.try_acquire(addr, 2));
        // Releasing an unknown IP is a no-op.
        counter.release(ip("203.0.113.5"));
        counter.release(addr);
        counter.release(addr);
        counter.release(addr);
        assert!(
            counter.try_acquire(addr, 2),
            "the counter did not underflow"
        );
    }

    #[test]
    fn accept_guard_releases_without_handover() {
        let counter = Arc::new(IpConnCounter::default());
        let active = Arc::new(AtomicUsize::new(0));
        let addr = ip("198.51.100.10");
        assert!(counter.try_acquire(addr, 1));
        active.fetch_add(1, Ordering::Relaxed);
        let slot = ConnSlot::new(Arc::clone(&active), Arc::clone(&counter), addr);
        drop(AcceptSlotGuard::new(Arc::clone(&slot)));
        assert_eq!(
            active.load(Ordering::Relaxed),
            0,
            "the global slot is freed"
        );
        assert!(
            counter.try_acquire(addr, 1),
            "the per-IP slot is freed when the accept task ends"
        );
    }

    #[test]
    fn handover_moves_the_release_to_the_websocket_guard() {
        let counter = Arc::new(IpConnCounter::default());
        let active = Arc::new(AtomicUsize::new(0));
        let addr = ip("198.51.100.11");
        assert!(counter.try_acquire(addr, 1));
        active.fetch_add(1, Ordering::Relaxed);
        let slot = ConnSlot::new(Arc::clone(&active), Arc::clone(&counter), addr);
        let accept_guard = AcceptSlotGuard::new(Arc::clone(&slot));
        let ws_guard = slot.handover().expect("the first handover must win");
        // The accept task ends (the HTTP connection resolved at upgrade):
        // the slot stays reserved for the WebSocket.
        drop(accept_guard);
        assert_eq!(active.load(Ordering::Relaxed), 1, "the WS slot is held");
        assert!(
            !counter.try_acquire(addr, 1),
            "the per-IP cap still counts the live WebSocket"
        );
        // The WebSocket ends: the slot is released exactly once.
        drop(ws_guard);
        assert_eq!(active.load(Ordering::Relaxed), 0);
        assert!(counter.try_acquire(addr, 1), "the slot is reusable");
    }

    #[test]
    fn late_handover_after_release_does_not_double_release() {
        let counter = Arc::new(IpConnCounter::default());
        let active = Arc::new(AtomicUsize::new(0));
        let addr = ip("198.51.100.12");
        assert!(counter.try_acquire(addr, 1));
        active.fetch_add(1, Ordering::Relaxed);
        let slot = ConnSlot::new(Arc::clone(&active), Arc::clone(&counter), addr);
        // The accept task ends first (no upgrade completed).
        drop(AcceptSlotGuard::new(Arc::clone(&slot)));
        assert_eq!(active.load(Ordering::Relaxed), 0);
        // A late handover finds the slot already released and must not
        // release it a second time.
        assert!(slot.handover().is_none(), "the release was already done");
        assert_eq!(active.load(Ordering::Relaxed), 0, "no underflow");
    }

    #[test]
    fn a_second_handover_is_refused() {
        let counter = Arc::new(IpConnCounter::default());
        let active = Arc::new(AtomicUsize::new(0));
        let addr = ip("198.51.100.13");
        assert!(counter.try_acquire(addr, 2));
        active.fetch_add(1, Ordering::Relaxed);
        let slot = ConnSlot::new(Arc::clone(&active), Arc::clone(&counter), addr);
        let first = slot.handover().expect("the first handover wins");
        assert!(
            slot.handover().is_none(),
            "a second owner must not take over the same slot"
        );
        drop(first);
        assert_eq!(active.load(Ordering::Relaxed), 0);
    }
}
