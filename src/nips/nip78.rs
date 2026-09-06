//! NIP-78: Application-specific data.
//!
//! Kinds 30078 (addressable) and 78 carry application-specific data. Per
//! the NIP, relays require the NIP-42 AUTH flow before accepting them and
//! only serve them to the authenticated owner (same pubkey as the event
//! author).

use crate::event::Event;

/// Plain (non-replaceable) application-specific data event.
pub const APP_SPECIFIC_KIND: u64 = 78;
/// Addressable (replaceable) application-specific data event.
pub const REPLACEABLE_APP_SPECIFIC_KIND: u64 = 30078;

/// Whether `kind` is a NIP-78 application-specific data event.
pub fn is_app_specific_kind(kind: u64) -> bool {
    matches!(kind, APP_SPECIFIC_KIND | REPLACEABLE_APP_SPECIFIC_KIND)
}

/// Whether `event` is a NIP-78 application-specific data event.
pub fn is_app_specific(event: &Event) -> bool {
    is_app_specific_kind(event.kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_detection() {
        assert!(is_app_specific_kind(78));
        assert!(is_app_specific_kind(30078));
        assert!(!is_app_specific_kind(1));
        assert!(!is_app_specific_kind(30077));
        assert!(!is_app_specific_kind(30079));
    }
}
