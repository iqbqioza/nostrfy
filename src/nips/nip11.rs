//! NIP-11: Relay Information Document.
//!
//! Served on `GET /` as `application/nostr+json`.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use serde_json::{Value, json};

use crate::config::{AccessControl, Config};
use crate::relay::Relay;
use crate::stats::Stats;

pub fn relay_info(
    config: &Config,
    access: &AccessControl,
    stats: &Stats,
    self_pubkey: Option<&str>,
) -> Value {
    let limits = &config.limits;
    // NIP-11: any field may be omitted. Empty string fields are omitted
    // too: some clients try to decode the pubkey/icon as data and fail on
    // an empty value.
    let mut info = json!({
        "name": config.relay.name,
        "description": config.relay.description,
        "pubkey": config.relay.pubkey,
        "contact": config.relay.contact,
        "icon": config.relay.icon,
        "supported_nips": config.effective_supported_nips(access),
        "software": env!("CARGO_PKG_REPOSITORY"),
        "version": env!("CARGO_PKG_VERSION"),
        "limitation": {
            "max_message_length": limits.max_ws_message_bytes,
            "max_subscriptions": limits.max_subscriptions,
            "max_filters": limits.max_filters,
            "max_limit": limits.max_limit,
            "max_subid_length": limits.max_sub_id_len,
            "max_event_tags": limits.max_tags,
            "max_content_length": limits.max_content_bytes,
            // Only advertise the PoW floor when NIP-13 is enabled and it is
            // actually enforced; otherwise reporting `require_pow` would
            // claim a difficulty the relay never checks.
            "min_pow_difficulty": if config.nip_enabled(13) { config.relay.require_pow } else { 0 },
            "auth_required": config.relay.require_auth,
            "payment_required": false,
            "restricted_writes": access.restrict_relay,
            "created_at_lower_limit": 0,
            // NIP-11: an absolute unix timestamp. The relay accepts events up
            // to `max_created_at_future` seconds into the future.
            "created_at_upper_limit": crate::util::unix_now() + limits.max_created_at_future_secs,
            "default_limit": limits.max_limit,
        },
        "relay_countries": [],
        "language_tags": [],
        "tags": [],
        "posting_policy": config.relay.post_policy,
        "payments_url": "",
        "fees": {
            "admission": [],
            "subscription": [],
            "publication": []
        },
        "stats": stats.as_json(),
    });
    if let Some(self_pubkey) = self_pubkey {
        info["self"] = json!(self_pubkey);
    }
    for field in [
        "pubkey",
        "contact",
        "icon",
        "posting_policy",
        "payments_url",
    ] {
        if info.get(field).and_then(Value::as_str) == Some("") {
            info.as_object_mut()
                .expect("relay_info builds an object")
                .remove(field);
        }
    }
    if config.nip_enabled(29) {
        info["nip29"] = json!({ "subgroups": true });
    }
    info
}

pub async fn stats_handler(State(relay): State<Arc<Relay>>) -> Json<Value> {
    Json(relay.stats.as_json())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::util::unix_now;

    fn info() -> Value {
        let cfg = Config::default();
        let access = crate::config::AccessControl::default();
        let stats = Stats::new();
        relay_info(&cfg, &access, &stats, None)
    }

    #[test]
    fn upper_limit_is_absolute() {
        let info = info();
        let upper = info["limitation"]["created_at_upper_limit"]
            .as_u64()
            .expect("upper limit is a number");
        let now = unix_now();
        let max_future = Config::default().limits.max_created_at_future_secs;
        assert!(
            upper >= now + max_future.saturating_sub(1) && upper <= now + max_future + 1,
            "upper limit must be now + max_created_at_future, got {upper} vs now {now} + {max_future}"
        );
    }

    #[test]
    fn retention_is_not_advertised() {
        let info = info();
        assert!(
            info.get("retention").is_none(),
            "retention is omitted to avoid breaking strict parsers (NIP-11 defines it as optional)"
        );
    }

    #[test]
    fn empty_fields_are_omitted() {
        let info = info();
        assert!(info.get("contact").is_none());
        assert!(info.get("icon").is_none());
        assert!(info.get("posting_policy").is_none());
        assert!(info.get("payments_url").is_none());
    }

    #[test]
    fn identity_fields_are_advertised_when_set() {
        let mut cfg = Config::default();
        cfg.relay.pubkey = "aa".repeat(32);
        cfg.relay.contact = "https://example.com/contact".to_string();
        cfg.relay.icon = "https://example.com/icon.png".to_string();
        let stats = Stats::new();
        let access = crate::config::AccessControl::default();
        let info = relay_info(&cfg, &access, &stats, Some(&"bb".repeat(32)));
        assert_eq!(info["pubkey"], "aa".repeat(32));
        assert_eq!(info["contact"], "https://example.com/contact");
        assert_eq!(info["icon"], "https://example.com/icon.png");
        assert_eq!(info["self"], "bb".repeat(32));
    }

    #[test]
    fn advertises_relay_nips() {
        let info = info();
        let nips = info["supported_nips"]
            .as_array()
            .expect("supported_nips is an array");
        let nips: Vec<u16> = nips.iter().map(|n| n.as_u64().unwrap() as u16).collect();
        for expected in [
            1u16, 9, 11, 13, 17, 22, 26, 29, 32, 33, 40, 42, 43, 45, 46, 47, 50, 57, 59, 62, 65,
            66, 67, 70, 77, 78, 84, 85, 86, 87, 88, 94, 98,
        ] {
            assert!(
                nips.contains(&expected),
                "NIP-{expected} must be advertised"
            );
        }
        // NIP-34 (git) is gated behind `relay.enabled_git` (default false).
        assert!(
            !nips.contains(&34),
            "NIP-34 must not be advertised while enable_git is false"
        );
    }
}
