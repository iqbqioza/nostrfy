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
            // NIP-13: the floor is enforced whenever it is configured,
            // independent of the advertisement toggle (hiding the NIP from
            // `supported_nips` must not silently disable the operator's
            // spam defense), so the document must report the real floor
            // rather than claim PoW is unchecked.
            "min_pow_difficulty": config.relay.require_pow,
            "auth_required": config.relay.require_auth,
            "payment_required": false,
            // NIP-11: true when users must know a write policy up front —
            // the pubkey whitelist or a kind allow/deny list qualifies;
            // ordinary anti-spam heuristics do not.
            "restricted_writes": access.restrict_relay
                || !access.allowed_kinds.is_empty()
                || !access.blocked_kinds.is_empty(),
            "created_at_lower_limit": 0,
            // NIP-11 limits are *relative* seconds from now (the spec's
            // examples are `300` and `3`), not absolute timestamps.
            "created_at_upper_limit": limits
                .max_created_at_future_secs
                .min(crate::config::MAX_CREATED_AT_FUTURE_SECS),
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
        "stats": stats.as_public_json(),
    });
    if let Some(self_pubkey) = self_pubkey {
        info["self"] = json!(self_pubkey);
    }
    if config.server.omit_version {
        info.as_object_mut()
            .expect("relay_info builds an object")
            .remove("version");
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

/// The `/relay/stats` endpoint. It answers
/// [`Relay::stats::as_public_json`], not the full snapshot: it needs no token
/// and the router adds a wildcard CORS policy, so serving the host's free disk
/// space and the failure counters here would publish a storage-capacity oracle
/// to every plain probe of the public page this origin also serves (the decoy
/// by default, or `server.landing_page_file`). The stats file (and
/// `nostrfy stats`) keep the full set for the operator. `/metrics` is
/// unauthenticated too and still serves them — see `PRIVATE_STATS_KEYS`.
pub async fn stats_handler(State(relay): State<Arc<Relay>>) -> Json<Value> {
    Json(relay.stats.as_public_json())
}

/// The cached static part of the NIP-11 document. The volatile `stats`
/// section is rebuilt per request, so it is deliberately not part of the
/// cache; the document depends on the config (invalidated by the config
/// version) and on the access-control lists that gate the advertised NIPs
/// and `restricted_writes`.
pub(crate) struct Nip11Cache {
    config_version: u64,
    restrict_relay: bool,
    allowed_kinds: Vec<u64>,
    blocked_kinds: Vec<u64>,
    doc: Arc<Value>,
}

impl Relay {
    /// The NIP-11 document with a fresh `stats` section. Building the
    /// static part needs the config and access locks and rebuilds the
    /// supported-NIPs list, so it is cached until the config version or one
    /// of the access lists it reads changes; the stats are rebuilt for
    /// every request. The fast path avoids the config lock entirely (a
    /// queued SIGHUP writer must not stall information requests).
    pub async fn relay_info_document(&self) -> Value {
        let version = self
            .config_version
            .load(std::sync::atomic::Ordering::Relaxed);
        let cached = {
            let access = self.access.read().await;
            let cache = self
                .nip11_cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            cache.as_ref().and_then(|c| {
                (c.config_version == version
                    && c.restrict_relay == access.restrict_relay
                    && c.allowed_kinds == access.allowed_kinds
                    && c.blocked_kinds == access.blocked_kinds)
                    .then(|| Arc::clone(&c.doc))
            })
        };
        let mut info = match cached {
            Some(doc) => (*doc).clone(),
            None => {
                // Canonical lock order: the accept paths hold `config.read`
                // while awaiting `access.read`.
                let cfg = self.config.read().await;
                let access = self.access.read().await;
                let doc = relay_info(&cfg, &access, &self.stats, self.relay_pubkey().as_deref());
                drop(cfg);
                self.nip11_cache
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .replace(Nip11Cache {
                        config_version: version,
                        restrict_relay: access.restrict_relay,
                        allowed_kinds: access.allowed_kinds.clone(),
                        blocked_kinds: access.blocked_kinds.clone(),
                        doc: Arc::new(doc.clone()),
                    });
                doc
            }
        };
        // The stats change on every request (connections, counters): always
        // serve a fresh section, cached document or not. A NIP-11 client is
        // by definition a Nostr client, so the document is exactly what a
        // plain probe fetches — it must not carry the storage/health
        // oracle `/relay/stats` withholds (see PRIVATE_STATS_KEYS).
        info["stats"] = self.stats.as_public_json();
        info
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn info() -> Value {
        let cfg = Config::default();
        let access = crate::config::AccessControl::default();
        let stats = Stats::new();
        relay_info(&cfg, &access, &stats, None)
    }

    #[test]
    fn upper_limit_reports_the_enforced_clamp() {
        let mut cfg = Config::default();
        cfg.limits.max_created_at_future_secs = u64::MAX;
        let info = relay_info(
            &cfg,
            &crate::config::AccessControl::default(),
            &Stats::new(),
            None,
        );
        assert_eq!(
            info["limitation"]["created_at_upper_limit"],
            json!(crate::config::MAX_CREATED_AT_FUTURE_SECS),
            "NIP-11 must report the clamped enforced window"
        );
    }

    #[test]
    fn upper_limit_is_relative() {
        let info = info();
        let upper = info["limitation"]["created_at_upper_limit"]
            .as_u64()
            .expect("upper limit is a number");
        // NIP-11's examples are relative seconds (300, 3), not absolute
        // timestamps.
        assert_eq!(upper, Config::default().limits.max_created_at_future_secs);
    }

    #[test]
    fn a_hidden_nip13_still_reports_the_enforced_pow_floor() {
        // The floor is enforced whenever it is configured, regardless of the
        // NIP-13 advertisement toggle: a hidden NIP-13 must not make the
        // document claim PoW is unchecked while `pow:` rejections continue.
        let mut cfg = Config::default();
        cfg.relay.require_pow = 25;
        cfg.relay.disabled_nips = vec![13];
        let info = relay_info(&cfg, &AccessControl::default(), &Stats::new(), None);
        assert_eq!(
            info["limitation"]["min_pow_difficulty"].as_u64(),
            Some(25),
            "the enforced floor must be advertised"
        );
        let nips: Vec<u64> = info["supported_nips"]
            .as_array()
            .expect("supported_nips is an array")
            .iter()
            .filter_map(|v| v.as_u64())
            .collect();
        assert!(
            !nips.contains(&13),
            "the operator's NIP-13 toggle still hides the NIP"
        );
    }

    #[test]
    fn the_stats_section_is_the_public_subset() {
        // A NIP-11 client sends `Accept: application/nostr+json`, which is
        // exactly the probe that distinguishes a Nostr client from a
        // scanner — the document must not carry the oracle
        // `/relay/stats` withholds via PRIVATE_STATS_KEYS.
        let stats = Stats::new();
        stats
            .db_free_bytes
            .store(999, std::sync::atomic::Ordering::Relaxed);
        stats
            .db_disk_full
            .store(1, std::sync::atomic::Ordering::Relaxed);
        stats
            .db_errors
            .store(3, std::sync::atomic::Ordering::Relaxed);
        stats
            .accept_errors
            .store(2, std::sync::atomic::Ordering::Relaxed);
        stats
            .rebuild_failures
            .store(1, std::sync::atomic::Ordering::Relaxed);
        stats
            .conn_refused_blocked
            .store(1, std::sync::atomic::Ordering::Relaxed);
        let info = relay_info(&Config::default(), &AccessControl::default(), &stats, None);
        let section = info
            .get("stats")
            .expect("the relay info document carries a stats section");
        for absent in [
            "db_free_bytes",
            "db_disk_full",
            "db_errors",
            "accept_errors",
            "rebuild_failures",
            "log_errors",
            "connection_refusals",
        ] {
            assert!(
                section.get(absent).is_none(),
                "{absent} must not leak through the NIP-11 stats section"
            );
        }
        for present in ["db_size_bytes", "uptime_secs", "written_at"] {
            assert!(
                section.get(present).is_some(),
                "{present} must remain in the public stats"
            );
        }
        assert_eq!(
            section.get("db_size_bytes").and_then(Value::as_u64),
            Some(0),
            "the public subset preserves the ordinary counters"
        );
    }

    #[test]
    fn restricted_writes_tracks_kind_lists() {
        let stats = Stats::new();
        let access = AccessControl::default();
        let info = relay_info(&Config::default(), &access, &stats, None);
        assert_eq!(
            info["limitation"]["restricted_writes"], false,
            "default writes are unrestricted"
        );
        let access = AccessControl {
            allowed_kinds: vec![1],
            ..Default::default()
        };
        let info = relay_info(&Config::default(), &access, &stats, None);
        assert_eq!(
            info["limitation"]["restricted_writes"], true,
            "a kind allowlist restricts writes"
        );
        let access = AccessControl {
            blocked_kinds: vec![5],
            ..Default::default()
        };
        let info = relay_info(&Config::default(), &access, &stats, None);
        assert_eq!(
            info["limitation"]["restricted_writes"], true,
            "a kind denylist restricts writes"
        );
        let access = AccessControl {
            restrict_relay: true,
            ..Default::default()
        };
        let info = relay_info(&Config::default(), &access, &stats, None);
        assert_eq!(
            info["limitation"]["restricted_writes"], true,
            "a pubkey whitelist restricts writes"
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
    fn version_can_be_omitted_without_changing_other_metadata() {
        let mut cfg = Config::default();
        let stats = Stats::new();
        let access = AccessControl::default();

        let info = relay_info(&cfg, &access, &stats, None);
        assert_eq!(info["version"], env!("CARGO_PKG_VERSION"));

        cfg.server.omit_version = true;
        let info = relay_info(&cfg, &access, &stats, None);
        assert!(info.get("version").is_none());
        assert_eq!(info["software"], env!("CARGO_PKG_REPOSITORY"));
        assert_eq!(info["name"], cfg.relay.name);
        assert!(info.get("supported_nips").is_some());
        assert!(info.get("limitation").is_some());
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
        // Key-dependent (29/43/66) and credential-dependent (86) NIPs are
        // advertised only when their prerequisites are configured.
        let mut cfg = Config::default();
        cfg.relay.private_key = "11".repeat(32);
        cfg.rpc.management_token = "token".to_string();
        let stats = Stats::new();
        let access = crate::config::AccessControl::default();
        let info = relay_info(&cfg, &access, &stats, None);
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

    #[test]
    fn key_dependent_nips_require_prerequisites() {
        // Without a relay key (or RPC credentials) the NIPs whose relay-side
        // behaviour cannot work are not advertised.
        let info = info();
        let nips = info["supported_nips"].as_array().unwrap();
        for missing in [29u64, 43, 66, 86] {
            assert!(
                !nips.iter().any(|n| n.as_u64() == Some(missing)),
                "NIP-{missing} must not be advertised without its prerequisites"
            );
        }
    }
}
