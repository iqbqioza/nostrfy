//! Event acceptance checks: base validation (NIP-01 signatures, limits,
//! NIP-13/26/42/43/70 and access control), the shared [`Precheck`] used by
//! both accept paths, and the nsec-leak detector.

use crate::config::{AccessControl, Config};
use crate::event::Event;
use crate::nips::{nip01, nip09, nip13, nip26, nip29, nip43, nip62, nip70};

/// A bech32-encoded nsec secret key is `nsec1` followed by 58 characters
/// (52 data characters plus a 6-character checksum), 63 characters in total.
const NSEC_PREFIX: &[u8; 5] = b"nsec1";
const NSEC_BODY_LEN: usize = 58;

/// Outcome of the shared pre-acceptance checks.
pub(crate) enum Precheck {
    Accept,
    Reject(String),
    /// NIP-62: the event is a valid request to vanish.
    Vanish,
}

/// The smallest batch large enough for parallel signature verification to
/// beat the per-thread spawn overhead (a flood from one connection yields
/// batches far above this).
const MIN_PARALLEL_VERIFY: usize = 16;
/// Cap on the verification threads spawned for one batch, to keep
/// concurrent floods from oversubscribing the machine.
const MAX_PARALLEL_VERIFY_THREADS: usize = 8;

/// Verifies the NIP-01 signatures of `events` across `available_parallelism`
/// cores and returns one verdict per event, aligned with the input order.
/// The Schnorr check is the dominant per-event CPU cost on the accept path
/// (tens of microseconds each); a batch that handed it to a single connection
/// worker would cap ingestion throughput at one core. Small batches fall back
/// to the inline sequential verify (the same call, same verdicts).
///
/// `Secp256k1<All>` is `Send + Sync` (the precomputed context is immutable),
/// so the shared context can verify on several threads at once.
pub(crate) fn verify_signatures_parallel(
    events: &[Event],
    secp: &secp256k1::Secp256k1<secp256k1::All>,
) -> Vec<bool> {
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let threads = cpus.min(MAX_PARALLEL_VERIFY_THREADS);
    if events.len() < MIN_PARALLEL_VERIFY || threads < 2 {
        return events
            .iter()
            .map(|e| nip01::verify(e, secp).is_ok())
            .collect();
    }
    let per = events.len().div_ceil(threads);
    std::thread::scope(|s| {
        let mut handles = Vec::with_capacity(events.len().div_ceil(per));
        for chunk in events.chunks(per) {
            handles.push(s.spawn(move || {
                chunk
                    .iter()
                    .map(|e| nip01::verify(e, secp).is_ok())
                    .collect::<Vec<bool>>()
            }));
        }
        let verdicts: Vec<bool> = handles
            .into_iter()
            .flat_map(|h| h.join().unwrap_or_default())
            .collect();
        // `div_ceil(per)` chunks never run empty, so the flattened length
        // is exactly `events.len()`.
        debug_assert_eq!(verdicts.len(), events.len());
        verdicts
    })
}

impl super::Relay {
    /// Runs the acceptance checks shared by the single and batched accept
    /// paths: base validation, NIP-62 vanish detection, NIP-43 join
    /// rejection and the NIP-29 write-access rules (h tag, relay-signed
    /// metadata, late publication, membership and `previous` references).
    /// `known_prefixes` supplies the batch's pre-fetched `previous` tag
    /// references; `None` falls back to per-reference database lookups.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn precheck(
        &self,
        cfg: &Config,
        access: &AccessControl,
        event: &Event,
        now: u64,
        authed: &[String],
        known_prefixes: Option<&std::collections::HashSet<Vec<u8>>>,
        verified: Option<bool>,
    ) -> Precheck {
        // Structural and signature validation first: the vanish detection
        // below must only ever run on a properly signed event authored by
        // the vanished pubkey (an unverified event claiming a foreign
        // pubkey must not trigger the deletion of that pubkey).
        if let Err(reason) = self.validate_base(cfg, event, now, authed, verified) {
            return Precheck::Reject(reason);
        }
        // NIP-62: request to vanish — delete everything by this pubkey.
        // The spec requires the relay to honor the request "regardless of
        // the user's status", so it is detected *before* the access-control
        // checks: a blocked or restricted pubkey must still be able to
        // vanish.
        if cfg.nip_enabled(62)
            && nip62::is_vanish(event)
            && nip62::targets_us(event, &cfg.relay_identity())
        {
            return Precheck::Vanish;
        }
        // Access control: blocked/allowlisted pubkeys and kinds.
        if !access.allows_pubkey(&event.pubkey) {
            return Precheck::Reject("blocked: pubkey not allowed".into());
        }
        if !access.allows_kind(event.kind) {
            return Precheck::Reject("blocked: kind not allowed".into());
        }
        // Spam defense: a pubkey may publish at most
        // `relay.max_events_per_min_per_pubkey` events per minute
        // (sliding 60-second window). Counted per accepted event before
        // the database write.
        if !self.publish_rate_allowed(cfg, &event.pubkey, now) {
            return Precheck::Reject("rate-limited: too many events".into());
        }
        // NIP-43: join requests carry an invite code, which this relay
        // never issues; every claim therefore fails (NIP-43 mandates an
        // OK reply).
        if cfg.nip_enabled(43) && event.kind == nip43::JOIN {
            return Precheck::Reject("restricted: this relay does not issue invite codes".into());
        }
        // NIP-29: group action events MUST carry an `h` tag.
        if cfg.nip_enabled(29) && nip29::is_group_action(event) && nip29::group_id(event).is_none()
        {
            return Precheck::Reject("invalid: group events must carry an h tag".into());
        }
        if cfg.nip_enabled(29) {
            // Group metadata events MUST be signed by the relay's own key.
            if (nip29::GROUP_META..=nip29::GROUP_PINS).contains(&event.kind)
                && Some(event.pubkey.as_str()) != self.relay_pubkey().as_deref()
            {
                return Precheck::Reject(
                    "blocked: group metadata must be published by the relay".into(),
                );
            }
            if nip29::group_id(event).is_some() {
                // Late publication prevention for group events.
                if cfg.limits.group_late_publish_secs > 0
                    && event
                        .created_at
                        .saturating_add(cfg.limits.group_late_publish_secs)
                        < now
                {
                    return Precheck::Reject("invalid: event is too old for this group".into());
                }
                let reason = {
                    let groups = self.groups.read().await;
                    groups.validate_write(event).err()
                };
                if let Some(reason) = reason {
                    return Precheck::Reject(reason);
                }
                // NIP-29 `previous` timeline references must exist.
                let mut unknown: Option<&str> = None;
                for prefix in nip29::previous_tags(event) {
                    let Ok(prefix) = hex::decode(&prefix) else {
                        unknown = Some("invalid: malformed previous tag");
                        break;
                    };
                    if !prefix.is_empty() {
                        let exists = match known_prefixes {
                            Some(known) => known.contains(&prefix),
                            None => self.db.event_id_prefix_exists(&prefix).await,
                        };
                        if !exists {
                            unknown = Some("invalid: unknown previous tag reference");
                            break;
                        }
                    }
                }
                if let Some(reason) = unknown {
                    return Precheck::Reject(reason.into());
                }
            }
        }
        Precheck::Accept
    }
}

impl super::Relay {
    /// Base structural, limit and signature validation (no access-control
    /// checks — those run in [`super::Relay::precheck`] *after* the NIP-62
    /// vanish detection, so that a blocked or restricted pubkey can still
    /// request to vanish).
    /// `verified` precomputes the NIP-01 signature check (the batch accept
    /// path verifies a whole batch's signatures in parallel on other cores).
    /// `None` performs the inline `nip01::verify`. All other base checks run
    /// first in both paths, so the reported reject reason is identical
    /// whether an event's signature was verified inline or in advance.
    pub(crate) fn validate_base(
        &self,
        cfg: &Config,
        event: &Event,
        now: u64,
        authed: &[String],
        verified: Option<bool>,
    ) -> std::result::Result<(), String> {
        let limits = &cfg.limits;

        // NIP-01: kind is an integer between 0 and 65535.
        if event.kind > 65535 {
            return Err("invalid: kind out of range".into());
        }
        // Ephemeral rejection (configurable): NIP-01 kinds 20000-29999 are
        // normally forwarded live without storage; when enabled they are
        // rejected outright, except for NIPs-specified ephemeral kinds
        // that must not be blocked (NIP-42 AUTH, NIP-98 HTTP auth,
        // NIP-43 JOIN/LEAVE, NIP-46 Nostr Connect, NIP-47 wallet).
        if cfg.relay.reject_ephemeral
            && (20000..30000).contains(&event.kind)
            && !Self::is_ephemeral_exempt(event.kind)
        {
            return Err("blocked: ephemeral events not allowed".into());
        }
        // NIP-34 (git): the kinds are rejected unless `relay.enabled_git`
        // is set — the default keeps the relay free of patch payloads.
        if !cfg.relay.enabled_git && Config::is_git_kind(event.kind) {
            return Err("blocked: NIP-34 git events are disabled".into());
        }
        // NIP-01: each tag is an array of one or more strings.
        if event.tags.iter().any(|t| t.is_empty()) {
            return Err("invalid: empty tag".into());
        }
        // NIP-09: a deletion request is defined as having a list of one or
        // more `e` or `a` tags. A kind-5 event with no targets has no
        // effect and would only accumulate as meaningless history.
        if cfg.nip_enabled(9)
            && event.kind == nip09::DELETION_KIND
            && !event
                .tags
                .iter()
                .any(|t| t.len() >= 2 && (t[0] == "e" || t[0] == "a"))
        {
            return Err("invalid: deletion request must reference at least one event".into());
        }

        // NIP-11's `max_content_length` is a count of unicode characters,
        // so the enforcement counts characters (the byte size is bounded by
        // the websocket message limit instead).
        if event.content.chars().count() > limits.max_content_bytes {
            return Err("invalid: content too large".into());
        }
        if event.tags.len() > limits.max_tags {
            return Err("invalid: too many tags".into());
        }
        if event
            .tags
            .iter()
            .any(|t| t.iter().any(|v| v.len() > limits.max_tag_value_bytes))
        {
            return Err("invalid: tag value too large".into());
        }
        // Events with a future created_at (beyond the tolerated skew) are
        // dropped silently with the NIP-01 `mute:` prefix instead of being
        // rejected as invalid.
        if event.created_at > now.saturating_add(limits.max_created_at_future_secs) {
            return Err("mute: event creation date is in the future".into());
        }

        // Security: events carrying secret key material (bech32 `nsec1`
        // strings) are dropped silently as well.
        let leaks_secret = contains_secret_key(&event.content)
            || event
                .tags
                .iter()
                .any(|t| t.iter().any(|v| contains_secret_key(v)));
        if leaks_secret {
            return Err("mute: event contains secret key material".into());
        }

        match verified {
            Some(true) => {}
            Some(false) => return Err("invalid: signature verification failed".to_string()),
            None => nip01::verify(event, self.secp())
                .map_err(|_| "invalid: signature verification failed".to_string())?,
        }

        if cfg.nip_enabled(26) && !nip26::verify(event, self.secp()) {
            return Err("invalid: delegation failed".into());
        }

        if cfg.nip_enabled(13)
            && cfg.relay.require_pow > 0
            && !nip13::verify(event, cfg.relay.require_pow)
        {
            return Err("pow: difficulty requirement not reached".into());
        }

        // NIP-42: auth events are ephemeral and must never be stored or
        // broadcast.
        if cfg.nip_enabled(42) && event.kind == crate::nips::nip42::AUTH_KIND {
            return Err("invalid: authentication events cannot be published".into());
        }

        // NIP-43: role definitions, membership lists and add/remove user
        // events MUST be signed by the relay's own key ("the pubkey
        // specified in the `self` field of the relay's NIP-11 document");
        // events signed by anyone else are rejected.
        if cfg.nip_enabled(43)
            && matches!(
                event.kind,
                nip43::ROLE_DEFINITION
                    | nip43::MEMBERSHIP_LIST
                    | nip43::ADD_USER
                    | nip43::REMOVE_USER
            )
            && Some(event.pubkey.as_str()) != self.relay_pubkey().as_deref()
        {
            return Err("blocked: relay metadata must be published by the relay".into());
        }

        // NIP-43: leave requests must be signed at the time of sending
        // ("created_at MUST be now, plus or minus a few minutes") and MUST
        // carry the NIP-70 `-` tag.
        if cfg.nip_enabled(43) && event.kind == nip43::LEAVE {
            if event.created_at.abs_diff(now) > 600 {
                return Err("invalid: leave request is too old".into());
            }
            if !nip70::is_protected(event) {
                return Err("invalid: leave request must carry a `-` tag".into());
            }
        }

        // NIP-70: reposts must not embed a protected event; relays SHOULD
        // summarily reject such reposts (kind 6 embeds the note JSON in the
        // content, kind 16 embeds replaceable events the same way).
        if cfg.nip_enabled(70)
            && (event.kind == 6 || event.kind == 16)
            && let Ok(embedded) = serde_json::from_str::<Event>(&event.content)
            && nip70::is_protected(&embedded)
        {
            return Err("restricted: repost of a protected event".into());
        }

        if cfg.nip_enabled(42) && cfg.relay.require_auth && authed.is_empty() {
            return Err("auth-required: this relay requires authentication".into());
        }

        // NIP-70: protected events may only be published by their author,
        // so the event's own pubkey must be among the authenticated keys.
        if cfg.nip_enabled(70)
            && nip70::is_protected(event)
            && !authed.iter().any(|pk| pk == &event.pubkey)
        {
            return Err(
                "auth-required: protected events may only be published by their author".into(),
            );
        }

        // NIP-78: relays SHOULD require the NIP-42 AUTH flow before
        // accepting kind 30078 events (and kind 78) — application-specific
        // data that is only served to the authenticated owner.
        if cfg.nip_enabled(78)
            && cfg.relay.nip78_auth
            && crate::nips::nip78::is_app_specific(event)
            && authed.is_empty()
        {
            return Err("auth-required: application-specific events require authentication".into());
        }

        Ok(())
    }

    /// NIPs-specified ephemeral kinds that must not be blocked even when
    /// `reject_ephemeral` is enabled (NIP-42 AUTH, NIP-98 HTTP auth,
    /// NIP-43 JOIN/LEAVE/INVITE, NIP-46 Nostr Connect, NIP-47 wallet
    /// request/response, NIP-59 ephemeral gift wrap, BUD-02 Blossom blobs
    /// — per NIPs README Event Kinds table and the NIP-42/43/46/47/59/98/B7
    /// specs).
    fn is_ephemeral_exempt(kind: u64) -> bool {
        matches!(
            kind,
            crate::nips::nip42::AUTH_KIND
                | crate::nips::nip98::AUTH_KIND
                | crate::nips::nip43::JOIN
                | crate::nips::nip43::LEAVE
                | 28935 // NIP-43 Invite Request
                | 24133 // NIP-46 Nostr Connect
                | 23194 // NIP-47 wallet request
                | 23195 // NIP-47 wallet response
                | 24242 // BUD-02 Blossom / NIP-B7 blobs
                | 21059 // NIP-59 ephemeral gift wrap
        )
    }
}

fn is_bech32_char(byte: u8) -> bool {
    // bech32 is case-insensitive: an all-uppercase encoding of a real key
    // is still a real key, so the detector must accept uppercase data
    // characters too (the checksum verification below is case-insensitive
    // as well, and `bech32_checksum_valid` rejects mixed-case strings).
    b"qpzry9x8gf2tvdw0s3jn54khce6mua7l".contains(&byte.to_ascii_lowercase())
}

/// Returns `true` when the text contains a real secret key: an `nsec1`
/// prefix (case-insensitive) followed by 58 bech32 characters whose bech32
/// checksum validates. A string that merely *resembles* a key (e.g. quoted
/// in an article, or `nsec1` + charset garbage with a bad checksum) is not
/// flagged, so the check cannot be used to censor content by baiting a
/// user into quoting a fake key.
pub(crate) fn contains_secret_key(text: &str) -> bool {
    let bytes = text.as_bytes();
    let win = NSEC_PREFIX.len() + NSEC_BODY_LEN;
    let mut i = 0;
    while i + win <= bytes.len() {
        if text.is_char_boundary(i)
            && bytes[i..i + NSEC_PREFIX.len()]
                .iter()
                .zip(NSEC_PREFIX)
                .all(|(b, p)| b.to_ascii_lowercase() == *p)
            && bytes[i + NSEC_PREFIX.len()..i + win]
                .iter()
                .all(|b| is_bech32_char(*b))
            && crate::nips::nip19::bech32_checksum_valid("nsec", &text[i..i + win])
        {
            return true;
        }
        i += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::super::Relay;
    use crate::config::{AccessControl, Config};
    use crate::event::Event;
    use crate::util::unix_now;
    use secp256k1::{Keypair, Secp256k1, XOnlyPublicKey};
    use std::sync::Arc;
    use tokio::sync::RwLock;

    fn signed(kind: u64, tags: Vec<Vec<String>>) -> Event {
        signed_with_seed(3u8, kind, tags)
    }

    fn signed_other_key(kind: u64, tags: Vec<Vec<String>>) -> Event {
        signed_with_seed(4u8, kind, tags)
    }

    fn signed_with_seed(seed: u8, kind: u64, tags: Vec<Vec<String>>) -> Event {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_seckey_slice(&secp, &[seed; 32]).unwrap();
        let pubkey = XOnlyPublicKey::from_keypair(&keypair).0.to_string();
        let mut ev = Event {
            id: String::new(),
            pubkey,
            created_at: unix_now(),
            kind,
            tags,
            content: String::new(),
            sig: String::new(),
        };
        ev.id = crate::nips::nip01::compute_id(&ev);
        let id = ev.id_bytes().unwrap();
        ev.sig = secp.sign_schnorr_no_aux_rand(&id, &keypair).to_string();
        ev
    }

    #[test]
    fn vanished_pubkey_rejects_new_events() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut cfg = Config::default();
            cfg.database.map_size = 16 * 1024 * 1024;
            cfg.database.max_map_size = 256 * 1024 * 1024;
            cfg.database.path = std::env::temp_dir().join("nostrd-vanish-test");
            let _ = std::fs::remove_dir_all(&cfg.database.path);
            let db = crate::db::DbClient::open(
                &cfg.database,
                true,
                Arc::new(Default::default()),
                0,
                128,
                4096,
                262144,
            )
            .unwrap();
            let config = Arc::new(RwLock::new(cfg));
            let mut relay = Relay::new(
                config.clone(),
                db,
                crate::stats::Stats::new(),
                "",
                crate::relay::LiveBusConfig {
                    buffer: 1024,
                    batch_interval_ms: 10,
                    batch_size: 64,
                },
            )
            .await;
            relay.start_live_bus();
            let relay = Arc::new(relay);
            let vanished = signed_with_seed(42u8, 1, vec![]);
            relay.vanish_pubkey(vanished.pubkey_bytes().unwrap()).await;
            let outcome = relay.accept_event(vanished, &[], None).await.0;
            assert!(
                matches!(&outcome, crate::db::PutOutcome::Invalid(reason) if reason.contains("vanish")),
                "a vanished pubkey's new events are rejected: {outcome:?}"
            );
            relay.db.shutdown();
        });
    }

    #[test]
    fn publish_rate_limits_events_per_pubkey_per_minute() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut cfg = Config::default();
            cfg.relay.max_events_per_min_per_pubkey = 3;
            cfg.database.map_size = 16 * 1024 * 1024;
            cfg.database.max_map_size = 256 * 1024 * 1024;
            cfg.database.path = std::env::temp_dir().join("nostrd-rate-test");
            let _ = std::fs::remove_dir_all(&cfg.database.path);
            let db = crate::db::DbClient::open(
                &cfg.database,
                true,
                Arc::new(Default::default()),
                0,
                128,
                4096,
                262144,
            )
            .unwrap();
            let config = Arc::new(RwLock::new(cfg));
            let relay = Arc::new(
                Relay::new(
                    config.clone(),
                    db,
                    crate::stats::Stats::new(),
                    "",
                    crate::relay::LiveBusConfig {
                        buffer: 1024,
                        batch_interval_ms: 10,
                        batch_size: 64,
                    },
                )
                .await,
            );
            let cfg = relay.config.read().await;
            let access = AccessControl::default();
            let now = unix_now();
            // The first three events of the minute are accepted.
            for i in 0..3 {
                let ev = signed(1, vec![vec!["content".into(), format!("{i}")]]);
                let out = relay
                    .precheck(&cfg, &access, &ev, now, &[], None, None)
                    .await;
                assert!(
                    matches!(out, super::Precheck::Accept),
                    "event {i} must be accepted under the limit"
                );
            }
            // The fourth is rate-limited.
            let ev = signed(1, vec![vec!["content".into(), "4".into()]]);
            let out = relay
                .precheck(&cfg, &access, &ev, now, &[], None, None)
                .await;
            assert!(
                matches!(out, super::Precheck::Reject(msg) if msg.contains("rate-limited")),
                "the event over the limit must be rate-limited"
            );
            // A different pubkey has its own window.
            let ev = signed_other_key(1, vec![]);
            let out = relay
                .precheck(&cfg, &access, &ev, now, &[], None, None)
                .await;
            assert!(
                matches!(out, super::Precheck::Accept),
                "another pubkey is not limited by the first window"
            );
            // After the minute passes the window slides open again.
            let ev = signed(1, vec![vec!["content".into(), "5".into()]]);
            let out = relay
                .precheck(&cfg, &access, &ev, now + 61, &[], None, None)
                .await;
            assert!(
                matches!(out, super::Precheck::Accept),
                "the window must slide open after 60 seconds"
            );
            drop(cfg);
            relay.db.shutdown();
        });
    }

    #[test]
    fn publish_rate_unlimited_by_default_and_bounded_map() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut cfg = Config::default();
            cfg.database.map_size = 16 * 1024 * 1024;
            cfg.database.max_map_size = 256 * 1024 * 1024;
            cfg.database.path = std::env::temp_dir().join("nostrd-rate-map-test");
            let _ = std::fs::remove_dir_all(&cfg.database.path);
            let db = crate::db::DbClient::open(
                &cfg.database,
                true,
                Arc::new(Default::default()),
                0,
                128,
                4096,
                262144,
            )
            .unwrap();
            let config = Arc::new(RwLock::new(cfg));
            let relay = Arc::new(
                Relay::new(
                    config.clone(),
                    db,
                    crate::stats::Stats::new(),
                    "",
                    crate::relay::LiveBusConfig {
                        buffer: 1024,
                        batch_interval_ms: 10,
                        batch_size: 64,
                    },
                )
                .await,
            );
            // 0 = unlimited: the check never rejects and the map stays empty.
            let cfg = Config::default();
            assert!(relay.publish_rate_allowed(&cfg, &"a".repeat(64), unix_now()));
            assert_eq!(
                relay.publish_rate.lock().unwrap().len(),
                0,
                "no window is recorded when the limit is disabled"
            );
            // The map is bounded: with the limit on, many pubkeys evict the
            // map instead of growing it.
            let mut cfg = Config::default();
            cfg.relay.max_events_per_min_per_pubkey = 1;
            for i in 0..20_000u64 {
                let pk = format!("{i:064x}");
                assert!(relay.publish_rate_allowed(&cfg, &pk, unix_now()));
            }
            assert!(
                relay.publish_rate.lock().unwrap().len() <= 10_000,
                "the tracked-pubkey map must not exceed its bound"
            );
            relay.db.shutdown();
        });
    }

    #[test]
    fn git_kinds_follow_enable_git() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            // Default config (enable_git = false): every NIP-34 kind is
            // rejected.
            let mut cfg = Config::default();
            cfg.database.map_size = 16 * 1024 * 1024;
            cfg.database.max_map_size = 256 * 1024 * 1024;
            cfg.database.path = std::env::temp_dir().join("nostrd-git-test-disabled");
            let _ = std::fs::remove_dir_all(&cfg.database.path);
            let db = crate::db::DbClient::open(
                &cfg.database,
                true,
                Arc::new(Default::default()),
                0,
                128,
                4096,
                262144,
            )
            .unwrap();
            let config = Arc::new(RwLock::new(cfg));
            let relay = Arc::new(
                Relay::new(
                    config.clone(),
                    db,
                    crate::stats::Stats::new(),
                    "",
                    crate::relay::LiveBusConfig {
                        buffer: 1024,
                        batch_interval_ms: 10,
                        batch_size: 64,
                    },
                )
                .await,
            );
            let cfg = relay.config.read().await;
            let access = AccessControl::default();
            for kind in [1617, 1618, 1619, 1621, 1622, 1630, 1633, 30617, 30618] {
                let ev = signed(kind, vec![]);
                let out = relay
                    .precheck(&cfg, &access, &ev, unix_now(), &[], None, None)
                    .await;
                assert!(
                    matches!(out, super::Precheck::Reject(msg) if msg.contains("NIP-34")),
                    "kind {kind} must be rejected when enable_git is false"
                );
            }
            // Boundary kinds around the git ranges stay accepted.
            for kind in [1616, 1623, 1629, 1634, 30616, 30619] {
                let ev = signed(kind, vec![]);
                let out = relay
                    .precheck(&cfg, &access, &ev, unix_now(), &[], None, None)
                    .await;
                assert!(
                    matches!(out, super::Precheck::Accept),
                    "kind {kind} must not be treated as a git kind"
                );
            }
            drop(cfg);
            relay.db.shutdown();

            // enable_git = true: the kinds are accepted.
            let mut cfg2 = Config::default();
            cfg2.relay.enabled_git = true;
            cfg2.database.path = std::env::temp_dir().join("nostrd-git-test-enabled");
            let _ = std::fs::remove_dir_all(&cfg2.database.path);
            let db2 = crate::db::DbClient::open(
                &cfg2.database,
                true,
                Arc::new(Default::default()),
                0,
                128,
                4096,
                262144,
            )
            .unwrap();
            let config2 = Arc::new(RwLock::new(cfg2));
            let relay2 = Arc::new(
                Relay::new(
                    config2.clone(),
                    db2,
                    crate::stats::Stats::new(),
                    "",
                    crate::relay::LiveBusConfig {
                        buffer: 1024,
                        batch_interval_ms: 10,
                        batch_size: 64,
                    },
                )
                .await,
            );
            let cfg2 = relay2.config.read().await;
            let access2 = AccessControl::default();
            for kind in [1617, 1621, 1633, 30618] {
                let ev = signed(kind, vec![]);
                let out = relay2
                    .precheck(&cfg2, &access2, &ev, unix_now(), &[], None, None)
                    .await;
                assert!(
                    matches!(out, super::Precheck::Accept),
                    "kind {kind} must be accepted when enable_git is true"
                );
            }
            drop(cfg2);
            relay2.db.shutdown();
        });
    }

    #[test]
    fn ephemeral_rejection_respects_config() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            // Default config: ephemeral events are allowed.
            let mut cfg = Config::default();
            cfg.database.map_size = 16 * 1024 * 1024;
            cfg.database.max_map_size = 256 * 1024 * 1024;
            cfg.database.path = std::env::temp_dir().join("nostrd-ephemeral-test-allow");
            let _ = std::fs::remove_dir_all(&cfg.database.path);
            let db = crate::db::DbClient::open(
                &cfg.database,
                true,
                Arc::new(Default::default()),
                0,
                128,
                4096,
                262144,
            )
            .unwrap();
            let config = Arc::new(RwLock::new(cfg));
            let stats = crate::stats::Stats::new();
            let relay = Relay::new(
                config.clone(),
                db,
                stats,
                "",
                crate::relay::LiveBusConfig {
                    buffer: 1024,
                    batch_interval_ms: 10,
                    batch_size: 64,
                },
            )
            .await;
            let relay = Arc::new(relay);
            let cfg = relay.config.read().await;
            let access = AccessControl::default();

            for kind in [20000, 25000, 29999] {
                let ev = signed(kind, vec![]);
                let out = relay
                    .precheck(&cfg, &access, &ev, unix_now(), &[], None, None)
                    .await;
                assert!(
                    matches!(out, super::Precheck::Accept),
                    "kind {kind} must be accepted when reject_ephemeral is false"
                );
            }
            // Boundary kinds must not be treated as ephemeral.
            for kind in [19999, 30000, 1, 0] {
                let ev = signed(kind, vec![]);
                let out = relay
                    .precheck(&cfg, &access, &ev, unix_now(), &[], None, None)
                    .await;
                assert!(
                    matches!(out, super::Precheck::Accept),
                    "kind {kind} must not be ephemeral"
                );
            }
            drop(cfg);
            relay.db.shutdown();

            // With reject_ephemeral = true: ephemeral range is blocked.
            let mut cfg2 = Config::default();
            cfg2.relay.reject_ephemeral = true;
            cfg2.database.path = std::env::temp_dir().join("nostrd-ephemeral-test-reject");
            let _ = std::fs::remove_dir_all(&cfg2.database.path);
            let db2 = crate::db::DbClient::open(
                &cfg2.database,
                true,
                Arc::new(Default::default()),
                0,
                128,
                4096,
                262144,
            )
            .unwrap();
            let config2 = Arc::new(RwLock::new(cfg2));
            let stats2 = crate::stats::Stats::new();
            let relay2 = Relay::new(
                config2.clone(),
                db2,
                stats2,
                "",
                crate::relay::LiveBusConfig {
                    buffer: 1024,
                    batch_interval_ms: 10,
                    batch_size: 64,
                },
            )
            .await;
            let relay2 = Arc::new(relay2);
            let cfg2 = relay2.config.read().await;
            let access2 = AccessControl::default();

            for kind in [20000, 25000, 29999] {
                let ev = signed(kind, vec![]);
                let out = relay2
                    .precheck(&cfg2, &access2, &ev, unix_now(), &[], None, None)
                    .await;
                assert!(
                    matches!(out, super::Precheck::Reject(msg) if msg.contains("ephemeral")),
                    "kind {kind} must be rejected when reject_ephemeral is true"
                );
            }
            // Boundaries still accepted.
            for kind in [19999, 30000, 1, 0] {
                let ev = signed(kind, vec![]);
                let out = relay2
                    .precheck(&cfg2, &access2, &ev, unix_now(), &[], None, None)
                    .await;
                assert!(
                    matches!(out, super::Precheck::Accept),
                    "kind {kind} must not be rejected by ephemeral filter"
                );
            }
            // NIPs-specified ephemeral kinds must be exempt even when enabled.
            for kind in [
                22242, // NIP-42 AUTH
                27235, // NIP-98 HTTP auth
                28934, // NIP-43 JOIN
                28935, // NIP-43 Invite Request
                28936, // NIP-43 LEAVE
                24133, // NIP-46 Nostr Connect
                23194, // NIP-47 wallet request
                23195, // NIP-47 wallet response
                24242, // BUD-02 Blossom / NIP-B7 blobs
                21059, // NIP-59 ephemeral gift wrap
            ] {
                let ev = signed(kind, vec![]);
                let out = relay2
                    .precheck(&cfg2, &access2, &ev, unix_now(), &[], None, None)
                    .await;
                assert!(
                    !matches!(out, super::Precheck::Reject(msg) if msg.contains("ephemeral")),
                    "kind {kind} must be exempt from ephemeral rejection"
                );
            }
            drop(cfg2);
            // SIGHUP-like reload: flipping the flag back to false must immediately allow ephemeral again.
            {
                let mut w = relay2.config.write().await;
                w.relay.reject_ephemeral = false;
            }
            let cfg2_reloaded = relay2.config.read().await;
            let ev = signed(20000, vec![]);
            let out = relay2
                .precheck(&cfg2_reloaded, &access2, &ev, unix_now(), &[], None, None)
                .await;
            assert!(
                matches!(out, super::Precheck::Accept),
                "reloading to false must re-allow ephemeral"
            );
            drop(cfg2_reloaded);
            relay2.db.shutdown();
        });
    }

    #[test]
    fn ephemeral_rejection_via_validate_base() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut cfg = Config::default();
            cfg.relay.reject_ephemeral = true;
            cfg.database.map_size = 16 * 1024 * 1024;
            cfg.database.max_map_size = 256 * 1024 * 1024;
            cfg.database.path = std::env::temp_dir().join("nostrd-ephemeral-validate-base");
            let _ = std::fs::remove_dir_all(&cfg.database.path);
            let db = crate::db::DbClient::open(
                &cfg.database,
                true,
                Arc::new(Default::default()),
                0,
                128,
                4096,
                262144,
            )
            .unwrap();
            let config = Arc::new(RwLock::new(cfg));
            let stats = crate::stats::Stats::new();
            let relay = Relay::new(
                config.clone(),
                db,
                stats,
                "",
                crate::relay::LiveBusConfig {
                    buffer: 1024,
                    batch_interval_ms: 10,
                    batch_size: 64,
                },
            )
            .await;
            let relay = Arc::new(relay);
            let cfg = relay.config.read().await;
            let ev = signed(20001, vec![]);
            let res = relay.validate_base(&cfg, &ev, unix_now(), &[], None);
            assert!(
                res.is_err() && res.unwrap_err().contains("ephemeral"),
                "validate_base must reject ephemeral when enabled"
            );
            // NIP-42 AUTH (22242) must not be masked as ephemeral — it has
            // its own dedicated rejection below.
            let auth_ev = signed(22242, vec![]);
            let auth_res = relay.validate_base(&cfg, &auth_ev, unix_now(), &[], None);
            assert!(
                auth_res.is_err() && !auth_res.unwrap_err().contains("ephemeral"),
                "AUTH kind must not be rejected as ephemeral"
            );
            relay.db.shutdown();
        });
    }

    #[test]
    fn blocked_pubkey_can_still_vanish() {
        // NIP-62: the relay MUST honor a vanish request "regardless of the
        // user's status" — a blocked pubkey must still be able to vanish.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut cfg = Config::default();
            cfg.database.map_size = 16 * 1024 * 1024;
            cfg.database.max_map_size = 256 * 1024 * 1024;
            cfg.database.path = std::env::temp_dir().join("nostrd-vanish-test");
            let _ = std::fs::remove_dir_all(&cfg.database.path);
            let db = crate::db::DbClient::open(
                &cfg.database,
                true,
                Arc::new(Default::default()),
                0,
                128,
                4096,
                262144,
            )
            .unwrap();
            let config = Arc::new(RwLock::new(cfg));
            let stats = crate::stats::Stats::new();
            let relay = Relay::new(
                config,
                db,
                stats,
                "",
                crate::relay::LiveBusConfig {
                    buffer: 1024,
                    batch_interval_ms: 10,
                    batch_size: 64,
                },
            )
            .await;
            let relay = Arc::new(relay);

            // The vanish event's pubkey is blocked: the vanish must still win.
            let mut access = AccessControl::default();
            let vanish = signed(62, vec![vec!["relay".into(), "127.0.0.1:8080".into()]]);
            access
                .blocked_pubkeys
                .push((vanish.pubkey.clone(), String::new()));
            let cfg = relay.config.read().await;
            let out = relay
                .precheck(&cfg, &access, &vanish, unix_now(), &[], None, None)
                .await;
            assert!(
                matches!(out, super::Precheck::Vanish),
                "a blocked pubkey's vanish request must be honored"
            );

            // A blocked pubkey's *regular* event is still rejected.
            let note = signed(1, vec![]);
            let out = relay
                .precheck(&cfg, &access, &note, unix_now(), &[], None, None)
                .await;
            assert!(
                matches!(out, super::Precheck::Reject(_)),
                "a blocked pubkey's regular events stay blocked"
            );
            relay.db.shutdown();
        });
    }
}
