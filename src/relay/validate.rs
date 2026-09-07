//! Event acceptance checks: base validation (NIP-01 signatures, limits,
//! NIP-13/26/42/43/70 and access control), the shared [`Precheck`] used by
//! both accept paths, and the nsec-leak detector.

use crate::config::{AccessControl, Config};
use crate::event::Event;
use crate::nips::{nip01, nip09, nip13, nip26, nip29, nip40, nip43, nip62, nip70};

/// A bech32-encoded nsec secret key is `nsec1` followed by 58 characters
/// (52 data characters plus a 6-character checksum), 63 characters in total.
const NSEC_PREFIX: &[u8; 5] = b"nsec1";
const NSEC_BODY_LEN: usize = 58;

/// Outcome of the shared pre-acceptance checks.
pub(crate) enum Precheck {
    Accept,
    Reject(String),
    /// The event is acknowledged as a duplicate (OK true, not stored):
    /// NIP-43's example for a member's repeated join claim.
    Duplicate(String),
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
        // vanish. Note: `validate_base` (signatures, PoW when configured)
        // still runs first — "status" covers allow/block state, not proof
        // of authorship or anti-spam proof-of-work.
        if cfg.nip_enabled(62)
            && nip62::is_vanish(event)
            && nip62::targets_us(event, &cfg.relay_identity())
        {
            return Precheck::Vanish;
        }
        // Access control: blocked/allowlisted pubkeys and kinds. The relay's
        // own pubkey and the admin pubkey (`relay.pubkey`) are exempt:
        // the operator must be able to publish command events even when
        // the relay is restricted to an allow list that does not include
        // them (the signed internal events bypass this path entirely).
        let is_operator = self
            .relay_pubkey
            .as_ref()
            .is_some_and(|pk| pk == &event.pubkey)
            || cfg.relay.pubkey.eq_ignore_ascii_case(&event.pubkey);
        if !is_operator && !access.allows_pubkey(&event.pubkey) {
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
        // OK reply). A member who already belongs to the relay gets the
        // spec's `duplicate:` verdict instead of a blanket refusal.
        if cfg.nip_enabled(43) && event.kind == nip43::JOIN {
            let is_member = self.roles.read().await.is_member_of(&event.pubkey);
            if is_member {
                // NIP-43: the spec's example replies OK `true` with the
                // `duplicate:` prefix for a member's repeated claim (the
                // claim itself is never stored — kind 28934 is ephemeral).
                return Precheck::Duplicate(
                    "duplicate: you are already a member of this relay".into(),
                );
            }
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
                // The in-memory invite set never forgets a code whose 9009
                // was NIP-09-deleted or NIP-40-expired (revocation only
                // takes effect after a restart). On a CLOSED group (where
                // the code decides admission) a JOIN with a code is
                // therefore confirmed against the stored, unexpired 9009
                // before admission — the same visibility the in-memory
                // check has (a 9009 of the same batch is not committed
                // yet either way). On open groups the code is optional
                // preauthorization and does not gate admission.
                if event.kind == nip29::JOIN
                    && let Some(code) = nip29::event_code(event)
                    && let Some(gid) = nip29::group_id(event)
                {
                    let closed = self
                        .groups
                        .read()
                        .await
                        .group(gid)
                        .is_some_and(|g| g.settings.closed);
                    if closed {
                        let f: Vec<crate::filter::Filter> =
                            serde_json::from_value(serde_json::json!([
                                { "kinds": [9009], "#h": [gid], "#code": [code] }
                            ]))
                            .expect("static filter");
                        let (stored, _) = self.db.query_req(f, 1, now).await;
                        if stored.is_empty() {
                            return Precheck::Reject(
                                "restricted: invalid invite code (final decision)".into(),
                            );
                        }
                    }
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
        // NIP-59: "Tags MUST always be empty in a `kind:13`" (the seal
        // wrapping an encrypted rumor) — a seal with tags is malformed.
        if event.kind == 13 && !event.tags.is_empty() {
            return Err("invalid: kind 13 seals must not have tags".into());
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
        // rejected as invalid (the NIP-01 example for this case carries
        // the `invalid:` prefix; `mute:` is reserved for ignored ephemeral
        // events).
        if event.created_at > now.saturating_add(limits.max_created_at_future_secs) {
            return Err("invalid: event creation date is in the future".into());
        }

        // NIP-40: the expiration value is required to be a unix timestamp.
        // A malformed value must not silently mean "no expiration" — the
        // client asked for expiry, so the relay would keep the event
        // forever. Rejected while NIP-40 is enabled.
        if cfg.nip_enabled(40)
            && event
                .tags
                .iter()
                .any(|t| t.first().is_some_and(|n| n == nip40::EXPIRATION_TAG))
            && nip40::expiry(event).is_none()
        {
            return Err("invalid: malformed expiration tag".into());
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
        // NIP-01: hex fields are lowercase by convention. An uppercase-hex
        // pubkey would be stored verbatim and then never match the
        // case-sensitive author/tag filters (the event becomes invisible
        // to clients), while normalizing it would break the id/signature
        // that were computed over the original string — so reject it.
        if event.pubkey != event.pubkey.to_ascii_lowercase() {
            return Err("invalid: pubkey must be lowercase hex".into());
        }
        // The same convention applies to the signature: an uppercase-hex
        // sig would be stored verbatim (and never match a lowercase
        // re-computation), so reject it.
        if event.sig != event.sig.to_ascii_lowercase() {
            return Err("invalid: sig must be lowercase hex".into());
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
        // broadcast. The MUST is unconditional: a relay that does not
        // advertise NIP-42 must still not broadcast kind 22242 to other
        // clients, so the check runs regardless of the NIP-42 toggle.
        if event.kind == crate::nips::nip42::AUTH_KIND {
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

        // NIP-70: "The default behavior of a relay MUST be to reject any
        // event that contains `["-"]`"; the only acceptance path is the
        // author's own NIP-42 authentication. The rule is unconditional —
        // the NIP-70 toggle only relaxes the SHOULD-level repost check.
        if nip70::is_protected(event) && !authed.iter().any(|pk| pk == &event.pubkey) {
            return Err(
                "auth-required: protected events may only be published by their author".into(),
            );
        }

        // NIP-78: relays SHOULD require the NIP-42 AUTH flow before
        // accepting kind 30078 events (and kind 78) — application-specific
        // data that is only served to the authenticated owner.
        if cfg.nip_enabled(78)
            && cfg.relay.enabled_nip78_auth
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
                | crate::nips::nip43::INVITE
                | crate::nips::nip43::LEAVE
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
        // Both window edges must lie on character boundaries: slicing in the
        // middle of a multi-byte character would panic and turn a crafted
        // UTF-8 event into a connection-task abort (DoS).
        if text.is_char_boundary(i)
            && text.is_char_boundary(i + win)
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
            cfg.database.path = std::env::temp_dir().join("nostrfy-vanish-test");
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
            relay
                .vanish_pubkey(vanished.pubkey_bytes().unwrap(), vanished.created_at)
                .await;
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
            cfg.database.path = std::env::temp_dir().join("nostrfy-rate-test");
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
            cfg.database.path = std::env::temp_dir().join("nostrfy-rate-map-test");
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
            // The map is bounded: with the limit on, many pubkeys are skipped
            // (never tracked) instead of growing the map, and a full map
            // must not clear everyone's windows — the first 10k pubkeys
            // are still rate-limited.
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
            // A tracked pubkey stays limited while the map is full: its
            // second event within the 60-second window is rejected.
            let tracked = format!("{:064x}", 0u64);
            assert!(
                !relay.publish_rate_allowed(&cfg, &tracked, unix_now()),
                "a full map must not reset a tracked pubkey's window"
            );
            // A fresh pubkey is skipped (fail-open for it alone) and the
            // map is never cleared.
            let fresh = "f".repeat(64);
            assert!(relay.publish_rate_allowed(&cfg, &fresh, unix_now()));
            assert_eq!(
                relay.publish_rate.lock().unwrap().len(),
                10_000,
                "the map is never cleared"
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
            cfg.database.path = std::env::temp_dir().join("nostrfy-git-test-disabled");
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
            cfg2.database.path = std::env::temp_dir().join("nostrfy-git-test-enabled");
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
            cfg.database.path = std::env::temp_dir().join("nostrfy-ephemeral-test-allow");
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
            cfg2.database.path = std::env::temp_dir().join("nostrfy-ephemeral-test-reject");
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
                crate::nips::nip43::JOIN,
                crate::nips::nip43::INVITE,
                crate::nips::nip43::LEAVE,
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
    fn spec_strictness_prefixes_sig_auth_nip70_expiration() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut cfg = Config::default();
            cfg.database.map_size = 16 * 1024 * 1024;
            cfg.database.max_map_size = 256 * 1024 * 1024;
            cfg.database.path = std::env::temp_dir().join("nostrfy-spec-strictness-validate");
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
            let relay = Relay::new(
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
            let relay = Arc::new(relay);
            let now = unix_now();
            let cfg = relay.config.read().await;

            // Item 3: a future-dated event is rejected with the NIP-01
            // `invalid:` prefix (the spec's example), not `mute:`.
            let mut future = signed(1, vec![]);
            future.created_at = now + 10_000;
            let secp = Secp256k1::new();
            let keypair = Keypair::from_seckey_slice(&secp, &[3u8; 32]).unwrap();
            future.id = crate::nips::nip01::compute_id(&future);
            let id = future.id_bytes().unwrap();
            future.sig = secp.sign_schnorr_no_aux_rand(&id, &keypair).to_string();
            let err = relay
                .validate_base(&cfg, &future, now, &[], None)
                .unwrap_err();
            assert!(
                err.starts_with("invalid: event creation date is in the future"),
                "{err}"
            );

            // Item 7: a malformed expiration value is rejected while NIP-40
            // is enabled (it must not silently mean "no expiration").
            let bad = signed(1, vec![vec!["expiration".into(), "not-a-number".into()]]);
            let err = relay.validate_base(&cfg, &bad, now, &[], None).unwrap_err();
            assert!(
                err.starts_with("invalid: malformed expiration tag"),
                "{err}"
            );
            // A bare `["expiration"]` tag (the value is required) is
            // malformed too.
            let bare = signed(1, vec![vec!["expiration".into()]]);
            assert!(relay.validate_base(&cfg, &bare, now, &[], None).is_err());
            // A well-formed value passes.
            let good = signed(1, vec![vec!["expiration".into(), (now + 100).to_string()]]);
            assert!(relay.validate_base(&cfg, &good, now, &[], None).is_ok());

            // Item 4: an uppercase-hex sig is rejected like an uppercase
            // pubkey.
            let mut upper = signed(1, vec![]);
            upper.sig = upper.sig.to_ascii_uppercase();
            let err = relay
                .validate_base(&cfg, &upper, now, &[], None)
                .unwrap_err();
            assert!(
                err.starts_with("invalid: sig must be lowercase hex"),
                "{err}"
            );

            // Item 5: kind 22242 is rejected even when NIP-42 is disabled
            // (the MUST NOT broadcast rule is unconditional).
            let auth = signed(22242, vec![]);
            let err = relay
                .validate_base(&cfg, &auth, now, &[], None)
                .unwrap_err();
            assert!(
                err.starts_with("invalid: authentication events cannot be published"),
                "{err}"
            );

            // Item 6: NIP-70's default MUST ("reject any event that contains
            // `["-"]`") holds even when the NIP-70 toggle is off; the only
            // acceptance path is the author's own AUTH.
            drop(cfg);
            {
                let mut w = relay.config.write().await;
                w.relay.disabled_nips.push(70);
                w.relay.disabled_nips.push(42);
            }
            let cfg = relay.config.read().await;
            let protected = signed(1, vec![vec!["-".into()]]);
            let err = relay
                .validate_base(&cfg, &protected, now, &[], None)
                .unwrap_err();
            assert!(
                err.starts_with("auth-required: protected events may only be published"),
                "{err}"
            );
            // The author's own authenticated key is the exception.
            let authed = vec![protected.pubkey.clone()];
            assert!(
                relay
                    .validate_base(&cfg, &protected, now, &authed, None)
                    .is_ok()
            );

            // With NIP-40 disabled, the malformed expiration tag is not
            // rejected (the relay does not interpret the tag at all).
            drop(cfg);
            {
                let mut w = relay.config.write().await;
                w.relay.disabled_nips.push(40);
            }
            let cfg = relay.config.read().await;
            let bad = signed(1, vec![vec!["expiration".into(), "not-a-number".into()]]);
            assert!(relay.validate_base(&cfg, &bad, now, &[], None).is_ok());

            drop(cfg);
            relay.db.shutdown();
        });
    }

    #[test]
    fn nip43_member_claim_acknowledged_as_duplicate() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut cfg = Config::default();
            cfg.database.map_size = 16 * 1024 * 1024;
            cfg.database.max_map_size = 256 * 1024 * 1024;
            cfg.database.path =
                std::env::temp_dir().join("nostrfy-nip43-claim-test");
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
            let relay = Relay::new(
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
            let relay = Arc::new(relay);
            let member = signed_with_seed(9u8, 1, vec![]);
            {
                let mut roles = relay.roles.write().await;
                roles.create("member", "Member", "", "", None);
                roles.assign(&member.pubkey, "member");
            }
            let claim = signed_with_seed(9u8, crate::nips::nip43::JOIN, vec![]);
            let (outcome, _) = relay.accept_event(claim, &[], None).await;
            assert!(
                matches!(
                    &outcome,
                    crate::db::PutOutcome::Duplicate(msg) if msg == "duplicate: you are already a member of this relay"
                ),
                "a member's repeated claim must be OK true with the duplicate: prefix: {outcome:?}"
            );
            // A non-member's claim is refused (this relay issues no invites).
            let stranger = signed_with_seed(10u8, crate::nips::nip43::JOIN, vec![]);
            let (outcome, _) = relay.accept_event(stranger, &[], None).await;
            assert!(
                matches!(&outcome, crate::db::PutOutcome::Invalid(reason) if reason.contains("invite codes")),
                "a non-member claim is refused: {outcome:?}"
            );
            relay.db.shutdown();
        });
    }

    #[test]
    fn seal_events_must_not_carry_tags() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_validate_relay("nostrfy-seal-test").await;
            let cfg = relay.config.read().await;
            let now = unix_now();
            // NIP-59: "Tags MUST always be empty in a `kind:13`".
            let tagged = signed(13, vec![vec!["p".into(), "aa".repeat(32)]]);
            let err = relay
                .validate_base(&cfg, &tagged, now, &[], None)
                .unwrap_err();
            assert!(
                err.starts_with("invalid: kind 13 seals must not have tags"),
                "{err}"
            );
            let clean = signed(13, vec![]);
            assert!(relay.validate_base(&cfg, &clean, now, &[], None).is_ok());
            drop(cfg);
            relay.db.shutdown();
        });
    }

    async fn build_validate_relay(dir: &str) -> Arc<Relay> {
        let mut cfg = Config::default();
        cfg.database.map_size = 16 * 1024 * 1024;
        cfg.database.max_map_size = 256 * 1024 * 1024;
        cfg.database.path = std::env::temp_dir().join(dir);
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
        let relay = Relay::new(
            config,
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
        Arc::new(relay)
    }

    #[test]
    fn validate_base_remaining_rejections() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_validate_relay("nostrfy-validate-rest-test").await;
            let cfg = relay.config.read().await;
            let access = AccessControl::default();
            let now = unix_now();

            // Kind out of range.
            let out = relay
                .precheck(&cfg, &access, &signed(65_536, vec![]), now, &[], None, None)
                .await;
            assert!(matches!(out, super::Precheck::Reject(m) if m.contains("kind out of range")));
            // An empty tag array.
            let mut ev = signed(1, vec![]);
            ev.tags = vec![vec![]];
            let out = relay
                .precheck(&cfg, &access, &ev, now, &[], None, None)
                .await;
            assert!(matches!(out, super::Precheck::Reject(m) if m.contains("empty tag")));
            // Oversized content / tags / tag values.
            let mut cfg2 = (*cfg).clone();
            cfg2.limits.max_content_bytes = 10;
            cfg2.limits.max_tags = 3;
            cfg2.limits.max_tag_value_bytes = 100;
            let relay2 = {
                let db = relay.db.clone();
                let config = Arc::new(RwLock::new(cfg2));
                Arc::new(
                    super::super::Relay::new(
                        config,
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
                )
            };
            let cfg2r = relay2.config.read().await;
            let access2 = AccessControl::default();
            let big = signed(1, vec![]);
            let mut ev = big.clone();
            ev.content = "x".repeat(11);
            let out = relay2
                .precheck(&cfg2r, &access2, &ev, now, &[], None, None)
                .await;
            assert!(matches!(out, super::Precheck::Reject(m) if m.contains("content too large")));
            let mut ev = big.clone();
            ev.tags = vec![vec!["t".into(), "1".into()]; 4];
            let out = relay2
                .precheck(&cfg2r, &access2, &ev, now, &[], None, None)
                .await;
            assert!(matches!(out, super::Precheck::Reject(m) if m.contains("too many tags")));
            let mut ev = big.clone();
            ev.tags = vec![vec!["t".into(), "x".repeat(101)]];
            let out = relay2
                .precheck(&cfg2r, &access2, &ev, now, &[], None, None)
                .await;
            assert!(matches!(out, super::Precheck::Reject(m) if m.contains("tag value too large")));
            drop(cfg2r);

            // Secret key material in the content is dropped.
            let nsec = crate::nips::nip19::bech32_encode("nsec", &[1u8; 32]).unwrap();
            let mut ev = signed(1, vec![]);
            ev.content = format!("key: {nsec}");
            let out = relay
                .precheck(&cfg, &access, &ev, now, &[], None, None)
                .await;
            assert!(matches!(out, super::Precheck::Reject(m) if m.contains("secret key")));

            // A wrong signature is rejected.
            let mut ev = signed(1, vec![]);
            ev.sig = "00".repeat(64);
            let out = relay
                .precheck(&cfg, &access, &ev, now, &[], None, None)
                .await;
            assert!(matches!(out, super::Precheck::Reject(m) if m.contains("signature")));

            // A bad delegation is rejected when NIP-26 is enabled.
            let ev = signed(
                1,
                vec![vec![
                    "delegation".into(),
                    "zz".into(),
                    "kind=1".into(),
                    "sig".into(),
                ]],
            );
            let out = relay
                .precheck(&cfg, &access, &ev, now, &[], None, None)
                .await;
            assert!(matches!(out, super::Precheck::Reject(m) if m.contains("delegation")));

            // Uppercase pubkey: without a verified verdict the signature
            // fails first; with the verdict the pubkey check itself runs.
            let mut ev = signed(1, vec![]);
            ev.pubkey = ev.pubkey.to_ascii_uppercase();
            let out = relay
                .precheck(&cfg, &access, &ev, now, &[], None, None)
                .await;
            assert!(matches!(out, super::Precheck::Reject(m) if m.contains("signature")));
            let out = relay
                .precheck(&cfg, &access, &ev, now, &[], None, Some(true))
                .await;
            assert!(
                matches!(out, super::Precheck::Reject(m) if m.contains("pubkey must be lowercase"))
            );

            // A kind blocked by the access control.
            let mut access = AccessControl::default();
            access.blocked_kinds.push(7);
            let out = relay
                .precheck(&cfg, &access, &signed(7, vec![]), now, &[], None, None)
                .await;
            assert!(matches!(out, super::Precheck::Reject(m) if m.contains("kind not allowed")));

            drop(cfg);
            relay.db.shutdown();
            relay2.db.shutdown();
        });
    }

    #[test]
    fn validate_base_group_nip43_pow_and_auth_gates() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_validate_relay("nostrfy-validate-gates-test").await;
            let cfg = relay.config.read().await;
            let access = AccessControl::default();
            let now = unix_now();
            let secp = Secp256k1::new();
            let h = |kind: u64, tags: Vec<Vec<String>>| {
                let keypair = Keypair::from_seckey_slice(&secp, &[5u8; 32]).unwrap();
                let pubkey = XOnlyPublicKey::from_keypair(&keypair).0.to_string();
                let mut e = Event {
                    id: String::new(),
                    pubkey,
                    created_at: now,
                    kind,
                    tags,
                    content: String::new(),
                    sig: String::new(),
                };
                e.id = crate::nips::nip01::compute_id(&e);
                let id = e.id_bytes().unwrap();
                e.sig = secp.sign_schnorr_no_aux_rand(&id, &keypair).to_string();
                e
            };
            let gh = |kind: u64, tags: Vec<Vec<String>>| {
                let mut tags = tags;
                tags.insert(0, vec!["h".to_string(), "g".into()]);
                h(kind, tags)
            };

            // A group action without an h tag is rejected.
            let join = h(
                crate::nips::nip29::JOIN,
                vec![vec!["code".into(), "x".into()]],
            );
            let out = relay
                .precheck(&cfg, &access, &join, now, &[], None, None)
                .await;
            assert!(matches!(out, super::Precheck::Reject(m) if m.contains("h tag")));

            // Group metadata not signed by the relay is rejected.
            let meta = gh(39000, vec![vec!["d".into(), "g".into()]]);
            let out = relay
                .precheck(&cfg, &access, &meta, now, &[], None, None)
                .await;
            assert!(matches!(out, super::Precheck::Reject(m) if m.contains("relay")));

            // NIP-43 metadata by a non-relay pubkey is rejected.
            let role_def = h(crate::nips::nip43::ROLE_DEFINITION, vec![]);
            let out = relay
                .precheck(&cfg, &access, &role_def, now, &[], None, None)
                .await;
            assert!(matches!(out, super::Precheck::Reject(m) if m.contains("relay")));

            // A NIP-43 leave request that is too old is rejected.
            let secp2 = Secp256k1::new();
            let mut leave = h(crate::nips::nip43::LEAVE, vec![vec!["-".into()]]);
            leave.created_at = now - 1000;
            leave.id = crate::nips::nip01::compute_id(&leave);
            let kp = Keypair::from_seckey_slice(&secp2, &[5u8; 32]).unwrap();
            let id = leave.id_bytes().unwrap();
            leave.sig = secp2.sign_schnorr_no_aux_rand(&id, &kp).to_string();
            let out = relay
                .precheck(&cfg, &access, &leave, now, &[], None, None)
                .await;
            assert!(matches!(out, super::Precheck::Reject(m) if m.contains("too old")));

            // A repost embedding a protected event is rejected.
            let protected = Event {
                id: String::new(),
                pubkey: "aa".repeat(32),
                created_at: now,
                kind: 1,
                tags: vec![vec!["-".into()]],
                content: "secret".into(),
                sig: String::new(),
            };
            let mut repost = h(6, vec![]);
            repost.content = serde_json::to_string(&protected).unwrap();
            repost.id = crate::nips::nip01::compute_id(&repost);
            let kp = Keypair::from_seckey_slice(&secp, &[5u8; 32]).unwrap();
            let id = repost.id_bytes().unwrap();
            repost.sig = secp.sign_schnorr_no_aux_rand(&id, &kp).to_string();
            let out = relay
                .precheck(&cfg, &access, &repost, now, &[], None, None)
                .await;
            assert!(matches!(out, super::Precheck::Reject(m) if m.contains("repost")));

            // require_auth without authentication.
            let mut cfg2 = (*cfg).clone();
            cfg2.relay.require_auth = true;
            let relay2 = {
                let db = relay.db.clone();
                let config = Arc::new(RwLock::new(cfg2));
                Arc::new(
                    super::super::Relay::new(
                        config,
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
                )
            };
            let cfg2r = relay2.config.read().await;
            let access2 = AccessControl::default();
            let out = relay2
                .precheck(&cfg2r, &access2, &signed(1, vec![]), now, &[], None, None)
                .await;
            assert!(matches!(out, super::Precheck::Reject(m) if m.contains("auth-required")));
            // NIP-78 AUTH-gated kind 78 without authentication.
            let mut ev = signed(1, vec![]);
            ev.kind = 78;
            ev.id = crate::nips::nip01::compute_id(&ev);
            let kp = Keypair::from_seckey_slice(&secp, &[3u8; 32]).unwrap();
            let id = ev.id_bytes().unwrap();
            ev.sig = secp.sign_schnorr_no_aux_rand(&id, &kp).to_string();
            let out = relay2
                .precheck(&cfg2r, &access2, &ev, now, &[], None, None)
                .await;
            assert!(matches!(out, super::Precheck::Reject(m) if m.contains("auth-required")));
            drop(cfg2r);

            // A PoW requirement rejects under-difficulty events.
            let mut cfg3 = (*cfg).clone();
            cfg3.relay.require_pow = 25;
            let relay3 = {
                let db = relay.db.clone();
                let config = Arc::new(RwLock::new(cfg3));
                Arc::new(
                    super::super::Relay::new(
                        config,
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
                )
            };
            let cfg3r = relay3.config.read().await;
            let out = relay3
                .precheck(&cfg3r, &access, &signed(1, vec![]), now, &[], None, None)
                .await;
            assert!(matches!(out, super::Precheck::Reject(m) if m.contains("pow")));
            drop(cfg3r);

            // The parallel signature verification path (16+ events).
            let mut events = Vec::new();
            for seed in 1..=20u8 {
                events.push(signed_with_seed(seed, 1, vec![]));
            }
            let verdicts =
                crate::relay::validate::verify_signatures_parallel(&events, relay.secp());
            assert_eq!(verdicts.len(), 20);
            assert!(verdicts.iter().all(|v| *v));
            let mut bad = events.clone();
            bad[3].sig = "00".repeat(64);
            let verdicts = crate::relay::validate::verify_signatures_parallel(&bad, relay.secp());
            assert!(!verdicts[3]);
            assert!(verdicts[0]);

            drop(cfg);
            relay.db.shutdown();
            relay2.db.shutdown();
            relay3.db.shutdown();
        });
    }

    #[test]
    fn validate_base_group_previous_and_late_publish() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_validate_relay("nostrfy-validate-previous-test").await;
            let cfg = relay.config.read().await;
            let access = AccessControl::default();
            let now = unix_now();
            let secp = Secp256k1::new();
            let h = |kind: u64, tags: Vec<Vec<String>>| {
                let keypair = Keypair::from_seckey_slice(&secp, &[6u8; 32]).unwrap();
                let pubkey = XOnlyPublicKey::from_keypair(&keypair).0.to_string();
                let mut e = Event {
                    id: String::new(),
                    pubkey,
                    created_at: now,
                    kind,
                    tags,
                    content: String::new(),
                    sig: String::new(),
                };
                e.id = crate::nips::nip01::compute_id(&e);
                let id = e.id_bytes().unwrap();
                e.sig = secp.sign_schnorr_no_aux_rand(&id, &keypair).to_string();
                e
            };
            let gh = |kind: u64, tags: Vec<Vec<String>>| {
                let mut tags = tags;
                tags.insert(0, vec!["h".to_string(), "g".into()]);
                h(kind, tags)
            };
            // Create the group so a post to it reaches the previous-tag
            // validation.
            {
                let mut groups = relay.groups.write().await;
                let create = gh(crate::nips::nip29::CREATE_GROUP, vec![]);
                groups.apply(&create, "relay", now, false, false);
            }
            // A malformed previous tag is rejected.
            let ev = gh(1, vec![vec!["previous".into(), "zz".into()]]);
            let out = relay
                .precheck(&cfg, &access, &ev, now, &[], None, None)
                .await;
            assert!(matches!(out, super::Precheck::Reject(m) if m.contains("malformed previous")));
            // An unknown previous reference is rejected.
            let ev = gh(1, vec![vec!["previous".into(), "aa".repeat(32)]]);
            let out = relay
                .precheck(&cfg, &access, &ev, now, &[], None, None)
                .await;
            assert!(matches!(out, super::Precheck::Reject(m) if m.contains("unknown previous")));
            // A known prefix (via the known-prefixes set) passes.
            let ev = gh(1, vec![vec!["previous".into(), "ab".repeat(32)]]);
            let known = std::collections::HashSet::from([hex::decode("ab".repeat(32)).unwrap()]);
            let out = relay
                .precheck(&cfg, &access, &ev, now, &[], Some(&known), None)
                .await;
            assert!(matches!(out, super::Precheck::Accept));

            // The late-publish guard rejects old group events.
            let mut cfg2 = (*cfg).clone();
            cfg2.limits.group_late_publish_secs = 60;
            let relay2 = {
                let db = relay.db.clone();
                let config = Arc::new(RwLock::new(cfg2));
                Arc::new(
                    super::super::Relay::new(
                        config,
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
                )
            };
            {
                let mut groups = relay2.groups.write().await;
                let create = gh(crate::nips::nip29::CREATE_GROUP, vec![]);
                groups.apply(&create, "relay", now, false, false);
            }
            let cfg2r = relay2.config.read().await;
            let access2 = AccessControl::default();
            let mut old = gh(1, vec![]);
            old.created_at = now - 100;
            old.id = crate::nips::nip01::compute_id(&old);
            let kp = Keypair::from_seckey_slice(&secp, &[6u8; 32]).unwrap();
            let id = old.id_bytes().unwrap();
            old.sig = secp.sign_schnorr_no_aux_rand(&id, &kp).to_string();
            let out = relay2
                .precheck(&cfg2r, &access2, &old, now, &[], None, None)
                .await;
            assert!(matches!(out, super::Precheck::Reject(m) if m.contains("too old")));
            drop(cfg2r);
            relay2.db.shutdown();
            relay.db.shutdown();
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
            cfg.database.path = std::env::temp_dir().join("nostrfy-ephemeral-validate-base");
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
            cfg.database.path = std::env::temp_dir().join("nostrfy-vanish-blocked-test");
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
