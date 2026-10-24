//! Buzz direct messages: kind:41010 open and kind:41012 hide.
//!
//! Buzz does not use a separate DM wire format: a DM is a NIP-29 group with
//! `channel_type=dm`, `private` and `hidden` set, whose id is derived from
//! the sorted participant pubkeys. The relay answers the open command in the
//! OK message (`response:{"channel_id":"..."}`), then publishes the normal
//! group metadata and membership notices. Kind:30622 (NIP-DV) carries the
//! viewer's hidden-DM set so a client can filter its sidebar.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use crate::db::PutOutcome;
use crate::event::Event;
use crate::nips::nip29;
use crate::util::unix_now;

/// Maximum participants in one DM channel (sender included).
const MAX_DM_PARTICIPANTS: usize = 64;

/// Deterministic UUID-shaped channel id for a participant set.
///
/// The relay secret is mixed in so an outsider who knows two pubkeys cannot
/// pre-create a group with the derived id and block their DM.
fn derive_channel_id(participants: &BTreeSet<String>, secret: Option<&[u8]>) -> String {
    let mut hasher = Sha256::new();
    if let Some(secret) = secret {
        hasher.update(secret);
        hasher.update(b"\n");
    }
    for pubkey in participants {
        hasher.update(pubkey.as_bytes());
        hasher.update(b"\n");
    }
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    // RFC 4122 version 5 (name-based, SHA-1 in the spec; the version nibble
    // is what clients use to recognise a UUID) and the RFC variant bits.
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-\
         {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

fn is_pubkey(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn synthetic(pubkey: &str, kind: u64, tags: Vec<Vec<String>>, content: &str, now: u64) -> Event {
    Event {
        id: String::new(),
        pubkey: pubkey.to_string(),
        created_at: now,
        kind,
        tags,
        content: content.to_string(),
        sig: String::new(),
    }
}

impl super::Relay {
    /// Handles kind:41010 (open or surface a DM).
    pub(crate) async fn handle_dm_open(&self, event: &Event, authed: &[String]) -> PutOutcome {
        let cfg = self.config.read().await.clone();
        if !cfg.relay.enabled_buzz {
            return PutOutcome::Invalid("blocked: Buzz support is disabled".into());
        }
        if !cfg.nip_enabled(29) {
            return PutOutcome::Invalid("blocked: NIP-29 is disabled".into());
        }
        if self.relay_pubkey_ref().is_none() {
            return PutOutcome::Invalid("error: the relay has no signing key".into());
        }
        if cfg.relay.require_auth && !authed.iter().any(|pk| pk == &event.pubkey) {
            return PutOutcome::Invalid("auth-required: authenticate before opening a DM".into());
        }
        if !self.access.read().await.allows_pubkey(&event.pubkey) {
            return PutOutcome::Invalid("restricted: this pubkey may not publish".into());
        }
        let mut participants: BTreeSet<String> = BTreeSet::new();
        participants.insert(event.pubkey.to_ascii_lowercase());
        for tag in event.tags.iter().filter(|t| t.len() >= 2 && t[0] == "p") {
            if !is_pubkey(&tag[1]) {
                return PutOutcome::Invalid(
                    "invalid: DM participant must be a 64-hex pubkey".into(),
                );
            }
            participants.insert(tag[1].to_ascii_lowercase());
        }
        if participants.len() < 2 {
            return PutOutcome::Invalid(
                "invalid: a DM needs at least one other participant".into(),
            );
        }
        if participants.len() > MAX_DM_PARTICIPANTS {
            return PutOutcome::Invalid("invalid: too many DM participants".into());
        }
        let secret = self
            .key
            .as_ref()
            .map(|key| key.secret_key().to_secret_bytes());
        let channel =
            derive_channel_id(&participants, secret.as_ref().map(|bytes| bytes.as_slice()));
        let now = unix_now();
        if !self.publish_rate_allowed(&cfg, &event.pubkey, now) {
            return PutOutcome::Invalid("rate-limited: too many events".into());
        }

        let metadata = {
            let mut groups = self.groups.write().await;
            let existing = groups.groups.get(&channel).cloned();
            if let Some(mut group) = existing {
                if group.channel_type != "dm" {
                    return PutOutcome::Invalid("invalid: that channel is not a DM".into());
                }
                // Opening an existing DM re-surfaces it from the viewer's
                // hidden set. A DM's metadata and writes stay member-only.
                group.settings.private = true;
                group.settings.restricted = true;
                group.settings.closed = true;
                group.settings.hidden = true;
                group.hidden_for.remove(&event.pubkey);
                let meta = nip29::events::build_meta_event(
                    &channel,
                    Some(&group),
                    self.relay_pubkey_ref().unwrap_or_default(),
                    now,
                );
                groups.groups.insert(channel.clone(), group);
                vec![meta]
            } else {
                let create = synthetic(
                    &event.pubkey,
                    nip29::CREATE_GROUP,
                    vec![
                        vec!["h".into(), channel.clone()],
                        vec!["name".into(), "Direct message".into()],
                        vec!["visibility".into(), "private".into()],
                        vec!["channel_type".into(), "dm".into()],
                        vec!["hidden".into()],
                        vec!["restricted".into()],
                    ],
                    "",
                    now,
                );
                let relay_pubkey = self.relay_pubkey_ref().unwrap_or_default();
                let mut emitted = groups.apply(&create, relay_pubkey, now, true, false);
                // Add every other participant as a plain member. The
                // creator stays the admin; participants must not be able to
                // remove each other through the DM.
                let mut put = synthetic(
                    &event.pubkey,
                    nip29::PUT_USER,
                    vec![vec!["h".into(), channel.clone()]],
                    "",
                    now.saturating_add(1),
                );
                for participant in &participants {
                    if participant != &event.pubkey {
                        put.tags.push(vec!["p".into(), participant.clone()]);
                    }
                }
                emitted.extend(groups.apply(
                    &put,
                    relay_pubkey,
                    now.saturating_add(1),
                    true,
                    false,
                ));
                emitted
            }
        };
        // The group apply can drop participants at the member caps; never
        // acknowledge a DM that only some participants can read.
        {
            let groups = self.groups.read().await;
            let complete = groups
                .groups
                .get(&channel)
                .is_some_and(|group| participants.iter().all(|pk| group.is_member(pk)));
            if !complete {
                drop(groups);
                // Roll back the in-memory create: no metadata was stored, so
                // leaving the partial group would expose a half-initialized
                // channel to later reads.
                self.groups.write().await.groups.remove(&channel);
                self.publish_rate_rollback(&event.pubkey, now);
                return PutOutcome::Invalid("error: could not create the DM channel".into());
            }
        }
        for mut relay_event in metadata {
            if self.store_relay_event(&mut relay_event).await.is_err() {
                self.publish_rate_rollback(&event.pubkey, now);
                return PutOutcome::Invalid(
                    "error: could not publish the DM metadata; retry".into(),
                );
            }
        }
        // The create itself publishes a 44100 for the creator and a 40099
        // channel_created through the normal group path; the additional
        // participants get their notices from the synthetic 9000.
        if let Err(()) = self.publish_dm_visibility(&event.pubkey).await {
            log::warn!("could not publish the DM visibility snapshot");
        }
        PutOutcome::Duplicate(format!(
            "response:{}",
            serde_json::json!({ "channel_id": channel })
        ))
    }

    /// Handles kind:41012 (hide a DM from the viewer's sidebar).
    pub(crate) async fn handle_dm_hide(&self, event: &Event, authed: &[String]) -> PutOutcome {
        let cfg = self.config.read().await.clone();
        if !cfg.relay.enabled_buzz {
            return PutOutcome::Invalid("blocked: Buzz support is disabled".into());
        }
        if !cfg.nip_enabled(29) {
            return PutOutcome::Invalid("blocked: NIP-29 is disabled".into());
        }
        if cfg.relay.require_auth && !authed.iter().any(|pk| pk == &event.pubkey) {
            return PutOutcome::Invalid("auth-required: authenticate before hiding a DM".into());
        }
        if self.relay_pubkey_ref().is_none() {
            return PutOutcome::Invalid("error: the relay has no signing key".into());
        }
        if !self.access.read().await.allows_pubkey(&event.pubkey) {
            return PutOutcome::Invalid("restricted: this pubkey may not publish".into());
        }
        let now = unix_now();
        if !self.publish_rate_allowed(&cfg, &event.pubkey, now) {
            return PutOutcome::Invalid("rate-limited: too many events".into());
        }
        let Some(channel) = event
            .tags
            .iter()
            .find(|t| t.len() >= 2 && t[0] == "h")
            .map(|t| t[1].clone())
        else {
            return PutOutcome::Invalid("invalid: dm hide requires an h tag".into());
        };
        {
            let mut groups = self.groups.write().await;
            let Some(group) = groups.groups.get_mut(&channel) else {
                return PutOutcome::Invalid("invalid: unknown DM channel".into());
            };
            if group.channel_type != "dm" || !group.is_member(&event.pubkey) {
                return PutOutcome::Invalid("restricted: not a member of this DM".into());
            }
            group.hidden_for.insert(event.pubkey.clone());
        }
        if let Err(()) = self.publish_dm_visibility(&event.pubkey).await {
            log::warn!("could not publish the DM visibility snapshot");
        }
        PutOutcome::Duplicate(String::new())
    }

    /// Publishes the NIP-DV kind:30622 snapshot for one viewer.
    pub(crate) async fn publish_dm_visibility(&self, viewer: &str) -> Result<(), ()> {
        let Some(relay_pubkey) = self.relay_pubkey() else {
            return Err(());
        };
        let hidden: Vec<String> = {
            let groups = self.groups.read().await;
            let mut hidden: Vec<String> = groups
                .groups
                .iter()
                .filter(|(_, group)| {
                    group.channel_type == "dm"
                        && group.hidden_for.contains(viewer)
                        && group.is_member(viewer)
                })
                .map(|(id, _)| id.clone())
                .collect();
            hidden.sort();
            hidden
        };
        let now = self.stamp_floor(unix_now());
        let mut event = Event {
            id: String::new(),
            pubkey: relay_pubkey,
            created_at: now,
            kind: 30622,
            tags: vec![
                vec!["d".into(), viewer.to_string()],
                vec!["p".into(), viewer.to_string()],
            ],
            content: String::new(),
            sig: String::new(),
        };
        for channel in hidden {
            event.tags.push(vec!["h".into(), channel]);
        }
        self.store_relay_event(&mut event).await.map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_id_is_deterministic_and_uuid_shaped() {
        let mut a = BTreeSet::new();
        a.insert("aa".repeat(32));
        a.insert("bb".repeat(32));
        let id = derive_channel_id(&a, None);
        assert_eq!(id.len(), 36);
        assert_eq!(&id[8..9], "-");
        assert_eq!(&id[13..14], "-");
        assert_eq!(&id[18..19], "-");
        assert_eq!(&id[23..24], "-");
        assert_eq!(id, derive_channel_id(&a, None));
        let mut b = BTreeSet::new();
        b.insert("bb".repeat(32));
        b.insert("aa".repeat(32));
        assert_eq!(id, derive_channel_id(&b, None));
        b.insert("cc".repeat(32));
        assert_ne!(id, derive_channel_id(&b, None));
        assert_ne!(id, derive_channel_id(&a, Some(b"relay-secret")));
    }
}
