//! Command events: with `relay.enabled_command_events = true`, kind:1
//! events authored by the admin pubkey (`relay.pubkey`) are executed as
//! operator commands without the CLI. The content is a slash-prefixed
//! command; the pubkey operand accepts `npub1...`, `nostr:npub1...` or
//! 64-hex:
//!
//! - `/relay allow <npub1...|nostr:npub1...|64-hex>` — add a pubkey to the relay allow list
//! - `/relay add <npub1...|nostr:npub1...|64-hex>` — alias of `/relay allow`
//! - `/relay deny <npub1...|nostr:npub1...|64-hex>` — add a pubkey to the relay deny list
//! - `/blossom allow <npub1...|nostr:npub1...|64-hex>` — add a pubkey to the Blossom upload allowlist
//! - `/blossom deny <npub1...|nostr:npub1...|64-hex>` — remove a pubkey from the Blossom upload allowlist
//!
//! The relay answers every recognized command with a kind:1111 event
//! signed with `relay.private_key` (tagged `e` to the command event and
//! `p` to the admin pubkey; served publicly, so the result is visible
//! even without NIP-42). Only the admin (`relay.pubkey`) can issue
//! commands: the author check runs on the event's verified signature.

use anyhow::anyhow;

use crate::config;
use crate::event::Event;
use crate::nips::nip19::{self, Nip19Entity};
use crate::util::unix_now;

use super::Relay;

/// The kind the relay uses to answer command events.
pub(crate) const RESPONSE_KIND: u64 = 1111;

/// A parsed operator command carried by a command event's content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Command {
    RelayAllow(String),
    RelayDeny(String),
    BlossomAllow(String),
    BlossomDeny(String),
}

impl Command {
    /// Canonical verb used in the reply text.
    fn verb(&self) -> &'static str {
        match self {
            Command::RelayAllow(_) => "/relay allow",
            Command::RelayDeny(_) => "/relay deny",
            Command::BlossomAllow(_) => "/blossom allow",
            Command::BlossomDeny(_) => "/blossom deny",
        }
    }

    /// The pubkey operand.
    fn pubkey(&self) -> &str {
        match self {
            Command::RelayAllow(pk)
            | Command::RelayDeny(pk)
            | Command::BlossomAllow(pk)
            | Command::BlossomDeny(pk) => pk,
        }
    }
}

/// Parses a command event's content:
///
/// - `None` — not a command (the event is stored like any other note);
/// - `Some(Err(msg))` — command-shaped content that could not be executed
///   (unknown verb, invalid pubkey): the relay answers with an error;
/// - `Some(Ok(cmd))` — a recognized command to execute.
pub(crate) fn parse(content: &str) -> Option<anyhow::Result<Command>> {
    let parts: Vec<&str> = content.split_whitespace().collect();
    let (list, action, raw) = match parts.as_slice() {
        ["/relay", "allow" | "add", pk] => ("relay", "allow", *pk),
        ["/relay", "deny", pk] => ("relay", "deny", *pk),
        ["/blossom", "allow", pk] => ("blossom", "allow", *pk),
        ["/blossom", "deny", pk] => ("blossom", "deny", *pk),
        ["/relay", _, _] | ["/blossom", _, _] => {
            return Some(Err(anyhow!("error: unknown command: {content}")));
        }
        _ => return None,
    };
    // Clients may prefix the pubkey with the `nostr:` URI scheme.
    let raw = raw.strip_prefix("nostr:").unwrap_or(raw);
    let pk = match normalize_pubkey(raw) {
        Some(pk) => pk,
        None => {
            return Some(Err(anyhow!("error: invalid pubkey: {raw}")));
        }
    };
    Some(Ok(match (list, action) {
        ("relay", "allow") => Command::RelayAllow(pk),
        ("relay", "deny") => Command::RelayDeny(pk),
        ("blossom", "allow") => Command::BlossomAllow(pk),
        ("blossom", "deny") => Command::BlossomDeny(pk),
        _ => unreachable!(),
    }))
}

/// A 64-hex pubkey or an `npub1...` string normalized to lowercase hex.
fn normalize_pubkey(value: &str) -> Option<String> {
    if !config::is_pubkey_or_npub(value) {
        return None;
    }
    if value.len() == 64 {
        return Some(value.to_ascii_lowercase());
    }
    match nip19::parse_nip19(value) {
        Ok(Nip19Entity::Pubkey(pk)) => Some(hex::encode(pk)),
        _ => None,
    }
}

/// The kind:1111 reply text for a relay allow/deny command. A failed
/// persistence is reported as an error instead of `ok:`: the change is
/// applied in memory, but reporting success would hide that it silently
/// disappears on the next restart.
fn access_reply(cmd: &Command, already: bool, persisted: bool) -> String {
    let noun = match cmd {
        Command::RelayAllow(_) => "allowed",
        Command::RelayDeny(_) => "denied",
        _ => unreachable!("access_reply is only used for /relay allow|deny"),
    };
    if already {
        format!("ok: {} is already {noun}", cmd.verb())
    } else if persisted {
        format!("ok: {} {}", cmd.verb(), cmd.pubkey())
    } else {
        format!(
            "error: {} {} was applied in memory but could not be persisted; it will be \
             lost on restart",
            cmd.verb(),
            cmd.pubkey()
        )
    }
}

/// The kind:1111 reply text for a `/blossom allow|deny` command. Same
/// contract as [`access_reply`]: only an applied change that failed to
/// persist is reported as an error (a no-op change has nothing to lose).
fn blossom_reply(cmd: &Command, changed: bool, persisted: bool) -> String {
    if !changed {
        return match cmd {
            Command::BlossomAllow(_) => format!("ok: {} is already allowed", cmd.verb()),
            Command::BlossomDeny(_) => format!("ok: {} is not on the allowlist", cmd.verb()),
            _ => unreachable!("blossom_reply is only used for /blossom allow|deny"),
        };
    }
    if persisted {
        format!("ok: {} {}", cmd.verb(), cmd.pubkey())
    } else {
        format!(
            "error: {} {} was applied in memory but could not be persisted; it will \
             be lost on restart",
            cmd.verb(),
            cmd.pubkey()
        )
    }
}

/// Applies a `/blossom allow` on top of the persisted allowlist: the
/// persisted list (re-read under the cross-process lock, `None` when that
/// read failed) is unioned with the daemon's in-memory list — a daemon-side
/// entry whose earlier persist failed must not be dropped by this write —
/// and the pubkey is appended when absent. Returns the list to write and
/// whether the command changed it.
fn merge_blossom_allow(
    persisted: Option<&[String]>,
    in_memory: &[String],
    pk: &str,
) -> (Vec<String>, bool) {
    let mut entries: Vec<String> = Vec::new();
    for entry in persisted.into_iter().flatten().chain(in_memory) {
        if !entries.contains(entry) {
            entries.push(entry.clone());
        }
    }
    let changed = !entries.iter().any(|e| e == pk);
    if changed {
        entries.push(pk.to_string());
    }
    (entries, changed)
}

/// Applies a `/blossom deny` on top of the persisted allowlist: the
/// persisted list (re-read under the cross-process lock; the in-memory list
/// is the fallback when that read failed) minus the pubkey. Unlike allow
/// there is no union with the in-memory list: an entry a CLI `blossom deny`
/// removed must stay removed. Returns the list to write and whether the
/// command changed it.
fn merge_blossom_deny(
    persisted: Option<&[String]>,
    in_memory: &[String],
    pk: &str,
) -> (Vec<String>, bool) {
    let changed = persisted.is_some_and(|list| list.iter().any(|e| e == pk))
        || in_memory.iter().any(|e| e == pk);
    let mut entries = match persisted {
        Some(list) => list.to_vec(),
        None => in_memory.to_vec(),
    };
    entries.retain(|e| e != pk);
    (entries, changed)
}

impl Relay {
    /// Runs the command-event side effect for a stored kind:1 event:
    /// recognizes the admin pubkey (`relay.pubkey`) and
    /// `relay.enabled_command_events`, parses the content and executes
    /// the command, then answers with a kind:1111 event carrying the
    /// result (signed with `relay.private_key`). Non-command events are
    /// ignored.
    pub(crate) async fn handle_command_event(&self, event: &Event) {
        let cfg = self.config.read().await;
        let enabled = cfg.relay.enabled_command_events;
        let admin = cfg.relay.pubkey.clone();
        drop(cfg);
        if !enabled {
            return;
        }
        if admin.is_empty() {
            return;
        }
        // The reply needs a key to be signed with.
        if self.relay_pubkey_ref().is_none() {
            return;
        }
        // Only the admin (`relay.pubkey`) can issue commands: the author
        // check runs on the event's verified signature. The comparison is
        // ASCII case-insensitive: an uppercase spelling of the same pubkey
        // must not silently disable the command interface.
        if !admin.eq_ignore_ascii_case(&event.pubkey) {
            return;
        }
        {
            let mut processed = self
                .command_events
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !processed.insert(event.id.clone()) {
                return;
            }
            if processed.len() > 4096 {
                processed.clear();
                processed.insert(event.id.clone());
            }
        }
        let Some(outcome) = parse(&event.content) else {
            return;
        };
        let text = match outcome {
            Ok(cmd) => self.execute_command(&cmd).await,
            Err(e) => e.to_string(),
        };
        self.reply_to_command(event, text).await;
    }

    /// Executes a parsed command and returns the result text for the
    /// kind:1111 reply. The access and allowlist mutations are persisted
    /// immediately, so they survive a restart (like the CLI commands); a
    /// failed persistence is reported as an error rather than `ok:`.
    pub(crate) async fn execute_command(&self, cmd: &Command) -> String {
        match cmd {
            Command::RelayAllow(pk) => {
                let mut access = self.access.write().await;
                let already = access.allowed_pubkeys.iter().any(|(p, _)| p == pk);
                if !already {
                    access.blocked_pubkeys.retain(|(p, _)| p != pk);
                    access.allowed_pubkeys.push((pk.clone(), String::new()));
                }
                drop(access);
                let persisted = self.persist_access().await;
                access_reply(cmd, already, persisted)
            }
            Command::RelayDeny(pk) => {
                let mut access = self.access.write().await;
                let already = access.blocked_pubkeys.iter().any(|(p, _)| p == pk);
                if !already {
                    access.allowed_pubkeys.retain(|(p, _)| p != pk);
                    access.blocked_pubkeys.push((pk.clone(), String::new()));
                }
                drop(access);
                let persisted = self.persist_access().await;
                access_reply(cmd, already, persisted)
            }
            Command::BlossomAllow(pk) => {
                // Capture and write are serialized (like `persist_roles`):
                // two concurrent commands could otherwise snapshot the list
                // in one order and queue their writes in the other, losing
                // the newer entry on the next restart. The in-process lock
                // only serializes daemon commands: the cross-process lock is
                // taken *before* the persisted list is re-read, so a
                // concurrent CLI read-modify-write cannot land between the
                // read and the write and be overwritten by the daemon's
                // older snapshot.
                let _guard = self.persist_blossom_allow_lock.lock().await;
                // Without the cross-process lock a concurrent CLI
                // read-modify-write could land between the re-read below
                // and the write and be overwritten by this older snapshot:
                // refuse the command instead of writing unserialized.
                let Some(_state_lock) = self.db.lock_access_state().await else {
                    return format!(
                        "error: {} {} could not be applied: the access state lock is unavailable",
                        cmd.verb(),
                        cmd.pubkey()
                    );
                };
                let persisted = self.db.try_load_blossom_allow().await;
                let mut allow = self.blossom_allow.write().await;
                let (entries, changed) = merge_blossom_allow(persisted.as_deref(), &allow, pk);
                // The written list is the new in-memory truth: it carries
                // the CLI entries the daemon had not observed yet.
                *allow = entries.clone();
                drop(allow);
                // The cross-process lock is already held: taking it again
                // from this process would block on itself.
                let saved = self.db.save_blossom_allow_locked(&entries).await;
                blossom_reply(cmd, changed, saved)
            }
            Command::BlossomDeny(pk) => {
                let _guard = self.persist_blossom_allow_lock.lock().await;
                // Same cross-process ordering as `/blossom allow` above:
                // refuse instead of writing unserialized.
                let Some(_state_lock) = self.db.lock_access_state().await else {
                    return format!(
                        "error: {} {} could not be applied: the access state lock is unavailable",
                        cmd.verb(),
                        cmd.pubkey()
                    );
                };
                let persisted = self.db.try_load_blossom_allow().await;
                let mut allow = self.blossom_allow.write().await;
                let (entries, changed) = merge_blossom_deny(persisted.as_deref(), &allow, pk);
                *allow = entries.clone();
                drop(allow);
                let saved = self.db.save_blossom_allow_locked(&entries).await;
                blossom_reply(cmd, changed, saved)
            }
        }
    }

    /// Signs (with `relay.private_key`), stores and broadcasts the kind:1111
    /// reply to a command event. The reply carries `e` = the command's id
    /// and `p` = the admin pubkey (`relay.pubkey`), so clients show it as
    /// addressed to the admin; it is served publicly, so the result stays
    /// visible even when NIP-42 is enabled.
    pub(crate) async fn reply_to_command(&self, command: &Event, text: String) {
        let Some(pubkey) = self.relay_pubkey() else {
            return;
        };
        let admin = self.config.read().await.relay.pubkey.clone();
        let stamp = self.stamp_floor(unix_now());
        let mut event = Event {
            id: String::new(),
            pubkey,
            created_at: stamp,
            kind: RESPONSE_KIND,
            tags: vec![vec!["e".into(), command.id.clone()]],
            content: text,
            sig: String::new(),
        };
        if !admin.is_empty() {
            event
                .tags
                .push(vec!["p".into(), admin.to_ascii_lowercase()]);
        }
        match self.store_relay_event(&mut event).await {
            Ok(true) => {}
            Ok(false) => {
                log::warn!(
                    "stored command response for {} but live delivery failed",
                    command.id
                );
            }
            Err(()) => {
                log::error!("could not store command response for {}", command.id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_command_forms() {
        // `anyhow::Error` is not `PartialEq`, so compare the parsed
        // command after unwrapping the anyhow result.
        fn parsed(content: &str) -> Option<Command> {
            parse(content).and_then(|r| r.ok())
        }
        let hex = "aa".repeat(32);
        let upper = "AA".repeat(32);
        assert_eq!(
            parsed(&format!("/relay allow {hex}")),
            Some(Command::RelayAllow(hex.clone()))
        );
        assert_eq!(
            parsed(&format!("/relay add {hex}")),
            Some(Command::RelayAllow(hex.clone()))
        );
        assert_eq!(
            parsed(&format!("/relay deny {hex}")),
            Some(Command::RelayDeny(hex.clone()))
        );
        // 64-hex input is normalized to lowercase.
        assert_eq!(
            parsed(&format!("/blossom allow {upper}")),
            Some(Command::BlossomAllow(hex))
        );
        // A real npub1 decodes to its hex pubkey.
        let npub = "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkws3w8ktc";
        let npub_hex = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
        assert_eq!(
            parsed(&format!("/blossom deny {npub}")),
            Some(Command::BlossomDeny(npub_hex.into()))
        );
        // The `nostr:` URI prefix is stripped before validation.
        assert_eq!(
            parsed(&format!("/relay allow nostr:{npub}")),
            Some(Command::RelayAllow(npub_hex.into()))
        );
        assert_eq!(
            parsed(&format!("/blossom deny nostr:{npub}")),
            Some(Command::BlossomDeny(npub_hex.into()))
        );
    }

    #[test]
    fn rejects_malformed_commands() {
        for bad in [
            "relay allow",
            "relay",
            "blossom",
            "blossom allow",
            "relay allow aabb extra",
            "relay allow aa",
            "/relay",
            "/relay allow",
            "/blossom",
            "/blossom allow",
            "/relay allow aabb extra",
            "hello world",
            "",
        ] {
            assert!(parse(bad).is_none(), "must ignore {bad:?}");
        }
        for bad in [
            "/relay allow npub1invalid",
            "/relay allow 1234",
            "/relay deny xyz",
            "/blossom allow not-a-pubkey",
            "/relay spam aa",
            "/relay allow nostr:notapubkey",
            " /relay allow aa",
            "/relay\nallow aa",
        ] {
            assert!(
                matches!(parse(bad), Some(Err(_))),
                "must report an error for {bad:?}"
            );
        }
    }

    #[test]
    fn access_reply_reports_persistence_failure() {
        let hex = "aa".repeat(32);
        assert_eq!(
            access_reply(&Command::RelayAllow(hex.clone()), false, true),
            format!("ok: /relay allow {hex}")
        );
        assert_eq!(
            access_reply(&Command::RelayAllow(hex.clone()), true, true),
            "ok: /relay allow is already allowed"
        );
        assert_eq!(
            access_reply(&Command::RelayDeny(hex.clone()), true, true),
            "ok: /relay deny is already denied"
        );
        // A failed persist must not be reported as success.
        let text = access_reply(&Command::RelayDeny(hex.clone()), false, false);
        assert!(text.starts_with("error:"), "{text}");
        assert!(text.contains(&hex), "{text}");
    }

    #[test]
    fn blossom_allow_merge_keeps_persisted_and_daemon_entries() {
        let persisted = vec!["cli".to_string()];
        let in_memory = vec!["daemon".to_string()];
        // The CLI entry (persisted, not in memory) and the daemon-only
        // entry both survive; order is persisted first, then in-memory.
        let (entries, changed) = merge_blossom_allow(Some(&persisted), &in_memory, "new");
        assert!(changed);
        assert_eq!(entries, vec!["cli", "daemon", "new"]);
        // An entry present in either list is not duplicated and reports
        // no change when it is the one being allowed.
        let (entries, changed) = merge_blossom_allow(Some(&persisted), &in_memory, "cli");
        assert!(!changed);
        assert_eq!(entries, vec!["cli", "daemon"]);
        // A failed re-read falls back to the in-memory list.
        let (entries, changed) = merge_blossom_allow(None, &in_memory, "new");
        assert!(changed);
        assert_eq!(entries, vec!["daemon", "new"]);
    }

    #[test]
    fn blossom_deny_merge_removes_persisted_entries() {
        let persisted = vec!["cli".to_string(), "keep".to_string()];
        let in_memory = vec!["cli".to_string(), "stale".to_string()];
        // The CLI-added entry is only in the persisted list: removing it is
        // a real change, and the written list is the persisted one minus
        // the pubkey (a CLI deny must not be resurrected).
        let (entries, changed) = merge_blossom_deny(Some(&persisted), &in_memory, "cli");
        assert!(changed);
        assert_eq!(entries, vec!["keep"]);
        let (entries, changed) = merge_blossom_deny(Some(&persisted), &in_memory, "absent");
        assert!(!changed);
        assert_eq!(entries, vec!["cli", "keep"]);
        // A failed re-read falls back to the in-memory list.
        let (entries, changed) = merge_blossom_deny(None, &in_memory, "stale");
        assert!(changed);
        assert_eq!(entries, vec!["cli"]);
    }
}
