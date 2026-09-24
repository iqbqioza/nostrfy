//! NIP-43: Relay Access Metadata and Requests.
//!
//! The relay can define roles (`kind:33534`, addressable by `d` tag) and
//! publish membership lists (`kind:13534`, replaceable) signed with its own
//! key. The NIP-86 role methods manage them; add/remove user events
//! (`kind:8000`/`kind:8001`) are published on assignment changes and leave
//! requests (`kind:28936`) update the member list.

use std::collections::HashMap;

use serde_json::json;

use crate::db::DbClient;
use crate::event::Event;
use crate::filter::Filter;
use crate::util::unix_now;

pub const ROLE_DEFINITION: u64 = 33534;
pub const MEMBERSHIP_LIST: u64 = 13534;
pub const ADD_USER: u64 = 8000;
pub const REMOVE_USER: u64 = 8001;
pub const JOIN: u64 = 28934;
/// NIP-43 invite request (`kind:28935`): a reserved ephemeral kind that MUST
/// be signed by the relay's own key (the NIP-11 `self` pubkey). This relay
/// never generates claims, so client-signed 28935 events are rejected at
/// intake (see `Relay::validate_base`).
pub const INVITE: u64 = 28935;
pub const LEAVE: u64 = 28936;
/// Tag on a `kind:33534` tombstone marking a role as deleted.
pub const DELETED_TAG: &str = "deleted";

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Role {
    pub label: String,
    pub description: String,
    pub color: String,
    pub order: Option<i64>,
}

/// NIP-43: the optional `color` tag is "a `hue` value from `0` to `360` for
/// the role". An empty string is allowed and means the tag is omitted;
/// anything else must be a plain integer in range, or clients would receive
/// a role color they cannot interpret. Validated at the RPC boundary
/// (`NIP-86 createrole`/`editrole`) before the role is stored or published.
pub fn check_role_color(color: &str) -> anyhow::Result<()> {
    if color.is_empty() {
        return Ok(());
    }
    match color.parse::<u32>() {
        Ok(hue) if hue <= 360 => Ok(()),
        _ => Err(anyhow::anyhow!(
            "role color must be a hue value from 0 to 360"
        )),
    }
}

#[derive(Debug, Default)]
pub struct RoleStore {
    pub roles: HashMap<String, Role>,
    /// pubkey -> role ids.
    pub assignments: HashMap<String, Vec<String>>,
    /// NIP-86 `createclaim` invite codes (NIP-43 PR #2408): a `kind:28934`
    /// join request carrying a listed code admits its author. Codes have
    /// no events behind them, so unlike roles/assignments they live only
    /// in the snapshot — a disaster rebuild from events drops them
    /// (fail-closed: joins are rejected until an admin recreates a code).
    pub claims: std::collections::BTreeSet<String>,
}

/// The persistable NIP-43 role state (see the `ROLE` table).
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub(crate) struct RolesSnapshot {
    pub roles: HashMap<String, Role>,
    pub assignments: HashMap<String, Vec<String>>,
    /// Invite codes (see [`RoleStore::claims`]). Absent in older
    /// snapshots (serde default) means no codes.
    #[serde(default)]
    pub claims: std::collections::BTreeSet<String>,
    /// The database's state generation the snapshot was taken at (see
    /// `DbClient::state_stamp`): a restore must reject a snapshot stamped
    /// before the current generation, because it predates a removal of a
    /// role-state event. Present in snapshots written after the stamp was
    /// introduced; older snapshots deserialize as 0.
    #[serde(default)]
    pub stamp: u64,
    /// The database's derived-state sequence the snapshot was taken at
    /// (see `DbClient::state_seq`): a restore must reject a snapshot whose
    /// sequence is below the current one, because it predates a
    /// NIP-29/NIP-43 state event. Present in snapshots written after the
    /// sequence was introduced; older snapshots deserialize as 0.
    #[serde(default)]
    pub seq: u64,
}

impl RoleStore {
    /// Whether `pubkey` holds at least one role assignment.
    pub fn is_member_of(&self, pubkey: &str) -> bool {
        // Membership is presence on the member list: a claim-admitted
        // joiner carries no roles yet still appears in `kind:13534` and
        // must get the `duplicate:` verdict on rejoin (every other entry
        // is kept role-non-empty by the assign/unassign/delete cleanup,
        // so this matches the old check on all existing states).
        self.assignments.contains_key(pubkey)
    }

    /// Persisted snapshot of the role state (see the `ROLE` table).
    pub(crate) fn snapshot(&self) -> RolesSnapshot {
        RolesSnapshot {
            roles: self.roles.clone(),
            assignments: self.assignments.clone(),
            claims: self.claims.clone(),
            // Filled by the persist path, which reads the database's
            // generation (`DbClient::state_stamp` and `DbClient::state_seq`).
            stamp: 0,
            seq: 0,
        }
    }

    /// Restores state persisted by [`Self::snapshot`].
    pub(crate) fn restore(&mut self, snap: RolesSnapshot) {
        self.roles = snap.roles;
        self.assignments = snap.assignments;
        self.claims = snap.claims;
    }

    /// Whether a snapshot stamped `snapshot_stamp` still reflects the
    /// database generation `current_stamp`: a snapshot from before a
    /// role-state removal (its stamp is older) must not be restored. A
    /// snapshot stamped at the current generation is current; one stamped
    /// ahead can only mean the counter was reset and is the freshest state
    /// available. A caller that cannot read `current_stamp` must fail
    /// closed (see the startup restore path).
    pub(crate) fn snapshot_is_current(snapshot_stamp: u64, current_stamp: u64) -> bool {
        snapshot_stamp >= current_stamp
    }

    /// Restores `snap` only when it does not predate either the database's
    /// `current_stamp` (a role-state removal advanced it) or `current_seq`
    /// (a role-state event was stored). Returns false without touching the
    /// store when the snapshot is stale, so the caller runs the existing
    /// rebuild path (fail-closed): restoring it would resurrect a deleted
    /// grant or lose a role-state event the snapshot predates.
    pub(crate) fn restore_checked(
        &mut self,
        snap: RolesSnapshot,
        current_stamp: u64,
        current_seq: u64,
    ) -> bool {
        if !Self::snapshot_is_current(snap.stamp, current_stamp)
            || !Self::snapshot_is_current(snap.seq, current_seq)
        {
            return false;
        }
        self.restore(snap);
        true
    }

    pub fn create(
        &mut self,
        id: &str,
        label: &str,
        description: &str,
        color: &str,
        order: Option<i64>,
    ) {
        self.roles.insert(
            id.to_string(),
            Role {
                label: label.to_string(),
                description: description.to_string(),
                color: color.to_string(),
                order,
            },
        );
    }

    pub fn delete(&mut self, id: &str) -> bool {
        if self.roles.remove(id).is_some() {
            // Drop lingering assignments to the deleted role so the
            // membership event never lists a non-existent role.
            for roles in self.assignments.values_mut() {
                roles.retain(|r| r != id);
            }
            self.assignments.retain(|_, roles| !roles.is_empty());
            true
        } else {
            false
        }
    }

    pub fn assign(&mut self, pubkey: &str, role: &str) -> bool {
        if !self.roles.contains_key(role) {
            return false;
        }
        let roles = self.assignments.entry(pubkey.to_string()).or_default();
        // Unlike `unassign` (which reports whether anything changed), the
        // old code always reported success: a duplicate assignment
        // needlessly scheduled snapshots and republished the membership
        // list with a fresh timestamp for identical state.
        if roles.iter().any(|r| r == role) {
            return false;
        }
        roles.push(role.to_string());
        true
    }

    pub fn unassign(&mut self, pubkey: &str, role: &str) -> bool {
        let mut changed = false;
        if let Some(roles) = self.assignments.get_mut(pubkey) {
            let before = roles.len();
            roles.retain(|r| r != role);
            changed = roles.len() != before;
            if roles.is_empty() {
                self.assignments.remove(pubkey);
            }
        }
        changed
    }

    /// Removes a pubkey from the member list (leave request). Returns true
    /// when the pubkey was listed.
    pub fn remove_pubkey(&mut self, pubkey: &str) -> bool {
        self.assignments.remove(pubkey).is_some()
    }

    /// Maximum invite-code length accepted by NIP-86 `createclaim`: codes
    /// persist in the roles snapshot, so an unbounded string must not
    /// enter the store.
    pub const MAX_CLAIM_LEN: usize = 128;

    /// Stores an invite code. Returns false when it already existed
    /// (idempotent success at the RPC layer).
    pub fn add_claim(&mut self, claim: &str) -> bool {
        self.claims.insert(claim.to_string())
    }

    /// Revokes an invite code. Returns false when no such code existed
    /// (idempotent success at the RPC layer).
    pub fn remove_claim(&mut self, claim: &str) -> bool {
        self.claims.remove(claim)
    }

    /// Whether `claim` is a listed invite code.
    pub fn has_claim(&self, claim: &str) -> bool {
        self.claims.contains(claim)
    }

    /// Admits a claim-holder to the member list: an entry with no roles
    /// yet (listed in `kind:13534`, counted by [`Self::is_member_of`]).
    pub fn admit(&mut self, pubkey: &str) {
        self.assignments.entry(pubkey.to_string()).or_default();
    }

    // ----- relay-generated events -----

    fn base(kind: u64, relay_pubkey: &str, now: u64) -> Event {
        Event {
            id: String::new(),
            pubkey: relay_pubkey.to_string(),
            created_at: now,
            kind,
            tags: vec![vec!["-".into()]],
            content: String::new(),
            sig: String::new(),
        }
    }

    /// `kind:33534` role definition for a role id.
    pub fn role_event(&self, id: &str, relay_pubkey: &str, now: u64) -> Event {
        let mut event = Self::base(ROLE_DEFINITION, relay_pubkey, now);
        event.tags.push(vec!["d".into(), id.to_string()]);
        if let Some(role) = self.roles.get(id) {
            if !role.label.is_empty() {
                event.tags.push(vec!["label".into(), role.label.clone()]);
            }
            if !role.description.is_empty() {
                event
                    .tags
                    .push(vec!["description".into(), role.description.clone()]);
            }
            if !role.color.is_empty() {
                event.tags.push(vec!["color".into(), role.color.clone()]);
            }
            if let Some(order) = role.order {
                event.tags.push(vec!["order".into(), order.to_string()]);
            }
        }
        event
    }

    /// `kind:33534` tombstone for a deleted role. Publishing it (addressable,
    /// `d`-tagged) replaces the stored role definition so that `delete_role`
    /// survives the restart rebuild; the rebuild skips tombstones.
    pub fn role_deletion_event(&self, id: &str, relay_pubkey: &str, now: u64) -> Event {
        let mut event = Self::base(ROLE_DEFINITION, relay_pubkey, now);
        event.tags.push(vec!["d".into(), id.to_string()]);
        event.tags.push(vec![DELETED_TAG.into()]);
        event
    }

    /// `kind:13534` membership list: every assigned pubkey with its roles.
    pub fn membership_event(&self, relay_pubkey: &str, now: u64) -> Event {
        let mut event = Self::base(MEMBERSHIP_LIST, relay_pubkey, now);
        let mut members: Vec<(String, Vec<String>)> = self
            .assignments
            .iter()
            .map(|(pk, roles)| {
                let mut roles = roles.clone();
                roles.sort();
                (pk.clone(), roles)
            })
            .collect();
        members.sort();
        for (pubkey, roles) in members {
            let mut tag = vec!["member".to_string(), pubkey];
            tag.extend(roles);
            event.tags.push(tag);
        }
        event
    }

    pub fn add_user_event(&self, pubkey: &str, relay_pubkey: &str, now: u64) -> Event {
        let mut event = Self::base(ADD_USER, relay_pubkey, now);
        event.tags.push(vec!["p".into(), pubkey.to_string()]);
        event
    }

    pub fn remove_user_event(&self, pubkey: &str, relay_pubkey: &str, now: u64) -> Event {
        let mut event = Self::base(REMOVE_USER, relay_pubkey, now);
        event.tags.push(vec!["p".into(), pubkey.to_string()]);
        event
    }

    /// Rebuilds the role store from the stored role definitions and
    /// membership lists (only the latest addressable/replaceable versions
    /// are retained in the database). Only events signed by the relay's own
    /// key are honored (NIP-43: these MUST be signed by the `self` pubkey).
    ///
    /// Returns `false` when the rebuild could not be completed (the database
    /// did not answer, or a page boundary could not be verified): the
    /// caller must not persist or serve a partially-rebuilt role store and
    /// aborts startup. The history is streamed in ascending pages and
    /// applied as it arrives, so memory stays bounded by one page.
    pub async fn rebuild(&mut self, db: &DbClient, relay_pubkey: &str) -> bool {
        // A vanished pubkey must not be resurrected as a role holder by a
        // pre-vanish membership list.
        // Streamed in bounded pages (see the NIP-29 rebuild).
        let mut vanished: std::collections::HashSet<String> = std::collections::HashSet::new();
        if db
            .vanish_pubkeys_each(|key| {
                // Both hex spellings (see the NIP-29 rebuild).
                vanished.insert(hex::encode(key));
                vanished.insert(hex::encode_upper(key));
            })
            .await
            .is_none()
        {
            log::error!(
                "role state rebuild aborted: the vanished-pubkey list is unavailable; \
                 refusing to persist an incomplete role store"
            );
            return false;
        }
        // Role definitions and membership lists are replaceable, so at most
        // one version per address is stored and the ascending scan order is
        // the only order needed. Pages never split a timestamp (the scan
        // collects every tie), so advancing `since` past the page cannot
        // skip an event.
        const PAGE: usize = 50_000;
        let mut since: Option<u64> = None;
        loop {
            let mut filter: Filter =
                serde_json::from_value(json!({ "kinds": [ROLE_DEFINITION, MEMBERSHIP_LIST] }))
                    .expect("static filter");
            filter.since = since;
            let Some((page, more)) = db
                .query_full_startup(vec![filter.clone()], PAGE, unix_now(), true)
                .await
            else {
                log::error!(
                    "role state rebuild aborted: the database did not answer; refusing to \
                     persist an incomplete role store"
                );
                return false;
            };
            if page.is_empty() {
                break;
            }
            if more {
                // The collector stopped early: the count cap with a full
                // page, but also the 64 MiB byte cap or the work budget
                // with a short page. Verify the boundary second (the newest
                // here) and continue past it instead of failing the whole
                // rebuild; a boundary that cannot be verified (a store
                // error, or a second larger than the verify budget) stays
                // fatal (fail-closed).
                let boundary = page.last().map(|e| e.created_at).unwrap_or(0);
                let delivered = page.iter().filter(|e| e.created_at == boundary).count();
                if !crate::nips::nip29::boundary_second_complete(
                    db,
                    filter.clone(),
                    boundary,
                    delivered,
                )
                .await
                {
                    log::error!(
                        "role state rebuild aborted: the boundary second {boundary} is not \
                         fully collected; refusing to persist an incomplete role store"
                    );
                    return false;
                }
            }
            let max_created = page.last().map(|event| event.created_at);
            for event in page {
                if event.pubkey != relay_pubkey {
                    continue;
                }
                match event.kind {
                    ROLE_DEFINITION => {
                        let Some(id) = tag_value(&event, "d") else {
                            continue;
                        };
                        // A `["deleted"]` tombstone (published by `delete_role`)
                        // must not resurrect the role on restart; lingering
                        // assignments to the deleted role are dropped too.
                        if event
                            .tags
                            .iter()
                            .any(|t| t.first().map(String::as_str) == Some(DELETED_TAG))
                        {
                            self.roles.remove(id);
                            for roles in self.assignments.values_mut() {
                                roles.retain(|r| r != id);
                            }
                            self.assignments.retain(|_, roles| !roles.is_empty());
                            continue;
                        }
                        self.roles.insert(
                            id.to_string(),
                            Role {
                                label: tag_value(&event, "label").unwrap_or("").to_string(),
                                description: tag_value(&event, "description")
                                    .unwrap_or("")
                                    .to_string(),
                                color: tag_value(&event, "color").unwrap_or("").to_string(),
                                order: tag_value(&event, "order").and_then(|o| o.parse().ok()),
                            },
                        );
                    }
                    MEMBERSHIP_LIST => {
                        for tag in &event.tags {
                            if tag.len() >= 2 && tag[0] == "member" && !vanished.contains(&tag[1]) {
                                // Sorted and deduplicated: the tag order is
                                // not part of the protocol, and an unstable
                                // order made rebuilt role lists differ from
                                // the published ones.
                                let mut roles = tag[2..].to_vec();
                                roles.sort();
                                roles.dedup();
                                self.assignments.insert(tag[1].clone(), roles);
                            }
                        }
                    }
                    _ => {}
                }
            }
            if !more {
                // The collector reported no truncation: every remaining
                // event was collected.
                break;
            }
            match max_created {
                Some(ts) if ts < u64::MAX => since = Some(ts.saturating_add(1)),
                _ => break,
            }
        }
        // Drop assignments whose role definition did not survive: a
        // NIP-09-deleted role must not keep authorizing its holders through
        // the membership list that still names them. The filter runs after
        // the whole scan because event timestamps are client-controlled: a
        // membership list may legitimately precede its role definition.
        let roles = &self.roles;
        for assigned in self.assignments.values_mut() {
            assigned.retain(|role| roles.contains_key(role));
        }
        self.assignments.retain(|_, assigned| !assigned.is_empty());
        true
    }
}

fn tag_value<'a>(event: &'a Event, name: &str) -> Option<&'a str> {
    event
        .tags
        .iter()
        .find(|t| t.len() >= 2 && t[0] == name)
        .map(|t| t[1].as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_color_must_be_a_hue_in_range() {
        // NIP-43: `color` is a hue from 0 to 360; the empty string means
        // the optional tag is omitted.
        assert!(check_role_color("").is_ok());
        assert!(check_role_color("0").is_ok());
        assert!(check_role_color("37").is_ok());
        assert!(check_role_color("360").is_ok());
        // Out of range or not a plain integer: rejected (the relay would
        // otherwise publish a color clients cannot interpret).
        assert!(check_role_color("361").is_err());
        assert!(check_role_color("-1").is_err());
        assert!(check_role_color("1.5").is_err());
        assert!(check_role_color("red").is_err());
        assert!(check_role_color("37px").is_err());
    }

    #[test]
    fn role_lifecycle() {
        let mut store = RoleStore::default();
        store.create("king", "king", "ruler", "37", Some(1));
        assert!(store.roles.contains_key("king"));
        assert!(store.assign("abc", "king"));
        assert!(!store.assign("abc", "ghost"), "unknown role rejected");
        assert!(
            !store.assign("abc", "king"),
            "a duplicate assignment changes nothing and must report so, \
             or callers republish identical membership state"
        );
        assert!(store.unassign("abc", "king"));
        assert!(
            store.assignments.is_empty(),
            "empty assignments are dropped"
        );
        assert!(store.delete("king"));
    }

    #[test]
    fn invite_claims_roundtrip_through_snapshot() {
        // Invite codes live in the snapshot (they have no events behind
        // them): add/remove/list plus snapshot/restore, and legacy
        // snapshots without the field still load.
        let mut store = RoleStore::default();
        assert!(store.add_claim("welcome-1"));
        assert!(!store.add_claim("welcome-1"), "re-adding reports no change");
        assert!(store.has_claim("welcome-1"));
        assert!(!store.has_claim("bogus"));
        store.admit("abc");
        assert!(
            store.is_member_of("abc"),
            "a claim-admitted joiner is a member"
        );
        let snap = store.snapshot();
        let json = serde_json::to_string(&snap).unwrap();
        let restored: RolesSnapshot = serde_json::from_str(&json).unwrap();
        let mut fresh = RoleStore::default();
        fresh.restore(restored);
        assert!(fresh.has_claim("welcome-1"));
        assert!(fresh.is_member_of("abc"));
        assert!(fresh.remove_claim("welcome-1"));
        assert!(
            !fresh.remove_claim("welcome-1"),
            "re-removal reports no change"
        );
        assert!(!fresh.has_claim("welcome-1"));
    }

    #[test]
    fn legacy_role_snapshot_without_stamp_restores_at_generation_zero() {
        // Snapshots written before the stamp existed lack the field: it
        // must default to 0 instead of failing the load (a failed load
        // would force a rebuild and silently discard the persisted state).
        // At generation 0 (no removal ever happened) the legacy snapshot is
        // current.
        let json = r#"{"roles":{"mod":{"label":"Mod","description":"","color":"","order":null}},"assignments":{"abc":["mod"]}}"#;
        let snap: RolesSnapshot = serde_json::from_str(json).unwrap();
        assert_eq!(snap.stamp, 0, "legacy snapshots have no generation stamp");
        assert_eq!(snap.seq, 0, "legacy snapshots have no state sequence");

        // Once a removal advanced the generation the legacy snapshot is
        // stale and the startup path must rebuild instead.
        let mut store = RoleStore::default();
        assert!(!store.restore_checked(snap, 1, 0));
        assert!(store.roles.is_empty(), "a rejected snapshot is not applied");

        // At generation 0 (no removal ever happened) it is current.
        let snap: RolesSnapshot = serde_json::from_str(json).unwrap();
        let mut store = RoleStore::default();
        assert!(store.restore_checked(snap, 0, 0));
        assert!(store.roles.contains_key("mod"));
        assert!(store.is_member_of("abc"));
    }

    #[test]
    fn stale_role_snapshot_generation_is_rejected_at_restore() {
        // Mirrors the NIP-29 group check: a snapshot taken before a
        // role-state removal (its stamp is older than the database
        // generation) must not be restored, because it would resurrect
        // state the removal invalidated. Equal generations are current; a
        // snapshot stamped ahead can only mean the counter was reset, and
        // it is the freshest state available.
        assert!(RoleStore::snapshot_is_current(7, 7));
        assert!(RoleStore::snapshot_is_current(8, 7));
        assert!(!RoleStore::snapshot_is_current(6, 7));

        let mut store = RoleStore::default();
        store.create("king", "king", "", "", None);
        store.assign("abc", "king");
        let mut stale = store.snapshot();
        stale.stamp = 6;
        stale.roles.clear();
        stale.assignments.clear();
        assert!(
            !store.restore_checked(stale, 7, 7),
            "a snapshot from before the current generation must be rejected"
        );
        assert!(
            store.roles.contains_key("king"),
            "a rejected snapshot must leave the store untouched"
        );

        let mut current = store.snapshot();
        current.stamp = 7;
        current.seq = 7;
        assert!(store.restore_checked(current, 7, 7));
        assert!(store.roles.contains_key("king"));
    }

    #[test]
    fn stale_role_snapshot_sequence_is_rejected_at_restore() {
        // The sequence tracks accepted role-state events, not just removals:
        // a snapshot taken before the event advanced the sequence must not
        // be restored, because the debounced persistence may have skipped
        // the save that would have carried the event's state.
        let mut store = RoleStore::default();
        store.create("king", "king", "", "", None);
        let mut snapshot = store.snapshot();
        snapshot.stamp = 0;
        snapshot.seq = 4;
        let mut restored = RoleStore::default();
        assert!(
            !restored.restore_checked(snapshot, 0, 5),
            "a snapshot below the current sequence must be rejected"
        );
        assert!(
            restored.roles.is_empty(),
            "a rejected snapshot is not applied"
        );

        let mut snapshot = store.snapshot();
        snapshot.stamp = 0;
        snapshot.seq = 5;
        assert!(restored.restore_checked(snapshot, 0, 5));
        assert!(restored.roles.contains_key("king"));
    }

    #[test]
    fn role_events_are_wellformed() {
        let mut store = RoleStore::default();
        store.create("king", "king", "ruler of the relay", "37", Some(1));
        store.assign("c308e1f8", "king");

        let now = 1_700_000_000;
        let role = store.role_event("king", "relaypub", now);
        assert_eq!(role.kind, ROLE_DEFINITION);
        assert_eq!(role.tags[0], vec!["-"]);
        assert!(role.tags.contains(&vec!["d".into(), "king".into()]));
        assert!(role.tags.contains(&vec!["label".into(), "king".into()]));
        assert!(role.tags.contains(&vec!["order".into(), "1".into()]));

        let members = store.membership_event("relaypub", now);
        assert_eq!(members.kind, MEMBERSHIP_LIST);
        assert_eq!(members.tags[0], vec!["-"]);
        assert!(
            members
                .tags
                .contains(&vec!["member".into(), "c308e1f8".into(), "king".into()])
        );

        let add = store.add_user_event("c308e1f8", "relaypub", now);
        assert_eq!(add.kind, ADD_USER);
        assert!(add.tags.contains(&vec!["p".into(), "c308e1f8".into()]));
    }

    #[test]
    fn rebuild_ignores_foreign_events() {
        use crate::nips::nip01;
        use std::sync::Arc;
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join("nostrfy-nip43-test")
            .join(format!("{:x}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        let cfg = crate::config::DatabaseConfig {
            path,
            // Small mappings: the test VM cannot afford several
            // default-sized (1 GB / 1 TiB) LMDB reservations at once, and
            // the test stores a handful of events.
            map_size: 16 * 1024 * 1024,
            max_map_size: 32 * 1024 * 1024,
            ..Default::default()
        };
        let db = crate::db::DbClient::open(
            &cfg,
            true,
            Arc::new(Default::default()),
            0,
            128,
            4096,
            262144,
        )
        .unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay_pk = "aa".repeat(32);
            let foreign_pk = "bb".repeat(32);
            // NIP-43: kind 33534 must be signed by the relay's own key; an
            // event signed by anyone else must not feed the role store.
            let relay_role = Event {
                id: String::new(),
                pubkey: relay_pk.clone(),
                created_at: 100,
                kind: ROLE_DEFINITION,
                tags: vec![
                    vec!["-".into()],
                    vec!["d".into(), "king".into()],
                    vec!["label".into(), "real".into()],
                ],
                content: String::new(),
                sig: String::new(),
            };
            let foreign_role = Event {
                id: String::new(),
                pubkey: foreign_pk,
                created_at: 200,
                kind: ROLE_DEFINITION,
                tags: vec![
                    vec!["-".into()],
                    vec!["d".into(), "king".into()],
                    vec!["label".into(), "fake".into()],
                ],
                content: String::new(),
                sig: String::new(),
            };
            let mut events = vec![relay_role, foreign_role];
            for ev in &mut events {
                ev.id = nip01::compute_id(ev);
            }
            let now = unix_now();
            assert_eq!(
                db.put(events[0].clone(), now).await,
                crate::db::PutOutcome::Stored
            );
            assert_eq!(
                db.put(events[1].clone(), now).await,
                crate::db::PutOutcome::Stored
            );

            let mut store = RoleStore::default();
            assert!(
                store.rebuild(&db, &relay_pk).await,
                "the rebuild must complete"
            );
            assert_eq!(store.roles.len(), 1);
            assert_eq!(store.roles["king"].label, "real");
        });
    }

    #[test]
    fn rebuild_skips_deleted_role_tombstones() {
        use crate::nips::nip01;
        use std::sync::Arc;
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join("nostrfy-nip43-delete-test")
            .join(format!("{:x}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        let cfg = crate::config::DatabaseConfig {
            path,
            // Small mappings: the test VM cannot afford several
            // default-sized (1 GB / 1 TiB) LMDB reservations at once, and
            // the test stores a handful of events.
            map_size: 16 * 1024 * 1024,
            max_map_size: 32 * 1024 * 1024,
            ..Default::default()
        };
        let db = crate::db::DbClient::open(
            &cfg,
            true,
            Arc::new(Default::default()),
            0,
            128,
            4096,
            262144,
        )
        .unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay_pk = "aa".repeat(32);
            let role = Event {
                id: String::new(),
                pubkey: relay_pk.clone(),
                created_at: 100,
                kind: ROLE_DEFINITION,
                tags: vec![
                    vec!["-".into()],
                    vec!["d".into(), "king".into()],
                    vec!["label".into(), "king".into()],
                ],
                content: String::new(),
                sig: String::new(),
            };
            // The tombstone replaces the role definition (newer, addressable).
            let tombstone = Event {
                id: String::new(),
                pubkey: relay_pk.clone(),
                created_at: 200,
                kind: ROLE_DEFINITION,
                tags: vec![
                    vec!["-".into()],
                    vec!["d".into(), "king".into()],
                    vec![DELETED_TAG.into()],
                ],
                content: String::new(),
                sig: String::new(),
            };
            let mut events = vec![role, tombstone];
            for ev in &mut events {
                ev.id = nip01::compute_id(ev);
            }
            let now = unix_now();
            assert_eq!(
                db.put(events[0].clone(), now).await,
                crate::db::PutOutcome::Stored
            );
            assert_eq!(
                db.put(events[1].clone(), now).await,
                crate::db::PutOutcome::Replaced,
                "the tombstone replaces the stored role definition"
            );
            let mut store = RoleStore::default();
            assert!(
                store.rebuild(&db, &relay_pk).await,
                "the rebuild must complete"
            );
            assert!(
                !store.roles.contains_key("king"),
                "a deleted role must not resurrect on restart"
            );
        });
    }

    #[test]
    fn rebuild_drops_assignments_to_missing_roles() {
        // A NIP-09-deleted role definition must not keep its holders
        // authorized through the membership list that still names them: the
        // rebuild keeps only the assignments whose role survived.
        use crate::nips::nip01;
        use std::sync::Arc;
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join("nostrfy-nip43-missing-role-test")
            .join(format!("{:x}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        let cfg = crate::config::DatabaseConfig {
            path,
            map_size: 16 * 1024 * 1024,
            max_map_size: 32 * 1024 * 1024,
            ..Default::default()
        };
        let db = crate::db::DbClient::open(
            &cfg,
            true,
            Arc::new(Default::default()),
            0,
            128,
            4096,
            262144,
        )
        .unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay_pk = "aa".repeat(32);
            let kept_member = "cc".repeat(32);
            let gone_member = "dd".repeat(32);
            let mut role = Event {
                id: String::new(),
                pubkey: relay_pk.clone(),
                created_at: 100,
                kind: ROLE_DEFINITION,
                tags: vec![
                    vec!["-".into()],
                    vec!["d".into(), "kept".into()],
                    vec!["label".into(), "Kept".into()],
                ],
                content: String::new(),
                sig: String::new(),
            };
            // The membership list still names the deleted role.
            let mut members = Event {
                id: String::new(),
                pubkey: relay_pk.clone(),
                created_at: 200,
                kind: MEMBERSHIP_LIST,
                tags: vec![
                    vec!["-".into()],
                    vec!["member".into(), kept_member.clone(), "kept".into()],
                    vec!["member".into(), gone_member.clone(), "gone".into()],
                ],
                content: String::new(),
                sig: String::new(),
            };
            for ev in [&mut role, &mut members] {
                ev.id = nip01::compute_id(ev);
            }
            let now = unix_now();
            for ev in [&role, &members] {
                assert_eq!(db.put(ev.clone(), now).await, crate::db::PutOutcome::Stored);
            }
            let mut store = RoleStore::default();
            assert!(
                store.rebuild(&db, &relay_pk).await,
                "the rebuild must complete"
            );
            assert!(store.roles.contains_key("kept"));
            assert!(
                store.is_member_of(&kept_member),
                "the surviving role's grant must be restored"
            );
            assert!(
                !store.is_member_of(&gone_member),
                "a deleted role's grant must not be restored"
            );
        });
    }

    #[test]
    fn rebuild_fails_closed_when_the_database_is_unavailable() {
        // A missing reply must not be mistaken for an empty history: the
        // rebuild reports failure so the startup refuses to persist or serve
        // an incomplete role store.
        use std::sync::Arc;
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join("nostrfy-nip43-rebuild-fail")
            .join(format!("{:x}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        let cfg = crate::config::DatabaseConfig {
            path,
            map_size: 16 * 1024 * 1024,
            max_map_size: 32 * 1024 * 1024,
            ..Default::default()
        };
        let db = crate::db::DbClient::open(
            &cfg,
            true,
            Arc::new(Default::default()),
            0,
            128,
            4096,
            262144,
        )
        .unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            db.shutdown();
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            let relay_pk = "aa".repeat(32);
            let mut store = RoleStore::default();
            assert!(
                !store.rebuild(&db, &relay_pk).await,
                "an unanswered rebuild must fail closed"
            );
            assert!(store.roles.is_empty());
        });
    }
}
