//! NIP-29: Relay-based Groups.
//!
//! The group state machine (access control, moderation application and
//! read visibility) lives here; the relay-generated metadata events are
//! built by the [`events`] module.

pub(crate) mod events;
#[cfg(test)]
pub(crate) mod tests;

use events::{
    apply_settings, build_admins_event, build_members_event, build_meta_event, build_pins_event,
    build_put_user, build_remove_user,
};

/// Moderation policy implemented here: any user with at least one role (from
/// a `kind:9000` put-user event or a `kind:9007` group creation) is an admin
/// and may send moderation events; the relay's own key is always an admin.
use std::collections::{HashMap, HashSet};

use anyhow::{anyhow, bail};
use serde_json::json;

use crate::db::DbClient;
use crate::event::Event;
use crate::filter::Filter;
use crate::util::unix_now;

pub const GROUP_META: u64 = 39000;
pub const GROUP_ADMINS: u64 = 39001;
pub const GROUP_MEMBERS: u64 = 39002;
/// Reserved group metadata kinds (no builder emits them yet): treated as
/// relay-signed metadata for forward compatibility.
#[allow(dead_code)]
pub const GROUP_ROLES: u64 = 39003;
#[allow(dead_code)]
pub const GROUP_PARTICIPANTS: u64 = 39004;
pub const GROUP_PINS: u64 = 39005;
pub const MOD_MIN: u64 = 9000;
pub const MOD_MAX: u64 = 9020;
pub const CREATE_GROUP: u64 = 9007;
pub const DELETE_GROUP: u64 = 9008;
pub const JOIN: u64 = 9021;
pub const LEAVE: u64 = 9022;

const H: &str = "h";
const D: &str = "d";
const P: &str = "p";
const E: &str = "e";
const A: &str = "a";
const CODE: &str = "code";

/// Maximum pinned events per group (`kind:9010` list / mirrored `39005`).
/// NIP-29 lets the relay limit pins; without a bound one moderation event
/// could pin unbounded in-memory and stored state.
pub(crate) const MAX_PINS: usize = 100;

/// Maximum invite codes per group (`kind:9009` accumulations). Codes are
/// never consumed and vanish does not track their authors, so without a
/// bound repeated `9009` events would grow the set without limit.
pub(crate) const MAX_INVITES: usize = 100;

/// Maximum members per group. Without a bound an admin could spam `9000`
/// events with fresh pubkeys, growing the member map (and every mirrored
/// `39001`/`39002`) without limit.
pub(crate) const MAX_MEMBERS: usize = 10_000;

/// Maximum members across every group (the global member budget). The
/// per-group cap alone still lets an attacker churn groups (or spread
/// grants) until the total member map exhausts memory; the global budget
/// bounds the sum. Enforced on JOIN/9000 through a maintained counter, so
/// the check costs O(1) instead of scanning every group per event.
pub(crate) const MAX_TOTAL_MEMBERS: usize = 1_000_000;

/// The declared-children adoption hint may hold this many ids per
/// configured group. The hint is only a fast path for the create-time
/// scan, so the budget is deliberately small.
const DECLARED_CHILDREN_PER_GROUP: usize = 4;

/// Absolute bound on the declared-children hint for an uncapped store
/// (`max_groups == 0`): the hint must never grow with the history, even
/// when the group cap is disabled.
const MAX_DECLARED_CHILDREN: usize = 10_000;

fn tag_value<'a>(event: &'a Event, name: &str) -> Option<&'a str> {
    event
        .tags
        .iter()
        .find(|t| t.len() >= 2 && t[0] == name)
        .map(|t| t[1].as_str())
}

/// Values of every occurrence of `name` in the event's tags.
fn tag_values<'a>(event: &'a Event, name: &'static str) -> impl Iterator<Item = &'a str> {
    event
        .tags
        .iter()
        .filter(move |t| t.len() >= 2 && t[0] == name)
        .map(|t| t[1].as_str())
}

/// Group id of a user or moderation event (from the `h` tag).
pub fn group_id(event: &Event) -> Option<&str> {
    tag_value(event, H)
}

/// Whether the event is a group *action*: moderation events (9000-9020),
/// join requests (9021) and leave requests (9022). These MUST carry an `h`
/// tag naming the group they act on.
pub fn is_group_action(event: &Event) -> bool {
    (MOD_MIN..=MOD_MAX).contains(&event.kind) || event.kind == JOIN || event.kind == LEAVE
}

/// Whether the event is a group event at all: user and moderation events
/// carry an `h` tag, relay-generated metadata events are kinds 39000-39005
/// identified by their `d` tag. Cheap enough to run per live event; mirrors
/// the `gid` selection in [`GroupStore::visible_to`].
pub fn is_group_event(event: &Event) -> bool {
    group_id(event).is_some()
        || ((GROUP_META..=GROUP_PINS).contains(&event.kind) && group_id_d(event).is_some())
}

/// Group id of a relay-generated metadata event (from the `d` tag).
pub fn group_id_d(event: &Event) -> Option<&str> {
    tag_value(event, D)
}

/// Group id of a stored event for visibility checks: the `h` tag for user
/// and moderation events, the `d` tag for relay-generated metadata events.
pub fn group_id_any(event: &Event) -> Option<&str> {
    match event.kind {
        GROUP_META..=GROUP_PINS => group_id_d(event),
        _ => group_id(event),
    }
}

/// Trait-based variant of [`group_id_any`] for the negentropy light path
/// (the candidate was deserialized without its content).
pub fn group_id_any_light<E: crate::filter::EventFields>(event: &E) -> Option<&str> {
    match event.kind() {
        GROUP_META..=GROUP_PINS => tag_value_light(event, D),
        _ => tag_value_light(event, H),
    }
}

fn tag_value_light<'a, E: crate::filter::EventFields>(
    event: &'a E,
    name: &'a str,
) -> Option<&'a str> {
    event
        .tags()
        .iter()
        .find(|t| t.len() >= 2 && t[0] == name)
        .map(|t| t[1].as_str())
}

/// The `previous` tag values of an event (NIP-29 timeline references).
/// The spec's canonical form is one tag with any number of values —
/// `["previous", "eb96c864", "2db75638", "b5d1065f"]` — so every value of
/// every `previous` tag counts.
pub fn previous_tags(event: &Event) -> Vec<String> {
    event
        .tags
        .iter()
        .filter(|t| t.len() >= 2 && t[0] == "previous")
        .flat_map(|t| t[1..].iter().cloned())
        .collect()
}

/// `e`-tag target ids of a `kind:9005` delete-event moderation action.
pub fn delete_targets(event: &Event) -> Vec<String> {
    tag_values(event, E).map(str::to_string).collect()
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct GroupSettings {
    pub private: bool,
    pub restricted: bool,
    pub closed: bool,
    pub hidden: bool,
    pub supported_kinds: Option<Vec<u64>>,
    pub name: String,
    pub picture: String,
    pub banner: String,
    pub about: String,
    /// NIP-29: the group supports LiveKit audio/video rooms.
    pub livekit: bool,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Group {
    /// pubkey -> set of roles.
    pub members: HashMap<String, HashSet<String>>,
    pub settings: GroupSettings,
    pub parent: Option<String>,
    pub children: Vec<String>,
    /// Pinned events as (tag, value) pairs.
    pub pins: Vec<(String, String)>,
    /// Valid invite codes.
    pub invites: HashSet<String>,
}

impl Group {
    /// A member carrying at least one role is an admin. (The relay's own key
    /// is handled separately: its relay-generated events are stored directly
    /// and never go through this check.)
    pub fn is_admin(&self, pubkey: &str) -> bool {
        self.members
            .get(pubkey)
            .is_some_and(|roles| !roles.is_empty())
    }

    pub fn is_member(&self, pubkey: &str) -> bool {
        self.members.contains_key(pubkey)
    }

    pub fn has_invite(&self, code: &str) -> bool {
        self.invites.contains(code)
    }
}

#[derive(Debug, Default)]
pub struct GroupStore {
    pub groups: HashMap<String, Group>,
    deleted: HashSet<String>,
    /// Groups whose create event is gone (the creator vanished, or the
    /// 9007 was deleted/expired) but whose other events survived the
    /// rebuild: their state cannot be restored, so their content must be
    /// withheld from everyone instead of becoming world-readable
    /// (fail-closed). A fresh CREATE_GROUP later removes the id from this
    /// set.
    ghost: HashSet<String>,
    /// Per-group timestamp of the last published member list (39002).
    /// NIP-29 marks the member list optional, and a 10k-member group would
    /// otherwise build, sign and store a 10k-tag event on every JOIN/LEAVE.
    members_published_at: HashMap<String, u64>,
    /// Cap on the store size (active groups + deleted markers): bounds the
    /// in-memory state even when an attacker churns group ids. 0 =
    /// unlimited.
    max_groups: usize,
    /// Total members across every group: the global budget (see
    /// [`MAX_TOTAL_MEMBERS`]) is enforced against this counter instead of
    /// rescanning every group per JOIN/9000. Every member-map mutation in
    /// this module (and [`Self::remove_member_everywhere`]) keeps it in
    /// sync; [`Self::restore`] recomputes it.
    total_members: usize,
    /// The global member budget; 0 = unlimited (tests).
    max_total_members: usize,
    /// Child ids that some group's `children` list declared (a hint, never
    /// the authority): a CREATE_GROUP scans the groups for an adopting
    /// parent only when the id was ever declared, so an uncapped store does
    /// not pay an O(groups) scan per create. Stale entries (a link that was
    /// later removed) only cost one scan.
    declared_children: HashSet<String>,
}

/// The persistable NIP-29 group state: everything [`GroupStore`] holds
/// except the capacity cap (which comes from the config on every start).
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub(crate) struct GroupsSnapshot {
    pub groups: HashMap<String, Group>,
    pub deleted: HashSet<String>,
    /// Present in snapshots written after the ghost marker was introduced:
    /// older snapshots lack the field, and a missing field must deserialize
    /// as "no ghosts" instead of failing the whole load (a failed load would
    /// force a full rebuild and silently discard the rest of the state).
    #[serde(default)]
    pub ghost: HashSet<String>,
    /// The database's group-state generation the snapshot was taken at
    /// (see `DbClient::state_stamp`): a restore must reject a snapshot
    /// stamped before the current generation, because it predates a
    /// group-state removal. Present in snapshots written after the stamp
    /// was introduced; older snapshots deserialize as 0.
    #[serde(default)]
    pub stamp: u64,
    /// The database's derived-state sequence the snapshot was taken at
    /// (see `DbClient::state_seq`): a restore must reject a snapshot whose
    /// sequence is below the current one, because it predates a
    /// NIP-29/NIP-43 state event (a debounced or skipped snapshot write
    /// leaves the old sequence behind, making the newer state detectable).
    /// Present in snapshots written after the sequence was introduced;
    /// older snapshots deserialize as 0.
    #[serde(default)]
    pub seq: u64,
}

/// Verifies that a rebuild page delivered every event of its boundary
/// second. The scan collector has hard caps (twice the page size for
/// same-timestamp ties, 64 MiB of content) that can cut a second while
/// still reporting `more`; stepping the cursor past it would silently drop
/// the unexamined events (and, for the ghost pass, fail open). The second
/// is re-queried with a wider limit and the completeness is accepted only
/// when that query answered with fewer than its own request limit and no
/// more events than the page delivered. Any doubt fails closed.
pub(crate) async fn boundary_second_complete(
    db: &crate::db::DbClient,
    mut filter: crate::filter::Filter,
    boundary: u64,
    delivered: usize,
) -> bool {
    const VERIFY_LIMIT: usize = 150_000;
    filter.since = Some(boundary);
    filter.until = Some(boundary);
    let Some((verify, more)) = db
        .query_full_startup(vec![filter], VERIFY_LIMIT, unix_now(), true)
        .await
    else {
        return false;
    };
    // `more` is the only signal that the verify query itself was cut short
    // (byte cap or work budget): if it is set the second may hold events
    // beyond what both queries returned, so the check must fail closed.
    !more && verify.len() < VERIFY_LIMIT && verify.len() <= delivered
}

impl GroupStore {
    pub fn with_cap(max_groups: usize) -> GroupStore {
        GroupStore {
            max_groups,
            max_total_members: MAX_TOTAL_MEMBERS,
            ..Default::default()
        }
    }

    /// Persisted snapshot of the group state (see the `GROUP` table): the
    /// live groups plus the delete/ghost markers. `max_groups` is config,
    /// not state, and is never persisted.
    pub(crate) fn snapshot(&self) -> GroupsSnapshot {
        GroupsSnapshot {
            groups: self.groups.clone(),
            deleted: self.deleted.clone(),
            ghost: self.ghost.clone(),
            // Filled by the persist path, which reads the database's
            // group-state generation (`DbClient::state_stamp` and
            // `DbClient::state_seq`).
            stamp: 0,
            seq: 0,
        }
    }

    /// Restores state persisted by [`Self::snapshot`], keeping the current
    /// capacity cap. The derived counters (`total_members`,
    /// `declared_children`) start from the restored groups.
    pub(crate) fn restore(&mut self, snap: GroupsSnapshot) {
        self.groups = snap.groups;
        self.deleted = snap.deleted;
        self.ghost = snap.ghost;
        self.recompute_derived();
    }

    /// Whether a snapshot stamped `snapshot_stamp` still reflects the
    /// database generation `current_stamp`: a snapshot from before a
    /// group-state removal (its stamp is older) must not be restored. A
    /// snapshot stamped at the current generation is current; one stamped
    /// ahead can only mean the counter was reset and is the freshest state
    /// available. A caller that cannot read `current_stamp` must fail
    /// closed (see the startup restore path).
    pub(crate) fn snapshot_is_current(snapshot_stamp: u64, current_stamp: u64) -> bool {
        snapshot_stamp >= current_stamp
    }

    /// Restores `snap` only when it does not predate either the database's
    /// `current_stamp` (a state-event removal advanced it) or `current_seq`
    /// (a state event was stored). Returns false without touching the store
    /// when the snapshot is stale, so the caller runs the existing rebuild
    /// path (fail-closed): restoring it would resurrect state a removal
    /// invalidated, or lose a state event the snapshot predates.
    pub(crate) fn restore_checked(
        &mut self,
        snap: GroupsSnapshot,
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

    /// Recomputes the counters derived from `groups` (after a restore or a
    /// bulk mutation), and drops throttle stamps of groups that no longer
    /// exist: the stamp map covers live groups only, so a restored store
    /// never throttles a re-created id on a deleted incarnation's stamp.
    fn recompute_derived(&mut self) {
        self.total_members = self.groups.values().map(|group| group.members.len()).sum();
        self.declared_children = self
            .groups
            .values()
            .flat_map(|group| group.children.iter().cloned())
            .collect();
        self.members_published_at
            .retain(|gid, _| self.groups.contains_key(gid));
    }

    /// Whether `fresh` more members would exceed the global member budget.
    fn at_member_capacity(&self, fresh: usize) -> bool {
        self.max_total_members > 0
            && self.total_members.saturating_add(fresh) > self.max_total_members
    }

    /// Whether another group may be created. The deleted and ghost markers
    /// count toward the budget: they are kept forever (a deleted group must
    /// not be resurrectable), so an unbounded number of distinct deletions
    /// (or rebuild-discovered ghosts) must not grow the store without limit
    /// either.
    fn at_capacity(&self) -> bool {
        self.max_groups > 0
            && self.groups.len() + self.deleted.len() + self.ghost.len() >= self.max_groups
    }

    /// The bound on the declared-children adoption hint: a small multiple
    /// of the group cap, or the absolute [`MAX_DECLARED_CHILDREN`] when the
    /// cap is disabled. The hint is monotonic without this bound: a 9002
    /// listing fresh placeholder child ids would grow it forever, and
    /// `at_capacity` never counted it.
    fn declared_children_cap(&self) -> usize {
        if self.max_groups == 0 {
            MAX_DECLARED_CHILDREN
        } else {
            self.max_groups.saturating_mul(DECLARED_CHILDREN_PER_GROUP)
        }
    }

    /// Drops declared child ids no live group's `children` list references
    /// any more: they can never be adopted, so they only occupy the hint
    /// budget. Runs when the hint is over (or at) its bound, so the scan is
    /// bounded by the live group state.
    fn prune_declared_children(&mut self) {
        let live: HashSet<&str> = self
            .groups
            .values()
            .flat_map(|group| group.children.iter().map(String::as_str))
            .collect();
        self.declared_children
            .retain(|id| live.contains(id.as_str()));
    }

    /// Records `id` as a declared-child adoption hint, pruning unreferenced
    /// entries when at the bound and dropping the hint entirely once the
    /// budget is exhausted. A missing hint only costs the adoption scan a
    /// later CREATE_GROUP would have skipped; the store stays bounded.
    fn declare_child(&mut self, id: &str) {
        if self.declared_children.contains(id) {
            return;
        }
        let cap = self.declared_children_cap();
        if self.declared_children.len() >= cap {
            self.prune_declared_children();
            if self.declared_children.len() >= cap {
                return;
            }
        }
        self.declared_children.insert(id.to_string());
    }

    pub fn group(&self, id: &str) -> Option<&Group> {
        self.groups.get(id)
    }

    /// Validates a write against the current group state. The error message
    /// is the reason string for the `OK` message on rejection. Access
    /// control is based on the event's author (`event.pubkey`), not on
    /// connection authentication.
    pub fn validate_write(&self, event: &Event) -> anyhow::Result<()> {
        self.validate_write_inner(event, None)
    }

    /// Like [`Self::validate_write`], but treats the relay's own key as the
    /// group master key. NIP-29 expects moderation events from "the relay
    /// master key or by group admins", so an operator can recover a group
    /// whose admins all left by signing the moderation event with
    /// `relay.private_key` (the NIP-11 `self` key).
    pub fn validate_write_for_relay(
        &self,
        event: &Event,
        relay_pubkey: Option<&str>,
    ) -> anyhow::Result<()> {
        self.validate_write_inner(event, relay_pubkey)
    }

    fn validate_write_inner(
        &self,
        event: &Event,
        relay_pubkey: Option<&str>,
    ) -> anyhow::Result<()> {
        // NIP-29: the event's `h` tag carries *the* group id. Multiple `h`
        // tags are ambiguous and dangerous: the checks below use the first
        // one while the stored tag index and subscriptions match any of
        // them, so an event validated against an open group could surface in
        // a restricted group's feed. Reject them outright.
        if event
            .tags
            .iter()
            .filter(|t| t.first().is_some_and(|name| name == H))
            .count()
            > 1
        {
            bail!("invalid: group events must carry only one h tag");
        }
        let Some(gid) = group_id(event) else {
            // NIP-29 group actions MUST carry an `h` tag (mirrors the intake
            // precheck): without it the event names no group to validate
            // against, so accepting it here would let a direct caller bypass
            // the requirement. Ordinary events without `h` are unaffected.
            if is_group_action(event) {
                bail!("invalid: group events must carry an h tag");
            }
            return Ok(());
        };
        // A ghosted id must never be resurrected by a create: its create
        // event is gone while survivors may still be stored, so a fresh
        // default-public group would expose their (possibly private)
        // content. The `deleted` tombstone is different: the relay purged
        // the group's events when the `9008` was applied (and only a
        // confirmed purge leaves the id as `deleted`), so clearing that
        // tombstone on a create is safe.
        if self.ghost.contains(gid) {
            bail!("blocked: the group has been deleted");
        }
        if self.deleted.contains(gid) {
            // A deleted id stays closed except for a fresh create: the
            // tombstone blocks every other write, but legitimate re-creation
            // with the same id must remain possible (the create clears the
            // marker in `apply`). Without this an id could never be reused.
            if event.kind == CREATE_GROUP {
                if self.at_capacity() {
                    bail!("restricted: group limit reached");
                }
                return Ok(());
            }
            bail!("blocked: the group has been deleted");
        }
        let Some(group) = self.groups.get(gid) else {
            // Unknown groups are open: only a create-group event may target
            // them explicitly. A JOIN to a group that does not exist (yet)
            // would be stored but never honored (the state machine has no
            // group to admit the user into), so it is rejected here like
            // every other moderation event for an unknown group.
            if event.kind == CREATE_GROUP {
                if self.at_capacity() {
                    bail!("restricted: group limit reached");
                }
                return Ok(());
            }
            bail!("restricted: unknown group");
        };
        let pubkey = event.pubkey.as_str();
        // The relay's own key is the group master key for moderation events
        // (see `validate_write_for_relay`): it is accepted even when no
        // group admin remains.
        let relay_signed = relay_pubkey.is_some_and(|pk| pk.eq_ignore_ascii_case(pubkey));

        if event.kind == JOIN {
            if group.is_member(pubkey) {
                bail!("duplicate: you are already a member of this group");
            }
            // Bound the member map like pins and invites: an uncapped
            // group would let joins grow mirrored state without limit.
            if group.members.len() >= MAX_MEMBERS {
                bail!("restricted: the group is full");
            }
            // The global budget caps the total member map across groups.
            if self.at_member_capacity(1) {
                bail!("restricted: the relay member limit is reached");
            }
            if group.settings.closed {
                // NIP-29: `closed` means join requests are ignored — the
                // request is rejected (final) and not stored. Admission to
                // a closed group happens via an invite code or a kind:9000
                // issued by an admin.
                //
                // The `code` tag is optional preauthorization (NIP-29): on
                // a closed group a JOIN must carry a valid invite code.
                // NIP-29: the rejection message SHOULD explain whether the
                // decision is final or pending — this relay has no pending
                // flow, so every rejection is marked final.
                if let Some(code) = event_code(event) {
                    if !group.has_invite(code) {
                        bail!("restricted: invalid invite code (final decision)");
                    }
                    return Ok(());
                }
                bail!("restricted: this group is closed (final decision)");
            }
            // NIP-29: omitting the `closed` tag means join requests are
            // honored; the relay admits the user right away. A `code` tag
            // on an open group is irrelevant to admission (an unknown or
            // stale code must not block an otherwise-honored join).
            return Ok(());
        }

        if event.kind == LEAVE {
            // NIP-29: "Any user can send one of these events to the relay in
            // order to be automatically removed from the group." There is no
            // admin exception: even the group's last admin may leave. The
            // group then has no admins and can only be managed by the relay's
            // own key.
            return Ok(());
        }

        if (MOD_MIN..=MOD_MAX).contains(&event.kind) {
            if !relay_signed && !group.is_admin(pubkey) {
                bail!("restricted: you are not an admin of this group");
            }
            if event.kind == 9002 {
                validate_edit_metadata(self, gid, group, event, relay_signed)?;
            }
            // NIP-29 allows the relay to limit pins: bound the 9010 list
            // so one event cannot pin unbounded state (the apply side caps
            // too, for history replayed without validation).
            if event.kind == 9010
                && event
                    .tags
                    .iter()
                    .filter(|t| t.len() >= 2 && (t[0] == E || t[0] == A))
                    .count()
                    > MAX_PINS
            {
                bail!("restricted: too many pinned events");
            }
            // Invite codes accumulate without consumption: bound the 9009
            // additions so repeated events cannot grow the set without
            // limit (the apply side stops inserting at the same bound).
            // Deduplicated like the 9000 member count below: the apply
            // side inserts into a set, so counting occurrences would
            // reject an event the apply would allow.
            if event.kind == 9009 {
                let fresh = tag_values(event, CODE)
                    .filter(|c| !group.has_invite(c))
                    .collect::<std::collections::HashSet<_>>()
                    .len();
                if group.invites.len().saturating_add(fresh) > MAX_INVITES {
                    bail!("restricted: too many invite codes");
                }
            }
            // Bound the member map: count fresh pubkeys (not already
            // members) so one 9000 cannot add unbounded members.
            if event.kind == 9000 {
                let fresh = event
                    .tags
                    .iter()
                    .filter(|t| t.len() >= 2 && t[0] == P)
                    .map(|t| t[1].as_str())
                    .filter(|pk| !group.is_member(pk))
                    .collect::<std::collections::HashSet<_>>()
                    .len();
                if group.members.len().saturating_add(fresh) > MAX_MEMBERS {
                    bail!("restricted: too many group members");
                }
                // The per-group cap does not bound the total across groups:
                // the global budget does.
                if self.at_member_capacity(fresh) {
                    bail!("restricted: the relay member limit is reached");
                }
            }
            // NIP-29: the group must retain at least one admin — a 9000
            // without roles could silently demote the last admin, and a
            // 9001 could remove them, leaving the group unmanageable
            // (nobody could then issue 9000/9001/9002 again). A member's own
            // LEAVE is exempt (NIP-29: any user may leave), so an admin-less
            // group is possible; the relay's own key can still manage it.
            let admin_removed: HashSet<String> = match event.kind {
                9000 => event
                    .tags
                    .iter()
                    // A `p` tag without roles (len == 2) or with an
                    // all-empty role list (`["p", pk, ""]`) demotes the
                    // subject: both must count as admin removal.
                    .filter(|t| t.len() >= 2 && t[0] == P && t[2..].iter().all(|r| r.is_empty()))
                    .map(|t| t[1].clone())
                    .collect(),
                9001 => tag_values(event, P).map(str::to_string).collect(),
                _ => HashSet::new(),
            };
            if event.kind == 9000 {
                // A `p` tag with roles only replaces roles (never removes
                // the user); a `p` tag without roles demotes. An
                // all-empty role list (`["p", pk, ""]`) is a demotion: the
                // apply side drops empty roles, so it must not count as a
                // role grant (which would bypass the last-admin guard).
                // The apply side processes the p tags *in order*, each
                // overwriting the member's roles, so the *final* state
                // decides: simulate it (e.g. `["p", A, "mod"], ["p", A]`
                // ends with A demoted even though a grant is present).
                // Simulate only the p-tag targets: cloning the whole member
                // map (up to MAX_MEMBERS = 10k entries) for every 9000
                // event was O(members) memory/CPU per moderation event.
                let mut overrides: HashMap<&str, bool> = HashMap::new();
                for tag in event.tags.iter().filter(|t| t.len() >= 2 && t[0] == P) {
                    let pk = tag[1].as_str();
                    let has_roles = tag[2..].iter().any(|r| !r.is_empty());
                    overrides.insert(pk, has_roles);
                }
                let retains_admin = group.members.iter().any(|(pk, roles)| {
                    overrides
                        .get(pk.as_str())
                        .copied()
                        .unwrap_or(!roles.is_empty())
                }) || overrides.values().any(|has| *has);
                if !retains_admin {
                    bail!("restricted: the group must retain at least one admin");
                }
                return Ok(());
            }
            let retains_admin = group
                .members
                .iter()
                .any(|(pk, roles)| !roles.is_empty() && !admin_removed.contains(pk));
            if !retains_admin {
                bail!("restricted: the group must retain at least one admin");
            }
            return Ok(());
        }

        if group.settings.restricted && !group.is_member(pubkey) {
            bail!("restricted: only group members can post");
        }
        if let Some(kinds) = &group.settings.supported_kinds
            && !kinds.contains(&event.kind)
        {
            bail!("restricted: this kind is not supported by the group");
        }
        Ok(())
    }

    /// Applies a stored event to the group state and returns the unsigned
    /// relay-generated events to publish (empty when `emit` is false, e.g.
    /// during startup rebuild). `ignore_capacity` lets the startup rebuild
    /// restore every group that was actually stored: a group dropped by the
    /// capacity limit must not become "unknown" (its private content would
    /// turn world-readable), and the limit still applies to new creations
    /// at runtime.
    pub fn apply(
        &mut self,
        event: &Event,
        relay_pubkey: &str,
        now: u64,
        emit: bool,
        ignore_capacity: bool,
    ) -> Vec<Event> {
        let Some(gid) = group_id(event) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        match event.kind {
            JOIN => {
                // Joined via a valid invite code on a closed group, or
                // honored on an open group (not `closed`): the `code` tag
                // is optional preauthorization and irrelevant to admission
                // on open groups. A closed group without a valid code
                // leaves the request pending for an admin to review.
                let admitted = self.groups.get(gid).is_some_and(|g| {
                    if g.settings.closed {
                        event_code(event).is_some_and(|code| g.has_invite(code))
                    } else {
                        true
                    }
                });
                if admitted {
                    let member = event.pubkey.clone();
                    let mut added = false;
                    if let Some(group) = self.groups.get_mut(gid) {
                        // Membership is the entry in the member map; roles
                        // (granted only via `kind:9000`) decide privileges.
                        // Bounded like validation (history replay bypasses
                        // the check above, so re-check here). The global
                        // member budget is bypassed on history replay
                        // (`ignore_capacity`): dropping a stored membership
                        // would change what the restart rebuilds.
                        let over_global = !ignore_capacity
                            && self.max_total_members > 0
                            && self.total_members >= self.max_total_members
                            && !group.is_member(&member);
                        if !over_global
                            && (group.members.len() < MAX_MEMBERS || group.is_member(&member))
                            && !group.is_member(&member)
                        {
                            group.members.insert(member.clone(), Default::default());
                            added = true;
                        }
                    }
                    if added {
                        self.total_members = self.total_members.saturating_add(1);
                    }
                    if emit {
                        out.push(build_put_user(gid, &member, &[], relay_pubkey, now));
                        out.extend(self.membership_events(gid, relay_pubkey, now));
                    }
                }
            }
            LEAVE => {
                let member = event.pubkey.clone();
                let removed = if let Some(group) = self.groups.get_mut(gid) {
                    group.members.remove(&member).is_some()
                } else {
                    false
                };
                if removed {
                    self.total_members = self.total_members.saturating_sub(1);
                }
                if emit && removed {
                    out.push(build_remove_user(gid, &member, relay_pubkey, now));
                    out.extend(self.membership_events(gid, relay_pubkey, now));
                }
            }
            9000 => {
                let mut added = 0usize;
                if let Some(group) = self.groups.get_mut(gid) {
                    // Re-check the last-admin invariant under the write
                    // lock, like the 9001 arm below: two concurrent 9000
                    // demotions can both pass the read-side validation and
                    // otherwise leave the group admin-less.
                    if !ignore_capacity {
                        // Runtime only: a rebuild replays stored history in
                        // a deterministic order that can differ from the
                        // arrival order (same second, id order), and
                        // dropping a demotion that was valid when accepted
                        // would resurrect the admin after a restart.
                        let mut overrides: HashMap<&str, bool> = HashMap::new();
                        for tag in event.tags.iter().filter(|t| t.len() >= 2 && t[0] == P) {
                            let has_roles = tag[2..].iter().any(|r| !r.is_empty());
                            overrides.insert(tag[1].as_str(), has_roles);
                        }
                        // The retention check must only count grants the
                        // apply loop below will actually insert: a fresh
                        // grant skipped at the group or global member cap
                        // would otherwise "retain" an admin that does not
                        // exist, and the demotion of the real last admin
                        // would leave the group admin-less. Simulate the
                        // loop's capacity decisions in tag order.
                        let mut group_room = MAX_MEMBERS.saturating_sub(group.members.len());
                        let mut global_room = if self.max_total_members > 0 {
                            self.max_total_members.saturating_sub(self.total_members)
                        } else {
                            usize::MAX
                        };
                        let mut inserted: HashSet<&str> = HashSet::new();
                        for tag in event.tags.iter().filter(|t| t.len() >= 2 && t[0] == P) {
                            let pk = tag[1].as_str();
                            if group.is_member(pk) || inserted.contains(pk) {
                                continue;
                            }
                            if group_room > 0 && global_room > 0 {
                                inserted.insert(pk);
                                group_room -= 1;
                                global_room -= 1;
                            }
                        }
                        let retains_admin = group.members.iter().any(|(pk, roles)| {
                            overrides
                                .get(pk.as_str())
                                .copied()
                                .unwrap_or(!roles.is_empty())
                        }) || inserted
                            .iter()
                            .any(|pk| overrides.get(*pk).copied().unwrap_or(false));
                        if !retains_admin {
                            // Drop the demotion: the event itself still
                            // stores, but the group keeps its last admin
                            // (the relay key can manage the group anyway).
                            return Vec::new();
                        }
                    }
                    // NIP-29: roles are carried as the elements after the
                    // pubkey in each `p` tag (["p", <pubkey>, <role>...]).
                    // The listed roles replace the user's previous roles
                    // ("the user roles must just be updated"), and a `p` tag
                    // without roles leaves the user a plain member.
                    for tag in event.tags.iter().filter(|t| t.len() >= 2 && t[0] == P) {
                        // Bounded like validation (see above). The global
                        // budget re-check is runtime-only (history replay
                        // must not drop stored members).
                        if group.members.len() >= MAX_MEMBERS && !group.is_member(&tag[1]) {
                            continue;
                        }
                        // Count members added earlier in this same event:
                        // `total_members` only grows after the loop, so a
                        // bare `>=` check would admit N fresh members past
                        // a nearly-full budget (concurrent fill between
                        // validation and apply makes the stale read real).
                        let over_global = !ignore_capacity
                            && self.max_total_members > 0
                            && self.total_members.saturating_add(added) >= self.max_total_members
                            && !group.is_member(&tag[1]);
                        if over_global {
                            continue;
                        }
                        let pk = tag[1].clone();
                        // An empty role element (`["p", pk, ""]`) is a
                        // malformed demotion: it must not turn into an
                        // admin grant (an empty-string role is non-empty).
                        let roles: HashSet<String> =
                            tag[2..].iter().filter(|r| !r.is_empty()).cloned().collect();
                        // An empty role list leaves the user a plain member
                        // (replacing any previous roles).
                        if !group.members.contains_key(&pk) {
                            added += 1;
                        }
                        group.members.insert(pk, roles);
                    }
                }
                if added > 0 {
                    self.total_members = self.total_members.saturating_add(added);
                }
                if emit {
                    out.extend(self.membership_events(gid, relay_pubkey, now));
                }
            }
            9001 => {
                let mut removed = 0usize;
                if let Some(group) = self.groups.get_mut(gid) {
                    // The last-admin invariant is validated under a read
                    // lock before the store; re-check it here under the
                    // write lock, or two concurrent 9001 events removing
                    // each other's admin could both pass validation and
                    // leave the group admin-less.
                    let removing: Vec<&str> = tag_values(event, P).collect();
                    let retains_admin = group
                        .members
                        .iter()
                        .any(|(pk, roles)| !roles.is_empty() && !removing.contains(&pk.as_str()));
                    if !ignore_capacity && !retains_admin {
                        // Drop the removal at runtime: the event itself
                        // still stores, but the group keeps its last admin
                        // (the relay key can manage the group regardless).
                        // A rebuild must replay what was stored instead
                        // (see the 9000 arm).
                        return Vec::new();
                    }
                    for pk in removing {
                        if group.members.remove(pk).is_some() {
                            removed += 1;
                        }
                    }
                }
                if removed > 0 {
                    self.total_members = self.total_members.saturating_sub(removed);
                }
                if emit {
                    out.extend(self.membership_events(gid, relay_pubkey, now));
                }
            }
            9002 => {
                // Re-check the graph invariants under the write lock: two
                // concurrent 9002 edits can each pass the read-side
                // validation against the same state and then interleave
                // into a cycle, drop a child another edit just adopted, or
                // reparent through an admin whose role was revoked in
                // between (the same TOCTOU the 9000/9001 arms close for the
                // last-admin invariant). A rebuild replays already-validated
                // history, so the re-check is runtime-only.
                if !ignore_capacity && let Some(group) = self.groups.get(gid) {
                    let relay_signed =
                        !relay_pubkey.is_empty() && event.pubkey.eq_ignore_ascii_case(relay_pubkey);
                    if validate_edit_metadata(self, gid, group, event, relay_signed).is_err() {
                        return Vec::new();
                    }
                }
                let (parent_before, parent_after, children_before, children_after) = {
                    match self.groups.get_mut(gid) {
                        Some(group) => {
                            apply_settings(group, event);
                            let children_before = group.children.clone();
                            // Deduplicate while preserving order: a repeated
                            // `child` tag must not list the same child twice.
                            let mut seen = HashSet::new();
                            group.children = tag_values(event, "child")
                                .map(str::to_string)
                                .filter(|c| seen.insert(c.clone()))
                                .collect();
                            let before = group.parent.clone();
                            let after = tag_value(event, "parent").map(str::to_string);
                            (before, after, children_before, group.children.clone())
                        }
                        None => (None, None, Vec::new(), Vec::new()),
                    }
                };
                // Keep the adoption hint current: a declared child id makes
                // a later CREATE_GROUP scan for the (deterministically
                // smallest) adopting parent. The hint is bounded (see
                // `declare_child`).
                for child in children_after {
                    self.declare_child(&child);
                }
                let mut linked_to_new_parent = false;
                if parent_before != parent_after {
                    if let Some(old) = parent_before.clone()
                        && let Some(parent_group) = self.groups.get_mut(&old)
                    {
                        parent_group.children.retain(|c| c != gid);
                    }
                    if let Some(new) = &parent_after
                        && let Some(parent_group) = self.groups.get_mut(new)
                        && !parent_group.children.iter().any(|c| c == gid)
                    {
                        parent_group.children.push(gid.to_string());
                        linked_to_new_parent = true;
                    }
                    if let Some(group) = self.groups.get_mut(gid) {
                        group.parent = parent_after.clone();
                    }
                }
                if linked_to_new_parent {
                    self.declare_child(gid);
                }
                // The parent side of the link: a `child` tag on the
                // parent's 9002 declares a child (the child's own `parent`
                // tag is its side of the link). The declared list replaces
                // the previous children; the parent back-pointer of the
                // removed children is cleared, and the added children get
                // their back-pointer set, keeping the two directions
                // consistent.
                let child_added: Vec<String> =
                    tag_values(event, "child").map(str::to_string).collect();
                let added_set: std::collections::HashSet<&str> =
                    child_added.iter().map(String::as_str).collect();
                let mut child_removed: Vec<String> = Vec::new();
                for child in &children_before {
                    if !added_set.contains(child.as_str()) {
                        child_removed.push(child.clone());
                    }
                }
                for child in &child_added {
                    let old_parent = self.groups.get(child).and_then(|g| g.parent.clone());
                    if old_parent.as_deref() == Some(gid) {
                        continue;
                    }
                    // A child that currently belongs to another parent is
                    // moved, not just listed: validation required the author
                    // to administer the child too, and NIP-29 keeps both
                    // sides of the link consistent ("and vice-versa"). The
                    // old parent's list is updated and republished as well.
                    if let Some(old) = old_parent.as_ref()
                        && let Some(old_group) = self.groups.get_mut(old)
                    {
                        old_group.children.retain(|c| c != child);
                    }
                    if let Some(child_group) = self.groups.get_mut(child) {
                        child_group.parent = Some(gid.to_string());
                    }
                    // The child's metadata changed (its parent tag): republish
                    // it so peers see the new link.
                    if emit {
                        if let Some(old) = &old_parent {
                            out.push(build_meta_event(
                                old,
                                self.groups.get(old),
                                relay_pubkey,
                                now,
                            ));
                        }
                        out.push(build_meta_event(
                            child,
                            self.groups.get(child),
                            relay_pubkey,
                            now,
                        ));
                    }
                }
                for child in &child_removed {
                    if let Some(child_group) = self.groups.get_mut(child)
                        && child_group.parent.as_deref() == Some(gid)
                    {
                        child_group.parent = None;
                        if emit {
                            out.push(build_meta_event(
                                child,
                                self.groups.get(child),
                                relay_pubkey,
                                now,
                            ));
                        }
                    }
                }
                if emit {
                    out.push(build_meta_event(
                        gid,
                        self.groups.get(gid),
                        relay_pubkey,
                        now,
                    ));
                    if let Some(parent) = self.groups.get(gid).and_then(|g| g.parent.clone()) {
                        out.push(build_meta_event(
                            &parent,
                            self.groups.get(&parent),
                            relay_pubkey,
                            now,
                        ));
                    }
                    // The old parent's children list changed too: its
                    // metadata must be republished or the stored event
                    // keeps listing this group as a child.
                    if parent_before != parent_after
                        && let Some(old) = parent_before
                    {
                        out.push(build_meta_event(
                            &old,
                            self.groups.get(&old),
                            relay_pubkey,
                            now,
                        ));
                    }
                    for child in self
                        .groups
                        .get(gid)
                        .map(|g| g.children.clone())
                        .unwrap_or_default()
                    {
                        out.push(build_meta_event(
                            &child,
                            self.groups.get(&child),
                            relay_pubkey,
                            now,
                        ));
                    }
                }
            }
            9005 => {
                // The referenced events are deleted by the relay itself.
            }
            CREATE_GROUP => {
                let mut adopted_parent = None;
                if !self.groups.contains_key(gid) && (ignore_capacity || !self.at_capacity()) {
                    // A fresh create resurrects an explicitly deleted id:
                    // clear the delete tombstone so the id is reusable. The
                    // deleted group's events were purged by the relay when
                    // the `9008` was applied, so re-creation starts from an
                    // empty history (no old private content can surface
                    // under the new, default-public settings). A ghost is
                    // deliberately NOT cleared: its create was lost while
                    // survivors may remain stored, so reviving it as a
                    // default-public group would expose them. Validation
                    // rejects such creates; this arm stays fail-closed for
                    // replays that bypass validation.
                    self.deleted.remove(gid);
                    let mut group = Group::default();
                    group
                        .members
                        .entry(event.pubkey.clone())
                        .or_default()
                        .insert("admin".into());
                    // A group that already declared this id as a child
                    // (a placeholder: the child did not exist yet) adopts
                    // it now, keeping both sides of the parent link
                    // consistent. Only a declared id pays the scan (the
                    // hint is kept by the 9002 arm), so an uncapped store
                    // does not turn n creates into O(n²); the smallest
                    // declaring parent wins deterministically when several
                    // groups declared the same placeholder id.
                    if self.declared_children.contains(gid) {
                        adopted_parent = self
                            .groups
                            .iter()
                            .filter(|(_, g)| g.children.iter().any(|c| c == gid))
                            .map(|(id, _)| id.clone())
                            .min();
                        if let Some(parent) = &adopted_parent {
                            group.parent = Some(parent.clone());
                        }
                    }
                    self.groups.insert(gid.to_string(), group);
                    self.total_members = self.total_members.saturating_add(1);
                    if emit && let Some(parent) = &adopted_parent {
                        // The adopting parent's stored metadata must name
                        // the now-existing child: its stored 39000 may have
                        // been built while the id was only a placeholder.
                        out.push(build_meta_event(
                            parent,
                            self.groups.get(parent),
                            relay_pubkey,
                            now,
                        ));
                    }
                }
                if emit && self.groups.contains_key(gid) {
                    // Emit only for a live group: a create blocked by the
                    // capacity cap (two concurrent creates racing past the
                    // read-side validation, like the 9000/9001 write-lock
                    // re-checks that drop instead) must not store or
                    // broadcast bare metadata for a group that was never
                    // created. A duplicate create for an existing group
                    // still republishes its metadata below.
                    out.push(build_meta_event(
                        gid,
                        self.groups.get(gid),
                        relay_pubkey,
                        now,
                    ));
                    out.extend(self.membership_events(gid, relay_pubkey, now));
                }
            }
            DELETE_GROUP => {
                if let Some(group) = self.groups.remove(gid) {
                    self.total_members = self.total_members.saturating_sub(group.members.len());
                    // The throttle stamp belongs to the deleted incarnation:
                    // without this a delete+create cycle within the window
                    // would skip the fresh 39002, and dead entries would
                    // accumulate alongside the delete tombstones.
                    self.members_published_at.remove(gid);
                    // Children become roots.
                    for child in group.children {
                        if let Some(child_group) = self.groups.get_mut(&child) {
                            child_group.parent = None;
                            if emit {
                                out.push(build_meta_event(
                                    &child,
                                    Some(child_group),
                                    relay_pubkey,
                                    now,
                                ));
                            }
                        }
                    }
                    // The deleted group leaves its parent's child list.
                    if let Some(parent) = group.parent
                        && let Some(parent_group) = self.groups.get_mut(&parent)
                    {
                        parent_group.children.retain(|c| c != gid);
                        if emit {
                            out.push(build_meta_event(
                                &parent,
                                Some(parent_group),
                                relay_pubkey,
                                now,
                            ));
                        }
                    }
                }
                self.deleted.insert(gid.to_string());
            }
            9009 => {
                if let Some(group) = self.groups.get_mut(gid) {
                    for code in tag_values(event, CODE) {
                        // Bounded like validation (history replay bypasses
                        // the check above, so stop inserting at the cap).
                        if group.invites.len() >= MAX_INVITES {
                            break;
                        }
                        group.invites.insert(code.to_string());
                    }
                }
            }
            9010 => {
                // Bounded like validation (history replay bypasses the
                // check above, so cap here too).
                if let Some(group) = self.groups.get_mut(gid) {
                    group.pins = event
                        .tags
                        .iter()
                        .filter(|t| t.len() >= 2 && (t[0] == E || t[0] == A))
                        .map(|t| (t[0].clone(), t[1].clone()))
                        .take(MAX_PINS)
                        .collect();
                }
                if emit {
                    out.push(build_pins_event(
                        gid,
                        self.groups.get(gid),
                        relay_pubkey,
                        now,
                    ));
                }
            }
            // No 9011: the current NIP-29 defines no remove-pin kind —
            // pinning, unpinning, reordering and clearing are all done by
            // submitting a new kind:9010 list. A stray 9011 is an inert
            // unknown moderation event (admin-gated by the 9000-9020
            // window, stored, and replayed as such after a restart).
            _ => {}
        }
        out
    }

    /// Whether a stored event may be served to `authed` (NIP-29 read access).
    pub fn visible_to(&self, event: &Event, authed: Option<&str>) -> bool {
        let Some(gid) = group_id_any(event) else {
            return true;
        };
        let is_meta = (GROUP_META..=GROUP_PINS).contains(&event.kind);
        self.visible_gid(gid, is_meta, authed)
    }

    /// Whether `event` belongs to a membership-gated group (`private`
    /// groups, or `hidden` groups' relay-generated metadata) — i.e. AUTH as
    /// a member could reveal it. Deleted, ghost and unknown groups are not
    /// AUTH-revealable: their content stays gone for everyone. Drives the
    /// NIP-67 `"auth"` EOSE hint.
    pub fn privacy_gated(&self, event: &Event) -> bool {
        let Some(gid) = group_id_any(event) else {
            return false;
        };
        if self.deleted.contains(gid) || self.ghost.contains(gid) {
            return false;
        }
        let is_meta = (GROUP_META..=GROUP_PINS).contains(&event.kind);
        self.groups
            .get(gid)
            .is_some_and(|g| (g.settings.private && !is_meta) || (g.settings.hidden && is_meta))
    }

    /// Whether the content of a group may be served to `authed`. `is_meta`
    /// distinguishes relay-generated metadata events (kinds 39000-39005),
    /// which `hidden` groups additionally withhold from non-members.
    /// Group ids that must stay hidden across a rebuild: the live groups
    /// (which the vanish may have removed), the existing ghosts and the
    /// delete tombstones. A rebuild must carry them so a second vanish
    /// rebuild cannot un-ghost a group whose state is already gone.
    pub fn hidden_group_ids(&self) -> Vec<String> {
        self.groups
            .keys()
            .cloned()
            .chain(self.ghost.iter().cloned())
            .chain(self.deleted.iter().cloned())
            .collect()
    }

    /// The delete tombstones (confirmed-purged ids). A rebuild must carry
    /// them so a confirmed purge stays re-creatable: the `9008` (and its
    /// purge marker) removed the group's events from the database, so the
    /// scan cannot reconstruct the tombstone on its own.
    pub(crate) fn deleted_group_ids(&self) -> Vec<String> {
        self.deleted.iter().cloned().collect()
    }

    /// The ghost markers (fail-closed ids whose history may survive). A
    /// rebuild must carry them so an unconfirmed purge keeps withholding
    /// the id's content even when the scan reconstructs part of it.
    pub(crate) fn ghost_group_ids(&self) -> Vec<String> {
        self.ghost.iter().cloned().collect()
    }

    /// Removes `pubkey` from every group's member map (a vanish) and keeps
    /// the global member counter in sync. Returns whether any membership
    /// was removed.
    pub fn remove_member_everywhere(&mut self, pubkey: &str) -> bool {
        let mut removed = 0usize;
        for group in self.groups.values_mut() {
            if group.members.remove(pubkey).is_some() {
                removed += 1;
            }
        }
        if removed > 0 {
            self.total_members = self.total_members.saturating_sub(removed);
            true
        } else {
            false
        }
    }

    /// Re-seeds the hidden markers captured before a rebuild and ghosts
    /// every previous id the rebuilt store no longer knows (see
    /// [`Self::ghost_missing`]). The delete tombstones must be restored
    /// (the scan cannot see an id whose events were purged), while a live
    /// group is never pre-marked deleted: a create accepted while the scan
    /// ran replays afterwards and legitimately resurrects the id.
    pub fn restore_hidden(
        &mut self,
        previous: impl IntoIterator<Item = String>,
        previous_deleted: impl IntoIterator<Item = String>,
        previous_ghost: impl IntoIterator<Item = String>,
    ) {
        for gid in previous_ghost {
            self.ghost.insert(gid);
        }
        for gid in previous_deleted {
            if !self.groups.contains_key(&gid) {
                self.deleted.insert(gid);
            }
        }
        self.ghost_missing(previous);
    }

    /// Marks every `previous` group id that the (rebuilt) store no longer
    /// knows — and that was not explicitly deleted — as a ghost: its
    /// create/state is gone, so on a keyless relay its surviving posts
    /// must be withheld instead of turning world-readable. The vanish
    /// rebuild seeds this from the pre-rebuild state, which catches the
    /// "creator vanished, only ordinary posts survived" case that the
    /// moderation-event scan cannot see.
    pub fn ghost_missing(&mut self, previous: impl IntoIterator<Item = String>) {
        for gid in previous {
            if !self.groups.contains_key(&gid) && !self.deleted.contains(&gid) {
                self.ghost.insert(gid);
            }
        }
    }

    pub fn visible_gid(&self, gid: &str, is_meta: bool, authed: Option<&str>) -> bool {
        // Content of a deleted group is never served: the group is gone,
        // and its (possibly private) history must not become readable by
        // everyone.
        if self.deleted.contains(gid) {
            return false;
        }
        // A group whose create event was lost (creator vanished, 9007
        // deleted or expired) cannot be restored with its settings: treat
        // it as gone so its surviving content is not served to everyone.
        if self.ghost.contains(gid) {
            return false;
        }
        let Some(group) = self.groups.get(gid) else {
            return true;
        };
        let member = authed.is_some_and(|pk| group.is_member(pk));
        // NIP-29: `private` restricts the group MESSAGES to members; the
        // metadata stays readable (it is not the private content). `hidden`
        // additionally hides the relay-generated metadata from non-members.
        if group.settings.private && !member && !is_meta {
            return false;
        }
        if group.settings.hidden && is_meta && !member {
            return false;
        }
        true
    }

    fn membership_events(&mut self, gid: &str, relay_pubkey: &str, now: u64) -> Vec<Event> {
        /// Groups up to this many members always get a fresh 39002.
        const MEMBERS_EAGER_MAX: usize = 1000;
        /// Larger groups get it at most once per this many seconds.
        const MEMBERS_INTERVAL_SECS: u64 = 60;
        let mut out = vec![build_admins_event(
            gid,
            self.groups.get(gid),
            relay_pubkey,
            now,
        )];
        let members = self.groups.get(gid).map(|g| g.members.len()).unwrap_or(0);
        let due = members <= MEMBERS_EAGER_MAX
            || self
                .members_published_at
                .get(gid)
                .is_none_or(|last| now.saturating_sub(*last) >= MEMBERS_INTERVAL_SECS);
        if due {
            self.members_published_at.insert(gid.to_string(), now);
            out.push(build_members_event(
                gid,
                self.groups.get(gid),
                relay_pubkey,
                now,
            ));
        }
        out
    }

    /// Builds the relay-signed metadata events (39000/39001/39002/39005)
    /// for every live group. Used after a rebuild from stored events: a
    /// database whose state was rebuilt — a migration from another relay,
    /// or a dropped snapshot — has no (or stale) stored metadata, and
    /// clients need it to display the groups.
    pub(crate) fn all_metadata_events(&mut self, relay_pubkey: &str, now: u64) -> Vec<Event> {
        let gids: Vec<String> = self.groups.keys().cloned().collect();
        let mut out = Vec::with_capacity(gids.len().saturating_mul(4));
        for gid in gids {
            out.push(build_meta_event(
                &gid,
                self.groups.get(&gid),
                relay_pubkey,
                now,
            ));
            out.push(build_pins_event(
                &gid,
                self.groups.get(&gid),
                relay_pubkey,
                now,
            ));
            out.extend(self.membership_events(&gid, relay_pubkey, now));
        }
        out
    }

    /// Rebuilds the in-memory group state from the stored events.
    ///
    /// Returns `false` when the rebuild could not be completed (the database
    /// did not answer, or a page boundary could not be verified): the
    /// caller must not persist or serve the partially-rebuilt store (missing
    /// groups turn private content world-readable) and aborts startup.
    ///
    /// This is the snapshot-less path (a new database, a legacy migration,
    /// or a crash after a vanish dropped the snapshot): the complete set of
    /// group ids is unknown, so besides the moderation history the rebuild
    /// walks the stored events to find the ids referenced by ordinary
    /// `h`-tagged posts. A group whose create/moderation events are gone —
    /// while ordinary posts survive — would otherwise be invisible and its
    /// (possibly private) content would turn world-readable. There is no
    /// index for "any event with an h tag", so that costs one bounded
    /// full-history pass; it only runs when no prior id set exists (the
    /// post-vanish rebuild seeds the ids from the pre-rebuild state instead,
    /// see [`Self::rebuild_after_vanish`]).
    ///
    /// The walks stream the history in pages, so memory stays bounded by
    /// one page instead of the whole history (the old implementation
    /// materialized and sorted every stored group event before applying
    /// anything).
    pub async fn rebuild(&mut self, db: &DbClient, relay_pubkey: Option<&str>) -> bool {
        self.rebuild_inner(db, relay_pubkey, None, Vec::new(), Vec::new())
            .await
    }

    /// Rebuilds after a vanish, seeding the hidden markers from the
    /// pre-rebuild [`Self::hidden_group_ids`], [`Self::deleted_group_ids`]
    /// and [`Self::ghost_group_ids`]: every group id that existed before
    /// the vanish is known, so any id missing from the rebuilt store is
    /// ghosted from the seed, and the delete tombstones (whose events the
    /// purge removed, so the scan cannot reconstruct them) are restored so
    /// a confirmed purge stays re-creatable. The full-history ordinary pass
    /// of [`Self::rebuild`] is unnecessary here and is skipped: the vanish
    /// accept path must not pay for a full table scan.
    pub async fn rebuild_after_vanish(
        &mut self,
        db: &DbClient,
        relay_pubkey: Option<&str>,
        previous: Vec<String>,
        previous_deleted: Vec<String>,
        previous_ghost: Vec<String>,
    ) -> bool {
        self.rebuild_inner(
            db,
            relay_pubkey,
            Some(previous),
            previous_deleted,
            previous_ghost,
        )
        .await
    }

    async fn rebuild_inner(
        &mut self,
        db: &DbClient,
        relay_pubkey: Option<&str>,
        previous: Option<Vec<String>>,
        previous_deleted: Vec<String>,
        previous_ghost: Vec<String>,
    ) -> bool {
        // 9021 JOIN is included so that honored joins survive a restart even
        // on relays without a private key (which never emit the relay-signed
        // 9000 put-user that would otherwise carry the membership).
        let kinds: Vec<u64> = (MOD_MIN..=MOD_MAX).chain([JOIN, LEAVE]).collect();
        // A vanished author must not be resurrected as a member by
        // replaying pre-vanish events signed by others (the vanish
        // deleted the author's own JOIN, but an admin's put-user or the
        // relay's own JOIN-time put-user survive): skip the events that
        // would add a vanished pubkey to a group.
        // Streamed into the set in bounded pages (a relay with millions of
        // vanish markers must not materialize them all at once).
        let mut vanished: std::collections::HashSet<String> = std::collections::HashSet::new();
        if db
            .vanish_pubkeys_each(|key| {
                // Both hex spellings: stored JOIN/9000 tags may predate the
                // lowercase normalization and would otherwise slip past the
                // vanish exclusion (resurrecting the member).
                vanished.insert(hex::encode(key));
                vanished.insert(hex::encode_upper(key));
            })
            .await
            .is_none()
        {
            log::error!(
                "group state rebuild aborted: the vanished-pubkey list is unavailable; \
                 refusing to persist an incomplete group store"
            );
            return false;
        }
        // Chronological replay: the ascending scan never splits a timestamp
        // across pages (it collects every event at the boundary timestamp),
        // so sorting each page by the state-machine rank and applying it
        // immediately is globally ordered exactly like the old whole-history
        // sort. Within the same second the kind is the tie-breaker: the
        // group-establishing events apply first (9007 create, 9008 delete),
        // then the member/settings operations (9000-9006, 9009-9010) which
        // need the group to exist, and joins/leaves last. Known limitation:
        // events of the same kind within the same second are ordered by id,
        // not by arrival — two conflicting 9000 edits in the same second
        // (e.g. grant-then-revoke of a role) may replay in the wrong order
        // after a restart. The relay stamps its generated metadata strictly
        // monotonic, so the *stored* 39000-39005 always reflect the latest
        // state; only the in-memory member map could diverge until the next
        // edit. The rank ordering also inverts cross-kind arrival order
        // within a second: a 9001 remove followed in the same second by a
        // 9021 JOIN replays as [9001, JOIN] (correct) but a JOIN followed by
        // a 9001 replays as [9001, JOIN] too — the removed member resurrects
        // until the next edit. Arrival order is not stored, so this cannot be
        // fixed exactly; the relay-stamped put-user (9000) events, which
        // arrive after the member operation, keep the stored 39002 list
        // correct.
        const PAGE: usize = 50_000;
        let mut since: Option<u64> = None;
        loop {
            let mut filter: Filter =
                serde_json::from_value(json!({ "kinds": kinds })).expect("static filter");
            filter.since = since;
            // `query_full_startup` gives each page the full-scan work budget
            // (not the smaller per-query one) and reports a missing reply
            // instead of degrading to an empty page; an empty page must only
            // ever mean "no more events".
            let Some((mut page, more)) = db
                .query_full_startup(vec![filter.clone()], PAGE, unix_now(), true)
                .await
            else {
                log::error!(
                    "group state rebuild aborted: the database did not answer; refusing to \
                     persist an incomplete group store"
                );
                return false;
            };
            if page.is_empty() {
                break;
            }
            if more {
                // The collector stopped early. It can stop on the count cap
                // with a full page, but also on the byte cap (64 MiB) or the
                // work budget with a short page; either way the boundary
                // second (the newest here) may be cut. Verifying it lets the
                // scan continue past it instead of failing the whole
                // rebuild; only a boundary that cannot be verified (a real
                // store error, or a second larger than the verify budget)
                // stays fatal.
                let boundary = page.last().map(|e| e.created_at).unwrap_or(0);
                let delivered = page.iter().filter(|e| e.created_at == boundary).count();
                if !boundary_second_complete(db, filter.clone(), boundary, delivered).await {
                    log::error!(
                        "group state rebuild aborted: the boundary second {boundary} is not \
                         fully collected; refusing to persist an incomplete group store"
                    );
                    return false;
                }
            }
            page.sort_by(|a, b| {
                (a.created_at, group_rank(a.kind), a.kind, &a.id).cmp(&(
                    b.created_at,
                    group_rank(b.kind),
                    b.kind,
                    &b.id,
                ))
            });
            let max_created = page.last().map(|event| event.created_at);
            for mut event in page {
                if event.kind == JOIN && vanished.contains(&event.pubkey) {
                    continue;
                }
                if event.kind == 9000 {
                    event
                        .tags
                        .retain(|t| t.len() < 2 || t[0] != P || !vanished.contains(&t[1]));
                    if event.tags.is_empty() {
                        continue;
                    }
                }
                // Every stored moderation event is replayed. The relay
                // applied it in arrival order when it was accepted, and a
                // second rebuild-time authorization would drop legitimate
                // events whose rank-ordered position differs from their
                // arrival: migrated databases are made faithful by the
                // migration itself, which refuses to import moderation its
                // own replay would reject.
                self.apply(&event, relay_pubkey.unwrap_or(""), unix_now(), false, true);
            }
            if !more {
                // The collector reported no truncation: every remaining
                // event was collected.
                break;
            }
            // The scan collects every event at the boundary timestamp, so
            // stepping past it cannot skip an event.
            match max_created {
                Some(ts) if ts < u64::MAX => since = Some(ts.saturating_add(1)),
                _ => break,
            }
        }
        // A prior id set (the post-vanish rebuild) makes the ghost detection
        // exact without touching ordinary events: every id the rebuilt store
        // no longer knows is ghosted from the seed. The delete tombstones
        // are re-seeded from the pre-rebuild state because the scan cannot
        // reconstruct an id whose events the purge removed (a confirmed
        // purge must stay re-creatable, not become a permanent ghost).
        if let Some(previous) = previous {
            self.restore_hidden(previous, previous_deleted, previous_ghost);
            return true;
        }
        // No prior id set: every group id referenced by a stored event must
        // be known or ghosted. The moderation walk above only sees the
        // state events; ordinary `h`-tagged posts (and the relay-signed
        // metadata, which uses `d` tags) are not covered by any kind filter,
        // and there is no index for "has an h tag", so this walks the whole
        // history in bounded pages (newest-first: only the ids are
        // collected, no events are retained). A page cut by the byte cap or
        // the work budget is resumed past its verified boundary second; a
        // boundary that cannot be verified aborts the rebuild (fail-closed),
        // because a silently dropped second would fail the ghost detection
        // open (private content world-readable).
        //
        // The h-tagged survivors are tracked separately: a delete tombstone
        // is normally safe (the relay purged the group's events, which
        // includes the 9008 itself), but a surviving h-tagged event proves
        // the purge never completed, so that id must be ghosted instead of
        // leaving a tombstone a fresh create could clear.
        let mut seen_gids: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut seen_h_gids: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut until: Option<u64> = None;
        loop {
            let filter = Filter {
                until,
                ..Default::default()
            };
            let Some((page, more)) = db
                .query_full_startup(vec![filter.clone()], PAGE, unix_now(), false)
                .await
            else {
                log::error!(
                    "group state rebuild aborted: the database did not answer; refusing to \
                     persist an incomplete group store"
                );
                return false;
            };
            if page.is_empty() {
                break;
            }
            let min_created = page.iter().map(|e| e.created_at).min().unwrap_or(0);
            if more {
                // The collector stopped early. A byte-cap (64 MiB) or
                // work-budget stop can cut the page below PAGE events, but
                // the boundary second (the oldest here) is verified the same
                // way: when it is fully collected the cursor may advance
                // past it and the walk continues, instead of failing the
                // whole rebuild (which would refuse to start). A boundary
                // that cannot be verified — a store error, or a second
                // larger than the verify budget — stays fatal (fail-closed).
                let delivered = page.iter().filter(|e| e.created_at == min_created).count();
                if !boundary_second_complete(db, filter.clone(), min_created, delivered).await {
                    log::error!(
                        "group state rebuild aborted: the ghost-detection boundary second \
                         {min_created} is not fully collected; the ghost detection is \
                         incomplete"
                    );
                    return false;
                }
            }
            for event in &page {
                if let Some(gid) = crate::nips::nip29::group_id(event) {
                    seen_gids.insert(gid.to_string());
                    seen_h_gids.insert(gid.to_string());
                } else if (GROUP_META..=GROUP_PINS).contains(&event.kind)
                    && let Some(gid) = crate::nips::nip29::group_id_d(event)
                {
                    // Only the relay-generated metadata kinds identify a
                    // group by `d`: every addressable event (long-form
                    // 30023, app data, ...) carries a `d` tag that must not
                    // ghost a non-existent group or consume the group
                    // budget. Mirrors `group_id_any`.
                    seen_gids.insert(gid.to_string());
                }
            }
            if !more || min_created == 0 {
                // No truncation (or the oldest second): the walk covered
                // every stored event.
                break;
            }
            until = Some(min_created - 1);
        }
        for gid in seen_gids {
            if self.groups.contains_key(&gid) {
                continue;
            }
            // A deleted id whose events are gone is safe to re-create; one
            // with h-tagged survivors is not (its purge never completed).
            if self.deleted.contains(&gid) && !seen_h_gids.contains(&gid) {
                continue;
            }
            self.ghost.insert(gid);
        }
        true
    }

    /// Fail-closed marker for a group whose stored history may still exist:
    /// the delete's purge has not been confirmed, so a later create must not
    /// restate the id as a public group (that would make the un-purged
    /// history readable) and reads stay withheld. Only a confirmed purge
    /// clears it again (see `unghost`).
    pub(crate) fn mark_ghost(&mut self, gid: &str) {
        self.ghost.insert(gid.to_string());
    }

    /// Removes a group id from the ghost set once its history is confirmed
    /// purged and downgrades it to the ordinary delete tombstone, which a
    /// fresh create may clear. The tombstone is (re-)asserted because the
    /// pending-purge resume may be the first path to confirm the purge and
    /// its in-memory state need not have applied the `9008` before.
    pub(crate) fn unghost(&mut self, gid: &str) {
        self.ghost.remove(gid);
        self.deleted.insert(gid.to_string());
    }
}

/// Replay order of group events within the same second: the create/delete
/// establish the group before the member/settings operations, joins and
/// leaves come last.
/// The same-second ordering rank used by the rebuild replay: the
/// group-establishing events (create/delete) apply first, then the
/// member/settings operations, then joins/leaves. Shared with the
/// migration's authorization replay so both orders agree.
pub(crate) fn group_rank(kind: u64) -> u8 {
    match kind {
        9007 | 9008 => 0,
        9021 | 9022 => 2,
        _ => 1,
    }
}

pub(crate) fn event_code(event: &Event) -> Option<&str> {
    tag_value(event, CODE)
}

/// Validates the subgroup rules of a `kind:9002` edit-metadata event.
/// `relay_signed` marks an event from the relay's own key, which NIP-29
/// treats as the group master key: it is an implicit admin of every group
/// (see `validate_write_for_relay`), so the group-admin requirements below
/// do not apply to it.
fn validate_edit_metadata(
    store: &GroupStore,
    gid: &str,
    _group: &Group,
    event: &Event,
    relay_signed: bool,
) -> anyhow::Result<()> {
    // NIP-29: "A kind:9002 MAY carry at most one parent tag". A second
    // parent tag would be silently ignored (only the first is applied), so
    // the edit is rejected outright instead.
    if tag_values(event, "parent").count() > 1 {
        bail!("restricted: at most one parent tag is allowed");
    }
    // A group cannot be its own child, and one 9002 must not make a
    // group both the parent and the child of this one (that would create
    // a two-way cycle the walks below cannot see: both directions would
    // be applied and every later parent edit would loop forever).
    let parent_value = tag_value(event, "parent").map(str::to_string);
    if tag_values(event, "child").any(|c| c == gid) {
        bail!("restricted: a group cannot be its own child");
    }
    if let Some(parent) = &parent_value
        && tag_values(event, "child").any(|c| c == parent)
    {
        bail!("restricted: a group cannot be both parent and child");
    }
    // The declared children must not create a cycle either: walking down
    // the children lists from the declared children must not reach this
    // group (e.g. `parent: P` together with `child: P` on a P that has no
    // parent would otherwise create a two-way cycle the upward walk
    // misses).
    for child in tag_values(event, "child") {
        // Breadth-first walk down the children lists from the declared
        // child; a visited set stops the walk on pre-existing cycles in
        // the stored data instead of looping forever.
        let mut queue: Vec<&str> = vec![child];
        let mut visited: HashSet<&str> = HashSet::new();
        while let Some(current) = queue.pop() {
            if current == gid {
                bail!("restricted: would create a cycle");
            }
            if !visited.insert(current) {
                continue;
            }
            if let Some(group) = store.groups.get(current) {
                queue.extend(group.children.iter().map(String::as_str));
            }
        }
    }
    // A parent value must not create a cycle or self-reference, and the
    // parent must exist and the author must be its admin.
    if let Some(parent) = parent_value {
        let mut cursor = Some(parent.as_str());
        let mut visited: HashSet<&str> = HashSet::new();
        while let Some(current) = cursor {
            if current == gid {
                bail!("restricted: would create a cycle");
            }
            if !visited.insert(current) {
                // A pre-existing cycle in the stored data: stop the walk
                // instead of looping forever.
                break;
            }
            cursor = store.groups.get(current).and_then(|g| g.parent.as_deref());
        }
        let parent_group = store
            .groups
            .get(&parent)
            .ok_or_else(|| anyhow!("restricted: parent group does not exist"))?;
        // The relay's own key is an implicit admin of every group (NIP-29:
        // the relay master key may manage groups), so a relay-signed 9002
        // must be able to reparent or adopt without an explicit role.
        if !relay_signed && !parent_group.is_admin(event.pubkey.as_str()) {
            bail!("restricted: you are not an admin of the parent group");
        }
    }
    // NIP-29: a metadata edit must carry every existing child as a child
    // tag, or the edit is rejected — otherwise a partial edit (e.g. only a
    // name change) would silently drop the children on the apply side,
    // which replaces the list.
    let children: HashSet<&str> = tag_values(event, "child").collect();
    if !_group
        .children
        .iter()
        .all(|c| children.contains(c.as_str()))
    {
        bail!("restricted: missing child tags in metadata edit");
    }
    // Adopting a new child through the parent's list requires authority
    // over the child too: otherwise a foreign admin could hijack an
    // orphan group by listing it (each group's own 39001 is authoritative
    // for its scope). Reordering already-linked children stays parent-only.
    // Unknown ids (no group yet) are still listable as placeholders.
    for child in tag_values(event, "child") {
        if _group.children.iter().any(|c| c == child) {
            continue;
        }
        if !relay_signed
            && let Some(child_group) = store.groups.get(child)
            && child_group.parent.as_deref() != Some(gid)
            && !child_group.is_admin(event.pubkey.as_str())
        {
            bail!("restricted: you are not an admin of the child group");
        }
    }
    // Bound the declared-children adoption hint: beyond its cap the edit is
    // refused outright instead of silently dropping the placeholder hints
    // (a repeated 9002 with fresh child ids would otherwise grow the hint
    // without limit). Mirror the apply side, which prunes entries no live
    // group lists: only the retained hint entries and the event's children
    // occupy the budget after the edit.
    let cap = store.declared_children_cap();
    let live: HashSet<&str> = store
        .groups
        .values()
        .flat_map(|group| group.children.iter().map(String::as_str))
        .collect();
    let mut declared_after: HashSet<&str> = store
        .declared_children
        .iter()
        .filter(|id| live.contains(id.as_str()))
        .map(String::as_str)
        .collect();
    declared_after.extend(tag_values(event, "child"));
    if declared_after.len() > cap {
        bail!("restricted: too many declared child groups");
    }
    Ok(())
}
