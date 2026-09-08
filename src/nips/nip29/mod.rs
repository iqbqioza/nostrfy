//! NIP-29: Relay-based Groups.
//!
//! The group state machine (access control, moderation application and
//! read visibility) lives here; the relay-generated metadata events are
//! built by the [`events`] module.

pub(crate) mod events;
#[cfg(test)]
mod tests;

use events::{
    apply_settings, build_admins_event, build_members_event, build_meta_event, build_pins_event,
    build_put_user, build_remove_user,
};

/// Moderation policy implemented here: any user with at least one role (from
/// a `kind:9000` put-user event or a `kind:9007` group creation) is an admin
/// and may send moderation events; the relay's own key is always an admin.
use std::collections::{HashMap, HashSet};

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

#[derive(Debug, Clone, Default)]
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

#[derive(Debug, Clone, Default)]
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
    /// Cap on the store size (active groups + deleted markers): bounds the
    /// in-memory state even when an attacker churns group ids. 0 =
    /// unlimited.
    max_groups: usize,
}

impl GroupStore {
    pub fn with_cap(max_groups: usize) -> GroupStore {
        GroupStore {
            max_groups,
            ..Default::default()
        }
    }

    /// Whether another group may be created. The deleted markers count
    /// toward the budget: they are kept forever (a deleted group must not
    /// be resurrectable), so an unbounded number of distinct deletions
    /// must not grow the store without limit either.
    fn at_capacity(&self) -> bool {
        self.max_groups > 0 && self.groups.len() + self.deleted.len() >= self.max_groups
    }
    pub fn group(&self, id: &str) -> Option<&Group> {
        self.groups.get(id)
    }

    /// Validates a write against the current group state. Returns the reason
    /// string for the `OK` message on rejection. Access control is based on
    /// the event's author (`event.pubkey`), not on connection authentication.
    pub fn validate_write(&self, event: &Event) -> Result<(), String> {
        let Some(gid) = group_id(event) else {
            return Ok(());
        };
        if self.deleted.contains(gid) {
            // A deleted id stays closed except for a fresh create: the
            // tombstone blocks every other write, but legitimate re-creation
            // with the same id must remain possible (the create clears the
            // marker in `apply`). Without this an id could never be reused.
            if event.kind == CREATE_GROUP {
                if self.at_capacity() {
                    return Err("restricted: group limit reached".into());
                }
                return Ok(());
            }
            return Err("blocked: the group has been deleted".into());
        }
        let Some(group) = self.groups.get(gid) else {
            // Unknown groups are open: only a create-group event may target
            // them explicitly. A JOIN to a group that does not exist (yet)
            // would be stored but never honored (the state machine has no
            // group to admit the user into), so it is rejected here like
            // every other moderation event for an unknown group.
            if event.kind == CREATE_GROUP {
                if self.at_capacity() {
                    return Err("restricted: group limit reached".into());
                }
                return Ok(());
            }
            return Err("restricted: unknown group".into());
        };
        let pubkey = event.pubkey.as_str();

        if event.kind == JOIN {
            if group.is_member(pubkey) {
                return Err("duplicate: you are already a member of this group".into());
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
                        return Err("restricted: invalid invite code (final decision)".into());
                    }
                    return Ok(());
                }
                return Err("restricted: this group is closed (final decision)".into());
            }
            // NIP-29: omitting the `closed` tag means join requests are
            // honored; the relay admits the user right away. A `code` tag
            // on an open group is irrelevant to admission (an unknown or
            // stale code must not block an otherwise-honored join).
            return Ok(());
        }

        if event.kind == LEAVE {
            // NIP-29: leaving must not remove the group's last admin
            // (nobody could then manage the group).
            let retains_admin = group
                .members
                .iter()
                .any(|(pk, roles)| !roles.is_empty() && pk != &event.pubkey);
            if !retains_admin {
                return Err("restricted: the group must retain at least one admin".into());
            }
            return Ok(());
        }

        if (MOD_MIN..=MOD_MAX).contains(&event.kind) {
            if !group.is_admin(pubkey) {
                return Err("restricted: you are not an admin of this group".into());
            }
            if event.kind == 9002 {
                validate_edit_metadata(self, gid, group, event)?;
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
                return Err("restricted: too many pinned events".into());
            }
            // Invite codes accumulate without consumption: bound the 9009
            // additions so repeated events cannot grow the set without
            // limit (the apply side stops inserting at the same bound).
            if event.kind == 9009 {
                let fresh = tag_values(event, CODE)
                    .filter(|c| !group.has_invite(c))
                    .count();
                if group.invites.len().saturating_add(fresh) > MAX_INVITES {
                    return Err("restricted: too many invite codes".into());
                }
            }
            // NIP-29: the group must retain at least one admin — a 9000
            // without roles could silently demote the last admin, and a
            // 9001/LEAVE could remove them, leaving the group unmanageable
            // (nobody could then issue 9000/9001/9002 again).
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
                let mut final_roles: HashMap<&str, bool> = group
                    .members
                    .iter()
                    .map(|(pk, roles)| (pk.as_str(), !roles.is_empty()))
                    .collect();
                for tag in event.tags.iter().filter(|t| t.len() >= 2 && t[0] == P) {
                    let pk = tag[1].as_str();
                    let has_roles = tag[2..].iter().any(|r| !r.is_empty());
                    final_roles.insert(pk, has_roles);
                }
                let retains_admin = final_roles.values().any(|admin| *admin);
                if !retains_admin {
                    return Err("restricted: the group must retain at least one admin".into());
                }
                return Ok(());
            }
            let retains_admin = group
                .members
                .iter()
                .any(|(pk, roles)| !roles.is_empty() && !admin_removed.contains(pk));
            if !retains_admin {
                return Err("restricted: the group must retain at least one admin".into());
            }
            return Ok(());
        }

        if group.settings.restricted && !group.is_member(pubkey) {
            return Err("restricted: only group members can post".into());
        }
        if let Some(kinds) = &group.settings.supported_kinds
            && !kinds.contains(&event.kind)
        {
            return Err("restricted: this kind is not supported by the group".into());
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
                    if let Some(group) = self.groups.get_mut(gid) {
                        // Membership is the entry in the member map; roles
                        // (granted only via `kind:9000`) decide privileges.
                        group.members.entry(member.clone()).or_default();
                    }
                    if emit {
                        out.push(build_put_user(gid, &member, &[], relay_pubkey, now));
                        out.extend(self.membership_events(gid, relay_pubkey, now));
                    }
                }
            }
            LEAVE => {
                let member = event.pubkey.clone();
                if let Some(group) = self.groups.get_mut(gid) {
                    group.members.remove(&member);
                }
                if emit {
                    out.push(build_remove_user(gid, &member, relay_pubkey, now));
                    out.extend(self.membership_events(gid, relay_pubkey, now));
                }
            }
            9000 => {
                if let Some(group) = self.groups.get_mut(gid) {
                    // NIP-29: roles are carried as the elements after the
                    // pubkey in each `p` tag (["p", <pubkey>, <role>...]).
                    // The listed roles replace the user's previous roles
                    // ("the user roles must just be updated"), and a `p` tag
                    // without roles leaves the user a plain member.
                    for tag in event.tags.iter().filter(|t| t.len() >= 2 && t[0] == P) {
                        let pk = tag[1].clone();
                        // An empty role element (`["p", pk, ""]`) is a
                        // malformed demotion: it must not turn into an
                        // admin grant (an empty-string role is non-empty).
                        let roles: HashSet<String> =
                            tag[2..].iter().filter(|r| !r.is_empty()).cloned().collect();
                        // An empty role list leaves the user a plain member
                        // (replacing any previous roles).
                        group.members.insert(pk, roles);
                    }
                }
                if emit {
                    out.extend(self.membership_events(gid, relay_pubkey, now));
                }
            }
            9001 => {
                if let Some(group) = self.groups.get_mut(gid) {
                    for pk in tag_values(event, P) {
                        group.members.remove(pk);
                    }
                }
                if emit {
                    out.extend(self.membership_events(gid, relay_pubkey, now));
                }
            }
            9002 => {
                let (parent_before, parent_after, children_before) = {
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
                            (before, after, children_before)
                        }
                        None => (None, None, Vec::new()),
                    }
                };
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
                    }
                    if let Some(group) = self.groups.get_mut(gid) {
                        group.parent = parent_after.clone();
                    }
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
                let mut child_removed: Vec<String> = Vec::new();
                for child in &children_before {
                    if !child_added.iter().any(|c| c == child) {
                        child_removed.push(child.clone());
                    }
                }
                for child in &child_added {
                    let old_parent = self.groups.get(child).and_then(|g| g.parent.clone());
                    if old_parent.as_deref() == Some(gid) {
                        continue;
                    }
                    // Only a child that does not already belong to another
                    // parent gets its back-pointer assigned here: changing
                    // an existing child's parent is the child's own 9002's
                    // decision (the parent's admin must not re-parent a
                    // group they do not administer).
                    if old_parent.is_some() {
                        continue;
                    }
                    if let Some(child_group) = self.groups.get_mut(child) {
                        child_group.parent = Some(gid.to_string());
                    }
                    // The child's metadata changed (its parent tag):
                    // republish it so peers see the new link.
                    if emit {
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
                if !self.groups.contains_key(gid) && (ignore_capacity || !self.at_capacity()) {
                    // A fresh create resurrects the id: clear a previous
                    // delete tombstone (and ghost marker) so the id is
                    // reusable. Note the tombstone itself is memory-only;
                    // if the `9008` event is later lost (author vanish,
                    // expiry, NIP-09 deletion), the next rebuild replays
                    // surviving history and the group returns — events are
                    // the source of truth, and an admin can re-delete.
                    self.deleted.remove(gid);
                    self.unghost(gid);
                    let mut group = Group::default();
                    group
                        .members
                        .entry(event.pubkey.clone())
                        .or_default()
                        .insert("admin".into());
                    self.groups.insert(gid.to_string(), group);
                }
                if emit {
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
            .is_some_and(|g| g.settings.private || (g.settings.hidden && is_meta))
    }

    /// Whether the content of a group may be served to `authed`. `is_meta`
    /// distinguishes relay-generated metadata events (kinds 39000-39005),
    /// which `hidden` groups additionally withhold from non-members.
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
        if group.settings.private && !member {
            return false;
        }
        if group.settings.hidden && is_meta && !member {
            return false;
        }
        true
    }

    fn membership_events(&self, gid: &str, relay_pubkey: &str, now: u64) -> Vec<Event> {
        vec![
            build_admins_event(gid, self.groups.get(gid), relay_pubkey, now),
            build_members_event(gid, self.groups.get(gid), relay_pubkey, now),
        ]
    }

    /// Rebuilds the in-memory group state from the stored moderation events.
    pub async fn rebuild(&mut self, db: &DbClient) {
        // 9021 JOIN is included so that honored joins survive a restart even
        // on relays without a private key (which never emit the relay-signed
        // 9000 put-user that would otherwise carry the membership).
        let kinds: Vec<u64> = (MOD_MIN..=MOD_MAX).chain([JOIN, LEAVE]).collect();
        // Walk every stored group event in pages (newest first) instead of
        // one giant query: a single query with a huge limit would be truncated
        // by the scan's collection cap / work budget and could exceed the
        // database request timeout, silently rebuilding an incomplete group
        // store (missing groups → private content world-readable, admin
        // writes rejected, deleted groups resurrected).
        const PAGE: usize = 50_000;
        let mut events: Vec<Event> = Vec::new();
        let mut until: Option<u64> = None;
        loop {
            let mut filter: Filter =
                serde_json::from_value(json!({ "kinds": kinds })).expect("static filter");
            filter.until = until;
            // `query_full` gives each page the full-scan work budget (not the
            // smaller per-query one), so a single second holding more events
            // than the small budget cannot be silently cut mid-boundary.
            let (page, more) = db.query_full(vec![filter], PAGE, unix_now()).await;
            if page.is_empty() {
                break;
            }
            let min_created = page.iter().map(|e| e.created_at).min().unwrap_or(0);
            let full = page.len() >= PAGE;
            if !full && more {
                log::warn!(
                    "group state rebuild ended early (scan budget exhausted with {} events in \
                     the page): the in-memory group store may be incomplete after this restart",
                    page.len()
                );
                events.extend(page);
                break;
            }
            events.extend(page);
            if !full {
                // Fewer than a page: every remaining event was collected.
                break;
            }
            if min_created == 0 {
                break;
            }
            // The scan collects every event at the boundary timestamp, so
            // stepping the cursor just below it cannot skip any event.
            until = Some(min_created - 1);
        }
        // Chronological order (the scan is per-kind, not globally ordered) so
        // that later events win. Within the same second the kind is used as a
        // tie-breaker: the group-establishing events apply first (9007 create,
        // 9008 delete), then the member/settings operations (9000-9006,
        // 9009-9010) which need the group to exist, and joins/leaves last.
        // Known limitation: events of the same kind within the same second
        // are ordered by id, not by arrival — two conflicting 9000 edits in
        // the same second (e.g. grant-then-revoke of a role) may replay in
        // the wrong order after a restart. The relay stamps its generated
        // metadata strictly monotonic, so the *stored* 39000-39005 always
        // reflect the latest state; only the in-memory member map could
        // diverge until the next edit.
        // The rank ordering also inverts cross-kind arrival order within a
        // second: a 9001 remove followed in the same second by a 9021 JOIN
        // replays as [9001, JOIN] (correct) but a JOIN followed by a 9001
        // replays as [9001, JOIN] too — the removed member resurrects until
        // the next edit. Arrival order is not stored, so this cannot be
        // fixed exactly; the relay-stamped put-user (9000) events, which
        // arrive after the member operation, keep the stored 39002 list
        // correct.
        events.sort_by(|a, b| {
            (a.created_at, group_rank(a.kind), a.kind, &a.id).cmp(&(
                b.created_at,
                group_rank(b.kind),
                b.kind,
                &b.id,
            ))
        });
        // A vanished author must not be resurrected as a member by
        // replaying pre-vanish events signed by others (the vanish
        // deleted the author's own JOIN, but an admin's put-user or the
        // relay's own JOIN-time put-user survive): skip the events that
        // would add a vanished pubkey to a group.
        let vanished: std::collections::HashSet<String> = db
            .vanish_pubkeys()
            .await
            .into_iter()
            .map(hex::encode)
            .collect();
        // Every group id referenced by the surviving events: any of them
        // that did not make it into `groups` (its create event was
        // deleted by a vanish / NIP-09 / expiry) becomes a ghost — its
        // content is withheld instead of turning world-readable.
        let mut seen_gids: std::collections::HashSet<String> = std::collections::HashSet::new();
        for event in &events {
            if let Some(gid) = crate::nips::nip29::group_id(event) {
                seen_gids.insert(gid.to_string());
            }
        }
        // The relay-signed metadata (39000-39005: name/picture, the admins
        // and members lists, pins) survives a vanished creator — and is
        // not part of the moderation walk above. Include its group ids in
        // the ghost detection, so a private group whose only surviving
        // events are its metadata cannot become world-readable after a
        // restart. Walk it in pages like the moderation walk: a relay
        // hosting many groups can hold far more than one page of metadata,
        // and a truncated walk would silently fail the ghost detection
        // open (private metadata world-readable).
        let meta_kinds: Vec<u64> = (GROUP_META..=GROUP_PINS).collect();
        let mut meta_events: Vec<Event> = Vec::new();
        let mut until: Option<u64> = None;
        loop {
            let mut filter: Filter =
                serde_json::from_value(json!({ "kinds": meta_kinds })).expect("static filter");
            filter.until = until;
            let (page, more) = db.query_full(vec![filter], PAGE, unix_now()).await;
            if page.is_empty() {
                break;
            }
            let min_created = page.iter().map(|e| e.created_at).min().unwrap_or(0);
            let full = page.len() >= PAGE;
            if !full && more {
                // The scan budget was exhausted mid-timestamp: the page is
                // partial and stepping the cursor would silently skip the
                // unexamined events of the same timestamp, leaving their
                // groups out of the ghost detection (fail-open). Stop and
                // warn, like the moderation walk above.
                log::warn!(
                    "group metadata scan ended early (scan budget exhausted with {} events in \
                     the page): the ghost detection may be incomplete after this restart",
                    page.len()
                );
                meta_events.extend(page);
                break;
            }
            meta_events.extend(page);
            if !full || min_created == 0 {
                break;
            }
            until = Some(min_created - 1);
        }
        for event in &meta_events {
            if let Some(gid) = crate::nips::nip29::group_id_d(event) {
                seen_gids.insert(gid.to_string());
            }
        }
        for mut event in events {
            // A vanished author must not be resurrected as a member by
            // replaying pre-vanish events signed by others (the vanish
            // deleted the author's own JOIN, but an admin's put-user or
            // the relay's own JOIN-time put-user survive): skip the
            // events that would add a vanished pubkey to a group. For a
            // 9000 put-user only the vanished pubkeys' `p` tags are
            // dropped — the other assignments of the same event must
            // still be applied.
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
            self.apply(&event, "", unix_now(), false, true);
        }
        for gid in seen_gids {
            if !self.groups.contains_key(&gid) && !self.deleted.contains(&gid) {
                self.ghost.insert(gid);
            }
        }
    }

    /// Removes a group id from the ghost set once a fresh CREATE_GROUP
    /// restores it.
    pub(crate) fn unghost(&mut self, gid: &str) {
        self.ghost.remove(gid);
    }
}

/// Replay order of group events within the same second: the create/delete
/// establish the group before the member/settings operations, joins and
/// leaves come last.
fn group_rank(kind: u64) -> u8 {
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
fn validate_edit_metadata(
    store: &GroupStore,
    gid: &str,
    _group: &Group,
    event: &Event,
) -> Result<(), String> {
    // NIP-29: "A kind:9002 MAY carry at most one parent tag". A second
    // parent tag would be silently ignored (only the first is applied), so
    // the edit is rejected outright instead.
    if tag_values(event, "parent").count() > 1 {
        return Err("restricted: at most one parent tag is allowed".into());
    }
    // A group cannot be its own child, and one 9002 must not make a
    // group both the parent and the child of this one (that would create
    // a two-way cycle the walks below cannot see: both directions would
    // be applied and every later parent edit would loop forever).
    let parent_value = tag_value(event, "parent").map(str::to_string);
    if tag_values(event, "child").any(|c| c == gid) {
        return Err("restricted: a group cannot be its own child".into());
    }
    if let Some(parent) = &parent_value
        && tag_values(event, "child").any(|c| c == parent)
    {
        return Err("restricted: a group cannot be both parent and child".into());
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
                return Err("restricted: would create a cycle".into());
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
                return Err("restricted: would create a cycle".into());
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
            .ok_or_else(|| "restricted: parent group does not exist".to_string())?;
        if !parent_group.is_admin(event.pubkey.as_str()) {
            return Err("restricted: you are not an admin of the parent group".into());
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
        return Err("restricted: missing child tags in metadata edit".into());
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
        if let Some(child_group) = store.groups.get(child)
            && child_group.parent.as_deref() != Some(gid)
            && !child_group.is_admin(event.pubkey.as_str())
        {
            return Err("restricted: you are not an admin of the child group".into());
        }
    }
    Ok(())
}
