//! NIP-29: Relay-based Groups.
//!
//! The group state machine (access control, moderation application and
//! read visibility) lives here; the relay-generated metadata events are
//! built by the [`events`] module.

pub(crate) mod events;
#[cfg(test)]
pub(crate) mod tests;

use events::{
    CREATE_ID_TAG, apply_plain_create_privacy, apply_settings, attach_create_id,
    build_admins_event, build_members_event, build_membership_notice, build_meta_event,
    build_participants_event, build_pins_event, build_put_user, build_remove_user,
    build_remove_users, build_roles_event, build_system_message,
};

/// Moderation policy implemented here: any user with at least one role (from
/// a `kind:9000` put-user event or a `kind:9007` group creation) is an admin
/// and may send moderation events; the relay's own key is always an admin.
use std::collections::{HashMap, HashSet};

use anyhow::bail;
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
/// NIP-CW query-time window bounds (relay-signed, never stored).
pub const WINDOW_BOUNDS: u64 = 39006;
/// NIP-CW thread-mode bounds (reserved; nostrfy serves the legacy thread
/// path and does not emit this overlay).
pub const THREAD_WINDOW_BOUNDS: u64 = 39007;
/// Buzz system messages (channel created, member joined/left).
pub const SYSTEM_MESSAGE: u64 = 40099;
/// Buzz membership notifications (kind:44100 added, kind:44101 removed).
pub const MEMBER_ADDED: u64 = 44100;
pub const MEMBER_REMOVED: u64 = 44101;
/// Buzz DM commands (relay-handled, never stored).
pub const DM_OPEN: u64 = 41010;
pub const DM_HIDE: u64 = 41012;
pub const MOD_MIN: u64 = 9000;
pub const MOD_MAX: u64 = 9020;
pub const PUT_USER: u64 = 9000;
pub const REMOVE_USER: u64 = 9001;
/// Internal marker on the relay-signed `9000` mirror emitted for a JOIN.
/// It lets replay treat that mirror as add-only without misclassifying an
/// ordinary relay-master-key `9000` demotion.
pub(crate) const JOIN_MIRROR_TAG: &str = "join_mirror";
pub const CREATE_GROUP: u64 = 9007;
pub const DELETE_GROUP: u64 = 9008;
/// NIP-29 join request. The normative section says a relay MUST reject a
/// request from a user it has not added, while the spec's "Implementation
/// quirks" section explicitly allows the relay to generate the `9000`
/// immediately. nostrfy follows the quirks section: the live path still
/// applies the closed-group/invite-code checks, and a join from an existing
/// member is refused with the spec's `duplicate:` prefix.
pub const JOIN: u64 = 9021;
pub const LEAVE: u64 = 9022;
/// NIP-29 `create-invite`: carries bearer invite codes. The codes are
/// member/admin-only (a non-member who can read them can join a `closed`
/// group), so visibility special-cases this kind.
pub const CREATE_INVITE: u64 = 9009;

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

/// Whether `value` is a NIP-01 lowercase hex pubkey: exactly 64 hex digits.
///
/// The membership map is keyed by the `p` tag value verbatim
/// ([`GroupStore::apply`]) and looked up with the event's own `pubkey`, which
/// NIP-01 defines as lowercase hex and intake rejects otherwise
/// (`validate_base`). A `p` value that is not a lowercase 32-byte hex key can
/// therefore never match a real member, so accepting one silently locks the
/// named account out of the group and publishes a junk entry in the
/// relay-signed `39002` member list.
pub fn is_pubkey_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Every `p` tag value of a group moderation event that is not a NIP-01
/// pubkey. Kinds `9000` (put-user) and `9001` (remove-user) name members with
/// `p` tags, so they are the only ones that can put a malformed key into the
/// membership map. The relay's own snapshots (`39000`-`39005`) are signed and
/// stored, never re-validated, and ordinary chat events carry `p` tags for
/// mentions, which must not be constrained here.
pub fn malformed_member_tags(event: &Event) -> impl Iterator<Item = &str> {
    let names_members = matches!(event.kind, PUT_USER | REMOVE_USER);
    event
        .tags
        .iter()
        .filter(move |t| names_members && t.len() >= 2 && t[0] == P)
        .map(|t| t[1].as_str())
        .filter(|value| !is_pubkey_hex(value))
}

/// Whether the event is a group *action*: moderation events (9000-9020),
/// join requests (9021) and leave requests (9022). These MUST carry an `h`
/// tag naming the group they act on.
pub fn is_group_action(event: &Event) -> bool {
    is_group_action_kind(event.kind)
}

/// Kind-only form of [`is_group_action`], for visibility checks that no
/// longer have the full event.
pub fn is_group_action_kind(kind: u64) -> bool {
    (MOD_MIN..=MOD_MAX).contains(&kind) || kind == JOIN || kind == LEAVE
}

/// Buzz membership notifications. They carry an `h` tag for context but are
/// stored community-globally (channel_id = None) so an agent or client can
/// subscribe before it knows the channel. They must therefore not be treated
/// as channel-scoped group events by the visibility/store paths.
pub fn is_membership_notice_kind(kind: u64) -> bool {
    matches!(kind, MEMBER_ADDED | MEMBER_REMOVED)
}

/// Whether the event is a group event at all: user and moderation events
/// carry an `h` tag, relay-generated metadata events are kinds 39000-39005
/// identified by their `d` tag. Cheap enough to run per live event; mirrors
/// the `gid` selection in [`GroupStore::visible_to`].
pub fn is_group_event(event: &Event) -> bool {
    !is_membership_notice_kind(event.kind)
        && (group_id(event).is_some()
            || ((GROUP_META..=GROUP_PINS).contains(&event.kind) && group_id_d(event).is_some()))
}

/// Group id of a relay-generated metadata event (from the `d` tag).
pub fn group_id_d(event: &Event) -> Option<&str> {
    tag_value(event, D)
}

/// Group id of a stored event for visibility checks: the `h` tag for user
/// and moderation events, the `d` tag for relay-generated metadata events.
pub fn group_id_any(event: &Event) -> Option<&str> {
    if is_membership_notice_kind(event.kind) {
        return None;
    }
    match event.kind {
        GROUP_META..=GROUP_PINS => group_id_d(event),
        _ => group_id(event),
    }
}

/// Trait-based variant of [`group_id_any`] for the negentropy light path
/// (the candidate was deserialized without its content).
pub fn group_id_any_light<E: crate::filter::EventFields>(event: &E) -> Option<&str> {
    if is_membership_notice_kind(event.kind()) {
        return None;
    }
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
    /// Buzz/NIP-CL channel topic and purpose (partial updates on kind:9002).
    #[serde(default)]
    pub topic: Option<String>,
    #[serde(default)]
    pub purpose: Option<String>,
    /// Buzz ephemeral-channel TTL in seconds. nostrfy stores the setting and
    /// publishes it; message expiry itself is handled by the event's own
    /// NIP-40 `expiration` when the client sets one.
    #[serde(default)]
    pub ttl: Option<u64>,
    /// Buzz archived marker, published as `["archived", "true"]`.
    #[serde(default)]
    pub archived: bool,
    /// NIP-CL `join_role`: the role a self-join receives (`member` or
    /// `guest`). An unknown stored value is treated as `guest`.
    #[serde(default)]
    pub join_role: Option<String>,
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
    /// NIP-CL: the pubkey that signed the kind:9007 which created the group.
    /// `None` for snapshots written before this field existed; a rebuild from
    /// the stored create event fills it in.
    #[serde(default)]
    pub creator: Option<String>,
    /// NIP-CL `created_at` tag: when the group was created (unix seconds).
    #[serde(default)]
    pub created_at: Option<u64>,
    /// Event id of the group's `9007` create (or the synthetic DM marker).
    /// State events validated against a previous incarnation carry the old
    /// id and are dropped after a delete/recreate. Missing on old snapshots;
    /// startup derives it from the stored create where possible.
    #[serde(default)]
    pub create_id: Option<String>,
    /// The creator's role was explicitly set by a 9000/9001 event. Disables
    /// the Buzz-mode snapshot migration that otherwise upgrades a lone
    /// `admin` to `owner` (or downgrades a Buzz default back to `admin`).
    #[serde(default)]
    pub creator_role_explicit: bool,
    /// NIP-CL channel type (`stream`, `forum`, `dm`, `workflow`, `system`).
    /// Empty for snapshots written before the field existed; clients then
    /// fall back to their own default, as NIP-CL requires for older events.
    #[serde(default)]
    pub channel_type: String,
    /// NIP-CL labels (the `t` tags after the channel type).
    #[serde(default)]
    pub labels: Vec<String>,
    /// A Buzz client applied a partial `9002` to this group. Once Buzz is
    /// disabled, a stored partial edit must still be replayed (and a live
    /// edit treated) as partial for privacy: its omitted tags were never
    /// meant to clear `private`/`hidden`. Snapshots persist this; a
    /// snapshot-less rebuild that has no marker can only infer Buzz origin
    /// from `channel_type`/`visibility`.
    #[serde(default)]
    pub buzz_metadata: bool,
    /// NIP-DV: pubkeys that hid this DM from their own sidebar. This is
    /// per-viewer presentation state, distinct from `settings.hidden`
    /// (which withholds a DM/system channel's metadata from non-members).
    #[serde(default)]
    pub hidden_for: HashSet<String>,
    /// NIP-CL announce channels: members who joined under
    /// `join_role=guest`. Guests can read and leave but cannot post or
    /// change topic/purpose.
    #[serde(default)]
    pub guests: HashSet<String>,
    /// Buzz agents admitted with `role=bot`. Buzz reads the `bot` role from
    /// kind:39002 to decide whether a member is an agent; the NIP-29 role
    /// set alone cannot carry it because a bot has no privileged role.
    #[serde(default)]
    pub bots: HashSet<String>,
}

/// NIP-CL channel types. A type outside this set is rejected; a type added
/// to a future revision is deliberately not accepted until it is defined.
pub const CHANNEL_TYPES: &[&str] = &["stream", "forum", "dm", "workflow", "system"];

/// The NIP-CL channel type carried by a create event, defaulting to `stream`
/// for clients that omit it.
pub fn channel_type(event: &Event) -> String {
    tag_value(event, "channel_type")
        .filter(|value| CHANNEL_TYPES.contains(value))
        .unwrap_or("stream")
        .to_string()
}

/// Whether a kind:9000 `p` tag leaves the subject with a privileged role.
///
/// In Buzz mode the separate `role` tag is authoritative only when the `p`
/// tag carries no role elements, and the `member`/`guest`/`bot` tiers are
/// not privileged. Validation and apply must agree on this: otherwise the
/// live last-admin guard can reject a valid role re-assertion, or accept a
/// `["p", admin, "guest"]` that apply turns into a guest and leaves the
/// group without an admin.
fn tag_grants_privileged_role(tag: &[String], buzz: bool, buzz_role: Option<&str>) -> bool {
    if !buzz {
        return tag.iter().skip(2).any(|role| !role.is_empty());
    }
    let mut any = false;
    for role in tag.iter().skip(2).filter(|role| !role.is_empty()) {
        any = true;
        if role != "member" && role != "guest" && role != "bot" {
            return true;
        }
    }
    !any && buzz_role
        .is_some_and(|role| !role.is_empty() && !matches!(role, "guest" | "member" | "bot"))
}

/// NIP-CL/Buzz tags that the live plain path ignores but the history replay
/// would honor. Plain mode must reject them on a group without Buzz
/// provenance; otherwise a stored create/edit changes visibility after a
/// restart even though it was a no-op when accepted.
fn has_replay_sensitive_buzz_tags(event: &Event) -> bool {
    event.tags.iter().any(|tag| {
        tag.first()
            .is_some_and(|name| name == "channel_type" || name == "visibility")
    })
}

/// Validates the NIP-CL tags on a create/edit event. The whole event is
/// rejected on any violation, as NIP-CL requires.
pub fn validate_channel_tags(event: &Event) -> Result<(), String> {
    if let Some(visibility) = tag_value(event, "visibility")
        && visibility != "open"
        && visibility != "private"
    {
        return Err(format!(
            "invalid: visibility must be \"open\" or \"private\" (got {visibility:?})"
        ));
    }
    if event.kind == CREATE_GROUP
        && let Some(kind) = tag_value(event, "channel_type")
        && !CHANNEL_TYPES.contains(&kind)
    {
        return Err(format!("invalid: unknown channel_type {kind:?}"));
    }
    if matches!(event.kind, CREATE_GROUP | 9002)
        && let Some(ttl) = tag_value(event, "ttl")
        && !ttl.is_empty()
        && ttl.parse::<u64>().is_err()
    {
        return Err("invalid: ttl must be a non-negative integer".into());
    }
    if event.kind == CREATE_GROUP || event.kind == 9002 {
        let labels = label_values(event);
        if labels.len() > 8 {
            return Err("invalid: at most 8 channel labels are allowed".into());
        }
        let mut seen = HashSet::new();
        let clear = labels.iter().any(String::is_empty);
        if clear && labels.len() > 1 {
            return Err("invalid: an empty label cannot be combined with other labels".into());
        }
        for label in labels {
            if label.is_empty() {
                continue;
            }
            if label.len() > 64
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".:-".contains(&b))
            {
                return Err(format!("invalid: malformed channel label {label:?}"));
            }
            if CHANNEL_TYPES.contains(&label.as_str()) {
                return Err(format!("invalid: channel label {label:?} is reserved"));
            }
            if !seen.insert(label.clone()) {
                return Err(format!("invalid: duplicate channel label {label:?}"));
            }
        }
    }
    Ok(())
}

/// The `t` tag values of a create/edit event, in order.
pub fn label_values(event: &Event) -> Vec<String> {
    event
        .tags
        .iter()
        .filter(|t| t.len() >= 2 && t[0] == "t")
        .map(|t| t[1].clone())
        .collect()
}

/// Emits the NIP-CL channel identity tags in their required order: the first
/// `t` is the channel type, later `t` tags are labels, then `P` names the
/// creator, and kind:39000 additionally carries `created_at`.
pub(crate) fn push_channel_identity_tags(
    event: &mut Event,
    group: Option<&Group>,
    include_created_at: bool,
) {
    let Some(group) = group else {
        return;
    };
    if !group.channel_type.is_empty() {
        event
            .tags
            .push(vec!["t".to_string(), group.channel_type.clone()]);
    }
    for label in &group.labels {
        event.tags.push(vec!["t".to_string(), label.clone()]);
    }
    if let Some(creator) = &group.creator {
        event.tags.push(vec!["P".to_string(), creator.clone()]);
    }
    if include_created_at && let Some(created_at) = group.created_at {
        event
            .tags
            .push(vec!["created_at".to_string(), created_at.to_string()]);
    }
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

    pub fn is_guest(&self, pubkey: &str) -> bool {
        self.guests.contains(pubkey)
    }

    pub fn has_invite(&self, code: &str) -> bool {
        self.invites.contains(code)
    }
}

/// Groups up to this many members always get a fresh 39002.
const MEMBERS_EAGER_MAX: usize = 1000;
/// Larger groups get a fresh 39002 at most once per this many seconds.
const MEMBERS_INTERVAL_SECS: u64 = 60;

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
    /// Groups whose 39002 was throttled since the last publish. The stats
    /// tick drains these once their interval elapses, so a dropped update is
    /// never permanent. Transient: a restart republishes all metadata.
    members_dirty: HashSet<String>,
    /// Cap on the store size (active groups + deleted markers): bounds the
    /// in-memory state even when an attacker churns group ids. 0 =
    /// unlimited.
    max_groups: usize,
    /// Whether the Buzz compatibility extensions are active (config
    /// `relay.enabled_buzz`). When false, group state is read and written
    /// with plain NIP-29 semantics: no NIP-CL tags, no Buzz role columns in
    /// `39002`, and `9002` replaces the metadata as NIP-29 specifies.
    /// Not persisted; set from the config at startup and on reload.
    pub(crate) buzz_enabled: bool,
    /// Total members across every group: the global budget (see
    /// [`MAX_TOTAL_MEMBERS`]) is enforced against this counter instead of
    /// rescanning every group per JOIN/9000. Every member-map mutation in
    /// this module (and [`Self::remove_member_everywhere`]) keeps it in
    /// sync; [`Self::restore`] recomputes it.
    total_members: usize,
    /// The global member budget; 0 = unlimited (tests).
    max_total_members: usize,
    /// Set while this relay replays its own stored history (or the
    /// migration after its explicit JOIN admission gate). A keyless relay
    /// has no relay-signed 9000 JOIN mirror, so its own accepted JOIN must
    /// be trusted even after the group later closed. Other history replays
    /// leave this false so `apply` re-adjudicates closed-group admission.
    pub(crate) trust_stored_joins: bool,
    /// Child ids that some group's `children` list declared (a hint, never
    /// the authority): a CREATE_GROUP scans the groups for an adopting
    /// parent only when the id was ever declared, so an uncapped store does
    /// not pay an O(groups) scan per create. Stale entries (a link that was
    /// later removed) only cost one scan.
    declared_children: HashSet<String>,
    /// Fail-closed while the store is being replaced after a removed
    /// group-state event invalidated its derivation: membership and
    /// visibility decisions made from pre-removal state would keep applying
    /// the removed grant (NIP-43's role store already gates this way). Set
    /// by [`Self::mark_stale`] (called from the relay's stale paths), and
    /// cleared by an ordinary `GroupsMap::default` rebuild either on a clean
    /// post-scan swap with a current view or from a fresh persistent state.
    pub(crate) stale: bool,
    /// The specific group ids whose derived state a removal invalidated and
    /// whose rebuild has not confirmed yet. Empty is normal operation; the
    /// global `stale` flag is the fallback for a removal whose groups could
    /// not be resolved (a failed lookup, a vanish, the startup resume), and
    /// gates every group. Keeping the two lets an unprivileged caller fail
    /// closed only the groups it actually touched instead of every group on
    /// the relay.
    pub(crate) stale_groups: HashSet<String>,
    /// The persisted state could not be restored or rebuilt (NIP-29 is
    /// disabled and no usable snapshot exists): every group id is unknown,
    /// so an unknown id must read as *private* instead of public — treating
    /// an empty store's ids as open would expose the content of the groups
    /// it lost (fail-open). Set by [`Self::mark_unrestored`] at startup;
    /// cleared by a successful snapshot restore or full rebuild.
    unrestored: bool,
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
    /// Buzz compatibility mode at snapshot capture. If it differs on the
    /// next restore, startup republishes the 39000/39001/39002 rosters so a
    /// mode switch is reflected without waiting for the next mutation.
    /// Older snapshots have no field and are refreshed once.
    #[serde(default)]
    pub buzz_enabled: Option<bool>,
}

/// The additive, snapshot-generation-stamped copy of the Buzz-specific
/// group state. A plain-mode event rebuild cannot reconstruct the guest/bot
/// tiers, separate role grants, or the `buzz_metadata` provenance, so this
/// backup restores them only when its generation still matches the rebuilt
/// events.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub(crate) struct BuzzBackup {
    #[serde(default)]
    pub stamp: u64,
    #[serde(default)]
    pub seq: u64,
    #[serde(default)]
    pub groups: HashMap<String, BuzzGroupBackup>,
}

/// The per-group subset carried by [`BuzzBackup`]. Membership is not used to
/// add or remove members; only roles of members the event rebuild already
/// has are restored.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub(crate) struct BuzzGroupBackup {
    #[serde(default)]
    pub create_id: Option<String>,
    #[serde(default)]
    pub buzz_metadata: bool,
    #[serde(default)]
    pub creator_role_explicit: bool,
    #[serde(default)]
    pub guests: HashSet<String>,
    #[serde(default)]
    pub bots: HashSet<String>,
    #[serde(default)]
    pub roles: HashMap<String, HashSet<String>>,
}

impl BuzzBackup {
    pub(crate) fn from_snapshot(snapshot: &GroupsSnapshot) -> Self {
        let mut groups = HashMap::new();
        for (gid, group) in &snapshot.groups {
            // A plain-origin group with no Buzz provenance replays its
            // roles with plain semantics, so it does not need a backup.
            if !group.buzz_metadata && group.guests.is_empty() && group.bots.is_empty() {
                continue;
            }
            groups.insert(
                gid.clone(),
                BuzzGroupBackup {
                    create_id: group.create_id.clone(),
                    buzz_metadata: group.buzz_metadata,
                    creator_role_explicit: group.creator_role_explicit,
                    guests: group.guests.clone(),
                    bots: group.bots.clone(),
                    roles: group.members.clone(),
                },
            );
        }
        Self {
            stamp: snapshot.stamp,
            seq: snapshot.seq,
            groups,
        }
    }
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
            buzz_enabled: Some(self.buzz_enabled),
        }
    }

    /// Merges DM groups carried across a migration rebuild. The rebuilt
    /// event state is authoritative for ordinary groups; DM groups are
    /// snapshot-only and are adopted only when the rebuilt store has no
    /// group under that id.
    pub(crate) fn merge_dm_snapshot(&mut self, snapshot: GroupsSnapshot) -> bool {
        let mut changed = false;
        for (gid, group) in snapshot.groups {
            if group.channel_type != "dm" {
                continue;
            }
            // A rebuilt/event-derived group is authoritative for its id.
            // The carry and the backup only fill DM ids the rebuild could
            // not recreate, never overwrite a live group.
            if let std::collections::hash_map::Entry::Vacant(slot) = self.groups.entry(gid) {
                slot.insert(group);
                changed = true;
            }
        }
        if changed {
            self.recompute_derived();
        }
        changed
    }

    /// Restores the Buzz-specific snapshot fields that the plain event
    /// replay cannot reconstruct. The create id must still match, so a
    /// deleted/recreated group never inherits the old incarnation's tiers
    /// or roles; membership itself is never added or removed here.
    pub(crate) fn merge_buzz_backup(&mut self, backup: BuzzBackup) -> bool {
        let mut changed = false;
        for (gid, entry) in backup.groups {
            let Some(group) = self.groups.get_mut(&gid) else {
                continue;
            };
            if group.create_id != entry.create_id {
                continue;
            }
            for (pubkey, roles) in entry.roles {
                if let Some(current) = group.members.get_mut(&pubkey)
                    && *current != roles
                {
                    *current = roles;
                    changed = true;
                }
            }
            let guests: HashSet<String> = entry
                .guests
                .into_iter()
                .filter(|pubkey| group.members.contains_key(pubkey))
                .collect();
            if group.guests != guests {
                group.guests = guests;
                changed = true;
            }
            let bots: HashSet<String> = entry
                .bots
                .into_iter()
                .filter(|pubkey| group.members.contains_key(pubkey))
                .collect();
            if group.bots != bots {
                group.bots = bots;
                changed = true;
            }
            if entry.buzz_metadata && !group.buzz_metadata {
                group.buzz_metadata = true;
                changed = true;
            }
            if group.creator_role_explicit != entry.creator_role_explicit {
                group.creator_role_explicit = entry.creator_role_explicit;
                changed = true;
            }
        }
        changed
    }

    /// Restores state persisted by [`Self::snapshot`], keeping the current
    /// capacity cap. The derived counters (`total_members`,
    /// `declared_children`) start from the restored groups.
    pub(crate) fn restore(&mut self, snap: GroupsSnapshot) {
        self.groups = snap.groups;
        self.deleted = snap.deleted;
        self.ghost = snap.ghost;
        // Snapshots written before the creator role became `owner` still
        // carry the old default `admin`. In Buzz mode, upgrade only that
        // exact default: a creator who was demoted (no roles) or explicitly
        // given another role is left alone. Plain NIP-29 keeps `admin`, so
        // disabling Buzz restores the pre-Buzz role label.
        for group in self.groups.values_mut() {
            let Some(creator) = group.creator.clone() else {
                continue;
            };
            let Some(roles) = group.members.get_mut(&creator) else {
                continue;
            };
            let upgrade = self.buzz_enabled
                && !group.creator_role_explicit
                && roles.len() == 1
                && roles.contains("admin");
            // A Buzz-created channel (it always carries a channel_type) is
            // restored by a relay that turned Buzz off: keep the documented
            // plain-NIP-29 creator label instead of exposing the Buzz-only
            // `owner` role. A plain group has no channel_type, so an
            // explicitly assigned `owner` role in a normal NIP-29 group is
            // left untouched.
            let downgrade = !self.buzz_enabled
                && !group.creator_role_explicit
                && !group.channel_type.is_empty()
                && roles.len() == 1
                && roles.contains("owner");
            if upgrade {
                // Buzz snapshots predating the owner default carry `admin`.
                roles.clear();
                roles.insert("owner".to_string());
            } else if downgrade {
                roles.clear();
                roles.insert("admin".to_string());
            }
        }
        self.members_dirty.clear();
        // The snapshot stores the roster but not the throttling/dirty
        // marker. A large group whose last 39002 was deferred before the
        // restart would otherwise keep the stale stored event until its
        // next membership change. Mark it for one stats-tick refresh.
        self.members_dirty.extend(
            self.groups
                .iter()
                .filter(|(_, group)| group.members.len() > MEMBERS_EAGER_MAX)
                .map(|(gid, _)| gid.clone()),
        );
        // The snapshot is authoritative: unknown ids are genuinely unknown
        // again (see the `unrestored` field).
        self.unrestored = false;
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

    /// Whether another *live* group may be created. Deleted tombstones are
    /// reclaimable (see [`Self::reclaim_tombstones`]); ghost markers are
    /// historical fail-closed ids whose stored history may survive, not live
    /// groups. Counting ghosts here let a create+delete churn of backed
    /// ghosts lock out every new group id forever, so they no longer consume
    /// the live budget. Their set is bounded by the h-tagged history that
    /// produced them (each ghost requires stored events), and the reaper
    /// releases the ones with no surviving history.
    fn at_capacity(&self) -> bool {
        self.max_groups > 0 && self.groups.len() >= self.max_groups
    }

    /// Whether a create currently hits the live group budget. Test-only:
    /// production uses [`Self::at_capacity`] directly.
    #[cfg(test)]
    pub(crate) fn create_capacity_reached(&self) -> bool {
        self.at_capacity()
    }

    /// Makes room for `room` new live groups within `max_groups`, dropping
    /// tombstones as needed. The in-memory delete markers are a fast path
    /// only: the database's purge marker and the purged events remain
    /// authoritative, and a tombstone's only unique effect is the friendlier
    /// rejection of a non-create write to an id that is unknown anyway — so
    /// an arbitrary tombstone is the right thing to drop. Without this, an
    /// anonymous create+delete churn over `max_groups` distinct ids
    /// exhausted the budget with tombstones and permanently rejected every
    /// later create (only a `max_groups` change recovered). Ghosts are never
    /// dropped: their surviving history must stay withheld, and they do not
    /// occupy the live budget (see [`Self::at_capacity`]).
    fn reclaim_tombstones(&mut self, room: usize) {
        if self.max_groups == 0 {
            return;
        }
        let budget = self.max_groups.saturating_sub(room);
        while self.groups.len() + self.deleted.len() > budget {
            let Some(victim) = self.deleted.iter().next().cloned() else {
                // Live groups alone exceed the budget: the create is
                // refused by `at_capacity` instead.
                break;
            };
            self.deleted.remove(&victim);
        }
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

    pub fn mark_stale(&mut self) {
        self.stale = true;
    }

    /// Marks the store as not restored (see [`Self::unrestored`]): unknown
    /// group ids must read as private, not public. Called by the startup
    /// when NIP-29 is disabled and no usable snapshot exists, so the empty
    /// store cannot expose the content of the groups it lost.
    pub(crate) fn mark_unrestored(&mut self) {
        self.unrestored = true;
    }

    /// Whether the store could not be restored (see [`Self::unrestored`]).
    /// A rebuild must preserve this fail-closed state until a *full* scan
    /// succeeds; a scoped/vanish rebuild cannot prove the lost ids.
    pub(crate) fn is_unrestored(&self) -> bool {
        self.unrestored
    }

    /// Fails closed for the named groups only (see [`Self::stale_groups`]).
    pub fn mark_groups_stale(&mut self, gids: impl IntoIterator<Item = String>) {
        self.stale_groups.extend(gids);
    }

    /// Whether `gid`'s derived state is unverified: the global flag covers
    /// removals whose scope could not be resolved, the set the ones that
    /// could.
    pub fn group_is_stale(&self, gid: &str) -> bool {
        self.stale || self.stale_groups.contains(gid)
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
        // a restricted group's feed. Reject them outright, whether or not
        // NIP-29 is currently enabled (the disabled-window intake also
        // enforces this in `validate_base`).
        if event
            .tags
            .iter()
            .filter(|t| t.first().is_some_and(|name| name == H))
            .count()
            > 1
        {
            bail!("invalid: group events must carry only one h tag");
        }
        if self.unrestored && event.kind != DELETE_GROUP {
            bail!("restricted: group state is unavailable");
        }
        let Some(gid) = group_id(event).filter(|gid| !gid.is_empty()) else {
            // NIP-29 group actions MUST carry a non-empty `h` tag (mirrors
            // the intake precheck): without it the event names no group to
            // validate against, so accepting it here would let a direct
            // caller bypass the requirement. Ordinary events without `h`
            // are unaffected.
            if is_group_action(event) {
                bail!("invalid: group events must carry an h tag");
            }
            return Ok(());
        };
        // The store is derived from an authority no longer certain (a
        // removed group-state event and the rebuild has not recomputed the
        // surviving tree): NIP-43 rejects role actions on the cleared store
        // for exactly the same reason. A stale `is_member` would keep
        // authorizing a member whose grant was removed, and a stale
        // settings blob would service requests with unverified privacy.
        // The gate is per group: a caller who removed state in *this* group
        // cannot deny writes to every other group on the relay.
        if self.group_is_stale(gid) {
            bail!("restricted: group state is rebuilding");
        }
        // A ghosted id must never be resurrected by a create: its create
        // event is gone while survivors may still be stored, so a fresh
        // default-public group would expose their (possibly private)
        // content. The `deleted` tombstone is different: the relay purged
        // the group's events when the `9008` was applied (and only a
        // confirmed purge leaves the id as `deleted`), so clearing that
        // tombstone on a create is safe.
        if self.ghost.contains(gid) {
            // A ghost with surviving history is normally un-writable, but
            // the relay master key may issue a 9008 to purge the surviving
            // events and release both the id and its capacity slot.
            let relay_signed = relay_pubkey.is_some_and(|pk| event.pubkey.eq_ignore_ascii_case(pk));
            if event.kind == DELETE_GROUP && relay_signed {
                return Ok(());
            }
            bail!("blocked: the group has been deleted");
        }
        if self.deleted.contains(gid) {
            // A deleted id stays closed except for a fresh create: the
            // tombstone blocks every other write, but legitimate re-creation
            // with the same id must remain possible (the create clears the
            // marker in `apply`). Without this an id could never be reused.
            if event.kind == CREATE_GROUP {
                if !self.buzz_enabled && has_replay_sensitive_buzz_tags(event) {
                    bail!("restricted: NIP-CL channel tags require Buzz support");
                }
                if self.at_capacity() {
                    bail!("restricted: group limit reached");
                }
                if self.at_member_capacity(1) {
                    bail!("restricted: the relay member limit is reached");
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
                if !self.buzz_enabled && has_replay_sensitive_buzz_tags(event) {
                    bail!("restricted: NIP-CL channel tags require Buzz support");
                }
                if self.at_capacity() {
                    bail!("restricted: group limit reached");
                }
                if self.at_member_capacity(1) {
                    bail!("restricted: the relay member limit is reached");
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

        // A group-state event cannot predate the incarnation it mutates.
        // This also blocks the common stale-after-recreate case and keeps
        // replay from silently discarding a backdated private setting.
        if event.kind != CREATE_GROUP
            && group
                .created_at
                .is_some_and(|created| event.created_at < created)
        {
            bail!("invalid: group event predates the group");
        }

        // A plain-origin group ignores NIP-CL channel tags live but the
        // history replay honors them as a privacy floor. Reject the tags on
        // a plain group so the two paths cannot diverge after a restart.
        // Buzz-created/edited groups keep the explicit transition.
        if !self.buzz_enabled
            && event.kind == 9002
            && group.channel_type.is_empty()
            && !group.buzz_metadata
            && has_replay_sensitive_buzz_tags(event)
        {
            bail!("restricted: NIP-CL channel tags require Buzz support");
        }

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

        // NIP-CL announce channels: guests can read and leave, but not post
        // or change topic/purpose. This is a Buzz extension; with Buzz
        // disabled, a stored `guest` role is an ordinary NIP-29 label (and
        // any non-empty role is privileged here), so the special read-only
        // restriction must not leak into plain NIP-29 operation.
        if self.buzz_enabled {
            let guest = group.is_guest(pubkey);
            if !is_group_action(event) && guest {
                bail!("restricted: only members can post in this channel");
            }
            // NIP-CL: any member (not a guest) may update the
            // topic/purpose with a kind:9002 that carries only those fields.
            // Every other metadata edit stays owner/admin-only.
            if event.kind == 9002 && !relay_signed && !group.is_admin(pubkey) {
                // Keep the exact same predicate in the apply path so a
                // member's topic/purpose edit cannot fall through to the
                // full parent/child replacement and detach a subgroup.
                if !is_member_topic_edit(group, event, relay_signed) {
                    bail!("restricted: you are not an admin of this group");
                }
                return Ok(());
            }
        }

        if (MOD_MIN..=MOD_MAX).contains(&event.kind) {
            if !relay_signed && !group.is_admin(pubkey) {
                bail!("restricted: you are not an admin of this group");
            }
            if event.kind == 9002 {
                let _ = validate_edit_metadata(self, gid, group, event, relay_signed, false)?;
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
            // The guard only protects groups that still have an admin: on
            // an already admin-less group there is no last admin to lose,
            // and only the relay key reaches this check there (anyone else
            // fails the admin check above), so plain adds and removals
            // must stay available for operator cleanup.
            let group_has_admin = group.members.values().any(|roles| !roles.is_empty());
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
                let buzz_role = if self.buzz_enabled {
                    tag_value(event, "role")
                } else {
                    None
                };
                let mut overrides: HashMap<&str, bool> = HashMap::new();
                for tag in event.tags.iter().filter(|t| t.len() >= 2 && t[0] == P) {
                    let pk = tag[1].as_str();
                    let has_roles = tag_grants_privileged_role(tag, self.buzz_enabled, buzz_role);
                    overrides.insert(pk, has_roles);
                }
                let retains_admin = group.members.iter().any(|(pk, roles)| {
                    overrides
                        .get(pk.as_str())
                        .copied()
                        .unwrap_or(!roles.is_empty())
                }) || overrides.values().any(|has| *has);
                if group_has_admin && !retains_admin {
                    bail!("restricted: the group must retain at least one admin");
                }
                return Ok(());
            }
            let retains_admin = group
                .members
                .iter()
                .any(|(pk, roles)| !roles.is_empty() && !admin_removed.contains(pk));
            if group_has_admin && !retains_admin {
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
    /// during startup rebuild). `history_replay` marks a replay of stored
    /// history (the startup rebuild, the migration): stored groups are
    /// restored even past the group capacity — a group dropped by the
    /// capacity limit must not become "unknown" (its private content would
    /// turn world-readable), and the limit still applies to new creations at
    /// runtime — while the state-dependent runtime checks (the member
    /// budgets, the last-admin invariant, the metadata graph's structural
    /// invariants) run on every path: an effect the live path dropped under
    /// a race is not resurrected by the next rebuild, so a rebuilt state
    /// cannot contain a cycle or an admin-less group that live would have
    /// refused. The metadata re-check's authorization/fidelity half is
    /// live-only (see `validate_edit_metadata`).
    /// The channel type carried by membership notices. Groups created before
    /// NIP-CL have no stored type; `stream` is the legacy default every
    /// Buzz client understands.
    pub(crate) fn notice_channel_type(&self, gid: &str) -> String {
        self.groups
            .get(gid)
            .map(|group| {
                if group.channel_type.is_empty() {
                    "stream".to_string()
                } else {
                    group.channel_type.clone()
                }
            })
            .unwrap_or_else(|| "stream".to_string())
    }

    pub fn apply(
        &mut self,
        event: &Event,
        relay_pubkey: &str,
        now: u64,
        emit: bool,
        history_replay: bool,
    ) -> Vec<Event> {
        self.apply_with_epoch(event, relay_pubkey, now, emit, history_replay, None)
    }

    /// [`Self::apply`] with an optional durable epoch read from the
    /// `group_epochs` index. A state event accepted for an older
    /// incarnation is dropped after delete/recreate even when its client
    /// timestamp is newer than the new create.
    pub fn apply_with_epoch(
        &mut self,
        event: &Event,
        relay_pubkey: &str,
        now: u64,
        emit: bool,
        history_replay: bool,
        expected_epoch: Option<&str>,
    ) -> Vec<Event> {
        let Some(gid) = group_id(event) else {
            return Vec::new();
        };
        // Relay-generated mirrors are stamped with the create id they were
        // produced for. A replay after delete/recreate must not let the old
        // mirror re-add a member to the new incarnation. Only relay-signed
        // events are checked so a client's unrelated custom `create_id` tag
        // cannot make its own state silently disappear.
        let relay_signed =
            !relay_pubkey.is_empty() && relay_pubkey.eq_ignore_ascii_case(&event.pubkey);
        if relay_signed
            && event.kind != CREATE_GROUP
            && let Some(expected) = event
                .tags
                .iter()
                .find(|tag| tag.len() >= 2 && tag[0] == CREATE_ID_TAG)
                .map(|tag| tag[1].as_str())
            && self
                .groups
                .get(gid)
                .and_then(|group| group.create_id.as_deref())
                != Some(expected)
        {
            return Vec::new();
        }
        if let Some(expected) = expected_epoch
            && event.kind != CREATE_GROUP
            && self
                .groups
                .get(gid)
                .and_then(|group| group.create_id.as_deref())
                != Some(expected)
        {
            return Vec::new();
        }
        // A delayed after-put from a previous incarnation must not mutate a
        // group re-created under the same id. The live validation runs
        // before the store commit; re-check the incarnation here under the
        // write lock. (A full create-id/epoch binding is a later hardening
        // step; created_at catches the ordinary delayed case safely.)
        if !history_replay
            && event.kind != CREATE_GROUP
            && self
                .groups
                .get(gid)
                .and_then(|group| group.created_at)
                .is_some_and(|created| event.created_at < created)
        {
            return Vec::new();
        }
        let mut out = Vec::new();
        match event.kind {
            JOIN => {
                // Admitted via a valid invite code on a closed group, or
                // honored on an open group (not `closed`): the `code` tag
                // is optional preauthorization and irrelevant to admission
                // on open groups. A closed group without a valid code is
                // ignored (NIP-29: `closed` means join requests are not
                // honored; this relay keeps no pending-join queue — the
                // live validation rejects such requests as final, so this
                // arm is a no-op for them on every path).
                // A keyless relay has no relay-signed 9000 mirror to carry
                // an accepted JOIN across a rebuild. Re-adjudicating the
                // stored JOIN against the *end-state* settings loses a join
                // accepted while the group was open if a later 9002 closed
                // it, or if the invite event behind a closed join was
                // deleted. Live validation remains the admission gate; a
                // keyless history replay trusts the stored JOIN.
                let replay_keyless_join =
                    history_replay && self.trust_stored_joins && relay_pubkey.is_empty();
                let admitted = self.groups.get(gid).is_some_and(|g| {
                    replay_keyless_join
                        || if g.settings.closed {
                            event_code(event).is_some_and(|code| g.has_invite(code))
                        } else {
                            true
                        }
                });
                if admitted {
                    let member = event.pubkey.clone();
                    let join_role_guest = self.buzz_enabled
                        && self.groups.get(gid).is_some_and(|g| {
                            g.settings
                                .join_role
                                .as_deref()
                                .is_some_and(|role| role != "member")
                        });
                    let mut added = false;
                    if let Some(group) = self.groups.get_mut(gid) {
                        // Membership is the entry in the member map; roles
                        // (granted only via `kind:9000`) decide privileges.
                        // Bounded like validation (history replay bypasses
                        // the check above, so re-check here). The global
                        // member budget applies on every path: a live drop
                        // under the race must not be resurrected by the next
                        // rebuild (B-1), and the rebuilt state must satisfy
                        // the same budget the live state does.
                        let over_global = self.max_total_members > 0
                            && self.total_members >= self.max_total_members
                            && !group.is_member(&member);
                        if !over_global
                            && (group.members.len() < MAX_MEMBERS || group.is_member(&member))
                            && !group.is_member(&member)
                        {
                            group.members.insert(member.clone(), Default::default());
                            // NIP-CL: an unknown stored join_role is treated
                            // as guest (only the explicit "member" grants a
                            // write-capable role). This is Buzz-only state:
                            // a relay that switched Buzz off must not create
                            // guest markers from a restored Buzz setting.
                            if self.buzz_enabled
                                && group
                                    .settings
                                    .join_role
                                    .as_deref()
                                    .is_some_and(|role| role != "member")
                            {
                                group.guests.insert(member.clone());
                            }
                            added = true;
                        }
                    }
                    if added {
                        self.total_members = self.total_members.saturating_add(1);
                    }
                    if emit && added {
                        // Carry the guest tier on the relay-signed mirror as
                        // a Buzz-level `role` tag. A p-tag role would turn
                        // into an ordinary admin label if Buzz is later
                        // disabled; the separate role tag is ignored by
                        // plain-NIP-29 replay. Stamp it with the apply
                        // stamp: inheriting the client's (possibly
                        // future-dated) JOIN timestamp would let the mirror
                        // outrank a later removal on replay.
                        let mut put = build_put_user(gid, &member, &[], relay_pubkey, now);
                        if join_role_guest {
                            put.tags.push(vec!["role".into(), "guest".into()]);
                        }
                        attach_create_id(
                            &mut put,
                            self.groups
                                .get(gid)
                                .and_then(|group| group.create_id.as_deref()),
                        );
                        out.push(put);
                        out.extend(self.membership_events(gid, relay_pubkey, now));
                        let channel_type = self.notice_channel_type(gid);
                        out.push(build_system_message(
                            gid,
                            &member,
                            Some(&member),
                            "member_joined",
                            relay_pubkey,
                            now,
                        ));
                        out.push(build_membership_notice(
                            MEMBER_ADDED,
                            gid,
                            &channel_type,
                            &member,
                            &member,
                            relay_pubkey,
                            now,
                        ));
                    }
                }
            }
            LEAVE => {
                let member = event.pubkey.clone();
                let removed = if let Some(group) = self.groups.get_mut(gid) {
                    group.guests.remove(&member);
                    group.bots.remove(&member);
                    // The hidden-DM preference belongs to a member; a later
                    // re-add must surface the channel rather than inherit
                    // the stale preference.
                    group.hidden_for.remove(&member);
                    group.members.remove(&member).is_some()
                } else {
                    false
                };
                if removed {
                    self.total_members = self.total_members.saturating_sub(1);
                }
                if emit && removed {
                    let mut remove = build_remove_user(gid, &member, relay_pubkey, now);
                    attach_create_id(
                        &mut remove,
                        self.groups
                            .get(gid)
                            .and_then(|group| group.create_id.as_deref()),
                    );
                    out.push(remove);
                    out.extend(self.membership_events(gid, relay_pubkey, now));
                    let channel_type = self.notice_channel_type(gid);
                    out.push(build_system_message(
                        gid,
                        &member,
                        Some(&member),
                        "member_left",
                        relay_pubkey,
                        now,
                    ));
                    out.push(build_membership_notice(
                        MEMBER_REMOVED,
                        gid,
                        &channel_type,
                        &member,
                        &member,
                        relay_pubkey,
                        now,
                    ));
                }
            }
            9000 => {
                let mut added = 0usize;
                let mut added_members: Vec<String> = Vec::new();
                // The separate `role` tag and the guest/bot tiers are Buzz
                // extensions. In plain NIP-29 mode they stay ordinary role
                // labels (any non-empty role is an admin role in this
                // relay), so disabling Buzz must not silently demote or
                // restrict an existing NIP-29 client.
                let buzz_role = if self.buzz_enabled {
                    tag_value(event, "role").map(str::to_string)
                } else {
                    None
                };
                let relay_signed =
                    !relay_pubkey.is_empty() && event.pubkey.eq_ignore_ascii_case(relay_pubkey);
                if let Some(group) = self.groups.get_mut(gid) {
                    let join_role_guest = self.buzz_enabled
                        && group
                            .settings
                            .join_role
                            .as_deref()
                            .is_some_and(|role| role != "member");
                    // Re-check the last-admin invariant under the write
                    // lock, like the 9001 arm below: two concurrent 9000
                    // demotions can both pass the read-side validation and
                    // otherwise leave the group admin-less. The re-check runs
                    // on every path: a rebuild replays stored history in a
                    // deterministic order that can differ from the arrival
                    // order (same second, id order), and replaying the event
                    // without the re-check would re-apply a demotion the live
                    // race dropped, leaving the group admin-less (B-1).
                    // A relay-signed JOIN mirror is add-only for an
                    // existing member: replay order must not overwrite a
                    // later explicit promotion or a tier restored by the
                    // JOIN. The dedicated marker distinguishes the mirror
                    // from an ordinary relay-master-key `9000` demotion.
                    let relay_join_mirror = relay_signed
                        && event
                            .tags
                            .iter()
                            .any(|tag| tag.first().is_some_and(|name| name == JOIN_MIRROR_TAG));
                    let mut overrides: HashMap<&str, bool> = HashMap::new();
                    for tag in event.tags.iter().filter(|t| t.len() >= 2 && t[0] == P) {
                        if relay_join_mirror && group.is_member(&tag[1]) {
                            continue;
                        }
                        // A Buzz `role=admin|owner|other` tag grants a
                        // privileged role even though the p tag itself has
                        // no role elements; the guest/bot tiers do not.
                        // This helper is shared with the live validation so
                        // the two cannot disagree about the final state.
                        let has_roles = tag_grants_privileged_role(
                            tag,
                            self.buzz_enabled,
                            buzz_role.as_deref(),
                        );
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
                    // Like validation: an already admin-less group has
                    // no last admin to protect (only the relay key can
                    // reach here with such an event).
                    let group_has_admin = group.members.values().any(|roles| !roles.is_empty());
                    if group_has_admin && !retains_admin {
                        // Drop the demotion: the event itself still
                        // stores, but the group keeps its last admin
                        // (the relay key can manage the group anyway).
                        return Vec::new();
                    }
                    // NIP-29: roles are carried as the elements after the
                    // pubkey in each `p` tag (["p", <pubkey>, <role>...]).
                    // The listed roles replace the user's previous roles
                    // ("the user roles must just be updated"), and a `p` tag
                    // without roles leaves the user a plain member.
                    for tag in event.tags.iter().filter(|t| t.len() >= 2 && t[0] == P) {
                        // Bounded like validation (see above). The global
                        // budget applies on every path: the live drop must
                        // not be resurrected by the next rebuild (B-1).
                        if group.members.len() >= MAX_MEMBERS && !group.is_member(&tag[1]) {
                            continue;
                        }
                        // Count members added earlier in this same event:
                        // `total_members` only grows after the loop, so a
                        // bare `>=` check would admit N fresh members past
                        // a nearly-full budget (concurrent fill between
                        // validation and apply makes the stale read real).
                        let over_global = self.max_total_members > 0
                            && self.total_members.saturating_add(added) >= self.max_total_members
                            && !group.is_member(&tag[1]);
                        if over_global {
                            continue;
                        }
                        if relay_join_mirror && group.is_member(&tag[1]) {
                            continue;
                        }
                        let pk = tag[1].clone();
                        // An empty role element (`["p", pk, ""]`) is a
                        // malformed demotion: it must not turn into an
                        // admin grant (an empty-string role is non-empty).
                        let mut roles: HashSet<String> =
                            tag[2..].iter().filter(|r| !r.is_empty()).cloned().collect();
                        // Buzz carries the role in a separate `["role", ...]`
                        // tag on kind:9000. Map its tiers onto the NIP-29
                        // role model: admin/owner are privileged, member and
                        // bot are plain members (bot is remembered
                        // separately for Buzz's 39002), guest is read-only.
                        let mut guest = false;
                        let mut bot = false;
                        // An empty `role` tag carries no role. It must not
                        // count as an explicit grant (or as a privileged
                        // role in the last-admin guard).
                        let explicit = !roles.is_empty()
                            || buzz_role.as_deref().is_some_and(|role| !role.is_empty());
                        if roles.is_empty()
                            && let Some(role) = buzz_role.as_deref()
                        {
                            match role {
                                "" => {}
                                "guest" => guest = true,
                                "member" => {}
                                "bot" => bot = true,
                                other => {
                                    roles.insert(other.to_string());
                                }
                            }
                        }
                        if self.buzz_enabled {
                            if roles.remove("guest") {
                                guest = true;
                            }
                            if roles.remove("bot") {
                                bot = true;
                            }
                            // Buzz's 39002 spells a plain member as the
                            // fourth p-tag element `member`; NIP-29's
                            // p-tag role list uses the same position. A
                            // Buzz client round-tripping its roster must
                            // not silently turn every member into an admin
                            // role named `member`.
                            roles.remove("member");
                            // A privileged role wins over a tier label in
                            // the same p tag: otherwise a user can be both
                            // an admin and a guest, which makes the roster
                            // inconsistent and blocks their posts.
                            if !roles.is_empty() {
                                guest = false;
                                bot = false;
                            }
                        }
                        if self.buzz_enabled {
                            let new_member = !group.members.contains_key(&pk);
                            if !explicit && new_member && join_role_guest {
                                guest = true;
                            }
                            // The p tag is a full role/tier replacement:
                            // an existing guest/bot promoted by a client
                            // with a bare `["p", pk]` (or an empty role
                            // element) must lose its tier. Old relay-signed
                            // JOIN mirrors also carry a bare p tag; they
                            // predate the `role=guest` tag, so a bare
                            // relay-signed 9000 keeps the existing tier
                            // instead of silently promoting every guest on
                            // a rebuild.
                            if guest {
                                group.guests.insert(pk.clone());
                            } else if explicit || new_member || !relay_signed {
                                group.guests.remove(&pk);
                            }
                            if bot {
                                group.bots.insert(pk.clone());
                            } else if explicit || new_member || !relay_signed {
                                group.bots.remove(&pk);
                            }
                            // An empty role list leaves the user a plain
                            // member (replacing any previous roles). A new
                            // membership also clears a stale hidden-DM
                            // preference left by an earlier incarnation.
                            if new_member {
                                group.hidden_for.remove(&pk);
                                added += 1;
                                added_members.push(pk.clone());
                            }
                        } else {
                            let new_member = !group.members.contains_key(&pk);
                            if new_member {
                                group.hidden_for.remove(&pk);
                                added += 1;
                                added_members.push(pk.clone());
                            }
                            // Plain NIP-29 has no guest/bot tiers: a plain
                            // role edit replaces any Buzz-mode markers too,
                            // so re-enabling Buzz cannot silently restore a
                            // stale read-only/bot label.
                            group.guests.remove(&pk);
                            group.bots.remove(&pk);
                        }
                        group.members.insert(pk, roles);
                    }
                    if event.tags.iter().any(|tag| {
                        tag.len() >= 2
                            && tag[0] == P
                            && group
                                .creator
                                .as_deref()
                                .is_some_and(|creator| creator == tag[1])
                    }) {
                        group.creator_role_explicit = true;
                    }
                }
                if added > 0 {
                    self.total_members = self.total_members.saturating_add(added);
                }
                if emit {
                    out.extend(self.membership_events(gid, relay_pubkey, now));
                    let channel_type = self.notice_channel_type(gid);
                    for member in &added_members {
                        out.push(build_system_message(
                            gid,
                            &event.pubkey,
                            Some(member),
                            "member_joined",
                            relay_pubkey,
                            now,
                        ));
                        out.push(build_membership_notice(
                            MEMBER_ADDED,
                            gid,
                            &channel_type,
                            member,
                            &event.pubkey,
                            relay_pubkey,
                            now,
                        ));
                    }
                }
            }
            9001 => {
                let mut removed = 0usize;
                let mut removed_members: Vec<String> = Vec::new();
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
                    // Like validation and the 9000 arm: an already
                    // admin-less group has no last admin to protect.
                    let group_has_admin = group.members.values().any(|roles| !roles.is_empty());
                    if group_has_admin && !retains_admin {
                        // Drop the removal: the event itself still stores,
                        // but the group keeps its last admin (the relay key
                        // can manage the group regardless). The re-check runs
                        // on the replay too, so a restart cannot resurrect
                        // the removal (B-1).
                        return Vec::new();
                    }
                    for pk in removing {
                        group.guests.remove(pk);
                        group.bots.remove(pk);
                        group.hidden_for.remove(pk);
                        if group.members.remove(pk).is_some() {
                            removed += 1;
                            removed_members.push(pk.to_string());
                        }
                    }
                }
                if removed > 0 {
                    self.total_members = self.total_members.saturating_sub(removed);
                }
                if emit {
                    // Record the removal as a relay-signed `9001` mirror
                    // (like the JOIN and LEAVE arms). The relay stamp is
                    // monotonic and later than everything applied before
                    // it, so a replay cannot resurrect the members: without
                    // the mirror, a removal whose own `created_at` predates
                    // a member's join (clock skew inside the accepted
                    // late-publish window) sorts before that join and the
                    // join (plus its put-user mirror) re-adds them on the
                    // next restart.
                    if !removed_members.is_empty() {
                        let mut remove =
                            build_remove_users(gid, &removed_members, relay_pubkey, now);
                        attach_create_id(
                            &mut remove,
                            self.groups
                                .get(gid)
                                .and_then(|group| group.create_id.as_deref()),
                        );
                        out.push(remove);
                    }
                    out.extend(self.membership_events(gid, relay_pubkey, now));
                    let channel_type = self.notice_channel_type(gid);
                    for member in &removed_members {
                        out.push(build_system_message(
                            gid,
                            &event.pubkey,
                            Some(member),
                            "member_removed",
                            relay_pubkey,
                            now,
                        ));
                        out.push(build_membership_notice(
                            MEMBER_REMOVED,
                            gid,
                            &channel_type,
                            member,
                            &event.pubkey,
                            relay_pubkey,
                            now,
                        ));
                    }
                }
            }
            9002 => {
                // A Buzz client sends partial metadata. Persist that
                // provenance so turning Buzz off later cannot reinterpret
                // the stored event as a whole-metadata replacement and
                // clear the group's privacy flags.
                if let Some(group) = self.groups.get_mut(gid) {
                    if self.buzz_enabled {
                        group.buzz_metadata = true;
                    } else if history_replay
                        && event.tags.iter().any(|tag| {
                            tag.first().is_some_and(|name| name == "visibility")
                                && tag.get(1).map(String::as_str) == Some("private")
                        })
                    {
                        // A snapshot-less rebuild can still recognize the
                        // privacy-bearing Buzz form even when the mode is
                        // off; without this marker the next name-only stored
                        // 9002 would be replayed as a whole-metadata edit
                        // and clear `private`.
                        group.buzz_metadata = true;
                    }
                }
                // Re-check the graph invariants under the write lock: two
                // concurrent 9002 edits can each pass the read-side
                // validation against the same state and then interleave
                // into a cycle, drop a child another edit just adopted, or
                // reparent through an admin whose role was revoked in
                // between (the same TOCTOU the 9000/9001 arms close for the
                // last-admin invariant). The re-check runs on the replay
                // too, so an effect dropped here is final: a rebuild cannot
                // introduce a cycle (B-1).
                let mut denials = EditLinkDenials::default();
                // Clone the pre-edit group so the replay-only settings
                // fallback can mutate the store after the immutable borrow
                // ends.
                let group_snapshot = self.groups.get(gid).cloned();
                if let Some(group) = &group_snapshot {
                    let relay_signed =
                        !relay_pubkey.is_empty() && event.pubkey.eq_ignore_ascii_case(relay_pubkey);
                    // A NIP-CL member topic/purpose edit is not a
                    // whole-metadata replacement and must not run the
                    // parent/child machinery (which would detach a subgroup
                    // because the event carries no `parent` tag).
                    if self.buzz_enabled && is_member_topic_edit(group, event, relay_signed) {
                        if let Some(group) = self.groups.get_mut(gid) {
                            apply_settings(group, event, true, history_replay);
                        }
                        if emit {
                            out.push(build_meta_event(
                                gid,
                                self.groups.get(gid),
                                relay_pubkey,
                                now,
                                self.buzz_enabled,
                            ));
                        }
                        return out;
                    }
                    match validate_edit_metadata(
                        self,
                        gid,
                        group,
                        event,
                        relay_signed,
                        history_replay,
                    ) {
                        Ok(links) => denials = links,
                        Err(_) if history_replay => {
                            // A structural error (cycle / declared-children
                            // cap) during replay drops the *links*, not the
                            // whole edit: the settings are still the last
                            // known admin intent and losing `private` would
                            // make the group public. The live path rejects
                            // such an edit outright.
                            if let Some(group) = self.groups.get_mut(gid) {
                                apply_settings(group, event, self.buzz_enabled, history_replay);
                            }
                            return Vec::new();
                        }
                        Err(_) => return Vec::new(),
                    }
                }
                // Buzz's 9002 is a partial edit, so an absent `parent` or
                // `child` tag leaves that link unchanged. Plain NIP-29's
                // whole-metadata edit keeps the pre-Buzz behavior: an absent
                // `parent` detaches and an absent child list clears it. A
                // Buzz-origin channel follows the stored partial semantics
                // on replay; a live plain edit is still NIP-29 whole
                // metadata (with the settings privacy floor).
                let partial_links = self.buzz_enabled
                    || (history_replay
                        && group_snapshot.as_ref().is_some_and(|group| {
                            !group.channel_type.is_empty() || group.buzz_metadata
                        }));
                // A valueless tag is malformed, not evidence that the field
                // was supplied. An explicit empty value (`["parent", ""]`)
                // is the Buzz-partial way to request a detach.
                let has_parent_tag = event
                    .tags
                    .iter()
                    .any(|tag| tag.len() >= 2 && tag[0] == "parent");
                let has_child_tags = event
                    .tags
                    .iter()
                    .any(|tag| tag.len() >= 2 && tag[0] == "child");
                let child_cap = self.declared_children_cap();
                let (parent_before, parent_after, children_before, children_after, livekit_before) = {
                    match self.groups.get_mut(gid) {
                        Some(group) => {
                            let livekit_before = group.settings.livekit;
                            apply_settings(group, event, self.buzz_enabled, history_replay);
                            let children_before = group.children.clone();
                            // Deduplicate while preserving order: a repeated
                            // `child` tag must not list the same child twice.
                            // A link the replay could not re-authorize is
                            // dropped here, not the whole event: the
                            // settings above still apply (M-7).
                            let mut seen = HashSet::new();
                            let declared: Vec<String> = tag_values(event, "child")
                                .filter(|child| !child.is_empty())
                                .filter(|child| !denials.children.contains(*child))
                                .map(str::to_string)
                                .filter(|c| seen.insert(c.clone()))
                                .collect();
                            group.children = if history_replay {
                                // A replay cannot reproduce the live arrival
                                // order within one second. Live validation
                                // requires a parent-side edit to carry every
                                // live-known child, so a *stored* edit that
                                // omits one only ever raced that child's
                                // addition (or skipped live validation, which
                                // the migration gates): merging keeps the
                                // link instead of detaching it. Child
                                // removals happen on the child's own side, so
                                // no live removal is reverted here. The merge
                                // is bounded like the declared-children hint
                                // (a history full of unvalidated 9002s cannot
                                // grow the list without limit).
                                let stored = group.children.clone();
                                let mut present: HashSet<String> = HashSet::new();
                                let mut merged = Vec::with_capacity(stored.len());
                                // The event's declared order is the NIP-29
                                // child order; append only stored children
                                // the event omitted (a same-second race).
                                for child in declared {
                                    if merged.len() >= child_cap {
                                        break;
                                    }
                                    if present.insert(child.clone()) {
                                        merged.push(child);
                                    }
                                }
                                for child in stored {
                                    if merged.len() >= child_cap {
                                        break;
                                    }
                                    if present.insert(child.clone()) {
                                        merged.push(child);
                                    }
                                }
                                merged
                            } else if partial_links && !has_child_tags {
                                // A Buzz partial edit with no child tags
                                // does not mean "remove every child".
                                children_before.clone()
                            } else {
                                declared
                            };
                            let before = group.parent.clone();
                            // A denied link must not detach an existing
                            // parent. The same holds for a Buzz partial edit
                            // that omits the parent tag; an explicit empty
                            // value is the request to detach.
                            let after = if denials.parent || (partial_links && !has_parent_tag) {
                                before.clone()
                            } else {
                                tag_value(event, "parent")
                                    .filter(|parent| !parent.is_empty())
                                    .map(str::to_string)
                            };
                            (
                                before,
                                after,
                                children_before,
                                group.children.clone(),
                                livekit_before,
                            )
                        }
                        None => (None, None, Vec::new(), Vec::new(), false),
                    }
                };
                // A 9002 for a group that does not exist must do nothing:
                // live validation rejects it (`unknown group`), so applying
                // its child-adoption half would steal children from their
                // real parents, dangle their parent pointers at the missing
                // id, and resurrect a bare 39000 for it. This mirrors the
                // parent-side guard below, which drops a link to a deleted
                // parent instead of dangling.
                if !self.groups.contains_key(gid) {
                    return Vec::new();
                }
                // Keep the adoption hint current: a declared child id makes
                // a later CREATE_GROUP scan for the (deterministically
                // smallest) adopting parent. The hint is bounded (see
                // `declare_child`).
                for child in &children_after {
                    self.declare_child(child);
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
                    // Mirror the live validation (`parent group does not
                    // exist`): a replay that deleted the parent earlier in
                    // the same second (the rebuild rank runs 9008 before
                    // 9002) must leave the child orphaned like the live
                    // delete did, not dangle a pointer at the deleted id.
                    let parent_exists = parent_after
                        .as_deref()
                        .is_none_or(|p| self.groups.contains_key(p));
                    if parent_exists && let Some(group) = self.groups.get_mut(gid) {
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
                let child_added: Vec<String> = tag_values(event, "child")
                    .filter(|child| !denials.children.contains(*child))
                    .map(str::to_string)
                    .collect();
                // Detect removals against the list the edit actually left
                // behind, not the event's own tags: on a replay the list is
                // the merge of the stored children and the tags, and a child
                // the replayed edit merely omits must not be detached.
                let children_now: std::collections::HashSet<&str> =
                    children_after.iter().map(String::as_str).collect();
                let mut child_removed: Vec<String> = Vec::new();
                for child in &children_before {
                    if !children_now.contains(child.as_str()) {
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
                    // it so peers see the new link. A declared child that does
                    // not exist yet (a placeholder) has no metadata to
                    // republish: a bare `39000` for it would store a group id
                    // the state machine knows nothing about — the create path
                    // refuses the same ("emit only for a live group") — and a
                    // snapshot-less rebuild would take that metadata for
                    // surviving history and ghost the id permanently.
                    if emit {
                        if let Some(old) = &old_parent {
                            out.push(build_meta_event(
                                old,
                                self.groups.get(old),
                                relay_pubkey,
                                now,
                                self.buzz_enabled,
                            ));
                        }
                        if self.groups.contains_key(child) {
                            out.push(build_meta_event(
                                child,
                                self.groups.get(child),
                                relay_pubkey,
                                now,
                                self.buzz_enabled,
                            ));
                        }
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
                                self.buzz_enabled,
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
                        self.buzz_enabled,
                    ));
                    // Leaving LiveKit: the stored 39004 would keep listing
                    // participants of a room that no longer exists. Publish
                    // an empty list (the spec allows zero `participant`
                    // tags) so subscribers see the room close; the poll
                    // skips non-livekit groups, so this is the only clear.
                    if livekit_before && !self.groups.get(gid).is_some_and(|g| g.settings.livekit) {
                        out.push(build_participants_event(gid, &[], relay_pubkey, now));
                    }
                    if let Some(parent) = self.groups.get(gid).and_then(|g| g.parent.clone()) {
                        out.push(build_meta_event(
                            &parent,
                            self.groups.get(&parent),
                            relay_pubkey,
                            now,
                            self.buzz_enabled,
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
                            self.buzz_enabled,
                        ));
                    }
                    for child in self
                        .groups
                        .get(gid)
                        .map(|g| g.children.clone())
                        .unwrap_or_default()
                    {
                        // Only an existing child has metadata to republish: a
                        // placeholder's bare `39000` would ghost the id on the
                        // next snapshot-less rebuild (see the child-adoption
                        // emit above).
                        if !self.groups.contains_key(&child) {
                            continue;
                        }
                        out.push(build_meta_event(
                            &child,
                            self.groups.get(&child),
                            relay_pubkey,
                            now,
                            self.buzz_enabled,
                        ));
                    }
                }
            }
            9005 => {
                // The referenced events are deleted by the relay itself.
            }
            CREATE_GROUP => {
                let mut adopted_parent = None;
                let mut created = false;
                // An empty id is rejected at intake and validation; the
                // replay path below must not resurrect one either (it would
                // create a phantom group outside the capacity budget). A
                // ghost id is rejected the same way: its create was lost
                // while survivors may remain stored, so reviving it as a
                // default-public group would expose them (validation
                // rejects such creates; this guard keeps replays that
                // bypass validation fail-closed).
                if !gid.is_empty()
                    && !self.groups.contains_key(gid)
                    && !self.ghost.contains(gid)
                    && (history_replay || (!self.at_capacity() && !self.at_member_capacity(1)))
                {
                    // The budget counts the tombstones too (they bound the
                    // store's memory): reclaim room for this group first, so
                    // a create+delete churn cannot fill the budget with
                    // tombstones and lock every later create out.
                    self.reclaim_tombstones(1);
                    // A fresh create resurrects an explicitly deleted id:
                    // clear the delete tombstone so the id is reusable. The
                    // deleted group's events were purged by the relay when
                    // the `9008` was applied, so re-creation starts from an
                    // empty history (no old private content can surface
                    // under the new, default-public settings). Ghost ids
                    // never reach this arm (guarded above), so there is no
                    // tombstone of theirs to clear here.
                    self.deleted.remove(gid);
                    // A Buzz-created channel always carries a channel_type.
                    // Preserve it on a plain-mode history replay so a later
                    // stored partial 9002 can keep the Buzz privacy floor
                    // (see `apply_plain_create_privacy`). Live plain creates
                    // keep the pre-Buzz empty value.
                    let group_channel_type = if self.buzz_enabled {
                        channel_type(event)
                    } else if history_replay {
                        tag_value(event, "channel_type")
                            .filter(|kind| CHANNEL_TYPES.contains(kind))
                            .map(str::to_string)
                            .unwrap_or_default()
                    } else {
                        String::new()
                    };
                    let mut group = Group {
                        creator: Some(event.pubkey.clone()),
                        created_at: Some(event.created_at),
                        create_id: Some(if event.id.is_empty() {
                            format!("synthetic:{gid}")
                        } else {
                            event.id.clone()
                        }),
                        channel_type: group_channel_type,
                        buzz_metadata: self.buzz_enabled,
                        ..Group::default()
                    };
                    // Buzz's kind:9007 carries the NIP-CL visibility,
                    // channel_type, labels and initial metadata; apply them
                    // fully in Buzz mode. Plain NIP-29 `9007` carries no
                    // metadata, so live creates keep the pre-Buzz default.
                    // A plain-mode history replay still honors the privacy
                    // floor of a stored Buzz create (see
                    // `apply_plain_create_privacy`).
                    if self.buzz_enabled {
                        apply_settings(&mut group, event, true, history_replay);
                    } else if history_replay {
                        apply_plain_create_privacy(&mut group, event);
                        // Only NIP-CL/Buzz provenance marks a plain-mode
                        // history create as Buzz-origin. A normal NIP-29
                        // `["private"]` tag also sets `settings.private`, but
                        // it is not evidence of a Buzz create; treating it as
                        // one would replay later whole-metadata 9002 edits as
                        // partial and change ordinary NIP-29 behavior after
                        // a restart.
                        let buzz_marker = event.tags.iter().any(|tag| {
                            tag.first().is_some_and(|name| name == "visibility")
                                && matches!(
                                    tag.get(1).map(String::as_str),
                                    Some("private" | "open" | "public")
                                )
                        });
                        if group.channel_type.is_empty() && buzz_marker {
                            // A Buzz/NIP-CL marker without an explicit
                            // channel type still identifies a Buzz create;
                            // mark it so later partial 9002 replays keep the
                            // privacy floor and metadata. Plain output
                            // ignores the field.
                            group.channel_type = "stream".to_string();
                        }
                        if !group.channel_type.is_empty() {
                            // Preserve the rest of a Buzz create (name,
                            // topic, labels, DM defaults, ...) on a mode-off
                            // rebuild. A plain create has no channel_type,
                            // so its tags stay ignored as before.
                            group.buzz_metadata = true;
                            apply_settings(&mut group, event, true, history_replay);
                        }
                    }
                    // NIP-CL: a DM or system channel is private unless the
                    // create explicitly says otherwise. This is Buzz-only;
                    // in plain NIP-29 the create's NIP-29 `private` tag is
                    // the only privacy switch. A mode-off history replay
                    // still applies the Buzz default so a stored DM/system
                    // create cannot turn its metadata public on a rebuild.
                    if (self.buzz_enabled || history_replay)
                        && matches!(group.channel_type.as_str(), "dm" | "system")
                        && tag_value(event, "visibility") != Some("open")
                    {
                        group.settings.private = true;
                        group.settings.restricted = true;
                        group.settings.closed = true;
                        group.settings.hidden = true;
                    }
                    // NIP-CL/Buzz: the channel creator owns the channel.
                    // Any non-empty NIP-29 role is an admin role in this
                    // relay, so `owner` keeps every existing authorization
                    // check working while giving Buzz the role it expects.
                    group
                        .members
                        .entry(event.pubkey.clone())
                        .or_default()
                        .insert(if self.buzz_enabled { "owner" } else { "admin" }.into());
                    // A group that already declared this id as a child
                    // (a placeholder: the child did not exist yet) adopts
                    // it now, keeping both sides of the parent link
                    // consistent. Only a declared id pays the scan (the
                    // hint is kept by the 9002 arm), so an uncapped store
                    // does not turn n creates into O(n²); the smallest
                    // declaring parent wins deterministically when several
                    // groups declared the same placeholder id.
                    //
                    // The adopting parent consented on its own side by
                    // declaring the placeholder, but the child's creator
                    // never agreed to the link: NIP-29 requires both sides
                    // to administer the group they attach (the 9002
                    // bidirectional rule in `validate_edit_metadata`), so
                    // the creating author must also be an admin of the
                    // prospective parent (the relay master key is an
                    // implicit admin of every group). Without the check, a
                    // parent admin pre-claims any not-yet-existing id as a
                    // placeholder child and whoever creates that id later
                    // is silently grafted into the pre-claimer's tree
                    // (their 39000 gains a `parent` tag they never chose).
                    // A creator who is not an admin of any declaring
                    // parent still gets their group, as a root.
                    if self.declared_children.contains(gid) {
                        let relay_signed = !relay_pubkey.is_empty()
                            && event.pubkey.eq_ignore_ascii_case(relay_pubkey);
                        adopted_parent = self
                            .groups
                            .iter()
                            .filter(|(_, g)| g.children.iter().any(|c| c == gid))
                            .filter(|(_, g)| relay_signed || g.is_admin(&event.pubkey))
                            .map(|(id, _)| id.clone())
                            .min();
                        if let Some(parent) = &adopted_parent {
                            group.parent = Some(parent.clone());
                        }
                    }
                    self.groups.insert(gid.to_string(), group);
                    self.total_members = self.total_members.saturating_add(1);
                    created = true;
                    // A placeholder can be declared by several parents. Only
                    // the deterministic adopter keeps the child; drop the
                    // stale entry from every other parent and republish its
                    // 39000 so the stored tree cannot name a second parent
                    // (which would make the child appear twice).
                    let adopted = adopted_parent.clone();
                    for (other_id, other) in self.groups.iter_mut() {
                        if Some(other_id.as_str()) == adopted.as_deref() {
                            continue;
                        }
                        if let Some(pos) = other.children.iter().position(|c| c == gid) {
                            other.children.remove(pos);
                            if emit {
                                out.push(build_meta_event(
                                    other_id,
                                    Some(other),
                                    relay_pubkey,
                                    now,
                                    self.buzz_enabled,
                                ));
                            }
                        }
                    }
                    if emit && let Some(parent) = &adopted_parent {
                        // The adopting parent's stored metadata must name
                        // the now-existing child: its stored 39000 may have
                        // been built while the id was only a placeholder.
                        out.push(build_meta_event(
                            parent,
                            self.groups.get(parent),
                            relay_pubkey,
                            now,
                            self.buzz_enabled,
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
                    // A DM's membership_events() already publishes the
                    // metadata (it carries the participant `p` tags); a
                    // second identical event would have the same id and be
                    // rejected as a duplicate by the relay's store.
                    if !self
                        .groups
                        .get(gid)
                        .is_some_and(|group| group.channel_type == "dm")
                    {
                        out.push(build_meta_event(
                            gid,
                            self.groups.get(gid),
                            relay_pubkey,
                            now,
                            self.buzz_enabled,
                        ));
                    }
                    if created {
                        let channel_type = self.notice_channel_type(gid);
                        out.push(build_system_message(
                            gid,
                            &event.pubkey,
                            None,
                            "channel_created",
                            relay_pubkey,
                            now,
                        ));
                        out.push(build_membership_notice(
                            MEMBER_ADDED,
                            gid,
                            &channel_type,
                            &event.pubkey,
                            &event.pubkey,
                            relay_pubkey,
                            now,
                        ));
                    }
                    out.extend(self.membership_events(gid, relay_pubkey, now));
                }
            }
            DELETE_GROUP => {
                // Tombstone only known ids: a delete for a completely
                // unknown id (no group, ghost, or tombstone — reachable
                // only via history replay, since validation rejects live
                // 9008s for unknown groups) must not consume the capacity
                // budget forever. Ghost ids keep their lifecycle (delete
                // tombstone, purge, re-creatable); already-deleted ids
                // re-insert idempotently.
                let known = self.groups.contains_key(gid)
                    || self.ghost.contains(gid)
                    || self.deleted.contains(gid);
                if let Some(group) = self.groups.remove(gid) {
                    self.total_members = self.total_members.saturating_sub(group.members.len());
                    // The throttle stamp belongs to the deleted incarnation:
                    // without this a delete+create cycle within the window
                    // would skip the fresh 39002, and dead entries would
                    // accumulate alongside the delete tombstones.
                    self.members_published_at.remove(gid);
                    self.members_dirty.remove(gid);
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
                                    self.buzz_enabled,
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
                                self.buzz_enabled,
                            ));
                        }
                    }
                }
                if known {
                    self.reclaim_tombstones(1);
                    self.deleted.insert(gid.to_string());
                }
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
    /// NIP-CL channel TTL: whether a non-state channel event is older than
    /// the group's configured TTL and must no longer be served. Physical
    /// deletion remains the normal reaper's job; this is the read-time
    /// authority so a TTL edit applies to existing messages immediately.
    pub fn channel_ttl_expired(&self, event: &Event, now: u64) -> bool {
        let Some(gid) = group_id_any(event) else {
            return false;
        };
        self.channel_ttl_expired_gid(gid, event.kind, event.created_at, now)
    }

    /// The lightweight NIP-77 variant: only the group id, kind and timestamp
    /// are available.
    pub fn channel_ttl_expired_gid(&self, gid: &str, kind: u64, created_at: u64, now: u64) -> bool {
        if is_group_action_kind(kind) || (GROUP_META..=GROUP_PINS).contains(&kind) {
            return false;
        }
        let Some(ttl) = self.groups.get(gid).and_then(|group| group.settings.ttl) else {
            return false;
        };
        ttl > 0 && created_at.saturating_add(ttl) <= now
    }

    pub fn visible_to(&self, event: &Event, authed: Option<&str>) -> bool {
        let Some(gid) = group_id_any(event) else {
            return true;
        };
        if !self.visible_kind(gid, event.kind, authed) {
            return false;
        }
        // A JOIN carries the bearer invite code that admitted it. Like the
        // 9009 itself, the code must never be readable by a non-member: a
        // closed public-read group would otherwise leak reusable credentials
        // through its join history.
        if event.kind == JOIN && event_code(event).is_some_and(|code| !code.is_empty()) {
            return authed.is_some_and(|pk| {
                self.groups
                    .get(gid)
                    .is_some_and(|group| group.is_member(pk))
            });
        }
        true
    }

    /// Whether `event` belongs to a membership-gated group (`private`
    /// groups, or `hidden` groups' relay-generated metadata) — i.e. AUTH as
    /// a member could reveal it. Deleted, ghost and unknown groups are not
    /// AUTH-revealable: their content stays gone for everyone. Drives the
    /// NIP-67 `"auth"` EOSE hint.
    pub fn privacy_gated(&self, event: &Event) -> bool {
        // A stale store cannot decide whether a group's content demands an
        // authenticated member, so those events are simply not served
        // (fail-closed): claiming they need auth would advertise that
        // authenticating might help when it cannot.
        let Some(gid) = group_id_any(event) else {
            return false;
        };
        // A stale group cannot decide whether its content demands an
        // authenticated member, so those events are simply not served
        // (fail-closed): claiming they need auth would advertise that
        // authenticating might help when it cannot.
        if self.group_is_stale(gid) {
            return false;
        }
        if self.deleted.contains(gid) || self.ghost.contains(gid) {
            return false;
        }
        let is_meta = (GROUP_META..=GROUP_PINS).contains(&event.kind);
        self.groups.get(gid).is_some_and(|g| {
            (g.settings.private && !is_meta)
                || (g.settings.hidden && (is_meta || is_group_action_kind(event.kind)))
                || event.kind == CREATE_INVITE
                // A JOIN with a code is member-only for the same reason as
                // the 9009 bearer token.
                || (event.kind == JOIN
                    && event_code(event).is_some_and(|code| !code.is_empty()))
        })
    }

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

    /// Whether `gid` carries the fail-closed ghost marker (see
    /// [`Self::mark_ghost`]).
    pub(crate) fn is_ghosted(&self, gid: &str) -> bool {
        self.ghost.contains(gid)
    }

    /// Re-checks the authorization of a live moderation event immediately
    /// before it is applied under the group write lock. The intake precheck
    /// is advisory by the time the database write completes: another admin
    /// may have demoted/removed the author in between, and the apply path
    /// must not let the queued event through on the old grant.
    ///
    /// This deliberately checks only authorization (plus the NIP-CL member
    /// topic/purpose exception), not capacity, last-admin or fidelity: those
    /// are re-checked by the apply arms themselves and must remain able to
    /// run for a still-authorized event.
    pub(crate) fn authorize_live_state_event(
        &self,
        event: &Event,
        relay_pubkey: &str,
    ) -> std::result::Result<(), String> {
        if !(MOD_MIN..=MOD_MAX).contains(&event.kind) {
            return Ok(());
        }
        let Some(gid) = group_id(event) else {
            return Ok(());
        };
        let Some(group) = self.groups.get(gid) else {
            return Ok(());
        };
        if !relay_pubkey.is_empty() && event.pubkey.eq_ignore_ascii_case(relay_pubkey) {
            return Ok(());
        }
        if group.is_admin(&event.pubkey) {
            return Ok(());
        }
        if event.kind == 9002 && self.buzz_enabled && is_member_topic_edit(group, event, false) {
            return Ok(());
        }
        Err("restricted: you are not an admin of this group".into())
    }

    /// Whether `gid` is a confirmed delete tombstone. A rebuild must not
    /// buffer pre-create state for such an id: the old incarnation is gone
    /// and a later create starts a new one.
    pub(crate) fn is_deleted(&self, gid: &str) -> bool {
        self.deleted.contains(gid)
    }

    /// Drops a group that was created only for a relay-side synthetic
    /// command (a Buzz DM open) and whose events were never stored. This is
    /// an in-memory rollback of state with no history, not a NIP-29 delete:
    /// no tombstone is needed, but the global member budget and the
    /// per-group publish throttle must be released with the group.
    pub(crate) fn rollback_unstored_group(&mut self, gid: &str) -> bool {
        let Some(group) = self.groups.remove(gid) else {
            return false;
        };
        self.total_members = self.total_members.saturating_sub(group.members.len());
        self.members_published_at.remove(gid);
        self.members_dirty.remove(gid);
        true
    }

    /// Carries snapshot-backed DM groups across an event-history rebuild.
    ///
    /// DM channels are created by synthetic `9007`/`9000` events that are
    /// deliberately never stored, so a rebuild from surviving events cannot
    /// recreate them. The live store is authoritative for this derived
    /// state; without this hand-off a state-removal rebuild would ghost every
    /// DM id (and `41010` could never recreate it).
    pub(crate) fn adopt_live_dm_groups(
        &mut self,
        groups: impl IntoIterator<Item = (String, Group)>,
    ) {
        for (gid, group) in groups {
            if group.channel_type != "dm" {
                continue;
            }
            // A non-DM group rebuilt from stored events owns the id; do not
            // overwrite it with a stale in-memory DM.
            if self
                .groups
                .get(&gid)
                .is_some_and(|existing| existing.channel_type != "dm")
            {
                continue;
            }
            self.groups.insert(gid.clone(), group);
            self.clear_ghost(&gid);
            self.deleted.remove(&gid);
            // A snapshot-backed DM is current even if the removal walk
            // scoped a stored metadata deletion to its id.
            self.stale_groups.remove(&gid);
        }
        self.recompute_derived();
    }

    /// Removes `pubkey` from every group's member map (a vanish) and keeps
    /// the global member counter in sync. Returns the affected group ids so
    /// the caller can republish their rosters and relay-signed 9000 mirrors;
    /// an empty result means no membership was removed.
    pub fn remove_member_everywhere(&mut self, pubkey: &str) -> Vec<String> {
        let mut affected = Vec::new();
        for (gid, group) in self.groups.iter_mut() {
            if group.members.remove(pubkey).is_some() {
                // A vanish must also drop the per-user Buzz tiers and DM
                // visibility preference; otherwise 39003 keeps advertising
                // a guest/bot role for a pubkey that is no longer a member.
                group.guests.remove(pubkey);
                group.bots.remove(pubkey);
                group.hidden_for.remove(pubkey);
                affected.push(gid.clone());
            }
        }
        if !affected.is_empty() {
            self.total_members = self.total_members.saturating_sub(affected.len());
            for gid in &affected {
                // Force the next membership publish to emit a fresh 39002
                // even for a throttled large group.
                self.members_published_at.remove(gid);
            }
        }
        affected
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

    /// Whether the content of a group may be served to `authed`. `is_meta`
    /// distinguishes relay-generated metadata events (kinds 39000-39005),
    /// which `hidden` groups additionally withhold from non-members. Callers
    /// that know the event kind should use [`Self::visible_kind`] so
    /// moderation events and invite codes are gated too.
    #[cfg(test)]
    pub fn visible_gid(&self, gid: &str, is_meta: bool, authed: Option<&str>) -> bool {
        self.visible_kind(gid, if is_meta { GROUP_META } else { 1 }, authed)
    }

    /// Kind-aware visibility: `hidden` withholds relay metadata and group
    /// actions (moderation/join/leave) from non-members, and invite codes
    /// (9009) are always member-only so a non-member cannot read the bearer
    /// code that admits them to a `closed` group.
    pub fn visible_kind(&self, gid: &str, kind: u64, authed: Option<&str>) -> bool {
        // While the store is known stale (a group-state event was removed
        // and the rebuild has not re-derived the answer), every group
        // decision fails closed: serving an event because its (possibly
        // removed) privacy setting allowed it, or granting membership to a
        // deleted user, hands current state they no longer hold. Mirrors
        // the NIP-43 role store's empty-swap during its own rebuild.
        if self.group_is_stale(gid) {
            return false;
        }
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
            // An unrestored store (NIP-29 disabled with no usable snapshot)
            // knows no group at all: an unknown id must read as private, not
            // public, or the empty store would expose the content of every
            // group it lost (fail-open).
            return !self.unrestored;
        };
        let member = authed.is_some_and(|pk| group.is_member(pk));
        let is_meta = (GROUP_META..=GROUP_PINS).contains(&kind);
        // NIP-29: `private` restricts the group MESSAGES to members; the
        // metadata stays readable (it is not the private content). `hidden`
        // additionally hides the group metadata and the moderation actions
        // that carry it (9002 edits etc.) from non-members. Invite codes are
        // bearer tokens for a `closed` group: a non-member who can read one
        // can join, so they are always member-only.
        if group.settings.private && !member && !is_meta {
            return false;
        }
        if group.settings.hidden && !member && (is_meta || is_group_action_kind(kind)) {
            return false;
        }
        if kind == CREATE_INVITE && !member {
            return false;
        }
        true
    }

    fn membership_events(&mut self, gid: &str, relay_pubkey: &str, now: u64) -> Vec<Event> {
        // A DM's kind:39000 carries its participants as `p` tags (Buzz reads
        // them there rather than joining 39002), so a membership change must
        // refresh the metadata as well. Ordinary channels keep 39000 as the
        // last admin edit, per NIP-29.
        let mut out = Vec::new();
        if self
            .groups
            .get(gid)
            .is_some_and(|group| group.channel_type == "dm")
        {
            out.push(build_meta_event(
                gid,
                self.groups.get(gid),
                relay_pubkey,
                now,
                self.buzz_enabled,
            ));
        }
        out.extend([
            build_admins_event(
                gid,
                self.groups.get(gid),
                relay_pubkey,
                now,
                self.buzz_enabled,
            ),
            // NIP-29's `39003` (the roles in use): small and cheap, so it
            // rides every membership change like the admin list.
            build_roles_event(
                gid,
                self.groups.get(gid),
                relay_pubkey,
                now,
                self.buzz_enabled,
            ),
        ]);
        let members = self.groups.get(gid).map(|g| g.members.len()).unwrap_or(0);
        let due = members <= MEMBERS_EAGER_MAX
            || self
                .members_published_at
                .get(gid)
                .is_none_or(|last| now.saturating_sub(*last) >= MEMBERS_INTERVAL_SECS);
        if due {
            self.members_published_at.insert(gid.to_string(), now);
            self.members_dirty.remove(gid);
            out.push(build_members_event(
                gid,
                self.groups.get(gid),
                relay_pubkey,
                now,
                self.buzz_enabled,
            ));
        } else {
            // Remember that this update was throttled: the stats tick retries
            // it once the interval elapses, so a large group's roster cannot
            // stay permanently stale.
            self.members_dirty.insert(gid.to_string());
        }
        out
    }

    /// Emits the deferred 39002 for groups whose update was throttled and
    /// whose interval has now elapsed. Called from the stats tick.
    pub(crate) fn due_membership_events(&mut self, relay_pubkey: &str, now: u64) -> Vec<Event> {
        let gids: Vec<String> = self.members_dirty.iter().cloned().collect();
        let mut out = Vec::new();
        for gid in gids {
            if !self.groups.contains_key(&gid) {
                self.members_dirty.remove(&gid);
                continue;
            }
            let members = self.groups.get(&gid).map(|g| g.members.len()).unwrap_or(0);
            let due = members <= MEMBERS_EAGER_MAX
                || self
                    .members_published_at
                    .get(&gid)
                    .is_none_or(|last| now.saturating_sub(*last) >= MEMBERS_INTERVAL_SECS);
            if due {
                self.members_dirty.remove(&gid);
                self.members_published_at.insert(gid.clone(), now);
                out.push(build_members_event(
                    &gid,
                    self.groups.get(&gid),
                    relay_pubkey,
                    now,
                    self.buzz_enabled,
                ));
            }
        }
        out
    }

    /// Builds the relay-signed metadata events (39000/39001/39002/39003/
    /// 39005) for every live group. Used after a rebuild from stored
    /// events: a database whose state was rebuilt — a migration from
    /// another relay, or a dropped snapshot — has no (or stale) stored
    /// metadata, and clients need it to display the groups.
    pub(crate) fn all_metadata_events(&mut self, relay_pubkey: &str, now: u64) -> Vec<Event> {
        let gids: Vec<String> = self.groups.keys().cloned().collect();
        let mut out = Vec::with_capacity(gids.len().saturating_mul(4));
        for gid in gids {
            // `membership_events` already emits the DM 39000 so its
            // participant `p` tags are refreshed. Emitting the generic one
            // here as well would produce two byte-identical replaceable
            // events; the second is a duplicate, making
            // `publish_group_metadata` report failure forever.
            if !self
                .groups
                .get(&gid)
                .is_some_and(|group| group.channel_type == "dm")
            {
                out.push(build_meta_event(
                    &gid,
                    self.groups.get(&gid),
                    relay_pubkey,
                    now,
                    self.buzz_enabled,
                ));
            }
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
        self.trust_stored_joins = true;
        let rebuilt = self
            .rebuild_inner(db, relay_pubkey, None, Vec::new(), Vec::new())
            .await;
        self.trust_stored_joins = false;
        if rebuilt {
            // A completed full replay walked every stored group event:
            // unknown ids are genuinely unknown again (see the `unrestored`
            // field). The vanish variant does not clear the flag: it only
            // rebuilds the ids that were already known. A full replay also
            // proves the removed-state gates no longer apply, so clear them;
            // otherwise a startup recovery mark would hide every group for
            // the process lifetime.
            self.unrestored = false;
            self.stale = false;
            self.stale_groups.clear();
        }
        rebuilt
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
        self.trust_stored_joins = true;
        let rebuilt = self
            .rebuild_inner(
                db,
                relay_pubkey,
                Some(previous),
                previous_deleted,
                previous_ghost,
            )
            .await;
        self.trust_stored_joins = false;
        rebuilt
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
        // after a restart. A stored 9002 is replayed as it was accepted (the
        // replay skips the live-only fidelity/authorization re-checks) and
        // merges its child list instead of replacing it, so a same-second
        // race neither drops the edit's settings nor detaches a child the
        // other edit added; the stored 39000-39005 are regenerated from that
        // state. The in-memory member map can still diverge from the
        // pre-restart state until the next edit. The rank ordering also
        // inverts cross-kind arrival order
        // within a second: a 9001 remove followed in the same second by a
        // 9021 JOIN replays as [9001, JOIN] (correct) but a JOIN followed by
        // a 9001 replays as [9001, JOIN] too — the removed member resurrects
        // until the next edit. Arrival order is not stored, so this cannot be
        // fixed exactly; the relay-stamped put-user (9000) events, which
        // arrive after the member operation, keep the stored 39002 list
        // correct.
        const PAGE: usize = 50_000;
        // A legacy/hostile history may contain a group-state event whose
        // client timestamp precedes its create. The live state machine
        // rejects state before the incarnation; a rebuild buffers it until
        // the create is seen instead of silently discarding a private
        // setting or admin grant. Bound the buffer so malformed history
        // cannot exhaust memory.
        const PENDING_STATE_MAX: usize = 50_000;
        let mut pending_state: HashMap<String, Vec<Event>> = HashMap::new();
        let mut pending_epochs: HashMap<String, String> = HashMap::new();
        let mut pending_arrivals: HashMap<String, u64> = HashMap::new();
        let mut pending_state_count = 0usize;
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
            let page_ids: Vec<Vec<u8>> = page
                .iter()
                .filter_map(|event| event.id_bytes().map(|id| id.to_vec()))
                .collect();
            let Some(page_epochs) = db.group_epochs_startup(page_ids.clone()).await else {
                log::error!(
                    "group state rebuild aborted: the group-epoch index did not answer; \
                     refusing to persist an incomplete group store"
                );
                return false;
            };
            let Some(page_arrivals) = db.event_arrivals(page_ids).await else {
                log::error!(
                    "group state rebuild aborted: the arrival index did not answer; \
                     refusing to persist an incomplete group store"
                );
                return false;
            };
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
            page.sort_by(|a, b| replay_order(a, b, &page_arrivals));
            let max_created = page.last().map(|event| event.created_at);
            // The removals issued in each second of this page. `group_rank`
            // applies a `9001` before a same-second `9021`, so without this
            // the join re-adds the member the removal just removed and a
            // removed member comes back on the next restart. Every other
            // pair keeps the order `group_rank` gives it.
            let same_second_removals =
                SameSecondRemovals::collect_with_arrivals(&page, &page_arrivals);
            for mut event in page {
                if event.kind == JOIN && vanished.contains(&event.pubkey) {
                    continue;
                }
                if event.kind == JOIN
                    && same_second_removals.removes_before(
                        &event.pubkey,
                        event.created_at,
                        group_id(&event).unwrap_or_default(),
                        page_arrivals.get(&event.id).copied(),
                    )
                {
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
                // Legacy events accepted before the 600-second group-state
                // future bound must not outrank later removals on replay.
                // The live path no longer admits them; skip them here rather
                // than resurrecting a stale membership.
                if event.created_at > unix_now().saturating_add(600) {
                    continue;
                }
                let gid = group_id(&event).unwrap_or_default().to_string();
                let event_epoch = event.id_bytes().map(hex::encode);
                let expected_epoch = event_epoch
                    .as_ref()
                    .and_then(|id| page_epochs.get(id))
                    .map(String::as_str);
                if event.kind != CREATE_GROUP
                    && !gid.is_empty()
                    && !self.groups.contains_key(&gid)
                    && !self.ghost.contains(&gid)
                    && !self.deleted.contains(&gid)
                {
                    // A delete for an unknown id is not a state-bearing
                    // event to resurrect; live validation would refuse it.
                    if event.kind == DELETE_GROUP {
                        continue;
                    }
                    if pending_state_count < PENDING_STATE_MAX {
                        if let (Some(key), Some(expected)) = (&event_epoch, expected_epoch) {
                            pending_epochs.insert(key.clone(), expected.to_string());
                        }
                        if let Some(seq) = page_arrivals.get(&event.id) {
                            pending_arrivals.insert(event.id.clone(), *seq);
                        }
                        pending_state.entry(gid).or_default().push(event);
                        pending_state_count += 1;
                        continue;
                    }
                    // Bounded history exceeded: fall back to the previous
                    // no-op behavior for the overflow rather than aborting a
                    // healthy store.
                    log::warn!(
                        "group rebuild pending-state cap ({PENDING_STATE_MAX}) exceeded; \
                         applying an out-of-order state event without its create"
                    );
                }
                // Every stored moderation event is replayed. The relay
                // applied it in arrival order when it was accepted, and a
                // second rebuild-time authorization would drop legitimate
                // events whose rank-ordered position differs from their
                // arrival: migrated databases are made faithful by the
                // migration itself, which refuses to import moderation its
                // own replay would reject.
                self.apply_with_epoch(
                    &event,
                    relay_pubkey.unwrap_or(""),
                    unix_now(),
                    false,
                    true,
                    expected_epoch,
                );
                if event.kind == CREATE_GROUP
                    && let Some(mut buffered) = pending_state.remove(&gid)
                {
                    buffered.sort_by(|a, b| replay_order(a, b, &pending_arrivals));
                    pending_state_count = pending_state_count.saturating_sub(buffered.len());
                    for buffered_event in buffered {
                        let expected = buffered_event
                            .id_bytes()
                            .map(hex::encode)
                            .and_then(|id| pending_epochs.remove(&id));
                        self.apply_with_epoch(
                            &buffered_event,
                            relay_pubkey.unwrap_or(""),
                            unix_now(),
                            false,
                            true,
                            expected.as_deref(),
                        );
                    }
                }
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
                if let Some(gid) = crate::nips::nip29::group_id(event).filter(|gid| !gid.is_empty())
                {
                    seen_gids.insert(gid.to_string());
                    seen_h_gids.insert(gid.to_string());
                } else if (GROUP_META..=GROUP_PINS).contains(&event.kind)
                    && let Some(gid) = crate::nips::nip29::group_id_d(event)
                    && !gid.is_empty()
                {
                    // Only the relay-generated metadata kinds identify a
                    // group by `d`: every addressable event (long-form
                    // 30023, app data, ...) carries a `d` tag that must not
                    // ghost a non-existent group or consume the group
                    // budget. Mirrors `group_id_any`.
                    //
                    // A keyed relay publishes this metadata itself:
                    // metadata stored by anyone else (possible only while
                    // NIP-29 was disabled) is not evidence that a group
                    // existed and must not ghost the id. Keyless rebuilds
                    // keep the conservative rule.
                    if relay_pubkey.is_none_or(|pk| event.pubkey.eq_ignore_ascii_case(pk)) {
                        seen_gids.insert(gid.to_string());
                    }
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
            if self.groups.contains_key(&gid) || self.ghost.contains(&gid) {
                continue;
            }
            // A deleted id whose events are gone is safe to re-create; one
            // with h-tagged survivors is not (its purge never completed).
            if self.deleted.contains(&gid) && !seen_h_gids.contains(&gid) {
                continue;
            }
            // The ghost set is a fail-closed memory structure, not a live
            // group budget (H02). It grows with the surviving h-tagged
            // history; refusing the rebuild once it reaches max_groups would
            // turn a single orphan h-id into an unrestored store that hides
            // every group. Keep inserting so the orphan history stays
            // withheld, and warn at the crossing point.
            if self.max_groups > 0 && self.ghost.len() == self.max_groups {
                log::warn!(
                    "NIP-29 rebuild ghost set reached relay.max_groups ({}); continuing in fail-closed mode",
                    self.max_groups
                );
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
        self.reclaim_tombstones(1);
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

    /// Clears a stale ghost marker without asserting a delete tombstone: a
    /// live group already proves the id need not stay hidden (the concurrent
    /// create/repair race, see `Relay::repair_group_ghost_for_create`).
    pub(crate) fn clear_ghost(&mut self, gid: &str) {
        self.ghost.remove(gid);
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

/// The pubkeys a `kind:9001` removed, indexed by the second that removed
/// them.
///
/// The rebuild replays stored history in `(created_at, group_rank, kind, id)`
/// order, which cannot recover the live arrival order inside a single second —
/// `id` is a hash. One pair therefore needs an explicit decision: a removal
/// and a re-join in the same second. `group_rank` applies the `9001` first and
/// the `9021` second, so the join re-adds the member the removal just removed
/// and a removed member is resurrected by the next restart. Re-ranking the
/// removal after the join would fix that, but it would also drag the removal
/// past the same-second moderation events, and the migration replay
/// authorizes those against the membership state at their own position
/// (`is_admin`), so it would change which of them a completed migration
/// accepted.
///
/// Skipping the join leaves every other pair's order bit-for-bit identical and
/// is the restrictive reading of an unknowable order: when a removal and a
/// re-join share a second, the member ends up removed. A join in any later
/// second is unaffected and is honoured.
/// Total replay order for one timestamp second. Create/delete retain their
/// structural precedence; ordinary state events prefer the durable ingest
/// sequence over the kind/rank/id fallback.
pub(crate) fn replay_order(
    a: &Event,
    b: &Event,
    arrivals: &HashMap<String, u64>,
) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let class = |kind: u64| match kind {
        CREATE_GROUP => 0u8,
        DELETE_GROUP => 1,
        _ => 2,
    };
    let base = |a: &Event, b: &Event| {
        (group_rank(a.kind), a.kind, &a.id).cmp(&(group_rank(b.kind), b.kind, &b.id))
    };
    match a.created_at.cmp(&b.created_at) {
        Ordering::Equal => {}
        other => return other,
    }
    let (ca, cb) = (class(a.kind), class(b.kind));
    match ca.cmp(&cb) {
        Ordering::Equal => {}
        other => return other,
    }
    if ca == 2
        && let (Some(sa), Some(sb)) = (arrivals.get(&a.id), arrivals.get(&b.id))
    {
        return sa.cmp(sb).then_with(|| base(a, b));
    }
    base(a, b)
}

type SecondRemovals = HashMap<(u64, String), HashMap<String, Vec<Option<u64>>>>;

#[derive(Default)]
pub(crate) struct SameSecondRemovals {
    by_second: SecondRemovals,
}

impl SameSecondRemovals {
    /// Indexes the `p` tags of every `kind:9001` in `events` by second. The
    /// caller must pass a page whose seconds are complete, which both replays
    /// already guarantee: each refuses to persist a page cut mid-second
    /// (`boundary_second_complete`), so no removal can be hiding in the next
    /// page while its join is applied in this one.
    #[cfg(test)]
    pub(crate) fn collect(events: &[Event]) -> Self {
        Self::collect_with_arrivals(events, &HashMap::new())
    }

    /// Like [`Self::collect`], but records the durable arrival sequence of
    /// each removal when available.
    pub(crate) fn collect_with_arrivals(events: &[Event], arrivals: &HashMap<String, u64>) -> Self {
        let mut by_second: SecondRemovals = HashMap::new();
        for event in events.iter().filter(|event| event.kind == REMOVE_USER) {
            let Some(gid) = group_id(event) else {
                continue;
            };
            let seq = arrivals.get(&event.id).copied();
            let entry = by_second
                .entry((event.created_at, gid.to_string()))
                .or_default();
            for pubkey in tag_values(event, P) {
                entry.entry(pubkey.to_string()).or_default().push(seq);
            }
        }
        Self { by_second }
    }

    /// Whether any `kind:9001` in the second `at` removed `pubkey` from
    /// `gid`. Legacy callers without arrival metadata conservatively let a
    /// removal win.
    pub(crate) fn removes(&self, pubkey: &str, at: u64, gid: &str) -> bool {
        self.by_second
            .get(&(at, gid.to_string()))
            .is_some_and(|removed| removed.contains_key(pubkey))
    }

    /// Arrival-aware form used by the rebuild: a JOIN that arrived after the
    /// removal survives; a removal without a durable arrival value remains
    /// conservative (remove wins).
    pub(crate) fn removes_before(
        &self,
        pubkey: &str,
        at: u64,
        gid: &str,
        join_seq: Option<u64>,
    ) -> bool {
        let Some(removals) = self
            .by_second
            .get(&(at, gid.to_string()))
            .and_then(|removed| removed.get(pubkey))
        else {
            return false;
        };
        let Some(_join_seq) = join_seq else {
            return true;
        };
        // When both the JOIN and every removal in the second have durable
        // arrival order, the page sort itself produces the correct final
        // state: no conservative suppression is needed. A removal without
        // sequence metadata falls back to the legacy remove-wins rule.
        removals.iter().any(Option::is_none)
    }
}

pub(crate) fn event_code(event: &Event) -> Option<&str> {
    tag_value(event, CODE)
}

/// Links a replay could not re-authorize. The caller applies the event's
/// settings but drops only these links (M-7): re-adjudicating authority is
/// order-dependent, so it must not discard an otherwise live-accepted
/// metadata edit wholesale.
#[derive(Default)]
struct EditLinkDenials {
    parent: bool,
    children: HashSet<String>,
}

/// Whether this is the NIP-CL member form of a topic/purpose edit. Such an
/// event is accepted without admin rights, but it is a partial settings
/// update only: the apply path must not interpret the absent `parent`/
/// `child` tags as a request to detach or clear the group's links.
fn is_member_topic_edit(group: &Group, event: &Event, relay_signed: bool) -> bool {
    if event.kind != 9002 || relay_signed {
        return false;
    }
    let pubkey = event.pubkey.as_str();
    if !group.is_member(pubkey) || group.is_guest(pubkey) || group.is_admin(pubkey) {
        return false;
    }
    event.tags.iter().all(|tag| {
        tag.is_empty() || matches!(tag[0].as_str(), H | "topic" | "purpose" | "previous")
    })
}

/// Validates the subgroup rules of a `kind:9002` edit-metadata event against
/// the graph as the edit will leave it. The structural and safety invariants
/// (a single `parent` tag, no self/two-way links, no cycles, the
/// declared-children bound) always run. The authorization/fidelity checks —
/// the parent existing and the author administering it, the edit carrying
/// every existing child, consent over newly adopted children — reject on the
/// live path (`replay == false`). On replay they record the denied links in
/// [`EditLinkDenials`] instead: the caller drops only those links and still
/// applies the edit's settings, because the arrival order inside one second
/// is not recoverable and dropping the whole edit would roll the derived
/// state back. Imported moderation is the migration's gate, not the
/// rebuild's.
///
/// `relay_signed` marks an event from the relay's own key, which NIP-29
/// treats as the group master key: it is an implicit admin of every group
/// (see `validate_write_for_relay`), so the group-admin requirements do not
/// apply to it.
fn validate_edit_metadata(
    store: &GroupStore,
    gid: &str,
    group: &Group,
    event: &Event,
    relay_signed: bool,
    replay: bool,
) -> anyhow::Result<EditLinkDenials> {
    let mut denials = EditLinkDenials::default();
    // NIP-29: "A kind:9002 MAY carry at most one parent tag". A second
    // parent tag would be silently ignored (only the first is applied), so
    // the edit is rejected outright instead.
    if tag_values(event, "parent").count() > 1 {
        bail!("restricted: at most one parent tag is allowed");
    }
    // An empty child id is not a group id: accepting it would leave a junk
    // entry in 39000 that no group can ever occupy or remove.
    if tag_values(event, "child").any(str::is_empty) {
        bail!("restricted: child id must not be empty");
    }
    // A group cannot be its own child, and one 9002 must not make a
    // group both the parent and the child of this one (that would create
    // a two-way cycle the walks below cannot see: both directions would
    // be applied and every later parent edit would loop forever).
    // An empty parent value is the explicit detach form; it is not a group
    // id that must exist.
    let parent_value = tag_value(event, "parent")
        .filter(|parent| !parent.is_empty())
        .map(str::to_string);
    if tag_values(event, "child").any(|c| c == gid) {
        bail!("restricted: a group cannot be its own child");
    }
    if let Some(parent) = &parent_value
        && tag_values(event, "child").any(|c| c == parent)
    {
        bail!("restricted: a group cannot be both parent and child");
    }
    // Both new edges must be checked together, against the graph as this edit
    // will leave it. The apply arm creates, in one commit:
    //
    //   `parent: P`  ->  gid.parent = P          (an upward edge from gid)
    //                    P.children += gid       (a downward edge from P)
    //   `child: C`   ->  C.parent  = gid         (an upward edge from C)
    //                    gid.children = [C…]    (a downward edge from gid)
    //
    // Two separate walks over the *stored* state cannot see a cycle that
    // closes through one of those new edges, because the edge does not exist
    // yet when the walk runs. Concretely, with `C.parent = G` already stored
    // and this group unparented, an edit carrying `parent: C` and `child: G`
    // passed both walks and published the cycle `G -> C -> G` in the
    // relay-signed 39000 metadata, so every client walking the tree up to a
    // root looped forever.
    //
    // The parent relation is functional (every group has at most one parent),
    // so every cycle contains a node whose upward walk revisits a node. This
    // edit only creates edges incident to `gid`, the new parent and the
    // declared children, so walking *up* from each of those — through the
    // pending edges rather than the stored ones — is exhaustive.
    let declared_children: HashSet<&str> = tag_values(event, "child").collect();
    let upcoming_parent = |node: &str| -> Option<&str> {
        // The pending edges of this edit replace the stored ones; every other
        // node keeps the parent the store holds.
        if node == gid {
            return parent_value.as_deref();
        }
        if declared_children.contains(node) {
            return Some(gid);
        }
        store.groups.get(node).and_then(|g| g.parent.as_deref())
    };
    // Walk *up* from every node this edit touches. The parent relation is
    // functional, so any cycle the edit creates contains one of them, and the
    // walk follows the pending edges rather than the stored ones — which is
    // what catches a cycle closing through an edge this very event adds.
    let mut starts: Vec<&str> = vec![gid];
    if let Some(parent) = &parent_value {
        starts.push(parent.as_str());
    }
    starts.extend(tag_values(event, "child"));
    for start in starts {
        let mut cursor = Some(start);
        let mut visited: HashSet<&str> = HashSet::new();
        while let Some(current) = cursor {
            // Revisiting a node means the parent relation loops. That is the
            // cycle this edit would create; a pre-existing one in the stored
            // data is reported the same way instead of being walked forever.
            if !visited.insert(current) {
                bail!("restricted: would create a cycle");
            }
            cursor = upcoming_parent(current);
        }
    }
    // The declared children must not create a cycle seen from below either:
    // walking down the children lists from a declared child must not reach
    // this group. This is kept alongside the upward walk because it rejects
    // declaring an *ancestor* as a child, which the upward walk cannot see
    // when the edit carries no `parent` tag (the group is detached from its
    // stored parent, so no upward walk from it loops). A visited set stops the
    // walk on pre-existing cycles in the stored data instead of looping.
    for child in tag_values(event, "child") {
        let mut queue: Vec<&str> = vec![child];
        let mut visited: HashSet<&str> = HashSet::new();
        while let Some(current) = queue.pop() {
            if current == gid {
                bail!("restricted: would create a cycle");
            }
            if !visited.insert(current) {
                continue;
            }
            queue.extend(
                store
                    .groups
                    .get(current)
                    .into_iter()
                    .flat_map(|g| g.children.iter().map(String::as_str)),
            );
        }
    }
    // A parent value must name an existing group, and the author must be its
    // admin. Live edits always re-check authority. A replay re-checks only a
    // *new* link: an already-linked parent was consented to by an earlier
    // accepted edit, and re-adjudicating it cannot reconstruct the historical
    // roles. A new link in a stored event (stored while NIP-29 was disabled,
    // or imported) must not graft a foreign group; a missing parent is
    // dropped by the apply side on replay instead of dangling.
    if let Some(parent) = parent_value {
        let already_linked = store
            .groups
            .get(gid)
            .and_then(|group| group.parent.as_deref())
            == Some(parent.as_str());
        if !replay || !already_linked {
            match store.groups.get(&parent) {
                Some(parent_group) => {
                    // The relay's own key is an implicit admin of every
                    // group (NIP-29: the relay master key may manage groups),
                    // so a relay-signed 9002 can reparent or adopt without an
                    // explicit role.
                    if !relay_signed && !parent_group.is_admin(event.pubkey.as_str()) {
                        if replay {
                            denials.parent = true;
                        } else {
                            bail!("restricted: you are not an admin of the parent group");
                        }
                    }
                }
                None => {
                    if !replay {
                        bail!("restricted: parent group does not exist");
                    }
                    // Replay: drop the dangling link but apply the settings.
                    denials.parent = true;
                }
            }
        }
    }
    // NIP-29: a metadata edit must carry every existing child as a child
    // tag, or the edit is rejected — otherwise a partial edit (e.g. only a
    // name change) would silently drop the children on the apply side,
    // which replaces the list. Live only: a replay merges the declared
    // children into the stored list instead of replacing it (see the
    // `apply` arm), so a stored edit that raced a same-second child addition
    // cannot detach that child, and the check has nothing left to protect.
    if !replay {
        // Buzz's 9002 is partial: no `child` tags means "leave the child
        // list unchanged", and the apply path preserves it. Plain NIP-29
        // keeps the whole-metadata rule: every existing child must be
        // listed, or the edit is rejected instead of silently dropping
        // them. If a Buzz edit does carry child tags, treat the list as the
        // replacement and enforce the same completeness check.
        let has_child_tags = event
            .tags
            .iter()
            .any(|tag| tag.len() >= 2 && tag[0] == "child");
        let partial_children = (store.buzz_enabled
            || (replay && (group.buzz_metadata || !group.channel_type.is_empty())))
            && !has_child_tags;
        if !partial_children {
            let children: HashSet<&str> = tag_values(event, "child").collect();
            if !group.children.iter().all(|c| children.contains(c.as_str())) {
                bail!("restricted: missing child tags in metadata edit");
            }
        }
    }
    // Adopting a new child through the parent's list requires authority
    // over the child too: otherwise a foreign admin could hijack an
    // orphan group by listing it (each group's own 39001 is authoritative
    // for its scope). Reordering already-linked children stays parent-only.
    // Unknown ids (no group yet) are still listable as placeholders. A
    // replay re-checks only *new* adoptions: a child that already names this
    // group as its parent consented earlier; a new link in a stored event
    // (stored while NIP-29 was disabled, or imported) must not graft a
    // foreign group.
    for child in tag_values(event, "child") {
        // "Already linked" means the *child's own* stored parent names
        // this group: only then did the child's side consent to the
        // link, and a reorder needs no further authority. An id that is
        // merely present in this group's stored children list may be a
        // placeholder declared before the child existed (see
        // `declare_child`): its creator never consented, so the
        // child-admin check below still applies. Otherwise the declaring
        // parent could graft a group it does not administer by
        // re-listing the placeholder after the child's creation.
        let linked = store
            .groups
            .get(child)
            .is_some_and(|g| g.parent.as_deref() == Some(gid));
        if linked {
            continue;
        }
        if !relay_signed
            && let Some(child_group) = store.groups.get(child)
            && !child_group.is_admin(event.pubkey.as_str())
        {
            if replay {
                denials.children.insert(child.to_string());
            } else {
                bail!("restricted: you are not an admin of the child group");
            }
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
    declared_after
        .extend(tag_values(event, "child").filter(|child| !denials.children.contains(*child)));
    if declared_after.len() > cap {
        bail!("restricted: too many declared child groups");
    }
    Ok(denials)
}
