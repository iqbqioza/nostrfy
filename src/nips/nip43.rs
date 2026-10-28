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
/// NIP-43 invite request (`kind:28935`): the spec's implementation note has
/// clients request it from relays. This relay does not produce 28935 events
/// (invite codes are issued with NIP-86 `createclaim`), so a client-signed
/// one is rejected at intake (see `Relay::validate_base`).
pub const INVITE: u64 = 28935;
pub const LEAVE: u64 = 28936;
/// Tag on a `kind:33534` tombstone marking a role as deleted.
pub const DELETED_TAG: &str = "deleted";
/// Upper bound on the NIP-43 relay member list (the claim-admitted
/// `assignments`, published as `kind:13534`). Every admission re-signs the
/// whole list with an add-user event, so an uncapped list lets one invite
/// code admit unbounded keys: each admission grows the O(n) republish into
/// O(n²) total work and the memory without limit. Mirrors the NIP-29
/// per-group member cap; members already listed are unaffected.
pub(crate) const MAX_RELAY_MEMBERS: usize = 10_000;

/// Bound on roles attached to one member. The NIP-43 roster is relay-signed
/// and rebuilt on every membership change, so an admin must not be able to
/// attach an unbounded role list to one pubkey.
pub(crate) const MAX_ROLES_PER_MEMBER: usize = 16;

/// Bound on distinct role definitions. Role definitions and the derived
/// 39003/39001 lists are relay-signed state; an unbounded registry makes a
/// single roster rebuild arbitrarily large.
pub(crate) const MAX_ROLES: usize = 256;

/// A role id is a tag value in the relay-signed roster, so its bytes are
/// bounded like any other generated metadata field.
pub(crate) const MAX_ROLE_BYTES: usize = 64;
pub(crate) const MAX_ROLES_BYTES_PER_MEMBER: usize = 4 * 1024;

/// Bound on NIP-86 invite codes. They live only in the roles snapshot, so
/// an uncapped admin-created set makes every snapshot write and list
/// response arbitrarily large.
pub(crate) const MAX_CLAIMS: usize = 10_000;

fn bounded_roster_roles(mut roles: Vec<String>, max_roles: usize) -> Vec<String> {
    roles.retain(|role| !role.is_empty() && role.len() <= MAX_ROLE_BYTES);
    roles.sort();
    roles.dedup();
    let mut used = 0usize;
    roles.retain(|role| {
        let next = used.saturating_add(role.len());
        if next > MAX_ROLES_BYTES_PER_MEMBER {
            return false;
        }
        used = next;
        true
    });
    roles.truncate(max_roles);
    roles
}

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
    /// in the snapshot — every rebuild from events drops them, including
    /// the routine role-store revocation a vanish triggers (fail-closed:
    /// joins are rejected until an admin recreates a code).
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

/// Whether `role` is the synthetic roster token injected for configured
/// relay owners. It is display metadata for Buzz, not a NIP-43 assignment:
/// accepting it as a real role made a removed operator identity survive a
/// rebuild and retain relay-admin authority.
fn is_synthetic_owner_role(role: &str) -> bool {
    role.eq_ignore_ascii_case("owner")
}

/// Removes the synthetic `owner` token from restored assignments. An entry
/// that consisted only of `owner` was the synthetic roster row (or an old
/// explicit owner grant, which has the same display-only semantics) and is
/// dropped; a role-empty entry without `owner` is a claim-admitted member
/// and must survive.
fn strip_synthetic_owner_assignments(assignments: &mut HashMap<String, Vec<String>>) {
    assignments.retain(|_, roles| {
        let had_owner = roles.iter().any(|role| is_synthetic_owner_role(role));
        roles.retain(|role| !is_synthetic_owner_role(role));
        !had_owner || !roles.is_empty()
    });
}

impl RoleStore {
    /// Whether the store holds event-derived role state: a role definition
    /// or an assignment that names at least one role. Role-empty entries can
    /// be claim-admitted members or synthetic owner/allowlist roster rows;
    /// they must not make an otherwise empty rebuild look authoritative over
    /// a former-key snapshot.
    pub fn has_role_state(&self) -> bool {
        !self.roles.is_empty() || self.assignments.values().any(|roles| !roles.is_empty())
    }

    /// Whether `pubkey` holds at least one role assignment.
    pub fn is_member_of(&self, pubkey: &str) -> bool {
        // Membership is presence on the member list: a claim-admitted
        // joiner carries no roles yet still appears in `kind:13534` and
        // must get the `duplicate:` verdict on rejoin. Only `remove_pubkey`
        // (a leave request) deletes an entry, and `unassign`/`delete` drop
        // one only when the cleanup itself emptied its role list, so a
        // role-empty entry is exactly the claim-admitted case.
        self.assignments.contains_key(pubkey)
    }

    /// Persisted snapshot of the role state (see the `ROLE` table).
    #[cfg(test)]
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

    /// Serializes the persisted role snapshot directly from the live store.
    /// The hot persistence path holds the read guard across this call, so the
    /// bytes describe one consistent state; this replaces the previous
    /// `snapshot()` clone (roles + every assignment vector + claims) that
    /// doubled the peak memory of a large member list.
    pub(crate) fn encode_snapshot(&self, stamp: u64, seq: u64) -> serde_json::Result<Vec<u8>> {
        #[derive(serde::Serialize)]
        struct SnapshotRef<'a> {
            roles: &'a HashMap<String, Role>,
            assignments: &'a HashMap<String, Vec<String>>,
            claims: &'a std::collections::BTreeSet<String>,
            stamp: u64,
            seq: u64,
        }
        serde_json::to_vec(&SnapshotRef {
            roles: &self.roles,
            assignments: &self.assignments,
            claims: &self.claims,
            stamp,
            seq,
        })
    }

    /// Restores state persisted by [`Self::snapshot`].
    pub(crate) fn restore(&mut self, snap: RolesSnapshot) {
        self.roles = snap.roles;
        if self.roles.len() > MAX_ROLES {
            let mut ids: Vec<String> = self.roles.keys().cloned().collect();
            ids.sort();
            let keep: std::collections::HashSet<String> = ids.into_iter().take(MAX_ROLES).collect();
            self.roles.retain(|id, _| keep.contains(id));
        }
        self.assignments = snap.assignments;
        // Older snapshots materialized the relay configuration's synthetic
        // `owner` roster row into a real assignment. That made a removed
        // operator identity retain the role after a restart. `owner` is a
        // display-only row injected by `membership_event`, never an
        // assignable NIP-43 role, so strip it while preserving every
        // ordinary role on the same member. A claim-admitted member's empty
        // entry is not an owner row and stays.
        strip_synthetic_owner_assignments(&mut self.assignments);
        if self.assignments.len() > MAX_RELAY_MEMBERS {
            let mut keys: Vec<String> = self.assignments.keys().cloned().collect();
            keys.sort();
            let keep: std::collections::HashSet<String> =
                keys.into_iter().take(MAX_RELAY_MEMBERS).collect();
            self.assignments.retain(|pk, _| keep.contains(pk));
        }
        for roles in self.assignments.values_mut() {
            *roles = bounded_roster_roles(std::mem::take(roles), MAX_ROLES_PER_MEMBER);
        }
        self.claims = snap.claims;
        if self.claims.len() > MAX_CLAIMS {
            // A snapshot written before the cap (or by an older build) must
            // not keep an unbounded claim list alive in memory. Keep the
            // deterministic BTreeSet prefix; an admin can re-create any
            // dropped code.
            self.claims = self.claims.iter().take(MAX_CLAIMS).cloned().collect();
        }
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
        if id.is_empty() || id.len() > MAX_ROLE_BYTES {
            return;
        }
        if !self.roles.contains_key(id) && self.roles.len() >= MAX_ROLES {
            return;
        }
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
            let kept = members_without_roles(&self.assignments);
            for roles in self.assignments.values_mut() {
                roles.retain(|r| r != id);
            }
            self.assignments
                .retain(|pubkey, roles| kept.contains(pubkey) || !roles.is_empty());
            true
        } else {
            false
        }
    }

    pub fn assign(&mut self, pubkey: &str, role: &str) -> bool {
        // `owner` is the synthetic roster token, not an assignable role.
        // Allowing it here would create an assignment that the rebuild
        // deliberately discards, so report the same "unknown role" result
        // as any other non-assignable id.
        if is_synthetic_owner_role(role) || !self.roles.contains_key(role) {
            return false;
        }
        if !self.assignments.contains_key(pubkey) && self.assignments.len() >= MAX_RELAY_MEMBERS {
            return false;
        }
        let roles = self.assignments.entry(pubkey.to_string()).or_default();
        if roles.len() >= MAX_ROLES_PER_MEMBER {
            return false;
        }
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
            // Only `remove_pubkey` (a leave request) deletes an entry; a
            // member whose grant this cleanup emptied goes, but a member
            // that was already role-empty — a claim-admitted joiner — must
            // keep the entry: it had no grant to lose, and dropping it would
            // silently revoke a membership `changed` reports as untouched,
            // so the caller skips both the persist and the republish and
            // every store disagrees until a later mutation papers over it.
            if roles.is_empty() && changed {
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
        // Replay and tests also call this directly, so repeat the intake
        // shape checks instead of relying on the NIP-86 validator.
        if claim.trim().is_empty()
            || claim != claim.trim()
            || claim.chars().count() > Self::MAX_CLAIM_LEN
            || claim.chars().any(char::is_control)
        {
            return false;
        }
        if self.claims.len() >= MAX_CLAIMS && !self.claims.contains(claim) {
            return false;
        }
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
    /// Returns false when the list is already at [`MAX_RELAY_MEMBERS`]: the
    /// replay path enforces the cap here because its live-store check saw
    /// the revoked empty store during a rebuild. An existing member is an
    /// idempotent success.
    pub fn admit(&mut self, pubkey: &str) -> bool {
        if self.assignments.contains_key(pubkey) {
            return true;
        }
        if self.assignments.len() >= MAX_RELAY_MEMBERS {
            return false;
        }
        self.assignments.entry(pubkey.to_string()).or_default();
        true
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
    ///
    /// `extra_members` lets a relay that enforces an allowlist include those
    /// pubkeys as plain `member` entries, so NIP-43-aware clients (Buzz)
    /// see the same closed community the write gate enforces. `owners` are
    /// the relay's own administrator identities (NIP-11 `pubkey` and the
    /// NIP-86 admin); they always carry the `owner` role, which is what Buzz's
    /// community-members panel reads. Owner entries win over an assigned
    /// role so a stale assignment cannot demote the relay operator.
    pub fn membership_event(
        &self,
        relay_pubkey: &str,
        now: u64,
        extra_members: &[String],
        owners: &[String],
    ) -> Event {
        let mut event = Self::base(MEMBERSHIP_LIST, relay_pubkey, now);
        let mut members: std::collections::BTreeMap<String, Vec<String>> =
            std::collections::BTreeMap::new();
        for (pk, assigned) in &self.assignments {
            let had_owner = assigned.iter().any(|role| is_synthetic_owner_role(role));
            let mut roles = assigned.clone();
            // A stale snapshot or an explicit NIP-86 owner grant must not
            // turn into a real roster role for an ordinary member. Only the
            // configured-owner branch below emits `owner`. An entry that
            // consisted only of the synthetic token is not a membership; a
            // role-empty entry without it is a claim-admitted member.
            roles.retain(|role| !is_synthetic_owner_role(role));
            if had_owner && roles.is_empty() {
                continue;
            }
            members.insert(
                pk.clone(),
                bounded_roster_roles(roles, MAX_ROLES_PER_MEMBER),
            );
        }
        for pubkey in extra_members {
            members.entry(pubkey.clone()).or_default();
        }
        for pubkey in owners {
            // Preserve an owner's explicitly assigned roles instead of
            // replacing the whole entry with `owner`. Otherwise a rebuild
            // that skipped the synthetic owner entry would also lose the
            // assigned role, and an owner demoted from config would lose it
            // permanently. `owner` itself is display-only: it is not stored
            // in `assignments` and does not authorize relay commands.
            let mut roles = self.assignments.get(pubkey).cloned().unwrap_or_default();
            roles.retain(|role| !is_synthetic_owner_role(role));
            let mut roles = bounded_roster_roles(roles, MAX_ROLES_PER_MEMBER.saturating_sub(1));
            if !roles.iter().any(|role| role == "owner") {
                roles.insert(0, "owner".to_string());
            }
            members.insert(pubkey.clone(), roles);
        }
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
        // Synthetic allowlist entries are published as role-empty members by
        // `membership_event`, but they are not role assignments. Rebuilding
        // them into `assignments` lets an unallow/ban leave them in `13534`
        // and consumes the relay member cap. Skip role-empty entries for the
        // current allowlist; a real role grant to an allowlisted member has
        // roles and is kept.
        let allowlisted: std::collections::HashSet<String> = match db.load_access().await {
            crate::db::LoadAccessOutcome::Loaded(access) => access
                .allowed_pubkeys
                .into_iter()
                .map(|(pubkey, _)| pubkey.to_ascii_lowercase())
                .collect(),
            crate::db::LoadAccessOutcome::Missing => std::collections::HashSet::new(),
            crate::db::LoadAccessOutcome::Failed => {
                log::warn!(
                    "role state rebuild cannot read the access allowlist; synthetic entries may \
                     remain until the next role rebuild"
                );
                std::collections::HashSet::new()
            }
        };
        // A vanished pubkey must not be resurrected as a role holder by a
        // pre-vanish membership list. The vanish table is permanent and
        // attacker-growable, so do not materialize every marker: collect the
        // bounded candidate set from the latest membership list and keep
        // only candidates that are actually vanished.
        let mut candidates: std::collections::HashSet<String> = std::collections::HashSet::new();
        let member_filter = Filter {
            kinds: Some(vec![MEMBERSHIP_LIST]),
            authors: Some(vec![relay_pubkey.to_string()]),
            limit: Some(1),
            ..Filter::default()
        };
        let Some((latest_members, _)) = db
            .query_full_startup(vec![member_filter], 1, unix_now(), false)
            .await
        else {
            log::error!(
                "role state rebuild aborted: the latest membership list could not be read; \
                 refusing to persist an incomplete role store"
            );
            return false;
        };
        for event in latest_members {
            for tag in event.tags.iter().filter(|tag| tag.len() >= 2) {
                if tag[0] == "member" && crate::nips::nip29::is_pubkey_hex(&tag[1]) {
                    candidates.insert(tag[1].to_ascii_lowercase());
                }
            }
        }
        let mut vanished: std::collections::HashSet<String> = std::collections::HashSet::new();
        if !candidates.is_empty()
            && db
                .vanish_pubkeys_each(|key| {
                    let lower = hex::encode(key);
                    if candidates.contains(&lower) {
                        vanished.insert(lower);
                    }
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
                            let kept = members_without_roles(&self.assignments);
                            for roles in self.assignments.values_mut() {
                                roles.retain(|r| r != id);
                            }
                            self.assignments
                                .retain(|pubkey, roles| kept.contains(pubkey) || !roles.is_empty());
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
                            if tag.len() < 2
                                || tag[0] != "member"
                                || vanished.contains(&tag[1])
                                || (tag.len() == 2
                                    && allowlisted.contains(&tag[1].to_ascii_lowercase()))
                            {
                                continue;
                            }
                            // `owner` is injected by `membership_event` for
                            // the configured relay identities; it is not a
                            // real role. Materializing it made a removed
                            // owner keep relay-admin authority forever.
                            // Strip it and preserve the member's ordinary
                            // roles; an owner-only row disappears. A bare
                            // row without `owner` is a claim-admitted
                            // member and remains an empty assignment.
                            let had_owner =
                                tag[2..].iter().any(|role| is_synthetic_owner_role(role));
                            let mut roles: Vec<String> = tag[2..]
                                .iter()
                                .filter(|role| !is_synthetic_owner_role(role))
                                .cloned()
                                .collect();
                            if had_owner && roles.is_empty() {
                                continue;
                            }
                            // Sorted and deduplicated: the tag order is
                            // not part of the protocol, and an unstable
                            // order made rebuilt role lists differ from
                            // the published ones.
                            roles.sort();
                            roles.dedup();
                            self.assignments.insert(tag[1].clone(), roles);
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
        let kept = members_without_roles(&self.assignments);
        for assigned in self.assignments.values_mut() {
            // `owner` was already stripped above. Every remaining role must
            // have survived its definition event; there is no synthetic
            // exemption left that could keep a removed grant authorized.
            assigned.retain(|role| roles.contains_key(role));
        }
        self.assignments
            .retain(|pubkey, assigned| kept.contains(pubkey) || !assigned.is_empty());
        true
    }
}

/// The pubkeys whose membership currently assigns no roles. Used by the
/// role cleanups to tell "a grant this cleanup emptied" from "a member
/// with no roles": deleting a role drops it from a grant, and an entry
/// left empty becomes stale ONLY when it had roles to lose. A
/// claim-admitted member (`admit`, no roles yet) was already empty, so it
/// is a real membership — keep it. The previous
/// `retain(|_, roles| !roles.is_empty())` ignored that difference and
/// evicted every claim-admitted participant on every role deletion and on
/// every rebuild.
fn members_without_roles(
    assignments: &std::collections::HashMap<String, Vec<String>>,
) -> std::collections::HashSet<String> {
    assignments
        .iter()
        .filter(|(_, roles)| roles.is_empty())
        .map(|(pubkey, _)| pubkey.clone())
        .collect()
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
    fn unassign_keeps_a_claim_admitted_member() {
        // A claim-admitted member is a role-empty entry (admit() creates it
        // with no roles), and `unassign` used to drop that entry even when it
        // removed nothing: `roles.is_empty()` was already true, so the member
        // silently lost the membership it got from its claim while `changed`
        // stayed false — the caller then skipped the persist AND the
        // republish, leaving the live store, the persisted snapshot and the
        // published `kind:13534` in disagreement. `delete` was fixed for this
        // with `members_without_roles`; `unassign` was missed.
        let mut store = RoleStore::default();
        store.create("r1", "r1", "", "", None);
        let claim_holder = "cc".repeat(32);
        let roled = "dd".repeat(32);
        store.admit(&claim_holder);
        assert!(store.assign(&roled, "r1"));
        assert!(store.is_member_of(&claim_holder));
        assert_eq!(store.assignments[&claim_holder].len(), 0);

        // Revoking a role the claim-holder never had: nothing changed, and
        // the membership must survive.
        assert!(
            !store.unassign(&claim_holder, "r1"),
            "revoking an absent grant reports no change"
        );
        assert!(
            store.is_member_of(&claim_holder),
            "a claim-admitted member must keep the membership it was admitted with"
        );
        assert_eq!(
            store.assignments[&claim_holder].len(),
            0,
            "the entry must not gain a role"
        );
        // The published membership (role-empty entries included) is intact.
        let members: Vec<&String> = store.assignments.keys().collect();
        assert!(
            members.iter().any(|m| m.as_str() == claim_holder),
            "the claim-holder must still be listed in kind:13534: {members:?}"
        );

        // The roled member is still cleaned up when its last role goes.
        assert!(store.unassign(&roled, "r1"));
        assert!(
            !store.is_member_of(&roled),
            "a member whose grant this cleanup emptied must still be dropped"
        );
        assert!(store.is_member_of(&claim_holder));
    }

    #[test]
    fn admission_cap_is_enforced_by_admit_itself() {
        // The replay path (rebuild + buffered `AdmitMember`) applies
        // `RoleStore::admit` without the live write-lock cap check, so the
        // store method itself must refuse to grow past the cap.
        let mut store = RoleStore::default();
        for i in 0..MAX_RELAY_MEMBERS {
            assert!(store.admit(&format!("{i:064x}")), "admission {i} must fit");
        }
        assert_eq!(store.assignments.len(), MAX_RELAY_MEMBERS);
        let extra = format!("{MAX_RELAY_MEMBERS:064x}");
        assert!(!store.admit(&extra), "the cap must refuse a new member");
        assert_eq!(store.assignments.len(), MAX_RELAY_MEMBERS);
        assert!(!store.is_member_of(&extra));
        // An existing member remains an idempotent success at the cap.
        let existing = store.assignments.keys().next().unwrap().clone();
        assert!(store.admit(&existing));
        assert_eq!(store.assignments.len(), MAX_RELAY_MEMBERS);
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

        let allowlisted = "dd".repeat(32);
        let owner = "ee".repeat(32);
        store.create("mod", "mod", "", "", None);
        assert!(store.assign(&owner, "mod"));
        let members = store.membership_event(
            "relaypub",
            now,
            std::slice::from_ref(&allowlisted),
            std::slice::from_ref(&owner),
        );
        assert_eq!(members.kind, MEMBERSHIP_LIST);
        assert_eq!(members.tags[0], vec!["-"]);
        assert!(
            members
                .tags
                .contains(&vec!["member".into(), "c308e1f8".into(), "king".into()])
        );
        assert!(
            members.tags.contains(&vec!["member".into(), allowlisted]),
            "an allowlisted pubkey must appear in the NIP-43 roster"
        );
        let owner_tag = members
            .tags
            .iter()
            .find(|tag| tag.len() >= 2 && tag[0] == "member" && tag[1] == owner)
            .expect("the relay owner must be listed");
        assert!(owner_tag.iter().any(|role| role == "owner"));
        assert!(
            owner_tag.iter().any(|role| role == "mod"),
            "a synthetic owner tag must not overwrite an assigned role"
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
    fn rebuild_keeps_claim_admitted_members() {
        // A claim-admitted joiner is admitted with an entry holding NO
        // roles (`admit`), and `is_member_of` treats it as membership with no
        // roles (its rejoin gets "duplicate:"). The rebuild's cleanups then
        // evicted every such entry: the deleted-role tombstone branch runs
        // `assignments.retain(|_, assigned| !assigned.is_empty())`, and so
        // does the end-of-rebuild filter — both assume an empty entry is
        // stale, but this one is deliberate. Every rebuild (any role event,
        // a vanish, a restart that rescans) and every `delete` (deleterole)
        // dropped all claim-admitted participants.
        use crate::nips::nip01;
        use std::sync::Arc;
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join("nostrfy-nip43-claim-rebuild-test")
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
            let claimy = "ab".repeat(32);
            let roledy = "cc".repeat(32);
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
            // The claim-admitted member carries no role; the other does.
            let mut members = Event {
                id: String::new(),
                pubkey: relay_pk.clone(),
                created_at: 200,
                kind: MEMBERSHIP_LIST,
                tags: vec![
                    vec!["-".into()],
                    vec!["member".into(), claimy.clone()],
                    vec!["member".into(), roledy.clone(), "kept".into()],
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
                store.is_member_of(&roledy),
                "a role grant survives the rebuild"
            );
            assert!(
                store.is_member_of(&claimy),
                "a claim-admitted member with no roles must survive the rebuild"
            );
            drop(db);
        });
    }

    #[test]
    fn invite_claims_are_bounded() {
        let mut store = RoleStore::default();
        for i in 0..MAX_CLAIMS {
            assert!(
                store.add_claim(&format!("claim-{i}")),
                "claim {i} must fit before the cap"
            );
        }
        assert!(
            !store.add_claim("claim-over-cap"),
            "a new claim must be refused at the cap"
        );
        assert!(
            !store.add_claim("claim-0"),
            "an existing claim remains an idempotent no-op success"
        );
    }

    #[test]
    fn role_assignment_and_registry_are_bounded() {
        let mut store = RoleStore::default();
        for i in 0..(MAX_ROLES + 4) {
            store.create(&format!("r{i}"), "R", "", "", None);
        }
        assert_eq!(
            store.roles.len(),
            MAX_ROLES,
            "the role registry must stop at its cap"
        );
        for i in 0..MAX_ROLES_PER_MEMBER {
            assert!(store.assign("aa", &format!("r{i}")));
        }
        assert!(
            !store.assign("aa", &format!("r{MAX_ROLES_PER_MEMBER}")),
            "one member must not accumulate an unbounded role list"
        );
    }

    #[test]
    fn rebuild_does_not_materialize_synthetic_owner_roles() {
        // `membership_event` publishes configured owners as `owner` rows for
        // Buzz's roster. They are display metadata, not assignments: a
        // removed operator must not retain relay-admin authority after a
        // rebuild, while an owner's ordinary assigned role must survive.
        use crate::nips::nip01;
        use std::sync::Arc;
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join("nostrfy-nip43-owner-rebuild-test")
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
            let current_owner = "11".repeat(32);
            let former_owner = "22".repeat(32);
            let claimy = "33".repeat(32);
            let mut role = Event {
                id: String::new(),
                pubkey: relay_pk.clone(),
                created_at: 100,
                kind: ROLE_DEFINITION,
                tags: vec![
                    vec!["-".into()],
                    vec!["d".into(), "mod".into()],
                    vec!["label".into(), "Mod".into()],
                ],
                content: String::new(),
                sig: String::new(),
            };
            let mut members = Event {
                id: String::new(),
                pubkey: relay_pk.clone(),
                created_at: 200,
                kind: MEMBERSHIP_LIST,
                tags: vec![
                    vec!["-".into()],
                    // Synthetic owner-only row for a current/former config
                    // identity: must not become an assignment.
                    vec!["member".into(), current_owner.clone(), "owner".into()],
                    // An owner with a real role keeps that role, but not the
                    // synthetic `owner` token.
                    vec![
                        "member".into(),
                        former_owner.clone(),
                        "owner".into(),
                        "mod".into(),
                    ],
                    // A claim-admitted member has no roles and is real.
                    vec!["member".into(), claimy.clone()],
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
            assert!(
                !store.assignments.contains_key(&current_owner),
                "a synthetic owner-only row must not become an assignment"
            );
            assert_eq!(
                store.assignments.get(&former_owner),
                Some(&vec!["mod".to_string()]),
                "the owner's ordinary role must survive without the synthetic token"
            );
            assert!(
                store.is_member_of(&claimy),
                "a claim-admitted role-empty member must survive"
            );
            assert!(
                store.has_role_state(),
                "the surviving mod role makes the store authoritative"
            );
        });
    }

    #[test]
    fn restore_strips_legacy_synthetic_owner_assignments() {
        let owner = "11".repeat(32);
        let former = "22".repeat(32);
        let claimy = "33".repeat(32);
        let mut assignments = std::collections::HashMap::new();
        assignments.insert(owner.clone(), vec!["owner".to_string()]);
        assignments.insert(former.clone(), vec!["owner".to_string(), "mod".to_string()]);
        assignments.insert(claimy.clone(), Vec::new());
        let mut store = RoleStore::default();
        store.restore(RolesSnapshot {
            assignments,
            ..Default::default()
        });
        assert!(
            !store.assignments.contains_key(&owner),
            "an owner-only legacy snapshot row is synthetic and must be dropped"
        );
        assert_eq!(
            store.assignments.get(&former),
            Some(&vec!["mod".to_string()]),
            "non-owner roles must survive snapshot sanitization"
        );
        assert!(
            store.is_member_of(&claimy),
            "a role-empty claim member must survive snapshot sanitization"
        );
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

#[cfg(test)]
mod snapshot_format_tests {
    use super::*;

    #[test]
    fn encoded_snapshot_matches_the_typed_format() {
        // The persistence hot path serializes the borrowed store directly.
        // Keep the bytes compatible with the typed reader and with older
        // binaries that expect the same fields.
        let mut store = RoleStore::default();
        store.create("mod", "Moderator", "keeps order", "37", Some(2));
        store.assign("aa".repeat(32).as_str(), "mod");
        store.admit("bb".repeat(32).as_str());
        store.add_claim("welcome-1");
        let mut expected = store.snapshot();
        expected.stamp = 42;
        expected.seq = 7;
        let data = store.encode_snapshot(42, 7).expect("encode");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&data).unwrap(),
            serde_json::to_value(&expected).unwrap(),
            "the role snapshot JSON must not drift"
        );
        assert!(serde_json::from_slice::<RolesSnapshot>(&data).is_ok());
    }
}
