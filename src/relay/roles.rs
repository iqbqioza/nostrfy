//! NIP-43 role administration: role definitions and member assignments
//! managed through the NIP-86 RPC, plus the published membership list
//! and add/remove-user events.

use std::sync::atomic::Ordering;

use crate::event::Event;
use crate::nips::nip01;
use crate::nips::nip43::RoleStore;
use crate::util::unix_now;

/// Outcome of an RPC-facing role grant/revoke. NIP-86 reports `true`
/// for both a landed change and an idempotent no-op (a duplicate grant
/// or a missing revocation); only an unknown grant target, a disabled
/// subsystem, a missing relay key, or a failed persistence surfaces an
/// error.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum RoleChange {
    /// The store changed (and the membership was republished).
    Applied,
    /// Nothing to do (duplicate grant / missing revocation): success.
    Noop,
    /// A grant naming a role that does not exist: an error.
    Unknown,
    /// NIP-43 disabled, relay key missing, or the membership event
    /// could not be stored: an error.
    Failed,
}

/// Failure of a NIP-86 invite-code mutation (see
/// [`super::Relay::create_claim`]).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum ClaimRejection {
    /// NIP-43 is disabled or the relay key is missing.
    Unavailable,
    /// The change is live in memory, but the role snapshot could not be
    /// persisted (or a rebuild still owns it). The caller must not report
    /// success: a lost `deleteclaim` would re-open the invite code.
    NotDurable,
}

/// Outcome of a NIP-43 claim admission (see [`super::Relay::admit_member`]).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum Admission {
    /// The membership is recorded (a new member, or one already listed).
    Recorded,
    /// The relay member list is at
    /// [`crate::nips::nip43::MAX_RELAY_MEMBERS`]: the admission was refused
    /// instead of growing it.
    Full,
    /// NIP-43 is disabled or the relay key is missing.
    Unavailable,
    /// The key requested to vanish (NIP-62): the admission was rolled back
    /// because a VANISH committed between the precheck and the write.
    Vanished,
}

impl super::Relay {
    /// Applies a role mutation to the live store, capturing it for replay
    /// when a rebuild is pending or in flight (see
    /// [`super::RolesRebuildBuffer`]). The caller holds the buffer lock from
    /// the live apply through its publish, so a mutation is either replayed
    /// onto the freshly rebuilt store or applied (and stored) after the swap —
    /// never lost in between. `mutate` returns `(result, changed)`; a refused
    /// mutation (e.g. an unknown role) is not captured, so the replay cannot
    /// apply what the live store rejected — except callers that force
    /// `changed` for removals the revoked empty store cannot confirm (see
    /// [`Self::apply_leave_request`]).
    ///
    /// The lock is passed in instead of taken here so the caller can keep it
    /// across the event publish. `mark_roles_stale` takes the same lock, so
    /// it cannot revoke the store between this apply and the publish: either
    /// it runs first (the mutation sees `dirty` and is captured) or the
    /// mutation finishes storing its event first (the rebuild sees the event).
    pub(super) async fn mutate_roles<R>(
        &self,
        buffer: &mut super::RolesRebuildBuffer,
        mutation: super::BufferedRoleMutation,
        mutate: impl FnOnce(&mut RoleStore) -> (R, bool),
    ) -> R {
        // Claims are snapshot-only and may accompany the old assignments we
        // are protecting after a keyless/empty rebuild; only a role or
        // membership change makes it safe to overwrite that snapshot.
        let clears_preserve = !matches!(
            &mutation,
            super::BufferedRoleMutation::CreateClaim { .. }
                | super::BufferedRoleMutation::DeleteClaim { .. }
        );
        let (result, changed) = {
            let mut roles = self.roles.write().await;
            mutate(&mut roles)
        };
        if changed && clears_preserve {
            // A real role/membership change supersedes the snapshot we
            // protected after an empty/keyless rebuild; persistence is safe.
            self.release_role_snapshot_preserve();
        }
        // Capture while a rebuild is pending, not just while its scan runs:
        // the revoked window starts at marking (`dirty`, stored before the
        // store is revoked) and ends at worker exit (`running`), but the scan
        // flag only covers the walk itself. A mutation accepted in the
        // pre-scan gap would otherwise never replay.
        let rebuild_pending = self.roles_rebuild.dirty.load(Ordering::SeqCst)
            || self.roles_rebuild.running.load(Ordering::SeqCst);
        if changed && (buffer.scanning || rebuild_pending) {
            if buffer.mutations.len() >= super::ROLES_REBUILD_BUFFER_MAX {
                buffer.overflow = true;
            } else {
                buffer.mutations.push(mutation);
            }
        }
        result
    }

    /// Signs a query-time relay event (a NIP-CW window or thread overlay)
    /// without storing it. Returns false when the relay has no signing key.
    pub(crate) fn sign_relay_event(&self, event: &mut Event) -> bool {
        let Some(keypair) = &self.key else {
            return false;
        };
        nip01::sign(event, keypair).is_ok()
    }

    /// Whether the relay-signed role definition for `id` survives in the
    /// stored history the rebuild will scan. During a revoked window the live
    /// store is empty, so an RPC must not accept a role id from a stale hint:
    /// the definition may be the very event whose removal triggered the
    /// rebuild. Checking the surviving event makes the reply honest (N43-L04).
    async fn role_definition_exists(&self, id: &str) -> bool {
        let Some(relay_pubkey) = self.relay_pubkey() else {
            return false;
        };
        let filter: crate::filter::Filter = serde_json::from_value(serde_json::json!({
            "kinds": [crate::nips::nip43::ROLE_DEFINITION],
            "#d": [id],
        }))
        .expect("static filter");
        match self
            .db
            .query_full_startup(vec![filter], 1, unix_now(), false)
            .await
        {
            Some((events, _)) => events.iter().any(|event| {
                event.pubkey == relay_pubkey
                    // A tombstone is the deleted role, not a definition.
                    && !event.tags.iter().any(|tag| {
                        tag.first().map(String::as_str) == Some(crate::nips::nip43::DELETED_TAG)
                    })
            }),
            // A database that cannot answer must not authorize the mutation:
            // the role's survival is unverified, so report it as unknown and
            // let the operator retry after the rebuild.
            None => false,
        }
    }

    /// Signs, stores and broadcasts a relay-generated event. The event must
    /// already carry a strictly monotonic [`StampClock`] stamp (all builders
    /// stamp through `stamp_floor`); a stored version can never outrank the
    /// newest state because the stamps reflect the order in which the state
    /// was applied, not the order in which the events are stored.
    pub(crate) async fn store_relay_event(&self, event: &mut Event) -> Result<bool, ()> {
        // Buzz-only relay events are side effects of group membership
        // changes. With the Buzz layer disabled, do not publish them: the
        // group operation itself must still succeed, so report success
        // without touching the database.
        if !self.config.read().await.relay.enabled_buzz
            && matches!(
                event.kind,
                crate::nips::nip29::SYSTEM_MESSAGE
                    | crate::nips::nip29::MEMBER_ADDED
                    | crate::nips::nip29::MEMBER_REMOVED
                    | 30622
            )
        {
            return Ok(true);
        }
        super::store_relay_event_parts(
            &self.db,
            self.key,
            &self.stamps,
            &self.live_tx,
            &self.stats,
            event,
            false,
        )
        .await
    }

    /// Role state events retry a same-timestamp replacement tie at the
    /// stamp clock's ceiling: NIP-01 keeps the lower id, so without the retry
    /// the newer membership list or role definition can be dropped as a
    /// duplicate and the role sequence never advances (N43-L03).
    pub(super) async fn store_role_event(&self, event: &mut Event) -> Result<bool, ()> {
        super::store_relay_event_parts(
            &self.db,
            self.key,
            &self.stamps,
            &self.live_tx,
            &self.stats,
            event,
            true,
        )
        .await
    }

    /// Signs, stores and broadcasts a relay-generated event. Returns
    /// whether the event actually landed in the database: the RPC-facing
    /// role methods must not report success when the persistence failed
    /// (a success would leave the operator with an in-memory-only change
    /// that silently disappears on the next restart).
    async fn publish_relay_event(&self, mut event: Event) -> bool {
        self.store_role_event(&mut event).await.is_ok()
    }

    /// The pubkeys a `restrict_relay` allowlist admits, as NIP-43 member
    /// entries. An open relay has no enforced membership, so the list is
    /// empty and NIP-43 is not advertised (see `effective_supported_nips`).
    pub(crate) async fn allowlisted_members(&self) -> Vec<String> {
        let access = self.access.read().await;
        if !access.restrict_relay {
            return Vec::new();
        }
        access
            .allowed_pubkeys
            .iter()
            .map(|(pubkey, _)| pubkey.to_ascii_lowercase())
            .collect()
    }

    /// The relay's administrator identities, published as NIP-43 `owner`
    /// entries: the advertised NIP-11 `pubkey` (`relay.pubkey`) and the
    /// NIP-86 admin (`rpc.admin_pubkey`). Buzz's community-members panel
    /// reads roles from `kind:13534`, so without these the operator appears
    /// absent or, worse, as a plain member. The relay's signing key
    /// (`relay.private_key`, NIP-11 `self`) is deliberately not included:
    /// it is the relay's event signer, not an administrator identity, and
    /// listing it would put a key no one controls in the member roster.
    /// Deduplicated and sorted for a deterministic event.
    pub(crate) async fn relay_owner_members(&self) -> Vec<String> {
        let cfg = self.config.read().await;
        let mut owners: Vec<String> = [cfg.relay.pubkey.trim(), cfg.rpc.admin_pubkey.trim()]
            .into_iter()
            .filter(|pk| !pk.is_empty())
            .map(str::to_ascii_lowercase)
            .collect();
        drop(cfg);
        owners.sort();
        owners.dedup();
        owners
    }

    /// Publishes the empty NIP-IA archived-identities snapshot
    /// (`kind:13535`). nostrfy has no archive store yet, but NIP-IA-aware
    /// clients (Buzz) query this snapshot as their archive-state check; a
    /// missing snapshot is reported as "archived identities could not be
    /// checked". The event is replaceable, so a fresh empty snapshot on every
    /// startup is harmless.
    pub(crate) async fn publish_archive_snapshot(&self) -> bool {
        let Some(relay_pubkey) = self.relay_pubkey() else {
            return false;
        };
        let now = self.stamp_floor(unix_now());
        let archived = self.archive.read().await.clone();
        let mut event = crate::nips::nip_ia::snapshot(&relay_pubkey, now, &archived);
        self.store_relay_event(&mut event).await.is_ok()
    }

    /// Applies a NIP-IA archive/unarchive request. The request event is
    /// stored by the caller after this succeeds. Supported policy paths are
    /// self and relay-admin; the NIP-OA owner-of-agent path is not enabled.
    pub(crate) async fn apply_identity_archive(
        &self,
        event: &crate::event::Event,
    ) -> Result<(), String> {
        if !matches!(event.kind, 9035 | 9036) {
            return Err("invalid: not a NIP-IA request".into());
        }
        if event.created_at.abs_diff(unix_now()) > 120 {
            return Err("restricted: archive request is outside the freshness window".into());
        }
        if event
            .tags
            .iter()
            .filter(|tag| tag.len() == 1 && tag[0] == "-")
            .count()
            != 1
        {
            return Err("invalid: archive request requires exactly one NIP-70 - tag".into());
        }
        let mut targets = event
            .tags
            .iter()
            .filter(|tag| tag.len() >= 2 && tag[0] == "p")
            .map(|tag| tag[1].to_ascii_lowercase());
        let Some(target) = targets.next() else {
            return Err("invalid: archive request requires one p tag".into());
        };
        if targets.next().is_some()
            || target.len() != 64
            || !target.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("invalid: archive request target must be one hex pubkey".into());
        }
        let replaced_by = event
            .tags
            .iter()
            .find(|tag| tag.len() >= 2 && tag[0] == "replaced-by")
            .map(|tag| tag[1].to_ascii_lowercase());
        if let Some(replaced_by) = &replaced_by
            && (replaced_by.len() != 64
                || !replaced_by.bytes().all(|byte| byte.is_ascii_hexdigit())
                || replaced_by == &target)
        {
            return Err("invalid: replaced-by must be a different hex pubkey".into());
        }
        let reason = event
            .tags
            .iter()
            .find(|tag| tag.len() >= 2 && tag[0] == "reason")
            .map(|tag| tag[1].as_str());
        let self_request = event.pubkey.eq_ignore_ascii_case(&target);
        let admin = self.is_relay_owner_or_admin(&event.pubkey).await;
        let owner = if !self_request && !admin {
            crate::nips::nip_ia::verify_owner_agent_request(event, &target)
        } else {
            None
        };
        if !self_request && !admin && owner.is_none() {
            return Err(
                "restricted: only the target, a relay admin or a proven agent owner may archive \
                 this identity"
                    .into(),
            );
        }
        if event.kind == 9036
            && self
                .access
                .read()
                .await
                .blocked_pubkeys
                .iter()
                .any(|(blocked, _)| blocked.eq_ignore_ascii_case(&target))
        {
            return Err("restricted: an access-control ban cannot be self-unarchived".into());
        }
        let archived = event.kind == 9035;
        let consent = if self_request {
            "self"
        } else if admin {
            "admin"
        } else {
            "owner"
        };
        let consent_pubkey = if self_request {
            Some(target.as_str())
        } else if admin {
            Some(event.pubkey.as_str())
        } else {
            owner.as_deref()
        };
        let changed = {
            let mut archive = self.archive.write().await;
            if archived {
                archive.insert(target.clone())
            } else {
                archive.remove(&target)
            }
        };
        if !changed {
            return Ok(());
        }
        let data = {
            let archive = self.archive.read().await;
            serde_json::to_vec(&*archive).map_err(|error| format!("error: {error}"))?
        };
        if !self.db.save_identity_archive(data).await {
            // Roll back so an ACKed request cannot disappear on restart.
            let mut archive = self.archive.write().await;
            if archived {
                archive.remove(&target);
            } else {
                archive.insert(target.clone());
            }
            return Err("error: could not persist the archive state".into());
        }
        let now = self.stamp_floor(unix_now());
        let Some(relay_pubkey) = self.relay_pubkey() else {
            return Err("error: relay has no signing key".into());
        };
        let mut delta = crate::nips::nip_ia::delta(
            &relay_pubkey,
            now,
            &target,
            archived,
            consent,
            consent_pubkey,
            &event.id,
            reason,
            replaced_by.as_deref(),
            &event.content,
        );
        if self.store_relay_event(&mut delta).await.is_err()
            || !self.publish_archive_snapshot().await
        {
            // Keep the durable set and the published snapshot in step: the
            // request is not ACKed, so a retry must be able to make progress
            // instead of finding an already-applied but unpublished state.
            let mut archive = self.archive.write().await;
            if archived {
                archive.remove(&target);
            } else {
                archive.insert(target.clone());
            }
            if let Ok(data) = serde_json::to_vec(&*archive) {
                let _ = self.db.save_identity_archive(data).await;
            }
            return Err("error: could not publish the archive state".into());
        }
        Ok(())
    }

    /// Publishes the current membership list and an add/remove user event.
    pub(crate) async fn publish_membership(&self, change: Option<(bool, String)>) -> bool {
        if !self.config.read().await.nip_enabled(43) {
            return false;
        }
        let Some(relay_pubkey) = self.relay_pubkey() else {
            return false;
        };
        // Stamped with the monotonic clock so concurrent changes cannot
        // collide on a timestamp (see `StampClock`).
        let now = self.stamp_floor(unix_now());
        let (add, pubkey) = match change {
            Some((add, pubkey)) => (add, Some(pubkey)),
            None => (false, None),
        };
        // The allowlist is part of the relay's closed-community roster; read
        // it (and the relay's own owner identities) before the role lock so
        // the guards are never nested.
        let extra_members = self.allowlisted_members().await;
        let owners = self.relay_owner_members().await;
        // Synthetic roster entries bypass `RoleStore::rebuild`'s vanish
        // filter because they have no event behind them. Filter them here;
        // an unavailable vanish lookup fails closed instead of republishing
        // an erased identity.
        let mut filtered_extra = Vec::with_capacity(extra_members.len());
        for pubkey in extra_members {
            match self.db.is_vanished(&pubkey).await {
                Some(false) => filtered_extra.push(pubkey),
                Some(true) => {}
                None => return false,
            }
        }
        let mut filtered_owners = Vec::with_capacity(owners.len());
        for pubkey in owners {
            match self.db.is_vanished(&pubkey).await {
                Some(false) => filtered_owners.push(pubkey),
                Some(true) => {}
                None => return false,
            }
        }
        let events = {
            let roles = self.roles.read().await;
            // The caller re-read the rebuild flags before calling, but a
            // removal can mark the store and revoke it between that read and
            // this one. Publishing the revoked empty store would replace the
            // last full 13534. Re-check under the same read guard; a retry
            // is safe and the RPC reports failure.
            if self.roles_rebuild.dirty.load(Ordering::SeqCst)
                || self.roles_rebuild.running.load(Ordering::SeqCst)
                || self.roles_rebuild.removal_committed.load(Ordering::SeqCst)
                || self.roles_rebuild.derived.in_flight()
            {
                return false;
            }
            let mut events =
                vec![roles.membership_event(&relay_pubkey, now, &filtered_extra, &filtered_owners)];
            if let Some(pubkey) = pubkey {
                events.push(if add {
                    roles.add_user_event(&pubkey, &relay_pubkey, now)
                } else {
                    roles.remove_user_event(&pubkey, &relay_pubkey, now)
                });
            }
            events
        };
        let ids: Vec<[u8; 32]> = events.iter().filter_map(Event::id_bytes).collect();
        let mut all_stored = true;
        for event in events {
            all_stored &= self.publish_relay_event(event).await;
        }
        if all_stored
            && (self.roles_rebuild.removal_committed.load(Ordering::SeqCst)
                || self.roles_rebuild.derived.in_flight())
        {
            // A removal committed between the pre-check and the write. The
            // new full list may predate the removal and would be the newest
            // event the rebuild reads, resurrecting the removed grant.
            let _ = self.db.remove_events_by_id(&ids).await;
            return false;
        }
        all_stored
    }

    /// NIP-43 role management, used by the NIP-86 RPC methods.
    pub async fn create_role(
        &self,
        id: &str,
        label: &str,
        description: &str,
        color: &str,
        order: Option<i64>,
    ) -> bool {
        if !self.config.read().await.nip_enabled(43) || self.key.is_none() {
            return false;
        }
        let relay_pubkey = self.relay_pubkey().unwrap_or_default();
        // Stamped with the monotonic clock so concurrent role changes
        // cannot collide on a timestamp (see `StampClock`).
        let mut buffer = self.roles_rebuild.buffer.lock().await;
        let event = self
            .mutate_roles(
                &mut buffer,
                super::BufferedRoleMutation::Create {
                    id: id.to_string(),
                    label: label.to_string(),
                    description: description.to_string(),
                    color: color.to_string(),
                    order,
                },
                |roles| {
                    roles.create(id, label, description, color, order);
                    (
                        roles.role_event(id, &relay_pubkey, self.stamp_floor(unix_now())),
                        true,
                    )
                },
            )
            .await;
        // Debounced persistence (also on publish failure: memory changed,
        // so the snapshot must follow or a restart would lose it). A
        // skipped save is detected at startup through the state sequence.
        self.schedule_roles_persist();
        let stored = self.publish_relay_event(event).await;
        drop(buffer);
        stored
    }

    /// NIP-86 `editrole`: updates an *existing* role. A typo'd or missing id
    /// must not silently create a brand-new role, so the role must already
    /// exist (unlike `create_role`).
    pub async fn edit_role(
        &self,
        id: &str,
        label: &str,
        description: &str,
        color: &str,
        order: Option<i64>,
    ) -> bool {
        if !self.config.read().await.nip_enabled(43) || self.key.is_none() {
            return false;
        }
        let relay_pubkey = self.relay_pubkey().unwrap_or_default();
        let mut buffer = self.roles_rebuild.buffer.lock().await;
        // A pending rebuild revoked the live store. The surviving stored
        // history is authoritative, not the old live ids: an edit accepted
        // for a role whose definition event was just removed would publish a
        // new definition and resurrect it (N43-L04).
        let pending = self.roles_rebuild.dirty.load(Ordering::SeqCst)
            || self.roles_rebuild.marking.load(Ordering::SeqCst)
            || self.roles_rebuild.running.load(Ordering::SeqCst);
        if pending && !self.role_definition_exists(id).await {
            drop(buffer);
            return false;
        }
        // The existence check and the update share one write guard: with a
        // separate read check a concurrent `delete_role` could land between
        // them and the edit would recreate the deleted role.
        let event = self
            .mutate_roles(
                &mut buffer,
                super::BufferedRoleMutation::Edit {
                    id: id.to_string(),
                    label: label.to_string(),
                    description: description.to_string(),
                    color: color.to_string(),
                    order,
                },
                |roles| {
                    // `pending` cannot change while the buffer lock is held:
                    // `mark_roles_stale` sets it under the same lock.
                    let known = roles.roles.contains_key(id) || pending;
                    if !known {
                        return (None, false);
                    }
                    let event = if roles.roles.contains_key(id) {
                        roles.create(id, label, description, color, order);
                        roles.role_event(id, &relay_pubkey, self.stamp_floor(unix_now()))
                    } else {
                        // The rebuild revoked the live store: build the
                        // definition from a scratch store and leave the
                        // fail-closed store empty. `Edit` replay applies it
                        // only if the role survives the rebuild.
                        let mut scratch = RoleStore::default();
                        scratch.create(id, label, description, color, order);
                        scratch.role_event(id, &relay_pubkey, self.stamp_floor(unix_now()))
                    };
                    (Some(event), true)
                },
            )
            .await;
        let Some(event) = event else {
            drop(buffer);
            return false;
        };
        // Deferred persistence and publish (same contract as
        // `create_role`): the in-memory change is snapshotted even when the
        // publish fails, so a restart cannot lose it.
        self.schedule_roles_persist();
        let stored = self.publish_relay_event(event).await;
        drop(buffer);
        stored
    }

    pub async fn delete_role(&self, id: &str) -> RoleChange {
        if !self.config.read().await.nip_enabled(43) || self.key.is_none() {
            return RoleChange::Failed;
        }
        // A rebuild marked before (or during) this call revokes the live
        // store: the deletion cannot be confirmed from the empty store, and
        // reporting `Noop` would lose it — the rebuild resurrects the role
        // from its surviving events (B-5). Force-buffer the deletion for
        // replay, and skip the full membership republish below (it cannot be
        // built from the revoked store). The buffer lock is held through the
        // tombstone publish so `mark_roles_stale` cannot revoke in between.
        let mut buffer = self.roles_rebuild.buffer.lock().await;
        let outcome = self
            .mutate_roles(
                &mut buffer,
                super::BufferedRoleMutation::Delete { id: id.to_string() },
                |roles| {
                    let removed = roles.delete(id);
                    // Read inside the mutation (under the write lock): the
                    // mark sets `dirty` under the same buffer lock, so while
                    // this call holds it a rebuild cannot start or revoke
                    // without being observed here.
                    let pending = self.roles_rebuild.dirty.load(Ordering::SeqCst)
                        || self.roles_rebuild.running.load(Ordering::SeqCst);
                    // Deleting a missing role is a no-op success (like the
                    // other removal methods), not an error; with a rebuild
                    // pending the deletion is buffered instead — the role may
                    // exist in the events the rebuild will replay.
                    if removed || pending {
                        (RoleChange::Applied, true)
                    } else {
                        (RoleChange::Noop, false)
                    }
                },
            )
            .await;
        // Stable while the buffer lock is held (the mark sets it under the
        // same lock), but re-read for the publish decision below.
        let rebuild_pending = self.roles_rebuild.dirty.load(Ordering::SeqCst)
            || self.roles_rebuild.running.load(Ordering::SeqCst);
        if outcome != RoleChange::Applied {
            drop(buffer);
            return outcome;
        }
        // Deferred persistence before publishing (see `create_role`):
        // the tombstone path below must not lose the in-memory deletion
        // on restart even if publishing fails.
        self.schedule_roles_persist();
        // Publish a tombstone `kind:33534` so the deletion survives the
        // restart rebuild (the rebuild skips `["deleted"]` tombstones);
        // then republish the membership list without the deleted role.
        // A failed tombstone save reports `Failed`: without the tombstone
        // the rebuild after a restart resurrects the role. A plain retry
        // does not publish it (the in-memory role is already gone, so the
        // deletion reads back as `Noop`) — re-create the role and delete
        // it again to write the tombstone.
        let relay_pubkey = self.relay_pubkey().unwrap_or_default();
        let event = {
            let roles = self.roles.read().await;
            roles.role_deletion_event(id, &relay_pubkey, self.stamp_floor(unix_now()))
        };
        let stored = self.publish_relay_event(event).await;
        if stored {
            if rebuild_pending {
                // The live store is revoked: publishing its (empty) member
                // list would store a wrong list that the rebuild would then
                // replay as the newest one. The tombstone alone announces the
                // deletion; the buffered replay drops the assignments to the
                // deleted role and the next membership change republishes
                // the full list.
            } else if !self.publish_membership(None).await {
                // The membership republish must not be silently dropped:
                // a failure would leave the old membership event stored,
                // and the restart rebuild would resurrect assignments to
                // the deleted role. The tombstone itself still guarantees
                // the role stays deleted; the operator is told the
                // membership refresh failed so it can be retried.
                log::warn!(
                    "delete_role {id}: the membership list could not be republished; assignments to the deleted role may resurface after a restart"
                );
            }
        }
        drop(buffer);
        if stored {
            RoleChange::Applied
        } else {
            RoleChange::Failed
        }
    }

    /// Applies a Buzz/NIP-43 relay member admin command (`9030` add,
    /// `9031` remove, `9032` change role). The command event itself is
    /// stored by the caller; this method only mutates the authoritative
    /// role store and republishes the roster.
    pub(crate) async fn apply_relay_member_command(
        &self,
        event: &crate::event::Event,
    ) -> Result<(), String> {
        if !self.config.read().await.nip_enabled(43) {
            return Err("restricted: NIP-43 is disabled".into());
        }
        if !self.is_relay_owner_or_admin(&event.pubkey).await {
            return Err("restricted: only the relay owner or an admin may manage members".into());
        }
        let kind = event.kind;
        if !matches!(kind, 9030..=9032) {
            return Err("invalid: not a relay member command".into());
        }
        let target = event
            .tags
            .iter()
            .filter(|tag| tag.len() >= 2 && tag[0] == "p")
            .map(|tag| tag[1].to_ascii_lowercase())
            .find(|target| target.len() == 64 && target.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or_else(|| "invalid: member command needs one hex p tag".to_string())?;
        let role = event
            .tags
            .iter()
            .filter(|tag| tag.len() >= 2 && tag[0] == "role")
            .map(|tag| tag[1].as_str())
            .next();
        if let Some(role) = role
            && !matches!(role, "member" | "admin")
        {
            return Err("invalid: role must be member or admin".into());
        }
        if kind == 9032 && role.is_none() {
            return Err("invalid: 9032 requires a role tag".into());
        }
        if kind == 9031
            && self
                .relay_owner_members()
                .await
                .iter()
                .any(|owner| owner.eq_ignore_ascii_case(&target))
        {
            return Err("restricted: cannot remove a configured relay owner".into());
        }
        let buffer = self.roles_rebuild.buffer.lock().await;
        if self.roles_rebuild.dirty.load(Ordering::SeqCst)
            || self.roles_rebuild.running.load(Ordering::SeqCst)
            || self.roles_rebuild.marking.load(Ordering::SeqCst)
        {
            return Err("error: role state is rebuilding; retry the command".into());
        }
        let mut definition_changed = false;
        let changed = {
            let mut roles = self.roles.write().await;
            match kind {
                9030 => {
                    let desired = role.unwrap_or("member");
                    if desired == "admin" && !roles.roles.contains_key("admin") {
                        roles.create("admin", "admin", "", "", None);
                        definition_changed = true;
                    }
                    let next = if desired == "admin" {
                        vec!["admin".to_string()]
                    } else {
                        Vec::new()
                    };
                    let changed = roles.assignments.get(&target) != Some(&next);
                    roles.assignments.insert(target.clone(), next);
                    changed
                }
                9032 => {
                    let desired = role.ok_or_else(|| "invalid: role is required".to_string())?;
                    if desired == "admin" && !roles.roles.contains_key("admin") {
                        roles.create("admin", "admin", "", "", None);
                        definition_changed = true;
                    }
                    let next = if desired == "admin" {
                        vec!["admin".to_string()]
                    } else {
                        Vec::new()
                    };
                    let changed = roles.assignments.get(&target) != Some(&next);
                    roles.assignments.insert(target.clone(), next);
                    changed
                }
                _ => {
                    if let Some(required) = role {
                        let current = roles.assignments.get(&target);
                        let matches = match required {
                            "member" => current.is_some_and(Vec::is_empty),
                            "admin" => {
                                current.is_some_and(|roles| roles.iter().any(|r| r == "admin"))
                            }
                            _ => false,
                        };
                        if !matches {
                            return Err(
                                "restricted: member does not have the requested role".into()
                            );
                        }
                    }
                    roles.remove_pubkey(&target)
                }
            }
        };
        let changed = changed || definition_changed;
        if !changed {
            return Ok(());
        }
        self.release_role_snapshot_preserve();
        self.schedule_roles_persist();
        if !self.publish_role_state().await {
            return Err("error: could not publish the NIP-43 roster".into());
        }
        if !self.persist_roles().await {
            return Err("error: could not persist the NIP-43 role state".into());
        }
        drop(buffer);
        Ok(())
    }

    pub async fn assign_role(&self, pubkey: &str, role: &str) -> RoleChange {
        if !self.config.read().await.nip_enabled(43) || self.key.is_none() {
            return RoleChange::Failed;
        }
        // A rebuild marked before (or during) this call revokes the live
        // store: publishing its membership list would store a partial 13534
        // (only the member this call just assigned) and the rebuild would
        // replay it as the newest. Capture the window like `unassign_role`.
        // The buffer lock is held through the publish for the same reason as
        // `create_role` (N43-M01).
        let mut buffer = self.roles_rebuild.buffer.lock().await;
        // The live store is revoked while a rebuild is pending, so its ids are
        // not evidence that the role survives. Verify against the stored
        // history instead of a stale hint: assigning to a role whose defining
        // event was removed would otherwise report Applied and silently
        // disappear on replay (N43-L04). `check_pending` is stable under the
        // buffer lock (`mark_roles_stale` flips both flags there); `marking`
        // only means the mark is waiting for this lock, so the live store is
        // still intact and a full membership publish is safe.
        let rebuild_pending = self.roles_rebuild.dirty.load(Ordering::SeqCst)
            || self.roles_rebuild.running.load(Ordering::SeqCst);
        let check_pending = rebuild_pending || self.roles_rebuild.marking.load(Ordering::SeqCst);
        if check_pending && !self.role_definition_exists(role).await {
            drop(buffer);
            return RoleChange::Unknown;
        }
        let (outcome, was_member) = self
            .mutate_roles(
                &mut buffer,
                super::BufferedRoleMutation::Assign {
                    pubkey: pubkey.to_string(),
                    role: role.to_string(),
                },
                |roles| {
                    let was_member = roles.assignments.contains_key(pubkey);
                    let known = roles.roles.contains_key(role) || check_pending;
                    if !known {
                        ((RoleChange::Unknown, was_member), false)
                    } else if roles
                        .assignments
                        .get(pubkey)
                        .is_some_and(|grants| grants.iter().any(|r| r == role))
                    {
                        ((RoleChange::Noop, was_member), false)
                    } else {
                        // On the revoked empty store `assign` is a no-op;
                        // `changed=true` captures it for replay.
                        roles.assign(pubkey, role);
                        ((RoleChange::Applied, was_member), true)
                    }
                },
            )
            .await;
        if outcome == RoleChange::Applied {
            // NIP-43's 8000 announces a *membership* change; granting a role
            // to an existing member only changes the 13534 list.
            let change = (!was_member).then(|| (true, pubkey.to_string()));
            if rebuild_pending {
                // Persist the grant even while the rebuild owns the store:
                // the debounced pass retries after the worker exits, so a
                // post-swap capture is not lost on a graceful restart.
                self.schedule_roles_persist();
                // Announce the membership transition with an add-user event
                // alone: the live store is revoked, so its full member list
                // must not be published. The buffered assignment replays
                // onto the rebuilt store; the next membership change
                // republishes the full list.
                if change.is_some() && !self.publish_add_user(pubkey).await {
                    drop(buffer);
                    return RoleChange::Failed;
                }
            } else {
                self.schedule_roles_persist();
                if !self.publish_membership(change).await {
                    drop(buffer);
                    return RoleChange::Failed;
                }
            }
        } else if outcome == RoleChange::Noop {
            // A previous attempt may have applied in memory but failed to
            // publish; a plain retry reads back as Noop. Republish the
            // current state so the retry can complete the original call.
            if rebuild_pending {
                if !self.publish_add_user(pubkey).await {
                    drop(buffer);
                    return RoleChange::Failed;
                }
            } else if !self.publish_membership(None).await {
                drop(buffer);
                return RoleChange::Failed;
            }
        }
        drop(buffer);
        outcome
    }

    pub async fn unassign_role(&self, pubkey: &str, role: &str) -> RoleChange {
        if !self.config.read().await.nip_enabled(43) || self.key.is_none() {
            return RoleChange::Failed;
        }
        // See `delete_role`: a revocation landing on the revoked empty store
        // cannot be confirmed, but must still be buffered or the rebuild
        // resurrects the assignment from the surviving membership events
        // (B-5), and the full member list must not be published from the
        // revoked store. The buffer lock is held through the publish
        // (N43-M01); `pending` is stable under it.
        let mut buffer = self.roles_rebuild.buffer.lock().await;
        let rebuild_pending = self.roles_rebuild.dirty.load(Ordering::SeqCst)
            || self.roles_rebuild.running.load(Ordering::SeqCst);
        let (outcome, is_member) = self
            .mutate_roles(
                &mut buffer,
                super::BufferedRoleMutation::Unassign {
                    pubkey: pubkey.to_string(),
                    role: role.to_string(),
                },
                |roles| {
                    let revoked = roles.unassign(pubkey, role);
                    let is_member = roles.assignments.contains_key(pubkey);
                    // Revoking an absent grant (or an unknown role) is a
                    // no-op success, per NIP-86's always-`true`; with a
                    // rebuild pending the revocation is buffered instead.
                    if revoked || rebuild_pending {
                        ((RoleChange::Applied, is_member), true)
                    } else {
                        ((RoleChange::Noop, is_member), false)
                    }
                },
            )
            .await;
        if outcome == RoleChange::Applied {
            if rebuild_pending {
                // The live store is revoked: the full member list cannot be
                // published from it (a wrong, empty list would be stored and
                // the rebuild would replay it as the newest). Announce the
                // revocation with a remove-user event alone; the buffered
                // replay keeps the grant out of the rebuilt list.
                if !self.publish_remove_user(pubkey).await {
                    drop(buffer);
                    return RoleChange::Failed;
                }
            } else {
                self.schedule_roles_persist();
                // NIP-43's 8001 announces a *membership* removal; losing one
                // of several roles only changes the 13534 list.
                let change = (!is_member).then(|| (false, pubkey.to_string()));
                if !self.publish_membership(change).await {
                    drop(buffer);
                    return RoleChange::Failed;
                }
            }
        } else if outcome == RoleChange::Noop {
            // See `assign_role`: a retry of a remove that already applied in
            // memory but failed to publish must republish the membership.
            if rebuild_pending {
                if !self.publish_remove_user(pubkey).await {
                    drop(buffer);
                    return RoleChange::Failed;
                }
            } else if !self.publish_membership(None).await {
                drop(buffer);
                return RoleChange::Failed;
            }
        }
        drop(buffer);
        outcome
    }

    /// NIP-86 `createclaim`: stores an invite code. Invite codes have no
    /// events behind them, so the roles snapshot is their only persistence.
    /// The mutation is written through instead of waiting for the debounced
    /// pass: a crash in that window loses the code, and a lost
    /// `deleteclaim` (below) is fail-open. Returns [`ClaimRejection::Unavailable`]
    /// when NIP-43 is disabled or the relay key is missing, and
    /// [`ClaimRejection::NotDurable`] when the snapshot could not be
    /// persisted (the change is live and a retry is scheduled; the caller
    /// must retry rather than report success).
    pub async fn create_claim(&self, claim: &str) -> Result<(), ClaimRejection> {
        if !self.config.read().await.nip_enabled(43) || self.key.is_none() {
            return Err(ClaimRejection::Unavailable);
        }
        // A duplicate code is a no-op success; the snapshot is still
        // written through below to confirm that it is durably present.
        let mut buffer = self.roles_rebuild.buffer.lock().await;
        let _ = self
            .mutate_roles(
                &mut buffer,
                super::BufferedRoleMutation::CreateClaim {
                    claim: claim.to_string(),
                },
                |roles| {
                    let added = roles.add_claim(claim);
                    (added, added)
                },
            )
            .await;
        drop(buffer);
        match self.persist_roles_outcome().await {
            super::PersistOutcome::Failed => {
                // Keep the debounced retry armed for a transient database
                // error (a rebuild-pending store is persisted by its worker).
                self.schedule_roles_persist();
                Err(ClaimRejection::NotDurable)
            }
            super::PersistOutcome::Deferred => {
                // The in-flight derived mutation will schedule the retry;
                // the claim is live and not a durability failure.
                self.schedule_roles_persist();
                Ok(())
            }
            super::PersistOutcome::Committed => Ok(()),
        }
    }

    /// NIP-86 `deleteclaim`: revokes an invite code. Revoking an absent
    /// code is a no-op success, but the snapshot is still written through
    /// so the reply states that the code is durably absent. Returns
    /// [`ClaimRejection::Unavailable`] when NIP-43 is disabled or the relay
    /// key is missing, and [`ClaimRejection::NotDurable`] when the snapshot
    /// could not be persisted.
    pub async fn delete_claim(&self, claim: &str) -> Result<(), ClaimRejection> {
        if !self.config.read().await.nip_enabled(43) || self.key.is_none() {
            return Err(ClaimRejection::Unavailable);
        }
        let mut buffer = self.roles_rebuild.buffer.lock().await;
        let _ = self
            .mutate_roles(
                &mut buffer,
                super::BufferedRoleMutation::DeleteClaim {
                    claim: claim.to_string(),
                },
                |roles| {
                    let removed = roles.remove_claim(claim);
                    // A deleteclaim during a rebuild must be buffered too, or
                    // a createclaim buffered earlier for the same code would
                    // re-add it when the replay runs (B-5). `dirty` is stable
                    // under the buffer lock.
                    let pending = self.roles_rebuild.dirty.load(Ordering::SeqCst)
                        || self.roles_rebuild.running.load(Ordering::SeqCst);
                    if removed || pending {
                        (true, true)
                    } else {
                        (false, false)
                    }
                },
            )
            .await;
        drop(buffer);
        match self.persist_roles_outcome().await {
            super::PersistOutcome::Failed => {
                self.schedule_roles_persist();
                Err(ClaimRejection::NotDurable)
            }
            super::PersistOutcome::Deferred => {
                self.schedule_roles_persist();
                Err(ClaimRejection::NotDurable)
            }
            super::PersistOutcome::Committed => Ok(()),
        }
    }

    /// Admits a `kind:28934` join by invite code: records the membership,
    /// schedules the snapshot persist, and republishes the member list
    /// with an add-user event (NIP-43 SHOULD + MAY). Returns
    /// [`Admission::Unavailable`] only when NIP-43 is disabled or the
    /// relay key is missing (the caller reports a retryable error instead
    /// of a false welcome), and [`Admission::Full`] when the member list
    /// is at [`crate::nips::nip43::MAX_RELAY_MEMBERS`] (the check is
    /// repeated here under the write lock: the precheck's read-side check
    /// can race two concurrent joins past the cap). Returns
    /// [`Admission::Vanished`] when a VANISH committed between the precheck
    /// and this write: the membership is rolled back, so the caller must
    /// not send a welcome.
    ///
    /// `nip43_enabled` is passed in instead of read from `self.config`
    /// here. The batched accept path held a `config` read guard across this
    /// call, and `tokio::sync::RwLock` is write-preferring: a nested
    /// `config.read()` queued behind a pending config writer (the SIGHUP
    /// reload task, the NIP-86 config methods) while that writer waited for
    /// the guard the same task already held — a permanent deadlock that
    /// wedged every later config reader, i.e. the whole relay (NIP-11, the
    /// WebSocket upgrade, NIP-86 and any further reload all hung; only
    /// `kill -9` recovered). Taking the flag from the caller's snapshot
    /// removes the re-entrancy entirely and keeps the decision consistent
    /// with the `precheck` that produced it.
    pub(crate) async fn admit_member(&self, pubkey: &str, nip43_enabled: bool) -> Admission {
        if !nip43_enabled || self.key.is_none() {
            return Admission::Unavailable;
        }
        // A rebuild revokes the live store. Accepting a join then would
        // either replay against the cap and be dropped after a welcome
        // (L-4) or disappear with a failed rebuild; a retryable refusal is
        // the honest answer. The flag is read under the buffer lock so a
        // concurrent mark cannot revoke between the check and the apply.
        let mut buffer = self.roles_rebuild.buffer.lock().await;
        if self.roles_rebuild.dirty.load(Ordering::SeqCst)
            || self.roles_rebuild.running.load(Ordering::SeqCst)
        {
            drop(buffer);
            return Admission::Unavailable;
        }
        let (outcome, added) = self
            .mutate_roles(
                &mut buffer,
                super::BufferedRoleMutation::AdmitMember {
                    pubkey: pubkey.to_string(),
                },
                |roles| {
                    if roles.assignments.contains_key(pubkey) {
                        ((Admission::Recorded, false), false)
                    } else if roles.admit(pubkey) {
                        ((Admission::Recorded, true), true)
                    } else {
                        ((Admission::Full, false), false)
                    }
                },
            )
            .await;
        drop(buffer);
        // NIP-43 join-vanish TOCTOU: a VANISH commits the marker before it
        // drops the vanished key's roles. Re-check after the live mutation;
        // if the marker landed first, roll the admission back. If it lands
        // after this check, the vanish's own role removal wins.
        match self.db.is_vanished(pubkey).await {
            Some(true) => {
                let _ = self.rollback_admission(pubkey).await;
                // Announce the removal even when the vanish handler already
                // dropped the store entry: the stored 13534 may still list
                // the key (L-5). Publishing the full list is safe after the
                // live store no longer contains it; while a rebuild owns
                // the store only the remove-user event is published.
                let pending = self.roles_rebuild.dirty.load(Ordering::SeqCst)
                    || self.roles_rebuild.running.load(Ordering::SeqCst);
                if !self.publish_remove_user(pubkey).await {
                    log::warn!(
                        "admit_member: cannot publish the remove-user for vanished {pubkey}"
                    );
                } else if !pending && !self.publish_membership(None).await {
                    log::warn!(
                        "admit_member: cannot republish kind 13534 after removing vanished {pubkey}"
                    );
                }
                return Admission::Vanished;
            }
            None => {
                // Fail closed for a fresh admission; a pre-existing member
                // is left alone on a transient read failure.
                if added {
                    self.rollback_admission(pubkey).await;
                }
                return Admission::Unavailable;
            }
            Some(false) => {}
        }
        // The DB round-trip above is long enough for a rebuild to start after
        // the pre-check. Re-check and publish under the buffer lock: a mark
        // that runs in between would revoke the member and the admission
        // would be lost after a welcome. If the rebuild indicator flips while
        // the publish runs, roll the admission back and report a retryable
        // refusal instead of a false success.
        if added {
            let buffer = self.roles_rebuild.buffer.lock().await;
            if self.roles_rebuild.dirty.load(Ordering::SeqCst)
                || self.roles_rebuild.running.load(Ordering::SeqCst)
            {
                drop(buffer);
                self.rollback_admission(pubkey).await;
                return Admission::Unavailable;
            }
            self.schedule_roles_persist();
            let published = self
                .publish_membership(Some((true, pubkey.to_string())))
                .await;
            let pending = self.roles_rebuild.dirty.load(Ordering::SeqCst)
                || self.roles_rebuild.running.load(Ordering::SeqCst);
            drop(buffer);
            if pending {
                // A rebuild started while the list was being published: the
                // revoked store replaces the live membership, and without a
                // capture the admitted key would disappear after the scan.
                // Capture the removal and refuse the welcome so the client
                // can retry against the rebuilt state.
                self.rollback_admission(pubkey).await;
                return Admission::Unavailable;
            }
            if !published {
                // A clean transient publish failure: the membership is
                // recorded and the next change republishes the full list
                // (same contract as the leave path).
                log::warn!(
                    "admit_member: the membership list could not be republished; {pubkey} may be missing from kind 13534 until the next change"
                );
            }
        }
        outcome
    }

    /// Rolls back a membership admitted by [`Self::admit_member`] when the
    /// post-admission vanish recheck finds the key vanished. Buffered like
    /// [`Self::apply_leave_request`] while a rebuild is pending, so the
    /// removal replays onto the rebuilt store instead of being resurrected.
    async fn rollback_admission(&self, pubkey: &str) -> bool {
        let mut buffer = self.roles_rebuild.buffer.lock().await;
        let rebuild_pending = self.roles_rebuild.dirty.load(Ordering::SeqCst)
            || self.roles_rebuild.running.load(Ordering::SeqCst);
        let removed = self
            .mutate_roles(
                &mut buffer,
                super::BufferedRoleMutation::RemovePubkey {
                    pubkey: pubkey.to_string(),
                },
                |roles| {
                    let removed = roles.remove_pubkey(pubkey);
                    (removed, removed || rebuild_pending)
                },
            )
            .await;
        // The rollback must survive a rebuild that raced it even though the
        // admission itself left no replayable record (see the vanish path).
        super::buffer_pubkey_removal(&mut buffer, &self.roles_rebuild, pubkey);
        drop(buffer);
        if removed && !rebuild_pending {
            self.schedule_roles_persist();
        }
        removed
    }

    /// NIP-43 leave request: removes the user from the member list and
    /// republishes it with a remove-user event.
    pub(crate) async fn apply_leave_request(&self, event: &Event) {
        // A leave arriving while a role rebuild is in flight must still
        // take effect: the live store is the revoked empty store, so the
        // removal reports "not a member" and would never be captured for
        // replay — and the rebuild would then resurrect the member from
        // the surviving membership list. The client already got `OK`
        // (LEAVE is ephemeral), so unlike the RPC paths there is no
        // failure to report and retry: force-buffer the removal while a
        // rebuild is pending (`dirty` covers mark-to-scan-start, `running`
        // covers scan-start-to-worker-exit, with no gap: `dirty` is stored
        // under the buffer lock before the store is revoked). The replay
        // applies it to the fresh store (a no-op when the member is absent).
        // The lock is held through the publish so the mark cannot revoke
        // between the apply and the announcement (N43-M01).
        let mut buffer = self.roles_rebuild.buffer.lock().await;
        let rebuild_pending = self.roles_rebuild.dirty.load(Ordering::SeqCst)
            || self.roles_rebuild.running.load(Ordering::SeqCst);
        let removed = self
            .mutate_roles(
                &mut buffer,
                super::BufferedRoleMutation::RemovePubkey {
                    pubkey: event.pubkey.clone(),
                },
                |roles| {
                    let removed = roles.remove_pubkey(&event.pubkey);
                    (removed, removed || rebuild_pending)
                },
            )
            .await;
        if removed {
            self.schedule_roles_persist();
            // A failed republish would let the rebuild resurrect the
            // member after a restart: surface it in the log.
            if !self
                .publish_membership(Some((false, event.pubkey.clone())))
                .await
            {
                log::warn!(
                    "apply_leave_request: the membership list could not be republished; {} may resurface after a restart",
                    event.pubkey
                );
            }
        } else if rebuild_pending {
            // Buffered for replay (or a no-op when the member is absent):
            // announce the departure with a remove-user event alone.
            // Publishing the revoked store's member list here would
            // broadcast (and store) a wrong list, while the remove-user
            // event tells clients exactly what happened. The next
            // membership change republishes the full list; the replayed
            // removal keeps the member out of it.
            if !self.publish_remove_user(&event.pubkey).await {
                log::warn!(
                    "apply_leave_request: the remove-user event could not be published; {} may resurface if the rebuild scan fails",
                    event.pubkey
                );
            }
        }
        // A leave has no stored event that carries it across a rebuild. If a
        // rebuild started while the leave applied or published, capture the
        // removal for the replay (N43-L01); outside that window the live
        // store and its membership list are authoritative.
        super::buffer_pubkey_removal(&mut buffer, &self.roles_rebuild, &event.pubkey);
        drop(buffer);
    }

    /// Publishes only the add-user event for an admission applied while the
    /// live store is revoked (see [`Self::admit_member`]): the full member
    /// list cannot be published from the empty store.
    async fn publish_add_user(&self, pubkey: &str) -> bool {
        let Some(relay_pubkey) = self.relay_pubkey() else {
            return false;
        };
        let now = self.stamp_floor(unix_now());
        let event = {
            let roles = self.roles.read().await;
            roles.add_user_event(pubkey, &relay_pubkey, now)
        };
        self.publish_relay_event(event).await
    }

    /// Publishes only the remove-user event for a departure applied while
    /// the live store is revoked (see [`Self::apply_leave_request`]): the
    /// full member list cannot be published from the empty store.
    pub(crate) async fn publish_remove_user(&self, pubkey: &str) -> bool {
        let Some(relay_pubkey) = self.relay_pubkey() else {
            return false;
        };
        let now = self.stamp_floor(unix_now());
        let event = {
            let roles = self.roles.read().await;
            roles.remove_user_event(pubkey, &relay_pubkey, now)
        };
        self.publish_relay_event(event).await
    }
}
