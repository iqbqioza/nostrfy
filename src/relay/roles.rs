//! NIP-43 role administration: role definitions and member assignments
//! managed through the NIP-86 RPC, plus the published membership list
//! and add/remove-user events.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::db::PutOutcome;
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
    /// [`super::RolesRebuildBuffer`]). The capture and the live apply share
    /// the buffer lock, so a mutation is either replayed onto the freshly
    /// rebuilt store or applied after the swap — never lost in between.
    /// `mutate` returns `(result, changed)`; a refused mutation (e.g. an
    /// unknown role) is not captured, so the replay cannot apply what the
    /// live store rejected — except callers that force `changed` for
    /// removals the revoked empty store cannot confirm (see
    /// [`Self::apply_leave_request`]).
    pub(super) async fn mutate_roles<R>(
        &self,
        mutation: super::BufferedRoleMutation,
        mutate: impl FnOnce(&mut RoleStore) -> (R, bool),
    ) -> R {
        let mut buffer = self.roles_rebuild.buffer.lock().await;
        let (result, changed) = {
            let mut roles = self.roles.write().await;
            mutate(&mut roles)
        };
        // Capture while a rebuild is pending, not just while its scan runs:
        // the revoked window starts at marking (`dirty`, stored before the
        // store is revoked) and ends at worker exit (`running`), but the
        // scan flag only covers the walk itself. A mutation accepted in the
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
        drop(buffer);
        result
    }

    /// Signs, stores and broadcasts a relay-generated event. The event must
    /// already carry a strictly monotonic [`StampClock`] stamp (all builders
    /// stamp through `stamp_floor`); a stored version can never outrank the
    /// newest state because the stamps reflect the order in which the state
    /// was applied, not the order in which the events are stored.
    pub(crate) async fn store_relay_event(&self, event: &mut Event) -> Result<bool, ()> {
        let Some(keypair) = &self.key else {
            return Err(());
        };
        if nip01::sign(event, keypair, self.secp.as_ref()).is_err() {
            return Err(());
        }
        let now = unix_now();
        // One allocation shared by the database write and the broadcast:
        // relay-generated events must not deep-copy their content twice.
        let shared = Arc::new(event.clone());
        let outcome = self.db.put(Arc::clone(&shared), now).await;
        if matches!(outcome, PutOutcome::Stored | PutOutcome::Replaced) {
            Ok(self.broadcast(shared).await.is_ok())
        } else {
            Err(())
        }
    }

    /// Signs, stores and broadcasts a relay-generated event. Returns
    /// whether the event actually landed in the database: the RPC-facing
    /// role methods must not report success when the persistence failed
    /// (a success would leave the operator with an in-memory-only change
    /// that silently disappears on the next restart).
    async fn publish_relay_event(&self, mut event: Event) -> bool {
        self.store_relay_event(&mut event).await.is_ok()
    }

    /// Publishes the current membership list and an add/remove user event.
    pub(crate) async fn publish_membership(&self, change: Option<(bool, String)>) -> bool {
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
        let events = {
            let roles = self.roles.read().await;
            // The caller re-read the rebuild flags before calling, but a
            // removal can mark the store and revoke it between that read and
            // this one. Publishing the revoked empty store would replace the
            // last full 13534. Re-check under the same read guard; a retry
            // is safe and the RPC reports failure.
            if self.roles_rebuild.dirty.load(Ordering::SeqCst)
                || self.roles_rebuild.running.load(Ordering::SeqCst)
            {
                return false;
            }
            let mut events = vec![roles.membership_event(&relay_pubkey, now)];
            if let Some(pubkey) = pubkey {
                events.push(if add {
                    roles.add_user_event(&pubkey, &relay_pubkey, now)
                } else {
                    roles.remove_user_event(&pubkey, &relay_pubkey, now)
                });
            }
            events
        };
        let mut all_stored = true;
        for event in events {
            all_stored &= self.publish_relay_event(event).await;
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
        let event = self
            .mutate_roles(
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
        self.publish_relay_event(event).await
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
        // The existence check and the update share one write guard: with a
        // separate read check a concurrent `delete_role` could land between
        // them and the edit would recreate the deleted role.
        let event = self
            .mutate_roles(
                super::BufferedRoleMutation::Edit {
                    id: id.to_string(),
                    label: label.to_string(),
                    description: description.to_string(),
                    color: color.to_string(),
                    order,
                },
                |roles| {
                    let pending = self.roles_rebuild.dirty.load(Ordering::SeqCst)
                        || self.roles_rebuild.running.load(Ordering::SeqCst);
                    let known = roles.roles.contains_key(id)
                        || (pending
                            && self
                                .roles_rebuild
                                .revoked_roles
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner())
                                .contains(id));
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
            return false;
        };
        // Deferred persistence and publish (same contract as
        // `create_role`): the in-memory change is snapshotted even when the
        // publish fails, so a restart cannot lose it.
        self.schedule_roles_persist();
        self.publish_relay_event(event).await
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
        // built from the revoked store).
        let mut rebuild_pending = self.roles_rebuild.dirty.load(Ordering::SeqCst)
            || self.roles_rebuild.running.load(Ordering::SeqCst);
        let outcome = self
            .mutate_roles(
                super::BufferedRoleMutation::Delete { id: id.to_string() },
                |roles| {
                    let removed = roles.delete(id);
                    // Re-read inside the mutation (under the write lock), not
                    // just from the pre-lock snapshot above: a rebuild marked
                    // in between would otherwise be missed, and a deletion
                    // landing on the already-revoked empty store would report
                    // "no such role" and never be buffered. Marking stores
                    // `dirty` before revoking under the same write lock, so
                    // observing the revoked store here implies observing the
                    // mark.
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
        // Re-read: the rebuild may have started between the snapshot above
        // and the mutation, in which case the deletion was buffered and the
        // full membership list still cannot be built from the revoked store.
        rebuild_pending = rebuild_pending
            || self.roles_rebuild.dirty.load(Ordering::SeqCst)
            || self.roles_rebuild.running.load(Ordering::SeqCst);
        if outcome != RoleChange::Applied {
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
        if stored {
            RoleChange::Applied
        } else {
            RoleChange::Failed
        }
    }

    pub async fn assign_role(&self, pubkey: &str, role: &str) -> RoleChange {
        if !self.config.read().await.nip_enabled(43) || self.key.is_none() {
            return RoleChange::Failed;
        }
        // A rebuild marked before (or during) this call revokes the live
        // store: publishing its membership list would store a partial 13534
        // (only the member this call just assigned) and the rebuild would
        // replay it as the newest. Capture the window like `unassign_role`.
        let mut rebuild_pending = self.roles_rebuild.dirty.load(Ordering::SeqCst)
            || self.roles_rebuild.running.load(Ordering::SeqCst);
        let (outcome, was_member) = self
            .mutate_roles(
                super::BufferedRoleMutation::Assign {
                    pubkey: pubkey.to_string(),
                    role: role.to_string(),
                },
                |roles| {
                    let was_member = roles.assignments.contains_key(pubkey);
                    let pending = self.roles_rebuild.dirty.load(Ordering::SeqCst)
                        || self.roles_rebuild.running.load(Ordering::SeqCst);
                    let known = roles.roles.contains_key(role)
                        || (pending
                            && self
                                .roles_rebuild
                                .revoked_roles
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner())
                                .contains(role));
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
        // Re-read: a rebuild may have started between the pre-lock snapshot
        // and the mutation (see `delete_role`).
        rebuild_pending = rebuild_pending
            || self.roles_rebuild.dirty.load(Ordering::SeqCst)
            || self.roles_rebuild.running.load(Ordering::SeqCst);
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
                    return RoleChange::Failed;
                }
            } else {
                self.schedule_roles_persist();
                if !self.publish_membership(change).await {
                    return RoleChange::Failed;
                }
            }
        } else if outcome == RoleChange::Noop {
            // A previous attempt may have applied in memory but failed to
            // publish; a plain retry reads back as Noop. Republish the
            // current state so the retry can complete the original call.
            if rebuild_pending {
                if !self.publish_add_user(pubkey).await {
                    return RoleChange::Failed;
                }
            } else if !self.publish_membership(None).await {
                return RoleChange::Failed;
            }
        }
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
        // revoked store.
        let mut rebuild_pending = self.roles_rebuild.dirty.load(Ordering::SeqCst)
            || self.roles_rebuild.running.load(Ordering::SeqCst);
        let (outcome, is_member) = self
            .mutate_roles(
                super::BufferedRoleMutation::Unassign {
                    pubkey: pubkey.to_string(),
                    role: role.to_string(),
                },
                |roles| {
                    let revoked = roles.unassign(pubkey, role);
                    let is_member = roles.assignments.contains_key(pubkey);
                    // Re-read inside the mutation (under the write lock): see
                    // `delete_role` for why the pre-lock snapshot is not
                    // enough.
                    let pending = self.roles_rebuild.dirty.load(Ordering::SeqCst)
                        || self.roles_rebuild.running.load(Ordering::SeqCst);
                    // Revoking an absent grant (or an unknown role) is a
                    // no-op success, per NIP-86's always-`true`; with a
                    // rebuild pending the revocation is buffered instead.
                    if revoked || pending {
                        ((RoleChange::Applied, is_member), true)
                    } else {
                        ((RoleChange::Noop, is_member), false)
                    }
                },
            )
            .await;
        // Re-read: the rebuild may have started between the snapshot above
        // and the mutation (see `apply_leave_request`).
        rebuild_pending = rebuild_pending
            || self.roles_rebuild.dirty.load(Ordering::SeqCst)
            || self.roles_rebuild.running.load(Ordering::SeqCst);
        if outcome == RoleChange::Applied {
            if rebuild_pending {
                // The live store is revoked: the full member list cannot be
                // published from it (a wrong, empty list would be stored and
                // the rebuild would replay it as the newest). Announce the
                // revocation with a remove-user event alone; the buffered
                // replay keeps the grant out of the rebuilt list.
                if !self.publish_remove_user(pubkey).await {
                    return RoleChange::Failed;
                }
            } else {
                self.schedule_roles_persist();
                // NIP-43's 8001 announces a *membership* removal; losing one
                // of several roles only changes the 13534 list.
                let change = (!is_member).then(|| (false, pubkey.to_string()));
                if !self.publish_membership(change).await {
                    return RoleChange::Failed;
                }
            }
        } else if outcome == RoleChange::Noop {
            // See `assign_role`: a retry of a remove that already applied in
            // memory but failed to publish must republish the membership.
            if rebuild_pending {
                if !self.publish_remove_user(pubkey).await {
                    return RoleChange::Failed;
                }
            } else if !self.publish_membership(None).await {
                return RoleChange::Failed;
            }
        }
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
        let _ = self
            .mutate_roles(
                super::BufferedRoleMutation::CreateClaim {
                    claim: claim.to_string(),
                },
                |roles| {
                    let added = roles.add_claim(claim);
                    (added, added)
                },
            )
            .await;
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
        let _ = self
            .mutate_roles(
                super::BufferedRoleMutation::DeleteClaim {
                    claim: claim.to_string(),
                },
                |roles| {
                    let removed = roles.remove_claim(claim);
                    // Re-read inside the mutation (see `delete_role`): a
                    // deleteclaim during a rebuild must be buffered too, or a
                    // createclaim buffered earlier for the same code would
                    // re-add it when the replay runs (B-5).
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
        match self.persist_roles_outcome().await {
            super::PersistOutcome::Failed => {
                self.schedule_roles_persist();
                Err(ClaimRejection::NotDurable)
            }
            super::PersistOutcome::Deferred => {
                self.schedule_roles_persist();
                Ok(())
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
        // the honest answer.
        if self.roles_rebuild.dirty.load(Ordering::SeqCst)
            || self.roles_rebuild.running.load(Ordering::SeqCst)
        {
            return Admission::Unavailable;
        }
        let (outcome, added) = self
            .mutate_roles(
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
        // The DB round-trip above is long enough for a rebuild to start
        // after the pre-check. Re-check now: publishing the revoked
        // store's list would store a partial 13534 (M-2).
        if self.roles_rebuild.dirty.load(Ordering::SeqCst)
            || self.roles_rebuild.running.load(Ordering::SeqCst)
        {
            if added {
                self.rollback_admission(pubkey).await;
            }
            return Admission::Unavailable;
        }
        if added {
            self.schedule_roles_persist();
            // A failed republish is logged, not fatal: the membership is
            // recorded and the next change republishes the full list (same
            // contract as the leave path).
            if !self
                .publish_membership(Some((true, pubkey.to_string())))
                .await
            {
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
        let mut rebuild_pending = self.roles_rebuild.dirty.load(Ordering::SeqCst)
            || self.roles_rebuild.running.load(Ordering::SeqCst);
        let removed = self
            .mutate_roles(
                super::BufferedRoleMutation::RemovePubkey {
                    pubkey: pubkey.to_string(),
                },
                |roles| {
                    let removed = roles.remove_pubkey(pubkey);
                    let pending = self.roles_rebuild.dirty.load(Ordering::SeqCst)
                        || self.roles_rebuild.running.load(Ordering::SeqCst);
                    (removed, removed || pending)
                },
            )
            .await;
        rebuild_pending = rebuild_pending
            || self.roles_rebuild.dirty.load(Ordering::SeqCst)
            || self.roles_rebuild.running.load(Ordering::SeqCst);
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
        // before the store is revoked). The replay applies it to the fresh
        // store (a no-op when the member is absent).
        let rebuild_pending = self.roles_rebuild.dirty.load(Ordering::SeqCst)
            || self.roles_rebuild.running.load(Ordering::SeqCst);
        let removed = self
            .mutate_roles(
                super::BufferedRoleMutation::RemovePubkey {
                    pubkey: event.pubkey.clone(),
                },
                |roles| {
                    let removed = roles.remove_pubkey(&event.pubkey);
                    // Re-read inside the mutation (under the write lock),
                    // not just from the pre-lock snapshot above: a rebuild
                    // marked in between would otherwise be missed, and a
                    // removal landing on the already-revoked empty store
                    // would report "not a member" and never be buffered —
                    // losing the leave while the rebuild resurrects the
                    // member. Marking stores `dirty` before revoking under
                    // the same write lock, so observing the revoked store
                    // here implies observing the mark.
                    let pending = self.roles_rebuild.dirty.load(Ordering::SeqCst)
                        || self.roles_rebuild.running.load(Ordering::SeqCst);
                    (removed, removed || pending)
                },
            )
            .await;
        // Re-read: the rebuild may have started between the pre-lock
        // snapshot and the mutation, in which case the departure was
        // buffered for replay and is announced below like the
        // snapshot-pending case.
        let rebuild_pending = rebuild_pending
            || self.roles_rebuild.dirty.load(Ordering::SeqCst)
            || self.roles_rebuild.running.load(Ordering::SeqCst);
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
    async fn publish_remove_user(&self, pubkey: &str) -> bool {
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
