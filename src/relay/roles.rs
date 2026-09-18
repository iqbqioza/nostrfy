//! NIP-43 role administration: role definitions and member assignments
//! managed through the NIP-86 RPC, plus the published membership list
//! and add/remove-user events.

use std::sync::Arc;

use crate::db::PutOutcome;
use crate::event::Event;
use crate::nips::nip01;
use crate::nips::nip43::RoleStore;
use crate::util::unix_now;

impl super::Relay {
    /// Applies a role mutation to the live store, capturing it for replay
    /// when a rebuild scan is in flight (see
    /// [`super::RolesRebuildBuffer`]). The capture and the live apply share
    /// the buffer lock, so a mutation is either replayed onto the freshly
    /// rebuilt store or applied after the swap — never lost in between.
    /// `mutate` returns `(result, changed)`; a refused mutation (e.g. an
    /// unknown role) is not captured, so the replay cannot apply what the
    /// live store rejected.
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
        if changed && buffer.scanning {
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
        if nip01::sign(event, keypair, &self.secp).is_err() {
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
                super::BufferedRoleMutation::Create {
                    id: id.to_string(),
                    label: label.to_string(),
                    description: description.to_string(),
                    color: color.to_string(),
                    order,
                },
                |roles| {
                    if !roles.roles.contains_key(id) {
                        return (None, false);
                    }
                    roles.create(id, label, description, color, order);
                    (
                        Some(roles.role_event(id, &relay_pubkey, self.stamp_floor(unix_now()))),
                        true,
                    )
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

    pub async fn delete_role(&self, id: &str) -> bool {
        if !self.config.read().await.nip_enabled(43) || self.key.is_none() {
            return false;
        }
        let removed = self
            .mutate_roles(
                super::BufferedRoleMutation::Delete { id: id.to_string() },
                |roles| {
                    let removed = roles.delete(id);
                    (removed, removed)
                },
            )
            .await;
        if removed {
            // Deferred persistence before publishing (see `create_role`):
            // the tombstone path below must not lose the in-memory deletion
            // on restart even if publishing fails.
            self.schedule_roles_persist();
            // Publish a tombstone `kind:33534` so the deletion survives the
            // restart rebuild (the rebuild skips `["deleted"]` tombstones);
            // then republish the membership list without the deleted role.
            // A failed tombstone save reports false: without it the role
            // would be resurrected by the rebuild after a restart (the
            // operator can re-create and re-delete to retry).
            let relay_pubkey = self.relay_pubkey().unwrap_or_default();
            let event = {
                let roles = self.roles.read().await;
                roles.role_deletion_event(id, &relay_pubkey, self.stamp_floor(unix_now()))
            };
            let stored = self.publish_relay_event(event).await;
            if stored {
                // The membership republish must not be silently dropped:
                // a failure would leave the old membership event stored,
                // and the restart rebuild would resurrect assignments to
                // the deleted role. The tombstone itself still guarantees
                // the role stays deleted; the operator is told the
                // membership refresh failed so it can be retried.
                if !self.publish_membership(None).await {
                    log::warn!(
                        "delete_role {id}: the membership list could not be republished; assignments to the deleted role may resurface after a restart"
                    );
                }
            }
            stored
        } else {
            false
        }
    }

    pub async fn assign_role(&self, pubkey: &str, role: &str) -> bool {
        if !self.config.read().await.nip_enabled(43) || self.key.is_none() {
            return false;
        }
        let assigned = self
            .mutate_roles(
                super::BufferedRoleMutation::Assign {
                    pubkey: pubkey.to_string(),
                    role: role.to_string(),
                },
                |roles| {
                    let assigned = roles.assign(pubkey, role);
                    (assigned, assigned)
                },
            )
            .await;
        if assigned {
            self.schedule_roles_persist();
            self.publish_membership(Some((true, pubkey.to_string())))
                .await
        } else {
            false
        }
    }

    pub async fn unassign_role(&self, pubkey: &str, role: &str) -> bool {
        if !self.config.read().await.nip_enabled(43) || self.key.is_none() {
            return false;
        }
        let changed = self
            .mutate_roles(
                super::BufferedRoleMutation::Unassign {
                    pubkey: pubkey.to_string(),
                    role: role.to_string(),
                },
                |roles| {
                    let changed = roles.unassign(pubkey, role);
                    (changed, changed)
                },
            )
            .await;
        if changed {
            self.schedule_roles_persist();
            self.publish_membership(Some((false, pubkey.to_string())))
                .await
        } else {
            false
        }
    }

    /// NIP-43 leave request: removes the user from the member list and
    /// republishes it with a remove-user event.
    pub(crate) async fn apply_leave_request(&self, event: &Event) {
        let removed = self
            .mutate_roles(
                super::BufferedRoleMutation::RemovePubkey {
                    pubkey: event.pubkey.clone(),
                },
                |roles| {
                    let removed = roles.remove_pubkey(&event.pubkey);
                    (removed, removed)
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
        }
    }
}
