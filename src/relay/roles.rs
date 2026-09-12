//! NIP-43 role administration: role definitions and member assignments
//! managed through the NIP-86 RPC, plus the published membership list
//! and add/remove-user events.

use crate::db::PutOutcome;
use crate::event::Event;
use crate::nips::nip01;
use crate::util::unix_now;

impl super::Relay {
    /// Signs, stores and broadcasts a relay-generated event. The event must
    /// already carry a strictly monotonic [`StampClock`] stamp (all builders
    /// stamp through `stamp_floor`); a stored version can never outrank the
    /// newest state because the stamps reflect the order in which the state
    /// was applied, not the order in which the events are stored.
    pub(crate) async fn store_relay_event(&self, event: &mut Event) -> bool {
        let Some(keypair) = &self.key else {
            return false;
        };
        if nip01::sign(event, keypair, &self.secp).is_err() {
            return false;
        }
        let now = unix_now();
        let outcome = self.db.put(event.clone(), now).await;
        if matches!(outcome, PutOutcome::Stored | PutOutcome::Replaced) {
            self.broadcast(event.clone()).await.is_ok()
        } else {
            false
        }
    }

    /// Signs, stores and broadcasts a relay-generated event. Returns
    /// whether the event actually landed in the database: the RPC-facing
    /// role methods must not report success when the persistence failed
    /// (a success would leave the operator with an in-memory-only change
    /// that silently disappears on the next restart).
    async fn publish_relay_event(&self, mut event: Event) -> bool {
        self.store_relay_event(&mut event).await
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
        let event = {
            let mut roles = self.roles.write().await;
            roles.create(id, label, description, color, order);
            roles.role_event(id, &relay_pubkey, self.stamp_floor(unix_now()))
        };
        // Write-through persistence (also on publish failure: memory
        // changed, so the snapshot must follow or a restart would lose it).
        self.persist_roles().await;
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
        if !self.roles.read().await.roles.contains_key(id) {
            return false;
        }
        self.create_role(id, label, description, color, order).await
    }

    pub async fn delete_role(&self, id: &str) -> bool {
        if !self.config.read().await.nip_enabled(43) || self.key.is_none() {
            return false;
        }
        let removed = self.roles.write().await.delete(id);
        if removed {
            // Write-through persistence before publishing (see
            // `create_role`): the tombstone path below must not lose the
            // in-memory deletion on restart even if publishing fails.
            self.persist_roles().await;
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
        let assigned = self.roles.write().await.assign(pubkey, role);
        if assigned {
            self.persist_roles().await;
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
        let changed = self.roles.write().await.unassign(pubkey, role);
        if changed {
            self.persist_roles().await;
            self.publish_membership(Some((false, pubkey.to_string())))
                .await
        } else {
            false
        }
    }

    /// NIP-43 leave request: removes the user from the member list and
    /// republishes it with a remove-user event.
    pub(crate) async fn apply_leave_request(&self, event: &Event) {
        let removed = self.roles.write().await.remove_pubkey(&event.pubkey);
        if removed {
            self.persist_roles().await;
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
