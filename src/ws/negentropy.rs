//! NIP-77 negentropy message handling: `NEG-OPEN`/`NEG-MSG`/`NEG-CLOSE`
//! and the `NEG-ERR` replies. The reconciliation protocol itself lives in
//! [`crate::nips::nip77`].

use serde_json::{Value, json};

use crate::filter::Filter;
use crate::nips::nip77;
use crate::util::unix_now;

use super::value_string;

/// NIP-77 negentropy state for one open subscription.
pub(crate) struct NegState {
    pub(crate) items: Vec<nip77::Item>,
    /// Remaining NEG-MSG rounds for this subscription. The reconciliation
    /// protocol completes in a bounded number of rounds proportional to the
    /// number of divergent ranges; a peer that keeps sending NEG-MSG with
    /// bogus fingerprints would otherwise force an unbounded, CPU-bounded
    /// bisection over the held items on every message.
    pub(crate) rounds_left: u32,
}

/// Cap on the number of NEG-MSG rounds a single subscription may consume
/// before it is closed (generous for legitimate syncs).
pub(crate) const MAX_NEG_MSG_ROUNDS: u32 = 128;

/// The maximum number of NEG-OPENs one connection may issue: each open
/// resets the round budget, so without this cap a client could renew the
/// 128-round CPU budget forever (closing and re-opening must not bypass
/// the cap, hence the connection-wide counter).
pub(crate) const MAX_NEG_OPENS: u32 = 256;

impl super::Conn {
    pub(crate) fn send_neg_err(&mut self, sub_id: &str, reason: &str) {
        self.send_json(json!(["NEG-ERR", sub_id, reason]));
    }

    pub(crate) fn send_neg_msg(&mut self, sub_id: &str, message: &[u8]) {
        self.send_json(json!(["NEG-MSG", sub_id, hex::encode(message)]));
    }

    pub(crate) async fn handle_neg_open(&mut self, rest: &[Value]) {
        // NIP-77 errors are NEG-ERR when a subscription id can be
        // correlated, NOTICE only when no id exists to echo.
        let correl_id: Option<String> = rest
            .first()
            .and_then(value_string)
            .filter(|s| !s.is_empty());
        if !self.relay.config.read().await.nip_enabled(77) {
            if let Some(sub_id) = correl_id {
                self.send_neg_err(&sub_id, "error: negentropy is not enabled on this relay");
            } else {
                self.send_notice("error: negentropy is not enabled on this relay");
            }
            return;
        }
        if rest.len() < 3 {
            if let Some(sub_id) = correl_id {
                self.send_neg_err(
                    &sub_id,
                    "error: NEG-OPEN requires a subscription id, filter and message",
                );
            } else {
                self.send_notice("error: NEG-OPEN requires a subscription id, filter and message");
            }
            return;
        }
        let sub_id = match value_string(&rest[0]) {
            Some(id) if !id.is_empty() => id,
            _ => {
                self.send_notice("error: NEG-OPEN subscription id must be a non-empty string");
                return;
            }
        };
        let max_sub_id_len = self.relay.config.read().await.limits.max_sub_id_len;
        if sub_id.len() > max_sub_id_len {
            self.send_neg_err(&sub_id, "error: NEG-OPEN subscription id too long");
            return;
        }
        let mut raw = rest[1].clone();
        if crate::filter::rewrite_inbox_outbox(&mut raw).is_err() {
            self.send_neg_err(&sub_id, "error: invalid NEG-OPEN filter");
            return;
        }
        let filter: Filter = match serde_json::from_value::<Filter>(raw) {
            Ok(mut filter) => {
                // Negentropy needs every matching record, not a capped page.
                filter.limit = None;
                // NIP-50 disabled: strip the search like REQ/COUNT/API do,
                // otherwise a NEG-OPEN would return a subset of what a REQ
                // with the same filter returns, and the peer would treat
                // the missing events as absent on this relay (and may
                // delete them locally).
                if !self.relay.config.read().await.nip_enabled(50) {
                    filter.search = None;
                }
                filter
            }
            Err(_) => {
                self.send_neg_err(&sub_id, "error: invalid NEG-OPEN filter");
                return;
            }
        };
        if filter.too_many_members() {
            self.send_neg_err(&sub_id, "error: too many ids or authors in the filter");
            return;
        }
        if filter.invalid_tag_values() {
            self.send_neg_err(&sub_id, "error: tag constraint values must be strings");
            return;
        }
        let Some(initial) = rest[2].as_str() else {
            self.send_neg_err(&sub_id, "error: NEG-OPEN message must be hex");
            return;
        };
        let Ok(initial) = hex::decode(initial) else {
            self.send_neg_err(&sub_id, "error: NEG-OPEN message must be hex");
            return;
        };
        // NIP-42: an auth-requiring relay applies the same policy to
        // negentropy subscriptions as to REQ subscriptions.
        if self.relay.config.read().await.relay.require_auth && !self.is_authed() {
            self.send_neg_err(&sub_id, "auth-required: please authenticate before syncing");
            return;
        }
        // The access lists gate syncing like the REQ path: denied pubkeys
        // are never served; `restrict_relay` gates publishing only, so
        // reading stays open. Read fresh per message, so command-event
        // changes apply immediately without a reconnect.
        if !self.access_allows_read().await {
            self.send_neg_err(&sub_id, "restricted: you are not allowed to sync");
            return;
        }

        let max_items = self.relay.config.read().await.limits.max_neg_items;
        let max_subs = self.relay.config.read().await.limits.max_subscriptions;
        // NIP-77: a NEG-OPEN for an already open id replaces it, so it
        // must not count against the cap — only new subscriptions are
        // limited.
        if !self.neg.contains_key(&sub_id) && self.neg.len() >= max_subs {
            self.send_neg_err(&sub_id, "error: too many subscriptions");
            return;
        }
        let now = unix_now();
        // The negentropy query only needs (created_at, id) records, so it
        // never materializes every matching full event in memory.
        let Some((items, more)) = self
            .relay
            .db
            .neg_items_reported(filter, max_items, now)
            .await
        else {
            // A timed-out sync must never be answered with an empty item
            // set: the peer would conclude everything is gone locally and
            // delete its events. NEG-ERR closes the subscription per
            // NIP-77, which is the safe failure mode.
            self.send_neg_err(&sub_id, "error: database timeout, please retry");
            return;
        };
        if more || items.len() > max_items {
            // NIP-77: the maximum number of processable records may be
            // returned as the fourth element.
            self.send_json(json!([
                "NEG-ERR",
                sub_id,
                "blocked: this query is too big",
                max_items
            ]));
            return;
        }
        // NIP-70/NIP-59/NIP-29: withhold protected events from
        // unauthenticated peers, gift wraps from anyone but their
        // recipients, and private/hidden group content from non-members,
        // exactly like the REQ path.
        let items: Vec<nip77::Item> = {
            let groups = self.relay.groups.read().await;
            items
                .into_iter()
                .filter(|item| {
                    if item.protected && !self.is_authed() {
                        return false;
                    }
                    // NIP-78: application-specific events are only synced
                    // to the authenticated owner.
                    if self.nip78_restricted
                        && item.app_specific
                        && !self.authed_pubkeys.iter().any(|pk| pk == &item.pubkey)
                    {
                        return false;
                    }
                    // NIP-59/NIP-17: gift wraps are only served to their
                    // recipients when NIP-42 is enabled (the same gate as
                    // the REQ path's `gift_wrap_visible`): with NIP-42
                    // disabled the wraps are public, and withholding them
                    // from NEG would make a syncing peer delete its local
                    // copies.
                    if self.giftwrap_restricted
                        && item.wrap_recipients.is_some()
                        && !self.authed_pubkeys.iter().any(|pk| {
                            item.wrap_recipients
                                .as_ref()
                                .is_some_and(|recips| recips.iter().any(|r| r == pk))
                        })
                    {
                        return false;
                    }
                    if let Some(gid) = &item.gid {
                        if self.authed_pubkeys.is_empty() {
                            groups.visible_gid(gid, item.meta, None)
                        } else {
                            self.authed_pubkeys
                                .iter()
                                .any(|pk| groups.visible_gid(gid, item.meta, Some(pk)))
                        }
                    } else {
                        true
                    }
                })
                .map(|item| (item.created, item.id))
                .collect()
        };
        let items = nip77::sort_items(items);

        // The items stay on this connection for the whole sync; bound the
        // total so that many concurrent NEG-OPENs cannot pin excessive
        // memory on a single connection.
        let total_cap = max_items.saturating_mul(2);
        // A NEG-OPEN for an already open subscription id replaces the
        // existing one (NIP-77). Account for the replacement *before*
        // removing the old state, so a failing NEG-OPEN (too many items)
        // cannot silently close the peer's existing subscription.
        let old_len = self
            .neg
            .get(&sub_id)
            .map(|state| state.items.len())
            .unwrap_or(0);
        if self
            .neg_total
            .saturating_sub(old_len)
            .saturating_add(items.len())
            > total_cap
        {
            self.send_json(json!([
                "NEG-ERR",
                sub_id,
                "blocked: too many negentropy items",
                total_cap
            ]));
            return;
        }
        // The initial message is validated *before* the old state is
        // removed: a failing NEG-OPEN must not close the peer's existing
        // subscription (the capacity check above already guards the "too
        // many items" path the same way).
        let response = match nip77::respond(&items, &initial) {
            Ok(response) => response,
            Err(reason) => {
                self.send_neg_err(&sub_id, &format!("error: {reason}"));
                return;
            }
        };
        // Bound the initial response like the NEG-MSG replies: a mode-2
        // answer returns every id of the range, and without the cap a
        // large max_neg_items would let one NEG-OPEN bypass the REQ
        // response budget entirely. The wire size is the hex encoding
        // (2x) plus the JSON frame, so budget against that.
        let budget = self.req_response_bytes;
        if budget > 0 && response.len() as u64 * 2 > budget {
            self.send_neg_err(
                &sub_id,
                "blocked: negentropy response too large (increase limits.max_req_response_bytes)",
            );
            return;
        }
        // Every open renews the round budget; the connection-wide count
        // caps how often, so a client cannot renew the 128-round CPU
        // budget forever by re-opening (or close+re-opening) the
        // subscription.
        if self.neg_opens_total >= MAX_NEG_OPENS {
            // Like every other failed NEG-OPEN, the old subscription is
            // left untouched.
            self.send_neg_err(
                &sub_id,
                "blocked: too many negentropy opens (connection limit)",
            );
            return;
        }
        self.neg_opens_total += 1;
        if let Some(old) = self.neg.remove(&sub_id) {
            self.neg_total = self.neg_total.saturating_sub(old.items.len());
            // Release the subscription slot of the replaced negentropy
            // subscription (the new one re-acquires it below).
            self.relay
                .stats
                .subscriptions_active
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            self.subscriptions_held
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }
        self.neg_total += items.len();
        self.neg.insert(
            sub_id.clone(),
            NegState {
                items,
                rounds_left: MAX_NEG_MSG_ROUNDS,
            },
        );
        // NEG-OPEN subscriptions are active subscriptions: they hold
        // filters and items until closed, so they count towards
        // `subscriptions_active` like REQ subscriptions.
        self.relay
            .stats
            .subscriptions_active
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.subscriptions_held
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.send_neg_msg(&sub_id, &response);
    }

    pub(crate) async fn handle_neg_msg(&mut self, rest: &[Value]) {
        if rest.len() < 2 {
            // Correlate with NEG-ERR when the id is known, else NOTICE.
            if let Some(sub_id) = rest
                .first()
                .and_then(value_string)
                .filter(|s| !s.is_empty())
            {
                self.send_neg_err(
                    &sub_id,
                    "error: NEG-MSG requires a subscription id and message",
                );
            } else {
                self.send_notice("error: NEG-MSG requires a subscription id and message");
            }
            return;
        }
        let Some(sub_id) = value_string(&rest[0]) else {
            self.send_notice("error: NEG-MSG subscription id must be a string");
            return;
        };
        if sub_id.is_empty() {
            self.send_notice("error: NEG-MSG subscription id must be a non-empty string");
            return;
        }
        let Some(message) = rest[1].as_str() else {
            // NIP-77: after NEG-ERR the subscription is closed — malformed
            // continuations close the id they name instead of lingering open.
            self.remove_neg_subscription(&sub_id);
            self.send_neg_err(&sub_id, "error: NEG-MSG message must be hex");
            return;
        };
        let Ok(message) = hex::decode(message) else {
            self.remove_neg_subscription(&sub_id);
            self.send_neg_err(&sub_id, "error: NEG-MSG message must be hex");
            return;
        };
        // The access lists gate in-flight syncs too: a pubkey that was
        // denied mid-reconciliation gets its sync stopped immediately
        // (per NIP-77 a NEG-ERR closes the subscription) — no reconnect
        // needed.
        if !self.access_allows_read().await {
            self.remove_neg_subscription(&sub_id);
            self.send_neg_err(&sub_id, "restricted: you are not allowed to sync");
            return;
        }
        let Some(_exists) = self.neg.get(&sub_id) else {
            self.send_neg_err(&sub_id, "closed: unknown subscription");
            return;
        };
        // NIP-77: "After a NEG-ERR is issued, the subscription is considered
        // to be closed." Exhausting the round budget closes it too.
        // Check without holding the borrow so the close can release it.
        if self.neg.get(&sub_id).is_some_and(|s| s.rounds_left == 0) {
            self.remove_neg_subscription(&sub_id);
            self.send_neg_err(&sub_id, "error: too many negentropy messages");
            return;
        }
        let Some(state) = self.neg.get_mut(&sub_id) else {
            self.send_neg_err(&sub_id, "closed: unknown subscription");
            return;
        };
        state.rounds_left -= 1;
        match nip77::respond(&state.items, &message) {
            Ok(response) => {
                // Bound the response like the REQ path's
                // `max_req_response_bytes`: a mode-2 reply returns every
                // id of the range (up to ~6 MiB of hex for 100k items),
                // and 128 rounds would otherwise amplify one connection
                // into hundreds of MiB of bandwidth.
                let budget = self.req_response_bytes;
                // The response is sent hex-encoded inside a JSON array
                // (roughly 2.2x the binary size), so budget against the
                // wire size, not the binary size.
                let wire_size = response.len() as u64 * 2;
                let over_budget = budget > 0 && wire_size > budget;
                if over_budget {
                    self.remove_neg_subscription(&sub_id);
                    self.send_neg_err(
                        &sub_id,
                        "blocked: negentropy response too large (increase limits.max_req_response_bytes)",
                    );
                    return;
                }
                self.send_neg_msg(&sub_id, &response)
            }
            Err(reason) => {
                self.remove_neg_subscription(&sub_id);
                self.send_neg_err(&sub_id, &format!("error: {reason}"));
            }
        }
    }

    /// Decrements `subscriptions_active` for a closed negentropy
    /// subscription (every NEG-OPEN success acquired one slot).
    pub(crate) fn release_neg_stats_subscription(&self) {
        self.relay
            .stats
            .subscriptions_active
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        self.subscriptions_held
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub(crate) fn handle_neg_close(&mut self, rest: &[Value]) {
        let Some(sub_id) = rest.first().and_then(value_string) else {
            self.send_notice("error: NEG-CLOSE requires a subscription id");
            return;
        };
        // NIP-77 separate namespace: NEG-CLOSE releases only NEG state.
        self.remove_neg_subscription(&sub_id);
    }
}
