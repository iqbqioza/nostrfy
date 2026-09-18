//! NIP-77 negentropy message handling: `NEG-OPEN`/`NEG-MSG`/`NEG-CLOSE`
//! and the `NEG-ERR` replies. The reconciliation protocol itself lives in
//! [`crate::nips::nip77`].

use serde_json::{Value, json};

use crate::filter::Filter;
use crate::nips::nip77;
use crate::util::unix_now;

/// NIP-77 negentropy state for one open subscription.
pub(crate) struct NegState {
    pub(crate) items: Vec<nip77::Item>,
    /// Remaining NEG-MSG rounds for this subscription. The reconciliation
    /// protocol completes in a bounded number of rounds proportional to the
    /// number of divergent ranges; a peer that keeps sending NEG-MSG with
    /// bogus fingerprints would otherwise force an unbounded, CPU-bounded
    /// bisection over the held items on every message.
    pub(crate) rounds_left: u32,
    /// The relay-wide NEG budget this state's items were reserved against
    /// (`None` for test fixtures).
    pub(crate) budget: Option<std::sync::Arc<super::PendingResponseBudget>>,
    /// The bytes reserved in `budget`; released on drop so NEG-CLOSE,
    /// replacement, connection drop and panic all unaccount exactly once
    /// (the same RAII contract as `PendingReq`).
    pub(crate) reserved: u64,
}

impl Drop for NegState {
    fn drop(&mut self) {
        if let Some(budget) = &self.budget {
            budget.release(self.reserved);
        }
    }
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
        self.send_control(json!(["NEG-ERR", sub_id, reason]));
    }

    /// NIP-77: "After a NEG-ERR is issued, the subscription is considered to
    /// be closed." Every refusal therefore releases any state held under the
    /// id before replying, so the client and the relay agree that the
    /// subscription is gone.
    pub(crate) fn neg_err(&mut self, sub_id: &str, reason: &str) {
        self.remove_neg_subscription(sub_id);
        self.send_neg_err(sub_id, reason);
    }

    pub(crate) fn send_neg_msg(&mut self, sub_id: &str, message: &[u8]) {
        self.send_control(json!(["NEG-MSG", sub_id, hex::encode(message)]));
    }

    /// Whether the outgoing queue is too deep for another (potentially
    /// multi-megabyte) negentropy reply: `send_control` bypasses the queue
    /// caps so completion-critical messages are never dropped, but an
    /// attacker driving rapid NEG-MSG rounds on a slow reader could
    /// otherwise accumulate gigabytes. Callers fail the round with a
    /// retryable NEG-ERR instead, bounding queued NEG bytes to a small
    /// multiple of the per-connection cap.
    fn neg_backpressured(&self) -> bool {
        self.out_queue_bytes > 0 && self.out_bytes > self.out_queue_bytes.saturating_mul(4)
    }

    pub(crate) async fn handle_neg_open(&mut self, rest: &[Value]) {
        // NIP-77 errors are NEG-ERR when a subscription id can be
        // correlated, NOTICE only when no id exists to echo.
        let correl_id: Option<String> = rest
            .first()
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .filter(|s| !s.is_empty());
        if !self.relay.config.read().await.nip_enabled(77) {
            if let Some(sub_id) = correl_id {
                self.neg_err(&sub_id, "error: negentropy is not enabled on this relay");
            } else {
                self.send_notice("error: negentropy is not enabled on this relay");
            }
            return;
        }
        if rest.len() < 3 {
            if let Some(sub_id) = correl_id {
                self.neg_err(
                    &sub_id,
                    "error: NEG-OPEN requires a subscription id, filter and message",
                );
            } else {
                self.send_notice("error: NEG-OPEN requires a subscription id, filter and message");
            }
            return;
        }
        let sub_id = match rest[0].as_str().map(str::to_string) {
            Some(id) if !id.is_empty() => id,
            _ => {
                self.send_notice("error: NEG-OPEN subscription id must be a non-empty string");
                return;
            }
        };
        let max_sub_id_len = self.relay.config.read().await.limits.max_sub_id_len;
        if sub_id.len() > max_sub_id_len {
            self.neg_err(&sub_id, "error: NEG-OPEN subscription id too long");
            return;
        }
        let mut raw = rest[1].clone();
        if crate::filter::rewrite_inbox_outbox(&mut raw).is_err() {
            self.neg_err(&sub_id, "error: invalid NEG-OPEN filter");
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
                self.neg_err(&sub_id, "error: invalid NEG-OPEN filter");
                return;
            }
        };
        if filter.too_many_members() {
            self.neg_err(
                &sub_id,
                "error: too many ids, authors, kinds or tag values in the filter",
            );
            return;
        }
        if filter.invalid_tag_values() {
            self.neg_err(&sub_id, "error: tag constraint values must be strings");
            return;
        }
        let Some(initial) = rest[2].as_str() else {
            self.neg_err(&sub_id, "error: NEG-OPEN message must be hex");
            return;
        };
        // NIP-42: an auth-requiring relay applies the same policy to
        // negentropy subscriptions as to REQ subscriptions. Checked before
        // the hex decode so an unauthenticated peer cannot force a
        // half-megabyte decode with a rejected frame.
        if self.relay.config.read().await.relay.require_auth && !self.is_authed() {
            self.neg_err(&sub_id, "auth-required: please authenticate before syncing");
            return;
        }
        // The access lists gate syncing like the REQ path: denied pubkeys
        // are never served; `restrict_relay` gates publishing only, so
        // reading stays open. Read fresh per message, so command-event
        // changes apply immediately without a reconnect.
        if !self.access_allows_read().await {
            self.neg_err(&sub_id, "restricted: you are not allowed to sync");
            return;
        }
        let Ok(initial) = hex::decode(initial) else {
            self.neg_err(&sub_id, "error: NEG-OPEN message must be hex");
            return;
        };

        // The configured value also sizes the relay-wide budget below (the
        // per-query cap is narrowed further for anonymous peers).
        let configured_max_items = self.relay.config.read().await.limits.max_neg_items;
        let mut max_items = configured_max_items;
        // Unauthenticated peers get a smaller per-query cap: the
        // per-connection budget is `2 × max_items`, and with the default
        // 100k items (~8 MiB held) times up to `max_connections` anonymous
        // clients the relay-wide exposure would be tens of GB. An
        // authenticated sync keeps the configured cap (large public syncs
        // can still authenticate).
        const UNAUTH_NEG_ITEMS: usize = 10_000;
        if !self.is_authed() {
            max_items = max_items.min(UNAUTH_NEG_ITEMS);
        }
        let max_subs = self.relay.config.read().await.limits.max_subscriptions;
        // NIP-77: a NEG-OPEN for an already open id replaces it, so it
        // must not count against the cap — only new subscriptions are
        // limited. The cap is shared with REQ subscriptions (both are
        // active subscriptions and both are counted in NIP-11's
        // `max_subscriptions`), so the combined count is checked.
        if !self.neg.contains_key(&sub_id) && self.neg.len() + self.subs.len() >= max_subs {
            self.neg_err(&sub_id, "error: too many subscriptions");
            return;
        }
        // Every open renews the round budget; the connection-wide count
        // caps how often, so a client cannot renew the 128-round CPU budget
        // forever by re-opening (or close+re-opening) the subscription.
        // Checked before the (potentially large) database query: once the
        // budget is exhausted, the scan work must not run at all.
        if self.neg_opens_total >= MAX_NEG_OPENS {
            self.neg_err(
                &sub_id,
                "blocked: too many negentropy opens (connection limit)",
            );
            return;
        }
        // Relay-wide CPU budget: spend the scan's worst case (this open's
        // item cap) before the query runs, so a coordinated flood of
        // NEG-OPENs across connections is refused before it reaches the
        // reader threads. Charged even when the open fails later, like the
        // per-connection open budget below: the scan work was already
        // driven.
        if !self.neg_cpu_budget.try_charge(
            max_items as u64,
            super::neg_cpu_budget_units(configured_max_items),
        ) {
            self.neg_err(&sub_id, "error: overloaded, please retry");
            return;
        }
        // Spend the budget before the scan: an open that fails later (a
        // codec error, a response over the byte budget, a full item cap)
        // has already driven the database query, so it must count too —
        // otherwise a client could run the scan unbounded by re-opening
        // with an initial message that always fails.
        self.neg_opens_total += 1;
        let now = unix_now();
        // The negentropy query only needs (created_at, id) records, so it
        // never materializes every matching full event in memory.
        let Some((items, more)) = self.relay.db.neg_query_result(filter, max_items, now).await
        else {
            // A failed sync must never be answered with an empty item set:
            // the peer would conclude everything is gone locally and delete
            // its events. The reported query variant returns `None` for
            // every failure (timeout, fail-fast, the reader dropping the
            // request on a store error); NEG-ERR closes the subscription
            // per NIP-77, which is the safe retryable failure mode.
            self.neg_err(&sub_id, "error: database unavailable; retry");
            return;
        };
        // The scan's collect cap is `max_items`, so the collected count can
        // never exceed it: `more` alone marks a query too large to answer.
        if more {
            // NIP-77: the maximum number of processable records may be
            // returned as the fourth element. NEG-ERR closes the id.
            self.remove_neg_subscription(&sub_id);
            self.send_control(json!([
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
                            item.wrap_recipients.as_ref().is_some_and(|recips| {
                                recips.iter().any(|r| r.eq_ignore_ascii_case(pk))
                            })
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
        // memory on a single connection. A NEG-OPEN for an already open id
        // first closes the existing subscription (NIP-77), so its items are
        // accounted out before the new set is admitted. This per-connection
        // cap (like `MAX_NEG_MSG_ROUNDS`/`MAX_NEG_OPENS` above) is a second
        // bound: the relay-wide `neg_budget` below bounds the aggregate
        // held items across connections, and `neg_backpressured` bounds the
        // queued NEG replies.
        let total_cap = max_items.saturating_mul(2);
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
            self.remove_neg_subscription(&sub_id);
            self.send_control(json!([
                "NEG-ERR",
                sub_id,
                "blocked: too many negentropy items",
                total_cap
            ]));
            return;
        }
        // The response is built before the old state is replaced: on any
        // failure the `neg_err` paths above release the id (NIP-77: a
        // NEG-ERR closes the subscription), so a refused open never leaves
        // the id half-replaced.
        let response = match nip77::respond(&items, &initial) {
            Ok(response) => response,
            Err(e) => {
                self.neg_err(&sub_id, &format!("error: {e}"));
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
            self.neg_err(
                &sub_id,
                "blocked: negentropy response too large (increase limits.max_req_response_bytes)",
            );
            return;
        }
        // Relay-wide NEG budget: the per-connection caps alone still let
        // `max_connections` connections pin tens of GB of held items, so
        // the set is reserved against the shared counter before it is
        // stored. A NEG-OPEN for an already open id first closes the
        // existing subscription (NIP-77): removing it releases its
        // reservation and its subscription slot first, so a same-size
        // replacement stays net zero even when the budget is full.
        // Over-budget opens fail retryably (`error:`) — which per NIP-77
        // closes the id — instead of pinning the items.
        if let Some(old) = self.neg.remove(&sub_id) {
            self.neg_total = self.neg_total.saturating_sub(old.items.len());
            // Release the subscription slot of the replaced negentropy
            // subscription (the new one re-acquires it below). Dropping
            // `old` also releases its budget reservation.
            self.release_neg_stats_subscription();
        }
        let item_bytes = items.len() as u64 * super::NEG_ITEM_BYTES;
        let Some(reserved) = self
            .neg_budget
            .try_reserve(item_bytes, super::neg_budget_bytes(configured_max_items))
        else {
            self.neg_err(&sub_id, "error: overloaded, please retry");
            return;
        };
        self.neg_total += items.len();
        self.neg.insert(
            sub_id.clone(),
            NegState {
                items,
                rounds_left: MAX_NEG_MSG_ROUNDS,
                budget: Some(std::sync::Arc::clone(&self.neg_budget)),
                reserved,
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
        if self.neg_backpressured() {
            self.remove_neg_subscription(&sub_id);
            self.neg_err(&sub_id, "blocked: overloaded, please retry");
            return;
        }
        self.send_neg_msg(&sub_id, &response);
    }

    pub(crate) async fn handle_neg_msg(&mut self, rest: &[Value]) {
        if rest.len() < 2 {
            // Correlate with NEG-ERR when the id is known, else NOTICE.
            // NIP-77: after NEG-ERR the subscription is closed, so a named
            // id is released like every other malformed continuation.
            if let Some(sub_id) = rest
                .first()
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .filter(|s| !s.is_empty())
            {
                self.neg_err(
                    &sub_id,
                    "error: NEG-MSG requires a subscription id and message",
                );
            } else {
                self.send_notice("error: NEG-MSG requires a subscription id and message");
            }
            return;
        }
        let Some(sub_id) = rest[0].as_str().map(str::to_string) else {
            self.send_notice("error: NEG-MSG subscription id must be a string");
            return;
        };
        if sub_id.is_empty() {
            self.send_notice("error: NEG-MSG subscription id must be a non-empty string");
            return;
        }
        // NIP-77 disabled mid-session (SIGHUP reload or a command event):
        // stop the in-flight sync like any other refusal instead of letting
        // a disabled feature keep running. The configured item cap sizes
        // the relay-wide CPU budget charged below.
        let (nip77_enabled, configured_max_items) = {
            let cfg = self.relay.config.read().await;
            (cfg.nip_enabled(77), cfg.limits.max_neg_items)
        };
        if !nip77_enabled {
            self.neg_err(&sub_id, "error: negentropy is not enabled on this relay");
            return;
        }
        // The access lists gate in-flight syncs too: a pubkey that was
        // denied mid-reconciliation gets its sync stopped immediately
        // (per NIP-77 a NEG-ERR closes the subscription) — no reconnect
        // needed.
        if !self.access_allows_read().await {
            self.neg_err(&sub_id, "restricted: you are not allowed to sync");
            return;
        }
        // Check the subscription before decoding the message: an unknown id
        // must not cost a hex decode (and allocation) of a large frame.
        if !self.neg.contains_key(&sub_id) {
            self.neg_err(&sub_id, "closed: unknown subscription");
            return;
        }
        let Some(message) = rest[1].as_str() else {
            // NIP-77: after NEG-ERR the subscription is closed — malformed
            // continuations close the id they name instead of lingering open.
            self.neg_err(&sub_id, "error: NEG-MSG message must be hex");
            return;
        };
        let Ok(message) = hex::decode(message) else {
            self.neg_err(&sub_id, "error: NEG-MSG message must be hex");
            return;
        };
        // NIP-77: "After a NEG-ERR is issued, the subscription is considered
        // to be closed." Exhausting the round budget closes it too.
        // Check without holding the borrow so the close can release it.
        if self.neg.get(&sub_id).is_some_and(|s| s.rounds_left == 0) {
            self.neg_err(&sub_id, "error: too many negentropy messages");
            return;
        }
        let Some(state) = self.neg.get_mut(&sub_id) else {
            self.neg_err(&sub_id, "closed: unknown subscription");
            return;
        };
        state.rounds_left -= 1;
        // Relay-wide CPU budget: a round's bisection costs about its held
        // item count. A coordinated flood of rounds across connections is
        // refused retryably instead of monopolizing the CPU; per NIP-77
        // the NEG-ERR closes this subscription.
        if !self.neg_cpu_budget.try_charge(
            state.items.len().max(1) as u64,
            super::neg_cpu_budget_units(configured_max_items),
        ) {
            self.neg_err(&sub_id, "error: overloaded, please retry");
            return;
        }
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
                    self.neg_err(
                        &sub_id,
                        "blocked: negentropy response too large (increase limits.max_req_response_bytes)",
                    );
                    return;
                }
                if self.neg_backpressured() {
                    self.neg_err(&sub_id, "blocked: overloaded, please retry");
                    return;
                }
                self.send_neg_msg(&sub_id, &response)
            }
            Err(e) => {
                self.neg_err(&sub_id, &format!("error: {e}"));
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
        let Some(sub_id) = rest.first().and_then(|v| v.as_str()).map(str::to_string) else {
            self.send_notice("error: NEG-CLOSE requires a subscription id");
            return;
        };
        // NIP-77 separate namespace: NEG-CLOSE releases only NEG state.
        self.remove_neg_subscription(&sub_id);
    }
}
