//! Protocol message handlers (NIP-01/42/45/67/70/77) and the live
//! delivery path. Every method operates on the [`super::Conn`] state; the
//! connection loop itself lives in `super`.
//!
//! NIP-45 divergence (`limit`): `COUNT` ignores each filter's `limit`,
//! including `limit: 0`, and counts every match (up to `limits.max_count`).
//! NIP-45 asks for the size of the match set and defines no ordering or
//! pagination, so a `limit` cannot bound "the last n events". `REQ` keeps
//! the NIP-01 interpretation where `limit: 0` yields an empty page for that
//! filter (and keeps the subscription alive). Both behaviors are pinned by
//! tests; clients must not use `limit: 0` to probe a COUNT.

use axum::extract::ws::Message;
use serde_json::{Value, json};

use crate::event::Event;
use crate::filter::Filter;
use crate::nips::{nip29, nip40, nip42, nip45, nip70};
use crate::util::unix_now;

/// A strict lower bound of the serialized wire frame
/// `["EVENT", <sub_id>, <event>]` in bytes, used to stop materializing a
/// stored response that already exceeds the connection's
/// `max_req_response_bytes`. JSON escaping and the numeric fields can only
/// add bytes, so an event whose lower bound pushes the total past the
/// budget will certainly fail the pump's exact byte check — the bound can
/// only keep *more* events than fit (bounded by the underestimate), never
/// less, so it cannot cause a silent truncation.
fn event_frame_lower_bound(event: &Event, sub_id_len: usize) -> u64 {
    let tag_bytes: usize = event
        .tags
        .iter()
        .map(|tag| tag.iter().map(String::len).sum::<usize>())
        .sum();
    event
        .content
        .len()
        .saturating_add(tag_bytes)
        .saturating_add(event.id.len())
        .saturating_add(event.pubkey.len())
        .saturating_add(event.sig.len())
        .saturating_add(sub_id_len) as u64
}

impl super::Conn {
    /// The verb of a JSON array message, extracted with a lightweight scan
    /// (no full parse): `["EVENT", ...]` → `"EVENT"`. Returns `None` when
    /// the text is not a string array.
    pub(crate) fn first_token(text: &str) -> Option<&str> {
        let rest = text.trim_start().strip_prefix('[')?.trim_start();
        let rest = rest.strip_prefix('"')?;
        let end = rest.find('"')?;
        Some(&rest[..end])
    }

    pub(crate) async fn handle_text(&mut self, text: &str) {
        let Some(kind) = Self::first_token(text) else {
            self.send_notice("error: expected an array message");
            return;
        };
        // EVENT messages are queued and accepted in batches so the
        // database commit cost is paid once per batch instead of once
        // per event; the batch is flushed when it is full, when the
        // socket is momentarily idle, or before any other message.
        // Fast path: the message is parsed directly as a `(verb, event)`
        // pair in a single JSON pass — the generic `Value` parse (and its
        // per-message allocation) is skipped entirely for the hot path.
        // The generic path is only taken for malformed messages (to emit
        // the NOTICE).
        if kind == "EVENT"
            && let Ok((_, event)) = serde_json::from_str::<(String, Event)>(text)
        {
            return self.queue_event_sized(event, text.len()).await;
        }
        let Ok(value) = serde_json::from_str::<Value>(text) else {
            self.send_notice("error: invalid json");
            return;
        };
        let Some(msg) = value.as_array() else {
            self.send_notice("error: expected an array message");
            return;
        };
        let Some(Some(kind)) = msg.first().map(|v| v.as_str()) else {
            self.send_notice("error: message type must be a string");
            return;
        };

        match kind {
            // The EVENT arm is only reached for malformed EVENT messages
            // (the valid ones returned above).
            "EVENT" => {
                self.queue_event(&msg[1..]).await;
            }
            "REQ" => {
                self.flush_pending_events().await;
                self.handle_req(&msg[1..]).await;
            }
            "CLOSE" => {
                self.flush_pending_events().await;
                self.handle_close(&msg[1..]);
            }
            "AUTH" => {
                self.flush_pending_events().await;
                self.handle_auth(&msg[1..]).await;
            }
            "COUNT" => {
                self.flush_pending_events().await;
                self.handle_count(&msg[1..]).await;
            }
            "NEG-OPEN" => {
                self.flush_pending_events().await;
                self.handle_neg_open(&msg[1..]).await;
            }
            "NEG-MSG" => {
                self.flush_pending_events().await;
                self.handle_neg_msg(&msg[1..]).await;
            }
            "NEG-CLOSE" => {
                self.flush_pending_events().await;
                self.handle_neg_close(&msg[1..]);
            }
            "PING" => {
                // A de-facto nostr convention: answer text PING messages
                // with a PONG so keep-alive probes get a response.
                self.send_json(json!(["PONG"]));
            }
            other => {
                self.flush_pending_events().await;
                self.send_notice(&format!("error: unsupported message type {other}"));
            }
        }
    }

    /// Queues an already-parsed event for batched acceptance, counting the
    /// frame's wire size against the per-connection pending-byte budget.
    pub(crate) async fn queue_event_sized(&mut self, event: Event, size: usize) {
        self.events_received_local += 1;
        // Path-specific write policy (nostrfy): `/inbox` and `/outbox` are
        // restricted endpoints — see `write_policy_reason`.
        if let Some(reason) = self.write_policy_reason(&event) {
            self.relay.stats.bump(&self.relay.stats.events_rejected, 1);
            self.send_ok(&event.id, false, &reason);
            return;
        }
        self.pending_bytes = self.pending_bytes.saturating_add(size);
        // The connection loop queues the batch at the end of its sliding
        // window (and resolves it on a spawned task while reading keeps
        // going); a mid-window synchronous flush here would serialize the
        // connection on every commit.
        self.pending_events.push(event);
    }

    /// Queues an already-parsed event for batched acceptance when the wire
    /// size is not known (tests and the generic `queue_event` path): the
    /// event's serialized size is a close upper bound of the frame.
    pub(crate) async fn queue_event_value(&mut self, event: Event) {
        let size = serde_json::to_string(&event).map(|s| s.len()).unwrap_or(0);
        self.queue_event_sized(event, size).await;
    }

    /// The write policy of the endpoint this connection is on:
    /// `/outbox` accepts only events authored by the NIP-42-authenticated
    /// pubkey of this connection (`relay.outbox_write_policy = "any"`) or
    /// only events authored by the relay's own pubkey (`"relay"`); `/inbox`
    /// accepts only events carrying a `p` tag — any recipient
    /// (`relay.inbox_write_policy = "any"`) or the relay itself
    /// (`"relay"`). Every other path is unrestricted.
    ///
    /// The policy strings and the relay pubkey are cached on the connection
    /// (refreshed on config-version changes): this runs once per EVENT, so
    /// it must not take the shared config lock or clone per call.
    pub(crate) fn write_policy_reason(&self, event: &Event) -> Option<String> {
        // Fast path: the vast majority of connections are on the default
        // path — a cheap string comparison rejects them first.
        if self.path != "/outbox" && self.path != "/inbox" {
            return None;
        }
        match self.path.as_str() {
            "/outbox" => match self.outbox_write_policy.trim() {
                "relay" => {
                    let Some(relay_pk) = self.relay_pubkey.as_deref() else {
                        return Some(
                            "restricted: the relay has no identity key for /outbox writes".into(),
                        );
                    };
                    if event.pubkey != relay_pk {
                        return Some(
                            "restricted: /outbox accepts only events authored by the relay".into(),
                        );
                    }
                    None
                }
                _ => {
                    if !self.authed_pubkeys.contains(&event.pubkey) {
                        return Some(
                            "restricted: /outbox accepts only your own NIP-42-authenticated events"
                                .into(),
                        );
                    }
                    None
                }
            },
            "/inbox" => match self.inbox_write_policy.trim() {
                "relay" => {
                    let Some(relay_pk) = self.relay_pubkey.as_deref() else {
                        return Some(
                            "restricted: the relay has no identity key for /inbox writes".into(),
                        );
                    };
                    let addressed_to_relay = event.tags.iter().any(|t| {
                        t.len() >= 2 && t[0] == "p" && t[1].eq_ignore_ascii_case(relay_pk)
                    });
                    if !addressed_to_relay {
                        return Some(
                            "restricted: /inbox accepts only events addressed to the relay".into(),
                        );
                    }
                    None
                }
                _ => {
                    if !event.tags.iter().any(|t| t.len() >= 2 && t[0] == "p") {
                        return Some(
                            "restricted: /inbox accepts only events carrying a p tag".into(),
                        );
                    }
                    None
                }
            },
            _ => None,
        }
    }

    /// Queues an EVENT message for batched acceptance (generic path).
    pub(crate) async fn queue_event(&mut self, rest: &[Value]) {
        let Some(value) = rest.first() else {
            // NIP-01: every received EVENT frame gets an OK, so a
            // publisher that sent a frame without an event object still
            // gets a correlated response.
            self.send_ok("", false, "invalid: EVENT requires an event object");
            return;
        };
        let event: Event = match serde_json::from_value(value.clone()) {
            Ok(event) => event,
            Err(_) => {
                // NIP-01: every EVENT gets an OK. Correlate with the id
                // when the malformed object still carries one; otherwise
                // the empty id is the only correlation the frame allows.
                self.send_ok(
                    value.get("id").and_then(Value::as_str).unwrap_or(""),
                    false,
                    "invalid: malformed event",
                );
                return;
            }
        };
        self.queue_event_value(event).await;
    }

    /// Accepts the queued events in one database batch and sends the OKs.
    pub(crate) async fn flush_pending_events(&mut self) {
        if self.pending_events.is_empty() {
            return;
        }
        let events = std::mem::take(&mut self.pending_events);
        self.pending_bytes = 0;
        let outcomes = self
            .relay
            .accept_events_batch(events, &self.authed_pubkeys)
            .await;
        for (id, outcome) in outcomes {
            match outcome {
                crate::db::PutOutcome::Stored | crate::db::PutOutcome::Replaced => {
                    self.send_ok(&id, true, "");
                }
                crate::db::PutOutcome::Ephemeral => {
                    // NIP-01: ephemeral kinds are delivered live but never
                    // stored. The event was accepted (forwarded to the
                    // current subscribers), so the OK is `true` with the
                    // empty message the spec allows; `mute:` means "ignored"
                    // and would contradict the acceptance.
                    self.send_ok(&id, true, "");
                }
                crate::db::PutOutcome::Duplicate(msg) => {
                    self.send_ok(&id, true, &msg);
                }
                crate::db::PutOutcome::Invalid(reason) => {
                    self.send_ok(&id, false, &reason);
                }
                crate::db::PutOutcome::Expired => {
                    self.send_ok(&id, false, "invalid: event has expired");
                }
                crate::db::PutOutcome::PreviouslyDeleted => {
                    self.send_ok(&id, false, "blocked: event has been deleted");
                }
            }
        }
    }

    pub(crate) async fn handle_req(&mut self, rest: &[Value]) {
        if rest.is_empty() {
            self.send_notice("error: REQ requires a subscription id and filters");
            return;
        }
        let sub_id = match rest[0].as_str() {
            Some(id) => id,
            None => {
                self.send_notice("error: subscription id must be a string");
                return;
            }
        };
        if rest.len() < 2 {
            // NIP-01: a REQ with a subscription id can be refused with a
            // terminal CLOSED (the client gets a correlated reply); only
            // without an id is there nothing to echo, so a NOTICE is used.
            self.reject_req(sub_id, "invalid: REQ requires at least one filter");
            return;
        }

        let cfg = self.relay.config.read().await;
        let (max_sub_id_len, max_filters, max_subscriptions, max_limit) = (
            cfg.limits.max_sub_id_len,
            cfg.limits.max_filters,
            cfg.limits.max_subscriptions,
            cfg.limits.max_limit,
        );
        let search_enabled = cfg.nip_enabled(50);
        let require_auth = cfg.relay.require_auth;
        let sub_bytes_limit = cfg.limits.max_sub_bytes;
        let eose_hint = cfg.nip_enabled(67);
        drop(cfg);
        if sub_id.is_empty() {
            self.reject_req(sub_id, "invalid: subscription id must not be empty");
            return;
        }
        if sub_id.len() > max_sub_id_len {
            self.reject_req(sub_id, "invalid: subscription id too long");
            return;
        }

        // Bound the filter count before parsing any filter: a frame full of
        // maximum-size filters must be refused without cloning and parsing
        // all of them first.
        if rest.len().saturating_sub(1) > max_filters {
            self.reject_req(sub_id, "invalid: too many filters");
            return;
        }
        let mut filters = Vec::new();
        for f in &rest[1..] {
            let mut f = f.clone();
            // nostrfy inbox/outbox keys expand into `#p`/`authors`; an invalid
            // value makes the whole subscription invalid like any other
            // malformed filter field.
            if crate::filter::rewrite_inbox_outbox(&mut f).is_err() {
                self.reject_req(sub_id, "invalid: invalid filter");
                return;
            }
            match serde_json::from_value::<Filter>(f) {
                Ok(filter) => filters.push(filter),
                Err(_) => {
                    self.reject_req(sub_id, "invalid: invalid filter");
                    return;
                }
            }
        }
        if filters.is_empty() {
            self.reject_req(sub_id, "invalid: REQ requires at least one filter");
            return;
        }
        if filters.iter().any(|f| f.too_many_members()) {
            self.reject_req(
                sub_id,
                "invalid: too many ids, authors, kinds or tag values in a filter",
            );
            return;
        }
        if filters.iter().any(|f| f.invalid_tag_values()) {
            self.reject_req(sub_id, "invalid: tag constraint values must be strings");
            return;
        }

        let search_disabled = filters.iter().any(|f| f.has_search()) && !search_enabled;

        if require_auth && !self.is_authed() {
            self.reject_req(
                sub_id,
                "auth-required: please authenticate before subscribing",
            );
            return;
        }
        // The access lists gate reading too: a denied pubkey is never
        // served (even when authenticated); `restrict_relay` narrows
        // publishing to the allow list, reading stays open to everyone.
        // Changes made by command events
        // (or NIP-86) apply to this connection immediately — the list is
        // read fresh per message, no reconnect needed.
        if !self.access_allows_read().await {
            self.reject_req(sub_id, "restricted: you are not allowed to subscribe");
            return;
        }
        // NIP-01: re-REQ with an existing id replaces the subscription, so it
        // must not count against the cap — only genuinely new subscriptions
        // are limited. The cap is shared with NEG-OPEN subscriptions (both
        // are active subscriptions), so the combined count is checked.
        if !self.subs.contains_key(sub_id) && self.subs.len() + self.neg.len() >= max_subscriptions
        {
            self.reject_req(sub_id, "error: too many subscriptions");
            return;
        }

        // `filters` is no longer needed after the validation above: move it
        // instead of cloning (the connection keeps its own copy in `subs`,
        // the scan takes this one).
        let mut stored = filters;
        if search_disabled {
            for f in &mut stored {
                f.search = None;
            }
            self.send_notice("search is not enabled on this relay");
        }

        // Bound the memory held by this connection's subscriptions: each
        // filter is bounded by the message size limit, so without a cap a
        // connection could pin many megabytes of filter data. The size is
        // counted straight from the serializer (no intermediate String).
        let sub_bytes: usize = stored
            .iter()
            .map(json_len)
            .fold(0usize, |acc, n| acc.saturating_add(n));
        let replacing = self.subs.get(sub_id).map(|(_, bytes, _)| *bytes);
        // NIP-01: a REQ replaces the subscription under this id. Every
        // still-queued frame of the previous incarnation must go — the old
        // response's events, its EOSE, and any CLOSED queued by an earlier
        // failed REQ under the same id (which would otherwise close the new
        // subscription on the wire).
        self.purge_queued_events_for(sub_id);
        let next_total = self
            .sub_bytes
            .saturating_sub(replacing.unwrap_or(0))
            .saturating_add(sub_bytes);
        if next_total > sub_bytes_limit {
            self.reject_req(sub_id, "error: too many subscriptions");
            return;
        }
        self.sub_bytes = next_total;
        self.subs.insert(
            sub_id.to_string(),
            (
                stored.clone(),
                sub_bytes,
                // The serialized sub id: the live path wraps every
                // matching event with it, so it is encoded once per
                // subscription instead of once per event.
                serde_json::to_string(sub_id).unwrap_or_default(),
            ),
        );
        // Register the subscription in the live index *before* running
        // the query, so no event stored between the query and the
        // subscription is missed (a duplicate delivery of an event that
        // is both in the query result and live is harmless: clients
        // deduplicate by id).
        self.sync_live_index();
        if replacing.is_none() {
            self.relay
                .stats
                .bump(&self.relay.stats.subscriptions_total, 1);
            self.relay
                .stats
                .bump(&self.relay.stats.subscriptions_active, 1);
            self.subscriptions_held
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }

        // Install the response barrier before querying. The connection task
        // cannot process live batches while this query is awaited, but
        // creating it here also makes the ordering invariant explicit:
        // stored events and EOSE are always queued before live events.
        self.enqueue_pending_req(crate::ws::PendingReq {
            sub_id: sub_id.to_string(),
            events: Default::default(),
            eose_hint,
            truncated_or_more: false,
            auth_hint: false,
            sent_bytes: 0,
            live: Default::default(),
            live_bytes: 0,
            eose_sent: false,
            budget: None,
            reserved: 0,
        });

        let now = unix_now();
        // NIP-01: `limit` applies to each filter independently. The scan
        // over-fetches each filter's limit (hidden-event slack) so that
        // events withheld by the visibility rules below do not consume the
        // limit slots; the visible results are then attributed back to the
        // filters, so one filter's matches cannot consume another filter's
        // quota. `max_limit` is operator-configured without an upper bound,
        // so the quotas are per-filter (a sum would need saturation and
        // still blur the attribution).
        let limits: Vec<usize> = stored
            .iter()
            .map(|f| f.limit.unwrap_or(max_limit).min(max_limit))
            .collect();
        let Some((events, more)) = self
            .relay
            .db
            .query_req_result(stored.clone(), max_limit, now)
            .await
        else {
            // A timed-out query must not be presented as an empty
            // timeline: close the subscription with a clear reason so the
            // client can retry. The subscription (which was registered
            // before the query) must be released too — a CLOSED sub must
            // not keep receiving live events. REQ namespace only.
            let sub_id = sub_id.to_string();
            self.remove_req_subscription(&sub_id);
            self.send_closed(&sub_id, "error: database unavailable; retry");
            return;
        };
        let mut to_send = Vec::new();
        // NIP-67: whether any withheld event could be revealed by AUTH, in
        // which case the `EOSE` carries the `"auth"` hint (challenges must
        // be enabled for the hint to make sense, mirroring
        // `send_auth_challenge`).
        let hint_eligible = {
            let cfg = self.relay.config.read().await;
            cfg.nip_enabled(42) && cfg.relay.send_auth_challenge
        };
        let mut auth_hidden = false;
        {
            // The global group-store read lock is only needed when the
            // result actually contains group events (COUNT and the live
            // path skip it the same way): holding it across every stored
            // event of a REQ would block group writes for no reason.
            let groups = if events.iter().any(nip29::is_group_event) {
                Some(self.relay.groups.read().await)
            } else {
                None
            };
            for event in events {
                if !self.visible_to(groups.as_deref(), &event) {
                    if hint_eligible && self.auth_hidden_behind(groups.as_deref(), &event) {
                        auth_hidden = true;
                    }
                    continue;
                }
                to_send.push(event);
            }
        }
        // Note: `truncated || more` below is computed pre-visibility-filter
        // (like the scan's `more`), so a fully-withheld page can still
        // report `more`. That is conservative on purpose: it prompts the
        // client to authenticate (see the `auth` hint) instead of wrongly
        // claiming completeness.
        let (mut kept, mut truncated) = attribute_visible_page(&mut to_send, &stored, &limits);
        // Same-second pagination guard: when the page is incomplete and
        // every kept event shares one `created_at`, the scan ended at (or
        // inside) that tie block and a client advancing inclusively
        // (`until = T`) would receive the same block forever. The whole
        // boundary second is dropped — a page never delivers a partial tie
        // — and the older events the scan over-fetched are attributed
        // instead, so the client's cursor advances past `T`. The omission
        // keeps the `more` hint; the extreme flood (the scan returned only
        // tie events) yields an empty `more` page, and the client proceeds
        // from `T - 1` on the next request.
        let page_capacity = limits.iter().copied().max().unwrap_or(0);
        let mut tie_truncated = false;
        while (more || truncated) && kept.len() >= page_capacity && !kept.is_empty() {
            let boundary = kept[0].created_at;
            if kept.iter().any(|event| event.created_at != boundary) {
                break;
            }
            to_send.retain(|event| event.created_at != boundary);
            let (next, next_truncated) = attribute_visible_page(&mut to_send, &stored, &limits);
            kept = next;
            truncated = next_truncated;
            tie_truncated = true;
        }
        to_send = kept;
        // Bound the memory this response pins while it waits for the
        // socket. The pump enforces `max_req_response_bytes` on the wire,
        // but without this a slow reader would hold the whole
        // `max_limit × filters` scan result per queued response (up to
        // `MAX_PENDING_REQS` of them). The first event past the budget is
        // kept, so the pump still hits its exact byte check on it and emits
        // the same `CLOSED ... response too large` the client would
        // otherwise receive: the truncation is never silent.
        let mut byte_truncated = false;
        if self.req_response_bytes > 0 {
            let mut total = 0u64;
            let mut kept = 0usize;
            for event in &to_send {
                total = total.saturating_add(event_frame_lower_bound(event, sub_id.len()));
                kept += 1;
                if total > self.req_response_bytes {
                    break;
                }
            }
            // Events were dropped because of the byte budget (not because
            // the scan's limit was reached). The pump's exact byte check
            // normally turns this into the over-budget CLOSED, but a SIGHUP
            // that raises `max_req_response_bytes` before the pump would
            // silently complete the response instead: the EOSE must carry
            // the pending/"more" marker for exactly these drops.
            byte_truncated = kept < to_send.len();
            to_send.truncate(kept);
        }
        // Relay-wide accounting: the materialized events stay pinned until
        // the response finishes pumping, so reserve their (lower-bound)
        // byte size against the relay-wide budget before queueing them.
        // Over-budget responses fail fast with a retryable CLOSED instead
        // of pinning memory; the reservation is released by
        // `PendingReq`'s Drop on every completion, close/replacement,
        // disconnect and panic path.
        let response_bytes = to_send.iter().fold(0u64, |acc, event| {
            acc.saturating_add(event_frame_lower_bound(event, sub_id.len()))
        });
        let Some(reserved) = self.pending_budget.try_reserve(
            response_bytes,
            super::pending_response_budget_bytes(self.req_response_bytes),
        ) else {
            self.remove_req_subscription(sub_id);
            self.send_closed(sub_id, "error: overloaded, please retry");
            return;
        };
        // The response is queued for the pump instead of being pushed into
        // the outgoing queue all at once: the connection loop moves it into
        // the capped queue in bounded chunks as the socket drains, so a
        // slow reader can never pin more than the byte cap in the queue —
        // or more than `limits.max_req_response_bytes` per response.
        let Some(pending) = self
            .pending_reqs
            .iter_mut()
            .find(|pending| pending.sub_id == sub_id)
        else {
            self.pending_budget.release(reserved);
            self.remove_req_subscription(sub_id);
            self.send_closed(sub_id, "error: response barrier lost, please retry");
            return;
        };
        pending.events = to_send.into();
        pending.budget = Some(std::sync::Arc::clone(&self.pending_budget));
        pending.reserved = reserved;
        pending.truncated_or_more = truncated || more || byte_truncated || tie_truncated;
        pending.auth_hint = auth_hidden;
    }

    pub(crate) fn handle_close(&mut self, rest: &[Value]) {
        let Some(Some(sub_id)) = rest.first().map(|v| v.as_str()) else {
            self.send_notice("error: CLOSE requires a subscription id");
            return;
        };
        // NIP-77: REQ and NEG-OPEN live in separate namespaces, so CLOSE
        // releases only the REQ subscription (`NEG-CLOSE` releases NEG).
        self.remove_req_subscription(sub_id);
        // NIP-01: the relay must send nothing further for a closed
        // subscription, so its still-queued frames (EVENT / EOSE /
        // CLOSED) are dropped rather than delivered after the CLOSE.
        self.purge_queued_events_for(sub_id);
    }

    /// Closes every REQ subscription with `reason`, like [`Self::handle_close`]
    /// per id: a connection that stops being allowed (ban, `require_auth`
    /// enabled mid-session) must not starve silently post-EOSE. NEG
    /// subscriptions live in a separate namespace and keep their own
    /// per-round gates.
    fn close_all_subs(&mut self, reason: &str) {
        // Collect first: the removal borrows `subs` mutably per id.
        let ids: Vec<String> = self.subs.keys().cloned().collect();
        for id in &ids {
            self.remove_req_subscription(id);
            self.purge_queued_events_for(id);
            self.send_closed(id, reason);
        }
    }

    /// Rejects a REQ with CLOSED, releasing any previous subscription held
    /// under the same id first. NIP-01 treats CLOSED as terminal: without the
    /// removal a failed re-REQ would leave a ghost subscription that keeps
    /// receiving live events for a client-considered-closed id.
    fn reject_req(&mut self, sub_id: &str, reason: &str) {
        self.remove_req_subscription(sub_id);
        self.send_closed(sub_id, reason);
    }

    /// Re-derives the connection's entries in the live subscription
    /// index from its current subscriptions. Called after every REQ /
    /// CLOSE / sub replacement: the index maps filter components to
    /// connections, and the bus delivers only to the candidate set.
    pub(crate) fn sync_live_index(&self) {
        let components: Vec<crate::relay::FilterComponents> = self
            .subs
            .values()
            .flat_map(|(filters, _, _)| filters.iter().map(crate::relay::FilterComponents::of))
            .collect();
        // `register` replaces this connection's previous components in
        // place, so only this connection's entries are touched instead of
        // the whole index.
        self.relay
            .sub_index
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .register(self.conn_id, components);
    }

    /// Releases a REQ subscription only (NIP-77 separate namespace):
    /// its filter bytes and its live slot. NEG state under the same id is
    /// left untouched (`NEG-CLOSE` releases NEG). Any response still waiting
    /// for the socket is removed with the subscription, so a CLOSE or a
    /// replacement cannot emit stale history after it.
    pub(crate) fn remove_req_subscription(&mut self, sub_id: &str) {
        self.pending_reqs.retain(|pending| pending.sub_id != sub_id);
        if let Some((_, bytes, _)) = self.subs.remove(sub_id) {
            self.sub_bytes = self.sub_bytes.saturating_sub(bytes);
            self.relay
                .stats
                .subscriptions_active
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            self.subscriptions_held
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            // Only an actual removal changes the live index. A CLOSE (or a
            // rejected REQ) for an unknown id must not take the index
            // write lock at all: an attacker could otherwise spam such
            // frames and block live delivery with no subscription state
            // to justify it.
            self.sync_live_index();
        }
    }

    /// Drops the queued frames belonging to a subscription being replaced
    /// or closed (NIP-01 re-REQ / CLOSE): the old response's events, its
    /// EOSE and any CLOSED queued for the id must not be delivered under
    /// the new filter set (or after the client closed the id). The byte,
    /// message and lifetime-traffic accounting is adjusted for the removed
    /// frames — they were counted when queued but never reach the wire.
    pub(crate) fn purge_queued_events_for(&mut self, sub_id: &str) {
        let tag = super::sub_fingerprint(sub_id);
        let mut removed_bytes = 0usize;
        let mut removed_msgs = 0u64;
        self.outgoing.retain(|frame| {
            if frame.event_sub == Some(tag) {
                removed_bytes = removed_bytes.saturating_add(super::message_size(&frame.message));
                removed_msgs += 1;
                false
            } else {
                true
            }
        });
        self.out_bytes = self.out_bytes.saturating_sub(removed_bytes);
        self.out_msgs = self.out_msgs.saturating_sub(removed_msgs);
        self.out_bytes_total = self.out_bytes_total.saturating_sub(removed_bytes as u64);
    }

    /// Releases negentropy state only (NIP-77 separate namespace).
    pub(crate) fn remove_neg_subscription(&mut self, sub_id: &str) {
        if let Some(state) = self.neg.remove(sub_id) {
            self.neg_total = self.neg_total.saturating_sub(state.items.len());
            self.release_neg_stats_subscription();
        }
    }

    pub(crate) async fn handle_auth(&mut self, rest: &[Value]) {
        // Bound the AUTH frames per connection: each well-formed frame
        // costs a Schnorr verification, so an unlimited stream would burn
        // CPU on one connection. The cap must stay comfortably above
        // `MAX_AUTH_KEYS`: every successful authentication counts as an
        // attempt too, so a multi-key client spending its whole key budget
        // would otherwise be refused before it could use it. Frames past
        // the cap are answered with OK (not a NOTICE): the client can
        // still read and reconnect, and NIP-42 requires a correlated
        // response for every AUTH.
        const MAX_AUTH_ATTEMPTS: u32 = 256;
        // Distinct keys recorded per connection. The AUTH attempt cap above
        // already bounds it in practice; the explicit cap remains a DoS
        // guard for the per-event visibility scan over the list.
        const MAX_AUTH_KEYS: usize = 64;
        self.auth_attempts = self.auth_attempts.saturating_add(1);
        if self.auth_attempts > MAX_AUTH_ATTEMPTS {
            // NIP-42: every AUTH must be answered with OK — including this
            // attempt-cap refusal. A NOTICE leaves the client without a
            // correlated response and, per spec, is not how AUTH is
            // refused. Correlate with the id when the frame carries one.
            let id = rest
                .first()
                .and_then(|v| v.get("id"))
                .and_then(Value::as_str)
                .unwrap_or("");
            self.send_control(json!(["OK", id, false, "error: too many AUTH attempts"]));
            return;
        }
        // NIP-42: a parsed AUTH message is always answered with OK, even
        // when no event (or no valid event) can be recovered. A missing
        // event object is still a parsed AUTH frame, so it gets OK with
        // the empty id and an `invalid:` reason instead of a NOTICE.
        let Some(value) = rest.first() else {
            self.send_control(json!([
                "OK",
                "",
                false,
                "invalid: AUTH requires an event object"
            ]));
            return;
        };
        let event: Event = match serde_json::from_value(value.clone()) {
            Ok(event) => event,
            Err(_) => {
                // Correlate with the id when the malformed event still
                // carries one; otherwise the empty id is the only
                // correlation the frame allows.
                self.send_control(json!([
                    "OK",
                    value.get("id").and_then(Value::as_str).unwrap_or(""),
                    false,
                    "invalid: malformed AUTH event"
                ]));
                return;
            }
        };
        if !self.relay.config.read().await.nip_enabled(42) {
            // NIP-42: client AUTH messages MUST be answered with OK, even
            // when the relay does not support authentication.
            self.send_control(nip42::ok(&event.id, false));
            return;
        }
        // NIP-01: event hex fields are lowercase. An uppercase pubkey would
        // verify (its id and signature cover the original string) but then
        // never match the exact-case author comparisons (NIP-70, /outbox,
        // NIP-78), so reject it up front instead of authenticating a key the
        // relay cannot actually use.
        if event.pubkey != event.pubkey.to_ascii_lowercase() {
            self.send_control(nip42::ok(&event.id, false));
            return;
        }
        let id = event.id.clone();
        let accepted = {
            let cfg = self.relay.config.read().await;
            nip42::verify(
                &event,
                &self.challenge,
                self.relay.secp(),
                unix_now(),
                &cfg.relay_identity(),
            )
        };
        if accepted {
            // NIP-42: all authenticated pubkeys are treated as authenticated.
            // Repeated AUTHs with the same key are deduplicated; the
            // number of distinct keys is capped as a DoS guard. At the cap
            // the new key is refused with an explicit OK false instead of
            // evicting the oldest: an eviction would silently invalidate an
            // earlier `OK true` and, with it, the visibility the client
            // authenticated for.
            if !self.authed_pubkeys.iter().any(|pk| pk == &event.pubkey) {
                if self.authed_pubkeys.len() >= MAX_AUTH_KEYS {
                    self.send_control(json!([
                        "OK",
                        id,
                        false,
                        "error: too many authenticated keys; reconnect to retry"
                    ]));
                    return;
                }
                self.authed_pubkeys.push(event.pubkey.clone());
            }
        }
        // The AUTH result is completion-critical: a dropped OK leaves the
        // client unsure whether its authentication was accepted.
        self.send_control(nip42::ok(&id, accepted));
    }

    /// Refuses a COUNT request: NIP-45 requires a CLOSED message, and
    /// CLOSED is terminal for the subscription id on the wire. A REQ
    /// subscription of the same id must therefore be released too, or the
    /// client would consider it closed while the relay kept delivering live
    /// events for it. REQ namespace only (NIP-77 uses NEG-CLOSE).
    fn reject_count(&mut self, sub_id: &str, reason: &str) {
        self.send_closed(sub_id, reason);
        self.remove_req_subscription(sub_id);
    }

    pub(crate) async fn handle_count(&mut self, rest: &[Value]) {
        if rest.is_empty() {
            self.send_notice("error: COUNT requires a subscription id and filters");
            return;
        }
        let Some(sub_id) = rest[0].as_str() else {
            self.send_notice("error: subscription id must be a string");
            return;
        };
        if rest.len() < 2 {
            // NIP-45: a COUNT with a subscription id is refused with the
            // same CLOSED a filters-less REQ uses (the client can
            // correlate); only without an id is a NOTICE the best reply.
            self.reject_count(sub_id, "invalid: COUNT requires at least one filter");
            return;
        }
        if sub_id.is_empty() {
            self.reject_count(sub_id, "invalid: subscription id must not be empty");
            return;
        }
        // One config snapshot for the whole handler: the count path used to
        // take the shared read lock five times per COUNT frame.
        let (max_sub_id_len, nip45, require_auth, max_filters, max_count, search_enabled) = {
            let cfg = self.relay.config.read().await;
            (
                cfg.limits.max_sub_id_len,
                cfg.nip_enabled(45),
                cfg.relay.require_auth,
                cfg.limits.max_filters,
                cfg.limits.max_count,
                cfg.nip_enabled(50),
            )
        };
        if sub_id.len() > max_sub_id_len {
            self.reject_count(sub_id, "invalid: subscription id too long");
            return;
        }
        // NIP-45: refusals must be answered with a CLOSED message.
        if !nip45 {
            self.reject_count(sub_id, "error: counting is not enabled on this relay");
            return;
        }
        if require_auth && !self.is_authed() {
            self.reject_count(sub_id, "auth-required: please authenticate before counting");
            return;
        }
        if !self.access_allows_read().await {
            self.reject_count(sub_id, "restricted: you are not allowed to count");
            return;
        }
        // Cap the filter count before parsing any filter: a 1 MiB COUNT
        // frame full of maximum-size filters would otherwise be cloned and
        // parsed before the refusal. Without the cap each filter would also
        // get its own full scan budget (~28k filters × 200k candidate
        // examinations on the shared reader thread).
        if rest.len().saturating_sub(1) > max_filters {
            self.reject_count(sub_id, "invalid: too many filters");
            return;
        }
        let mut filters = Vec::new();
        for f in &rest[1..] {
            let mut f = f.clone();
            if crate::filter::rewrite_inbox_outbox(&mut f).is_err() {
                self.reject_count(sub_id, "invalid: invalid filter");
                return;
            }
            match serde_json::from_value::<Filter>(f) {
                Ok(filter) => filters.push(filter),
                Err(_) => {
                    self.reject_count(sub_id, "invalid: invalid filter");
                    return;
                }
            }
        }
        // NIP-45: COUNT requires at least one filter.
        if filters.is_empty() {
            self.reject_count(sub_id, "invalid: COUNT requires at least one filter");
            return;
        }
        if filters.iter().any(|f| f.too_many_members()) {
            self.reject_count(
                sub_id,
                "invalid: too many ids, authors, kinds or tag values in a filter",
            );
            return;
        }
        if filters.iter().any(|f| f.invalid_tag_values()) {
            self.reject_count(sub_id, "invalid: tag constraint values must be strings");
            return;
        }
        let count_limit = max_count;
        let mut count_filters = filters.clone();
        // NIP-50: when the search capability is disabled, strip `search` like
        // REQ does — otherwise COUNT would filter by terms a REQ would ignore
        // (count/REQ divergence) and drive search walks for a feature the
        // relay claims not to offer.
        if !search_enabled {
            for f in &mut count_filters {
                f.search = None;
            }
        }
        // `count_reported` (not `count_result`): NIP-45 COUNT must apply the
        // connection's visibility rules (NIP-70/59/78/29) and the HLL
        // registers, which need the matching events, not just their count.
        // Both variants share the same reported-`None` failure contract.
        let Some((events, more)) = self
            .relay
            .db
            .count_reported(count_filters, count_limit, unix_now())
            .await
        else {
            // A failed scan must not be reported as zero: the client
            // cannot distinguish an error from an empty match set.
            self.reject_count(sub_id, "error: database unavailable; retry");
            return;
        };
        // NIP-70/59/29: COUNT applies the same visibility rules as REQ, so
        // an unauthenticated peer cannot learn the size of a private group,
        // the existence of gift wraps or the count of protected events.
        let events: Vec<Event> = {
            let has_group_events = events.iter().any(nip29::is_group_event);
            let groups = if has_group_events {
                Some(self.relay.groups.read().await)
            } else {
                None
            };
            events
                .into_iter()
                .filter(|e| {
                    (self.is_authed() || !nip70::is_protected(e))
                        && self.gift_wrap_visible(e)
                        && self.nip78_visible(e)
                        && groups.as_deref().is_none_or(|g| {
                            if self.authed_pubkeys.is_empty() {
                                g.visible_to(e, None)
                            } else {
                                self.authed_pubkeys
                                    .iter()
                                    .any(|pk| g.visible_to(e, Some(pk)))
                            }
                        })
                })
                .collect()
        };
        self.send_control(nip45::count_response(sub_id, &filters, &events, more));
    }

    /// Whether an event withheld from this connection could be served to an
    /// authenticated pubkey (NIP-70 protected, NIP-59 gift-wrap recipient,
    /// NIP-78 owner, NIP-29 privacy-gated group member). Drives the NIP-67
    /// `"auth"` EOSE hint.
    /// Whether this connection may read at all: a denied pubkey is never
    /// served (even when authenticated); `restrict_relay` gates publishing
    /// only, reading stays open to everyone. The list is read fresh on
    /// every message, so changes
    /// made by command events or NIP-86 apply to live connections without
    /// a reconnect.
    pub(crate) async fn access_allows_read(&mut self) -> bool {
        // Lock order: config before access — the same order as the accept
        // path (`config.read` held across `access.read`). Acquiring access
        // first and then awaiting config would set up a lock cycle with an
        // access writer and a config writer (tokio RwLocks are fair).
        let admin = self.relay.config.read().await.relay.pubkey.clone();
        let access = self.relay.access.read().await;
        let verdict = self.read_verdict(&access, &admin);
        // The verdict seeds `access_allowed_cache` (also computed once at
        // connect), so the non-blocking hot path always falls back to a
        // genuinely computed verdict — never to an uninitialized value.
        self.access_allowed_cache = verdict;
        verdict
    }

    /// Non-blocking variant for the hot live-delivery path: recomputes the
    /// verdict from a non-blocking lock read (the steady state), and when
    /// the lists are momentarily contended falls back to the verdict of
    /// the last successful check (stale by at most one write hold). It
    /// never fails open to "allowed".
    pub(crate) fn access_allows_read_sync(&mut self) -> bool {
        let Ok(access) = self.relay.access.try_read() else {
            return self.access_allowed_cache;
        };
        let Ok(cfg) = self.relay.config.try_read() else {
            // The config write lock is held (a SIGHUP reload): keep the
            // previous verdict instead of recomputing without the admin
            // pubkey, which would drop the operator exemption for the
            // duration of the reload.
            return self.access_allowed_cache;
        };
        let verdict = self.read_verdict(&access, &cfg.relay.pubkey);
        self.access_allowed_cache = verdict;
        verdict
    }

    /// The access-list verdict for this connection: the deny list gates
    /// identified pubkeys (publish AND read — "never serve these
    /// pubkeys"), while `restrict_relay` and the allow list gate WRITES
    /// only (the NIP-11 `restricted_writes` semantics): reading stays
    /// open to everyone else, including anonymous connections (they
    /// cannot be identified against the lists). The relay's own pubkey
    /// and the admin pubkey (`relay.pubkey`) are always admitted — the
    /// operator must be able to read command-event replies on restricted
    /// relays.
    fn read_verdict(&self, access: &crate::config::AccessControl, admin: &str) -> bool {
        if self.is_operator_pubkey(admin) {
            return true;
        }
        if self.authed_pubkeys.is_empty() {
            // Anonymous connections cannot be identified against the
            // lists, so the lists cannot apply to them: they always read.
            return true;
        }
        // Deny when ANY authenticated key is blocked (fail closed): the
        // per-event visibility checks union over every authenticated key,
        // so allowing on any-clean-key would serve the banned key's
        // private content (its gift wraps, owned application data and
        // group memberships) to a holder pairing it with a fresh key.
        !self.authed_pubkeys.iter().any(|pk| {
            access
                .blocked_pubkeys
                .iter()
                .any(|(p, _)| p.eq_ignore_ascii_case(pk))
        })
    }

    /// Whether any authenticated pubkey is an operator identity: the
    /// relay's own key or the admin pubkey (`relay.pubkey`).
    fn is_operator_pubkey(&self, admin: &str) -> bool {
        self.authed_pubkeys
            .iter()
            .any(|pk| self.relay.relay_pubkey.as_ref().is_some_and(|r| r == pk) || admin == pk)
    }

    pub(crate) fn auth_hidden_behind(
        &self,
        groups: Option<&nip29::GroupStore>,
        event: &Event,
    ) -> bool {
        // NIP-70: protected events are served to any authenticated client.
        if !self.is_authed() && nip70::is_protected(event) {
            return true;
        }
        // NIP-59 gift wraps are served to the authenticated recipient and
        // NIP-78 application-specific events to the authenticated owner, so
        // both are AUTH-revealable.
        if !self.gift_wrap_visible(event) || !self.nip78_visible(event) {
            return true;
        }
        // NIP-29: content of a `private` group (or `hidden` metadata) is
        // served to authenticated members. Deleted/ghost/unknown groups are
        // not AUTH-revealable — their content stays gone for everyone. The
        // store is absent when the batch holds no group event.
        groups.is_some_and(|groups| groups.privacy_gated(event))
    }

    /// NIP-59 / NIP-17: gift wraps are signed by random keys, so they may
    /// only be served to their recipients, i.e. authenticated users whose
    /// pubkey appears in a `p` tag of the wrap (enforced with NIP-42 auth;
    /// skipped when NIP-42 is disabled).
    pub(crate) fn gift_wrap_visible(&self, event: &Event) -> bool {
        !self.giftwrap_restricted
            || event.kind != crate::nips::nip62::GIFT_WRAP_KIND
            || event.tags.iter().any(|t| {
                t.len() >= 2
                    && t[0] == "p"
                    && self
                        .authed_pubkeys
                        .iter()
                        // Case-insensitive like the vanish purge (which
                        // walks both cases): an uppercase `p` wrap is stored
                        // verbatim and must still reach its recipient.
                        .any(|pk| pk.eq_ignore_ascii_case(&t[1]))
            })
    }
    /// Whether a NIP-78 application-specific event may be served on this
    /// connection: only to the authenticated owner (the event author's
    /// pubkey), when the AUTH gate is on.
    pub(crate) fn nip78_visible(&self, event: &Event) -> bool {
        !self.nip78_restricted
            || !crate::nips::nip78::is_app_specific(event)
            || self.authed_pubkeys.iter().any(|pk| pk == &event.pubkey)
    }
    /// Whether a stored or live event may be served on this connection
    /// (NIP-70 protected, NIP-59 gift-wrap recipient and NIP-29 group
    /// access checks). `groups` is `None` when the batch contains no group
    /// event: the expensive group-store lock is skipped then, and the
    /// NIP-29 check (which can only fail for a group event) does not run.
    pub(crate) fn visible_to(&self, groups: Option<&nip29::GroupStore>, event: &Event) -> bool {
        // NIP-70: protected events are only served to authenticated clients.
        // The `-` tag constrains *publication* (author-only, enforced on the
        // write path); NIP-43's relay-generated membership metadata carries
        // it by spec while remaining readable to authenticated clients.
        if !self.is_authed() && nip70::is_protected(event) {
            return false;
        }
        if !self.gift_wrap_visible(event) {
            return false;
        }
        if !self.nip78_visible(event) {
            return false;
        }
        let Some(groups) = groups else {
            // No group event in the batch means the group check cannot
            // change the outcome; a group event without the store would be
            // a caller bug, so fail closed for it.
            return !nip29::is_group_event(event);
        };
        if self.authed_pubkeys.is_empty() {
            groups.visible_to(event, None)
        } else {
            self.authed_pubkeys
                .iter()
                .any(|pk| groups.visible_to(event, Some(pk)))
        }
    }
    /// Streams live events that match active subscriptions.
    ///
    /// `groups` is only present when the batch contains group events (the
    /// caller skips the lock otherwise); `expiry_enabled` is a per-connection
    /// cache refreshed whenever a message arrives, so the hot live path does
    /// not acquire the shared config lock once per batch per connection.
    #[cfg(test)]
    pub(crate) fn deliver_live(
        &mut self,
        event: &Event,
        event_json: &str,
        groups: Option<&nip29::GroupStore>,
    ) {
        self.deliver_live_at(event, event_json, groups, unix_now());
    }

    /// Delivers a live event using a timestamp shared by its live batch.
    /// Expiration checks only need second precision, so querying the clock
    /// once per batch avoids repeated system calls at high event rates.
    pub(crate) fn deliver_live_at(
        &mut self,
        event: &Event,
        event_json: &str,
        groups: Option<&nip29::GroupStore>,
        now: u64,
    ) {
        // Fast path: most connections have no subscriptions.
        if self.subs.is_empty() {
            return;
        }
        // The access lists gate live delivery too: a denied pubkey stops
        // receiving events immediately — the list is read per event, no
        // reconnect needed. The first denied event closes the starving
        // subscriptions with the same CLOSED the REQ path sends, instead
        // of leaving them silent post-EOSE (a client cannot distinguish a
        // ban from a quiet relay).
        if !self.access_allows_read_sync() {
            self.close_all_subs("restricted: you are not allowed to subscribe");
            return;
        }
        // Enabling `require_auth` mid-session must cut anonymous live
        // streams: REQ/COUNT/NEG-OPEN already refuse them, and a flip that
        // left live flowing would fail open.
        if self.require_auth && !self.is_authed() {
            self.close_all_subs("auth-required: please authenticate before subscribing");
            return;
        }
        // NIP-70/NIP-59/NIP-78/NIP-29: one consolidated visibility check
        // (the group store is absent when the batch has no group events,
        // and the earlier per-rule checks duplicated what `visible_to`
        // already enforces).
        if !self.visible_to(groups, event) {
            return;
        }
        // NIP-40: an event with a passed expiration timestamp is never
        // delivered, for every kind. Ephemeral kinds are only exempt from
        // *storage* (they are never persisted); the expiration tag still
        // means "do not relay after this time", so it applies here too.
        if self.expiry_enabled
            && let Some(exp) = nip40::expiry(event)
            && exp <= now
        {
            return;
        }
        // Build each frame under a borrow of `subs` (no sub-id clone, no
        // second hash lookup) and defer the direct sends until the borrow
        // ends: `send` takes `&mut self`, so it cannot run inside the
        // iteration.
        let mut direct: Vec<(Message, u64)> = Vec::new();
        for (sub_id, (filters, _, sub_json)) in self.subs.iter() {
            // The filter's tag plan is hoisted out of the per-event loop
            // (`matches_with`): the live path matches every event against
            // every subscription, and the plan keeps tag matching
            // O(event tags + filter values) instead of the old
            // values × tags product.
            if !filters.iter().any(|f| f.matches_with(event, f.tag_plan())) {
                continue;
            }
            let mut out = String::with_capacity(event_json.len() + sub_json.len() + 16);
            out.push_str("[\"EVENT\",");
            out.push_str(sub_json);
            out.push(',');
            out.push_str(event_json);
            out.push(']');
            // NIP-01: EOSE is the boundary between a subscription's stored
            // events and its real-time stream. While the subscription's
            // stored response is still pumping, hold the live event in the
            // pending response so it is queued after the EOSE; sending it
            // directly would let it overtake the remaining stored events.
            if let Some(idx) = self.pending_reqs.iter().position(|p| p.sub_id == *sub_id) {
                let size = out.len();
                let cap = self.out_queue_cap();
                let pending = &mut self.pending_reqs[idx];
                // The same byte-cap rule as `drain_pending_live` (including
                // the safety ceiling when `max_out_queue_bytes` is unset):
                // without it a slow reader with no configured cap could pin
                // gigabytes in the per-response backlog.
                let over = pending.live.len() >= super::OUT_QUEUE_LIMIT
                    || pending.live_bytes.saturating_add(size) > cap;
                if over {
                    self.dropped += 1;
                    self.relay.stats.bump(&self.relay.stats.buffers_dropped, 1);
                    self.live_overflowed = true;
                    break;
                } else {
                    pending.live_bytes += size;
                    pending.live.push_back(out);
                }
            } else {
                direct.push((Message::Text(out.into()), super::sub_fingerprint(sub_id)));
            }
        }
        for (msg, tag) in direct {
            if !self.send_tagged(msg, Some(tag)) {
                // A live event dropped at the outgoing cap is not
                // recoverable (ephemeral kinds are not stored anywhere),
                // and the subscription would look healthy while silently
                // missing it: mark the connection so the caller closes it
                // with a CLOSED, exactly like a pending-response overflow.
                self.live_overflowed = true;
                break;
            }
        }
    }
}

/// Attributes the visible scan results to the filters whose quotas they
/// consume: the first filter with remaining quota that matches gets the
/// event (the same rule the scan's search path applies), so a filter that
/// matched many events cannot starve a later filter. Events at the
/// boundary timestamp of a filter whose quota is already exhausted still
/// belong to that filter's page (NIP-01/NIP-67: a page never splits a
/// created_at tie), exactly like the scan's per-filter boundary
/// continuation. Returns the kept events and whether any event was
/// dropped (the caller turns that into the `more` completeness hint).
/// Drains `events`, so the caller can re-run the attribution after
/// dropping a boundary second.
fn attribute_visible_page(
    events: &mut Vec<Event>,
    filters: &[Filter],
    limits: &[usize],
) -> (Vec<Event>, bool) {
    let mut remaining = limits.to_vec();
    let mut boundaries: Vec<Option<u64>> = vec![None; remaining.len()];
    let mut kept = Vec::with_capacity(events.len());
    let mut truncated = false;
    for event in events.drain(..) {
        let mut placed = false;
        for (i, filter) in filters.iter().enumerate() {
            if remaining[i] == 0 {
                continue;
            }
            if filter.matches(&event) {
                remaining[i] -= 1;
                if remaining[i] == 0 {
                    boundaries[i] = Some(event.created_at);
                }
                placed = true;
                break;
            }
        }
        if !placed {
            placed = filters.iter().enumerate().any(|(i, filter)| {
                boundaries[i] == Some(event.created_at) && filter.matches(&event)
            });
        }
        if placed {
            kept.push(event);
        } else {
            truncated = true;
        }
    }
    (kept, truncated)
}

/// The JSON serialization size of a value without allocating the string:
/// the per-subscription filter byte budget only needs the length, and
/// serializing through a counting writer avoids the intermediate `String`.
fn json_len<T: serde::Serialize>(value: &T) -> usize {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(buf.len());
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, value)
        .map(|()| counter.0)
        .unwrap_or_default()
}
