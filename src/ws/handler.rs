//! Protocol message handlers (NIP-01/42/45/67/70/77) and the live
//! delivery path. Every method operates on the [`super::Conn`] state; the
//! connection loop itself lives in `super`.

use axum::extract::ws::Message;
use serde_json::{Value, json};

use crate::event::Event;
use crate::filter::Filter;
use crate::nips::{nip29, nip40, nip42, nip45, nip70};
use crate::util::unix_now;

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
            return self.queue_event_value(event).await;
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

    /// Queues an already-parsed event for batched acceptance.
    pub(crate) async fn queue_event_value(&mut self, event: Event) {
        self.events_received_local += 1;
        // Path-specific write policy (nostrfy): `/inbox` and `/outbox` are
        // restricted endpoints — see `write_policy_reason`.
        if let Some(reason) = self.write_policy_reason(&event).await {
            self.relay.stats.bump(&self.relay.stats.events_rejected, 1);
            self.send_ok(&event.id, false, &reason);
            return;
        }
        // The connection loop queues the batch at the end of its sliding
        // window (and resolves it on a spawned task while reading keeps
        // going); a mid-window synchronous flush here would serialize the
        // connection on every commit.
        self.pending_events.push(event);
    }

    /// The write policy of the endpoint this connection is on:
    /// `/outbox` accepts only events authored by the NIP-42-authenticated
    /// pubkey of this connection (`relay.outbox_write_policy = "any"`) or
    /// only events authored by the relay's own pubkey (`"relay"`); `/inbox`
    /// accepts only events carrying a `p` tag — any recipient
    /// (`relay.inbox_write_policy = "any"`) or the relay itself
    /// (`"relay"`). Every other path is unrestricted.
    pub(crate) async fn write_policy_reason(&self, event: &Event) -> Option<String> {
        // Fast path: the vast majority of connections are on the default
        // path — a cheap string comparison rejects them before any clone
        // (the clones below exist only so the future does not hold `&self`
        // across the config await; the connection task's future must be
        // `Send`).
        if self.path != "/outbox" && self.path != "/inbox" {
            return None;
        }
        let path = self.path.clone();
        let authed = self.authed_pubkeys.clone();
        let relay = self.relay.clone();
        match path.as_str() {
            "/outbox" => {
                let policy = relay
                    .config
                    .read()
                    .await
                    .server
                    .outbox_write_policy
                    .trim()
                    .to_string();
                match policy.as_str() {
                    "relay" => {
                        let Some(relay_pk) = relay.relay_pubkey() else {
                            return Some(
                                "restricted: the relay has no identity key for /outbox writes"
                                    .into(),
                            );
                        };
                        if event.pubkey != relay_pk {
                            return Some(
                                "restricted: /outbox accepts only events authored by the relay"
                                    .into(),
                            );
                        }
                        None
                    }
                    _ => {
                        if !authed.contains(&event.pubkey) {
                            return Some(
                                "restricted: /outbox accepts only your own NIP-42-authenticated events"
                                    .into(),
                            );
                        }
                        None
                    }
                }
            }
            "/inbox" => {
                let policy = relay
                    .config
                    .read()
                    .await
                    .server
                    .inbox_write_policy
                    .trim()
                    .to_string();
                let relay_pk = relay.relay_pubkey();
                match policy.as_str() {
                    "relay" => {
                        let Some(relay_pk) = relay_pk else {
                            return Some(
                                "restricted: the relay has no identity key for /inbox writes"
                                    .into(),
                            );
                        };
                        let addressed_to_relay = event
                            .tags
                            .iter()
                            .any(|t| t.len() >= 2 && t[0] == "p" && t[1] == relay_pk);
                        if !addressed_to_relay {
                            return Some(
                                "restricted: /inbox accepts only events addressed to the relay"
                                    .into(),
                            );
                        }
                    }
                    _ => {
                        if !event.tags.iter().any(|t| t.len() >= 2 && t[0] == "p") {
                            return Some(
                                "restricted: /inbox accepts only events carrying a p tag".into(),
                            );
                        }
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// Queues an EVENT message for batched acceptance (generic path).
    pub(crate) async fn queue_event(&mut self, rest: &[Value]) {
        if rest.is_empty() {
            self.send_notice("error: EVENT requires an event object");
            return;
        }
        let event: Event = match serde_json::from_value(rest[0].clone()) {
            Ok(event) => event,
            Err(_) => {
                self.send_notice("error: invalid event object");
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
                    // stored; the NIP-01 `mute:` prefix acknowledges this.
                    self.send_ok(&id, true, "mute: ephemeral event not stored");
                }
                crate::db::PutOutcome::Duplicate => {
                    self.send_ok(&id, true, "duplicate: event already stored");
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
        if rest.len() < 2 {
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
            self.send_closed(sub_id, "invalid: subscription id must not be empty");
            return;
        }
        if sub_id.len() > max_sub_id_len {
            self.send_closed(sub_id, "invalid: subscription id too long");
            return;
        }

        let mut filters = Vec::new();
        for f in &rest[1..] {
            let mut f = f.clone();
            // nostrfy inbox/outbox keys expand into `#p`/`authors`; an invalid
            // value makes the whole subscription invalid like any other
            // malformed filter field.
            if crate::filter::rewrite_inbox_outbox(&mut f).is_err() {
                self.send_closed(sub_id, "invalid: invalid filter");
                return;
            }
            match serde_json::from_value::<Filter>(f) {
                Ok(filter) => filters.push(filter),
                Err(_) => {
                    self.send_closed(sub_id, "invalid: invalid filter");
                    return;
                }
            }
        }
        if filters.is_empty() {
            self.send_closed(sub_id, "invalid: REQ requires at least one filter");
            return;
        }
        if filters.len() > max_filters {
            self.send_closed(sub_id, "invalid: too many filters");
            return;
        }
        if filters.iter().any(|f| f.too_many_members()) {
            self.send_closed(sub_id, "invalid: too many ids or authors in a filter");
            return;
        }
        if filters.iter().any(|f| f.invalid_tag_values()) {
            self.send_closed(sub_id, "invalid: tag constraint values must be strings");
            return;
        }

        let search_disabled = filters.iter().any(|f| f.has_search()) && !search_enabled;

        if require_auth && !self.is_authed() {
            self.send_closed(
                sub_id,
                "auth-required: please authenticate before subscribing",
            );
            return;
        }
        // The access lists gate reading too: a denied pubkey is never
        // served (even when authenticated), and `restrict_relay` narrows
        // subscriptions to the allow list. Changes made by command events
        // (or NIP-86) apply to this connection immediately — the list is
        // read fresh per message, no reconnect needed.
        if !self.access_allows_read().await {
            self.send_closed(sub_id, "restricted: you are not allowed to subscribe");
            return;
        }
        // NIP-01: re-REQ with an existing id replaces the subscription, so it
        // must not count against the cap — only genuinely new subscriptions
        // are limited.
        if !self.subs.contains_key(sub_id) && self.subs.len() >= max_subscriptions {
            self.send_closed(sub_id, "error: too many subscriptions");
            return;
        }

        let mut stored = filters.clone();
        if search_disabled {
            for f in &mut stored {
                f.search = None;
            }
            self.send_notice("search is not enabled on this relay");
        }

        // Bound the memory held by this connection's subscriptions: each
        // filter is bounded by the message size limit, so without a cap a
        // connection could pin many megabytes of filter data.
        let sub_bytes: usize = stored
            .iter()
            .map(|f| {
                serde_json::to_string(f)
                    .map(|s| s.len())
                    .unwrap_or_default()
            })
            .sum();
        let replacing = self.subs.get(sub_id).map(|(_, bytes, _)| *bytes);
        let next_total = self
            .sub_bytes
            .saturating_sub(replacing.unwrap_or(0))
            .saturating_add(sub_bytes);
        if next_total > sub_bytes_limit {
            self.send_closed(sub_id, "error: too many subscriptions");
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

        let now = unix_now();
        // The scan over-fetches each filter's limit (hidden-event slack) so
        // that events withheld by the visibility rules below do not consume
        // the limit slots; the visible results are then truncated back to
        // the requested per-filter limits (their sum, since the scan unions
        // the filters).
        let original_total: usize = stored
            .iter()
            .map(|f| f.limit.unwrap_or(max_limit).min(max_limit))
            .sum();
        let (events, more) = self.relay.db.query_req(stored, max_limit, now).await;
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
            let groups = self.relay.groups.read().await;
            for event in events {
                if !self.visible_to(&groups, &event) {
                    if hint_eligible && self.auth_hidden_behind(&groups, &event) {
                        auth_hidden = true;
                    }
                    continue;
                }
                to_send.push(event);
            }
        }
        let truncated = to_send.len() > original_total;
        to_send.truncate(original_total);
        // The response is queued for the pump instead of being pushed into
        // the outgoing queue all at once: the connection loop moves it into
        // the capped queue in bounded chunks as the socket drains, so a
        // slow reader can never pin more than the byte cap in the queue —
        // or more than `limits.max_req_response_bytes` per response.
        self.enqueue_pending_req(crate::ws::PendingReq {
            sub_id: sub_id.to_string(),
            events: to_send.into(),
            eose_hint,
            truncated_or_more: truncated || more,
            auth_hint: auth_hidden,
            sent_bytes: 0,
        });
    }

    pub(crate) fn handle_close(&mut self, rest: &[Value]) {
        let Some(Some(sub_id)) = rest.first().map(|v| v.as_str()) else {
            self.send_notice("error: CLOSE requires a subscription id");
            return;
        };
        // `remove_subscription` re-syncs the live index.
        self.remove_subscription(sub_id);
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
        let mut index = self
            .relay
            .sub_index
            .write()
            .unwrap_or_else(|p| p.into_inner());
        index.unregister(self.conn_id);
        index.register(self.conn_id, &components);
    }

    /// Releases a subscription (and any negentropy state held under the
    /// same id): its filter bytes, its live slot and its negentropy items.
    pub(crate) fn remove_subscription(&mut self, sub_id: &str) {
        if let Some((_, bytes, _)) = self.subs.remove(sub_id) {
            self.sub_bytes = self.sub_bytes.saturating_sub(bytes);
            self.relay
                .stats
                .subscriptions_active
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            self.subscriptions_held
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }
        // NIP-77: a CLOSE on a subscription id also ends any negentropy
        // state held under the same id (even when no REQ subscription with
        // that id exists — a NEG-OPEN-only id must still be closable),
        // releasing its items from the connection's memory accounting and
        // its subscription slot.
        if let Some(state) = self.neg.remove(sub_id) {
            self.neg_total = self.neg_total.saturating_sub(state.items.len());
            self.release_neg_stats_subscription();
        }
        self.sync_live_index();
    }

    pub(crate) async fn handle_auth(&mut self, rest: &[Value]) {
        if !self.relay.config.read().await.nip_enabled(42) {
            self.send_notice("error: authentication is not enabled on this relay");
            return;
        }
        if rest.is_empty() {
            self.send_notice("error: AUTH requires an event object");
            return;
        }
        let event: Event = match serde_json::from_value(rest[0].clone()) {
            Ok(event) => event,
            Err(_) => {
                self.send_notice("error: invalid auth event");
                return;
            }
        };
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
            // Bound the list: repeated AUTHs with the same key are
            // deduplicated and the number of distinct keys is capped so a
            // connection cannot grow this vector (or the per-event
            // visibility scan over it) without limit. At the cap the
            // oldest key is evicted (FIFO) so every accepted AUTH stays
            // recorded and the OK reply stays truthful.
            if !self.authed_pubkeys.iter().any(|pk| pk == &event.pubkey) {
                if self.authed_pubkeys.len() >= 64 {
                    self.authed_pubkeys.remove(0);
                }
                self.authed_pubkeys.push(event.pubkey.clone());
            }
        }
        // The AUTH result is completion-critical: a dropped OK leaves the
        // client unsure whether its authentication was accepted.
        self.send_control(nip42::ok(&id, accepted));
    }

    pub(crate) async fn handle_count(&mut self, rest: &[Value]) {
        if rest.len() < 2 {
            self.send_notice("error: COUNT requires a subscription id and filters");
            return;
        }
        let Some(sub_id) = rest[0].as_str() else {
            self.send_notice("error: subscription id must be a string");
            return;
        };
        if sub_id.is_empty() {
            self.send_closed(sub_id, "invalid: subscription id must not be empty");
            return;
        }
        let max_sub_id_len = self.relay.config.read().await.limits.max_sub_id_len;
        if sub_id.len() > max_sub_id_len {
            self.send_closed(sub_id, "invalid: subscription id too long");
            return;
        }
        // NIP-45: refusals must be answered with a CLOSED message.
        if !self.relay.config.read().await.nip_enabled(45) {
            self.send_closed(sub_id, "error: counting is not enabled on this relay");
            return;
        }
        if self.relay.config.read().await.relay.require_auth && !self.is_authed() {
            self.send_closed(sub_id, "auth-required: please authenticate before counting");
            return;
        }
        if !self.access_allows_read().await {
            self.send_closed(sub_id, "restricted: you are not allowed to count");
            return;
        }
        let mut filters = Vec::new();
        for f in &rest[1..] {
            let mut f = f.clone();
            if crate::filter::rewrite_inbox_outbox(&mut f).is_err() {
                self.send_closed(sub_id, "invalid: invalid filter");
                return;
            }
            match serde_json::from_value::<Filter>(f) {
                Ok(filter) => filters.push(filter),
                Err(_) => {
                    self.send_closed(sub_id, "invalid: invalid filter");
                    return;
                }
            }
        }
        // NIP-45: COUNT requires at least one filter.
        if filters.is_empty() {
            self.send_closed(sub_id, "invalid: COUNT requires at least one filter");
            return;
        }
        if filters.iter().any(|f| f.too_many_members()) {
            self.send_closed(sub_id, "invalid: too many ids or authors in a filter");
            return;
        }
        if filters.iter().any(|f| f.invalid_tag_values()) {
            self.send_closed(sub_id, "invalid: tag constraint values must be strings");
            return;
        }
        // Cap the filter count like REQ: without it each filter would get its
        // own full scan budget, so a single 1 MiB COUNT frame could drive
        // ~28k filters × 200k candidate examinations on the shared reader
        // thread (~1400x the full-scan budget).
        if filters.len() > self.relay.config.read().await.limits.max_filters {
            self.send_closed(sub_id, "invalid: too many filters");
            return;
        }
        let count_limit = self.relay.config.read().await.limits.max_count;
        let mut count_filters = filters.clone();
        // NIP-50: when the search capability is disabled, strip `search` like
        // REQ does — otherwise COUNT would filter by terms a REQ would ignore
        // (count/REQ divergence) and drive search walks for a feature the
        // relay claims not to offer.
        if !self.relay.config.read().await.nip_enabled(50) {
            for f in &mut count_filters {
                f.search = None;
            }
        }
        let (events, more) = self
            .relay
            .db
            .count(count_filters, count_limit, unix_now())
            .await;
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
    /// served (even when authenticated), and with `restrict_relay` only
    /// allow-listed pubkeys are served — anonymous connections are then
    /// refused too. The list is read fresh on every message, so changes
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
        self.authed_pubkeys
            .iter()
            .any(|pk| !access.blocked_pubkeys.iter().any(|(p, _)| p == pk))
    }

    /// Whether any authenticated pubkey is an operator identity: the
    /// relay's own key or the admin pubkey (`relay.pubkey`).
    fn is_operator_pubkey(&self, admin: &str) -> bool {
        self.authed_pubkeys.iter().any(|pk| {
            self.relay.relay_pubkey.as_ref().is_some_and(|r| r == pk)
                || admin.eq_ignore_ascii_case(pk)
        })
    }

    pub(crate) fn auth_hidden_behind(&self, groups: &nip29::GroupStore, event: &Event) -> bool {
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
        // not AUTH-revealable — their content stays gone for everyone.
        groups.privacy_gated(event)
    }

    /// NIP-59 / NIP-17: gift wraps are signed by random keys, so they may
    /// only be served to their recipients, i.e. authenticated users whose
    /// pubkey appears in a `p` tag of the wrap (enforced with NIP-42 auth;
    /// skipped when NIP-42 is disabled).
    pub(crate) fn gift_wrap_visible(&self, event: &Event) -> bool {
        !self.giftwrap_restricted
            || event.kind != crate::nips::nip62::GIFT_WRAP_KIND
            || event
                .tags
                .iter()
                .any(|t| t.len() >= 2 && t[0] == "p" && self.authed_pubkeys.contains(&t[1]))
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
    /// access checks).
    pub(crate) fn visible_to(&self, groups: &nip29::GroupStore, event: &Event) -> bool {
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
    pub(crate) fn deliver_live(
        &mut self,
        event: &Event,
        event_json: &str,
        groups: Option<&nip29::GroupStore>,
    ) {
        // Fast path: most connections have no subscriptions.
        if self.subs.is_empty() {
            return;
        }
        // The access lists gate live delivery too: a pubkey that was
        // denied (or a connection that `restrict_relay` no longer admits)
        // stops receiving events immediately — the list is read per event,
        // no reconnect needed.
        if !self.access_allows_read_sync() {
            return;
        }
        // NIP-70: protected events are only delivered to authenticated
        // clients.
        if !self.is_authed() && nip70::is_protected(event) {
            return;
        }
        // NIP-59: gift wraps are only delivered to their recipients, even
        // when the batch contains no group events (visible_to is only
        // reached when the groups lock was taken).
        if !self.gift_wrap_visible(event) {
            return;
        }
        // NIP-78: application-specific events are only delivered to the
        // authenticated owner.
        if !self.nip78_visible(event) {
            return;
        }
        if let Some(groups) = groups
            && !self.visible_to(groups, event)
        {
            return;
        }
        // NIP-40: expired stored events are not delivered live; ephemeral
        // kinds are exempt ("an expiration timestamp does not affect
        // storage of ephemeral events").
        if self.expiry_enabled
            && !(20000..30000).contains(&event.kind)
            && let Some(exp) = nip40::expiry(event)
            && exp < unix_now()
        {
            return;
        }
        let matching: Vec<String> = self
            .subs
            .iter()
            .filter(|(_, (filters, _, _))| filters.iter().any(|f| f.matches(event)))
            .map(|(sub_id, _)| sub_id.clone())
            .collect();
        if matching.is_empty() {
            return;
        }
        // The event JSON is shared (encoded once by the live bus) and the
        // sub id JSON is cached per subscription: the wrap below only
        // concatenates strings.
        for sub_id in matching {
            let Some((_, _, sub_json)) = self.subs.get(&sub_id) else {
                continue;
            };
            let mut out = String::with_capacity(event_json.len() + sub_json.len() + 16);
            out.push_str("[\"EVENT\",");
            out.push_str(sub_json);
            out.push(',');
            out.push_str(event_json);
            out.push(']');
            self.send(Message::Text(std::mem::take(&mut out).into()));
        }
    }
}
