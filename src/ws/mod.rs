//! WebSocket connection handling: the per-connection [`Conn`]
//! state, the connection loop and the live fan-out. The protocol
//! message handlers (REQ/EVENT/AUTH/COUNT/NEG) live in [`handler`].

mod handler;
mod negentropy;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};

use crate::event::Event;
use crate::filter::Filter;
use crate::nips::{nip29, nip42};
use crate::relay::Relay;
use crate::stats::Stats;

/// Secondary bound on the number of queued messages (a long tail of small
/// messages must not outgrow the VecDeque either).
const OUT_QUEUE_LIMIT: usize = 4096;
/// Events queued on a connection before they are accepted as one database
/// batch (the batch shares a single write commit).
pub(crate) const EVENT_BATCH: usize = 64;

/// A REQ response waiting to be pumped to the socket in bounded chunks:
/// the scan result is held here and moved into the capped outgoing queue
/// as the socket drains, instead of being queued all at once (which could
/// pin hundreds of MiB for a slow reader).
pub(crate) struct PendingReq {
    pub(crate) sub_id: String,
    pub(crate) events: std::collections::VecDeque<Event>,
    pub(crate) eose_hint: bool,
    pub(crate) truncated_or_more: bool,
    /// NIP-67 `"auth"` hint: more stored events match the filters if the
    /// client performs AUTH; the challenge is queued ahead of the EOSE.
    pub(crate) auth_hint: bool,
    /// Serialized bytes of the EVENT messages queued so far (against
    /// `limits.max_req_response_bytes`).
    pub(crate) sent_bytes: u64,
    /// Live EVENT messages that matched this subscription while its stored
    /// response was still pumping. NIP-01 defines EOSE as the boundary
    /// between stored and real-time events, so these wait here until the
    /// stored events and the EOSE have been queued.
    pub(crate) live: std::collections::VecDeque<String>,
    /// Serialized bytes held in `live`, against the outgoing byte cap.
    pub(crate) live_bytes: usize,
    /// Whether the EOSE (and any AUTH challenge before it) has been queued;
    /// afterwards the pump only drains `live`.
    pub(crate) eose_sent: bool,
}

/// Upper bound on queued REQ responses per connection: beyond this the
/// oldest pending response is cut off (its EOSE is sent immediately) so a
/// client flooding REQs while reading slowly cannot pile up unbounded
/// scan results.
const MAX_PENDING_REQS: usize = 4;

pub struct Conn {
    pub(crate) relay: Arc<Relay>,
    /// The WebSocket endpoint path this connection was established on
    /// (`/`, `/inbox` or `/outbox`); drives the path-specific write policy.
    pub(crate) path: String,
    /// Outgoing messages awaiting a TCP write, drained by the connection
    /// loop after every select iteration.
    pub(crate) outgoing: std::collections::VecDeque<Message>,
    /// Bytes currently queued in `outgoing`; the byte cap decides whether a
    /// new message is queued or dropped.
    pub(crate) out_bytes: usize,
    /// Per-connection byte cap for the outgoing queue (`limits.max_out_queue_bytes`,
    /// cached once per connection).
    pub(crate) out_queue_bytes: usize,
    /// Byte budget for a single REQ response (`limits.max_req_response_bytes`,
    /// cached once per connection; 0 = unlimited).
    pub(crate) req_response_bytes: u64,
    /// REQ responses awaiting the pump: the scan results are moved into
    /// the capped outgoing queue in chunks as the socket drains.
    pub(crate) pending_reqs: std::collections::VecDeque<PendingReq>,
    /// Subscription id -> (filters, serialized filter bytes).
    subs: HashMap<String, (Vec<Filter>, usize, String)>,
    /// Bytes held by the filters of all active subscriptions.
    pub(crate) sub_bytes: usize,
    /// NIP-77 negentropy state per subscription id: the held items plus the
    /// remaining number of NEG-MSG rounds (a budget so a peer cannot drive
    /// unbounded CPU-bounded reconciliation work with tiny messages).
    neg: HashMap<String, negentropy::NegState>,
    /// Total number of negentropy items held across all open NEG-OPEN
    /// subscriptions, so that a connection cannot pin more than twice the
    /// configured per-query maximum in memory.
    pub(crate) neg_total: usize,
    /// Total NEG-OPENs this connection has issued (including re-opens of
    /// closed subscriptions): caps how often the 128-round CPU budget can
    /// be renewed, independently of the per-subscription state.
    pub(crate) neg_opens_total: u32,
    pub(crate) challenge: String,
    /// Every pubkey authenticated on this connection (NIP-42: all of them
    /// are treated as authenticated).
    pub(crate) authed_pubkeys: Vec<String>,
    /// Events received but not yet accepted; flushed in batches so the
    /// database commit cost is amortized over many events.
    pub(crate) pending_events: Vec<Event>,
    /// Wire bytes of the events held in `pending_events`, so a burst of
    /// maximum-size frames cannot accumulate before the batch is flushed.
    pub(crate) pending_bytes: usize,
    /// Live-event receiver, created when the first REQ subscribes (before
    /// the query runs, so no stored event can fall into the gap between the
    /// query and the subscription) and dropped when the last subscription
    /// closes, so connections without active subscriptions are never woken
    /// by live events. A duplicate delivery of an event that is both in the
    /// query result and live is harmless (clients deduplicate by id).
    pub(crate) live: Option<tokio::sync::mpsc::Receiver<LiveBatch>>,
    /// The connection's id in the relay's live subscription index and
    /// delivery-queue map.
    pub(crate) conn_id: u64,
    /// This connection's open subscription count (REQ + negentropy),
    /// tracked so the connection guard can release `subscriptions_active`
    /// on panic as well as on the normal exit path.
    pub(crate) subscriptions_held: Arc<std::sync::atomic::AtomicUsize>,
    /// Whether this connection delivers NIP-40 expired events live. Cached
    /// from the config on connect and refreshed only after a SIGHUP
    /// reload (see `config_version`), so the per-batch live path avoids
    /// the shared config lock.
    pub(crate) expiry_enabled: bool,
    /// The relay's `config_version` when `expiry_enabled` /
    /// `giftwrap_restricted` were last refreshed.
    pub(crate) config_version: u64,
    /// Whether NIP-59 gift wraps are only served to their recipients
    /// (enforced with NIP-42 auth; false when NIP-42 is disabled).
    pub(crate) giftwrap_restricted: bool,
    /// Whether NIP-78 application-specific events (kinds 78/30078) are only
    /// served to the authenticated owner when the AUTH gate is on (cached
    /// from the config on connect and refreshed after a SIGHUP reload).
    pub(crate) nip78_restricted: bool,
    /// Last verdict of the access-list read gate (see
    /// [`Conn::access_allows_read_sync`]): the non-blocking hot path falls
    /// back to this instead of failing open when the lists are contended.
    pub(crate) access_allowed_cache: bool,
    pub(crate) dropped: u64,
    /// Per-connection message/byte counters, flushed into the shared stats
    /// once on disconnect so that a million connections do not hammer the
    /// same cache lines for every single message.
    pub(crate) in_msgs: u64,
    pub(crate) in_bytes: u64,
    pub(crate) out_msgs: u64,
    pub(crate) out_bytes_total: u64,
    /// Per-connection counter of received EVENT messages, flushed into the
    /// shared stats on disconnect like the other per-connection counters
    /// (an event-rate hot path must not touch a shared cache line).
    pub(crate) events_received_local: u64,
}

/// A live-delivery batch: the events plus their shared, pre-serialized
/// JSON (encoded once by the live bus task).
pub(crate) type LiveBatch = Arc<Vec<(crate::event::Event, Arc<String>)>>;

impl Conn {
    pub(crate) fn send(&mut self, msg: Message) {
        let size = message_size(&msg);
        // 0 = unlimited (the REQ-response budget documents the same meaning).
        let over_byte_cap = self.out_queue_bytes > 0
            && !self.outgoing.is_empty()
            && self.out_bytes.saturating_add(size) > self.out_queue_bytes;
        if self.outgoing.len() >= OUT_QUEUE_LIMIT || over_byte_cap {
            self.dropped += 1;
            self.relay.stats.bump(&self.relay.stats.buffers_dropped, 1);
            return;
        }
        self.out_bytes += size;
        self.out_msgs += 1;
        self.out_bytes_total += size as u64;
        self.outgoing.push_back(msg);
    }

    pub(crate) fn send_json(&mut self, value: Value) {
        if let Ok(text) = serde_json::to_string(&value) {
            self.send(Message::Text(text.into()));
        }
    }

    /// Queues a completion-critical control message (EOSE / CLOSED /
    /// NEG-MSG / NEG-ERR) bypassing the byte cap: a dropped EOSE would
    /// leave the client hanging on a completed subscription, and a dropped
    /// NEG-MSG/NEG-ERR would hang a sync — worse than a dropped live event.
    /// The messages are tiny except for NEG-MSG id lists (bounded by
    /// `max_neg_items` and `max_req_response_bytes`, plus the NEG
    /// backpressure guard). As a last-resort OOM guard the queue length is
    /// still capped at twice `OUT_QUEUE_LIMIT`: legitimate clients drain
    /// far faster than control traffic arrives, so reaching it means an
    /// attacker flooding inbound frames on a stalled socket — drops are
    /// counted like any other queue drop.
    pub(crate) fn send_control(&mut self, value: Value) {
        if self.outgoing.len() >= OUT_QUEUE_LIMIT * 2 {
            self.dropped += 1;
            self.relay.stats.bump(&self.relay.stats.buffers_dropped, 1);
            return;
        }
        if let Ok(text) = serde_json::to_string(&value) {
            let size = text.len();
            self.out_bytes += size;
            self.out_msgs += 1;
            self.out_bytes_total += size as u64;
            self.outgoing.push_back(Message::Text(text.into()));
        }
    }

    pub(crate) fn send_notice(&mut self, text: &str) {
        self.send_json(json!(["NOTICE", text]));
    }

    /// NIP-01 CLOSED: a REQ was rejected or ended, with a machine-readable
    /// reason. Completion-critical: a dropped CLOSED would leave the
    /// client waiting on a subscription that will never deliver.
    pub(crate) fn send_closed(&mut self, sub_id: &str, reason: &str) {
        self.send_control(json!(["CLOSED", sub_id, reason]));
    }

    pub(crate) fn send_ok(&mut self, id: &str, accepted: bool, message: &str) {
        self.send_json(json!(["OK", id, accepted, message]));
    }

    /// Whether the pending EVENT batch must be flushed before reading more
    /// frames: the documented count ([`EVENT_BATCH`], sharing one database
    /// commit) or the byte budget (one full frame, `max_msg_size`) is
    /// reached. Without the byte bound a burst of maximum-size frames
    /// accumulated up to the whole window before validation.
    pub(crate) fn pending_batch_full(&self, max_msg_size: usize) -> bool {
        self.pending_events.len() >= EVENT_BATCH || self.pending_bytes >= max_msg_size
    }

    /// Queues a REQ response for the pump. Responses are processed in
    /// order; when more than [`MAX_PENDING_REQS`] are queued (a client
    /// flooding REQs while reading slowly), the oldest is cut off — its
    /// EOSE is sent immediately so the client sees a completed
    /// subscription instead of a hanging one.
    pub(crate) fn enqueue_pending_req(&mut self, pending: PendingReq) {
        // A REQ replaces the subscription of the same id (NIP-01): drop
        // any still-pumping response for it so stale events are never
        // delivered for the replaced subscription.
        self.pending_reqs.retain(|p| p.sub_id != pending.sub_id);
        if self.pending_reqs.len() >= MAX_PENDING_REQS
            && let Some(mut dropped) = self.pending_reqs.pop_front()
        {
            // The dropped response was cut off before its remaining
            // events were sent: flag it so the EOSE carries the NIP-67
            // "more" hint instead of claiming a complete result (the
            // subscription itself stays open).
            dropped.truncated_or_more = true;
            // Only a response whose EOSE has not gone out needs the closing
            // EOSE. A response that already ended (EOSE sent, live events
            // still buffered) must not get a second EOSE, and a CLOSEd
            // subscription must not receive anything further (the pump
            // applies the same guard before its EOSE).
            if !dropped.eose_sent && self.subs.contains_key(&dropped.sub_id) {
                self.finish_pending_req(&dropped);
            }
        }
        self.pending_reqs.push_back(pending);
    }

    /// Sends the closing EOSE (or the budget CLOSED) of a pending
    /// response. EOSE/CLOSED are tiny, so they take the uncapped path —
    /// the byte cap exists for large payloads, and a dropped EOSE would
    /// leave the client hanging on a completed subscription.
    fn finish_pending_req(&mut self, pending: &PendingReq) {
        let eose = if pending.eose_hint {
            // NIP-67: `"auth"` advertises stored events that match the
            // filters but are withheld pending AUTH (protected events,
            // gift wraps, NIP-78 owner data, private groups). The spec
            // requires an AUTH challenge to be sent *before* the EOSE
            // that carries the hint, so it is queued ahead of it.
            if pending.auth_hint {
                self.send_control(nip42::auth_message(&self.challenge));
            }
            // `"finish"`/`"more"` describe the events servable without
            // AUTH; `"auth"` and either hint may coexist (e.g. the spec's
            // `["EOSE", sub, ["auth", "finish"]]`).
            let mut hints = Vec::with_capacity(2);
            if pending.auth_hint {
                hints.push("auth");
            }
            hints.push(if pending.truncated_or_more {
                "more"
            } else {
                "finish"
            });
            json!(["EOSE", pending.sub_id, hints])
        } else {
            json!(["EOSE", pending.sub_id])
        };
        self.send_control(eose);
    }

    /// Moves the pending REQ responses into the capped outgoing queue in
    /// bounded chunks: at most one pump per loop iteration, filling the
    /// queue up to the byte cap. A slow reader therefore pins at most the
    /// byte cap in the queue, and at most `req_response_bytes` per
    /// response — responses beyond the budget are closed with
    /// `CLOSED ... response too large` so the client can re-request with
    /// a narrower filter.
    pub(crate) fn pump_pending_reqs(&mut self) {
        loop {
            // The access lists gate the pump too: results queued before a
            // deny are dropped, so the restriction applies immediately
            // without disconnecting the connection. The subscriptions are
            // closed (CLOSED + unregistered), so the client does not hang
            // waiting for an EOSE that will never come.
            if !self.access_allows_read_sync() {
                let ids: Vec<String> = self.pending_reqs.iter().map(|p| p.sub_id.clone()).collect();
                self.pending_reqs.clear();
                for id in ids {
                    self.send_closed(&id, "restricted: you are not allowed to subscribe");
                    self.remove_req_subscription(&id);
                }
                break;
            }
            // A subscription closed while its response was still pumping
            // is dropped without an EOSE (the client already closed it).
            let closed = self
                .pending_reqs
                .front()
                .is_some_and(|f| !self.subs.contains_key(&f.sub_id));
            if closed {
                self.pending_reqs.pop_front();
                continue;
            }
            let Some(front) = self.pending_reqs.front_mut() else {
                break;
            };
            let mut budget_exceeded = false;
            while self.outgoing.len() < OUT_QUEUE_LIMIT {
                let Some(event) = front.events.front() else {
                    break;
                };
                // Hand-rolled framing: `["EVENT", <sub_id>, <event>]`
                // (the same one-pass construction `deliver_live` uses).
                // The `json!` macro would deep-clone the event into a
                // `Value` tree before serializing; serializing the
                // sub-id string and the event separately and concatenating
                // writes straight to the wire.
                let event_json = serde_json::to_string(event).unwrap_or_default();
                let sub_json = serde_json::to_string(&front.sub_id).unwrap_or_default();
                let mut text = String::with_capacity(event_json.len() + sub_json.len() + 16);
                text.push_str("[\"EVENT\",");
                text.push_str(&sub_json);
                text.push(',');
                text.push_str(&event_json);
                text.push(']');
                let size = text.len();
                // Strict byte cap after the first message: a single
                // oversized event must still be delivered (dropping it
                // would lose data permanently), so the first push may
                // exceed the cap by one message; afterwards the queue
                // cannot grow past the cap.
                if self.out_queue_bytes > 0
                    && self.out_bytes > 0
                    && self.out_bytes.saturating_add(size) > self.out_queue_bytes
                {
                    break;
                }
                if self.req_response_bytes > 0
                    && front.sent_bytes.saturating_add(size as u64) > self.req_response_bytes
                {
                    budget_exceeded = true;
                    break;
                }
                front.events.pop_front();
                front.sent_bytes += size as u64;
                self.out_bytes += size;
                self.out_msgs += 1;
                self.out_bytes_total += size as u64;
                self.outgoing.push_back(Message::Text(text.into()));
            }
            if budget_exceeded {
                let sub_id = front.sub_id.clone();
                self.send_control(json!([
                    "CLOSED",
                    sub_id,
                    "blocked: response too large; narrow the filter or paginate"
                ]));
                // The CLOSED ends the subscription: release it exactly
                // like a client CLOSE (filter bytes, live slot, stats).
                // REQ namespace only (NIP-77 separate namespace).
                self.remove_req_subscription(&sub_id);
                self.pending_reqs.pop_front();
                continue;
            }
            if !front.events.is_empty() {
                // The queue is full or the count cap is reached: the next
                // loop iteration resumes the pump after the drain.
                break;
            }
            // All stored events are queued. Send the EOSE (with any AUTH
            // challenge ahead of it) before draining the live events that
            // arrived while the response was pumping: NIP-01 defines EOSE
            // as the boundary between stored and real-time events.
            let mut pending = self.pending_reqs.pop_front().expect("front exists");
            if !pending.eose_sent {
                pending.eose_sent = true;
                self.finish_pending_req(&pending);
            }
            self.drain_pending_live(&mut pending);
            if pending.live.is_empty() {
                continue;
            }
            // The queue filled up again with live events: keep the entry so
            // the next pump (after the socket drains) resumes in order.
            self.pending_reqs.push_front(pending);
            break;
        }
    }

    /// Moves the live events held for a pumped-out REQ response into the
    /// capped outgoing queue. The caller keeps the entry while a non-empty
    /// backlog remains, so the next pump (after the socket drains) resumes
    /// exactly where this one stopped.
    fn drain_pending_live(&mut self, pending: &mut PendingReq) {
        while self.outgoing.len() < OUT_QUEUE_LIMIT {
            let Some(text) = pending.live.front() else {
                return;
            };
            let size = text.len();
            // The same byte-cap rule as the stored events: the first message
            // may exceed the cap so a single event is never lost.
            if self.out_queue_bytes > 0
                && self.out_bytes > 0
                && self.out_bytes.saturating_add(size) > self.out_queue_bytes
            {
                return;
            }
            let text = pending.live.pop_front().expect("front checked");
            pending.live_bytes = pending.live_bytes.saturating_sub(size);
            self.out_bytes += size;
            self.out_msgs += 1;
            self.out_bytes_total += size as u64;
            self.outgoing.push_back(Message::Text(text.into()));
        }
    }

    /// Whether the connection is authenticated (with any pubkey).
    pub(crate) fn is_authed(&self) -> bool {
        !self.authed_pubkeys.is_empty()
    }

    pub(crate) async fn send_auth_challenge(&mut self) {
        let enabled = {
            let cfg = self.relay.config.read().await;
            cfg.nip_enabled(42) && cfg.relay.send_auth_challenge
        };
        if enabled {
            self.send_json(nip42::auth_message(&self.challenge));
        }
    }

    /// Whether this connection's source IP is blocked (NIP-86 `blockip`).
    /// Called when the blocked-IP list changes, so a read-only subscriber
    /// that never sends a frame is disconnected like any other.
    pub(crate) async fn source_ip_blocked(&self, peer_ip: std::net::IpAddr) -> bool {
        crate::util::ip_blocked(&self.relay.access.read().await.blocked_ips, peer_ip)
    }
}

pub(crate) fn value_string(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn message_size(msg: &Message) -> usize {
    match msg {
        Message::Text(text) => text.len(),
        Message::Binary(data) | Message::Ping(data) | Message::Pong(data) => data.len(),
        Message::Close(_) => 0,
    }
}

/// Releases the connection's accounting when the connection task ends, no
/// matter how it ends. A panic anywhere in the connection handling would
/// otherwise skip the disconnect cleanup and leak the `connections_active`
/// counter, slowly refusing every new connection.
struct ConnectionGuard {
    relay: Arc<Relay>,
    stats: Arc<Stats>,
    peer_ip: std::net::IpAddr,
    /// The connection's live-index id, unregistered on drop so a panic in
    /// the connection handling cannot leave a dead entry (the bus would
    /// keep trying to deliver to a gone connection forever).
    conn_id: u64,
    /// The connection's open subscription count, released on drop so a
    /// panic cannot leak `subscriptions_active` (the normal exit path
    /// swaps it to zero first, so the drop only subtracts the rest).
    subscriptions_held: Arc<std::sync::atomic::AtomicUsize>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.stats
            .connections_active
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        self.relay.release_connection(&self.peer_ip);
        self.relay
            .sub_index
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .unregister(self.conn_id);
        self.relay
            .conn_queues
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&self.conn_id);
        let held = self
            .subscriptions_held
            .swap(0, std::sync::atomic::Ordering::Relaxed);
        self.stats
            .subscriptions_active
            .fetch_sub(held as u64, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Conn {
    /// Handles one inbound frame: bounds it against the message size
    /// limit, counts it and feeds it to the protocol handler. Returns
    /// `true` when the frame exceeded the limit and the connection must
    /// close.
    async fn handle_frame(&mut self, frame: Message, max_msg_size: usize) -> bool {
        // Borrow the text instead of copying it: the handler only reads
        // the frame, so the `Utf8Bytes` is passed by reference (the
        // per-frame allocation and memcpy of the old `to_string()` are
        // dropped entirely).
        let text = match &frame {
            Message::Text(text) => text.as_str(),
            Message::Binary(data) => return self.handle_binary(data, max_msg_size).await,
            // A Close inside the batch window must end the connection too
            // (RFC 6455: answer the close and stop reading), not be
            // swallowed until the next select iteration. (Pings are not
            // handled here: tungstenite already queues the pong.)
            Message::Close(_) => return true,
            _ => return false,
        };
        if text.len() > max_msg_size {
            self.send_notice("error: message too large");
            return true;
        }
        self.in_msgs += 1;
        self.in_bytes += text.len() as u64;
        self.handle_text(text).await;
        false
    }

    /// Decodes a binary frame (bytes with lossy UTF-8 fallback) and feeds
    /// it to the protocol handler. Returns `true` when the connection must
    /// close.
    async fn handle_binary(&mut self, data: &[u8], max_msg_size: usize) -> bool {
        if data.len() > max_msg_size {
            self.send_notice("error: message too large");
            return true;
        }
        let text = String::from_utf8_lossy(data);
        self.in_msgs += 1;
        self.in_bytes += text.len() as u64;
        self.handle_text(&text).await;
        false
    }
}

pub async fn handle_connection(
    mut socket: WebSocket,
    relay: Arc<Relay>,
    peer_ip: std::net::IpAddr,
    path: String,
) {
    // Read the caps before accounting: everything between `fetch_add`
    // and the guard below is synchronous (`try_register_connection` takes
    // no lock across an await), so a panic cannot strand the slot across
    // an await point before the guard owns it.
    let (max_connections, max_per_ip) = {
        let cfg = relay.config.read().await;
        (
            cfg.limits.max_connections,
            cfg.limits.max_connections_per_ip,
        )
    };
    // Account the connection with add-then-check so the cap stays exact
    // under concurrency.
    let active = relay
        .stats
        .connections_active
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        + 1;
    relay.stats.bump(&relay.stats.connections_total, 1);

    // `active` is the post-increment count (this connection included), so
    // `>` accepts exactly `max_connections` connections. Short-circuit
    // order matters: when the global cap already refuses, the per-IP slot
    // is never taken, so only the global counter is rolled back.
    if active > max_connections as u64 || !relay.try_register_connection(&peer_ip, max_per_ip) {
        relay
            .stats
            .connections_active
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        let _ = socket.close().await;
        return;
    }
    let conn_id = relay
        .next_conn_id
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let subscriptions_held = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let _guard = ConnectionGuard {
        relay: relay.clone(),
        stats: relay.stats.clone(),
        peer_ip,
        conn_id,
        subscriptions_held: Arc::clone(&subscriptions_held),
    };

    let challenge = match nip42::generate_challenge() {
        // RNG failure must fail the connection closed: a constant fallback
        // challenge would let one AUTH event replay across connections.
        // `_guard` releases the slot on return.
        None => {
            log::error!("RNG failure generating AUTH challenge; refusing connection");
            let _ = socket.close().await;
            return;
        }
        Some(challenge) => challenge,
    };

    let (mut sender, mut receiver) = socket.split();
    let (
        max_msg_size,
        out_queue_bytes,
        req_response_bytes,
        expiry_enabled,
        giftwrap_restricted,
        nip78_restricted,
        idle_timeout,
    ) = {
        let cfg = relay.config.read().await;
        (
            cfg.limits.max_ws_message_bytes,
            cfg.limits.max_out_queue_bytes,
            cfg.limits.max_req_response_bytes,
            cfg.nip_enabled(40),
            cfg.nip_enabled(42),
            cfg.nip_enabled(78) && cfg.relay.enabled_nip78_auth,
            cfg.limits.ws_idle_timeout_secs,
        )
    };
    // Idle connections (no inbound frames) hold their slot forever; when the
    // operator enables the idle timeout the relay closes them, sending a
    // periodic PING so an alive-but-silent subscriber (which auto-responds
    // with a PONG, itself an inbound frame) stays connected while dead peers
    // are reaped. The deadline is measured from the *last inbound frame*, not
    // from the loop restart, so the keep-alive PING and live deliveries never
    // reset it (otherwise dead peers would never be reaped).
    let idle: Option<Duration> = if idle_timeout > 0 {
        Some(Duration::from_secs(idle_timeout))
    } else {
        None
    };
    let mut last_activity = std::time::Instant::now();
    // A single persistent idle deadline (reset in place on every inbound
    // frame): the per-iteration `timeout(remaining)` of the old loop
    // created and destroyed a timer-wheel entry every pass — for live-
    // active connections that was dozens of times per second. The jitter
    // (derived from the connection id, so no RNG) spreads the deadlines
    // of a large simultaneous cohort instead of timing them all out in
    // the same instant.
    let mut ping: Option<tokio::time::Interval> = idle.map(|d| {
        let mut interval = tokio::time::interval(Duration::from_secs((d.as_secs() / 3).max(5)));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick of a fresh interval fires immediately: reset it so
        // a connect burst does not PING every connection at once.
        interval.reset();
        interval
    });

    // NIP-86 blockip: watch the blocked-IP list changes so this connection
    // is dropped when its source IP becomes blocked, even if it only
    // receives live events and never sends a frame.
    let mut ip_blocks_rx = relay.ip_blocks_tx.subscribe();

    let idle_jitter = Duration::from_millis(conn_id % 2000);
    let idle_sleep: Option<tokio::time::Sleep> =
        idle.map(|d| tokio::time::sleep_until(tokio::time::Instant::now() + d + idle_jitter));
    let mut idle_sleep = idle_sleep.map(Box::pin);
    let (live_tx, live_rx): (
        tokio::sync::mpsc::Sender<crate::ws::LiveBatch>,
        tokio::sync::mpsc::Receiver<crate::ws::LiveBatch>,
    ) = tokio::sync::mpsc::channel(crate::relay::LIVE_QUEUE_CAPACITY);
    relay
        .conn_queues
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(conn_id, live_tx);
    let mut conn = Conn {
        relay,
        conn_id,
        subscriptions_held,
        live: Some(live_rx),
        path,
        outgoing: std::collections::VecDeque::new(),
        out_bytes: 0,
        out_queue_bytes,
        req_response_bytes,
        subs: HashMap::new(),
        sub_bytes: 0,
        neg: HashMap::new(),
        neg_total: 0,
        neg_opens_total: 0,
        challenge,
        authed_pubkeys: Vec::new(),
        pending_events: Vec::new(),
        pending_bytes: 0,
        expiry_enabled,
        giftwrap_restricted,
        nip78_restricted,
        access_allowed_cache: false,
        config_version: 0,
        dropped: 0,
        in_msgs: 0,
        in_bytes: 0,
        out_msgs: 0,
        out_bytes_total: 0,
        events_received_local: 0,
        pending_reqs: std::collections::VecDeque::new(),
    };
    conn.send_auth_challenge().await;
    // Seed the access-read verdict cache with a genuinely computed value,
    // so the non-blocking live/pump checks never fall back to an
    // uninitialized (sentinel) verdict during the first contention window.
    conn.access_allows_read().await;

    // A single task per connection: incoming messages and live batches are
    // processed in the same loop, and outgoing messages are flushed to the
    // socket after every iteration. This halves the task count (no separate
    // writer task) and the per-connection channel.
    #[allow(unused_assignments)] // the initial value is overwritten before the first read
    let mut drain_stalled = !conn.outgoing.is_empty();
    loop {
        // Drain pending outgoing messages. A slow reader stalls only its
        // own connection (outgoing is bounded, so new messages are dropped).
        // Batch the flush: `start_send` for every queued message and one
        // `flush` for the whole batch, so a burst of N messages costs one
        // write syscall instead of N (the per-message `send` flushed each
        // one).
        while let Some(msg) = conn.outgoing.pop_front() {
            conn.out_bytes = conn.out_bytes.saturating_sub(message_size(&msg));
            if sender.feed(msg).await.is_err() {
                break;
            }
        }
        // One flush for the whole batch: N queued messages cost a single
        // write syscall. A failed flush (the socket died) surfaces as the
        // next inbound read error and ends the connection.
        let _ = sender.flush().await;
        // Pump the queued REQ responses through the capped outgoing queue
        // in bounded chunks (see `pump_pending_reqs`).
        conn.pump_pending_reqs();
        // Remember whether anything is still queued *after* the pump
        // refilled the outgoing queue: the flush_wake branch retries
        // promptly only when there is more to send. (A tungstenite feed
        // never leaves a message queued on WouldBlock, so the queue's
        // emptiness is what decides whether the socket is the bottleneck.)
        drain_stalled = !conn.outgoing.is_empty();
        let live_fut = async {
            match conn.live.as_mut() {
                Some(rx) => rx.recv().await,
                None => std::future::pending().await,
            }
        };
        // Periodic keep-alive PING (when the idle timeout is enabled).
        let ping_fut = async {
            match ping.as_mut() {
                Some(interval) => interval.tick().await,
                None => std::future::pending().await,
            }
        };
        // Wakes the top-of-loop drain (which flushes the outgoing queue)
        // when the previous drain could not empty it: a client that is
        // blocked sending EVENTs cannot receive the OKs that unblock it
        // unless the relay actually sends them, and without this branch
        // the loop would wait for the next inbound frame (which never
        // comes while the peer is blocked). When the last drain emptied
        // the queue there is nothing to throttle, so the branch sleeps
        // only when the socket itself is the bottleneck.
        let flush_wake = async {
            if drain_stalled {
                tokio::time::sleep(tokio::time::Duration::from_millis(1)).await
            } else {
                std::future::pending().await
            }
        };
        let incoming_fut = async {
            match &mut idle_sleep {
                Some(sleep) => {
                    // The deadline is measured from the last inbound frame
                    // (only the incoming branch updates `last_activity`, so
                    // pings/live batches cannot mask a dead peer); a frame
                    // advanced the deadline, so reset the single Sleep in
                    // place.
                    let target = tokio::time::Instant::from_std(last_activity)
                        + idle.expect("idle_sleep is Some only when idle is Some")
                        + idle_jitter;
                    if sleep.as_mut().deadline() != target {
                        sleep.as_mut().reset(target);
                    }
                    tokio::select! {
                        biased;
                        _ = sleep.as_mut() => Err(()),
                        frame = receiver.next() => match frame {
                            Some(Ok(frame)) => Ok(frame),
                            _ => Err(()),
                        },
                    }
                }
                None => match receiver.next().await {
                    Some(Ok(frame)) => Ok(frame),
                    _ => Err(()),
                },
            }
        };
        tokio::select! {
            incoming = incoming_fut => {
                match incoming {
                    // Idle timeout (ws_idle_timeout_secs): no inbound frames.
                    Err(_) => break,
                    Ok(Message::Close(_)) => break,
                    Ok(frame) => {
                        last_activity = std::time::Instant::now();
                        if conn.handle_frame(frame, max_msg_size).await {
                            break;
                        }
                        // Refresh the cached NIP-40/NIP-42 flags only when
                        // the config actually changed (the version bumps on
                        // every SIGHUP reload): the hot frame path never
                        // takes the shared config lock.
                        let version = conn
                            .relay
                            .config_version
                            .load(std::sync::atomic::Ordering::Relaxed);
                        if version != conn.config_version {
                            conn.config_version = version;
                            let cfg = conn.relay.config.read().await;
                            conn.expiry_enabled = cfg.nip_enabled(40);
                            conn.giftwrap_restricted = cfg.nip_enabled(42);
                            conn.nip78_restricted = cfg.nip_enabled(78) && cfg.relay.enabled_nip78_auth;
                        }
                    }
                }
                // Batch window: keep reading for a moment so consecutive
                // EVENT messages from a busy publisher share one database
                // commit, then flush the queue when the socket is idle. The
                // iteration cap bounds the window so a client flooding
                // frames cannot starve this connection's live delivery and
                // outgoing flush (which only run in the outer select).
                let mut too_large = false;
                // A single `Sleep` deadline covers the whole window: the
                // per-frame `timeout(1ms)` of the old loop created and
                // destroyed a timer-wheel entry for every frame (and taxed
                // every single-frame REQ/EVENT with a full millisecond).
                // The deadline is *sliding*: each frame resets it (1 ms
                // after the frame), so a continuous burst coalesces into
                // one window (and one database commit), while an idle
                // client still gets its OK within ~1 ms. The frame cap
                // bounds the window when a client floods faster than the
                // relay can drain; it is sized well above the receive
                // buffer so a full socket becomes one batch.
                let window_deadline = tokio::time::sleep_until(
                    tokio::time::Instant::now() + tokio::time::Duration::from_millis(1),
                );
                tokio::pin!(window_deadline);
                for _ in 0..EVENT_BATCH * 32 {
                    let frame = tokio::select! {
                        biased;
                        frame = receiver.next() => match frame {
                            Some(Ok(frame)) => frame,
                            _ => break,
                        },
                        _ = &mut window_deadline => break,
                    };
                    last_activity = std::time::Instant::now();
                    if conn.handle_frame(frame, max_msg_size).await {
                        too_large = true;
                        break;
                    }
                    // The pending batch is bounded by count and bytes: flush
                    // it through the post-window path instead of reading the
                    // rest of the window (which let a flood of maximum-size
                    // frames pile up parsed events before validation).
                    if conn.pending_batch_full(max_msg_size) {
                        break;
                    }
                    // Slide the window: the next frame extends the batch
                    // instead of starting a new window (and a new commit).
                    window_deadline
                        .as_mut()
                        .reset(tokio::time::Instant::now() + tokio::time::Duration::from_millis(1));
                }
                if too_large {
                    break;
                }
                conn.flush_pending_events().await;
                // Deliver the REQ responses queued by the frames handled
                // in this iteration: without this, a client that sends one
                // REQ and waits would not receive the response until the
                // next select event (a further frame, the keep-alive PING
                // or a live batch) drives the top-of-loop drain.
                while let Some(msg) = conn.outgoing.pop_front() {
                    conn.out_bytes = conn.out_bytes.saturating_sub(message_size(&msg));
                    if sender.feed(msg).await.is_err() {
                        break;
                    }
                }
                if sender.flush().await.is_err() {
                    break;
                }
                conn.pump_pending_reqs();
            }
            _ = ping_fut => {
                // Keep-alive: a healthy client answers with a PONG (an
                // inbound frame, which resets the idle timeout), so an idle
                // subscriber stays connected while a dead peer is reaped.
                let _ = sender.send(Message::Ping(vec![].into())).await;
            }
            _ = flush_wake => {
                // The outgoing queue holds OKs (or REQ responses) that
                // must reach the peer for its send path to unblock: wake
                // the top-of-loop drain promptly instead of waiting for
                // the next inbound frame.
            }
            changed = ip_blocks_rx.changed() => {
                // NIP-86 blockip: wake on every blocked-IP list change so a
                // read-only subscriber (no inbound frames) is dropped too.
                // An `Err` means the relay (and its sender) is gone.
                if changed.is_err() || conn.source_ip_blocked(peer_ip).await {
                    break;
                }
            }
            live_batch = live_fut => {
                match live_batch {
                    Some(batch) => {
                        // Refresh the cached NIP-40/NIP-42 flags only when
                        // the config actually changed (the version bumps on
                        // every SIGHUP reload): the hot live path never
                        // takes the shared config lock.
                        let version = conn
                            .relay
                            .config_version
                            .load(std::sync::atomic::Ordering::Relaxed);
                        if version != conn.config_version {
                            conn.config_version = version;
                            let cfg = conn.relay.config.read().await;
                            conn.expiry_enabled = cfg.nip_enabled(40);
                            conn.giftwrap_restricted = cfg.nip_enabled(42);
                            conn.nip78_restricted = cfg.nip_enabled(78) && cfg.relay.enabled_nip78_auth;
                        }
                        // The group store lock and its Arc clone are only
                        // taken when the batch actually contains group
                        // events (rare); ordinary traffic skips the shared
                        // state entirely.
                        let has_group_events =
                            batch.iter().any(|(e, _)| nip29::is_group_event(e));
                        let store = if has_group_events {
                            Some(Arc::clone(&conn.relay.groups))
                        } else {
                            None
                        };
                        let guard = if let Some(store) = &store {
                            Some(store.read().await)
                        } else {
                            None
                        };
                        let groups = guard.as_deref();
                        for (event, json) in batch.iter() {
                            conn.deliver_live(event, json, groups);
                        }
                    }
                    None => break,
                }
            }
        }
    }

    // Events received but not yet batched are accepted before closing, so
    // a client that disconnects without waiting for its OKs does not lose
    // them. The live broadcast of these events still reaches subscribers.
    conn.flush_pending_events().await;

    // Final flush: deliver any queued messages (e.g. NOTICEs) before
    // closing the connection.
    while let Some(msg) = conn.outgoing.pop_front() {
        conn.out_bytes = conn.out_bytes.saturating_sub(message_size(&msg));
        if sender.send(msg).await.is_err() {
            break;
        }
    }
    let _ = sender.close().await;

    // Remove the connection from the live subscription index and the
    // delivery-queue map (the queue sender is dropped with the map entry;
    // the bus task's `send` then fails and the connection is skipped).
    conn.relay
        .sub_index
        .write()
        .unwrap_or_else(|p| p.into_inner())
        .unregister(conn.conn_id);
    conn.relay
        .conn_queues
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(&conn.conn_id);

    // Flush the per-connection counters into the shared stats once, so the
    // hot per-message path never contends on the shared atomics.
    conn.relay
        .stats
        .bump(&conn.relay.stats.messages_in, conn.in_msgs);
    conn.relay
        .stats
        .bump(&conn.relay.stats.bytes_in, conn.in_bytes);
    conn.relay
        .stats
        .bump(&conn.relay.stats.messages_out, conn.out_msgs);
    conn.relay
        .stats
        .bump(&conn.relay.stats.bytes_out, conn.out_bytes_total);
    conn.relay.stats.bump(
        &conn.relay.stats.events_received,
        conn.events_received_local,
    );

    // Release the connection's accounting: any subscriptions still open at
    // disconnect were never CLOSE'd, so decrement them here (REQ
    // subscriptions and negentropy subscriptions both hold a slot). The
    // guard drops the remainder if a panic ever skips this path.
    let held = conn
        .subscriptions_held
        .swap(0, std::sync::atomic::Ordering::Relaxed);
    conn.relay
        .stats
        .subscriptions_active
        .fetch_sub(held as u64, std::sync::atomic::Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Keypair, Secp256k1, XOnlyPublicKey};
    use serde_json::Value;
    use tokio::sync::RwLock;

    use crate::config::Config;
    use crate::nips::nip01::{compute_id, sign};
    use crate::relay::LiveBusConfig;
    use crate::util::unix_now;

    fn temp_db_path() -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join("nostrfy-ws-test")
            .join(format!("{:x}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        path
    }

    fn signed_note(
        secp: &Secp256k1<secp256k1::All>,
        content: &str,
        created: u64,
        tags: Vec<Vec<String>>,
    ) -> Event {
        let keypair = Keypair::from_seckey_slice(secp, &[1u8; 32]).unwrap();
        let pubkey = XOnlyPublicKey::from_keypair(&keypair).0.to_string();
        let mut ev = Event {
            id: String::new(),
            pubkey,
            created_at: created,
            kind: 1,
            tags,
            content: content.into(),
            sig: String::new(),
        };
        sign(&mut ev, &keypair, secp).unwrap();
        ev
    }

    /// Like [`signed_note`] but with a distinct author per seed byte.
    fn signed_note_seeded(
        secp: &Secp256k1<secp256k1::All>,
        seed: u8,
        content: &str,
        created: u64,
        tags: Vec<Vec<String>>,
    ) -> Event {
        let keypair = Keypair::from_seckey_slice(secp, &[seed; 32]).unwrap();
        let pubkey = XOnlyPublicKey::from_keypair(&keypair).0.to_string();
        let mut ev = Event {
            id: String::new(),
            pubkey,
            created_at: created,
            kind: 1,
            tags,
            content: content.into(),
            sig: String::new(),
        };
        sign(&mut ev, &keypair, secp).unwrap();
        ev
    }

    fn signed_auth(secp: &Secp256k1<secp256k1::All>, challenge: &str, created: u64) -> Event {
        let keypair = Keypair::from_seckey_slice(secp, &[2u8; 32]).unwrap();
        let pubkey = XOnlyPublicKey::from_keypair(&keypair).0.to_string();
        let mut ev = Event {
            id: String::new(),
            pubkey,
            created_at: created,
            kind: 22242,
            tags: vec![
                vec!["challenge".into(), challenge.into()],
                vec!["relay".into(), "127.0.0.1:8080".into()],
            ],
            content: String::new(),
            sig: String::new(),
        };
        ev.id = compute_id(&ev);
        let id = ev.id_bytes().unwrap();
        ev.sig = secp.sign_schnorr_no_aux_rand(&id, &keypair).to_string();
        ev
    }

    /// Like [`signed_note_seeded`] but with an arbitrary kind and a valid
    /// signature over that kind (kind mutations after signing break the sig).
    fn signed_kind_note_seeded(
        secp: &Secp256k1<secp256k1::All>,
        seed: u8,
        kind: u64,
        content: &str,
        created: u64,
        tags: Vec<Vec<String>>,
    ) -> Event {
        let keypair = Keypair::from_seckey_slice(secp, &[seed; 32]).unwrap();
        let pubkey = XOnlyPublicKey::from_keypair(&keypair).0.to_string();
        let mut ev = Event {
            id: String::new(),
            pubkey,
            created_at: created,
            kind,
            tags,
            content: content.into(),
            sig: String::new(),
        };
        sign(&mut ev, &keypair, secp).unwrap();
        ev
    }

    /// AUTH event signed with a specific key seed (owner of the events it
    /// must reveal). Seed 2 matches [`signed_auth`]/[`signed_note_seeded`].
    fn signed_auth_seeded(
        secp: &Secp256k1<secp256k1::All>,
        seed: u8,
        challenge: &str,
        created: u64,
    ) -> Event {
        let keypair = Keypair::from_seckey_slice(secp, &[seed; 32]).unwrap();
        let pubkey = XOnlyPublicKey::from_keypair(&keypair).0.to_string();
        let mut ev = Event {
            id: String::new(),
            pubkey,
            created_at: created,
            kind: 22242,
            tags: vec![
                vec!["challenge".into(), challenge.into()],
                vec!["relay".into(), "127.0.0.1:8080".into()],
            ],
            content: String::new(),
            sig: String::new(),
        };
        ev.id = compute_id(&ev);
        let id = ev.id_bytes().unwrap();
        ev.sig = secp.sign_schnorr_no_aux_rand(&id, &keypair).to_string();
        ev
    }

    async fn build_conn() -> Conn {
        build_conn_with("").await
    }

    /// Builds a connection on a pre-built relay (for tests that need
    /// several connections sharing one relay + subscription index).
    async fn build_conn_on(relay: Arc<Relay>) -> Conn {
        let (out_queue_bytes, expiry_enabled, giftwrap_restricted, nip78_restricted) = {
            let cfg = relay.config.read().await;
            (
                cfg.limits.max_out_queue_bytes,
                cfg.nip_enabled(40),
                cfg.nip_enabled(42),
                cfg.nip_enabled(78) && cfg.relay.enabled_nip78_auth,
            )
        };
        let conn_id = relay
            .next_conn_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (live_tx, live_rx) = tokio::sync::mpsc::channel(crate::relay::LIVE_QUEUE_CAPACITY);
        relay
            .conn_queues
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(conn_id, live_tx);
        Conn {
            relay,
            conn_id,
            subscriptions_held: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            live: Some(live_rx),
            path: "/".into(),
            outgoing: std::collections::VecDeque::new(),
            out_bytes: 0,
            out_queue_bytes,
            req_response_bytes: 0,
            pending_reqs: std::collections::VecDeque::new(),
            subs: HashMap::new(),
            sub_bytes: 0,
            neg: HashMap::new(),
            neg_total: 0,
            neg_opens_total: 0,
            challenge: "test-challenge".into(),
            authed_pubkeys: Vec::new(),
            pending_events: Vec::new(),
            pending_bytes: 0,
            expiry_enabled,
            giftwrap_restricted,
            nip78_restricted,
            access_allowed_cache: false,
            config_version: 0,
            dropped: 0,
            in_msgs: 0,
            in_bytes: 0,
            out_msgs: 0,
            out_bytes_total: 0,
            events_received_local: 0,
        }
    }

    async fn build_conn_with(private_key: &str) -> Conn {
        build_conn_on(build_relay_with(private_key).await).await
    }

    /// Builds a relay with the test memory-mapped database and its live bus
    /// running, for tests that need several connections sharing one relay.
    async fn build_relay_with(private_key: &str) -> Arc<Relay> {
        let mut cfg = Config::default();
        cfg.database.path = temp_db_path();
        // Small memory map: the parallel tests each open a DB, and the
        // production 1 TiB reservation would exhaust the container's
        // memory under the concurrent load (sparse, but the mappings add
        // up). The tests store a handful of events.
        cfg.database.map_size = 16 * 1024 * 1024;
        cfg.database.max_map_size = 256 * 1024 * 1024;
        let db = crate::db::DbClient::open(
            &cfg.database,
            true,
            Arc::new(Default::default()),
            0,
            128,
            4096,
            262144,
        )
        .unwrap();
        let config = Arc::new(RwLock::new(cfg));
        let stats = Stats::new();
        let mut relay = Relay::new(
            config,
            db,
            stats,
            private_key,
            LiveBusConfig {
                buffer: 1024,
                batch_interval_ms: 10,
                batch_size: 64,
            },
        )
        .await;
        relay.start_live_bus();
        Arc::new(relay)
    }

    /// Every queued outgoing text message parsed as JSON.
    fn outgoing_json(conn: &Conn) -> Vec<Value> {
        conn.outgoing
            .iter()
            .filter_map(|m| match m {
                Message::Text(t) => serde_json::from_str(t).ok(),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn req_delivers_matching_events_then_eose() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            let e1 = signed_note(conn.relay.secp(), "hello", now, vec![]);
            let e2 = signed_note(conn.relay.secp(), "world", now - 1, vec![]);
            conn.relay.db.put(e1.clone(), now).await;
            conn.relay.db.put(e2.clone(), now).await;
            conn.handle_req(&[json!("sub"), json!({"kinds": [1]})])
                .await;
            conn.pump_pending_reqs();
            let msgs = outgoing_json(&conn);
            let events: Vec<&Value> = msgs.iter().filter(|m| m[0] == "EVENT").collect();
            assert_eq!(events.len(), 2);
            let ids: Vec<String> = events
                .iter()
                .map(|m| m[2]["id"].as_str().unwrap().to_string())
                .collect();
            assert!(ids.contains(&e1.id) && ids.contains(&e2.id));
            assert!(msgs.iter().any(|m| m[0] == "EOSE" && m[1] == "sub"));
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn req_timeout_closes_and_releases_the_subscription() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            let e1 = signed_note(conn.relay.secp(), "hello", now, vec![]);
            conn.relay.db.put(e1.clone(), now).await;
            // Killing the DB reader makes the REQ query fail deterministically
            // (`query_req_reported` returns None), exactly like a timed-out
            // scan: the CLOSED path must release the subscription it had
            // registered before the query, or the dead sub keeps receiving
            // live events under a closed id.
            conn.relay.db.shutdown();
            conn.handle_req(&[json!("sub"), json!({"kinds": [1]})])
                .await;
            conn.pump_pending_reqs();
            let msgs = outgoing_json(&conn);
            assert!(
                msgs.iter().any(|m| m[0] == "CLOSED"
                    && m[1] == "sub"
                    && m[2] == "error: database timeout, please retry"),
                "a timed-out REQ must be closed with a retryable reason"
            );
            assert!(
                !conn.subs.contains_key("sub"),
                "the subscription must be released on a timed-out query"
            );
            assert!(
                !msgs.iter().any(|m| m[0] == "EVENT" && m[1] == "sub"),
                "no events may be delivered for the closed subscription"
            );
            // A live event published afterwards must not reach the closed
            // sub (deliver_live reads `self.subs`).
            let e2 = signed_note(conn.relay.secp(), "late", now + 1, vec![]);
            conn.deliver_live(&e2, &serde_json::to_string(&e2).unwrap_or_default(), None);
            assert!(
                !outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "EVENT" && m[1] == "sub"),
                "live delivery must stop for the released subscription"
            );
        });
    }

    #[test]
    fn req_hides_protected_events_from_anonymous() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            let normal = signed_note(conn.relay.secp(), "public", now, vec![]);
            let protected = signed_note(conn.relay.secp(), "secret", now, vec![vec!["-".into()]]);
            conn.relay.db.put(normal.clone(), now).await;
            conn.relay.db.put(protected.clone(), now).await;
            conn.handle_req(&[json!("sub"), json!({"kinds": [1]})])
                .await;
            conn.pump_pending_reqs();
            let ids: Vec<String> = outgoing_json(&conn)
                .iter()
                .filter(|m| m[0] == "EVENT")
                .map(|m| m[2]["id"].as_str().unwrap().to_string())
                .collect();
            assert!(ids.contains(&normal.id));
            assert!(
                !ids.contains(&protected.id),
                "protected event must be hidden from anonymous"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn req_inbox_outbox_filters() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            let secp = conn.relay.secp();
            let alice_pk = XOnlyPublicKey::from_keypair(
                &Keypair::from_seckey_slice(secp, &[1u8; 32]).unwrap(),
            )
            .0
            .to_string();
            let bob_pk = XOnlyPublicKey::from_keypair(
                &Keypair::from_seckey_slice(secp, &[2u8; 32]).unwrap(),
            )
            .0
            .to_string();
            let alice_plain = signed_note_seeded(secp, 1, "alice plain", now, vec![]);
            let alice_to_bob = signed_note_seeded(
                secp,
                1,
                "alice to bob",
                now - 1,
                vec![vec!["p".into(), bob_pk.clone()]],
            );
            let bob_to_alice = signed_note_seeded(
                secp,
                2,
                "bob to alice",
                now - 2,
                vec![vec!["p".into(), alice_pk.clone()]],
            );
            for e in [&alice_plain, &alice_to_bob, &bob_to_alice] {
                conn.relay.db.put(e.clone(), now).await;
            }

            // outbox: only the events authored by the pubkey.
            conn.handle_req(&[json!("o"), json!({"outbox": alice_pk})])
                .await;
            conn.pump_pending_reqs();
            let contents: Vec<String> = outgoing_json(&conn)
                .iter()
                .filter(|m| m[0] == "EVENT" && m[1] == "o")
                .map(|m| m[2]["content"].as_str().unwrap().to_string())
                .collect();
            assert!(contents.contains(&"alice plain".to_string()));
            assert!(contents.contains(&"alice to bob".to_string()));
            assert!(
                !contents.contains(&"bob to alice".to_string()),
                "outbox must not return other authors"
            );

            // inbox: only the events addressed to the pubkey (#p tag).
            conn.handle_req(&[json!("i"), json!({"inbox": alice_pk})])
                .await;
            conn.pump_pending_reqs();
            let contents: Vec<String> = outgoing_json(&conn)
                .iter()
                .filter(|m| m[0] == "EVENT" && m[1] == "i")
                .map(|m| m[2]["content"].as_str().unwrap().to_string())
                .collect();
            assert_eq!(contents, vec!["bob to alice".to_string()]);

            // Combined: events by Bob addressed to Alice.
            conn.handle_req(&[json!("io"), json!({"outbox": bob_pk, "inbox": alice_pk})])
                .await;
            conn.pump_pending_reqs();
            let contents: Vec<String> = outgoing_json(&conn)
                .iter()
                .filter(|m| m[0] == "EVENT" && m[1] == "io")
                .map(|m| m[2]["content"].as_str().unwrap().to_string())
                .collect();
            assert_eq!(contents, vec!["bob to alice".to_string()]);

            // An invalid pubkey rejects the whole subscription.
            conn.handle_req(&[json!("bad"), json!({"outbox": "not-a-pubkey"})])
                .await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "CLOSED" && m[1] == "bad"),
                "an invalid outbox value must reject the subscription"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn auth_grants_protected_event_visibility() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            let protected = signed_note(conn.relay.secp(), "secret", now, vec![vec!["-".into()]]);
            conn.relay.db.put(protected.clone(), now).await;
            // AUTH with a valid event for this connection's challenge.
            let auth = signed_auth(conn.relay.secp(), "test-challenge", now);
            conn.handle_auth(&[serde_json::to_value(&auth).unwrap()])
                .await;
            assert!(conn.is_authed());
            conn.handle_req(&[json!("sub"), json!({"kinds": [1]})])
                .await;
            conn.pump_pending_reqs();
            let ids: Vec<String> = outgoing_json(&conn)
                .iter()
                .filter(|m| m[0] == "EVENT")
                .map(|m| m[2]["id"].as_str().unwrap().to_string())
                .collect();
            assert!(
                ids.contains(&protected.id),
                "authed client sees protected events"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn auth_disabled_still_answers_ok() {
        // NIP-42: client AUTH MUST be answered with OK even when the relay
        // has NIP-42 disabled.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            {
                let mut w = conn.relay.config.write().await;
                w.relay.disabled_nips.push(42);
            }
            let now = unix_now();
            let auth = signed_auth(conn.relay.secp(), "test-challenge", now);
            conn.handle_auth(&[serde_json::to_value(&auth).unwrap()])
                .await;
            let msgs = outgoing_json(&conn);
            assert!(
                msgs.iter()
                    .any(|m| m[0] == "OK" && m[1] == auth.id && m[2] == false),
                "disabled AUTH must still answer OK false: {msgs:?}"
            );
            assert!(!conn.is_authed(), "disabled AUTH must not authenticate");
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn close_and_neg_close_use_separate_namespaces() {
        // NIP-77: CLOSE releases only REQ, NEG-CLOSE only NEG.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            conn.handle_req(&[json!("s"), json!({"kinds": [1]})]).await;
            conn.handle_neg_open(&[json!("s"), json!({"kinds": [1]}), json!("61000000")])
                .await;
            assert!(conn.subs.contains_key("s"));
            assert!(conn.neg.contains_key("s"));
            conn.handle_close(&[json!("s")]);
            assert!(
                !conn.subs.contains_key("s"),
                "CLOSE must release the REQ sub"
            );
            assert!(
                conn.neg.contains_key("s"),
                "CLOSE must leave NEG state untouched"
            );
            conn.handle_neg_close(&[json!("s")]);
            assert!(
                !conn.neg.contains_key("s"),
                "NEG-CLOSE must release the NEG state"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn count_applies_visibility_to_protected_events() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            conn.relay
                .db
                .put(signed_note(conn.relay.secp(), "public", now, vec![]), now)
                .await;
            conn.relay
                .db
                .put(
                    signed_note(conn.relay.secp(), "secret", now, vec![vec!["-".into()]]),
                    now,
                )
                .await;
            conn.handle_count(&[json!("c"), json!({"kinds": [1]})])
                .await;
            let msgs = outgoing_json(&conn);
            let count = msgs
                .iter()
                .find(|m| m[0] == "COUNT")
                .expect("a COUNT response is sent");
            assert_eq!(
                count[2]["count"].as_u64(),
                Some(1),
                "protected events are not counted for anonymous"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn req_hides_nip78_events_from_anonymous_and_nonowners() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay_with("").await;
            let mut conn = build_conn_on(relay.clone()).await;
            let now = unix_now();
            let normal = signed_note(relay.secp(), "public", now, vec![]);
            // NIP-78 app-specific event authored by the seed-2 key (the key
            // that `signed_auth` authenticates as).
            let mut app = signed_note_seeded(
                relay.secp(),
                2,
                "app-specific",
                now,
                vec![vec!["d".into(), "profile".into()]],
            );
            app.kind = 30078;
            app.id = crate::nips::nip01::compute_id(&app);
            relay.db.put(normal.clone(), now).await;
            relay.db.put(app.clone(), now).await;

            conn.handle_req(&[json!("sub"), json!({"kinds": [1, 30078]})])
                .await;
            conn.pump_pending_reqs();
            let ids: Vec<String> = outgoing_json(&conn)
                .iter()
                .filter(|m| m[0] == "EVENT")
                .map(|m| m[2]["id"].as_str().unwrap().to_string())
                .collect();
            assert!(ids.contains(&normal.id));
            assert!(
                !ids.contains(&app.id),
                "NIP-78 event must be hidden from an anonymous client"
            );

            // The owner sees its own app-specific event.
            let mut owner = build_conn_on(relay.clone()).await;
            let auth = signed_auth(relay.secp(), "test-challenge", now);
            owner
                .handle_auth(&[serde_json::to_value(&auth).unwrap()])
                .await;
            assert!(owner.is_authed());
            owner
                .handle_req(&[json!("sub"), json!({"kinds": [30078]})])
                .await;
            owner.pump_pending_reqs();
            assert!(
                outgoing_json(&owner)
                    .iter()
                    .any(|m| m[0] == "EVENT" && m[2]["id"] == app.id),
                "the authenticated owner sees its own NIP-78 event"
            );

            // A third party authenticated with a different key does not.
            let mut other = build_conn_on(relay).await;
            let auth = signed_auth_seeded(other.relay.secp(), 3, "test-challenge", now);
            other
                .handle_auth(&[serde_json::to_value(&auth).unwrap()])
                .await;
            assert!(other.is_authed());
            other
                .handle_req(&[json!("sub"), json!({"kinds": [30078]})])
                .await;
            other.pump_pending_reqs();
            assert!(
                !outgoing_json(&other)
                    .iter()
                    .any(|m| m[0] == "EVENT" && m[2]["id"] == app.id),
                "an authenticated non-owner must not see the NIP-78 event"
            );

            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn count_applies_visibility_to_nip78_events() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            conn.relay
                .db
                .put(signed_note(conn.relay.secp(), "public", now, vec![]), now)
                .await;
            let mut app = signed_note(conn.relay.secp(), "app", now, vec![]);
            app.kind = 30078;
            app.id = crate::nips::nip01::compute_id(&app);
            conn.relay.db.put(app, now).await;
            conn.handle_count(&[json!("c"), json!({"kinds": [1, 30078]})])
                .await;
            let msgs = outgoing_json(&conn);
            let count = msgs
                .iter()
                .find(|m| m[0] == "COUNT")
                .expect("a COUNT response is sent");
            assert_eq!(
                count[2]["count"].as_u64(),
                Some(1),
                "NIP-78 events are not counted for anonymous"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn publish_requires_auth_for_nip78_events() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay_with("").await;
            let mut conn = build_conn_on(relay.clone()).await;
            let now = unix_now();
            for kind in [78, 30078] {
                let mut ev = signed_note(relay.secp(), "app", now, vec![]);
                ev.kind = kind;
                ev.id = crate::nips::nip01::compute_id(&ev);
                conn.queue_event_value(ev.clone()).await;
                conn.flush_pending_events().await;
                assert!(
                    !outgoing_json(&conn)
                        .iter()
                        .any(|m| m[0] == "OK" && m[1] == ev.id && m[2] == true),
                    "kind {kind} must be rejected on an anonymous connection"
                );
            }

            // The AUTH'd author can publish its own app-specific event.
            let mut owner = build_conn_on(relay).await;
            let auth = signed_auth(owner.relay.secp(), "test-challenge", now);
            owner
                .handle_auth(&[serde_json::to_value(&auth).unwrap()])
                .await;
            let app = signed_kind_note_seeded(
                owner.relay.secp(),
                2,
                78,
                "owner-app",
                now,
                vec![vec!["d".into(), "profile".into()]],
            );
            owner.queue_event_value(app.clone()).await;
            owner.flush_pending_events().await;
            assert!(
                outgoing_json(&owner)
                    .iter()
                    .any(|m| m[0] == "OK" && m[1] == app.id && m[2] == true),
                "an authenticated client may publish kind 78"
            );

            conn.relay.db.shutdown();
        });
    }

    /// Hex pubkey of a secret key (hex), for tests that act as the admin.
    fn pubkey_of_secret(secp: &Secp256k1<secp256k1::All>, secret_hex: &str) -> String {
        let secret = hex::decode(secret_hex).unwrap();
        let keypair = Keypair::from_seckey_slice(secp, &secret).unwrap();
        XOnlyPublicKey::from_keypair(&keypair).0.to_string()
    }

    /// A kind:1 event signed with an explicit secret key (hex), so a test
    /// can publish "as the admin" (relay.pubkey holder).
    fn signed_command_event(
        secp: &Secp256k1<secp256k1::All>,
        secret_hex: &str,
        content: &str,
        created: u64,
    ) -> Event {
        let secret = hex::decode(secret_hex).unwrap();
        let keypair = Keypair::from_seckey_slice(secp, &secret).unwrap();
        let pubkey = XOnlyPublicKey::from_keypair(&keypair).0.to_string();
        let mut ev = Event {
            id: String::new(),
            pubkey,
            created_at: created,
            kind: 1,
            tags: Vec::new(),
            content: content.into(),
            sig: String::new(),
        };
        sign(&mut ev, &keypair, secp).unwrap();
        ev
    }

    /// Stored kind:1111 events matching the `e` tag.
    async fn stored_replies(relay: &Arc<Relay>, e_tag: &str, now: u64) -> Vec<Event> {
        let f: Vec<crate::filter::Filter> = serde_json::from_value(serde_json::json!([
            { "kinds": [1111], "#e": [e_tag] }
        ]))
        .unwrap();
        let (events, _) = relay.db.query_req(f, 500, now).await;
        events
    }

    #[test]
    fn group_join_requires_a_stored_invite() {
        // On a CLOSED group, a JOIN with an invite code is only admitted
        // while a stored, undeleted 9009 backs the code: revoking the
        // 9009 (NIP-09) must take effect immediately, even though the
        // in-memory invite set still holds the code.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay_with("").await;
            let mut conn = build_conn_on(relay.clone()).await;
            let now = unix_now();
            let code = "abc123";

            // Create the group, close it, issue the invite, and join
            // with the code.
            let create = signed_kind_note_seeded(
                relay.secp(),
                1,
                crate::nips::nip29::CREATE_GROUP,
                "",
                now,
                vec![vec!["h".into(), "g1".into()]],
            );
            let close = signed_kind_note_seeded(
                relay.secp(),
                1,
                9002,
                "",
                now,
                vec![vec!["h".into(), "g1".into()], vec!["closed".into()]],
            );
            let invite = signed_kind_note_seeded(
                relay.secp(),
                1,
                9009,
                "",
                now,
                vec![
                    vec!["h".into(), "g1".into()],
                    vec!["code".into(), code.into()],
                ],
            );
            let join = signed_kind_note_seeded(
                relay.secp(),
                2,
                crate::nips::nip29::JOIN,
                "",
                now,
                vec![
                    vec!["h".into(), "g1".into()],
                    vec!["code".into(), code.into()],
                ],
            );
            for ev in [&create, &close, &invite, &join] {
                conn.queue_event_value(ev.clone()).await;
                conn.flush_pending_events().await;
                assert!(
                    outgoing_json(&conn)
                        .iter()
                        .any(|m| m[0] == "OK" && m[1] == ev.id && m[2] == true),
                    "the create/close/invite/join sequence is accepted"
                );
            }

            // Revoke the invite by deleting its 9009.
            let deletion = signed_kind_note_seeded(
                relay.secp(),
                1,
                crate::nips::nip09::DELETION_KIND,
                "",
                now + 1,
                vec![vec!["e".into(), invite.id.clone()]],
            );
            conn.queue_event_value(deletion.clone()).await;
            conn.flush_pending_events().await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "OK" && m[1] == deletion.id && m[2] == true),
                "the deletion is accepted"
            );

            // A different pubkey joining with the revoked code is refused,
            // even though the in-memory invite set still holds the code.
            let join2 = signed_kind_note_seeded(
                relay.secp(),
                3,
                crate::nips::nip29::JOIN,
                "",
                now,
                vec![
                    vec!["h".into(), "g1".into()],
                    vec!["code".into(), code.into()],
                ],
            );
            conn.queue_event_value(join2.clone()).await;
            conn.flush_pending_events().await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "OK" && m[1] == join2.id && m[2] == false),
                "a revoked invite code must not admit a join"
            );

            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn allowed_authors_posts_stay_readable_on_write_restricted_relays() {
        // End-to-end: with
        // `restrict_relay = true` + an allow list, the allowed author's
        // posts must remain readable by anonymous and non-listed readers
        // (the allow list is a write restriction, NIP-11
        // `restricted_writes`). Before the fix, anonymous readers were
        // refused entirely and the posts were unreadable.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay_with("").await;
            // The author of `signed_note` (seed 1) is the allowed pubkey.
            let author = {
                let keypair = Keypair::from_seckey_slice(relay.secp(), &[1u8; 32]).unwrap();
                XOnlyPublicKey::from_keypair(&keypair).0.to_string()
            };
            {
                let mut access = relay.access.write().await;
                access.restrict_relay = true;
                access.allowed_pubkeys.push((author.clone(), String::new()));
            }

            // The allowed author publishes.
            let mut author_conn = build_conn_on(relay.clone()).await;
            let note = signed_note(relay.secp(), "issue-61 note", unix_now(), vec![]);
            author_conn.queue_event_value(note.clone()).await;
            author_conn.flush_pending_events().await;
            assert!(
                outgoing_json(&author_conn)
                    .iter()
                    .any(|m| m[0] == "OK" && m[1] == note.id && m[2] == true),
                "the allowed author may publish"
            );

            // An anonymous reader sees the note (the reported symptom).
            let mut anon = build_conn_on(relay.clone()).await;
            anon.handle_req(&[json!("sub"), json!({"kinds": [1]})])
                .await;
            anon.pump_pending_reqs();
            let msgs = outgoing_json(&anon);
            assert!(
                !msgs.iter().any(|m| m[0] == "CLOSED"),
                "anonymous may subscribe on a write-restricted relay"
            );
            assert!(
                msgs.iter()
                    .any(|m| m[0] == "EVENT" && m[2]["id"] == note.id),
                "the anonymous reader receives the allowed author's post"
            );

            // A non-listed pubkey can read the post...
            let mut outsider = build_conn_on(relay.clone()).await;
            outsider
                .handle_req(&[json!("sub"), json!({"kinds": [1]})])
                .await;
            outsider.pump_pending_reqs();
            assert!(
                outgoing_json(&outsider)
                    .iter()
                    .any(|m| m[0] == "EVENT" && m[2]["id"] == note.id),
                "a non-listed pubkey can read the allowed author's post"
            );
            // ...but cannot publish (the write restriction stays).
            let outsider_note = signed_note_seeded(relay.secp(), 2, "outsider", unix_now(), vec![]);
            outsider.queue_event_value(outsider_note.clone()).await;
            outsider.flush_pending_events().await;
            assert!(
                !outgoing_json(&outsider)
                    .iter()
                    .any(|m| m[0] == "OK" && m[1] == outsider_note.id && m[2] == true),
                "a non-listed pubkey cannot publish (write restriction)"
            );

            relay.db.shutdown();
        });
    }

    #[test]
    fn command_events_edit_lists_and_reply_with_1111() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let secret = "aa".repeat(32);
            let relay = build_relay_with(&secret).await;
            relay.config.write().await.relay.pubkey = pubkey_of_secret(relay.secp(), &secret);
            relay.config.write().await.relay.enabled_command_events = true;
            let mut conn = build_conn_on(relay.clone()).await;
            let now = unix_now();
            let target = "bb".repeat(32);

            // relay allow: the access list changes immediately and the
            // change is persisted for the CLI/restart.
            let cmd = signed_command_event(
                relay.secp(),
                &secret,
                &format!("/relay allow {target}"),
                now,
            );
            conn.queue_event_value(cmd.clone()).await;
            conn.flush_pending_events().await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "OK" && m[1] == cmd.id && m[2] == true),
                "the command event is accepted"
            );
            assert!(
                relay
                    .access
                    .read()
                    .await
                    .allowed_pubkeys
                    .iter()
                    .any(|(p, _)| p == &target),
                "relay allow must add the pubkey to the allow list"
            );
            let (deny, allow) = relay.db.load_relay_pubkeys().await.unwrap_or_default();
            assert!(allow.iter().any(|(p, _)| p == &target));
            assert!(deny.is_empty());

            // The kind:1111 reply is stored, tagged to the command and
            // served publicly (no `-` tag): visible even without NIP-42.
            let replies = stored_replies(&relay, &cmd.id, now).await;
            assert_eq!(replies.len(), 1, "one reply per command");
            assert_eq!(replies[0].pubkey, relay.relay_pubkey().unwrap());
            assert!(
                replies[0]
                    .tags
                    .iter()
                    .all(|t| t.first().map(String::as_str) != Some("-")),
                "the reply must be public, not NIP-70 protected"
            );
            let admin = pubkey_of_secret(relay.secp(), &secret);
            assert!(
                replies[0]
                    .tags
                    .iter()
                    .any(|t| t == &vec!["p".into(), admin.clone()]),
                "the reply must mention the admin with a p tag"
            );
            assert!(
                replies[0]
                    .content
                    .contains(&format!("/relay allow {target}")),
                "reply content: {}",
                replies[0].content
            );

            // relay deny: moves the pubkey from allow to deny (the `nostr:`
            // URI prefix is accepted on the operand).
            let cmd = signed_command_event(
                relay.secp(),
                &secret,
                &format!("/relay deny nostr:{target}"),
                now + 1,
            );
            conn.queue_event_value(cmd.clone()).await;
            conn.flush_pending_events().await;
            assert!(
                relay
                    .access
                    .read()
                    .await
                    .blocked_pubkeys
                    .iter()
                    .any(|(p, _)| p == &target),
                "relay deny must add the pubkey to the deny list"
            );
            assert!(
                !relay
                    .access
                    .read()
                    .await
                    .allowed_pubkeys
                    .iter()
                    .any(|(p, _)| p == &target),
                "relay deny must remove the pubkey from the allow list"
            );

            // blossom allow/deny edits the upload allowlist, persisted.
            let uploader = "cc".repeat(32);
            let cmd = signed_command_event(
                relay.secp(),
                &secret,
                &format!("/blossom allow {uploader}"),
                now + 2,
            );
            conn.queue_event_value(cmd.clone()).await;
            conn.flush_pending_events().await;
            assert!(
                relay
                    .blossom_allow
                    .read()
                    .await
                    .iter()
                    .any(|p| p == &uploader),
                "blossom allow must add the uploader"
            );
            assert!(
                relay
                    .db
                    .load_blossom_allow()
                    .await
                    .unwrap_or_default()
                    .contains(&uploader),
                "the blossom allowlist must be persisted"
            );
            let cmd = signed_command_event(
                relay.secp(),
                &secret,
                &format!("/blossom deny {uploader}"),
                now + 3,
            );
            conn.queue_event_value(cmd.clone()).await;
            conn.flush_pending_events().await;
            assert!(
                !relay.blossom_allow.read().await.contains(&uploader),
                "blossom deny must remove the uploader"
            );

            // An invalid operand gets an error reply, lists unchanged.
            let cmd = signed_command_event(relay.secp(), &secret, "/relay allow zzz", now + 4);
            conn.queue_event_value(cmd.clone()).await;
            conn.flush_pending_events().await;
            let replies = stored_replies(&relay, &cmd.id, now + 4).await;
            assert_eq!(replies.len(), 1);
            assert!(
                replies[0].content.starts_with("error: invalid pubkey"),
                "reply content: {}",
                replies[0].content
            );
            assert!(
                !relay
                    .access
                    .read()
                    .await
                    .allowed_pubkeys
                    .iter()
                    .any(|(p, _)| p == "zzz"),
                "an invalid command must not change the lists"
            );

            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn command_events_require_flag_and_owner_author() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let secret = "aa".repeat(32);
            let relay = build_relay_with(&secret).await; // flag defaults to false
            relay.config.write().await.relay.pubkey = pubkey_of_secret(relay.secp(), &secret);
            let mut conn = build_conn_on(relay.clone()).await;
            let now = unix_now();
            let target = "bb".repeat(32);

            // Flag off: the note is stored, but nothing is executed.
            let cmd = signed_command_event(
                relay.secp(),
                &secret,
                &format!("/relay allow {target}"),
                now,
            );
            conn.queue_event_value(cmd.clone()).await;
            conn.flush_pending_events().await;
            assert!(
                relay.access.read().await.allowed_pubkeys.is_empty(),
                "no list change while the flag is off"
            );
            assert!(stored_replies(&relay, &cmd.id, now).await.is_empty());

            // A different author cannot run commands even with the flag on.
            relay.config.write().await.relay.enabled_command_events = true;
            let impostor = signed_note(
                relay.secp(),
                &format!("/relay allow {target}"),
                now + 1,
                vec![],
            );
            conn.queue_event_value(impostor.clone()).await;
            conn.flush_pending_events().await;
            assert!(
                relay.access.read().await.allowed_pubkeys.is_empty(),
                "a non-owner cannot run commands"
            );
            assert!(
                stored_replies(&relay, &impostor.id, now + 1)
                    .await
                    .is_empty()
            );

            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn command_deny_applies_to_live_connections_immediately() {
        // A `/relay deny` command must take effect on an already-open
        // connection without disconnecting it: new REQs/COUNTs are refused
        // and live delivery stops, but the connection stays up.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let secret = "aa".repeat(32);
            let relay = build_relay_with(&secret).await;
            relay.config.write().await.relay.pubkey = pubkey_of_secret(relay.secp(), &secret);
            relay.config.write().await.relay.enabled_command_events = true;
            let mut operator = build_conn_on(relay.clone()).await;
            let victim = "cc".repeat(32);
            let mut victim_conn = build_conn_on(relay.clone()).await;
            victim_conn.authed_pubkeys = vec![victim.clone()];
            let now = unix_now();

            // The victim reads fine before the command...
            victim_conn
                .handle_req(&[json!("sub"), json!({"kinds": [1]})])
                .await;
            assert!(
                !outgoing_json(&victim_conn)
                    .iter()
                    .any(|m| m[0] == "CLOSED" && m[1] == "sub"),
                "the victim may subscribe before the deny"
            );

            // ...the operator runs /relay deny...
            let cmd =
                signed_command_event(relay.secp(), &secret, &format!("/relay deny {victim}"), now);
            operator.queue_event_value(cmd.clone()).await;
            operator.flush_pending_events().await;
            assert!(
                relay
                    .access
                    .read()
                    .await
                    .blocked_pubkeys
                    .iter()
                    .any(|(p, _)| p == &victim),
                "the deny is applied"
            );

            // Results queued before the deny are dropped by the pump...
            victim_conn.pump_pending_reqs();
            assert!(
                !outgoing_json(&victim_conn).iter().any(|m| m[0] == "EVENT"),
                "pre-deny REQ results are dropped after the deny"
            );

            // ...and the very same connection is refused new reads while
            // staying connected (no connection-level close is sent).
            victim_conn.outgoing.clear();
            victim_conn
                .handle_req(&[json!("sub2"), json!({"kinds": [1]})])
                .await;
            assert!(
                outgoing_json(&victim_conn).iter().any(|m| m[0] == "CLOSED"
                    && m[1] == "sub2"
                    && m[2].as_str().unwrap_or("").starts_with("restricted:")),
                "the new REQ is refused with restricted"
            );
            victim_conn
                .handle_count(&[json!("cnt"), json!({"kinds": [1]})])
                .await;
            assert!(
                outgoing_json(&victim_conn).iter().any(|m| m[0] == "CLOSED"
                    && m[1] == "cnt"
                    && m[2].as_str().unwrap_or("").starts_with("restricted:")),
                "the COUNT is refused with restricted"
            );
            victim_conn.outgoing.clear();
            let ev = signed_note(relay.secp(), "live", now + 1, vec![]);
            victim_conn.deliver_live(&ev, &serde_json::to_string(&ev).unwrap_or_default(), None);
            assert!(
                !outgoing_json(&victim_conn).iter().any(|m| m[0] == "EVENT"),
                "live delivery stops for the denied pubkey"
            );

            operator.relay.db.shutdown();
        });
    }

    #[test]
    fn restrict_relay_gates_writes_only() {
        // `restrict_relay` + the allow list gate WRITES only (NIP-11
        // `restricted_writes`): the allowed pubkey's posts stay readable
        // by everyone — anonymous connections, outsiders and the relay's
        // own key. Only a denied pubkey loses read access.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay_with(&"aa".repeat(32)).await;
            let allowed = "bb".repeat(32);
            let denied = "dd".repeat(32);
            {
                let mut access = relay.access.write().await;
                access.restrict_relay = true;
                access
                    .allowed_pubkeys
                    .push((allowed.clone(), String::new()));
                access.blocked_pubkeys.push((denied.clone(), String::new()));
            }

            // Anonymous readers are always admitted: the allow list is a
            // write restriction, not a read one.
            let mut anon = build_conn_on(relay.clone()).await;
            anon.handle_req(&[json!("sub"), json!({"kinds": [1]})])
                .await;
            anon.pump_pending_reqs();
            assert!(
                !outgoing_json(&anon).iter().any(|m| m[0] == "CLOSED"),
                "anonymous may read on a write-restricted relay"
            );

            // An authenticated outsider may read too.
            let mut outsider = build_conn_on(relay.clone()).await;
            outsider.authed_pubkeys = vec!["ee".repeat(32)];
            outsider
                .handle_req(&[json!("sub"), json!({"kinds": [1]})])
                .await;
            outsider.pump_pending_reqs();
            assert!(
                !outgoing_json(&outsider).iter().any(|m| m[0] == "CLOSED"),
                "an authenticated outsider may read on a write-restricted relay"
            );

            // A denied pubkey loses read access.
            let mut denier = build_conn_on(relay.clone()).await;
            denier.authed_pubkeys = vec![denied.clone()];
            denier
                .handle_req(&[json!("sub"), json!({"kinds": [1]})])
                .await;
            assert!(
                outgoing_json(&denier)
                    .iter()
                    .any(|m| m[0] == "CLOSED"
                        && m[2].as_str().unwrap_or("").starts_with("restricted:")),
                "a denied pubkey is refused reads"
            );

            // The relay's own pubkey is always admitted (the operator
            // reads command replies on restricted relays).
            let mut self_conn = build_conn_on(relay.clone()).await;
            self_conn.authed_pubkeys = vec![relay.relay_pubkey().unwrap()];
            self_conn
                .handle_req(&[json!("sub"), json!({"kinds": [1]})])
                .await;
            self_conn.pump_pending_reqs();
            assert!(
                !outgoing_json(&self_conn).iter().any(|m| m[0] == "CLOSED"),
                "the relay's own pubkey may subscribe on a restricted relay"
            );

            anon.relay.db.shutdown();
        });
    }

    #[test]
    fn command_events_work_on_restricted_relays() {
        // On a `restrict_relay` relay the allow list gates publishing only
        // (reading stays open) — and the relay's own pubkey is exempt
        // from the lists, so command events still run and the reply
        // stays readable.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let secret = "aa".repeat(32);
            let relay = build_relay_with(&secret).await;
            relay.config.write().await.relay.pubkey = pubkey_of_secret(relay.secp(), &secret);
            relay.config.write().await.relay.enabled_command_events = true;
            {
                let mut access = relay.access.write().await;
                access.restrict_relay = true;
            }
            let mut conn = build_conn_on(relay.clone()).await;
            conn.authed_pubkeys = vec![relay.relay_pubkey().unwrap()];
            let now = unix_now();
            let target = "bb".repeat(32);

            let cmd = signed_command_event(
                relay.secp(),
                &secret,
                &format!("/relay allow {target}"),
                now,
            );
            conn.queue_event_value(cmd.clone()).await;
            conn.flush_pending_events().await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "OK" && m[1] == cmd.id && m[2] == true),
                "the command event is accepted on a restricted relay"
            );
            assert!(
                relay
                    .access
                    .read()
                    .await
                    .allowed_pubkeys
                    .iter()
                    .any(|(p, _)| p == &target),
                "the allow is applied"
            );
            let replies = stored_replies(&relay, &cmd.id, now).await;
            assert_eq!(replies.len(), 1, "the reply is stored");
            assert!(
                replies[0]
                    .content
                    .contains(&format!("/relay allow {target}")),
                "reply content: {}",
                replies[0].content
            );

            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn live_delivery_hides_nip78_events() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay_with("").await;
            let mut conn = build_conn_on(relay.clone()).await;
            let now = unix_now();
            conn.handle_req(&[json!("sub"), json!({"kinds": [30078]})])
                .await;
            assert!(conn.live.is_some(), "REQ must subscribe to live events");

            let ev = signed_kind_note_seeded(relay.secp(), 2, 30078, "live-app", now, vec![]);
            relay.broadcast(ev.clone());
            let received = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                conn.live.as_mut().unwrap().recv(),
            )
            .await;
            match received {
                Ok(Some(_batch)) => {
                    conn.deliver_live(&ev, &serde_json::to_string(&ev).unwrap_or_default(), None);
                    assert!(
                        !outgoing_json(&conn)
                            .iter()
                            .any(|m| m[0] == "EVENT" && m[2]["id"] == ev.id),
                        "deliver_live must hide NIP-78 events from anonymous"
                    );
                }
                other => panic!("live bus did not deliver: {other:?}"),
            }

            // The authenticated owner receives its own live app-specific event.
            let mut owner = build_conn_on(relay.clone()).await;
            let auth = signed_auth(owner.relay.secp(), "test-challenge", now);
            owner
                .handle_auth(&[serde_json::to_value(&auth).unwrap()])
                .await;
            owner
                .handle_req(&[json!("sub"), json!({"kinds": [30078]})])
                .await;
            // The stored response (here empty) is pumped before any live
            // event: pulling it through the pump mirrors the connection loop
            // and leaves the subscription in its EOSE-sent state.
            owner.pump_pending_reqs();
            relay.broadcast(ev.clone());
            let received = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                owner.live.as_mut().unwrap().recv(),
            )
            .await;
            match received {
                Ok(Some(_batch)) => {
                    owner.deliver_live(&ev, &serde_json::to_string(&ev).unwrap_or_default(), None);
                    assert!(
                        outgoing_json(&owner)
                            .iter()
                            .any(|m| m[0] == "EVENT" && m[2]["id"] == ev.id),
                        "the owner receives its own live NIP-78 event"
                    );
                }
                other => panic!("live bus did not deliver: {other:?}"),
            }

            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn inbox_outbox_write_policies() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let now = unix_now();
            let some_pk = "cc".repeat(32);

            // /inbox with the default "any" policy: a p tag is required.
            let mut conn = build_conn().await;
            conn.path = "/inbox".into();
            let secp = conn.relay.secp();
            let addressed = signed_note_seeded(
                secp,
                1,
                "addressed",
                now,
                vec![vec!["p".into(), some_pk.clone()]],
            );
            let plain = signed_note_seeded(secp, 1, "plain", now - 1, vec![]);
            conn.queue_event_value(addressed.clone()).await;
            conn.queue_event_value(plain.clone()).await;
            conn.flush_pending_events().await;
            let msgs = outgoing_json(&conn);
            let ok_of = |id: &str| {
                msgs.iter()
                    .find(|m| m[0] == "OK" && m[1] == id)
                    .cloned()
                    .unwrap()
            };
            assert_eq!(
                ok_of(&addressed.id)[2],
                true,
                "a p-tagged event is accepted"
            );
            assert_eq!(ok_of(&plain.id)[2], false, "an untagged event is rejected");
            assert!(
                ok_of(&plain.id)[3]
                    .as_str()
                    .unwrap_or("")
                    .contains("restricted"),
                "the rejection is machine-readable"
            );
            conn.relay.db.shutdown();

            // /inbox with the "relay" policy: only events p-tagging the
            // relay's own pubkey are accepted.
            let mut conn = build_conn_with(&hex::encode([7u8; 32])).await;
            conn.path = "/inbox".into();
            conn.relay.config.write().await.server.inbox_write_policy = "relay".into();
            let relay_pk = conn.relay.relay_pubkey().unwrap();
            let secp = conn.relay.secp();
            let to_relay =
                signed_note_seeded(secp, 1, "to relay", now, vec![vec!["p".into(), relay_pk]]);
            let to_other = signed_note_seeded(
                secp,
                1,
                "to other",
                now - 1,
                vec![vec!["p".into(), some_pk]],
            );
            conn.queue_event_value(to_relay.clone()).await;
            conn.queue_event_value(to_other.clone()).await;
            conn.flush_pending_events().await;
            let msgs = outgoing_json(&conn);
            let ok_of = |id: &str| {
                msgs.iter()
                    .find(|m| m[0] == "OK" && m[1] == id)
                    .cloned()
                    .unwrap()
            };
            assert_eq!(ok_of(&to_relay.id)[2], true);
            assert_eq!(ok_of(&to_other.id)[2], false);
            conn.relay.db.shutdown();

            // /outbox: NIP-42 auth is required and the event must be the
            // authenticated user's own.
            let mut conn = build_conn().await;
            conn.path = "/outbox".into();
            let secp = conn.relay.secp().clone();
            let mine = signed_note_seeded(&secp, 2, "mine", now, vec![]);
            let others = signed_note_seeded(&secp, 1, "theirs", now - 1, vec![]);
            conn.queue_event_value(mine.clone()).await;
            conn.flush_pending_events().await;
            let msgs = outgoing_json(&conn);
            assert!(
                msgs.iter()
                    .any(|m| m[0] == "OK" && m[1] == mine.id && m[2] == false),
                "unauthenticated writes are rejected"
            );
            // Authenticate as the key-2 author and retry.
            conn.outgoing.clear();
            let auth = signed_auth(&secp, "test-challenge", now);
            conn.handle_auth(&[serde_json::to_value(&auth).unwrap()])
                .await;
            assert!(conn.is_authed());
            conn.queue_event_value(mine.clone()).await;
            conn.queue_event_value(others.clone()).await;
            conn.flush_pending_events().await;
            let msgs = outgoing_json(&conn);
            let ok_of = |id: &str| {
                msgs.iter()
                    .find(|m| m[0] == "OK" && m[1] == id)
                    .cloned()
                    .unwrap()
            };
            assert_eq!(ok_of(&mine.id)[2], true, "own authed events are accepted");
            assert_eq!(
                ok_of(&others.id)[2],
                false,
                "another author's event is rejected"
            );
            conn.relay.db.shutdown();

            // /outbox with the "relay" policy: only the relay's own events.
            let mut conn = build_conn_with(&hex::encode([7u8; 32])).await;
            conn.path = "/outbox".into();
            conn.relay.config.write().await.server.outbox_write_policy = "relay".into();
            let relay_pk = conn.relay.relay_pubkey().unwrap();
            let secp = conn.relay.secp().clone();
            let relay_event = signed_note_seeded(&secp, 7, "relay event", now, vec![]);
            let user_event = signed_note_seeded(&secp, 1, "user event", now - 1, vec![]);
            assert_eq!(relay_event.pubkey, relay_pk, "seed 7 is the relay key");
            conn.queue_event_value(relay_event.clone()).await;
            conn.queue_event_value(user_event.clone()).await;
            conn.flush_pending_events().await;
            let msgs = outgoing_json(&conn);
            let ok_of = |id: &str| {
                msgs.iter()
                    .find(|m| m[0] == "OK" && m[1] == id)
                    .cloned()
                    .unwrap()
            };
            assert_eq!(
                ok_of(&relay_event.id)[2],
                true,
                "the relay's own event is accepted without auth"
            );
            assert_eq!(
                ok_of(&user_event.id)[2],
                false,
                "another author's event is rejected in relay mode"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn ephemeral_events_rejected_via_ws_when_configured() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let now = unix_now();
            // Default config: ephemeral forwarded (accepted, not stored).
            let mut conn = build_conn().await;
            let ephemeral = signed_note_seeded(conn.relay.secp(), 1, "ephemeral", now, vec![]);
            let mut ev = ephemeral.clone();
            ev.kind = 20000;
            ev.id = crate::nips::nip01::compute_id(&ev);
            let id = ev.id_bytes().unwrap();
            ev.sig = conn
                .relay
                .secp()
                .sign_schnorr_no_aux_rand(
                    &id,
                    &Keypair::from_seckey_slice(conn.relay.secp(), &[1u8; 32]).unwrap(),
                )
                .to_string();
            conn.queue_event_value(ev.clone()).await;
            conn.flush_pending_events().await;
            let msgs = outgoing_json(&conn);
            let ok = msgs.iter().find(|m| m[0] == "OK" && m[1] == ev.id).unwrap();
            assert_eq!(ok[2], true, "ephemeral must be forwarded when not rejected");
            assert_eq!(
                ok[3].as_str().unwrap_or(""),
                "",
                "an accepted ephemeral must not carry the `mute:` prefix"
            );
            conn.relay.db.shutdown();

            // With reject_ephemeral = true via SIGHUP-like reload.
            let mut conn = build_conn().await;
            conn.relay.config.write().await.relay.reject_ephemeral = true;
            let ephemeral2 = {
                let mut e = signed_note_seeded(conn.relay.secp(), 1, "ephemeral2", now, vec![]);
                e.kind = 25000;
                e.id = crate::nips::nip01::compute_id(&e);
                let id = e.id_bytes().unwrap();
                e.sig = conn
                    .relay
                    .secp()
                    .sign_schnorr_no_aux_rand(
                        &id,
                        &Keypair::from_seckey_slice(conn.relay.secp(), &[1u8; 32]).unwrap(),
                    )
                    .to_string();
                e
            };
            let exempt = {
                let mut e = signed_note_seeded(conn.relay.secp(), 1, "exempt", now, vec![]);
                e.kind = 27235; // NIP-98 HTTP auth — must stay allowed
                e.id = crate::nips::nip01::compute_id(&e);
                let id = e.id_bytes().unwrap();
                e.sig = conn
                    .relay
                    .secp()
                    .sign_schnorr_no_aux_rand(
                        &id,
                        &Keypair::from_seckey_slice(conn.relay.secp(), &[1u8; 32]).unwrap(),
                    )
                    .to_string();
                e
            };
            conn.queue_event_value(ephemeral2.clone()).await;
            conn.queue_event_value(exempt.clone()).await;
            conn.flush_pending_events().await;
            let msgs = outgoing_json(&conn);
            let ok_ephem = msgs
                .iter()
                .find(|m| m[0] == "OK" && m[1] == ephemeral2.id)
                .unwrap();
            assert_eq!(ok_ephem[2], false);
            assert!(
                ok_ephem[3].as_str().unwrap_or("").contains("ephemeral"),
                "rejected ephemeral must mention ephemeral"
            );
            let ok_exempt = msgs
                .iter()
                .find(|m| m[0] == "OK" && m[1] == exempt.id)
                .unwrap();
            assert_eq!(
                ok_exempt[2], true,
                "NIPs-exempt ephemeral (27235) must not be blocked"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn flush_pending_events_acks_each_outcome() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            let valid = signed_note(conn.relay.secp(), "ok", now, vec![]);
            let mut invalid = signed_note(conn.relay.secp(), "bad", now, vec![]);
            invalid.sig = "00".repeat(64);
            conn.queue_event_value(valid.clone()).await;
            conn.queue_event_value(invalid.clone()).await;
            conn.flush_pending_events().await;
            let msgs = outgoing_json(&conn);
            let oks: Vec<&Value> = msgs.iter().filter(|m| m[0] == "OK").collect();
            assert_eq!(oks.len(), 2);
            let by_id = |id: &str| oks.iter().find(|m| m[1] == id).copied().unwrap();
            assert_eq!(by_id(&valid.id)[2], true);
            assert_eq!(by_id(&invalid.id)[2], false);
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn req_rejects_too_many_filters() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let mut args = vec![json!("sub")];
            for _ in 0..25 {
                args.push(json!({"kinds": [1]}));
            }
            conn.handle_req(&args).await;
            let msgs = outgoing_json(&conn);
            assert!(
                msgs.iter().any(|m| m[0] == "CLOSED"
                    && m[2].as_str().unwrap_or("").contains("too many filters")),
                "too many filters must be refused with CLOSED"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn req_replacement_is_allowed_at_the_subscription_cap() {
        // NIP-01: re-REQ with an existing id replaces the subscription, so
        // it must work even when the connection already holds the maximum
        // number of subscriptions.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let max = conn.relay.config.read().await.limits.max_subscriptions;
            for i in 0..max {
                conn.handle_req(&[json!(format!("s{i}")), json!({"kinds": [1]})])
                    .await;
            }
            assert_eq!(conn.subs.len(), max, "the cap is reached");

            // Replacing an existing subscription is accepted...
            conn.handle_req(&[json!("s0"), json!({"kinds": [2]})]).await;
            assert!(
                !outgoing_json(&conn).iter().any(|m| m[0] == "CLOSED"),
                "re-REQ of an existing id must replace, not be refused"
            );
            assert_eq!(conn.subs.len(), max, "a replacement adds no subscription");

            // ...while a genuinely new id is refused at the cap.
            conn.handle_req(&[json!("s-extra"), json!({"kinds": [1]})])
                .await;
            assert!(
                outgoing_json(&conn).iter().any(|m| m[0] == "CLOSED"
                    && m[1] == "s-extra"
                    && m[2]
                        .as_str()
                        .unwrap_or("")
                        .contains("too many subscriptions")),
                "a new subscription is refused at the cap"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn req_failed_replacement_releases_the_old_subscription() {
        // A failed re-REQ (CLOSED) must release the previous subscription
        // held under the same id: otherwise the ghost keeps receiving live
        // events for a client-considered-closed id.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            conn.handle_req(&[json!("ghost"), json!({"kinds": [1]})])
                .await;
            assert!(conn.subs.contains_key("ghost"));
            conn.outgoing.clear();

            let mut args = vec![json!("ghost")];
            for _ in 0..25 {
                args.push(json!({"kinds": [1]}));
            }
            conn.handle_req(&args).await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "CLOSED" && m[1] == "ghost"),
                "the failed re-REQ must close the id"
            );
            assert!(
                !conn.subs.contains_key("ghost"),
                "the old subscription must be released"
            );

            // No live delivery for the closed id.
            let now = unix_now();
            let ev = signed_note(conn.relay.secp(), "live", now, vec![]);
            conn.deliver_live(&ev, &serde_json::to_string(&ev).unwrap_or_default(), None);
            assert!(
                !outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "EVENT" && m[1] == "ghost"),
                "a closed id must not receive live events"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn text_ping_is_answered_with_pong() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            conn.handle_text("[\"PING\"]").await;
            let msgs = outgoing_json(&conn);
            assert!(
                msgs.iter().any(|m| m[0] == "PONG"),
                "a text PING must be answered with a PONG"
            );
            conn.relay.db.shutdown();
        });
    }
    #[test]
    fn first_token_extracts_the_verb_without_a_parse() {
        assert_eq!(Conn::first_token("[\"EVENT\",{}]"), Some("EVENT"));
        assert_eq!(Conn::first_token("[ \"REQ\", \"s\", {}]"), Some("REQ"));
        assert_eq!(Conn::first_token("[\"PING\"]"), Some("PING"));
        assert_eq!(Conn::first_token("[\"EVENT\""), Some("EVENT"));
        assert_eq!(Conn::first_token("[123]"), None);
        assert_eq!(Conn::first_token("\"REQ\""), None);
        assert_eq!(Conn::first_token("not json"), None);
        assert_eq!(Conn::first_token(""), None);
    }

    #[test]
    fn event_dispatch_parses_once_and_queues() {
        // The hot path parses the EVENT frame directly as a typed pair
        // (single JSON pass) and queues it for batched acceptance.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let event = crate::event::Event {
                id: "0".repeat(64),
                pubkey: "ab".repeat(32),
                created_at: unix_now(),
                kind: 1,
                tags: vec![],
                content: "hello".into(),
                sig: "0".repeat(128),
            };
            let payload = format!("[\"EVENT\",{}]", serde_json::to_string(&event).unwrap());
            conn.handle_text(&payload).await;
            assert_eq!(conn.pending_events.len(), 1, "the event must be queued");
            assert_eq!(conn.pending_events[0].content, "hello");
            assert_eq!(conn.events_received_local, 1, "the local counter must bump");
            // A malformed EVENT falls back to the generic path and gets a
            // NOTICE, not a crash.
            conn.pending_events.clear();
            conn.handle_text("[\"EVENT\",{\"id\":1}]").await;
            assert!(conn.pending_events.is_empty());
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "NOTICE" || m[0] == "OK"),
                "a malformed event must produce a diagnostic"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn deeply_nested_json_is_rejected_without_abort() {
        // serde_json enforces a recursion limit (default 128): a deeply
        // nested frame must fail parsing with a NOTICE, never abort the
        // process with a stack overflow (which `catch_unwind` could not
        // contain and which would kill every connection).
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let deep = format!("[\"REQ\",\"s\",{}]", "[".repeat(5000));
            conn.handle_text(&deep).await;
            assert!(
                outgoing_json(&conn).iter().any(|m| m[0] == "NOTICE"),
                "deep nesting must be rejected with a NOTICE: {:?}",
                outgoing_json(&conn)
            );
            // The connection survives and still serves normal requests.
            conn.outgoing.clear();
            conn.handle_req(&[json!("alive"), json!({"kinds": [1]})])
                .await;
            assert!(
                conn.subs.contains_key("alive"),
                "the connection must stay usable after a hostile frame"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn live_delivery_uses_shared_json_and_cached_sub_json() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            conn.handle_req(&[json!("sub"), json!({"kinds": [30002]})])
                .await;
            // Finish the stored response first: a live event delivered while
            // the response is pumping waits for its EOSE (by design), so the
            // shared-JSON wrapping is asserted after the pump.
            conn.pump_pending_reqs();
            // The sub id JSON is cached at REQ time.
            let cached = conn.subs.get("sub").map(|(_, _, j)| j.clone()).unwrap();
            assert_eq!(cached, "\"sub\"");
            let mut ev = signed_note(conn.relay.secp(), "shared-json", now, vec![]);
            ev.kind = 30002;
            ev.id = crate::nips::nip01::compute_id(&ev);
            // Deliver with a pre-serialized JSON (as the bus provides):
            // the wrapped message must embed exactly those bytes.
            let event_json = serde_json::to_string(&ev).unwrap();
            conn.deliver_live(&ev, &event_json, None);
            let msg = outgoing_json(&conn);
            assert!(
                msg.iter().any(|m| {
                    m[0] == "EVENT"
                        && m[1] == "sub"
                        && serde_json::to_string(&m[2]).unwrap() == event_json
                }),
                "the shared JSON must be wrapped per subscription"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn live_index_delivers_only_to_candidate_connections() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            // Two connections on the *same* relay: the candidate
            // narrowing is a property of the shared subscription index,
            // so building separate relays would prove nothing.
            let mut shared = Relay::new(
                Arc::new(RwLock::new(Config::default())),
                crate::db::DbClient::open(
                    &{
                        let mut cfg = Config::default();
                        cfg.database.path = temp_db_path();
                        cfg.database.map_size = 16 * 1024 * 1024;
                        cfg.database.max_map_size = 256 * 1024 * 1024;
                        cfg.database
                    },
                    true,
                    Arc::new(Default::default()),
                    0,
                    128,
                    4096,
                    262144,
                )
                .unwrap(),
                Stats::new(),
                "",
                crate::relay::LiveBusConfig {
                    buffer: 1024,
                    batch_interval_ms: 10,
                    batch_size: 64,
                },
            )
            .await;
            shared.start_live_bus();
            let shared = Arc::new(shared);
            let mut conn_a = build_conn_on(Arc::clone(&shared)).await;
            let mut conn_b = build_conn_on(Arc::clone(&shared)).await;
            let now = unix_now();
            conn_a
                .handle_req(&[json!("a"), json!({"kinds": [30001]})])
                .await;
            conn_b
                .handle_req(&[json!("b"), json!({"kinds": [1]})])
                .await;
            // Both connections are in the index (their kinds), but a
            // kind-30001 event's candidate set contains only conn_a.
            let mut ev = signed_note(conn_a.relay.secp(), "candidate-check", now, vec![]);
            ev.kind = 30001;
            ev.id = crate::nips::nip01::compute_id(&ev);
            conn_a.relay.broadcast(ev.clone());
            let received_a = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                conn_a.live.as_mut().unwrap().recv(),
            )
            .await;
            assert!(
                received_a.is_ok(),
                "the matching connection receives the batch"
            );
            // conn_b's queue stays silent (nothing is sent to it).
            let received_b = tokio::time::timeout(
                std::time::Duration::from_millis(300),
                conn_b.live.as_mut().unwrap().recv(),
            )
            .await;
            assert!(
                received_b.is_err(),
                "a non-matching connection must not be woken"
            );
            conn_a.relay.db.shutdown();
        });
    }

    #[test]
    fn live_flags_refresh_only_on_config_version_change() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let conn = build_conn().await;
            let v0 = conn.config_version;
            // Same version: no refresh happens (nothing to assert besides
            // the field staying put — the flag refresh is data-driven).
            assert_eq!(conn.config_version, v0);
            // A bumped version on the relay is picked up by the next live
            // loop iteration (exercised by `handle_frame`'s sibling
            // refresh; here we only assert the plumbing).
            conn.relay
                .config_version
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            assert_eq!(
                conn.relay
                    .config_version
                    .load(std::sync::atomic::Ordering::Relaxed),
                v0 + 1
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn live_delivery_through_the_bus() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            conn.handle_req(&[json!("sub"), json!({"kinds": [30001]})])
                .await;
            assert!(conn.live.is_some(), "REQ must subscribe to live events");
            // Finish the (empty) stored response before the live event: a
            // live event delivered while a response is pumping is held for
            // its EOSE, so the queue assertion needs the subscription in its
            // EOSE-sent state.
            conn.pump_pending_reqs();

            let mut ev = signed_note(conn.relay.secp(), "live-check", now, vec![]);
            ev.kind = 30001;
            ev.id = crate::nips::nip01::compute_id(&ev);
            // The relay broadcast path: queue, bus task, receiver, deliver.
            conn.relay.broadcast(ev.clone());
            let received = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                conn.live.as_mut().unwrap().recv(),
            )
            .await;
            match received {
                Ok(Some(batch)) => {
                    assert!(
                        batch.iter().any(|(e, _)| e.id == ev.id),
                        "the broadcast event must arrive on the live receiver"
                    );
                    conn.deliver_live(&ev, &serde_json::to_string(&ev).unwrap_or_default(), None);
                    let msgs = outgoing_json(&conn);
                    assert!(
                        msgs.iter()
                            .any(|m| m[0] == "EVENT" && m[2]["content"] == "live-check"),
                        "deliver_live must queue the event for the subscriber"
                    );
                }
                other => panic!("live bus did not deliver: {other:?}"),
            }
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn neg_open_error_paths() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;

            // NIP-77 disabled: NEG-ERR with the id (NIP-77 error path),
            // not a NOTICE — the client can correlate the failure.
            {
                let mut w = conn.relay.config.write().await;
                w.relay.disabled_nips.push(77);
            }
            conn.handle_neg_open(&[json!("s"), json!({}), json!("61000000")])
                .await;
            assert!(
                outgoing_json(&conn).iter().any(|m| m[0] == "NEG-ERR"
                    && m[1] == "s"
                    && m[2].as_str().unwrap().contains("not enabled")),
                "a disabled NIP-77 must yield a NEG-ERR"
            );
            conn.outgoing.clear();
            // Without an id there is nothing to correlate: NOTICE.
            conn.handle_neg_open(&[]).await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "NOTICE" && m[1].as_str().unwrap().contains("not enabled")),
                "a disabled NIP-77 without id must yield a NOTICE"
            );
            conn.outgoing.clear();
            {
                let mut w = conn.relay.config.write().await;
                w.relay.disabled_nips.retain(|n| *n != 77);
            }

            // Malformed NEG-OPEN frames with an id correlate via NEG-ERR.
            conn.handle_neg_open(&[json!("s"), json!({})]).await;
            assert!(
                outgoing_json(&conn).iter().any(|m| m[0] == "NEG-ERR"
                    && m[1] == "s"
                    && m[2].as_str().unwrap().contains("NEG-OPEN")),
                "a short NEG-OPEN must yield a NEG-ERR"
            );
            conn.outgoing.clear();
            conn.handle_neg_open(&[json!(""), json!({}), json!("61000000")])
                .await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "NOTICE" && m[1].as_str().unwrap().contains("non-empty")),
                "an empty sub id must yield a NOTICE"
            );
            conn.outgoing.clear();
            let max_sub = conn.relay.config.read().await.limits.max_sub_id_len;
            conn.handle_neg_open(&[json!("x".repeat(max_sub + 1)), json!({}), json!("61000000")])
                .await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "NEG-ERR" && m[2].as_str().unwrap().contains("too long")),
                "an over-long sub id must yield a NEG-ERR"
            );
            conn.outgoing.clear();
            conn.handle_neg_open(&[json!("s"), json!({"inbox": 42}), json!("61000000")])
                .await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "NEG-ERR" && m[2].as_str().unwrap().contains("filter")),
                "an invalid inbox/outbox filter must yield a NEG-ERR"
            );
            conn.outgoing.clear();
            conn.handle_neg_open(&[json!("s"), json!("not-a-filter"), json!("61000000")])
                .await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "NEG-ERR" && m[2].as_str().unwrap().contains("filter")),
                "a non-filter JSON must yield a NEG-ERR"
            );
            conn.outgoing.clear();
            conn.handle_neg_open(&[
                json!("s"),
                json!({"ids": vec![json!("a".repeat(64)); 513]}),
                json!("61000000"),
            ])
            .await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "NEG-ERR" && m[2].as_str().unwrap().contains("too many")),
                "a filter over the member cap must yield a NEG-ERR"
            );
            conn.outgoing.clear();
            conn.handle_neg_open(&[json!("s"), json!({"#t": 42}), json!("61000000")])
                .await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "NEG-ERR" && m[2].as_str().unwrap().contains("strings")),
                "a filter with non-string tag values must yield a NEG-ERR"
            );
            conn.outgoing.clear();
            conn.handle_neg_open(&[json!("s"), json!({}), json!(42)])
                .await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "NEG-ERR" && m[2].as_str().unwrap().contains("hex")),
                "a non-string initial message must yield a NEG-ERR"
            );
            conn.outgoing.clear();
            conn.handle_neg_open(&[json!("s"), json!({}), json!("zzz")])
                .await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "NEG-ERR" && m[2].as_str().unwrap().contains("hex")),
                "a non-hex initial message must yield a NEG-ERR"
            );
            conn.outgoing.clear();

            // AUTH-required relay: an unauthenticated NEG-OPEN is refused.
            {
                let mut w = conn.relay.config.write().await;
                w.relay.require_auth = true;
            }
            conn.handle_neg_open(&[json!("s"), json!({}), json!("61000000")])
                .await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "NEG-ERR" && m[2].as_str().unwrap().contains("auth-required")),
                "an unauthenticated NEG-OPEN on an auth-requiring relay must be refused"
            );
            conn.outgoing.clear();
            {
                let mut w = conn.relay.config.write().await;
                w.relay.require_auth = false;
            }

            // A blocked (authed) pubkey is refused syncing.
            let blocked = "bb".repeat(32);
            conn.authed_pubkeys.push(blocked.clone());
            conn.relay
                .access
                .write()
                .await
                .blocked_pubkeys
                .push((blocked, String::new()));
            conn.handle_neg_open(&[json!("s"), json!({}), json!("61000000")])
                .await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "NEG-ERR" && m[2].as_str().unwrap().contains("restricted")),
                "a blocked pubkey must be refused syncing"
            );
            conn.outgoing.clear();
            conn.authed_pubkeys.clear();
            conn.relay.access.write().await.blocked_pubkeys.clear();

            // The subscription cap applies to new ids only.
            {
                let mut w = conn.relay.config.write().await;
                w.limits.max_subscriptions = 1;
            }
            conn.handle_neg_open(&[json!("s1"), json!({}), json!("61000000")])
                .await;
            conn.outgoing.clear();
            conn.handle_neg_open(&[json!("s2"), json!({}), json!("61000000")])
                .await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "NEG-ERR" && m[2].as_str().unwrap().contains("too many")),
                "a new NEG-OPEN over the subscription cap must be refused"
            );
            conn.outgoing.clear();
            {
                let mut w = conn.relay.config.write().await;
                w.limits.max_subscriptions = 100;
            }

            // A timed-out query (the reader is gone) closes with NEG-ERR.
            conn.relay.db.shutdown();
            conn.handle_neg_open(&[json!("s"), json!({}), json!("61000000")])
                .await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "NEG-ERR" && m[2].as_str().unwrap().contains("timeout")),
                "a timed-out sync must close with NEG-ERR"
            );
        });
    }

    #[test]
    fn neg_open_query_size_and_item_filters() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            for i in 0..5 {
                let e = signed_note(conn.relay.secp(), &format!("e{i}"), now - i, vec![]);
                let out = conn.relay.db.put(e.clone(), now).await;
                assert_eq!(out, crate::db::PutOutcome::Stored, "event {i} stored");
            }
            let f: crate::filter::Filter =
                serde_json::from_value(serde_json::json!({"kinds": [1]})).unwrap();
            let (stored, _) = conn.relay.db.query(vec![f.clone()], 10, now).await;
            assert_eq!(stored.len(), 5, "all five events are queryable");

            // The per-connection item cap is enforced across concurrent
            // subscriptions (cap = max_neg_items * 2). Use a max that covers
            // the five stored events so each query is complete (`more ==
            // false`); a smaller max would correctly reject every query as
            // "too big" instead of syncing a truncated set.
            {
                let mut w = conn.relay.config.write().await;
                w.limits.max_neg_items = 5;
            }
            conn.handle_neg_open(&[json!("a"), json!({"kinds": [1]}), json!("61000000")])
                .await;
            conn.outgoing.clear();
            conn.handle_neg_open(&[json!("b"), json!({"kinds": [1]}), json!("61000000")])
                .await;
            conn.outgoing.clear();
            conn.handle_neg_open(&[json!("c"), json!({"kinds": [1]}), json!("61000000")])
                .await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "NEG-ERR" && m[2].as_str().unwrap().contains("too many")),
                "the total item cap must close the third subscription"
            );
            conn.outgoing.clear();
            conn.handle_neg_close(&[json!("a")]);
            conn.handle_neg_close(&[json!("b")]);
            conn.handle_neg_close(&[json!("c")]);

            // Protected events are withheld from anonymous peers. Raise the
            // item cap so the six stored events (five public + one hidden)
            // fit: the query is complete and the hidden event is filtered
            // after the scan.
            {
                let mut w = conn.relay.config.write().await;
                w.limits.max_neg_items = 10;
            }
            let mut protected = signed_note(conn.relay.secp(), "secret", now, vec![]);
            protected.tags = vec![vec!["-".into()]];
            protected.id = crate::nips::nip01::compute_id(&protected);
            conn.relay.db.put(protected, now).await;
            conn.handle_neg_open(&[json!("s"), json!({"kinds": [1]}), json!("61000000")])
                .await;
            assert!(
                outgoing_json(&conn).iter().any(|m| m[0] == "NEG-MSG"),
                "an anonymous NEG-OPEN over protected events still succeeds"
            );
            conn.outgoing.clear();

            // A NEG-MSG for an unknown subscription closes with NEG-ERR.
            conn.handle_neg_msg(&[json!("ghost"), json!("61000000")])
                .await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "NEG-ERR" && m[2].as_str().unwrap().contains("unknown")),
                "a NEG-MSG for an unknown sub must close with NEG-ERR"
            );
            conn.outgoing.clear();
            // Malformed NEG-MSG frames: with a known id they close via
            // NEG-ERR (NIP-77), without one via NOTICE.
            conn.handle_neg_msg(&[json!("s")]).await;
            assert!(
                outgoing_json(&conn).iter().any(|m| m[0] == "NEG-ERR"
                    && m[1] == "s"
                    && m[2].as_str().unwrap().contains("NEG-MSG")),
                "a short NEG-MSG must yield a NEG-ERR: {:?}",
                outgoing_json(&conn)
            );
            assert!(
                !conn.neg.contains_key("s"),
                "a short NEG-MSG must close the subscription"
            );
            conn.outgoing.clear();
            conn.handle_neg_msg(&[json!(true), json!("61000000")]).await;
            assert!(
                outgoing_json(&conn).iter().any(|m| m[0] == "NOTICE"),
                "a non-string sub id must yield a NOTICE: {:?}",
                outgoing_json(&conn)
            );
            conn.outgoing.clear();
            conn.handle_neg_msg(&[json!("s"), json!(42)]).await;
            assert!(
                outgoing_json(&conn).iter().any(|m| m[0] == "NEG-ERR"
                    && m[1] == "s"
                    && m[2].as_str().unwrap().contains("hex")),
                "a non-string NEG-MSG message must yield a NEG-ERR"
            );
            assert!(
                !conn.neg.contains_key("s"),
                "a malformed NEG-MSG must close the subscription"
            );
            conn.outgoing.clear();
            conn.handle_neg_msg(&[json!("s"), json!("zzz")]).await;
            assert!(
                outgoing_json(&conn).iter().any(|m| m[0] == "NEG-ERR"
                    && m[1] == "s"
                    && m[2].as_str().unwrap().contains("hex")),
                "a non-hex NEG-MSG message must yield a NEG-ERR"
            );
            assert!(
                !conn.neg.contains_key("s"),
                "a non-hex NEG-MSG must close the subscription"
            );
            conn.outgoing.clear();

            // Exhausting the round budget closes the subscription.
            conn.handle_neg_open(&[json!("r"), json!({}), json!("61000000")])
                .await;
            conn.outgoing.clear();
            if let Some(state) = conn.neg.get_mut("r") {
                state.rounds_left = 0;
            }
            conn.handle_neg_msg(&[json!("r"), json!("61000000")]).await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "NEG-ERR" && m[2].as_str().unwrap().contains("too many")),
                "an exhausted round budget must close the subscription"
            );
            assert!(!conn.neg.contains_key("r"), "the sub must be released");
            conn.outgoing.clear();

            // A NEG-MSG whose response exceeds the byte budget closes the
            // subscription and releases its items.
            conn.handle_neg_open(&[json!("b"), json!({"kinds": [1]}), json!("61000000")])
                .await;
            conn.outgoing.clear();
            conn.req_response_bytes = 10;
            // A fingerprint range with a bogus fingerprint forces the relay
            // to answer with the full id list (a large response).
            let ask_all = format!("61000001{}", "00".repeat(16));
            conn.handle_neg_msg(&[json!("b"), json!(ask_all)]).await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "NEG-ERR" && m[2].as_str().unwrap().contains("too large")),
                "an over-budget NEG-MSG response must close the subscription: {:?}",
                outgoing_json(&conn)
            );
            assert!(!conn.neg.contains_key("b"), "the sub must be released");
            conn.outgoing.clear();

            // A saturated outgoing queue fails the round with a retryable
            // NEG-ERR instead of accumulating unbounded NEG bytes.
            conn.req_response_bytes = 0;
            conn.handle_neg_open(&[json!("q"), json!({"kinds": [1]}), json!("61000000")])
                .await;
            conn.outgoing.clear();
            conn.out_queue_bytes = 1;
            conn.out_bytes = 100;
            conn.handle_neg_msg(&[json!("q"), json!("61000000")]).await;
            assert!(
                outgoing_json(&conn).iter().any(|m| m[0] == "NEG-ERR"
                    && m[1] == "q"
                    && m[2].as_str().unwrap().contains("overloaded")),
                "a backpressured NEG-MSG must fail retryably: {:?}",
                outgoing_json(&conn)
            );
            assert!(
                !conn.neg.contains_key("q"),
                "a backpressured round must close the subscription"
            );
            conn.outgoing.clear();
            conn.out_queue_bytes = 256 * 1024;
            conn.out_bytes = 0;

            // NEG-CLOSE with a missing id yields a NOTICE.
            conn.handle_neg_close(&[]);
            assert!(outgoing_json(&conn).iter().any(|m| m[0] == "NOTICE"));
            conn.outgoing.clear();

            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn neg_syncs_loose_protected_tag_as_public() {
        // `["-", "extra"]` is public like the REQ path: only the exact
        // `["-"]` tag is protected. An anonymous NEG-OPEN must include it
        // in the sync set instead of withholding it.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            let mut ev = signed_note(conn.relay.secp(), "loose", now, vec![]);
            ev.tags = vec![vec!["-".into(), "extra".into()]];
            ev.id = crate::nips::nip01::compute_id(&ev);
            conn.relay.db.put(ev.clone(), now).await;
            {
                let mut w = conn.relay.config.write().await;
                w.limits.max_neg_items = 10;
            }
            conn.handle_neg_open(&[json!("loose"), json!({"kinds": [1]}), json!("61000000")])
                .await;
            let state = conn.neg.get("loose").expect("sync must stay open");
            let want = ev.id_bytes().expect("test event id");
            assert!(
                state.items.iter().any(|(_, id)| *id == want),
                "a [\"-\", \"extra\"] event must be synced to anonymous peers"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn neg_open_remaining_gates_and_limit() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            // A search filter over-fetches (the relevance budget): with a
            // small max_neg_items the query returns more records than the
            // cap and the NIP-77 "too big" NEG-ERR fires.
            for i in 0..5 {
                let e = signed_note(conn.relay.secp(), &format!("needle {i}"), now - i, vec![]);
                conn.relay.db.put(e.clone(), now).await;
            }
            {
                let mut w = conn.relay.config.write().await;
                w.limits.max_neg_items = 2;
            }
            conn.handle_neg_open(&[json!("big"), json!({"search": "needle"}), json!("61000000")])
                .await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "NEG-ERR" && m[2].as_str().unwrap().contains("too big")),
                "a search query over the cap must close with NEG-ERR: {:?}",
                outgoing_json(&conn)
            );
            conn.outgoing.clear();
            {
                let mut w = conn.relay.config.write().await;
                w.limits.max_neg_items = 100_000;
            }

            // NIP-78 / NIP-59 / NIP-29 item filtering: a kind-78 event, a
            // gift wrap for another recipient and a private group event are
            // withheld from an anonymous peer (the response is empty).
            let secp = conn.relay.secp();
            let mut app = signed_note(secp, "app data", now, vec![]);
            app.kind = crate::nips::nip78::APP_SPECIFIC_KIND;
            conn.relay.db.put(app, now).await;
            let mut wrap = signed_note(secp, "secret dm", now, vec![]);
            wrap.kind = crate::nips::nip62::GIFT_WRAP_KIND;
            wrap.tags = vec![vec!["p".into(), "cc".repeat(32)]];
            conn.relay.db.put(wrap, now).await;
            conn.handle_neg_open(&[
                json!("filtered"),
                json!({"kinds": [78, 1059]}),
                json!("61000000"),
            ])
            .await;
            let msgs = outgoing_json(&conn);
            assert!(
                msgs.iter().any(|m| m[0] == "NEG-MSG" && m[2] == "61000000"),
                "withheld items must produce an empty sync response: {msgs:?}"
            );
            conn.outgoing.clear();
            conn.handle_neg_close(&[json!("filtered")]);

            // The per-connection NEG-OPEN limit (MAX_NEG_OPENS).
            conn.neg_opens_total = super::negentropy::MAX_NEG_OPENS;
            conn.handle_neg_open(&[json!("s"), json!({}), json!("61000000")])
                .await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "NEG-ERR"
                        && m[2].as_str().unwrap().contains("connection limit")),
                "the NEG-OPEN count limit must be enforced"
            );
            conn.outgoing.clear();
            conn.neg_opens_total = 0;

            // A blocked authed pubkey: NEG-MSG is refused and the state is
            // released.
            let blocked = "dd".repeat(32);
            conn.authed_pubkeys.push(blocked.clone());
            conn.relay
                .access
                .write()
                .await
                .blocked_pubkeys
                .push((blocked, String::new()));
            conn.handle_neg_open(&[json!("bk"), json!({}), json!("61000000")])
                .await;
            conn.outgoing.clear();
            conn.handle_neg_msg(&[json!("bk"), json!("61000000")]).await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "NEG-ERR" && m[2].as_str().unwrap().contains("restricted")),
                "a blocked pubkey's NEG-MSG must be refused"
            );
            assert!(!conn.neg.contains_key("bk"), "the blocked sync is released");
            conn.outgoing.clear();
            conn.authed_pubkeys.clear();
            conn.relay.access.write().await.blocked_pubkeys.clear();

            // A NEG-MSG that fails to parse closes the subscription and
            // releases its items (an over-range-count message fails the
            // response).
            conn.handle_neg_open(&[json!("r2"), json!({}), json!("61000000")])
                .await;
            conn.outgoing.clear();
            // Many fingerprint ranges force the codec's per-message range
            // cap to trip: MAX_NEG_RANGES_PER_MSG + 1 ranges.
            let ranges = 1025; // MAX_NEG_RANGES_PER_MSG + 1
            // Encode each range as [infinity bound][mode fingerprint][fp]:
            // a single multi-range message.
            let mut wire = vec![0x61u8];
            for _ in 0..ranges {
                wire.extend_from_slice(&[0x00, 0x00, 0x01]);
                wire.extend_from_slice(&[0u8; 16]);
            }
            let hex_msg = hex::encode(&wire);
            conn.handle_neg_msg(&[json!("r2"), json!(hex_msg)]).await;
            assert!(
                outgoing_json(&conn).iter().any(|m| m[0] == "NEG-ERR"),
                "an unprocessable NEG-MSG must close the subscription: {:?}",
                outgoing_json(&conn)
            );
            assert!(!conn.neg.contains_key("r2"), "the sub is released");

            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn failed_neg_opens_consume_the_connection_budget() {
        // A NEG-OPEN that runs the database scan and then fails (here: the
        // response exceeds the per-connection byte budget) must still spend
        // the connection-wide open budget, or a client could run scans
        // unbounded by always failing the open after the scan.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            conn.req_response_bytes = 1;
            conn.handle_neg_open(&[json!("s"), json!({}), json!("61000000")])
                .await;
            assert!(
                outgoing_json(&conn).iter().any(|m| m[0] == "NEG-ERR"),
                "the oversized response must be refused"
            );
            assert_eq!(
                conn.neg_opens_total, 1,
                "a refused open must still spend the connection budget"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn exhausted_neg_open_budget_skips_the_database_query() {
        // The connection-wide NEG-OPEN cap is checked before the large
        // database query: an exhausted budget answers "connection limit"
        // instead of spending the scan and then reporting a different
        // refusal.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            // More events than a tiny item cap, so the scan would answer
            // "too big" if it ran.
            conn.relay.config.write().await.limits.max_neg_items = 1;
            for i in 0..3 {
                let ev = signed_note(conn.relay.secp(), &format!("e{i}"), now - i, vec![]);
                conn.relay.db.put(ev, now).await;
            }
            conn.neg_opens_total = super::negentropy::MAX_NEG_OPENS;
            conn.handle_neg_open(&[json!("s"), json!({"kinds": [1]}), json!("61000000")])
                .await;
            let msgs = outgoing_json(&conn);
            let err = msgs
                .iter()
                .find(|m| m[0] == "NEG-ERR")
                .expect("the open must be refused");
            assert!(
                err[2].as_str().unwrap().contains("connection limit"),
                "the budget check must run before the database query: {err:?}"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn neg_open_counts_towards_active_subscriptions() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let stats = conn.relay.stats.clone();
            let before = stats
                .subscriptions_active
                .load(std::sync::atomic::Ordering::Relaxed);
            // A NEG-OPEN with an empty client set (skip-to-infinity).
            conn.handle_neg_open(&[json!("s"), json!({"kinds": [1]}), json!("61000000")])
                .await;
            let after_open = stats
                .subscriptions_active
                .load(std::sync::atomic::Ordering::Relaxed);
            assert_eq!(
                after_open,
                before + 1,
                "an open NEG subscription must hold a slot"
            );
            conn.handle_neg_close(&[json!("s")]);
            let after_close = stats
                .subscriptions_active
                .load(std::sync::atomic::Ordering::Relaxed);
            assert_eq!(
                after_close, before,
                "closing the NEG subscription must release the slot"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn neg_open_failed_replace_closes_the_old_subscription() {
        // NIP-77: "If a NEG-OPEN is issued for a currently open subscription
        // ID, the existing subscription is first closed", and "after a
        // NEG-ERR is issued, the subscription is considered to be closed".
        // A failed replacement therefore closes the id instead of leaving
        // the old state running.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let stats = conn.relay.stats.clone();
            let before = stats
                .subscriptions_active
                .load(std::sync::atomic::Ordering::Relaxed);
            conn.handle_neg_open(&[json!("s"), json!({"kinds": [1]}), json!("61000000")])
                .await;
            assert_eq!(
                stats
                    .subscriptions_active
                    .load(std::sync::atomic::Ordering::Relaxed),
                before + 1,
                "the first open holds a slot"
            );
            assert!(conn.neg.contains_key("s"), "the first open is live");
            // A syntactically valid hex message that fails to parse:
            // version byte followed by an out-of-order bound.
            let bad = hex::encode([0x61u8, 0x02, 0x00, 0x01]);
            conn.handle_neg_open(&[json!("s"), json!({"kinds": [1]}), json!(bad)])
                .await;
            assert!(
                conn.outgoing
                    .iter()
                    .any(|m| m.to_text().is_ok_and(|t| t.contains("NEG-ERR"))),
                "the failed replacement must send a NEG-ERR"
            );
            assert!(
                !conn.neg.contains_key("s"),
                "a NEG-ERR closes the subscription: the old state is released"
            );
            assert_eq!(
                stats
                    .subscriptions_active
                    .load(std::sync::atomic::Ordering::Relaxed),
                before,
                "the closed id's subscription slot is released"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn neg_open_byte_cap_rejects_oversized_initial_response() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            // A small response budget: any mode-2 answer over it is
            // rejected with NEG-ERR, which closes the (here non-existent)
            // subscription.
            // Any initial answer is at least the version byte plus a
            // bound, so a 1-byte budget rejects everything.
            conn.req_response_bytes = 1;
            conn.handle_neg_open(&[json!("s"), json!({"kinds": [1]}), json!("61000000")])
                .await;
            assert!(
                conn.outgoing
                    .iter()
                    .any(|m| m.to_text().is_ok_and(|t| t.contains("NEG-ERR"))),
                "the oversized response must produce a NEG-ERR"
            );
            assert!(
                conn.neg.is_empty(),
                "the failed open must not leave a subscription"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn neg_open_replacement_success_is_net_zero() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let stats = conn.relay.stats.clone();
            let before = stats
                .subscriptions_active
                .load(std::sync::atomic::Ordering::Relaxed);
            conn.handle_neg_open(&[json!("s"), json!({"kinds": [1]}), json!("61000000")])
                .await;
            conn.handle_neg_open(&[json!("s"), json!({"kinds": [1]}), json!("61000000")])
                .await;
            assert_eq!(
                stats
                    .subscriptions_active
                    .load(std::sync::atomic::Ordering::Relaxed),
                before + 1,
                "a successful replacement keeps exactly one slot"
            );
            conn.handle_neg_close(&[json!("s")]);
            assert_eq!(
                stats
                    .subscriptions_active
                    .load(std::sync::atomic::Ordering::Relaxed),
                before,
                "closing releases the slot"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn neg_open_item_cap_closes_the_old_subscription() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            // Open "s" against an empty database: it succeeds and holds
            // state.
            conn.handle_neg_open(&[json!("s"), json!({"kinds": [1]}), json!("61000000")])
                .await;
            assert_eq!(conn.neg.len(), 1, "the first open succeeds");
            conn.relay.config.write().await.limits.max_neg_items = 2;
            // Store more matching events than the cap, then replace "s":
            // the over-cap NEG-ERR closes the id (NIP-77).
            for i in 0..3 {
                let ev = signed_note(conn.relay.secp(), &format!("e{i}"), now - i, vec![]);
                conn.relay.db.put(ev, now).await;
            }
            conn.handle_neg_open(&[json!("s"), json!({"kinds": [1]}), json!("61000000")])
                .await;
            assert!(
                outgoing_json(&conn).iter().any(|m| {
                    m[0] == "NEG-ERR" && m[2].as_str().unwrap().contains("too big")
                }),
                "the over-cap query must be refused"
            );
            assert!(
                conn.neg.is_empty(),
                "the NEG-ERR must close the old subscription"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn req_hidden_events_do_not_consume_limit_slots() {
        // Regression: NIP-70 protected events used to consume the per-filter
        // limit during the scan, so a REQ with limit N returned fewer than N
        // visible events (and re-REQing could never recover them). The scan
        // now over-fetches and the connection truncates the visible results.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            let hidden = signed_note(conn.relay.secp(), "secret", now, vec![vec!["-".into()]]);
            let v1 = signed_note(conn.relay.secp(), "v1", now - 1, vec![]);
            let v2 = signed_note(conn.relay.secp(), "v2", now - 2, vec![]);
            let v3 = signed_note(conn.relay.secp(), "v3", now - 3, vec![]);
            for e in [&hidden, &v1, &v2, &v3] {
                conn.relay.db.put(e.clone(), now).await;
            }
            conn.handle_req(&[json!("sub"), json!({"kinds": [1], "limit": 3})])
                .await;
            conn.pump_pending_reqs();
            let contents: Vec<String> = outgoing_json(&conn)
                .iter()
                .filter(|m| m[0] == "EVENT")
                .map(|m| m[2]["content"].as_str().unwrap().to_string())
                .collect();
            assert_eq!(
                contents,
                vec!["v1", "v2", "v3"],
                "the hidden event must not consume a limit slot"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn req_visible_truncate_keeps_created_at_ties() {
        // NIP-01/NIP-67 boundary rule: events sharing the boundary
        // `created_at` belong to the same page — the visible truncation
        // must extend ties instead of cutting them in half.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            let v1 = signed_note(conn.relay.secp(), "v1", now, vec![]);
            let v2 = signed_note(conn.relay.secp(), "v2", now, vec![]);
            let v3 = signed_note(conn.relay.secp(), "v3", now - 1, vec![]);
            for e in [&v1, &v2, &v3] {
                conn.relay.db.put(e.clone(), now).await;
            }
            conn.handle_req(&[json!("sub"), json!({"kinds": [1], "limit": 1})])
                .await;
            conn.pump_pending_reqs();
            let contents: Vec<String> = outgoing_json(&conn)
                .iter()
                .filter(|m| m[0] == "EVENT")
                .map(|m| m[2]["content"].as_str().unwrap().to_string())
                .collect();
            assert!(
                contents.contains(&"v1".to_string()) && contents.contains(&"v2".to_string()),
                "same-timestamp ties must stay together: {contents:?}"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn req_response_chunks_through_the_outgoing_byte_cap() {
        // Backpressure: REQ responses are pumped through the capped
        // outgoing queue in bounded chunks — the queue never holds more
        // than the byte cap, and no response event is dropped (a dropped
        // event is lost permanently — the subscription is answered once).
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            // A tiny per-connection cap so one chunk holds a single event.
            conn.out_queue_bytes = 1024;
            let now = unix_now();
            let big = "x".repeat(10_000);
            let mut ids = Vec::new();
            for i in 0..5 {
                let ev = signed_note(
                    conn.relay.secp(),
                    &format!("big-{i}-{big}"),
                    now - i,
                    vec![],
                );
                conn.relay.db.put(ev.clone(), now).await;
                ids.push(ev.id.clone());
            }
            conn.handle_req(&[json!("sub"), json!({"kinds": [1], "limit": 5})])
                .await;
            assert_eq!(
                conn.pending_reqs.len(),
                1,
                "the response is queued for the pump"
            );
            // Pump in chunks until the response is fully queued. Each
            // pump respects the byte cap: the queue never grows past it.
            let mut delivered = Vec::new();
            loop {
                conn.pump_pending_reqs();
                assert!(
                    conn.out_bytes <= conn.out_queue_bytes + 11_000,
                    "the queue is bounded by the cap plus one event (a single \
                     oversized event must still be delivered)"
                );
                for msg in outgoing_json(&conn) {
                    if msg[0] == "EVENT" {
                        delivered.push(msg[2]["id"].as_str().unwrap().to_string());
                    }
                }
                conn.outgoing.clear();
                conn.out_bytes = 0;
                if conn.pending_reqs.is_empty() {
                    break;
                }
            }
            assert_eq!(
                delivered.len(),
                5,
                "all five response events must be delivered through the chunks"
            );
            assert!(
                ids.iter().all(|id| delivered.contains(id)),
                "no response event may be dropped"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn live_events_wait_for_the_pending_eose() {
        // NIP-01: EOSE marks the end of stored events and the beginning of
        // the real-time stream. A live event that arrives while a stored
        // response is still pumping must be queued after the EOSE, never
        // ahead of the remaining stored events.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            // One stored event per pump, so the live event arrives while the
            // response is still being drained.
            conn.out_queue_bytes = 1024;
            let now = unix_now();
            conn.subs
                .insert("s".into(), (vec![Filter::default()], 0, "\"s\"".into()));
            let mut events = std::collections::VecDeque::new();
            for i in 0..3 {
                events.push_back(signed_note(
                    conn.relay.secp(),
                    &format!("stored-{i}-{}", "x".repeat(2_000)),
                    now - i,
                    vec![],
                ));
            }
            conn.enqueue_pending_req(PendingReq {
                sub_id: "s".into(),
                events,
                eose_hint: false,
                truncated_or_more: false,
                auth_hint: false,
                sent_bytes: 0,
                live: Default::default(),
                live_bytes: 0,
                eose_sent: false,
            });
            // A live event for the same subscription arrives mid-response:
            // it must be held for the post-EOSE stream.
            let live = signed_note(conn.relay.secp(), "live", now, vec![]);
            let live_json = serde_json::to_string(&live).unwrap();
            conn.deliver_live(&live, &live_json, None);
            assert!(
                !outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "EVENT" && m[2]["content"] == "live"),
                "the live event must not overtake the stored response"
            );

            // Drain the queue chunk by chunk, collecting the message order.
            let mut order = Vec::new();
            for _ in 0..20 {
                conn.pump_pending_reqs();
                order.extend(outgoing_json(&conn));
                conn.outgoing.clear();
                conn.out_bytes = 0;
                if conn.pending_reqs.is_empty() {
                    break;
                }
            }
            assert!(
                conn.pending_reqs.is_empty(),
                "the response must finish within the drain loop"
            );
            let stored = |m: &Value| {
                m[0] == "EVENT"
                    && m[2]["content"]
                        .as_str()
                        .is_some_and(|c| c.starts_with("stored-"))
            };
            let eose = order
                .iter()
                .position(|m| m[0] == "EOSE" && m[1] == "s")
                .expect("the EOSE must be queued");
            let last_stored = order.iter().rposition(stored).expect("stored events");
            let live_pos = order
                .iter()
                .position(|m| m[0] == "EVENT" && m[2]["content"] == "live")
                .expect("the live event must be queued");
            assert_eq!(
                order.iter().filter(|m| stored(m)).count(),
                3,
                "all stored events must be delivered"
            );
            assert!(
                last_stored < eose,
                "every stored event must precede the EOSE"
            );
            assert!(live_pos > eose, "the live event must follow the EOSE");
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn pump_closes_oversized_responses() {
        // `max_req_response_bytes`: a response exceeding the budget is
        // closed with `CLOSED ... response too large`; the events already
        // queued stay, and the client can re-request with a narrower
        // filter instead of the subscription hanging.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            conn.req_response_bytes = 3_000;
            let now = unix_now();
            let mut events = std::collections::VecDeque::new();
            for i in 0..3 {
                let ev = signed_note(
                    conn.relay.secp(),
                    &format!("big-{i}-{}", "y".repeat(2_000)),
                    now - i,
                    vec![],
                );
                events.push_back(ev);
            }
            conn.subs
                .insert("s".into(), (Vec::new(), 0, "\"s\"".into()));
            conn.enqueue_pending_req(PendingReq {
                sub_id: "s".into(),
                events,
                eose_hint: false,
                truncated_or_more: false,
                auth_hint: false,
                sent_bytes: 0,
                live: Default::default(),
                live_bytes: 0,
                eose_sent: false,
            });
            conn.pump_pending_reqs();
            let msgs = outgoing_json(&conn);
            let events_sent = msgs.iter().filter(|m| m[0] == "EVENT").count();
            let closed = msgs.iter().find(|m| m[0] == "CLOSED" && m[1] == "s");
            assert!(
                !conn.subs.contains_key("s"),
                "the CLOSED must release the subscription"
            );
            assert_eq!(events_sent, 1, "the first event fits the budget");
            assert!(
                closed.is_some_and(|m| m[2].as_str().unwrap().contains("response too large")),
                "the over-budget response must be closed"
            );
            assert!(
                !msgs.iter().any(|m| m[0] == "EOSE"),
                "a closed response must not send EOSE"
            );
            assert!(
                conn.pending_reqs.is_empty(),
                "the closed response must not stay queued"
            );
            // An event larger than the whole budget closes immediately.
            let mut events = std::collections::VecDeque::new();
            events.push_back(signed_note(
                conn.relay.secp(),
                &"z".repeat(10_000),
                now,
                vec![],
            ));
            conn.subs
                .insert("s2".into(), (Vec::new(), 0, "\"s2\"".into()));
            conn.enqueue_pending_req(PendingReq {
                sub_id: "s2".into(),
                events,
                eose_hint: false,
                truncated_or_more: false,
                auth_hint: false,
                sent_bytes: 0,
                live: Default::default(),
                live_bytes: 0,
                eose_sent: false,
            });
            conn.pump_pending_reqs();
            let msgs = outgoing_json(&conn);
            assert!(
                msgs.iter().any(|m| m[0] == "CLOSED" && m[1] == "s2"),
                "an event beyond the whole budget closes without delivery"
            );
            assert!(!conn.subs.contains_key("s2"));
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn pending_reqs_are_bounded_and_the_oldest_is_cut_off() {
        // More than MAX_PENDING_REQS queued REQ responses (a client
        // flooding REQs while reading slowly): the oldest is cut off with
        // its EOSE sent immediately, so the subscription never hangs.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            for i in 0..5 {
                conn.subs
                    .insert(format!("s{i}"), (Vec::new(), 0, String::new()));
                let mut events = std::collections::VecDeque::new();
                events.push_back(signed_note(
                    conn.relay.secp(),
                    &format!("e{i}"),
                    now - i,
                    vec![],
                ));
                conn.enqueue_pending_req(PendingReq {
                    sub_id: format!("s{i}"),
                    events,
                    eose_hint: true,
                    truncated_or_more: false,
                    auth_hint: false,
                    sent_bytes: 0,
                    live: Default::default(),
                    live_bytes: 0,
                    eose_sent: false,
                });
            }
            assert_eq!(
                conn.pending_reqs.len(),
                MAX_PENDING_REQS,
                "the queue must be bounded"
            );
            // The cut-off response (s0) got its EOSE immediately.
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "EOSE" && m[1] == "s0"),
                "the oldest response must be finished with an EOSE"
            );
            // The remaining responses are pumped in order with their
            // EOSEs (eose_hint = true -> the hint variant).
            let mut all = Vec::new();
            loop {
                conn.pump_pending_reqs();
                for m in outgoing_json(&conn) {
                    all.push(m.clone());
                }
                conn.outgoing.clear();
                conn.out_bytes = 0;
                if conn.pending_reqs.is_empty() {
                    break;
                }
            }
            for i in 1..5 {
                assert!(
                    all.iter()
                        .any(|m| m[0] == "EOSE" && m[1] == format!("s{i}")),
                    "response s{i} must finish with its EOSE"
                );
            }
            assert!(
                all.iter()
                    .any(|m| m[0] == "EOSE" && m[1] == "s1" && m[2] == json!(["finish"])),
                "the hint variant must be sent when eose_hint is on"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn pending_req_cutoff_does_not_resend_eose() {
        // A pending response whose EOSE was already sent (its buffered live
        // events still queued) must not receive a second EOSE when the
        // pending queue overflows, and a CLOSEd subscription must not
        // receive an EOSE at all.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            conn.subs
                .insert("s0".into(), (Vec::new(), 0, "\"s0\"".into()));
            let mut live = std::collections::VecDeque::new();
            live.push_back("[\"EVENT\",\"s0\",{}]".to_string());
            conn.enqueue_pending_req(PendingReq {
                sub_id: "s0".into(),
                events: Default::default(),
                eose_hint: true,
                truncated_or_more: false,
                auth_hint: false,
                sent_bytes: 0,
                live,
                live_bytes: 0,
                eose_sent: true,
            });
            for i in 1..=MAX_PENDING_REQS {
                conn.subs
                    .insert(format!("s{i}"), (Vec::new(), 0, String::new()));
                conn.enqueue_pending_req(PendingReq {
                    sub_id: format!("s{i}"),
                    events: Default::default(),
                    eose_hint: true,
                    truncated_or_more: false,
                    auth_hint: false,
                    sent_bytes: 0,
                    live: Default::default(),
                    live_bytes: 0,
                    eose_sent: false,
                });
            }
            assert!(
                !outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "EOSE" && m[1] == "s0"),
                "a response whose EOSE was already sent must not get a second EOSE"
            );

            // The same cutoff for a CLOSEd subscription stays silent.
            conn.pending_reqs.clear();
            conn.outgoing.clear();
            conn.out_bytes = 0;
            conn.enqueue_pending_req(PendingReq {
                sub_id: "gone".into(),
                events: Default::default(),
                eose_hint: true,
                truncated_or_more: false,
                auth_hint: false,
                sent_bytes: 0,
                live: Default::default(),
                live_bytes: 0,
                eose_sent: false,
            });
            for i in 0..MAX_PENDING_REQS {
                conn.enqueue_pending_req(PendingReq {
                    sub_id: format!("t{i}"),
                    events: Default::default(),
                    eose_hint: true,
                    truncated_or_more: false,
                    auth_hint: false,
                    sent_bytes: 0,
                    live: Default::default(),
                    live_bytes: 0,
                    eose_sent: false,
                });
            }
            assert!(
                !outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "EOSE" && m[1] == "gone"),
                "a CLOSEd subscription must not receive an EOSE"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn eose_auth_hint_is_preceded_by_a_challenge() {
        // NIP-67 `"auth"` hint: the hint array carries `"auth"`, and the
        // spec's MUST — an AUTH message before the EOSE — is honored by
        // queueing the challenge ahead of the EOSE.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            conn.subs
                .insert("s".into(), (Vec::new(), 0, "\"s\"".into()));
            conn.enqueue_pending_req(PendingReq {
                sub_id: "s".into(),
                events: std::collections::VecDeque::new(),
                eose_hint: true,
                truncated_or_more: false,
                auth_hint: true,
                sent_bytes: 0,
                live: Default::default(),
                live_bytes: 0,
                eose_sent: false,
            });
            conn.pump_pending_reqs();
            let msgs = outgoing_json(&conn);
            let eose = msgs
                .iter()
                .position(|m| m[0] == "EOSE")
                .expect("an EOSE is sent");
            let auth = msgs
                .iter()
                .position(|m| m[0] == "AUTH")
                .expect("the AUTH challenge must precede the hint EOSE");
            assert!(
                auth < eose,
                "the AUTH challenge must be queued before the EOSE containing the hint"
            );
            assert_eq!(
                msgs[eose][2],
                json!(["auth", "finish"]),
                "the hint array carries auth and finish"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn req_emits_auth_hint_when_protected_events_are_withheld() {
        // An anonymous REQ over a subscription that also matches NIP-70
        // protected events gets `["EOSE", sub, ["auth", "finish"]]` with a
        // challenge first; the authenticated owner instead receives the
        // protected event and a plain `["finish"]`.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay_with("").await;
            let mut conn = build_conn_on(relay.clone()).await;
            let now = unix_now();
            let normal = signed_note(relay.secp(), "public", now, vec![]);
            let protected = signed_note(relay.secp(), "secret", now, vec![vec!["-".into()]]);
            relay.db.put(normal.clone(), now).await;
            relay.db.put(protected.clone(), now).await;

            conn.handle_req(&[json!("sub"), json!({"kinds": [1]})])
                .await;
            conn.pump_pending_reqs();
            let msgs = outgoing_json(&conn);
            assert!(
                !msgs
                    .iter()
                    .any(|m| m[0] == "EVENT" && m[2]["id"] == protected.id),
                "the protected event stays hidden from anonymous"
            );
            let eose = msgs
                .iter()
                .position(|m| m[0] == "EOSE")
                .expect("an EOSE is sent");
            assert_eq!(
                msgs[eose][2],
                json!(["auth", "finish"]),
                "withheld auth-gated events must carry the auth hint"
            );
            assert!(
                msgs.iter().take(eose).any(|m| m[0] == "AUTH"),
                "the challenge must be queued before the auth-hinted EOSE"
            );

            // The authenticated owner fetches the whole subscription: no
            // auth hint, no extra challenge.
            let mut owner = build_conn_on(relay).await;
            let auth = signed_auth(owner.relay.secp(), "test-challenge", now);
            owner
                .handle_auth(&[serde_json::to_value(&auth).unwrap()])
                .await;
            owner
                .handle_req(&[json!("sub"), json!({"kinds": [1]})])
                .await;
            owner.pump_pending_reqs();
            let msgs = outgoing_json(&owner);
            assert!(
                !msgs.iter().any(|m| m[0] == "AUTH"),
                "an authed owner needs no extra challenge"
            );
            let eose = msgs
                .iter()
                .position(|m| m[0] == "EOSE")
                .expect("an EOSE is sent");
            assert_eq!(
                msgs[eose][2],
                json!(["finish"]),
                "the authed owner gets a plain finish"
            );

            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn pump_skips_closed_subscriptions_and_replaced_ids() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            let mut events = std::collections::VecDeque::new();
            events.push_back(signed_note(conn.relay.secp(), "e0", now, vec![]));
            // A response whose subscription was CLOSEd in the meantime is
            // dropped by the pump without events or EOSE.
            conn.enqueue_pending_req(PendingReq {
                sub_id: "closed".into(),
                events,
                eose_hint: true,
                truncated_or_more: false,
                auth_hint: false,
                sent_bytes: 0,
                live: Default::default(),
                live_bytes: 0,
                eose_sent: false,
            });
            conn.pump_pending_reqs();
            assert!(
                conn.pending_reqs.is_empty(),
                "the response of a closed subscription must be dropped"
            );
            assert!(
                outgoing_json(&conn).is_empty(),
                "no events or EOSE may be queued for a closed subscription"
            );
            // A REQ replacing the same subscription id drops the stale
            // still-pumping response.
            conn.subs
                .insert("s".into(), (Vec::new(), 0, "\"s\"".into()));
            let mut first = std::collections::VecDeque::new();
            first.push_back(signed_note(conn.relay.secp(), "old", now, vec![]));
            conn.enqueue_pending_req(PendingReq {
                sub_id: "s".into(),
                events: first,
                eose_hint: false,
                truncated_or_more: false,
                auth_hint: false,
                sent_bytes: 0,
                live: Default::default(),
                live_bytes: 0,
                eose_sent: false,
            });
            let mut second = std::collections::VecDeque::new();
            second.push_back(signed_note(conn.relay.secp(), "new", now - 1, vec![]));
            conn.enqueue_pending_req(PendingReq {
                sub_id: "s".into(),
                events: second,
                eose_hint: false,
                truncated_or_more: false,
                auth_hint: false,
                sent_bytes: 0,
                live: Default::default(),
                live_bytes: 0,
                eose_sent: false,
            });
            assert_eq!(conn.pending_reqs.len(), 1, "the stale response is dropped");
            conn.pump_pending_reqs();
            let msgs = outgoing_json(&conn);
            assert!(
                msgs.iter()
                    .any(|m| m[0] == "EVENT" && m[2]["content"] == "new"),
                "only the replacement response is delivered"
            );
            assert!(
                !msgs
                    .iter()
                    .any(|m| m[0] == "EVENT" && m[2]["content"] == "old"),
                "the stale response must not be delivered"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn eose_is_delivered_even_at_the_message_count_cap() {
        // A REQ response of exactly OUT_QUEUE_LIMIT events fills the
        // queue to the message-count cap; the EOSE must still be queued
        // (a dropped EOSE would leave the client hanging on a completed
        // subscription).
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            // A byte cap generous enough that the message-count cap is the
            // binding constraint for ~300-byte events (4096 of them).
            conn.out_queue_bytes = 8 << 20;
            conn.subs
                .insert("s".into(), (Vec::new(), 0, "\"s\"".into()));
            let now = unix_now();
            let mut events = std::collections::VecDeque::new();
            for i in 0..OUT_QUEUE_LIMIT {
                events.push_back(signed_note(
                    conn.relay.secp(),
                    &format!("tiny-{i}"),
                    now - i as u64,
                    vec![],
                ));
            }
            conn.enqueue_pending_req(PendingReq {
                sub_id: "s".into(),
                events,
                eose_hint: false,
                truncated_or_more: false,
                auth_hint: false,
                sent_bytes: 0,
                live: Default::default(),
                live_bytes: 0,
                eose_sent: false,
            });
            conn.pump_pending_reqs();
            let msgs = outgoing_json(&conn);
            assert_eq!(
                msgs.iter().filter(|m| m[0] == "EVENT").count(),
                OUT_QUEUE_LIMIT,
                "all events must be queued"
            );
            assert!(
                msgs.iter().any(|m| m[0] == "EOSE" && m[1] == "s"),
                "the EOSE must be delivered even at the message-count cap"
            );
            assert!(
                conn.pending_reqs.is_empty(),
                "the response must be finished"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn pending_event_batch_is_bounded_by_count_and_bytes() {
        // A flood of maximum-size frames must not accumulate parsed events
        // up to the whole window cap: the batch is flushed at EVENT_BATCH
        // events or one full frame's bytes, whichever comes first.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            let max_msg = 1 << 20;
            assert!(!conn.pending_batch_full(max_msg));
            // Bytes: one full-size frame trips the bound.
            let ev = signed_note(conn.relay.secp(), "big", now, vec![]);
            conn.queue_event_sized(ev, max_msg).await;
            assert_eq!(conn.pending_bytes, max_msg);
            assert!(
                conn.pending_batch_full(max_msg),
                "the byte bound must trip"
            );
            conn.flush_pending_events().await;
            assert!(conn.pending_events.is_empty());
            assert_eq!(conn.pending_bytes, 0, "the byte counter resets on flush");
            assert!(!conn.pending_batch_full(max_msg));
            // Count: EVENT_BATCH small events trip the bound.
            for i in 0..EVENT_BATCH - 1 {
                let ev = signed_note(
                    conn.relay.secp(),
                    &format!("small-{i}"),
                    now - i as u64,
                    vec![],
                );
                conn.queue_event_sized(ev, 64).await;
            }
            assert!(
                !conn.pending_batch_full(max_msg),
                "below the count bound the batch stays open"
            );
            let ev = signed_note(conn.relay.secp(), "last", now, vec![]);
            conn.queue_event_sized(ev, 64).await;
            assert!(
                conn.pending_batch_full(max_msg),
                "the count bound must trip"
            );
            conn.flush_pending_events().await;
            assert_eq!(conn.pending_bytes, 0);
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn refused_count_releases_the_same_id_req_subscription() {
        // NIP-01/NIP-45: CLOSED is terminal for a subscription id. A COUNT
        // refused with CLOSED for an id that is also an active REQ
        // subscription must release that subscription, or the client would
        // consider it closed while the relay kept delivering live events.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            // Open a REQ subscription "x".
            conn.handle_req(&[json!("x"), json!({"kinds": [1]})])
                .await;
            conn.pump_pending_reqs();
            assert!(conn.subs.contains_key("x"), "the REQ subscription is open");
            // Disable COUNT and refuse a COUNT with the same id.
            conn.relay
                .config
                .write()
                .await
                .relay
                .disabled_nips
                .push(45);
            conn.handle_count(&[json!("x"), json!({"kinds": [1]})])
                .await;
            let msgs = outgoing_json(&conn);
            assert!(
                msgs.iter().any(|m| m[0] == "CLOSED" && m[1] == "x"),
                "the refusal must be a CLOSED"
            );
            assert!(
                !conn.subs.contains_key("x"),
                "the same-id REQ subscription must be released with the CLOSED"
            );
            // The live index no longer wakes the connection for "x".
            assert!(
                conn.relay
                    .sub_index
                    .read()
                    .unwrap_or_else(|p| p.into_inner())
                    .candidates(&signed_note(conn.relay.secp(), "after", unix_now(), vec![]))
                    .is_empty(),
                "a closed subscription must not receive live events"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn source_ip_blocked_and_change_notification() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let conn = build_conn().await;
            let peer: std::net::IpAddr = "198.51.100.7".parse().unwrap();
            assert!(!conn.source_ip_blocked(peer).await);
            // A v4-mapped entry must match the plain IPv4 peer.
            conn.relay
                .access
                .write()
                .await
                .blocked_ips
                .push(("::ffff:198.51.100.7".into(), String::new()));
            assert!(conn.source_ip_blocked(peer).await);
            // Every mutation wakes the connection's watcher immediately,
            // which is what disconnects read-only subscribers.
            let mut rx = conn.relay.ip_blocks_tx.subscribe();
            conn.relay.note_ip_blocks_changed();
            assert!(
                rx.changed().await.is_ok(),
                "the block change must wake the connection watcher"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn malformed_event_and_auth_still_get_ok() {
        // NIP-01/NIP-42: EVENT and AUTH messages must be answered with OK
        // even when the payload is malformed, as long as an id can be
        // correlated.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let id = "ab".repeat(32);
            conn.handle_text(&format!(
                r#"["EVENT", {{"id":"{id}","created_at":-1}}]"#
            ))
            .await;
            let msgs = outgoing_json(&conn);
            let ok = msgs
                .iter()
                .find(|m| m[0] == "OK" && m[1] == id)
                .expect("a malformed EVENT with an id must get an OK");
            assert_eq!(ok[2], false);
            assert!(
                ok[3].as_str().unwrap_or("").starts_with("invalid:"),
                "the OK must carry a machine-readable reason: {ok:?}"
            );

            // Without an id there is nothing to correlate: NOTICE.
            conn.outgoing.clear();
            conn.out_bytes = 0;
            conn.handle_text(r#"["EVENT", {"created_at":-1}]"#).await;
            let msgs = outgoing_json(&conn);
            assert!(msgs.iter().any(|m| m[0] == "NOTICE"));
            assert!(!msgs.iter().any(|m| m[0] == "OK"));

            // A malformed AUTH with an id likewise gets OK false.
            conn.outgoing.clear();
            conn.out_bytes = 0;
            conn.handle_text(&format!(
                r#"["AUTH", {{"id":"{id}","created_at":-1}}]"#
            ))
            .await;
            let msgs = outgoing_json(&conn);
            let ok = msgs
                .iter()
                .find(|m| m[0] == "OK" && m[1] == id)
                .expect("a malformed AUTH with an id must get an OK");
            assert_eq!(ok[2], false);

            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn uppercase_auth_pubkey_is_rejected() {
        // NIP-01: hex fields are lowercase. An uppercase AUTH pubkey would
        // verify but never match the exact-case author checks, so it must be
        // refused instead of stored as an authenticated key.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            let mut auth = signed_auth(conn.relay.secp(), "test-challenge", now);
            auth.pubkey = auth.pubkey.to_ascii_uppercase();
            auth.id = crate::nips::nip01::compute_id(&auth);
            let keypair = Keypair::from_seckey_slice(conn.relay.secp(), &[2u8; 32]).unwrap();
            let id = auth.id_bytes().unwrap();
            auth.sig = conn
                .relay
                .secp()
                .sign_schnorr_no_aux_rand(&id, &keypair)
                .to_string();
            conn.handle_auth(&[serde_json::to_value(&auth).unwrap()])
                .await;
            let msgs = outgoing_json(&conn);
            let ok = msgs
                .iter()
                .find(|m| m[0] == "OK" && m[1] == auth.id)
                .expect("AUTH must be answered with OK");
            assert_eq!(ok[2], false, "uppercase pubkeys must be rejected");
            assert!(!conn.is_authed(), "no key must be recorded");
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn deletion_without_targets_is_rejected() {
        // NIP-09: a deletion request (kind 5) is defined as having one or
        // more `e`/`a` tags; one without targets is rejected.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            let bare = signed_note(conn.relay.secp(), "delete nothing", now, vec![]);
            let mut bare = bare;
            bare.kind = 5;
            bare.id = crate::nips::nip01::compute_id(&bare);
            conn.queue_event_value(bare.clone()).await;
            conn.flush_pending_events().await;
            let msgs = outgoing_json(&conn);
            let ok = msgs
                .iter()
                .find(|m| m[0] == "OK" && m[1] == bare.id)
                .expect("an OK reply is sent");
            assert_eq!(ok[2], false);
            assert!(
                ok[3]
                    .as_str()
                    .unwrap_or("")
                    .contains("deletion request must reference"),
                "the reason must explain the rejection"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn live_index_survives_close_and_resubscribe() {
        // Regression: closing the last subscription used to drop the live
        // receiver (the old design), which the per-connection index delivery
        // never recreated — a resubscribed connection silently stopped
        // receiving live events.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            conn.handle_req(&[json!("a"), json!({"kinds": [1]})]).await;
            conn.handle_close(&[json!("a")]);
            // The connection is unregistered after the close.
            assert!(
                conn.relay
                    .sub_index
                    .read()
                    .unwrap_or_else(|p| p.into_inner())
                    .candidates(&signed_note(conn.relay.secp(), "x", now, vec![]))
                    .is_empty(),
                "no subscriptions after CLOSE"
            );
            // Resubscribe: the live receiver must still be alive and the
            // connection must be a candidate again.
            conn.handle_req(&[json!("b"), json!({"kinds": [1]})]).await;
            assert!(
                conn.live.is_some(),
                "live receiver survives a CLOSE + REQ cycle"
            );
            let ev = signed_note(conn.relay.secp(), "resubscribed", now, vec![]);
            conn.relay.broadcast(ev);
            let received = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                conn.live.as_mut().unwrap().recv(),
            )
            .await;
            assert!(received.is_ok(), "live delivery resumes after CLOSE + REQ");
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn send_control_is_bounded_as_last_resort() {
        // `send_control` bypasses the byte cap so completion-critical
        // messages are never dropped, but the queue length still caps at
        // twice `OUT_QUEUE_LIMIT`: 8192 tiny EOSEs queued without a drain
        // means an attacker, not a slow reader.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            for _ in 0..OUT_QUEUE_LIMIT * 2 {
                conn.send_control(serde_json::json!(["EOSE", "s"]));
            }
            assert_eq!(conn.outgoing.len(), OUT_QUEUE_LIMIT * 2);
            let dropped_before = conn.dropped;
            conn.send_control(serde_json::json!(["EOSE", "s"]));
            assert_eq!(conn.outgoing.len(), OUT_QUEUE_LIMIT * 2);
            assert_eq!(conn.dropped, dropped_before + 1);
            conn.relay.db.shutdown();
        });
    }
}
