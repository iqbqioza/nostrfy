//! The relay: event acceptance (single and batched), live
//! broadcasting, NIP-29/NIP-43 group and role state, and the
//! live-delivery subscription index.
//! relay-generated event publishing. Event validation lives in
//! [`validate`].

mod commands;
mod index;
pub(crate) use index::{FilterComponents, SubscriptionIndex};
mod roles;
mod validate;

use std::sync::Arc;

use secp256k1::{Keypair, Secp256k1, XOnlyPublicKey};
use std::collections::HashMap;
use std::sync::atomic::{AtomicIsize, AtomicU64, AtomicUsize, Ordering};
use tokio::sync::RwLock;
use tokio::sync::mpsc;

use crate::config::{AccessControl, Config};
use crate::db::{DbClient, PutOutcome};
use crate::event::Event;
use crate::nips::nip09;
use crate::nips::nip29::{self, GroupStore};
use crate::nips::nip43::{self, RoleStore};
use crate::stats::Stats;
use crate::util::unix_now;

/// Per-connection live-delivery queue capacity (in batches): a
/// connection that stops reading drops live batches instead of
/// accumulating them (the old broadcast channel's lag semantics).
pub(crate) const LIVE_QUEUE_CAPACITY: usize = 64;

pub struct Relay {
    pub config: Arc<RwLock<Config>>,
    pub access: Arc<RwLock<AccessControl>>,
    pub db: DbClient,
    pub stats: Arc<Stats>,
    /// The live subscription index: filter components (kinds, authors,
    /// tags) → connection ids. The bus task looks up the candidate
    /// connections for each event batch and delivers only to them, so an
    /// event wakes the connections that can match it instead of every
    /// subscriber (the per-connection filter match remains the final
    /// check).
    pub sub_index: std::sync::Arc<std::sync::RwLock<crate::relay::SubscriptionIndex>>,
    /// Per-connection live-delivery queues: the bus task sends each batch
    /// to the candidate connections' bounded queues (dropped when full,
    /// the same backpressure semantics as the old broadcast).
    pub conn_queues: std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<u64, mpsc::Sender<crate::ws::LiveBatch>>>,
    >,
    /// Connection id counter: the id identifies a connection in the
    /// subscription index and the queue map.
    pub next_conn_id: std::sync::atomic::AtomicU64,
    live_tx: mpsc::Sender<(Event, Arc<String>)>,
    live_rx: Option<mpsc::Receiver<(Event, Arc<String>)>>,
    live_batch_interval_ms: u64,
    live_batch_size: usize,
    pub groups: Arc<RwLock<GroupStore>>,
    /// NIP-43 role definitions and member assignments.
    pub roles: Arc<RwLock<RoleStore>>,
    /// Limits concurrent `/api/v1` queries so a flood of REST traffic
    /// fails fast (503) instead of piling up behind WebSocket work. The
    /// limit is adjustable at runtime (SIGHUP config reload).
    pub api_limit: Arc<ApiLimiter>,
    /// Active WebSocket connections per source IP, so a socket flood from
    /// a single host cannot consume the whole connection budget.
    per_ip_connections: std::sync::Mutex<HashMap<String, usize>>,
    /// Per-pubkey sliding window of accepted event timestamps
    /// (`relay.max_events_per_min_per_pubkey`). Bounded: the map is
    /// cleared when it reaches its cap instead of growing.
    publish_rate: std::sync::Mutex<HashMap<String, std::collections::VecDeque<u64>>>,
    /// Bumped whenever the blocked-IP list changes (NIP-86 blockip/
    /// unblockip): connections compare this against the value captured at
    /// connect and re-check the list (and close) when it changed, so a
    /// newly blocked IP's existing connections are dropped too.
    pub ip_blocks_version: AtomicU64,
    /// Bumped on every SIGHUP config reload: connections cache the NIP-40/
    /// NIP-42 flags against this version and refresh them only when it
    /// changes, so the hot live path never takes the shared config lock.
    pub config_version: std::sync::atomic::AtomicU64,
    /// The relay's own keypair (from `relay.private_key`), used to sign
    /// NIP-29 and NIP-43 relay-generated events.
    key: Option<Keypair>,
    /// Cached hex pubkey of the relay's own key (fixed at startup, like
    /// `key`). The access-control checks exempt it, so the operator can
    /// always publish command events and read on restricted relays.
    pub(crate) relay_pubkey: Option<String>,
    secp: Secp256k1<secp256k1::All>,
    /// Path of the config file, set at startup so NIP-86 runtime changes
    /// (relay name/description/icon) can be persisted to disk; without
    /// persistence a SIGHUP config reload would silently revert them.
    pub config_path: Arc<tokio::sync::RwLock<Option<std::path::PathBuf>>>,
    /// Strictly monotonic stamp for relay-generated events: see
    /// [`StampClock`].
    stamps: StampClock,
    /// The Blossom file server state (when configured), so its handlers can
    /// share the relay's state.
    pub blossom: Arc<tokio::sync::RwLock<Option<Arc<crate::server::blossom::BlossomState>>>>,
    /// The Blossom upload allowlist (normalized hex pubkeys), loaded from
    /// the relay database at startup and refreshed on SIGHUP.
    pub blossom_allow: Arc<tokio::sync::RwLock<Vec<String>>>,
    /// Rate-limited audit trail of the management operations (NIP-86).
    pub audit: crate::audit::AuditLog,
}

/// Issues strictly increasing timestamps for relay-generated events.
///
/// The relay stamps its generated replaceable events (NIP-29 39000-39005,
/// NIP-43 33534/13534) so that the newest group/role state always wins the
/// NIP-01 replacement tie-break. With plain `unix_now()` stamps, two group
/// events applied in the same second would share a timestamp and the
/// replacement would fall back to the id comparison — where a *stale*,
/// later-committed version could beat the newer state. The clock guarantees
/// that stamps reflect the order in which the state was applied, not the
/// order in which the events happen to be stored.
pub(crate) struct StampClock {
    last: AtomicU64,
}

impl StampClock {
    fn new() -> Self {
        StampClock {
            last: AtomicU64::new(0),
        }
    }

    /// Returns a timestamp strictly greater than every previously issued
    /// stamp and at least `floor`. Issued stamps cap at `u64::MAX - 1`
    /// (the last unique value: `min(u64::MAX - 2)` before the increment),
    /// so the issued value can never collide with a previous one within
    /// the reachable range.
    pub(crate) fn stamp(&self, floor: u64) -> u64 {
        let mut cur = self.last.load(Ordering::Relaxed);
        loop {
            let next = cur
                .max(floor.saturating_sub(1))
                .min(u64::MAX - 2)
                .saturating_add(1);
            match self
                .last
                .compare_exchange_weak(cur, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return next,
                Err(actual) => cur = actual,
            }
        }
    }
}

/// Tuning of the live fan-out bus.
#[derive(Debug, Clone, Copy)]
pub struct LiveBusConfig {
    /// Bound on the queue of events waiting to be broadcast.
    pub buffer: usize,
    /// The bus flushes at least this often (milliseconds).
    pub batch_interval_ms: u64,
    /// Maximum events per flushed batch.
    pub batch_size: usize,
}

/// Bounds the number of concurrently served `/api/v1` queries. Implemented
/// with a cheap atomic counter instead of a `tokio::sync::Semaphore` so the
/// limit can be changed at runtime (SIGHUP config reload) without
/// reallocating the shared handle.
pub struct ApiLimiter {
    max: AtomicUsize,
    in_flight: AtomicIsize,
}

/// An acquired `/api/v1` slot; the slot is released when the guard drops,
/// on every exit path of the request handler.
pub struct ApiPermit {
    limiter: Arc<ApiLimiter>,
}

impl Drop for ApiPermit {
    fn drop(&mut self) {
        self.limiter.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

impl ApiLimiter {
    fn new(max: usize) -> Arc<ApiLimiter> {
        Arc::new(ApiLimiter {
            max: AtomicUsize::new(max.max(1)),
            in_flight: AtomicIsize::new(0),
        })
    }

    /// Applies a new concurrency ceiling (from a config reload). The ceiling
    /// takes effect for every new request.
    pub fn set_max(&self, max: usize) {
        self.max.store(max.max(1), Ordering::Relaxed);
    }

    /// Reserves one in-flight slot when one is free, returning the guard
    /// that releases it. `None` when the limiter is saturated (503).
    pub fn try_acquire(self: &Arc<Self>) -> Option<ApiPermit> {
        let max = self.max.load(Ordering::Relaxed) as isize;
        let mut cur = self.in_flight.load(Ordering::Relaxed);
        loop {
            if cur >= max {
                return None;
            }
            match self.in_flight.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Some(ApiPermit {
                        limiter: Arc::clone(self),
                    });
                }
                Err(actual) => cur = actual,
            }
        }
    }
}

impl Relay {
    pub async fn new(
        config: Arc<RwLock<Config>>,
        db: DbClient,
        stats: Arc<Stats>,
        private_key_hex: &str,
        live_bus: LiveBusConfig,
    ) -> Relay {
        let (live_tx, live_rx) = mpsc::channel(live_bus.buffer.max(16));
        let live_batch_interval_ms = live_bus.batch_interval_ms.clamp(1, 1000);
        let live_batch_size = live_bus.batch_size.max(1);
        let secp = Secp256k1::new();
        let key = if private_key_hex.is_empty() {
            None
        } else {
            match hex::decode(private_key_hex) {
                Ok(bytes) if bytes.len() == 32 => Keypair::from_seckey_slice(&secp, &bytes).ok(),
                _ => {
                    log::warn!("invalid relay.private_key: ignoring");
                    None
                }
            }
        };
        let relay_pubkey = key
            .as_ref()
            .map(|keypair| XOnlyPublicKey::from_keypair(keypair).0.to_string());
        let api_max_concurrent = config.read().await.limits.max_api_concurrent;
        // Seed the access control: the persisted runtime state wins, so NIP-86
        // bans/allowlists survive restarts; the config `access` section seeds
        // the very first run only (when no runtime state exists yet). The
        // pubkey allow/deny lists live in the relay database (LMDB),
        // managed with `nostrfy relay allow/deny` — never in the config.
        let mut access = match db.load_access().await {
            Some(access) => access,
            None => config.read().await.access.clone(),
        };
        // `restrict_relay` is config-owned: an older persisted blob (which
        // predates the flag) would otherwise silently override it with the
        // serde default `false`.
        access.restrict_relay = config.read().await.access.restrict_relay;
        // The pubkey lists and the Blossom allowlist are stored in the
        // relay database and loaded into memory at startup (and refreshed
        // on SIGHUP). A failed load must stop the relay instead of
        // starting with empty (fail-open) security state: an empty deny
        // list lifts every ban, and an empty allowlist opens an
        // allowlist-only relay.
        let (deny, allow) = match db.load_relay_pubkeys().await {
            Some(lists) => lists,
            None => {
                log::error!(
                    "cannot load the persisted relay pubkey access lists; refusing to start"
                );
                std::process::exit(1);
            }
        };
        access.blocked_pubkeys = deny;
        access.allowed_pubkeys = allow;
        let blossom_allow = match db.load_blossom_allow().await {
            Some(list) => list,
            None => {
                log::error!(
                    "cannot load the persisted Blossom upload allowlist; refusing to start"
                );
                std::process::exit(1);
            }
        };
        Relay {
            config: Arc::clone(&config),
            access: Arc::new(RwLock::new(access)),
            db,
            stats,
            sub_index: std::sync::Arc::new(std::sync::RwLock::new(SubscriptionIndex::default())),
            conn_queues: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
            next_conn_id: std::sync::atomic::AtomicU64::new(1),
            live_tx,
            live_rx: Some(live_rx),
            live_batch_interval_ms,
            live_batch_size,
            groups: Arc::new(RwLock::new(GroupStore::with_cap(
                config.read().await.relay.max_groups,
            ))),
            roles: Arc::new(RwLock::new(RoleStore::default())),
            api_limit: ApiLimiter::new(api_max_concurrent),
            per_ip_connections: std::sync::Mutex::new(HashMap::new()),
            publish_rate: std::sync::Mutex::new(HashMap::new()),
            ip_blocks_version: AtomicU64::new(0),
            config_version: AtomicU64::new(0),
            key,
            relay_pubkey,
            secp,
            config_path: Arc::new(tokio::sync::RwLock::new(None)),
            stamps: StampClock::new(),
            blossom: Arc::new(tokio::sync::RwLock::new(None)),
            blossom_allow: Arc::new(tokio::sync::RwLock::new(blossom_allow)),
            audit: crate::audit::AuditLog::default(),
        }
    }

    /// A strictly monotonic timestamp for relay-generated events (see
    /// [`StampClock`]): at least `floor`, and greater than every stamp
    /// issued before.
    pub(crate) fn stamp_floor(&self, floor: u64) -> u64 {
        self.stamps.stamp(floor)
    }

    /// Spawns the live batching task. Must be called once, after the relay
    /// is created.
    pub fn start_live_bus(&mut self) {
        let Some(mut rx) = self.live_rx.take() else {
            return;
        };
        let sub_index = std::sync::Arc::clone(&self.sub_index);
        let conn_queues = std::sync::Arc::clone(&self.conn_queues);
        let interval_ms = self.live_batch_interval_ms;
        let batch_size = self.live_batch_size;
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut batch: Vec<(Event, Arc<String>)> = Vec::with_capacity(batch_size);
            let flush = |batch: &mut Vec<(Event, Arc<String>)>| {
                if batch.is_empty() {
                    return;
                }
                let batch = Arc::new(std::mem::take(batch));
                // Deliver to the candidate connections only: the
                // subscription index maps each event's components to the
                // connections that could match, so an event wakes the
                // subscribers that can see it instead of all of them.
                // The per-connection filter match remains the final
                // check; the per-connection queues drop when full (the
                // same backpressure as the old broadcast).
                let conns = {
                    let index = sub_index.read().unwrap_or_else(|p| p.into_inner());
                    let mut conns = std::collections::HashSet::new();
                    for (event, _) in batch.iter() {
                        conns.extend(index.candidates(event));
                    }
                    conns
                };
                // Collect the candidate senders under the lock, then drop
                // the lock before delivering: the sends never block
                // (`try_send`), so holding the map lock during the
                // fan-out would only delay connections joining/leaving.
                let senders: Vec<mpsc::Sender<crate::ws::LiveBatch>> = {
                    let queues = conn_queues.lock().unwrap_or_else(|p| p.into_inner());
                    conns
                        .iter()
                        .filter_map(|conn| queues.get(conn).cloned())
                        .collect()
                };
                for sender in senders {
                    // `try_send` on the bounded queue: a slow connection
                    // that stops reading drops the batch instead of
                    // accumulating it in memory (the same lag semantics
                    // as the old broadcast channel).
                    let _ = sender.try_send(batch.clone());
                }
            };
            loop {
                tokio::select! {
                    event = rx.recv() => match event {
                        Some((event, json)) => {
                            batch.push((event, json));
                            if batch.len() >= batch_size {
                                flush(&mut batch);
                            }
                        }
                        None => {
                            flush(&mut batch);
                            return;
                        }
                    },
                    _ = interval.tick() => flush(&mut batch),
                }
            }
        });
    }

    /// Queues an event for live delivery to subscribers. The event is
    /// dropped (never stored) when the live buffer is full, as it remains
    /// available through subscriptions. The JSON is encoded once here —
    /// every subscriber shares the same serialization.
    pub fn broadcast(&self, event: Event) {
        let json = Arc::new(serde_json::to_string(&event).unwrap_or_default());
        let _ = self.live_tx.try_send((event, json));
    }

    /// Whether `pubkey` may publish another event under
    /// `relay.max_events_per_min_per_pubkey` (a sliding 60-second window;
    /// 0 = unlimited). The window map is bounded at 10,000 pubkeys — the
    /// cap never clears the whole map (a clear would reset every window
    /// and permanently disable the limit): expired windows are evicted
    /// first, and a still-full map skips tracking the new pubkey only
    /// (fail-open for that key, limits preserved for everyone else).
    pub(crate) fn publish_rate_allowed(&self, cfg: &Config, pubkey: &str, now: u64) -> bool {
        const MAX_TRACKED_PUBKEYS: usize = 10_000;
        let max = cfg.relay.max_events_per_min_per_pubkey;
        if max == 0 {
            return true;
        }
        let mut rate = self.publish_rate.lock().unwrap_or_else(|p| p.into_inner());
        // Already-tracked pubkeys are always enforced: the cap logic below
        // only decides whether a *new* pubkey is tracked, so a full map
        // can never disable the limit for tracked keys.
        if let Some(window) = rate.get_mut(pubkey) {
            while window.front().is_some_and(|t| now.saturating_sub(*t) >= 60) {
                window.pop_front();
            }
            if window.len() >= max as usize {
                return false;
            }
            window.push_back(now);
            return true;
        }
        // New pubkey: never clear the whole map (a clear would reset every
        // window and permanently disable the limit). Expired windows are
        // evicted first; a still-full map skips tracking the new pubkey
        // only (fail-open for that key, limits preserved for everyone
        // else).
        if rate.len() >= MAX_TRACKED_PUBKEYS {
            rate.retain(|_, w| w.front().is_some_and(|t| now.saturating_sub(*t) < 60));
            if rate.len() >= MAX_TRACKED_PUBKEYS {
                return true;
            }
        }
        rate.entry(pubkey.to_string()).or_default().push_back(now);
        true
    }

    /// Hex pubkey of the relay's own key, if configured.
    pub fn relay_pubkey(&self) -> Option<String> {
        self.relay_pubkey.clone()
    }

    pub fn secp(&self) -> &Secp256k1<secp256k1::All> {
        &self.secp
    }

    /// Persists the current access control lists to the database so NIP-86
    /// runtime bans/allowlists survive restarts. Callers must release the
    /// `access` write lock before awaiting this.
    pub async fn persist_access(&self) {
        let access = self.access.read().await.clone();
        let deny = access.blocked_pubkeys.clone();
        let allow = access.allowed_pubkeys.clone();
        self.db.save_access(access).await;
        // The pubkey lists are excluded from the `access` blob: keep them
        // in their own LMDB key so the CLI and NIP-86 share one source.
        self.db.save_relay_pubkeys(&deny, &allow).await;
    }

    /// Registers a new WebSocket connection from `ip` if it does not exceed
    /// the per-IP cap. Returns `false` (and registers nothing) when the cap
    /// would be exceeded, so the caller rejects the connection.
    pub fn try_register_connection(&self, ip: &std::net::IpAddr, max_per_ip: usize) -> bool {
        if max_per_ip == 0 {
            return true;
        }
        // Recover from a poisoned lock instead of panicking: a panic while
        // holding the map would otherwise kill every later connection.
        let mut map = self
            .per_ip_connections
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let count = map.entry(ip.to_string()).or_insert(0);
        if *count >= max_per_ip {
            return false;
        }
        *count += 1;
        true
    }

    /// Releases one connection slot for `ip` (called when the connection
    /// closes).
    pub fn release_connection(&self, ip: &std::net::IpAddr) {
        // Recover from a poisoned lock instead of panicking: a panic while
        // holding the map would otherwise kill every later connection.
        let mut map = self
            .per_ip_connections
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if let Some(count) = map.get_mut(&ip.to_string()) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                map.remove(&ip.to_string());
            }
        }
    }

    /// Reloads the database-owned access state (Blossom upload allowlist,
    /// relay pubkey deny/allow lists) at SIGHUP. A failed or timed-out
    /// load keeps the previous lists: overwriting them with an empty
    /// result would silently lift every ban (fail-open).
    pub async fn reload_db_state(&self) {
        match self.db.try_load_blossom_allow().await {
            Some(list) => {
                *self.blossom_allow.write().await = list;
                log::info!("Blossom upload allowlist reloaded from the database");
            }
            None => log::warn!("Blossom upload allowlist reload failed; keeping the previous list"),
        }
        match self.db.try_load_relay_pubkeys().await {
            Some((deny, allow)) => {
                // Read the config *before* taking the access write lock: the
                // accept paths hold `config.read` while awaiting
                // `access.read`, so acquiring `access.write` first and then
                // awaiting `config.read` would set up a lock cycle (this
                // method holding the write lock awaiting `config.read`,
                // an accept holding `config.read` awaiting `access.read`).
                let restrict_relay = self.config.read().await.access.restrict_relay;
                let mut access = self.access.write().await;
                access.blocked_pubkeys = deny;
                access.allowed_pubkeys = allow;
                access.restrict_relay = restrict_relay;
                log::info!("relay pubkey access lists reloaded from the database");
            }
            None => {
                log::warn!("relay pubkey access lists reload failed; keeping the previous lists")
            }
        }
    }

    pub fn has_relay_key(&self) -> bool {
        self.key.is_some()
    }

    /// Bumps the blocked-IP version so every connection re-checks the list
    /// (and closes when its source IP is now blocked).
    pub fn note_ip_blocks_changed(&self) {
        self.ip_blocks_version.fetch_add(1, Ordering::Relaxed);
    }

    /// Persists a runtime change of one `[relay]` config field (e.g. the
    /// NIP-86 `changerelayname`/`changerelaydescription`/`changerelayicon`
    /// methods) to the config file, preserving comments and unrelated
    /// lines. A failure only warns: the change stays applied in memory
    /// until the next config reload.
    pub async fn persist_relay_field(&self, field: &str, value: &str) {
        let Some(path) = self.config_path.read().await.clone() else {
            log::warn!(
                "cannot persist relay.{field}: the config file path is unknown \
                 (running without a config file?); the change applies until the \
                 next config reload"
            );
            return;
        };
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                let updated = crate::config::set_relay_field_in_text(&text, field, value);
                if let Err(e) = crate::config::write_text_atomic(&path, &updated) {
                    log::warn!(
                        "cannot persist relay.{field} to {}: {e}; the change applies \
                         until the next config reload",
                        path.display()
                    );
                }
            }
            Err(e) => {
                log::warn!(
                    "cannot read {} to persist relay.{field}: {e}",
                    path.display()
                );
            }
        }
    }

    /// Validates and stores a single event. The live path batches events
    /// through [`Self::accept_events_batch`], which falls back to this
    /// method for batches containing group-state events.
    pub async fn accept_event(
        &self,
        event: Event,
        authed: &[String],
        known_prefixes: Option<&std::collections::HashSet<Vec<u8>>>,
    ) -> (PutOutcome, Option<Arc<Event>>) {
        let now = unix_now();
        let cfg = self.config.read().await;
        let access = self.access.read().await;

        match self
            .precheck(&cfg, &access, &event, now, authed, known_prefixes, None)
            .await
        {
            crate::relay::validate::Precheck::Reject(reason) => {
                self.stats.bump(&self.stats.events_rejected, 1);
                return (PutOutcome::Invalid(reason), None);
            }
            crate::relay::validate::Precheck::Vanish => {
                // NIP-62: delete everything by this pubkey and never
                // accept anything from it again.
                let Some(pubkey) = event.pubkey_bytes() else {
                    return (PutOutcome::Invalid("invalid: bad pubkey".into()), None);
                };
                drop(cfg);
                drop(access);
                self.vanish_pubkey(pubkey).await;
                // A vanish request is accepted like any other event (the
                // OK:true is sent): count it so the accepted/rejected
                // accounting stays consistent with the OKs.
                self.stats.bump(&self.stats.events_accepted, 1);
                return (PutOutcome::Stored, None);
            }
            crate::relay::validate::Precheck::Accept => {}
        }

        // First-seen trust check: a pubkey's first accepted event records
        // its arrival; events from pubkeys first seen within the configured
        // window are rejected (spam from freshly created accounts). The
        // lookup is read-only here — the first-seen timestamp is only
        // persisted once an event actually stores, so a rejected first event
        // (expired/duplicate/invalid) cannot pre-warm the account-age clock.
        let mut persist_first_seen = false;
        if cfg.relay.new_pubkey_min_age_secs > 0
            && let Some(pubkey) = event.pubkey_bytes()
        {
            let first_seens = self.db.first_seen_batch(vec![pubkey]).await;
            let Some(&(created, first_seen)) = first_seens.first() else {
                // The database is unavailable or overloaded: fail closed.
                self.stats.bump(&self.stats.events_rejected, 1);
                return (
                    PutOutcome::Invalid("error: database unavailable".into()),
                    None,
                );
            };
            persist_first_seen = created;
            if !created && now.saturating_sub(first_seen) < cfg.relay.new_pubkey_min_age_secs {
                self.stats.bump(&self.stats.events_rejected, 1);
                return (
                    PutOutcome::Invalid("restricted: your account is too new".into()),
                    None,
                );
            }
        }

        let outcome = self.db.put(event.clone(), now).await;
        if persist_first_seen
            && matches!(
                outcome,
                PutOutcome::Stored | PutOutcome::Replaced | PutOutcome::Ephemeral
            )
            && let Some(pubkey) = event.pubkey_bytes()
        {
            self.db.touch_first_seen_batch(vec![(pubkey, now)]).await;
        }
        let (nip9, nip43, nip29_enabled) =
            (cfg.nip_enabled(9), cfg.nip_enabled(43), cfg.nip_enabled(29));
        drop(cfg);
        drop(access);

        match outcome {
            PutOutcome::Stored | PutOutcome::Replaced | PutOutcome::Ephemeral => {
                self.stats.bump(&self.stats.events_accepted, 1);
                self.after_put(event, now, nip9, nip43, nip29_enabled).await;
                (outcome, None)
            }
            PutOutcome::Duplicate => {
                self.stats.bump(&self.stats.events_duplicate, 1);
                (outcome, None)
            }
            other => {
                self.stats.bump(&self.stats.events_rejected, 1);
                (other, None)
            }
        }
    }

    /// Accepts a batch of events from one connection, returning the outcome
    /// of each. The database layer commits the whole batch in a single write
    /// transaction, so the commit cost is paid once per batch instead of
    /// once per event. Ordering and per-event replies are preserved.
    pub async fn accept_events_batch(
        &self,
        events: Vec<Event>,
        authed: &[String],
    ) -> Vec<(String, PutOutcome)> {
        let batch = self.accept_batch_begin(events, authed).await;
        batch.finish(self).await
    }

    /// The in-flight part of a non-group batch: the per-event checks have
    /// run and the write is queued on the writer thread, but the commit
    /// has not been awaited yet. The connection can keep reading frames
    /// while the writer commits.
    /// Phase 1 of [`Self::accept_events_batch`]: the per-event checks and
    /// the writer queueing. The write is *queued* (not awaited), so the
    /// caller can keep reading frames while the writer commits; the
    /// outcomes arrive through [`PendingBatch::finish`]. Batches containing
    /// group-state events are fully resolved here (the sequential path).
    pub(crate) async fn accept_batch_begin(
        &self,
        events: Vec<Event>,
        authed: &[String],
    ) -> PendingBatch {
        // Group moderation events mutate the in-memory group state; their
        // effects must be visible to later events of the same batch (e.g. a
        // put-user followed by the new member's post), so batches containing
        // them are processed sequentially.
        if events.iter().any(|e| {
            nip29::group_id(e).is_some()
                || (nip29::MOD_MIN..=nip29::MOD_MAX).contains(&e.kind)
                || e.kind == nip29::JOIN
                || e.kind == nip29::LEAVE
        }) {
            // Check every `previous` tag reference of the whole batch in one
            // database round trip: a single event must not be able to
            // amplify into thousands of database requests. Dedup with a set
            // so that a batch full of distinct `previous` tags (up to
            // max_tags per event) cannot turn the dedup itself quadratic.
            let mut prefixes: Vec<Vec<u8>> = Vec::new();
            let mut seen_prefixes: std::collections::HashSet<Vec<u8>> =
                std::collections::HashSet::new();
            for event in &events {
                for prefix in nip29::previous_tags(event) {
                    let Ok(prefix) = hex::decode(&prefix) else {
                        continue;
                    };
                    if !prefix.is_empty() && seen_prefixes.insert(prefix.clone()) {
                        prefixes.push(prefix);
                    }
                }
            }
            let mut known: std::collections::HashSet<Vec<u8>> = if prefixes.is_empty() {
                std::collections::HashSet::new()
            } else {
                let existing = self.db.prefixes_exist(prefixes.clone()).await;
                prefixes
                    .into_iter()
                    .zip(existing)
                    .filter_map(|(p, exists)| exists.then_some(p))
                    .collect()
            };
            // References to sibling events of the same batch are valid: the
            // group state changes are applied sequentially, so an earlier
            // event of the batch is a legitimate `previous` target even
            // though it is not committed to the database yet.
            for event in &events {
                if let Ok(id_bytes) = hex::decode(&event.id) {
                    for len in 1..=id_bytes.len() {
                        known.insert(id_bytes[..len].to_vec());
                    }
                }
            }
            let mut out = Vec::with_capacity(events.len());
            for event in events {
                let id = event.id.clone();
                let (outcome, _) = self.accept_event(event, authed, Some(&known)).await;
                out.push((id, outcome));
            }
            return PendingBatch {
                receiver: None,
                resolved: Some(out),
                results: Vec::new(),
                put_slots: Vec::new(),
                puts: Vec::new(),
                new_pubkeys: Vec::new(),
                vanishes: Vec::new(),
                now: 0,
                nip9: false,
                nip43: false,
                nip29: false,
            };
        }
        let now = unix_now();
        let cfg = self.config.read().await;
        let access = self.access.read().await;
        let mut results: Vec<(String, PutOutcome)> = Vec::with_capacity(events.len());
        let mut puts: Vec<Event> = Vec::new();
        let mut put_slots: Vec<usize> = Vec::new();
        // (slot, id, event) of the vanish requests, resolved at the end so
        // the OK replies keep the order of the received batch.
        let mut vanishes: Vec<(usize, String, Event)> = Vec::new();

        // This path only sees events without group involvement: batches
        // containing group events (an `h` tag or a moderation/join/leave
        // kind) are routed to the sequential [`Self::accept_event`] path
        // above. The shared `precheck` still runs for every event.
        //
        // The Schnorr signature check dominates the per-event accept cost
        // (tens of microseconds), so a large batch first verifies every
        // signature in parallel across the machine's cores and the
        // sequential loop below reuses the verdicts. `validate_base` runs
        // its cheap checks before consulting a verdict, so the reject
        // reasons are identical to the inline-verify path.
        let verified = crate::relay::validate::verify_signatures_parallel(&events, self.secp());
        for event in events {
            let id = event.id.clone();
            let verified = verified.get(results.len()).copied();
            match self
                .precheck(&cfg, &access, &event, now, authed, None, verified)
                .await
            {
                crate::relay::validate::Precheck::Reject(reason) => {
                    self.stats.bump(&self.stats.events_rejected, 1);
                    results.push((id, PutOutcome::Invalid(reason)));
                    continue;
                }
                crate::relay::validate::Precheck::Vanish => {
                    vanishes.push((results.len(), id, event));
                    results.push((String::new(), PutOutcome::Invalid(String::new())));
                    continue;
                }
                crate::relay::validate::Precheck::Accept => {}
            }
            put_slots.push(results.len());
            results.push((String::new(), PutOutcome::Invalid(String::new())));
            puts.push(event);
        }

        let groups_enabled = cfg.nip_enabled(29);
        let roles_enabled = cfg.nip_enabled(43);
        let nip9_enabled = cfg.nip_enabled(9);
        let min_age = cfg.relay.new_pubkey_min_age_secs;
        drop(cfg);
        drop(access);

        // First-seen trust check: pubkeys first seen within the configured
        // window may not publish (their first event established the
        // account). Performed in one database round trip for the batch. The
        // lookup is read-only; first-seen is only persisted for events that
        // actually store, so a failed first event cannot pre-warm the clock.
        let mut new_pubkeys: Vec<bool> = Vec::new();
        if min_age > 0 && !puts.is_empty() {
            let pubkeys: Vec<[u8; 32]> = puts
                .iter()
                .map(|e| e.pubkey_bytes().unwrap_or([0u8; 32]))
                .collect();
            let first_seens = self.db.first_seen_batch(pubkeys).await;
            if first_seens.len() != puts.len() {
                // The database is unavailable or overloaded: every pending
                // event of the batch fails closed.
                for (event, slot) in puts.into_iter().zip(put_slots) {
                    self.stats.bump(&self.stats.events_rejected, 1);
                    results[slot] = (
                        event.id,
                        PutOutcome::Invalid("error: database unavailable".into()),
                    );
                }
                puts = Vec::new();
                put_slots = Vec::new();
            } else {
                let mut kept = Vec::with_capacity(puts.len());
                let mut kept_slots = Vec::with_capacity(put_slots.len());
                let mut kept_new = Vec::with_capacity(puts.len());
                for ((event, slot), (created, first_seen)) in
                    puts.into_iter().zip(put_slots).zip(first_seens)
                {
                    if !created && now.saturating_sub(first_seen) < min_age {
                        self.stats.bump(&self.stats.events_rejected, 1);
                        results[slot] = (
                            event.id,
                            PutOutcome::Invalid("restricted: your account is too new".into()),
                        );
                    } else {
                        kept_new.push(created);
                        kept.push(event);
                        kept_slots.push(slot);
                    }
                }
                puts = kept;
                put_slots = kept_slots;
                new_pubkeys = kept_new;
            }
        }

        let receiver = if puts.is_empty() {
            None
        } else {
            self.db
                .put_batch_deferred(puts.iter().map(|e| (e.clone(), now)).collect())
        };

        PendingBatch {
            receiver,
            resolved: None,
            results,
            put_slots,
            puts,
            new_pubkeys,
            vanishes,
            now,
            nip9: nip9_enabled,
            nip43: roles_enabled,
            nip29: groups_enabled,
        }
    }

    async fn after_put(
        &self,
        event: Event,
        now: u64,
        nip9: bool,
        nip43: bool,
        nip29_enabled: bool,
    ) {
        if nip9 && event.kind == nip09::DELETION_KIND {
            let removed = self
                .db
                .apply_deletion(
                    nip09::deletion_targets(&event),
                    nip09::deletion_addresses(&event),
                    Some(event.pubkey.clone()),
                    event.created_at,
                )
                .await;
            self.stats.bump(&self.stats.events_deleted, removed as u64);
            // NIP-59: gift wraps are signed by random keys, so their
            // recipient cannot delete them via NIP-09; the relay
            // deletes wraps addressed to the deleter instead.
            if let Some(pubkey) = event.pubkey_bytes() {
                let purged = self.db.delete_gift_wraps_to(pubkey).await;
                self.stats.bump(&self.stats.events_deleted, purged as u64);
            }
        }
        if nip43 && event.kind == nip43::LEAVE {
            // NIP-43: leave requests (ephemeral kinds) update the member
            // list without being stored.
            self.apply_leave_request(&event).await;
        }
        let is_group_event = nip29_enabled
            && ((nip29::MOD_MIN..=nip29::MOD_MAX).contains(&event.kind)
                || event.kind == nip29::JOIN
                || event.kind == nip29::LEAVE);
        if is_group_event {
            self.apply_group_event(&event, now).await;
        }
        // Command events: with `relay.enabled_command_events` a kind:1
        // event authored by the relay's own pubkey carries an operator
        // command; it is executed here (after storage, like the other
        // side effects) and answered with a relay-signed kind:1111 event.
        if event.kind == 1 {
            self.handle_command_event(&event).await;
        }
        self.broadcast(event);
    }

    /// NIP-62: deletes every event by `pubkey` and removes the pubkey from
    /// every NIP-29 group (its moderation events were deleted along with
    /// everything else).
    async fn vanish_pubkey(&self, pubkey: [u8; 32]) {
        let pubkey_hex = hex::encode(pubkey);
        let removed = self.db.apply_vanish(pubkey).await;
        self.stats.bump(&self.stats.events_deleted, removed as u64);
        if self.config.read().await.nip_enabled(29) {
            let mut groups = self.groups.write().await;
            for group in groups.groups.values_mut() {
                group.members.remove(&pubkey_hex);
            }
        }
        // NIP-43 role assignments hold pubkeys too: a vanished author
        // must not keep its roles.
        if self.config.read().await.nip_enabled(43) {
            let mut roles = self.roles.write().await;
            roles.assignments.remove(&pubkey_hex);
        }
    }

    /// Applies a stored NIP-29 event to the group state and publishes the
    /// relay-generated metadata events.
    async fn apply_group_event(&self, event: &Event, now: u64) {
        let relay_pubkey = self.relay_pubkey().unwrap_or_default();
        // Relay-generated events are stamped with the strictly monotonic
        // clock (not plain `now`): two events applied in the same second
        // must still be distinguishable, or the NIP-01 id tie-break could
        // let a stale, later-committed version win. The floor is clamped
        // to `now`: a group event may carry a future created_at (allowed
        // up to max_created_at_future_secs), and stamping the metadata in
        // the future would make it invisible to `until: now` scans and,
        // after a restart, unreplaceable until the wall clock catches up.
        let stamp = self.stamp_floor(now);
        let generated = self.groups.write().await.apply(
            event,
            &relay_pubkey,
            stamp,
            self.has_relay_key(),
            false,
        );

        if event.kind == 9005 {
            // Group moderation delete-event: admins may delete events, but
            // only within their own group — an admin of one group must not
            // be able to delete another group's content (or the relay's
            // metadata) by referencing its id.
            if let Some(gid) = nip29::group_id(event) {
                let removed = self
                    .db
                    .apply_group_deletion(nip29::delete_targets(event), gid.to_string())
                    .await;
                self.stats.bump(&self.stats.events_deleted, removed as u64);
            }
        }

        for mut ev in generated {
            if !self.store_relay_event(&mut ev).await {
                // The in-memory group state moved on, but the stored
                // metadata did not: without this the saved 39000-39005
                // stay stale until the next edit (and the restart rebuild
                // replays the older moderation events). Surface it.
                log::warn!(
                    "could not store the relay-generated group event for {}",
                    ev.tags
                        .iter()
                        .find(|t| t.first().map(String::as_str) == Some("d"))
                        .and_then(|t| t.get(1))
                        .cloned()
                        .unwrap_or_default()
                );
            }
        }
    }
}

pub(crate) struct PendingBatch {
    receiver: Option<tokio::sync::oneshot::Receiver<Vec<PutOutcome>>>,
    resolved: Option<Vec<(String, PutOutcome)>>,
    results: Vec<(String, PutOutcome)>,
    put_slots: Vec<usize>,
    puts: Vec<Event>,
    new_pubkeys: Vec<bool>,
    vanishes: Vec<(usize, String, Event)>,
    now: u64,
    nip9: bool,
    nip43: bool,
    nip29: bool,
}

impl PendingBatch {
    /// Phase 2 of [`Self::accept_events_batch`]: awaits the commit
    /// (for non-group batches) and applies the side effects
    /// (first-seen persistence, vanish resolution, NIP-09/29/43 and
    /// the live broadcast). Group batches were fully resolved in
    /// `begin` and return their results here.
    pub(crate) async fn finish(self, relay: &Relay) -> Vec<(String, PutOutcome)> {
        if let Some(resolved) = self.resolved {
            return resolved;
        }
        let mut results = self.results;
        let puts = self.puts;
        let put_slots = self.put_slots;
        let new_pubkeys = self.new_pubkeys;
        let vanishes = self.vanishes;
        let now = self.now;
        let nip9 = self.nip9;
        let nip43 = self.nip43;
        let nip29 = self.nip29;
        let Some(receiver) = self.receiver else {
            for (event, slot) in puts.into_iter().zip(put_slots) {
                relay.stats.bump(&relay.stats.events_rejected, 1);
                results[slot] = (
                    event.id,
                    PutOutcome::Invalid("error: database overloaded".into()),
                );
            }
            return results;
        };
        let mut outcomes = receiver.await.unwrap_or_default();
        if outcomes.len() != puts.len() {
            // The write was rejected before it was queued (overload
            // fail-fast): nothing will commit, so every pending event
            // is reported as failed instead of being replied with an
            // empty id.
            outcomes = vec![PutOutcome::Invalid("error: database overloaded".into()); puts.len()];
        }

        // Record the first-seen timestamp only for accounts whose first
        // event actually stored: a failed first event must not pre-warm
        // the account-age clock.
        let is_new_vec = if new_pubkeys.is_empty() {
            vec![false; puts.len()]
        } else {
            new_pubkeys
        };
        let mut persist_first_seen: Vec<[u8; 32]> = Vec::new();
        for (((event, outcome), slot), is_new) in puts
            .into_iter()
            .zip(outcomes)
            .zip(put_slots)
            .zip(is_new_vec)
        {
            let id = event.id.clone();
            match outcome {
                PutOutcome::Stored | PutOutcome::Replaced | PutOutcome::Ephemeral => {
                    relay.stats.bump(&relay.stats.events_accepted, 1);
                    if is_new && let Some(pk) = event.pubkey_bytes() {
                        persist_first_seen.push(pk);
                    }
                    relay.after_put(event, now, nip9, nip43, nip29).await;
                }
                PutOutcome::Duplicate => {
                    relay.stats.bump(&relay.stats.events_duplicate, 1);
                }
                _ => {
                    relay.stats.bump(&relay.stats.events_rejected, 1);
                }
            }
            results[slot] = (id, outcome);
        }
        if !persist_first_seen.is_empty() {
            relay
                .db
                .touch_first_seen_batch(
                    persist_first_seen.into_iter().map(|pk| (pk, now)).collect(),
                )
                .await;
        }

        for (slot, id, event) in vanishes {
            if let Some(pubkey) = event.pubkey_bytes() {
                relay.vanish_pubkey(pubkey).await;
            }
            // Same accounting as the single-event path: a vanish is
            // accepted (its OK:true is sent) and counts as accepted.
            relay.stats.bump(&relay.stats.events_accepted, 1);
            results[slot] = (id, PutOutcome::Stored);
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use super::Relay;
    use super::StampClock;
    use super::validate::contains_secret_key;

    /// Builds a relay with an empty database.
    async fn build_relay() -> std::sync::Arc<Relay> {
        build_relay_cfg(false).await
    }

    async fn build_relay_cfg(disable_fsync: bool) -> std::sync::Arc<Relay> {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join("nostrfy-relay-dbstate")
            .join(format!("{:x}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        let mut cfg = crate::config::Config::default();
        cfg.database.path = path;
        cfg.database.map_size = 16 * 1024 * 1024;
        cfg.database.max_map_size = 256 * 1024 * 1024;
        cfg.database.disabled_fsync = disable_fsync;
        let db = crate::db::DbClient::open(
            &cfg.database,
            true,
            std::sync::Arc::new(Default::default()),
            0,
            128,
            4096,
            262144,
        )
        .unwrap();
        let config = std::sync::Arc::new(tokio::sync::RwLock::new(cfg));
        let stats = crate::stats::Stats::new();
        let relay = Relay::new(
            config,
            db,
            stats,
            "",
            crate::relay::LiveBusConfig {
                buffer: 1024,
                batch_interval_ms: 10,
                batch_size: 64,
            },
        )
        .await;
        std::sync::Arc::new(relay)
    }

    #[tokio::test]
    async fn reload_db_state_applies_persisted_lists() {
        let relay = build_relay().await;
        relay
            .db
            .save_relay_pubkeys(&[("aa".repeat(32), "test".into())], &[])
            .await;
        relay.reload_db_state().await;
        assert_eq!(
            relay.access.read().await.blocked_pubkeys.len(),
            1,
            "the persisted deny list must be applied"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn reload_db_state_keeps_previous_lists_on_failure() {
        let relay = build_relay().await;
        // Mark the live lists: a failed reload must not overwrite them
        // with an empty (fail-open) result.
        relay
            .access
            .write()
            .await
            .blocked_pubkeys
            .push(("bb".repeat(32), "marker".into()));
        relay.blossom_allow.write().await.push("npub1marker".into());
        // The reader thread is gone: every reload request is reported as
        // failed.
        relay.db.shutdown();
        relay.reload_db_state().await;
        assert_eq!(
            relay.access.read().await.blocked_pubkeys.len(),
            1,
            "the previous deny list must survive a failed reload"
        );
        assert_eq!(
            relay.blossom_allow.read().await.len(),
            1,
            "the previous allowlist must survive a failed reload"
        );
    }

    #[test]
    fn stamp_clock_is_strictly_monotonic() {
        let clock = StampClock::new();
        let a = clock.stamp(100);
        let b = clock.stamp(50);
        let c = clock.stamp(1000);
        let d = clock.stamp(0);
        assert!(a >= 100);
        assert!(b > a, "a lower floor must not lower the stamp");
        assert!(c > b && c >= 1000);
        assert!(d > c, "a zero floor must not lower the stamp");
    }

    #[test]
    fn nsec_detection() {
        // A real nsec (checksum-valid bech32m) is detected.
        let key = crate::nips::nip19::bech32_encode("nsec", &[0x42u8; 32]).unwrap();
        assert_eq!(key.len(), 63);
        assert!(contains_secret_key(&format!("look at my key {key} here")));
        assert!(contains_secret_key(&key));

        // Embedded in tags.
        assert!(contains_secret_key(&format!("prefix-{key}-suffix")));

        // Too short: not a key.
        assert!(!contains_secret_key("nsec1"));
        assert!(!contains_secret_key(&format!("nsec1{}", &key[5..45])));

        // Invalid bech32 characters are not matched.
        let mut bad = key[5..].chars().collect::<Vec<_>>();
        bad[0] = 'B'; // 'B' is not in the bech32 charset
        let bad: String = bad.into_iter().collect();
        assert!(!contains_secret_key(&format!("nsec1{bad}")));

        // A checksum-invalid look-alike (quoted fake key / garbage) is NOT
        // flagged: content cannot be censored by baiting a user into quoting
        // an nsec-shaped string.
        let fake_body: String = (0..58)
            .map(|i| "qpzry9x8gf2tvdw0s3jn54khce6mua7l".as_bytes()[i % 32] as char)
            .collect();
        assert!(
            !contains_secret_key(&format!("nsec1{fake_body}")),
            "an invalid-checksum nsec look-alike must not be flagged"
        );

        // Case-insensitive prefix with a valid checksum: an all-uppercase
        // key is still a real key (bech32 permits all-uppercase).
        let upper = key.to_uppercase();
        assert!(contains_secret_key(&upper));

        // A *mixed-case* string (uppercase prefix, lowercase data) is
        // invalid bech32 and must not be flagged.
        assert!(!contains_secret_key(&format!("NSEC1{}", &key[5..])));
    }

    /// Ingestion throughput benchmark through the real write path:
    /// `accept_event[s]` → precheck (Schnorr verify) → batched LMDB commit →
    /// first-seen / side effects → live broadcast. Reports the parallel vs
    /// sequential signature-verify cost and the durable (fsync) vs
    /// fsync-disabled end-to-end ingest. Run with:
    /// `cargo test --release -- --ignored bench_ingest --nocapture`.
    #[ignore]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn bench_ingest_events_per_sec() {
        fn bench_signed(
            secp: &secp256k1::Secp256k1<secp256k1::All>,
            i: usize,
            now: u64,
        ) -> crate::event::Event {
            // `i` spans the run counter, so no two runs reuse (pubkey, id)s.
            // The low bytes vary so every seckey < the curve order n.
            let mut seckey = [0u8; 32];
            seckey[31] = ((i % 250) as u8) + 1;
            seckey[30] = (i / 250) as u8;
            let keypair = secp256k1::Keypair::from_seckey_slice(secp, &seckey).unwrap();
            let pubkey = secp256k1::XOnlyPublicKey::from_keypair(&keypair)
                .0
                .to_string();
            let mut ev = crate::event::Event {
                id: String::new(),
                pubkey,
                created_at: now,
                kind: 1,
                tags: vec![vec!["t".into(), "bench".into()]],
                content: format!("bench event {i}"),
                sig: String::new(),
            };
            ev.id = crate::nips::nip01::compute_id(&ev);
            let sig = secp.sign_schnorr_no_aux_rand(&ev.id_bytes().unwrap(), &keypair);
            ev.sig = sig.to_string();
            ev
        }

        let relay = build_relay().await;
        let fsync_off_relay = build_relay_cfg(true).await;
        let secp = relay.secp(); // shares the relay's precomputed context

        // Signature-verify cost alone (the dominant per-event CPU work), one
        // batch through the parallel path vs the sequential inline path. The
        // end-to-end numbers below include DB commit time, which dominates on
        // slow disks, so this section isolates the parallel verify gain.
        {
            const N: usize = 8000;
            let now = crate::util::unix_now();
            let big: Vec<crate::event::Event> =
                (0..N).map(|i| bench_signed(secp, i, now)).collect();
            let t0 = std::time::Instant::now();
            for batch in big.chunks(1000) {
                let v = crate::relay::validate::verify_signatures_parallel(batch, secp);
                assert!(v.iter().all(|b| *b));
            }
            let par = t0.elapsed().as_secs_f64();
            let t0 = std::time::Instant::now();
            for batch in big.chunks(1000) {
                let v: Vec<bool> = batch
                    .iter()
                    .map(|e| crate::nips::nip01::verify(e, secp).is_ok())
                    .collect();
                assert!(v.iter().all(|b| *b));
            }
            let seq = t0.elapsed().as_secs_f64();
            println!(
                "verify only: {N} sigs parallel {:>6.0}/s vs sequential {:>6.0}/s ({:.1}x)",
                N as f64 / par,
                N as f64 / seq,
                seq / par
            );
        }

        // End-to-end ingest through the full accept path, with the durable
        // (fsync) DB and the fsync-disabled DB side by side.
        let mut run = 0usize;
        for (set, total) in [("flood batch", 1000usize), ("stream batch", 5000usize)] {
            let now = crate::util::unix_now();
            let pre: Vec<crate::event::Event> = (0..total)
                .map(|i| bench_signed(secp, run + i, now))
                .collect();
            run += total;
            for (name, target) in [("durable", &relay), ("fsync-off", &fsync_off_relay)] {
                let t0 = std::time::Instant::now();
                for chunk in pre.chunks(100) {
                    let results = target.accept_events_batch(chunk.to_vec(), &[]).await;
                    let accepted = results
                        .iter()
                        .filter(|(_, o)| matches!(o, crate::db::PutOutcome::Stored))
                        .count();
                    assert_eq!(accepted, chunk.len(), "every benchmark event must store");
                }
                let elapsed = t0.elapsed().as_secs_f64();
                let eps = total as f64 / elapsed;
                println!("{set} ({name}): {total} events in {elapsed:.3} s -> {eps:.0} events/sec");
            }
        }
        relay.db.shutdown();
        fsync_off_relay.db.shutdown();
    }
}
