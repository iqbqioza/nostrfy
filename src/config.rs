//! `nostrd.toml` configuration: relay identity, server binding,
//! limits, database, daemon paths and NIP toggles.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const DEFAULT_CONFIG: &str = "nostrd.toml";

/// NIPs advertised in the NIP-11 document. NIPs whose behaviour is purely
/// client-side are generally not advertised (NIP-11: "Client-side NIPs SHOULD
/// NOT be advertised"): NIP-28 explicitly "imposes no additional requirements
/// on relays", so it is not listed. The client-side NIPs that ARE listed
/// (17/22/32/46/47/57/59/65/78/84/85/87/88/94) are advertised deliberately:
/// the relay stores and serves their events (or forwards their ephemeral
/// kinds), so clients rely on them. NIP-34 (git) is advertised only when
/// `relay.enabled_git` is set (the kinds are rejected otherwise). NIP-A3
/// (kind 10133) is served but cannot be advertised: it is a `draft` with no
/// integer identifier and NIP-11's `supported_nips` is an array of integer
/// identifiers. The remaining file-storage NIPs (95/96 HTTP file storage)
/// are excluded per the project rules (Blossom is provided separately by
/// the `[blossom]` file server). NIP-33 was merged into NIP-01 but remains
/// advertised for clients that check it.
pub const RELAY_NIPS: &[u16] = &[
    1, 9, 11, 13, 17, 22, 26, 29, 32, 33, 34, 40, 42, 43, 45, 46, 47, 50, 57, 59, 62, 65, 66, 67,
    70, 77, 78, 84, 85, 86, 87, 88, 94, 98,
];

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub relay: RelayConfig,
    pub server: ServerConfig,
    pub rpc: RpcConfig,
    pub limits: LimitsConfig,
    pub database: DatabaseConfig,
    pub daemon: DaemonConfig,
    /// Initial access control lists (NIP-86 bans/allowlists), seeded at
    /// startup so they survive restarts.
    pub access: AccessControl,
    /// Blossom file server (media hosting) settings.
    pub blossom: BlossomConfig,
}

/// Blossom (BUD-01/02) file server configuration.
///
/// The feature is active when `host` is non-empty: requests whose Host
/// header matches it are served only the Blossom routes (like
/// `server.api_host` for the REST API), so the media server and the relay
/// live on the same port behind one reverse proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BlossomConfig {
    /// Hostname dedicated to the Blossom server (e.g. `media.example.com`).
    /// Empty = the feature is disabled.
    pub host: String,
    /// Storage backend: `"local"` (files under `local_path`) or `"s3"`
    /// (any S3-compatible service, including Cloudflare R2).
    pub storage: String,
    /// Directory for local storage. Files are kept as
    /// `<local_path>/<npub1...>/<sha256>` (the `bucket/{npub1}/{file}`
    /// hierarchy on disk).
    pub local_path: PathBuf,
    /// Maximum accepted upload size in bytes (the HTTP body limit for
    /// `PUT /upload`).
    pub max_upload_bytes: usize,
    /// Local-storage disk-full guard: uploads are refused while the free
    /// space on the filesystem hosting `local_path` is below this many
    /// bytes (a full disk would make the LMDB writer fail and risk
    /// SIGBUS on memory-map writes). 0 disables the check.
    pub min_free_bytes: u64,
    /// S3 endpoint (e.g. `https://<account>.r2.cloudflarestorage.com` for
    /// Cloudflare R2, `https://s3.amazonaws.com` for AWS).
    pub s3_endpoint: String,
    /// S3 region (Cloudflare R2 uses `"auto"`).
    pub s3_region: String,
    /// S3 bucket name — the `bucket` of the `bucket/{npub1}/{file}` layout.
    pub s3_bucket: String,
    pub s3_access_key: String,
    pub s3_secret_key: String,
    /// When true, only the pubkeys in the Blossom upload allowlist may
    /// upload blobs. The allowlist itself lives in the relay database
    /// (LMDB), managed with `nostrd blossom allow/deny`.
    pub restrict_uploads: bool,
}

impl Default for BlossomConfig {
    fn default() -> Self {
        BlossomConfig {
            host: String::new(),
            storage: "local".into(),
            local_path: PathBuf::from("./data/images"),
            max_upload_bytes: 20 * 1024 * 1024,
            min_free_bytes: 32 * 1024 * 1024,
            s3_endpoint: String::new(),
            s3_region: String::new(),
            s3_bucket: String::new(),
            s3_access_key: String::new(),
            s3_secret_key: String::new(),
            restrict_uploads: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RelayConfig {
    pub name: String,
    pub description: String,
    pub pubkey: String,
    pub contact: String,
    pub icon: String,
    pub post_policy: String,
    /// Hex-encoded secret key of the relay itself. When set, the relay can
    /// sign and publish NIP-29 group metadata events.
    pub private_key: String,
    /// Public URL of this relay (e.g. "wss://relay.example.com"). Used for
    /// NIP-62 request-to-vanish matching; falls back to host:port when empty.
    pub public_url: String,
    /// Optional LiveKit server URL for NIP-29 live audio/video rooms.
    pub livekit_url: String,
    pub livekit_api_key: String,
    pub livekit_api_secret: String,
    /// Explicit allowlist of NIP numbers; empty means "all except disabled".
    pub enabled_nips: Vec<u16>,
    pub disabled_nips: Vec<u16>,
    /// When true, ephemeral events (NIP-01 kinds 20000-29999) are rejected
    /// at publish time instead of being forwarded live.
    pub reject_ephemeral: bool,
    /// When true, NIP-34 git events (kinds 1617-1633, 30617/30618) are
    /// accepted and NIP-34 is advertised in the NIP-11 document. Default
    /// false: the kinds are rejected and NIP-34 is not advertised.
    pub enabled_git: bool,
    /// Events must carry at least this many leading zero bits in their id
    /// to be accepted (0 disables the check).
    pub require_pow: u8,
    /// Spam defense: a pubkey's first accepted event is recorded, and
    /// events from pubkeys first seen less than this many seconds ago are
    /// rejected with `restricted: your account is too new` (0 disables).
    pub new_pubkey_min_age_secs: u64,
    /// Spam defense: a pubkey may publish at most this many events per
    /// minute (a sliding 60-second window). 0 disables the check.
    pub max_events_per_min_per_pubkey: u64,
    /// Cap on the in-memory NIP-29 group store (active groups plus
    /// deleted-group markers). 0 = unlimited.
    pub max_groups: usize,
    /// When true, connections must complete a NIP-42 AUTH exchange before
    /// they may publish or subscribe.
    pub require_auth: bool,
    /// Send a NIP-42 auth-request challenge when a connection arrives
    /// without authentication.
    pub send_auth_challenge: bool,
    /// When true, NIP-78 application-specific events (kinds 78 and 30078)
    /// require the NIP-42 AUTH flow before they are accepted, and are only
    /// served to the authenticated owner (the event author's pubkey).
    pub enabled_nip78_auth: bool,
    /// When true, kind:1 events authored by the relay's own pubkey
    /// (`relay.private_key`) are executed as operator commands: content
    /// "relay allow/deny <npub1...|hex>" edits the relay access lists and
    /// "blossom allow/deny <npub1...|hex>" edits the Blossom upload
    /// allowlist, without the CLI. The relay answers each command with a
    /// relay-signed kind:1111 event (tagged to the command).
    pub enabled_command_events: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    /// Hostname (Host header) dedicated to the REST API. When set, requests
    /// whose Host header matches this value are served only the `/api/v1`
    /// routes, and requests for any other host never reach them: the API
    /// and the WebSocket relay are split by hostname on the same port
    /// (e.g. `api.example.com` vs `relay.example.com`). Empty = the API is
    /// served on every host, next to the WebSocket endpoint.
    pub api_host: String,
    /// Expose Prometheus metrics on `GET /metrics` (text format). Served on
    /// the API host when one is configured; without `api_host` the metrics
    /// are public on every host.
    pub metrics_enabled: bool,
    /// Which paths serve the WebSocket endpoint (and the NIP-11 document):
    /// `root` (default) serves `/`, `/ws` and `/ws/`; `inbox-outbox` serves
    /// only `/inbox` and `/outbox`; `all` serves all of them. The inbox and
    /// outbox paths let a relay advertise distinct endpoints for the
    /// inbox/outbox routing model (e.g. `wss://relay.example.com/inbox`).
    pub ws_paths: String,
    /// Write policy for events published through `/inbox` (only enforced
    /// when the path is served): `any` accepts events carrying at least
    /// one `p` tag (addressed to anyone); `relay` accepts only events that
    /// `p`-tag the relay's own pubkey (which requires `relay.private_key`).
    /// Events published through `/outbox` always require NIP-42 auth and
    /// must be authored by the authenticated pubkey.
    pub inbox_write_policy: String,
    /// Write policy for events published through `/outbox` (only enforced
    /// when the path is served): `any` accepts events authored by any
    /// NIP-42-authenticated pubkey of the connection; `relay` accepts only
    /// events authored by the relay's own pubkey (which requires
    /// `relay.private_key`), making `/outbox` a pure relay outbox.
    pub outbox_write_policy: String,
}

/// NIP-86 management RPC settings: the separate management port, the
/// bearer token / admin pubkey authentication, and the request body
/// limit.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RpcConfig {
    /// Separate local management port for NIP-86; 0 disables it.
    pub management_port: u16,
    pub management_host: String,
    pub management_token: String,
    /// Admin pubkey for NIP-98 authenticated management calls.
    pub admin_pubkey: String,
    /// Body limit for the NIP-86 management RPC (the JSON-RPC handler and
    /// the legacy management endpoints): requests are tiny method+params
    /// documents, so a 64 KiB ceiling is generous.
    pub max_admin_body_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LimitsConfig {
    pub max_connections: usize,
    /// Per-source-IP cap on WebSocket connections: a single host cannot
    /// consume the whole connection budget (a socket flood from one IP
    /// would otherwise evict legitimate clients). 0 = no per-IP cap.
    pub max_connections_per_ip: usize,
    /// Maximum accepted WebSocket message size in bytes.
    pub max_ws_message_bytes: usize,
    /// Per-connection kernel receive buffer (KiB, 0 = kernel default).
    /// Larger buffers let the relay absorb a publishing burst while it
    /// commits a batch, which keeps the batch size (and the number of
    /// commits) high for a fast publisher. The buffer only consumes real
    /// kernel memory while data is actually queued, so a large value does
    /// not cost idle connections anything.
    pub socket_recv_buffer_kb: u32,
    pub max_filters: usize,
    pub max_subscriptions: usize,
    pub max_limit: usize,
    /// NIP-45 COUNT: upper bound for the returned count.
    pub max_count: usize,
    pub max_sub_id_len: usize,
    pub max_content_bytes: usize,
    pub max_tags: usize,
    pub max_tag_value_bytes: usize,
    /// Events whose created_at is more than this many seconds in the future
    /// are silently dropped (OK `mute:`) instead of rejected as invalid.
    pub max_created_at_future_secs: u64,
    /// NIP-77: maximum number of records a single NEG-OPEN may process.
    pub max_neg_items: usize,
    /// Maximum total bytes of subscription filters held by a single
    /// connection.
    pub max_sub_bytes: usize,
    /// NIP-29: reject group events whose created_at is older than this many
    /// seconds (late publication prevention); 0 disables the check.
    pub group_late_publish_secs: u64,
    /// REST API: maximum number of concurrent `/api/v1` requests being
    /// served at once. Requests beyond this limit fail fast with `503`
    /// instead of queuing, so a flood of API traffic cannot stall the
    /// WebSocket subscribers (which share the same database).
    pub max_api_concurrent: usize,
    /// REST API: upper bound for the `limit` query parameter (0 = no bound).
    pub max_api_limit: usize,
    /// REST API: upper bound for the `offset` query parameter (0 = no bound).
    pub max_api_offset: usize,
    /// REST API: maximum length of the `search` query parameter in bytes
    /// (0 = no bound).
    pub max_api_search_bytes: usize,
    /// Maximum bytes of outgoing messages queued for a single connection
    /// before new ones are dropped (protects memory against slow readers).
    pub max_out_queue_bytes: usize,
    /// Seconds a connection may stay idle (no inbound frames) before it is
    /// closed. When non-zero the relay also sends periodic WebSocket PINGs so
    /// an alive-but-silent subscriber keeps its slot and dead peers are
    /// detected and reaped; 0 disables the idle timeout entirely.
    pub ws_idle_timeout_secs: u64,
    /// Live fan-out: events are accumulated and broadcast in batches of at
    /// most `live_batch_size` events every `live_batch_interval_ms`, so that
    /// idle connections wake up once per batch instead of once per event.
    pub live_batch_interval_ms: u64,
    pub live_batch_size: usize,
    /// Bounded queue for events waiting to be broadcast live; messages are
    /// dropped (never stored) when it overflows.
    pub live_buffer: usize,
    /// HTTP/1.1 header read timeout in seconds: a connection that does not
    /// deliver a complete request head within this window is closed
    /// (slow-loris defense). Applies to every HTTP connection, WebSocket
    /// upgrades included.
    pub http_read_timeout_secs: u64,
    /// Per-IP cap on new connections per second (all protocols). A host
    /// opening sockets faster than this is refused until the window slides.
    /// 0 disables the check.
    pub max_connections_per_sec_per_ip: u64,
    /// Byte budget for a single REQ response (the stored events delivered
    /// for one subscription). Responses larger than this are cut off with
    /// a `CLOSED ... response too large` reply so a slow reader cannot
    /// pin unbounded memory; 0 disables the budget.
    pub max_req_response_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DatabaseConfig {
    pub path: PathBuf,
    pub max_dbs: u32,
    pub max_readers: u32,
    /// Memory map size in bytes. The map is opened at `max_map_size` (a
    /// sparse virtual-address reservation), so this value only acts as a
    /// floor: the actual map is never smaller than this or `max_map_size`.
    pub map_size: usize,
    /// Memory map ceiling in bytes. The map is opened at this size once and
    /// never resized at runtime: the reservation is virtual address space
    /// (sparse file), so physical memory and disk grow only with the data
    /// actually written.
    pub max_map_size: usize,
    pub purge_interval_secs: u64,
    /// How many threads serve the WebSocket reader queue (REQ/COUNT/NEG
    /// scans and the small lookups). More threads parallelize query
    /// serving across cores; the scans share LMDB read transactions, so
    /// they never take the write lock.
    pub reader_threads: usize,
    /// Enable the NIP-50 full-text word index.
    pub search_index: bool,
    /// How many words of each event's content are added to the NIP-50
    /// search index.
    pub max_indexed_words: usize,
    /// Write the per-event metadata header used by the scan prefilter
    /// (kind/created_at/pubkey/expiry). Disabling it removes one random
    /// index write per event — the ingest cost stays flat as the database
    /// grows — and the scan falls back to the full parse for the prefilter
    /// checks.
    pub meta_index: bool,
    /// Initial per-connection WebSocket read/write buffer size in bytes
    /// (the buffers grow on demand; the name predates the current use).
    pub db_buffer_size: usize,
    /// Seconds a database request may wait before timing out (0 = wait
    /// forever). A timeout keeps the relay responsive even when the storage
    /// is stuck: the request fails with a clear error instead of hanging.
    pub db_request_timeout_secs: u64,
    /// Skip the synchronous disk flush after every write batch (LMDB
    /// `MDB_NOSYNC`). Writes land in the OS page cache and are flushed by
    /// the kernel later, which multiplies ingest throughput at the cost of
    /// durability: on a power loss the most recent writes since the last
    /// kernel flush may be lost. The default (false) flushes every batch.
    pub disabled_fsync: bool,
    /// Overload protection: when the database thread's queue holds more than
    /// this many pending messages (or `max_db_queue_events` events), new
    /// database requests fail fast instead of accumulating in memory.
    pub max_db_queue_msgs: usize,
    pub max_db_queue_events: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DaemonConfig {
    pub pid_file: PathBuf,
    pub log_file: PathBuf,
    pub stats_file: PathBuf,
    pub stats_interval_secs: u64,
    /// Rotate the log file when it grows past this many bytes (0 disables
    /// rotation). The old file is renamed to `.1` and older backups shift up
    /// to `max_log_files` backups.
    pub max_log_size_bytes: u64,
    /// Number of rotated log backups to keep (each is the previous generation
    /// of the log file).
    pub max_log_files: u32,
}

impl Default for RelayConfig {
    fn default() -> Self {
        RelayConfig {
            name: "nostrd".into(),
            description: "A minimal and stable Nostr relay".into(),
            pubkey: String::new(),
            contact: String::new(),
            icon: String::new(),
            post_policy: String::new(),
            private_key: String::new(),
            public_url: String::new(),
            livekit_url: String::new(),
            livekit_api_key: String::new(),
            livekit_api_secret: String::new(),
            enabled_nips: Vec::new(),
            disabled_nips: Vec::new(),
            reject_ephemeral: false,
            enabled_git: false,
            require_pow: 0,
            new_pubkey_min_age_secs: 0,
            max_events_per_min_per_pubkey: 0,
            max_groups: 1_000,
            require_auth: false,
            send_auth_challenge: true,
            enabled_nip78_auth: true,
            enabled_command_events: false,
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            host: "127.0.0.1".into(),
            port: 8080,
            api_host: String::new(),
            metrics_enabled: true,
            ws_paths: "root".into(),
            inbox_write_policy: "any".into(),
            outbox_write_policy: "any".into(),
        }
    }
}

impl Default for RpcConfig {
    fn default() -> Self {
        RpcConfig {
            management_port: 0,
            management_host: "127.0.0.1".into(),
            management_token: String::new(),
            admin_pubkey: String::new(),
            max_admin_body_bytes: 64 * 1024,
        }
    }
}

impl Default for LimitsConfig {
    fn default() -> Self {
        LimitsConfig {
            max_connections: 10_000,
            max_connections_per_ip: 64,
            max_ws_message_bytes: 1 << 20,
            socket_recv_buffer_kb: 64,
            max_filters: 20,
            max_subscriptions: 20,
            max_limit: 500,
            max_count: 2_000,
            max_sub_id_len: 64,
            max_content_bytes: 64 * 1024,
            max_tags: 2_000,
            max_tag_value_bytes: 1_024,
            max_created_at_future_secs: 60 * 60,
            max_neg_items: 100_000,
            max_sub_bytes: 1 << 20,
            group_late_publish_secs: 3_600,
            max_api_concurrent: 8,
            max_api_limit: 5_000,
            max_api_offset: 50_000,
            max_api_search_bytes: 2_048,
            max_out_queue_bytes: 256 * 1024,
            ws_idle_timeout_secs: 300,
            live_batch_interval_ms: 20,
            live_batch_size: 32,
            live_buffer: 65_536,
            http_read_timeout_secs: 30,
            max_connections_per_sec_per_ip: 0,
            max_req_response_bytes: 32 * 1024 * 1024,
        }
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        DatabaseConfig {
            path: PathBuf::from("./data"),
            max_dbs: 32,
            max_readers: 128,
            map_size: 1024 * 1024 * 1024,
            // 1 TiB of virtual address space; the actual disk usage grows
            // only with the stored data (sparse file).
            max_map_size: 1024 * 1024 * 1024 * 1024,
            purge_interval_secs: 300,
            reader_threads: 2,
            search_index: true,
            max_indexed_words: 32,
            meta_index: true,
            db_buffer_size: 2_048,
            db_request_timeout_secs: 30,
            disabled_fsync: false,
            max_db_queue_msgs: 4_096,
            max_db_queue_events: 262_144,
        }
    }
}

impl Default for DaemonConfig {
    fn default() -> Self {
        DaemonConfig {
            pid_file: PathBuf::from("./nostrd.pid"),
            log_file: PathBuf::from("./nostrd.log"),
            stats_file: PathBuf::from("./nostrd.stats.json"),
            stats_interval_secs: 5,
            max_log_size_bytes: 50 * 1024 * 1024,
            max_log_files: 5,
        }
    }
}

/// Legacy config aliases: `(old section, old key, new section, new key)`.
/// A config written for an older layout is accepted: the old value is
/// applied to the new location with a deprecation warning (the warning
/// also tells the operator which key to use next time).
const LEGACY_ALIASES: &[(&str, &str, &str, &str)] = &[
    ("relay", "enable_git", "relay", "enabled_git"),
    ("server", "require_auth", "relay", "require_auth"),
    (
        "server",
        "send_auth_challenge",
        "relay",
        "send_auth_challenge",
    ),
    ("server", "management_port", "rpc", "management_port"),
    ("server", "management_host", "rpc", "management_host"),
    ("server", "management_token", "rpc", "management_token"),
    ("server", "admin_pubkey", "rpc", "admin_pubkey"),
    ("limits", "require_pow", "relay", "require_pow"),
    (
        "limits",
        "new_pubkey_min_age_secs",
        "relay",
        "new_pubkey_min_age_secs",
    ),
    (
        "limits",
        "max_events_per_min_per_pubkey",
        "relay",
        "max_events_per_min_per_pubkey",
    ),
    ("limits", "max_groups", "relay", "max_groups"),
    (
        "limits",
        "max_ws_message_size",
        "limits",
        "max_ws_message_bytes",
    ),
    ("limits", "count_limit", "limits", "max_count"),
    ("limits", "neg_max_items", "limits", "max_neg_items"),
    (
        "limits",
        "max_created_at_future",
        "limits",
        "max_created_at_future_secs",
    ),
    (
        "limits",
        "max_conn_per_sec_per_ip",
        "limits",
        "max_connections_per_sec_per_ip",
    ),
    (
        "limits",
        "api_max_concurrent",
        "limits",
        "max_api_concurrent",
    ),
    ("limits", "api_max_limit", "limits", "max_api_limit"),
    ("limits", "api_max_offset", "limits", "max_api_offset"),
    (
        "limits",
        "api_max_search_bytes",
        "limits",
        "max_api_search_bytes",
    ),
    (
        "limits",
        "max_admin_body_bytes",
        "rpc",
        "max_admin_body_bytes",
    ),
    (
        "limits",
        "max_indexed_words",
        "database",
        "max_indexed_words",
    ),
    ("limits", "buffer_size", "database", "db_buffer_size"),
    (
        "limits",
        "db_request_timeout_secs",
        "database",
        "db_request_timeout_secs",
    ),
    ("limits", "db_queue_msgs", "database", "max_db_queue_msgs"),
    (
        "limits",
        "db_queue_events",
        "database",
        "max_db_queue_events",
    ),
    ("database", "map_max_size", "database", "max_map_size"),
    (
        "daemon",
        "log_max_size_bytes",
        "daemon",
        "max_log_size_bytes",
    ),
    ("daemon", "log_max_files", "daemon", "max_log_files"),
];

/// A checked integer cast for the alias application: the legacy values
/// were previously validated by serde's field types (a negative or
/// overflowing value failed the whole config load), so an alias must not
/// silently wrap one into a huge number. On failure the value degrades to
/// the safe default (0) — the config validation rejects the resulting
/// zero limits, and 0 means "disabled" for the policy knobs.
fn alias_int<T: TryFrom<i64> + Default>(v: &toml::Value) -> T {
    v.as_integer()
        .and_then(|i| T::try_from(i).ok())
        .unwrap_or_default()
}

/// A boolean legacy alias: a non-boolean value is warned about instead of
/// being silently dropped to `false` (an auth flag silently disabled is
/// worse than a loudly ignored value).
fn alias_bool(v: &toml::Value, key: &str) -> bool {
    match v.as_bool() {
        Some(b) => b,
        None => {
            log::warn!("deprecated config key {key} expects a boolean; the value was ignored");
            false
        }
    }
}

/// Applies the legacy aliases found in `raw` to `cfg` and warns about
/// each one. The old keys are recognized (never flagged as unknown) and
/// their values land in the new locations.
fn apply_legacy_aliases(raw: &str, cfg: &mut Config) {
    let Ok(value) = raw.parse::<toml::Value>() else {
        return;
    };
    let Some(table) = value.as_table() else {
        return;
    };
    for (old_section, old_key, new_section, new_key) in LEGACY_ALIASES {
        let Some(section) = table.get(*old_section).and_then(toml::Value::as_table) else {
            continue;
        };
        let Some(v) = section.get(*old_key) else {
            continue;
        };
        log::warn!(
            "config key [{old_section}].{old_key} is deprecated; use [{new_section}].{new_key} instead — the value is still applied"
        );
        match (*old_section, *old_key) {
            ("relay", "enable_git") => cfg.relay.enabled_git = alias_bool(v, "relay.enable_git"),
            ("server", "require_auth") => {
                cfg.relay.require_auth = alias_bool(v, "server.require_auth")
            }
            ("server", "send_auth_challenge") => {
                cfg.relay.send_auth_challenge = alias_bool(v, "server.send_auth_challenge")
            }
            ("server", "management_port") => cfg.rpc.management_port = alias_int::<u16>(v),
            ("server", "management_host") => {
                cfg.rpc.management_host = v.as_str().unwrap_or("").to_string()
            }
            ("server", "management_token") => {
                cfg.rpc.management_token = v.as_str().unwrap_or("").to_string()
            }
            ("server", "admin_pubkey") => {
                cfg.rpc.admin_pubkey = v.as_str().unwrap_or("").to_string()
            }
            ("limits", "require_pow") => cfg.relay.require_pow = alias_int::<u8>(v),
            ("limits", "new_pubkey_min_age_secs") => {
                cfg.relay.new_pubkey_min_age_secs = alias_int::<u64>(v)
            }
            ("limits", "max_events_per_min_per_pubkey") => {
                cfg.relay.max_events_per_min_per_pubkey = alias_int::<u64>(v)
            }
            ("limits", "max_groups") => cfg.relay.max_groups = alias_int::<usize>(v),
            ("limits", "max_ws_message_size") => {
                cfg.limits.max_ws_message_bytes = alias_int::<usize>(v)
            }
            ("limits", "count_limit") => cfg.limits.max_count = alias_int::<usize>(v),
            ("limits", "neg_max_items") => cfg.limits.max_neg_items = alias_int::<usize>(v),
            ("limits", "max_created_at_future") => {
                cfg.limits.max_created_at_future_secs = alias_int::<u64>(v)
            }
            ("limits", "max_conn_per_sec_per_ip") => {
                cfg.limits.max_connections_per_sec_per_ip = alias_int::<u64>(v)
            }
            ("limits", "api_max_concurrent") => {
                cfg.limits.max_api_concurrent = alias_int::<usize>(v)
            }
            ("limits", "api_max_limit") => cfg.limits.max_api_limit = alias_int::<usize>(v),
            ("limits", "api_max_offset") => cfg.limits.max_api_offset = alias_int::<usize>(v),
            ("limits", "api_max_search_bytes") => {
                cfg.limits.max_api_search_bytes = alias_int::<usize>(v)
            }
            ("limits", "max_admin_body_bytes") => {
                cfg.rpc.max_admin_body_bytes = alias_int::<usize>(v)
            }
            ("limits", "max_indexed_words") => {
                cfg.database.max_indexed_words = alias_int::<usize>(v)
            }
            ("limits", "buffer_size") => cfg.database.db_buffer_size = alias_int::<usize>(v),
            ("limits", "db_request_timeout_secs") => {
                cfg.database.db_request_timeout_secs = alias_int::<u64>(v)
            }
            ("limits", "db_queue_msgs") => cfg.database.max_db_queue_msgs = alias_int::<usize>(v),
            ("limits", "db_queue_events") => {
                cfg.database.max_db_queue_events = alias_int::<usize>(v)
            }
            ("database", "map_max_size") => cfg.database.max_map_size = alias_int::<usize>(v),
            ("daemon", "log_max_size_bytes") => cfg.daemon.max_log_size_bytes = alias_int::<u64>(v),
            ("daemon", "log_max_files") => cfg.daemon.max_log_files = alias_int::<u32>(v),
            _ => {}
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("cannot read {}: {e}", path.display())))?;
        let mut cfg: Config = toml::from_str(&raw)
            .map_err(|e| Error::Config(format!("invalid {}: {e}", path.display())))?;
        apply_legacy_aliases(&raw, &mut cfg);
        warn_unknown_fields(&raw);
        Ok(cfg)
    }

    pub fn write_default(path: &Path) -> Result<()> {
        if path.exists() {
            return Err(Error::Config(format!(
                "{} already exists, refusing to overwrite",
                path.display()
            )));
        }
        let cfg = Config::default();
        let toml = toml::to_string_pretty(&cfg)
            .map_err(|e| Error::Config(format!("cannot serialize config: {e}")))?;
        std::fs::write(path, toml)?;
        // The file will hold secrets later (the relay private key, S3
        // keys, the management token): create it 0600 so the operator's
        // later edits cannot leave a 0644 config with secrets readable
        // by other users.
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    /// Resolves every relative path against the config file directory so that
    /// paths stay valid after the daemon changes its working directory.
    pub fn absolutize_paths(&mut self, config_path: &Path) {
        let base = match config_path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => {
                std::fs::canonicalize(parent).unwrap_or_else(|_| PathBuf::from(parent))
            }
            _ => std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        };
        let abs = |p: PathBuf| -> PathBuf { if p.is_absolute() { p } else { base.join(p) } };
        self.database.path = abs(self.database.path.clone());
        self.daemon.pid_file = abs(self.daemon.pid_file.clone());
        self.daemon.log_file = abs(self.daemon.log_file.clone());
        self.daemon.stats_file = abs(self.daemon.stats_file.clone());
        // The daemon runs with CWD "/" (see the daemonize step): a
        // relative Blossom storage path must be anchored to the config
        // directory, or the blobs would land in the root filesystem.
        self.blossom.local_path = abs(self.blossom.local_path.clone());
    }

    /// The set of NIPs this relay claims to support (NIP-11).
    ///
    /// Only NIPs with actual relay-side behaviour are advertised: the NIP-11
    /// spec says client-side NIPs SHOULD NOT be advertised, and advertising
    /// them misleads clients (e.g. into relying on NIP-02 or NIP-05 features
    /// this relay does not provide).
    pub fn effective_supported_nips(&self, access: &AccessControl) -> Vec<u16> {
        let base = if !self.relay.enabled_nips.is_empty() {
            self.relay
                .enabled_nips
                .iter()
                .copied()
                .filter(|num| RELAY_NIPS.contains(num))
                .collect::<Vec<_>>()
        } else {
            RELAY_NIPS
                .iter()
                .copied()
                .filter(|num| !self.relay.disabled_nips.contains(num))
                .collect::<Vec<_>>()
        };
        base.into_iter()
            .filter(|nip| {
                if let Some(kinds) = Self::nip_kinds(*nip) {
                    kinds
                        .iter()
                        .any(|k| self.is_kind_effectively_allowed(*k, access))
                } else {
                    // No associated kinds (e.g. NIP-11, NIP-86) — always advertised when enabled.
                    true
                }
            })
            .collect()
    }

    fn is_kind_effectively_allowed(&self, kind: u64, access: &AccessControl) -> bool {
        if !access.allows_kind(kind) {
            return false;
        }
        if !self.relay.enabled_git && Self::is_git_kind(kind) {
            return false;
        }
        if self.relay.reject_ephemeral
            && (20000..30000).contains(&kind)
            && !Self::is_ephemeral_exempt(kind)
        {
            return false;
        }
        true
    }

    /// The NIP-34 git event kinds. `enable_git` gates them at publish time
    /// and (via [`Self::is_kind_effectively_allowed`]) drops NIP-34 from
    /// the advertised list when disabled.
    pub(crate) fn is_git_kind(kind: u64) -> bool {
        matches!(
            kind,
            1617 // NIP-34 Patches
                | 1618 // Pull Requests
                | 1619 // Pull Request Updates
                | 1621 // Issues
                | 1622 // Git Replies (deprecated)
                | 1630
                ..=1633 // Status
                | 30617 // Repository announcements
                | 30618 // Repository state announcements
        )
    }

    fn is_ephemeral_exempt(kind: u64) -> bool {
        matches!(
            kind,
            22242 // NIP-42 AUTH
                | 27235 // NIP-98 HTTP auth
                | 28934 // NIP-43 JOIN
                | 28935 // NIP-43 Invite Request
                | 28936 // NIP-43 LEAVE
                | 24133 // NIP-46 Nostr Connect
                | 23194 // NIP-47 wallet request
                | 23195 // NIP-47 wallet response
                | 24242 // BUD-02 Blossom / NIP-B7 blobs
                | 21059 // NIP-59 ephemeral gift wrap
        )
    }

    fn nip_kinds(nip: u16) -> Option<&'static [u64]> {
        match nip {
            1 => None, // core — always advertised
            9 => Some(&[5]),
            11 => None,
            13 => None,
            17 => Some(&[14, 15, 1059, 21059]),
            22 => Some(&[1111]),
            26 => None,
            28 => Some(&[40, 41, 42, 43, 44]),
            29 => Some(&[
                9000, 9001, 9002, 9003, 9004, 9005, 9006, 9007, 9008, 9009, 9010, 9020, 9021, 9022,
                39000, 39001, 39002, 39005,
            ]),
            32 => Some(&[1985]),
            33 => None, // range 30000-39999 — not checked against kind block lists
            34 => Some(&[
                1617, 1618, 1619, 1621, 1622, 1630, 1631, 1632, 1633, 30617, 30618,
            ]),
            40 => None,
            42 => Some(&[22242]),
            43 => Some(&[8000, 8001, 28934, 28935, 28936, 33534, 13534]),
            45 => None,
            46 => Some(&[24133]),
            47 => Some(&[23194, 23195]),
            50 => None,
            57 => Some(&[9734, 9735]),
            59 => Some(&[1059, 21059]),
            62 => Some(&[62]),
            65 => Some(&[10002]),
            66 => Some(&[30166, 10166]),
            67 => None,
            70 => None,
            77 => None,
            78 => Some(&[30078]),
            84 => Some(&[9802]),
            85 => Some(&[30382, 30383, 30384]),
            86 => None,
            87 => Some(&[38172, 38173]),
            88 => Some(&[1018, 1068]),
            94 => Some(&[1063]),
            98 => Some(&[27235]),
            _ => None,
        }
    }

    /// The relay's own URL identity (host:port plus the optional public
    /// URL), used by the NIP-42/62/98 tag validations.
    pub fn relay_identity(&self) -> crate::nips::nip62::RelayIdentity<'_> {
        crate::nips::nip62::RelayIdentity::new(
            &self.server.host,
            self.server.port,
            &self.relay.public_url,
        )
    }

    pub fn nip_enabled(&self, num: u16) -> bool {
        if !self.relay.enabled_nips.is_empty() {
            return self.relay.enabled_nips.contains(&num);
        }
        !self.relay.disabled_nips.contains(&num)
    }

    /// Validates the configuration values. Returns a clear error message for
    /// the first problem found, so `nostrd check` and startup fail fast
    /// instead of misbehaving at runtime with a typo'd key or an impossible
    /// database layout.
    pub fn validate(&self) -> Result<()> {
        // Hex key format checks.
        let hex32 = |value: &str, what: &str| -> Result<()> {
            if value.is_empty() {
                return Ok(());
            }
            match hex::decode(value) {
                Ok(b) if b.len() == 32 => Ok(()),
                _ => Err(Error::Config(format!(
                    "{what} must be 64 hex characters (32 bytes), got {value:?}"
                ))),
            }
        };
        hex32(&self.relay.pubkey, "relay.pubkey")?;
        hex32(&self.rpc.admin_pubkey, "rpc.admin_pubkey")?;

        // Secret key: must be a valid secp256k1 secret key when set.
        if !self.relay.private_key.is_empty() {
            let bytes = hex::decode(&self.relay.private_key)
                .map_err(|_| Error::Config("relay.private_key must be 64 hex characters".into()))?;
            if bytes.len() != 32 {
                return Err(Error::Config("relay.private_key must be 32 bytes".into()));
            }
            secp256k1::SecretKey::from_slice(&bytes).map_err(|_| {
                Error::Config("relay.private_key is not a valid secp256k1 secret key".into())
            })?;
        }

        // Ports.
        if self.server.port == 0 {
            return Err(Error::Config(
                "server.port must be between 1 and 65535".into(),
            ));
        }
        // WebSocket path selection.
        if !matches!(self.server.ws_paths.trim(), "root" | "inbox-outbox" | "all") {
            return Err(Error::Config(format!(
                "server.ws_paths must be \"root\", \"inbox-outbox\" or \"all\", got {:?}",
                self.server.ws_paths
            )));
        }
        // Inbox write policy.
        if !matches!(self.server.inbox_write_policy.trim(), "any" | "relay") {
            return Err(Error::Config(format!(
                "server.inbox_write_policy must be \"any\" or \"relay\", got {:?}",
                self.server.inbox_write_policy
            )));
        }
        // Outbox write policy.
        if !matches!(self.server.outbox_write_policy.trim(), "any" | "relay") {
            return Err(Error::Config(format!(
                "server.outbox_write_policy must be \"any\" or \"relay\", got {:?}",
                self.server.outbox_write_policy
            )));
        }
        if self.rpc.management_port > 0 && self.rpc.management_port == self.server.port {
            return Err(Error::Config(
                "rpc.management_port must differ from server.port".into(),
            ));
        }
        // Host split hostnames must be bare hostnames: a scheme, path or
        // port in the config would never match a request Host header and
        // silently hide the split routes (or, worse, the whole API).
        for (name, value) in [
            ("server.api_host", self.server.api_host.as_str()),
            ("blossom.host", self.blossom.host.as_str()),
        ] {
            if value.trim().is_empty() {
                // A whitespace-only value is a config error: the runtime
                // treats it as non-empty, and the split routes would be
                // blocked on every host (the whole API silently 404s).
                if !value.is_empty() {
                    return Err(Error::Config(format!(
                        "{name} must be a bare hostname or empty, got {value:?}"
                    )));
                }
                continue;
            }
            // A bare hostname must only contain hostname characters: a
            // whitespace or control character (e.g. `api host` or a
            // trailing newline) could never match a request Host header
            // and would silently hide the whole API / Blossom server
            // (404 on every request). IPv6 literals keep their brackets
            // and colons; underscores are tolerated (common in practice).
            let valid_chars = value.chars().all(|c| {
                c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '[' | ']')
            });
            if value.contains('/') || !valid_chars || bare_host_has_port(value.trim()) {
                return Err(Error::Config(format!(
                    "{name} must be a bare hostname (no scheme, port, path or whitespace), got {value:?}"
                )));
            }
        }
        // `server.api_host` and `blossom.host` split the same port by Host
        // header: the same hostname for both would make the relay's
        // WebSocket endpoint unreachable on it.
        if !self.server.api_host.trim().is_empty()
            && !self.blossom.host.trim().is_empty()
            && self
                .server
                .api_host
                .trim()
                .trim_matches(['[', ']'])
                .eq_ignore_ascii_case(self.blossom.host.trim().trim_matches(['[', ']']))
        {
            return Err(Error::Config(
                "server.api_host and blossom.host must be different hostnames".into(),
            ));
        }

        // Blocked IPs must parse as IP addresses.
        for (ip, _) in &self.access.blocked_ips {
            ip.parse::<std::net::IpAddr>().map_err(|_| {
                Error::Config(format!(
                    "access.blocked_ips contains an invalid IP address: {ip:?}"
                ))
            })?;
        }

        // Database layout.
        if self.database.map_size > self.database.max_map_size {
            return Err(Error::Config(
                "database.map_size must not exceed database.max_map_size".into(),
            ));
        }

        // NIP toggles: `enabled_nips` wins silently; surface the ambiguity.
        if !self.relay.enabled_nips.is_empty() && !self.relay.disabled_nips.is_empty() {
            log::warn!(
                "relay.enabled_nips and relay.disabled_nips are both set; enabled_nips wins"
            );
        }

        // `require_auth` only takes effect when NIP-42 is enabled (the
        // AUTH message is the only way to authenticate); silently ignoring
        // it would leave a supposedly auth-required relay wide open.
        if self.relay.require_auth && !self.nip_enabled(42) {
            return Err(Error::Config(
                "relay.require_auth requires NIP-42 to be enabled (add 42 to relay.enabled_nips or remove 42 from relay.disabled_nips)".into(),
            ));
        }
        // `enabled_nip78_auth` has the same footgun: with NIP-42 disabled nobody
        // can authenticate, so every kind 78/30078 event would be rejected
        // at publish and never served.
        if self.relay.enabled_nip78_auth && !self.nip_enabled(42) {
            return Err(Error::Config(
                "relay.enabled_nip78_auth requires NIP-42 to be enabled (add 42 to relay.enabled_nips or remove 42 from relay.disabled_nips)".into(),
            ));
        }
        if self.relay.enabled_nip78_auth && !self.nip_enabled(78) {
            log::warn!(
                "relay.enabled_nip78_auth is set but NIP-78 is not enabled; the AUTH gate is inactive"
            );
        }
        // Limits must be usable (zero would disable core functionality or
        // make the queue fail fast on the first request).
        let l = &self.limits;
        let nonzero = [
            ("limits.max_connections", l.max_connections),
            ("limits.max_ws_message_bytes", l.max_ws_message_bytes),
            ("limits.max_filters", l.max_filters),
            ("limits.max_subscriptions", l.max_subscriptions),
            ("limits.max_limit", l.max_limit),
            ("limits.max_count", l.max_count),
            ("limits.max_neg_items", l.max_neg_items),
            ("limits.max_sub_bytes", l.max_sub_bytes),
            ("limits.max_api_concurrent", l.max_api_concurrent),
            ("limits.live_buffer", l.live_buffer),
            ("limits.live_batch_size", l.live_batch_size),
            ("limits.max_out_queue_bytes", l.max_out_queue_bytes),
        ];
        let db_nonzero = [
            ("database.db_buffer_size", self.database.db_buffer_size),
            ("database.reader_threads", self.database.reader_threads),
            (
                "database.max_indexed_words",
                self.database.max_indexed_words,
            ),
            (
                "database.max_db_queue_msgs",
                self.database.max_db_queue_msgs,
            ),
            (
                "database.max_db_queue_events",
                self.database.max_db_queue_events,
            ),
        ];
        if self.limits.socket_recv_buffer_kb > 4096 {
            return Err(Error::Config(
                "limits.socket_recv_buffer_kb must be at most 4096".into(),
            ));
        }
        if !(1..=64).contains(&self.database.reader_threads) {
            return Err(Error::Config(
                "database.reader_threads must be between 1 and 64".into(),
            ));
        }
        for (name, value) in db_nonzero {
            if value == 0 {
                return Err(Error::Config(format!("{name} must be at least 1 (got 0)")));
            }
        }
        for (name, value) in nonzero {
            if value == 0 {
                return Err(Error::Config(format!("{name} must be at least 1 (got 0)")));
            }
        }

        // NIP-42 AUTH relay-tag, NIP-62 vanish and NIP-86 NIP-98 admin auth
        // all compare client URLs against `relay_identity()`. With an empty
        // `public_url` that identity is `server.host:server.port`; a
        // wildcard or loopback bind (0.0.0.0, ::, 127.0.0.1) never matches a
        // client's real hostname, silently breaking all three. Warn loudly.
        if self.relay.public_url.trim().is_empty() {
            let host = self.server.host.trim();
            if matches!(host, "0.0.0.0" | "::" | "127.0.0.1" | "::1" | "localhost") {
                log::warn!(
                    "relay.public_url is empty and server.host is {host:?}: NIP-42 AUTH, \
                     NIP-62 vanish and NIP-86 NIP-98 auth will not match client URLs; \
                     set relay.public_url to the public wss:// address"
                );
            }
        } else if !self.relay.public_url.contains("://") {
            log::warn!(
                "relay.public_url {0:?} has no scheme (wss:///ws://); set it to the public \
                 wss:// address or NIP-42/62/98 URL matching may fail",
                self.relay.public_url
            );
        }

        // Paths must be non-empty: an empty database path would silently open
        // the LMDB environment inside the config file's directory.
        if self.database.path.as_os_str().is_empty() {
            return Err(Error::Config("database.path must not be empty".into()));
        }
        if self.daemon.pid_file.as_os_str().is_empty()
            || self.daemon.log_file.as_os_str().is_empty()
            || self.daemon.stats_file.as_os_str().is_empty()
        {
            return Err(Error::Config(
                "daemon.pid_file, daemon.log_file and daemon.stats_file must not be empty".into(),
            ));
        }

        // LiveKit configuration must be complete when enabled.
        if !self.relay.livekit_url.trim().is_empty()
            && (self.relay.livekit_api_key.trim().is_empty()
                || self.relay.livekit_api_secret.trim().is_empty())
        {
            log::warn!(
                "relay.livekit_url is set but livekit_api_key/livekit_api_secret are empty: \
                 tokens will be signed with an empty secret and rejected by LiveKit"
            );
        }

        // A very high PoW requirement makes every event infeasible to mine;
        // warn instead of silently disabling writes.
        if self.relay.require_pow >= 64 {
            log::warn!(
                "config.relay.require_pow = {} is practically unmineable; new events will be \
                 rejected with 'pow: difficulty requirement not reached'",
                self.relay.require_pow
            );
        }

        // `require_auth` with `send_auth_challenge = false` is a total
        // lockout: the challenge is only ever sent on connect, so nobody can
        // authenticate and every REQ/EVENT/COUNT is refused.
        if self.relay.require_auth && !self.relay.send_auth_challenge {
            log::warn!(
                "relay.require_auth is true but relay.send_auth_challenge is false: the \
                 AUTH challenge is never sent, so no client can authenticate and all \
                 REQ/EVENT/COUNT messages will be refused"
            );
        }

        // NIP-29: the group metadata/members/admins snapshots (39000-39005)
        // are relay-signed and are only generated when the relay has a key.
        // Without one, clients get no 39001/39002 at group creation.
        if self.nip_enabled(29) && self.relay.private_key.trim().is_empty() {
            log::warn!(
                "relay.private_key is empty while NIP-29 is enabled: the relay cannot sign \
                 group metadata (39000-39005), so 39001 (admins) / 39002 (members) snapshots \
                 are not generated at group creation; run 'nostrd genkey' to set a key"
            );
        }

        // Command events: the admin pubkey (`relay.pubkey`) issues them and
        // `relay.private_key` signs the replies; warn when either is missing.
        if self.relay.enabled_command_events {
            if self.relay.pubkey.trim().is_empty() {
                log::warn!(
                    "relay.enabled_command_events is true but relay.pubkey is empty: no \
                     kind:1 command events can be recognized; set relay.pubkey to the \
                     admin pubkey"
                );
            }
            if self.relay.private_key.trim().is_empty() {
                log::warn!(
                    "relay.enabled_command_events is true but relay.private_key is empty: \
                     the kind:1111 replies cannot be signed; run 'nostrd genkey' to set a key"
                );
            }
        }

        // Blossom file server: the storage backend must be known, and S3
        // storage needs its credentials. The feature is opt-in via `host`.
        let b = &self.blossom;
        if !b.host.trim().is_empty() {
            if b.max_upload_bytes == 0 {
                return Err(Error::Config(
                    "blossom.max_upload_bytes must be at least 1".into(),
                ));
            }
            match b.storage.as_str() {
                "local" => {
                    if b.local_path.as_os_str().is_empty() {
                        return Err(Error::Config("blossom.local_path must not be empty".into()));
                    }
                }
                "s3" => {
                    if b.s3_endpoint.trim().is_empty()
                        || b.s3_bucket.trim().is_empty()
                        || b.s3_access_key.trim().is_empty()
                        || b.s3_secret_key.trim().is_empty()
                    {
                        return Err(Error::Config(
                            "blossom.storage = \"s3\" requires s3_endpoint, s3_bucket, \
                             s3_access_key and s3_secret_key"
                                .into(),
                        ));
                    }
                }
                other => {
                    return Err(Error::Config(format!(
                        "blossom.storage must be \"local\" or \"s3\", got {other:?}"
                    )));
                }
            }
        }
        Ok(())
    }
}

/// Whether a bare hostname contains a `:` outside IPv6 brackets (i.e. a
/// port). `[::1]` is fine; `media.example.com:8080` and the unbracketed
/// `::1` (the host-split matching brackets IPv6 literals, so the
/// unbracketed form could never match a Host header) are not.
fn bare_host_has_port(host: &str) -> bool {
    host.contains(':') && !host.starts_with('[')
}

/// Whether a string is a 64-hex pubkey or a parseable `npub1...`.
/// Shared with the CLI (`nostrd blossom allow/deny`).
pub(crate) fn is_pubkey_or_npub(value: &str) -> bool {
    if value.len() == 64 && hex::decode(value).map(|b| b.len() == 32).unwrap_or(false) {
        return true;
    }
    if value.starts_with("npub1")
        && crate::nips::nip19::parse_nip19(value)
            .is_ok_and(|e| matches!(e, crate::nips::nip19::Nip19Entity::Pubkey(_)))
    {
        return true;
    }
    false
}

// The pubkey allow/deny lists are runtime state managed via
// `nostrd relay allow/deny` and NIP-86, persisted in the relay database
// (LMDB) — not in the config file (see `restrict_relay`). The fields stay
// in this struct for the in-memory checks but are excluded from both the
// TOML `[access]` section and the persisted JSON.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AccessControl {
    /// (pubkey, reason) pairs; the reason is reported by NIP-86
    /// `listbannedpubkeys`. Persisted in LMDB under `relay_pubkeys`.
    #[serde(skip)]
    pub blocked_pubkeys: Vec<(String, String)>,
    #[serde(skip)]
    pub allowed_pubkeys: Vec<(String, String)>,
    pub blocked_kinds: Vec<u64>,
    pub allowed_kinds: Vec<u64>,
    /// (ip, reason) pairs, reported by NIP-86 `listblockedips`.
    #[serde(deserialize_with = "de_access_entries")]
    pub blocked_ips: Vec<(String, String)>,
    /// When true, only the pubkeys on the allow list (`nostrd relay allow`)
    /// may publish. When false (default), everyone except the denied
    /// pubkeys may publish.
    pub restrict_relay: bool,
}

/// Deserializes an access list that accepts both the current format —
/// `[["pubkey", "reason"], ...]` — and the legacy format — `["pubkey", ...]`
/// (plain strings). The persisted JSON and the TOML `[access]` section both
/// go through this, so upgrading never fails to read the old data: the
/// legacy entries simply get an empty reason.
fn de_access_entries<'de, D>(de: D) -> std::result::Result<Vec<(String, String)>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let items: Vec<serde_json::Value> = serde::Deserialize::deserialize(de)?;
    items
        .into_iter()
        .map(|v| match v {
            serde_json::Value::String(s) => Ok((s, String::new())),
            serde_json::Value::Array(a) if a.len() >= 2 && a[0].is_string() && a[1].is_string() => {
                Ok((
                    a[0].as_str().unwrap().to_string(),
                    a[1].as_str().unwrap().to_string(),
                ))
            }
            other => Err(serde::de::Error::custom(format!(
                "invalid access list entry: {other}"
            ))),
        })
        .collect()
}

impl AccessControl {
    pub fn allows_pubkey(&self, pubkey: &str) -> bool {
        // A denied pubkey is always rejected — even when restrict_relay
        // is off (the default: everyone else may publish).
        if self.blocked_pubkeys.iter().any(|(p, _)| p == pubkey) {
            return false;
        }
        !self.restrict_relay || self.allowed_pubkeys.iter().any(|(p, _)| p == pubkey)
    }

    pub fn allows_kind(&self, kind: u64) -> bool {
        if self.blocked_kinds.contains(&kind) {
            return false;
        }
        self.allowed_kinds.is_empty() || self.allowed_kinds.contains(&kind)
    }
}

/// Escapes a string for a TOML basic string literal. The TOML spec requires
/// every control character (U+0000-U+0008, U+000A-U+001F, U+007F) to be
/// escaped; leaving one raw would make the written config file unparseable.
pub(crate) fn toml_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 8);
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// Replaces (or inserts) a `field = "value"` line inside the `[relay]`
/// section of a config file's text, preserving every other line, comment
/// and section. Handles three cases: a matching line already present in the
/// `[relay]` section (replaced), no such line in `[relay]` (inserted right
/// after the header), and no `[relay]` section at all (appended).
/// Used by `nostrd genkey` (private_key) and the NIP-86 relay-name changes.
pub(crate) fn set_relay_field_in_text(text: &str, field: &str, value: &str) -> String {
    let line = format!("{field} = \"{}\"", toml_escape(value));

    // Locate a real `[relay]` section header: a line whose trimmed text
    // starts with `[relay]` followed by `]`. A `[relay]` inside a comment or
    // a string value is not a section header and must not match.
    let mut header_start = None;
    let mut offset = 0;
    for l in text.split_inclusive('\n') {
        let t = l.trim();
        // `[relay]` header line: exactly `[relay]`, or `[relay]` followed by
        // whitespace or a comment. A `[relay]` inside a comment or a string
        // value does not start with `[relay]` as a header.
        if t == "[relay]"
            || t.starts_with("[relay] ")
            || t.starts_with("[relay]\t")
            || t.starts_with("[relay]#")
        {
            header_start = Some(offset);
            break;
        }
        offset += l.len();
    }
    let Some(header_start) = header_start else {
        // No [relay] section: append one at the end.
        let mut s = text.to_string();
        if !s.ends_with('\n') {
            s.push('\n');
        }
        s.push_str(&format!("[relay]\n{line}\n"));
        return s;
    };

    // The header line ends at the first newline after its start (or EOF when
    // it is the last line without a trailing newline).
    let header_end = text[header_start..]
        .find('\n')
        .map(|i| header_start + i + 1)
        .unwrap_or(text.len());

    // Bound the section at the next `[section]` header line.
    let mut section_end = text.len();
    let mut cursor = header_end;
    for l in text[header_end..].split_inclusive('\n') {
        let t = l.trim();
        if t.starts_with('[') && t.ends_with(']') {
            section_end = cursor;
            break;
        }
        cursor += l.len();
    }
    let section = &text[header_end..section_end];

    // Case 1: a matching line already exists in the section — replace it.
    // The line must be the field itself (followed by `=`, whitespace or
    // end-of-line), not an unrelated key that merely starts with the
    // field name (unknown keys are warned about but never rejected, so
    // e.g. `private_key_note = "x"` must not be clobbered by genkey).
    if let Some(offset) = section.lines().position(|l| {
        l.trim_start().strip_prefix(field).is_some_and(|rest| {
            rest.is_empty() || rest.starts_with('=') || rest.starts_with([' ', '\t'])
        })
    }) {
        let mut new_section = String::new();
        for (i, l) in section.lines().enumerate() {
            if i == offset {
                let indent: String = l.chars().take_while(|c| c.is_whitespace()).collect();
                new_section.push_str(&format!("{indent}{line}\n"));
            } else {
                new_section.push_str(l);
                new_section.push('\n');
            }
        }
        let mut s = text.to_string();
        s.replace_range(header_end..section_end, &new_section);
        return s;
    }

    // Case 2: no matching line — insert it right after the `[relay]`
    // header line, keeping the header on its own line even when the header
    // is the last line of the file without a trailing newline.
    let mut s = text.to_string();
    if header_end >= s.len() {
        // Header is the last line without a trailing newline.
        s.push('\n');
        s.push_str(&line);
        s.push('\n');
    } else {
        s.insert_str(header_end, &format!("{line}\n"));
    }
    s
}

/// Writes `text` to `path` atomically (temp file + rename) so a crash in
/// the middle of a write never leaves a truncated config file behind.
/// The temp is created `0600` and the target's permissions are applied
/// *after* the rename: the new content is never readable by others, not
/// even during the write window, and a normal 0644 config stays 0644
/// while a 0600 config (holding the relay private key) stays 0600.
/// The stricter of two permission modes (bitwise AND keeps exactly the
/// intersection): restoring a config's mode must never widen a
/// concurrent `genkey`'s 0600 back to a stale 0644 capture.
fn stricter_mode(captured: u32, current: u32) -> u32 {
    captured & current
}

pub(crate) fn write_text_atomic(path: &Path, text: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let tmp = path.with_extension("tmp");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    file.write_all(text.as_bytes())?;
    drop(file);
    // Apply the final mode to the temp *before* the rename, intersecting
    // the pre-write mode with the file's current mode: the intersection
    // is the stricter of the two, so a concurrent `genkey` that set 0600
    // cannot be widened back to a stale 0644 capture — while a plain
    // (secret-free) 0644 config stays 0644. The temp's 0600 creation
    // covers the window before this point, and a non-file target (the
    // rename below fails) leaves the temp at 0600.
    if let Ok(meta) = std::fs::metadata(path)
        && meta.is_file()
    {
        let captured = meta.permissions().mode() & 0o777;
        let current = std::fs::metadata(path)
            .map(|m| PermissionsExt::mode(&m.permissions()) & 0o777)
            .unwrap_or(captured);
        let _ = std::fs::set_permissions(
            &tmp,
            std::fs::Permissions::from_mode(stricter_mode(captured, current)),
        );
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Warns about config keys the schema does not know (a typo like
/// `server.potr = 9000` would otherwise be silently ignored and the relay
/// start with the default value). Implemented as a warning rather than a
/// hard error because older config files legitimately carry keys the schema
/// dropped (e.g. `software`/`version`).
/// The known config keys per section, used by [`warn_unknown_fields`] to
/// flag typos. A section or key missing from this list makes `nostrd check`
/// (and every start) warn about perfectly valid settings — the list must
/// cover every serializable field (enforced by the
/// `known_keys_cover_every_serialized_field` test).
fn known_config_keys() -> &'static [(&'static str, &'static [&'static str])] {
    &[
        // `software`/`version` were part of the older config template and
        // are recognized (and ignored) so operators upgrading from it are
        // not warned about them on every start.
        (
            "relay",
            &[
                "name",
                "description",
                "pubkey",
                "contact",
                "icon",
                "post_policy",
                "private_key",
                "public_url",
                "livekit_url",
                "livekit_api_key",
                "livekit_api_secret",
                "enabled_nips",
                "disabled_nips",
                "reject_ephemeral",
                "enabled_git",
                "require_pow",
                "new_pubkey_min_age_secs",
                "max_events_per_min_per_pubkey",
                "max_groups",
                "require_auth",
                "send_auth_challenge",
                "enabled_nip78_auth",
                "enabled_command_events",
                "enable_git",
                "software",
                "version",
            ],
        ),
        (
            "server",
            &[
                "host",
                "port",
                "api_host",
                "ws_paths",
                "inbox_write_policy",
                "outbox_write_policy",
                "metrics_enabled",
                "management_port",
                "management_host",
                "management_token",
                "admin_pubkey",
                "require_auth",
                "send_auth_challenge",
            ],
        ),
        (
            "rpc",
            &[
                "management_port",
                "management_host",
                "management_token",
                "admin_pubkey",
                "max_admin_body_bytes",
            ],
        ),
        (
            "limits",
            &[
                "max_connections",
                "max_connections_per_ip",
                "max_ws_message_bytes",
                "socket_recv_buffer_kb",
                "max_filters",
                "max_subscriptions",
                "max_limit",
                "max_count",
                "max_sub_id_len",
                "max_content_bytes",
                "max_tags",
                "max_tag_value_bytes",
                "max_created_at_future_secs",
                "max_neg_items",
                "max_sub_bytes",
                "group_late_publish_secs",
                "max_api_concurrent",
                "max_api_limit",
                "max_api_offset",
                "max_api_search_bytes",
                "max_out_queue_bytes",
                "ws_idle_timeout_secs",
                "live_batch_interval_ms",
                "live_batch_size",
                "live_buffer",
                "http_read_timeout_secs",
                "max_connections_per_sec_per_ip",
                "max_req_response_bytes",
                "max_ws_message_size",
                "count_limit",
                "neg_max_items",
                "api_max_concurrent",
                "api_max_limit",
                "api_max_offset",
                "api_max_search_bytes",
                "max_created_at_future",
                "max_admin_body_bytes",
                "max_groups",
                "require_pow",
                "max_indexed_words",
                "buffer_size",
                "db_request_timeout_secs",
                "new_pubkey_min_age_secs",
                "db_queue_msgs",
                "db_queue_events",
                "max_conn_per_sec_per_ip",
                "max_events_per_min_per_pubkey",
            ],
        ),
        (
            "database",
            &[
                "path",
                "max_dbs",
                "max_readers",
                "map_size",
                "max_map_size",
                "purge_interval_secs",
                "reader_threads",
                "search_index",
                "max_indexed_words",
                "meta_index",
                "db_buffer_size",
                "db_request_timeout_secs",
                "disabled_fsync",
                "max_db_queue_msgs",
                "max_db_queue_events",
                "map_max_size",
            ],
        ),
        (
            "daemon",
            &[
                "pid_file",
                "log_file",
                "stats_file",
                "stats_interval_secs",
                "max_log_size_bytes",
                "max_log_files",
                "log_max_size_bytes",
                "log_max_files",
            ],
        ),
        (
            "access",
            &[
                "blocked_kinds",
                "allowed_kinds",
                "blocked_ips",
                "restrict_relay",
            ],
        ),
        (
            "blossom",
            &[
                "host",
                "storage",
                "local_path",
                "max_upload_bytes",
                "min_free_bytes",
                "s3_endpoint",
                "s3_region",
                "s3_bucket",
                "s3_access_key",
                "s3_secret_key",
                "restrict_uploads",
            ],
        ),
    ]
}

fn warn_unknown_fields(raw: &str) {
    let Ok(value) = raw.parse::<toml::Value>() else {
        return;
    };
    let known = known_config_keys();
    let Some(table) = value.as_table() else {
        return;
    };
    // Unknown top-level sections (e.g. a typo'd `[serve]` instead of
    // `[server]`) are silently ignored by serde; warn so the operator
    // notices the section never took effect.
    for (section, table) in table {
        let Some(keys) = known.iter().find(|(s, _)| s == section).map(|(_, k)| *k) else {
            log::warn!(
                "unknown config section [{section}] is ignored; check the spelling \
                 (the relay runs with the defaults for this section)"
            );
            continue;
        };
        let Some(table) = table.as_table() else {
            continue;
        };
        for (key, _) in table {
            if !keys.contains(&key.as_str()) {
                log::warn!(
                    "unknown config key [{section}].{key} is ignored; check the spelling \
                     (the relay runs with the default for this field)"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_keys_cover_every_serialized_field() {
        // The `warn_unknown_fields` list must cover every serializable
        // config field, or `nostrd check` (and every start) warns about
        // perfectly valid settings. Serialize the default config and
        // cross-check every emitted section and key against the list.
        let cfg = Config::default();
        let raw = toml::to_string(&cfg).unwrap();
        let value: toml::Value = raw.parse().unwrap();
        let known = known_config_keys();
        for (section, keys) in known {
            let Some(table) = value.get(*section).and_then(toml::Value::as_table) else {
                continue;
            };
            for key in table.keys() {
                assert!(
                    keys.contains(&key.as_str()),
                    "config key [{section}].{key} is missing from the known-keys list"
                );
            }
        }
        for section in value.as_table().unwrap().keys() {
            assert!(
                known.iter().any(|(s, _)| s == section),
                "config section [{section}] is missing from the known-keys list"
            );
        }
    }

    #[test]
    fn set_relay_field_does_not_clobber_prefix_matches() {
        // Unknown keys are warned about but never rejected, so a line that
        // merely starts with the field name (e.g. `name_note`) must not be
        // replaced — only the exact `field = ...` line is.
        let text = "[relay]\nname = \"relay\"\nname_note = \"keep\"\nother = 1\n";
        let out = set_relay_field_in_text(text, "name", "renamed");
        assert!(out.contains("name = \"renamed\""), "{out}");
        assert!(out.contains("name_note = \"keep\""), "{out}");
        assert!(out.contains("other = 1"), "{out}");
        // The same boundary protects the private key: `private_key_note`
        // is not the `private_key` line.
        let text = "[relay]\nprivate_key_note = \"x\"\n";
        let out = set_relay_field_in_text(text, "private_key", "ab");
        assert!(out.contains("private_key = \"ab\""), "{out}");
        assert!(out.contains("private_key_note = \"x\""), "{out}");
    }

    #[test]
    fn legacy_aliases_apply_and_warn() {
        // A config written for the old layout is accepted: every legacy
        // key lands in its new location.
        let raw = r#"
[relay]
enable_git = true
[server]
require_auth = true
send_auth_challenge = false
management_port = 9999
management_host = "127.0.0.2"
management_token = "old-token"
admin_pubkey = "abababababababababababababababababababababababababababababababab"
[limits]
require_pow = 4
new_pubkey_min_age_secs = 60
max_events_per_min_per_pubkey = 30
max_groups = 7
max_ws_message_size = 4096
count_limit = 123
neg_max_items = 99
max_created_at_future = 300
max_conn_per_sec_per_ip = 5
api_max_concurrent = 3
api_max_limit = 11
api_max_offset = 22
api_max_search_bytes = 33
max_admin_body_bytes = 1024
max_indexed_words = 64
buffer_size = 512
db_request_timeout_secs = 9
db_queue_msgs = 88
db_queue_events = 77
[database]
map_max_size = 1073741824
[daemon]
log_max_size_bytes = 12345
log_max_files = 2
"#;
        let cfg: Config = toml::from_str(raw).unwrap();
        let mut cfg = cfg;
        apply_legacy_aliases(raw, &mut cfg);
        assert!(cfg.relay.enabled_git);
        assert!(cfg.relay.require_auth);
        assert!(!cfg.relay.send_auth_challenge);
        assert_eq!(cfg.rpc.management_port, 9999);
        assert_eq!(cfg.rpc.management_host, "127.0.0.2");
        assert_eq!(cfg.rpc.management_token, "old-token");
        assert_eq!(cfg.rpc.admin_pubkey, "ab".repeat(32));
        assert_eq!(cfg.relay.require_pow, 4);
        assert_eq!(cfg.relay.new_pubkey_min_age_secs, 60);
        assert_eq!(cfg.relay.max_events_per_min_per_pubkey, 30);
        assert_eq!(cfg.relay.max_groups, 7);
        assert_eq!(cfg.limits.max_ws_message_bytes, 4096);
        assert_eq!(cfg.limits.max_count, 123);
        assert_eq!(cfg.limits.max_neg_items, 99);
        assert_eq!(cfg.limits.max_created_at_future_secs, 300);
        assert_eq!(cfg.limits.max_connections_per_sec_per_ip, 5);
        assert_eq!(cfg.limits.max_api_concurrent, 3);
        assert_eq!(cfg.limits.max_api_limit, 11);
        assert_eq!(cfg.limits.max_api_offset, 22);
        assert_eq!(cfg.limits.max_api_search_bytes, 33);
        assert_eq!(cfg.rpc.max_admin_body_bytes, 1024);
        assert_eq!(cfg.database.max_indexed_words, 64);
        assert_eq!(cfg.database.db_buffer_size, 512);
        assert_eq!(cfg.database.db_request_timeout_secs, 9);
        assert_eq!(cfg.database.max_db_queue_msgs, 88);
        assert_eq!(cfg.database.max_db_queue_events, 77);
        assert_eq!(cfg.database.max_map_size, 1 << 30);
        assert_eq!(cfg.daemon.max_log_size_bytes, 12345);
        assert_eq!(cfg.daemon.max_log_files, 2);
    }

    #[test]
    fn legacy_aliases_do_not_wrap_invalid_values() {
        // The old serde field types rejected a negative or overflowing
        // value at load time; an alias must not silently wrap one into a
        // huge number. Invalid values degrade to 0 (safe defaults).
        let raw = "[limits]\ncount_limit = -5\nmax_groups = -1\nmanagement_port = 70000\n";
        let cfg: Config = toml::from_str(raw).unwrap();
        let mut cfg = cfg;
        apply_legacy_aliases(raw, &mut cfg);
        assert_eq!(
            cfg.limits.max_count, 0,
            "a negative count_limit must not wrap"
        );
        assert_eq!(
            cfg.relay.max_groups, 0,
            "a negative max_groups must not wrap"
        );
        assert_eq!(
            cfg.rpc.management_port, 0,
            "an overflowing port must not wrap"
        );
    }

    #[test]
    fn legacy_aliases_in_known_keys_are_not_unknown() {
        // The legacy keys must be recognized by `warn_unknown_fields`:
        // they are deprecated, not unknown.
        let raw = "[limits]\ncount_limit = 5\n";
        warn_unknown_fields(raw);
        // (no assertion: the deprecated keys would produce a warning,
        // never an "unknown config key" warning — the test guards the
        // known-keys list via `known_keys_cover_every_serialized_field`
        // and the alias table above.)
        let known = known_config_keys();
        for (old_section, old_key, _, _) in LEGACY_ALIASES {
            let keys = known
                .iter()
                .find(|(s, _)| s == old_section)
                .map(|(_, k)| *k)
                .unwrap();
            assert!(
                keys.contains(old_key),
                "legacy key [{old_section}].{old_key} must stay in the known-keys list"
            );
        }
    }

    #[test]
    fn blossom_allowlist_pubkey_validation() {
        assert!(is_pubkey_or_npub(&"a".repeat(64)));
        assert!(is_pubkey_or_npub(
            "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6"
        ));
        assert!(!is_pubkey_or_npub("not-a-pubkey"));
        assert!(!is_pubkey_or_npub(&"a".repeat(63)));
    }

    #[test]
    fn absolutize_paths_anchors_blossom_storage() {
        let mut cfg = Config::default();
        cfg.blossom.local_path = PathBuf::from("./data/images");
        cfg.database.path = PathBuf::from("./data");
        let dir = std::env::temp_dir().join("nostrd-abs-test");
        let _ = std::fs::create_dir_all(&dir);
        let cfg_path = dir.join("nostrd.toml");
        cfg.absolutize_paths(&cfg_path);
        assert!(
            cfg.blossom.local_path.is_absolute(),
            "blossom path is anchored"
        );
        assert_eq!(
            cfg.blossom.local_path,
            dir.join("data/images"),
            "relative blossom path resolves against the config directory"
        );
        assert_eq!(cfg.database.path, dir.join("data"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn limits_defaults_are_safe_and_roundtrip() {
        // The hardened defaults: a per-IP connection cap and an idle
        // timeout are on, and the new rate limits default to off (opt-in).
        let cfg = Config::default();
        assert_eq!(cfg.limits.max_connections_per_ip, 64);
        assert_eq!(cfg.limits.ws_idle_timeout_secs, 300);
        assert_eq!(cfg.limits.http_read_timeout_secs, 30);
        assert_eq!(cfg.limits.max_connections_per_sec_per_ip, 0);
        assert_eq!(cfg.relay.max_events_per_min_per_pubkey, 0);
        assert_eq!(cfg.rpc.max_admin_body_bytes, 64 * 1024);
        assert_eq!(cfg.relay.max_groups, 1_000);
        assert_eq!(cfg.limits.max_req_response_bytes, 32 * 1024 * 1024);
        // The moved keys keep their pre-reorg defaults: the legacy
        // `[server]` send_auth_challenge default was true.
        assert!(!cfg.relay.require_auth && cfg.relay.send_auth_challenge);
        // The written default file loads back with the same values.
        let dir = std::env::temp_dir().join("nostrd-config-limits-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nostrd.toml");
        Config::write_default(&path).unwrap();
        let loaded = Config::load(&path).unwrap();
        assert_eq!(loaded.limits.max_connections_per_ip, 64);
        assert_eq!(loaded.limits.ws_idle_timeout_secs, 300);
        assert_eq!(loaded.limits.http_read_timeout_secs, 30);
        assert_eq!(loaded.limits.max_connections_per_sec_per_ip, 0);
        assert_eq!(loaded.relay.max_events_per_min_per_pubkey, 0);
        assert_eq!(loaded.limits.max_req_response_bytes, 32 * 1024 * 1024);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stricter_mode_never_widens_permissions() {
        assert_eq!(stricter_mode(0o644, 0o600), 0o600);
        assert_eq!(stricter_mode(0o600, 0o644), 0o600);
        assert_eq!(stricter_mode(0o644, 0o644), 0o644);
        assert_eq!(stricter_mode(0o600, 0o600), 0o600);
    }

    #[test]
    fn write_default_creates_0600_config() {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir()
            .join("nostrd-init-test")
            .join(format!("{:x}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nostrd.toml");
        Config::write_default(&path).unwrap();
        let mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(&path).unwrap().permissions(),
        ) & 0o777;
        assert_eq!(
            mode, 0o600,
            "a freshly created config must not be world-readable"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_text_atomic_preserves_target_permissions() {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir()
            .join("nostrd-config-write-test")
            .join(format!("{:x}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nostrd.toml");
        std::fs::write(&path, "a = 1").unwrap();
        // A genkey-style 0600 config: the atomic rewrite (NIP-86
        // `changerelay*` persistence) must not revert it to 0644.
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        write_text_atomic(&path, "a = 2").unwrap();
        let mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(&path).unwrap().permissions(),
        ) & 0o777;
        assert_eq!(
            mode, 0o600,
            "the atomic rewrite must preserve the secret file's permissions"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "a = 2");
        // A plain (secret-free) 0644 config stays 0644.
        let plain = dir.join("plain.toml");
        std::fs::write(&plain, "a = 1").unwrap();
        write_text_atomic(&plain, "a = 2").unwrap();
        let mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(&plain).unwrap().permissions(),
        ) & 0o777;
        assert_eq!(mode, 0o644, "a plain config keeps its mode");
        // When the rename cannot complete (the target is a directory),
        // the leftover temp must still be 0600 — the content was never
        // world-readable during the write.
        let dir_target = dir.join("adir");
        std::fs::create_dir(&dir_target).unwrap();
        assert!(write_text_atomic(&dir_target, "x").is_err());
        let mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(dir.join("adir.tmp"))
                .unwrap()
                .permissions(),
        ) & 0o777;
        assert_eq!(mode, 0o600, "the temp must never exceed 0600");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn default_config_roundtrip() {
        let dir = std::env::temp_dir().join("nostrd-config-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nostrd.toml");
        Config::write_default(&path).unwrap();
        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.server.port, 8080);
        assert!(
            cfg.effective_supported_nips(&crate::config::AccessControl::default())
                .contains(&1)
        );
        assert!(
            cfg.effective_supported_nips(&crate::config::AccessControl::default())
                .contains(&11)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_relay_nips_are_advertised() {
        let cfg = Config::default();
        let access = AccessControl::default();
        let nips = cfg.effective_supported_nips(&access);
        // Relay-side NIPs are advertised.
        for n in [
            1, 9, 11, 13, 17, 22, 26, 29, 32, 33, 40, 42, 43, 45, 46, 47, 50, 57, 59, 62, 65, 66,
            67, 70, 77, 78, 84, 85, 86, 87, 88, 94, 98,
        ] {
            assert!(nips.contains(&n), "NIP-{n} must be advertised");
        }
        // NIP-34 (git) is gated behind `enable_git` (default false).
        assert!(
            !nips.contains(&34),
            "NIP-34 must not be advertised while enable_git is false"
        );
        // Client-side NIPs without relay-side behaviour must not be
        // advertised (NIP-11). NIP-28 explicitly "imposes no additional
        // requirements on relays". The advertised client-side set (17/22/32/
        // 46/47/57/59/65/78/84/85/87/88/94) is deliberate: their events are
        // stored and served. NIP-A3 (kind 10133) is served but has no integer
        // identifier, so it cannot appear in the numeric list.
        for n in [2, 3, 5, 19, 28, 51, 68, 99] {
            assert!(
                !nips.contains(&n),
                "client-side NIP-{n} must not be advertised"
            );
        }
        // `enable_git = true` advertises NIP-34.
        let mut cfg = Config::default();
        cfg.relay.enabled_git = true;
        assert!(
            cfg.effective_supported_nips(&access).contains(&34),
            "NIP-34 must be advertised when enable_git is true"
        );
        // An explicit allowlist still only advertises relay-side NIPs.
        let mut cfg = Config::default();
        cfg.relay.enabled_nips = vec![1, 2, 50];
        assert_eq!(cfg.effective_supported_nips(&access), vec![1, 50]);
    }

    #[test]
    fn disabled_nips_are_removed() {
        let mut cfg = Config::default();
        cfg.relay.disabled_nips = vec![11, 50];
        let access = AccessControl::default();
        assert!(!cfg.effective_supported_nips(&access).contains(&11));
        assert!(!cfg.nip_enabled(50));
        assert!(cfg.nip_enabled(1));
    }

    #[test]
    fn blocked_or_ephemeral_rejected_kinds_drop_their_nip() {
        // Blocking every kind a NIP defines must drop that NIP from the
        // advertisement.
        let cfg = Config::default();
        let access = AccessControl {
            blocked_kinds: vec![5], // NIP-09 (deletion)
            ..Default::default()
        };
        let nips = cfg.effective_supported_nips(&access);
        assert!(
            !nips.contains(&9),
            "NIP-09 must not be advertised when kind 5 is blocked"
        );
        assert!(nips.contains(&1));

        // Blocking only ONE of a NIP's many kinds keeps it advertised
        // (any accepted kind keeps the NIP).
        let cfg = Config::default();
        let access = AccessControl {
            blocked_kinds: vec![9000], // one NIP-29 group kind
            ..Default::default()
        };
        let nips = cfg.effective_supported_nips(&access);
        assert!(
            nips.contains(&29),
            "NIP-29 must stay advertised when only kind 9000 is blocked"
        );

        // reject_ephemeral with a non-exempt ephemeral kind drops NIP-42/98.
        let mut cfg = Config::default();
        cfg.relay.reject_ephemeral = true;
        let access = AccessControl::default();
        let nips = cfg.effective_supported_nips(&access);
        assert!(
            nips.contains(&42),
            "NIP-42 AUTH kind is exempt and still advertised"
        );
        assert!(
            nips.contains(&98),
            "NIP-98 HTTP auth kind is exempt and still advertised"
        );

        // Allowing only a subset still advertises the NIP (any accepted kind).
        let cfg = Config::default();
        let access = AccessControl {
            allowed_kinds: vec![1, 9000, 28936, 24242, 22242],
            ..Default::default()
        };
        let nips = cfg.effective_supported_nips(&access);
        assert!(nips.contains(&1), "kind 1 is allowed -> NIP-01 advertised");
        assert!(
            nips.contains(&29),
            "group kinds 9000/28936 are allowed -> NIP-29 advertised"
        );
        assert!(nips.contains(&42), "22242 allowed -> NIP-42 advertised");
        assert!(
            nips.contains(&40),
            "NIP-40 (no kinds) is always advertised when enabled"
        );
    }

    #[test]
    fn advertised_client_nips_track_their_kinds() {
        let cfg = Config::default();
        // Each advertised client-side NIP is dropped when all its kinds are
        // blocked.
        for (nip, kinds) in [
            (17, &[14u64, 15, 1059, 21059][..]),
            (22, &[1111][..]),
            (32, &[1985][..]),
            (46, &[24133][..]),
            (47, &[23194, 23195][..]),
            (57, &[9734, 9735][..]),
            (59, &[1059, 21059][..]),
            (65, &[10002][..]),
            (66, &[30166, 10166][..]),
            (78, &[30078][..]),
            (84, &[9802][..]),
            (85, &[30382, 30383, 30384][..]),
            (87, &[38172, 38173][..]),
            (88, &[1018, 1068][..]),
            (94, &[1063][..]),
        ] {
            let access = AccessControl {
                blocked_kinds: kinds.to_vec(),
                ..Default::default()
            };
            let nips = cfg.effective_supported_nips(&access);
            assert!(
                !nips.contains(&nip),
                "NIP-{nip} must not be advertised when all its kinds are blocked"
            );
        }
        // NIP-34: enabled via `enable_git`, and dropped when every git kind
        // is blocked.
        let mut cfg = Config::default();
        cfg.relay.enabled_git = true;
        let access = AccessControl {
            blocked_kinds: vec![
                1617, 1618, 1619, 1621, 1622, 1630, 1631, 1632, 1633, 30617, 30618,
            ],
            ..Default::default()
        };
        assert!(
            !cfg.effective_supported_nips(&access).contains(&34),
            "NIP-34 must not be advertised when all git kinds are blocked"
        );
        // reject_ephemeral keeps the exempt ephemeral kinds of NIP-46/47 and
        // the regular kinds of NIP-17 (only 1059 is rejected).
        let mut cfg = Config::default();
        cfg.relay.reject_ephemeral = true;
        let access = AccessControl::default();
        let nips = cfg.effective_supported_nips(&access);
        assert!(
            nips.contains(&46),
            "NIP-46 (exempt) stays with reject_ephemeral"
        );
        assert!(
            nips.contains(&47),
            "NIP-47 (exempt) stays with reject_ephemeral"
        );
        assert!(nips.contains(&17), "NIP-17 stays via kinds 14/15");
        assert!(nips.contains(&59), "NIP-59 stays via kind 1059/21059");
        assert!(nips.contains(&22), "NIP-22 stays via kind 1111");
        // NIP-65/78 are replaceable/addressable: never dropped by reject_ephemeral.
        assert!(nips.contains(&65));
        assert!(nips.contains(&78));
    }

    #[test]
    fn access_control() {
        let mut ac = AccessControl::default();
        ac.blocked_pubkeys.push(("bad".into(), String::new()));
        assert!(!ac.allows_pubkey("bad"));
        assert!(ac.allows_pubkey("good"));
        ac.blocked_kinds.push(5);
        assert!(!ac.allows_kind(5));
        assert!(ac.allows_kind(1));
    }

    #[test]
    fn access_entries_accept_legacy_and_pairs() {
        // The persisted JSON and the TOML [access] section may carry the
        // legacy plain-string form; reading it must not fail (the entries
        // get an empty reason).
        let legacy = AccessControl {
            blocked_pubkeys: vec![("aa".repeat(32), String::new())],
            allowed_pubkeys: Vec::new(),
            blocked_kinds: vec![],
            allowed_kinds: vec![],
            blocked_ips: vec![("203.0.113.9".into(), String::new())],
            restrict_relay: false,
        };
        let json = serde_json::to_string(&legacy).unwrap();
        // Simulate the pre-reason persisted document.
        let old_json = r#"{"blocked_pubkeys":["REPL"],"allowed_pubkeys":[],"blocked_kinds":[],"allowed_kinds":[],"blocked_ips":["203.0.113.9"]}"#;
        let old_json = old_json.replace("REPL", &"aa".repeat(32));
        let parsed: AccessControl = serde_json::from_str(&old_json).expect("legacy JSON reads");
        // The pubkey lists are skipped from the config/blob and now live in
        // the database under their own key (migrated at startup); reading
        // the legacy document must still succeed, dropping the entries.
        assert!(
            parsed.blocked_pubkeys.is_empty(),
            "pubkey lists are not config state"
        );
        assert!(parsed.allowed_pubkeys.is_empty());
        assert_eq!(parsed.blocked_ips[0].0, "203.0.113.9");
        // The current format round-trips with its reasons.
        let with_reason = AccessControl {
            blocked_pubkeys: vec![("bb".repeat(32), "spam".to_string())],
            ..Default::default()
        };
        let raw = serde_json::to_string(&with_reason).unwrap();
        let parsed: AccessControl = serde_json::from_str(&raw).unwrap();
        // Serialization skips the pubkey lists: they live in LMDB.
        assert!(parsed.blocked_pubkeys.is_empty());
        assert!(parsed.allowed_pubkeys.is_empty());
        let _ = json;
    }

    #[test]
    fn allows_pubkey_respects_restrict_relay_and_deny() {
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        let mut access = AccessControl::default();
        // Default (restrict_relay = false): everyone may publish.
        assert!(access.allows_pubkey(&a));
        assert!(access.allows_pubkey(&b));
        // A denied pubkey is rejected even without restrict_relay.
        access.blocked_pubkeys.push((b.clone(), String::new()));
        assert!(access.allows_pubkey(&a));
        assert!(!access.allows_pubkey(&b));
        // restrict_relay = true: only the allow list may publish.
        access.restrict_relay = true;
        assert!(
            !access.allows_pubkey(&a),
            "empty allow list locks everyone out"
        );
        access.allowed_pubkeys.push((a.clone(), String::new()));
        assert!(access.allows_pubkey(&a));
        assert!(!access.allows_pubkey(&b), "denied wins even when allowed");
    }

    #[test]
    fn validation_accepts_defaults() {
        assert!(Config::default().validate().is_ok());
    }

    #[test]
    fn validation_rejects_bad_keys() {
        let mut cfg = Config::default();
        cfg.relay.pubkey = "zz".repeat(32);
        assert!(cfg.validate().is_err(), "pubkey must be hex");
        cfg.relay.pubkey = "aa".repeat(31); // 62 chars
        assert!(cfg.validate().is_err(), "pubkey must be 32 bytes");
        cfg.relay.private_key = "gg".repeat(32);
        assert!(cfg.validate().is_err(), "secret key must be valid hex");
        cfg.relay.private_key = "00".repeat(32); // 0 is not on the curve
        assert!(
            cfg.validate().is_err(),
            "secret key must be on the secp256k1 curve"
        );
    }

    #[test]
    fn validation_rejects_port_collision_and_map_layout() {
        let mut cfg = Config::default();
        cfg.server.port = 8080;
        cfg.rpc.management_port = 8080;
        assert!(
            cfg.validate().is_err(),
            "management_port must differ from port"
        );
        cfg.rpc.management_port = 0;

        cfg.database.map_size = 1024 * 1024;
        cfg.database.max_map_size = 512 * 1024;
        assert!(
            cfg.validate().is_err(),
            "map_size must not exceed map_max_size"
        );
    }

    #[test]
    fn validation_rejects_hosts_with_invalid_characters() {
        let mut cfg = Config::default();
        // Valid hosts pass: a DNS name, an IPv6 literal, an underscore,
        // on both split hosts.
        for (host, name) in [
            ("api.example.com", "server.api_host"),
            ("[::1]", "server.api_host"),
            ("my_host", "server.api_host"),
            ("media.example.com", "blossom.host"),
            ("[::1]", "blossom.host"),
        ] {
            if name == "server.api_host" {
                cfg.server.api_host = host.into();
            } else {
                cfg.blossom.host = host.into();
            }
            assert!(cfg.validate().is_ok(), "{host} must be valid");
        }
        cfg.server.api_host = String::new();
        cfg.blossom.host = String::new();
        // Whitespace-only values are rejected too: the runtime treats
        // them as non-empty and would block every API path (silent 404).
        cfg.server.api_host = "   ".into();
        assert!(
            cfg.validate().is_err(),
            "whitespace-only api_host must be rejected"
        );
        cfg.server.api_host = String::new();
        cfg.blossom.host = " ".into();
        assert!(
            cfg.validate().is_err(),
            "whitespace-only blossom.host must be rejected"
        );
        cfg.blossom.host = String::new();
        // Whitespace (a silent 404 for the whole API), a scheme, a path
        // and a port are all rejected.
        for bad in [
            "api host",
            "api.example.com ",
            "\tapi.example.com",
            "https://api.x",
            "api.x/",
            "api.x:8080",
        ] {
            cfg.server.api_host = bad.into();
            assert!(
                cfg.validate().is_err(),
                "{bad:?} must be rejected as an api_host"
            );
            cfg.server.api_host = String::new();
            cfg.blossom.host = bad.into();
            assert!(
                cfg.validate().is_err(),
                "{bad:?} must be rejected as a blossom.host"
            );
            cfg.blossom.host = String::new();
        }
    }

    #[test]
    fn validation_rejects_bad_ws_paths() {
        let mut cfg = Config::default();
        assert!(cfg.validate().is_ok(), "default ws_paths is valid");
        for value in ["root", "inbox-outbox", "all"] {
            cfg.server.ws_paths = value.into();
            assert!(cfg.validate().is_ok(), "{value} must be valid");
        }
        cfg.server.ws_paths = "inbox".into();
        assert!(cfg.validate().is_err(), "unknown ws_paths must be rejected");
    }

    #[test]
    fn validation_rejects_bad_inbox_write_policy() {
        let mut cfg = Config::default();
        assert!(
            cfg.validate().is_ok(),
            "default inbox_write_policy is valid"
        );
        for value in ["any", "relay"] {
            cfg.server.inbox_write_policy = value.into();
            assert!(cfg.validate().is_ok(), "{value} must be valid");
        }
        cfg.server.inbox_write_policy = "any_p".into();
        assert!(
            cfg.validate().is_err(),
            "unknown inbox_write_policy must be rejected"
        );
    }

    #[test]
    fn validation_rejects_bad_outbox_write_policy() {
        let mut cfg = Config::default();
        assert!(
            cfg.validate().is_ok(),
            "default outbox_write_policy is valid"
        );
        for value in ["any", "relay"] {
            cfg.server.outbox_write_policy = value.into();
            assert!(cfg.validate().is_ok(), "{value} must be valid");
        }
        cfg.server.outbox_write_policy = "any_p".into();
        assert!(
            cfg.validate().is_err(),
            "unknown outbox_write_policy must be rejected"
        );
    }

    #[test]
    fn relay_reject_ephemeral_defaults_and_parses() {
        let cfg = Config::default();
        assert!(!cfg.relay.reject_ephemeral, "default must be false");
        assert!(cfg.validate().is_ok());

        let toml_true = "[relay]\nreject_ephemeral = true\n";
        let parsed: Config = toml::from_str(toml_true).expect("must parse true");
        assert!(parsed.relay.reject_ephemeral);

        let toml_false = "[relay]\nreject_ephemeral = false\n";
        let parsed: Config = toml::from_str(toml_false).expect("must parse false");
        assert!(!parsed.relay.reject_ephemeral);

        // Missing key defaults to false via #[serde(default)]
        let parsed: Config = toml::from_str("").expect("empty must parse");
        assert!(!parsed.relay.reject_ephemeral);
    }

    #[test]
    fn validation_rejects_bad_access_entries() {
        let mut cfg = Config::default();
        cfg.access.blocked_ips = vec![("not-an-ip".into(), String::new())];
        assert!(cfg.validate().is_err(), "blocked IPs must parse");
    }

    #[test]
    fn enabled_nip78_auth_defaults_parses_and_requires_nip42() {
        let cfg = Config::default();
        assert!(
            cfg.relay.enabled_nip78_auth,
            "default must be true (spec-conformant private NIP-78)"
        );
        assert!(cfg.validate().is_ok());

        let parsed: Config =
            toml::from_str("[relay]\nenabled_nip78_auth = false\n").expect("must parse false");
        assert!(!parsed.relay.enabled_nip78_auth);

        // Missing key defaults to true via #[serde(default)]
        let parsed: Config = toml::from_str("").expect("empty must parse");
        assert!(parsed.relay.enabled_nip78_auth);

        // The gate needs NIP-42, otherwise nobody can authenticate.
        let mut cfg = Config::default();
        cfg.relay.disabled_nips = vec![42];
        assert!(
            cfg.validate().is_err(),
            "enabled_nip78_auth requires NIP-42 to be enabled"
        );
    }

    #[test]
    fn validation_rejects_zero_limits() {
        let mut cfg = Config::default();
        cfg.limits.max_connections = 0;
        assert!(
            cfg.validate().is_err(),
            "max_connections must be at least 1"
        );
    }

    #[test]
    fn toml_escape_handles_all_control_chars() {
        // U+007F (DEL) and other control characters must be escaped: the
        // toml crate rejects them raw in basic strings.
        for ch in ['\u{0}', '\u{7f}', '\u{1f}'] {
            let escaped = toml_escape(&format!("a{ch}b"));
            assert!(
                !escaped.contains(ch),
                "control character must be escaped, got {escaped:?}"
            );
            assert!(
                toml::from_str::<toml::Value>(&format!("x = \"{escaped}\"")).is_ok(),
                "escaped output must parse as TOML"
            );
        }
        assert_eq!(toml_escape("quote\\backslash"), "quote\\\\backslash");
    }
}
