//! strfry configuration import: a tolerant reader for the libconfig-style
//! `strfry.conf` and the mapping of its settings onto `nostrfy.toml`.
//!
//! `nostrfy migrate-strfry` uses this to offer the operator a merge of the
//! settings that have a direct nostrfy equivalent. The parser is
//! deliberately small and tolerant: it understands `key = value`
//! assignments and `block { ... }` nesting (enough for every strfry
//! option), ignores comments and anything it cannot parse, and never
//! executes the file.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::config::Config;

/// One parsed strfry value.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Value {
    Str(String),
    Int(i64),
    Bool(bool),
    /// An array value. Only recorded so the "not merged" report can see
    /// that the key is present; nostrfy has no list-valued mapping.
    List,
}

/// The parsed strfry config, keyed by dotted path (`relay.info.name`).
#[derive(Debug, Default)]
pub(crate) struct StrfryConfig {
    values: BTreeMap<String, Value>,
}

impl StrfryConfig {
    /// Parses the assignments and nested blocks of a libconfig file. The
    /// tokenizer understands quoted strings, comments, `key = value` (or
    /// `key: value`) assignments, `block { ... }` nesting on one or several
    /// lines, and skips arrays/objects it does not need.
    pub(crate) fn parse(text: &str) -> Self {
        let tokens = tokenize(text);
        let mut values = BTreeMap::new();
        let mut index = 0;
        parse_block(&tokens, &mut index, "", &mut values);
        StrfryConfig { values }
    }

    pub(crate) fn get(&self, path: &str) -> Option<&Value> {
        self.values.get(path)
    }

    /// Whether any parsed key starts with `prefix` (used for the "not
    /// merged" report of whole blocks like `relay.logging.`).
    fn has_prefix(&self, prefix: &str) -> bool {
        self.values.keys().any(|key| key.starts_with(prefix))
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Name(String),
    Str(String),
    Int(i64),
    Bool(bool),
    Eq,
    LBrace,
    RBrace,
    Semi,
    /// A token the parser does not need (an array, object or stray text).
    Other,
}

/// Splits libconfig text into tokens, dropping comments.
fn tokenize(text: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            c if c.is_whitespace() => {}
            '#' => {
                while chars.peek().is_some_and(|c| *c != '\n') {
                    chars.next();
                }
            }
            '{' => tokens.push(Token::LBrace),
            '}' => tokens.push(Token::RBrace),
            '=' | ':' => tokens.push(Token::Eq),
            ';' | ',' => tokens.push(Token::Semi),
            '"' => tokens.push(Token::Str(read_string(&mut chars))),
            '[' => {
                skip_balanced(&mut chars);
                tokens.push(Token::Other);
            }
            _ => {
                let mut word = String::from(ch);
                while let Some(c) = chars.peek() {
                    if c.is_whitespace()
                        || matches!(c, '{' | '}' | '=' | ':' | ';' | ',' | '#' | '"' | '[')
                    {
                        break;
                    }
                    word.push(*c);
                    chars.next();
                }
                if word == "true" {
                    tokens.push(Token::Bool(true));
                } else if word == "false" {
                    tokens.push(Token::Bool(false));
                } else if let Ok(number) = word.parse::<i64>() {
                    tokens.push(Token::Int(number));
                } else {
                    tokens.push(Token::Name(word));
                }
            }
        }
    }
    tokens
}

/// Reads a quoted string body (the opening quote was consumed), honoring
/// `\\`/`\"` escapes.
fn read_string(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> String {
    let mut out = String::new();
    let mut escaped = false;
    for ch in chars.by_ref() {
        if escaped {
            out.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '"' => break,
            _ => out.push(ch),
        }
    }
    out
}

/// Skips a balanced `[...]` array (the opening bracket was consumed).
fn skip_balanced(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    let mut depth = 1;
    while let Some(ch) = chars.next() {
        match ch {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    return;
                }
            }
            '"' => {
                read_string(chars);
            }
            _ => {}
        }
    }
}

/// Parses assignments and nested blocks under `prefix` into `values`.
fn parse_block(
    tokens: &[Token],
    index: &mut usize,
    prefix: &str,
    values: &mut BTreeMap<String, Value>,
) {
    while *index < tokens.len() {
        match &tokens[*index] {
            Token::RBrace => {
                *index += 1;
                return;
            }
            Token::Semi | Token::Other => *index += 1,
            Token::Name(key) => {
                let key = key.clone();
                *index += 1;
                match tokens.get(*index) {
                    Some(Token::Eq) => {
                        *index += 1;
                        match tokens.get(*index) {
                            Some(Token::LBrace) => {
                                *index += 1;
                                parse_block(tokens, index, &format!("{prefix}{key}."), values);
                            }
                            Some(Token::Str(value)) => {
                                values.insert(format!("{prefix}{key}"), Value::Str(value.clone()));
                                *index += 1;
                            }
                            Some(Token::Int(value)) => {
                                values.insert(format!("{prefix}{key}"), Value::Int(*value));
                                *index += 1;
                            }
                            Some(Token::Bool(value)) => {
                                values.insert(format!("{prefix}{key}"), Value::Bool(*value));
                                *index += 1;
                            }
                            Some(Token::Name(value)) => {
                                values.insert(format!("{prefix}{key}"), Value::Str(value.clone()));
                                *index += 1;
                            }
                            // The tokenizer turns `[ ... ]` into a single
                            // `Other` token: record the key as an array so
                            // the "not merged" report can list it.
                            Some(Token::Other) => {
                                values.insert(format!("{prefix}{key}"), Value::List);
                                *index += 1;
                            }
                            _ => {}
                        }
                    }
                    Some(Token::LBrace) => {
                        *index += 1;
                        parse_block(tokens, index, &format!("{prefix}{key}."), values);
                    }
                    _ => *index += 1,
                }
            }
            _ => *index += 1,
        }
    }
}

/// A proposed change to `nostrfy.toml`.
#[derive(Debug, Clone)]
pub(crate) struct Proposal {
    /// The strfry key the value came from (shown to the operator).
    pub strfry_key: &'static str,
    /// The nostrfy section and key.
    pub section: &'static str,
    pub key: &'static str,
    /// Human-readable current and proposed values.
    pub current: String,
    pub proposed: String,
    /// The TOML literal to write.
    value_toml: String,
}

impl Proposal {
    /// The `section.key` path shown to the operator.
    pub(crate) fn path(&self) -> String {
        format!("{}.{}", self.section, self.key)
    }
}

/// strfry keys (or blocks) that have no safe nostrfy equivalent, with the
/// reason shown to the operator. Only entries present in the parsed file
/// are reported.
const UNMAPPED: &[(&str, &str)] = &[
    (
        "db",
        "the strfry database path is the migration source, not a nostrfy setting",
    ),
    ("dbParams.noReadAhead", "nostrfy chooses its own LMDB flags"),
    (
        "events.maxEventSize",
        "the frame cap comes from limits.max_ws_message_bytes (mapped from maxWebsocketPayloadSize)",
    ),
    (
        "events.rejectEventsOlderThanSeconds",
        "nostrfy has no global event-age limit (only limits.group_late_publish_secs for NIP-29)",
    ),
    (
        "events.rejectEphemeralEventsOlderThanSeconds",
        "nostrfy never stores ephemeral events",
    ),
    (
        "events.ephemeralEventsLifetimeSeconds",
        "nostrfy never stores ephemeral events",
    ),
    (
        "relay.nofiles",
        "raise the open-file limit in the service manager (systemd LimitNOFILE)",
    ),
    (
        "relay.realIpHeader",
        "configure server.trusted_proxies with the proxy's CIDR ranges",
    ),
    (
        "relay.autoPingSeconds",
        "nostrfy sends keep-alive PINGs based on limits.ws_idle_timeout_secs",
    ),
    (
        "relay.enableTcpKeepalive",
        "enable TCP keep-alive in the reverse proxy / OS",
    ),
    (
        "relay.queryTimesliceBudgetMicroseconds",
        "nostrfy uses a fixed per-scan work budget",
    ),
    (
        "relay.maxTagsPerFilter",
        "nostrfy bounds filter members with fixed internal caps",
    ),
    (
        "relay.auth.enabled",
        "NIP-42 is enabled by default; use relay.require_auth to require it",
    ),
    (
        "relay.auth.restrictedReadKinds",
        "nostrfy has no per-kind read gating",
    ),
    (
        "relay.auth.restrictReadToInvolvedPubkey",
        "nostrfy has no per-kind read gating",
    ),
    (
        "relay.info.self",
        "the relay's own pubkey is derived from relay.private_key (run `nostrfy genkey`)",
    ),
    ("relay.info.banner", "nostrfy has no NIP-11 banner field"),
    (
        "relay.info.privacy",
        "nostrfy has no NIP-11 privacy-policy field",
    ),
    ("relay.info.terms", "nostrfy has no NIP-11 terms field"),
    (
        "relay.info.nips",
        "nostrfy computes supported_nips from relay.enabled_nips/disabled_nips",
    ),
    (
        "relay.writePolicy.plugin",
        "nostrfy has no write-policy plugin interface",
    ),
    (
        "relay.writePolicy.timeoutSeconds",
        "nostrfy has no write-policy plugin interface",
    ),
    (
        "relay.compression.enabled",
        "nostrfy does not implement permessage-deflate",
    ),
    (
        "relay.compression.slidingWindow",
        "nostrfy does not implement permessage-deflate",
    ),
    (
        "relay.logging.dumpInAll",
        "use RUST_LOG and daemon.log_file",
    ),
    (
        "relay.logging.dumpInEvents",
        "use RUST_LOG and daemon.log_file",
    ),
    (
        "relay.logging.dumpInReqs",
        "use RUST_LOG and daemon.log_file",
    ),
    (
        "relay.logging.dbScanPerf",
        "nostrfy exports scan metrics through /metrics",
    ),
    (
        "relay.logging.invalidEvents",
        "nostrfy logs rejections; use RUST_LOG to tune the level",
    ),
    (
        "relay.numThreads.ingester",
        "nostrfy sizes its runtime automatically",
    ),
    (
        "relay.numThreads.reqWorker",
        "use database.reader_threads for the reader pool",
    ),
    (
        "relay.numThreads.reqMonitor",
        "nostrfy sizes its runtime automatically",
    ),
    (
        "relay.numThreads.negentropy",
        "nostrfy sizes its runtime automatically",
    ),
    (
        "relay.negentropy.enabled",
        "NIP-77 is controlled by relay.enabled_nips/disabled_nips",
    ),
    (
        "relay.filterValidation.enabled",
        "nostrfy validates filters against its own limits",
    ),
    (
        "relay.filterValidation.maxFiltersPerReq",
        "use limits.max_filters",
    ),
    (
        "relay.filterValidation.minFiltersPerReq",
        "nostrfy accepts any non-empty filter list",
    ),
    (
        "relay.filterValidation.maxKindsPerFilter",
        "nostrfy bounds filter members with fixed internal caps",
    ),
    (
        "relay.filterValidation.allowedKinds",
        "use [access] blocked_kinds/allowed_kinds",
    ),
    (
        "relay.filterValidation.requireAuthorOrTag",
        "nostrfy does not enforce filter shape",
    ),
];

/// The strfry settings that map onto `nostrfy.toml`, as
/// `(strfry key, nostrfy section, nostrfy key)` for string values.
const STRING_MAP: &[(&str, &str, &str)] = &[
    ("relay.info.name", "relay", "name"),
    ("relay.info.description", "relay", "description"),
    ("relay.info.contact", "relay", "contact"),
    ("relay.info.icon", "relay", "icon"),
    ("relay.info.pubkey", "relay", "pubkey"),
    ("relay.auth.serviceUrl", "relay", "public_url"),
    ("relay.bind", "server", "host"),
];

/// The integer-valued mappings: `(strfry key, section, key, current value)`.
fn integer_mappings(cfg: &Config) -> Vec<(&'static str, &'static str, &'static str, i64)> {
    vec![
        ("relay.port", "server", "port", cfg.server.port as i64),
        (
            "relay.maxWebsocketPayloadSize",
            "limits",
            "max_ws_message_bytes",
            cfg.limits.max_ws_message_bytes as i64,
        ),
        (
            "relay.maxReqFilterSize",
            "limits",
            "max_filters",
            cfg.limits.max_filters as i64,
        ),
        (
            "relay.maxFilterLimit",
            "limits",
            "max_limit",
            cfg.limits.max_limit as i64,
        ),
        (
            "relay.maxSubsPerConnection",
            "limits",
            "max_subscriptions",
            cfg.limits.max_subscriptions as i64,
        ),
        (
            "relay.maxPendingOutboundBytes",
            "limits",
            "max_out_queue_bytes",
            cfg.limits.max_out_queue_bytes as i64,
        ),
        (
            "relay.maxFilterLimitCount",
            "limits",
            "max_count",
            cfg.limits.max_count as i64,
        ),
        (
            "relay.negentropy.maxSyncEvents",
            "limits",
            "max_neg_items",
            cfg.limits.max_neg_items as i64,
        ),
        (
            "events.maxNumTags",
            "limits",
            "max_tags",
            cfg.limits.max_tags as i64,
        ),
        (
            "events.maxTagValSize",
            "limits",
            "max_tag_value_bytes",
            cfg.limits.max_tag_value_bytes as i64,
        ),
        (
            "events.rejectEventsNewerThanSeconds",
            "limits",
            "max_created_at_future_secs",
            cfg.limits.max_created_at_future_secs as i64,
        ),
        (
            "dbParams.maxreaders",
            "database",
            "max_readers",
            cfg.database.max_readers as i64,
        ),
    ]
}

/// Computes the settings worth offering: only values present in the strfry
/// config that differ from the current effective nostrfy value. Values that
/// cannot be applied safely are skipped (see the reasons below).
pub(crate) fn proposals(strfry: &StrfryConfig, nostrfy: &Config) -> Vec<Proposal> {
    let mut out = Vec::new();
    for (strfry_key, section, key) in STRING_MAP {
        let Some(Value::Str(value)) = strfry.get(strfry_key) else {
            continue;
        };
        let current = match (*section, *key) {
            ("relay", "name") => &nostrfy.relay.name,
            ("relay", "description") => &nostrfy.relay.description,
            ("relay", "contact") => &nostrfy.relay.contact,
            ("relay", "icon") => &nostrfy.relay.icon,
            ("relay", "pubkey") => &nostrfy.relay.pubkey,
            ("relay", "public_url") => &nostrfy.relay.public_url,
            ("server", "host") => &nostrfy.server.host,
            _ => continue,
        };
        if value.is_empty() || value == current {
            continue;
        }
        out.push(Proposal {
            strfry_key,
            section,
            key,
            current: current.clone(),
            proposed: value.clone(),
            value_toml: format!("\"{}\"", crate::config::toml_escape(value)),
        });
    }
    for (strfry_key, section, key, current) in integer_mappings(nostrfy) {
        let Some(Value::Int(value)) = strfry.get(strfry_key) else {
            continue;
        };
        // `maxFilterLimitCount = 0` disables COUNT on strfry; nostrfy has
        // no equivalent (max_count = 0 would answer every COUNT with 0), so
        // leave the nostrfy value alone.
        if strfry_key == "relay.maxFilterLimitCount" && *value == 0 {
            continue;
        }
        if *value <= 0 || *value == current {
            continue;
        }
        out.push(Proposal {
            strfry_key,
            section,
            key,
            current: current.to_string(),
            proposed: value.to_string(),
            value_toml: value.to_string(),
        });
    }
    // The LMDB map size: strfry's `mapsize` is the whole map, nostrfy's
    // `map_size` is the initial map (it grows to `max_map_size`). Only
    // offer it when it fits under nostrfy's configured ceiling, or the
    // merged config would fail validation.
    if let Some(Value::Int(value)) = strfry.get("dbParams.mapsize")
        && *value > 0
        && *value as u64 <= nostrfy.database.max_map_size as u64
        && *value as u64 != nostrfy.database.map_size as u64
    {
        out.push(Proposal {
            strfry_key: "dbParams.mapsize",
            section: "database",
            key: "map_size",
            current: nostrfy.database.map_size.to_string(),
            proposed: value.to_string(),
            value_toml: value.to_string(),
        });
    }
    out
}

/// The strfry keys/blocks present in the config that are not merged, with
/// the reason.
pub(crate) fn unmapped(strfry: &StrfryConfig) -> Vec<(&'static str, &'static str)> {
    UNMAPPED
        .iter()
        .filter(|(key, _)| strfry.get(key).is_some() || strfry.has_prefix(&format!("{key}.")))
        .copied()
        .collect()
}

/// Applies the proposals to the config text, preserving comments and every
/// unrelated line.
pub(crate) fn apply_proposals(text: &str, proposals: &[Proposal]) -> String {
    let mut out = text.to_string();
    for proposal in proposals {
        out = crate::config::set_config_field_in_text(
            &out,
            proposal.section,
            proposal.key,
            &proposal.value_toml,
        );
    }
    out
}

/// Parses and validates a merged config text without writing it, so a merge
/// that would produce an invalid config is refused before the file is
/// touched.
pub(crate) fn validate_merged(text: &str) -> Result<(), String> {
    let cfg: Config = toml::from_str(text).map_err(|e| e.to_string())?;
    cfg.validate().map_err(|e| e.to_string())
}

/// Finds the strfry config to read, in strfry's own search order: an
/// explicit path, `$STRFRY_CONFIG`, `./strfry.conf`, `/etc/strfry.conf`.
pub(crate) fn find_config(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = explicit {
        return path.exists().then(|| path.to_path_buf());
    }
    if let Ok(path) = std::env::var("STRFRY_CONFIG") {
        let path = PathBuf::from(path);
        if path.exists() {
            return Some(path);
        }
    }
    for candidate in ["strfry.conf", "/etc/strfry.conf"] {
        let path = PathBuf::from(candidate);
        if path.exists() {
            return Some(path);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
##
## Default strfry config
##
db = "./strfry-db/"

dbParams {
    maxreaders = 256
    mapsize = 10995116277760
    noReadAhead = false
}

events {
    maxEventSize = 65536
    rejectEventsNewerThanSeconds = 900
    maxNumTags = 2000
    maxTagValSize = 1024
}

relay {
    bind = "127.0.0.1"   # comment after a value
    port = 7777
    auth {
        enabled = true
        serviceUrl = "wss://relay.example.com"
    }
    info {
        name = "strfry default"
        description = "This is a \"strfry\" instance."
        pubkey = ""
    }
    maxWebsocketPayloadSize = 131072
    maxReqFilterSize = 200
    maxFilterLimit = 500
    maxSubsPerConnection = 200
    maxPendingOutboundBytes = 33554432
    maxFilterLimitCount = 1000000
    negentropy { maxSyncEvents = 1000000 }
    writePolicy { plugin = "" }
    compression { enabled = true }
    logging { invalidEvents = true }
    filterValidation { allowedKinds = [0, 1] }
}
"#;

    fn parsed() -> StrfryConfig {
        StrfryConfig::parse(SAMPLE)
    }

    #[test]
    fn parses_scalars_blocks_and_comments() {
        let cfg = parsed();
        assert_eq!(
            cfg.get("relay.info.name"),
            Some(&Value::Str("strfry default".into()))
        );
        assert_eq!(cfg.get("relay.port"), Some(&Value::Int(7777)));
        assert_eq!(cfg.get("relay.auth.enabled"), Some(&Value::Bool(true)));
        assert_eq!(cfg.get("dbParams.noReadAhead"), Some(&Value::Bool(false)));
        assert_eq!(cfg.get("db"), Some(&Value::Str("./strfry-db/".into())));
        // A comment after a value is stripped, and a `#` inside a string
        // stays part of the value.
        assert_eq!(cfg.get("relay.bind"), Some(&Value::Str("127.0.0.1".into())));
        assert_eq!(
            cfg.get("relay.info.description"),
            Some(&Value::Str("This is a \"strfry\" instance.".into()))
        );
    }

    #[test]
    fn proposes_only_differing_values() {
        let cfg = parsed();
        let nostrfy = Config::default();
        let proposals = proposals(&cfg, &nostrfy);
        let paths: Vec<String> = proposals.iter().map(Proposal::path).collect();
        // Differing values are proposed.
        for path in [
            "server.port",
            "relay.name",
            "relay.description",
            "relay.public_url",
            "limits.max_ws_message_bytes",
            "limits.max_filters",
            "limits.max_subscriptions",
            "limits.max_out_queue_bytes",
            "limits.max_count",
            "limits.max_neg_items",
            "limits.max_created_at_future_secs",
            "database.max_readers",
        ] {
            assert!(paths.contains(&path.into()), "{path} must be proposed");
        }
        // Values equal to the nostrfy defaults are not proposed (the
        // sample's bind is the default `127.0.0.1`, maxFilterLimit 500,
        // maxNumTags 2000 and maxTagValSize 1024).
        for path in [
            "server.host",
            "limits.max_limit",
            "limits.max_tags",
            "limits.max_tag_value_bytes",
        ] {
            assert!(
                !paths.contains(&path.into()),
                "{path} equals the default and must not be proposed"
            );
        }
        // An empty strfry value is not proposed.
        assert!(!paths.contains(&"relay.pubkey".into()));
        // strfry's 10 TB map exceeds nostrfy's ceiling: skipped.
        assert!(!paths.contains(&"database.map_size".into()));
    }

    #[test]
    fn skips_the_zero_count_cap_and_oversized_mapsize() {
        let mut cfg = parsed();
        // maxFilterLimitCount = 0 means "disable COUNT" on strfry.
        cfg.values
            .insert("relay.maxFilterLimitCount".into(), Value::Int(0));
        let nostrfy = Config::default();
        assert!(
            !proposals(&cfg, &nostrfy)
                .iter()
                .any(|p| p.path() == "limits.max_count"),
            "a disabled COUNT must not map to max_count = 0"
        );
        // strfry's default 10 TB map exceeds nostrfy's 1 TB ceiling.
        cfg.values
            .insert("dbParams.mapsize".into(), Value::Int(10_995_116_277_760));
        assert!(
            !proposals(&cfg, &nostrfy)
                .iter()
                .any(|p| p.path() == "database.map_size"),
            "a map size above max_map_size must not be proposed"
        );
        cfg.values
            .insert("dbParams.mapsize".into(), Value::Int(2_147_483_648));
        assert!(
            proposals(&cfg, &nostrfy)
                .iter()
                .any(|p| p.path() == "database.map_size"),
            "a map size under the ceiling is proposed"
        );
    }

    #[test]
    fn applies_proposals_preserving_comments() {
        let text = "\
# my relay
[relay]
# the operator's name comment
name = \"old\"
private_key = \"0101010101010101010101010101010101010101010101010101010101010101\"   # secret

[server]
port = 8080

[limits]
max_tags = 100
";
        let nostrfy = Config::default();
        let proposals = proposals(&parsed(), &nostrfy);
        let merged = apply_proposals(text, &proposals);
        // Unrelated lines and comments survive; only the replaced line's
        // own trailing comment is dropped (the helper rewrites that line).
        assert!(merged.contains("# my relay"));
        assert!(merged.contains("# the operator's name comment"));
        assert!(merged.contains(
            "private_key = \"0101010101010101010101010101010101010101010101010101010101010101\"   # secret"
        ));
        // The proposed values replaced the old ones.
        assert!(merged.contains("name = \"strfry default\""));
        assert!(merged.contains("port = 7777"));
        // `maxNumTags` equals the nostrfy default, so the operator's value
        // is left alone.
        assert!(merged.contains("max_tags = 100"));
        // A key whose section is missing is inserted with its section.
        assert!(merged.contains("max_readers = 256"));
        // The merged text parses and validates.
        validate_merged(&merged).expect("the merged config must be valid");
    }

    #[test]
    fn reports_unmapped_present_keys_only() {
        let cfg = parsed();
        let unmapped = unmapped(&cfg);
        let keys: Vec<&str> = unmapped.iter().map(|(key, _)| *key).collect();
        assert!(keys.contains(&"db"));
        assert!(keys.contains(&"relay.writePolicy.plugin"));
        assert!(keys.contains(&"relay.compression.enabled"));
        // An array-valued setting is present (its value is not parsed, but
        // the key must still be reported).
        assert!(keys.contains(&"relay.filterValidation.allowedKinds"));
        // A mapped key must never appear in both reports.
        assert!(!keys.contains(&"relay.maxPendingOutboundBytes"));
        // Keys absent from the file are not reported.
        assert!(!keys.contains(&"relay.info.banner"));
        assert!(!keys.contains(&"relay.filterValidation.enabled"));
    }

    #[test]
    fn find_config_prefers_the_explicit_path() {
        let dir =
            std::env::temp_dir().join(format!("nostrfy-strfry-config-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("custom.conf");
        std::fs::write(&path, "db = \"/x\"\n").unwrap();
        assert_eq!(find_config(Some(&path)), Some(path.clone()));
        assert_eq!(find_config(Some(&dir.join("missing.conf"))), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
