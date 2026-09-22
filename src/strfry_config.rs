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
        parse_block(&tokens, &mut index, "", &mut values, 0);
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
            // strfry parses its config as jaxn, which accepts `#`, `//` and
            // `/* ... */` comments. Missing the latter two merged
            // commented-out assignments or let a commented-out brace
            // derail the nesting.
            '#' => skip_line_comment(&mut chars),
            '/' => match chars.peek() {
                Some('/') => {
                    chars.next();
                    skip_line_comment(&mut chars);
                }
                Some('*') => {
                    chars.next();
                    skip_block_comment(&mut chars);
                }
                _ => tokens.push(Token::Name("/".into())),
            },
            '{' => tokens.push(Token::LBrace),
            '}' => tokens.push(Token::RBrace),
            '=' | ':' => tokens.push(Token::Eq),
            ';' | ',' => tokens.push(Token::Semi),
            '"' | '\'' => {
                // A triple quote opens a multi-line string whose content
                // may contain structure-like lines; consume it as one value.
                let delim = ch;
                let mut lookahead = chars.clone();
                if lookahead.next() == Some(delim) && lookahead.next() == Some(delim) {
                    chars.next();
                    chars.next();
                    tokens.push(Token::Str(read_multiline_string(&mut chars, delim)));
                } else {
                    tokens.push(Token::Str(read_string(&mut chars, delim)));
                }
            }
            '+' => tokens.push(Token::Name("+".into())),
            '[' => {
                skip_balanced(&mut chars);
                tokens.push(Token::Other);
            }
            _ => {
                let mut word = String::from(ch);
                while let Some(c) = chars.peek() {
                    if c.is_whitespace()
                        || matches!(
                            c,
                            '{' | '}' | '=' | ':' | ';' | ',' | '#' | '"' | '\'' | '[' | '/' | '+'
                        )
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
                } else if let Some(number) = parse_int(&word) {
                    tokens.push(Token::Int(number));
                } else {
                    tokens.push(Token::Name(word));
                }
            }
        }
    }
    tokens
}

/// Parses a decimal or `0x`-hex integer the way jaxn does (strfry accepts
/// hex for every numeric setting).
fn parse_int(word: &str) -> Option<i64> {
    let (negative, rest) = match word.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, word),
    };
    if let Some(hex) = rest
        .strip_prefix("0x")
        .or_else(|| rest.strip_prefix("0X"))
        .filter(|hex| !hex.is_empty())
    {
        let value = i64::from_str_radix(hex, 16).ok()?;
        return Some(if negative { -value } else { value });
    }
    word.parse::<i64>().ok()
}

/// Reads a triple-quoted multi-line string body (the opening delimiter was
/// consumed). The closing delimiter is the first occurrence of the same
/// three characters; an unterminated string consumes the rest of the file.
fn read_multiline_string(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    delim: char,
) -> String {
    // jaxn's `mqstring` strips one newline (LF or CRLF) right after the
    // opening delimiter; keeping it would merge a different value.
    if chars.peek() == Some(&'\r') {
        let mut lookahead = chars.clone();
        lookahead.next();
        if lookahead.peek() == Some(&'\n') {
            chars.next();
            chars.next();
        }
    } else if chars.peek() == Some(&'\n') {
        chars.next();
    }
    let mut out = String::new();
    while let Some(ch) = chars.next() {
        if ch == delim && chars.peek() == Some(&delim) {
            let mut lookahead = chars.clone();
            lookahead.next();
            if lookahead.next() == Some(delim) {
                chars.next();
                chars.next();
                break;
            }
        }
        out.push(ch);
    }
    out
}

/// Skips the rest of a `#` or `//` comment (the marker was consumed).
fn skip_line_comment(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    while chars.peek().is_some_and(|c| *c != '\n') {
        chars.next();
    }
}

/// Skips a `/* ... */` block comment (the opening `/*` was consumed). An
/// unterminated comment consumes the rest of the file, like the grammar's
/// end-of-input acceptance.
fn skip_block_comment(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    let mut star = false;
    for ch in chars.by_ref() {
        if star && ch == '/' {
            return;
        }
        star = ch == '*';
    }
}

/// Reads a quoted string body (the opening quote was consumed), decoding the
/// jaxn escapes strfry accepts (`\" \' \\ \/ \b \f \n \r \t \v \0`,
/// `\uXXXX` and `\u{...}`). An unknown escape keeps its backslash: silently
/// dropping it would merge a different value than strfry read.
fn read_string(chars: &mut std::iter::Peekable<std::str::Chars<'_>>, quote: char) -> String {
    let mut out = String::new();
    while let Some(ch) = chars.next() {
        if ch == quote {
            break;
        }
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('"') => out.push('"'),
            Some('\'') => out.push('\''),
            Some('\\') => out.push('\\'),
            Some('/') => out.push('/'),
            Some('b') => out.push('\u{0008}'),
            Some('f') => out.push('\u{000C}'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('v') => out.push('\u{000B}'),
            Some('0') => out.push('\0'),
            Some('u') => match read_unicode_escape(chars) {
                Some(decoded) => out.push(decoded),
                None => out.push_str("\\u"),
            },
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// Reads the tail of a `\u` escape (the `u` was consumed): `{codepoint}` or
/// four hex digits, combining a UTF-16 surrogate pair when present.
fn read_unicode_escape(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Option<char> {
    if chars.peek() == Some(&'{') {
        chars.next();
        let mut hex = String::new();
        for ch in chars.by_ref() {
            if ch == '}' {
                break;
            }
            hex.push(ch);
        }
        return char::from_u32(u32::from_str_radix(&hex, 16).ok()?);
    }
    let mut hex = String::new();
    for _ in 0..4 {
        hex.push(chars.next()?);
    }
    let code = u32::from_str_radix(&hex, 16).ok()?;
    if (0xD800..0xDC00).contains(&code) {
        // A high surrogate: the low half must follow as `\uXXXX`.
        if chars.next() == Some('\\') && chars.next() == Some('u') {
            let mut low = String::new();
            for _ in 0..4 {
                low.push(chars.next()?);
            }
            let low = u32::from_str_radix(&low, 16).ok()?;
            if (0xDC00..0xE000).contains(&low) {
                return char::from_u32(0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00));
            }
        }
        return None;
    }
    char::from_u32(code)
}

/// Skips a balanced `[...]` array (the opening bracket was consumed),
/// honoring strings and comments so a `[`/`]` inside them cannot derail the
/// scan.
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
            '"' | '\'' => {
                let delim = ch;
                let mut lookahead = chars.clone();
                if lookahead.next() == Some(delim) && lookahead.next() == Some(delim) {
                    chars.next();
                    chars.next();
                    read_multiline_string(chars, delim);
                } else {
                    read_string(chars, delim);
                }
            }
            '#' => skip_line_comment(chars),
            '/' => match chars.peek() {
                Some('/') => {
                    chars.next();
                    skip_line_comment(chars);
                }
                Some('*') => {
                    chars.next();
                    skip_block_comment(chars);
                }
                _ => {}
            },
            _ => {}
        }
    }
}

/// Maximum block nesting the parser recurses into. Real configs are a few
/// levels deep; an absurdly nested (hostile or corrupt) file must not
/// overflow the stack.
const MAX_PARSE_DEPTH: usize = 64;

/// Parses assignments and nested blocks under `prefix` into `values`.
fn parse_block(
    tokens: &[Token],
    index: &mut usize,
    prefix: &str,
    values: &mut BTreeMap<String, Value>,
    depth: usize,
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
                                if depth < MAX_PARSE_DEPTH {
                                    parse_block(
                                        tokens,
                                        index,
                                        &format!("{prefix}{key}."),
                                        values,
                                        depth + 1,
                                    );
                                } else {
                                    // Too deep: skip the block without
                                    // recursing (the remaining values are
                                    // ignored rather than overflowing).
                                    skip_block(tokens, index);
                                }
                            }
                            // The tokenizer turns `[ ... ]` into a single
                            // `Other` token: record the key as an array so
                            // the "not merged" report can list it.
                            Some(Token::Other) => {
                                values.insert(format!("{prefix}{key}"), Value::List);
                                *index += 1;
                            }
                            _ => {
                                if let Some(value) = read_scalar(tokens, index) {
                                    values.insert(format!("{prefix}{key}"), value);
                                }
                            }
                        }
                    }
                    Some(Token::LBrace) => {
                        *index += 1;
                        if depth < MAX_PARSE_DEPTH {
                            parse_block(
                                tokens,
                                index,
                                &format!("{prefix}{key}."),
                                values,
                                depth + 1,
                            );
                        } else {
                            skip_block(tokens, index);
                        }
                    }
                    _ => *index += 1,
                }
            }
            _ => *index += 1,
        }
    }
}

/// Reads a scalar value, applying jaxn's `+` concatenation (`"a" + "b"`
/// concatenates strings, `1 + 2` adds numbers).
fn read_scalar(tokens: &[Token], index: &mut usize) -> Option<Value> {
    fn one(tokens: &[Token], index: &mut usize) -> Option<Value> {
        // Unary plus: `+5` is 5 (jaxn allows a leading sign).
        if matches!(tokens.get(*index), Some(Token::Name(name)) if name == "+") {
            *index += 1;
        }
        let value = match tokens.get(*index)? {
            Token::Str(value) => Value::Str(value.clone()),
            Token::Int(value) => Value::Int(*value),
            Token::Bool(value) => Value::Bool(*value),
            Token::Name(value) => Value::Str(value.clone()),
            _ => return None,
        };
        *index += 1;
        Some(value)
    }
    let mut value = one(tokens, index)?;
    while matches!(tokens.get(*index), Some(Token::Name(name)) if name == "+") {
        *index += 1;
        let next = one(tokens, index)?;
        value = match (value, next) {
            (Value::Str(left), Value::Str(right)) => Value::Str(left + &right),
            (Value::Int(left), Value::Int(right)) => Value::Int(left.saturating_add(right)),
            // A mixed or invalid concatenation keeps the left value, like
            // the reference parser's error tolerance.
            (left, _) => left,
        };
    }
    Some(value)
}

/// Skips a `{ ... }` block without recursing (the opening brace was
/// consumed by the caller).
fn skip_block(tokens: &[Token], index: &mut usize) {
    let mut depth = 0usize;
    while *index < tokens.len() {
        match &tokens[*index] {
            Token::LBrace => depth += 1,
            Token::RBrace if depth == 0 => {
                *index += 1;
                return;
            }
            Token::RBrace => depth -= 1,
            _ => {}
        }
        *index += 1;
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
        // `0` is meaningful for these two and reads the same way in
        // nostrfy: no future-dated event (`created_at > now`) and no
        // configured outgoing-queue cap.
        let zero_ok = matches!(
            strfry_key,
            "events.rejectEventsNewerThanSeconds" | "relay.maxPendingOutboundBytes"
        );
        if *value < 0 || (*value == 0 && !zero_ok) || *value == current {
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
    // `relay.info.pubkey` accepts an npub or 32-byte hex on strfry;
    // nostrfy's `relay.pubkey` must be 64-hex, so only a hex value can be
    // merged (a non-hex value is reported as unmapped below).
    if let Some(Value::Str(value)) = strfry.get("relay.info.pubkey") {
        let hex = value.to_ascii_lowercase();
        if hex.len() == 64
            && hex.chars().all(|c| c.is_ascii_hexdigit())
            && hex != nostrfy.relay.pubkey
        {
            out.push(Proposal {
                strfry_key: "relay.info.pubkey",
                section: "relay",
                key: "pubkey",
                current: nostrfy.relay.pubkey.clone(),
                proposed: hex.clone(),
                value_toml: format!("\"{hex}\""),
            });
        }
    }
    // The LMDB map: strfry's `mapsize` is the whole reservation, and
    // nostrfy opens its map at `database.max_map_size` (the map is never
    // resized). Only an increase is offered: a smaller strfry map is
    // already covered by the nostrfy value, while raising the ceiling
    // prevents a map-full during or after the migration.
    if let Some(Value::Int(value)) = strfry.get("dbParams.mapsize")
        && *value > 0
        && *value as u64 > nostrfy.database.max_map_size as u64
    {
        out.push(Proposal {
            strfry_key: "dbParams.mapsize",
            section: "database",
            key: "max_map_size",
            current: nostrfy.database.max_map_size.to_string(),
            proposed: value.to_string(),
            value_toml: value.to_string(),
        });
    }
    out
}

/// The strfry keys/blocks present in the config that are not merged, with
/// the reason.
pub(crate) fn unmapped(
    strfry: &StrfryConfig,
    nostrfy: &Config,
) -> Vec<(&'static str, &'static str)> {
    let mut out: Vec<(&'static str, &'static str)> = UNMAPPED
        .iter()
        .filter(|(key, _)| strfry.get(key).is_some() || strfry.has_prefix(&format!("{key}.")))
        .copied()
        .collect();
    // A non-hex `relay.info.pubkey` (an npub, which strfry accepts) cannot
    // be merged: nostrfy requires 64 hex characters.
    if let Some(Value::Str(value)) = strfry.get("relay.info.pubkey")
        && !value.is_empty()
        && !(value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit()))
    {
        out.push((
            "relay.info.pubkey",
            "nostrfy requires a 64-hex pubkey; convert the npub before merging",
        ));
    }
    // A `maxFilterLimitCount = 0` disables COUNT on strfry; nostrfy has no
    // equivalent, so keeping its value silently would leave COUNT enabled.
    if matches!(strfry.get("relay.maxFilterLimitCount"), Some(Value::Int(0))) {
        out.push((
            "relay.maxFilterLimitCount",
            "0 disables COUNT on strfry; disable NIP-45 with relay.disabled_nips = [45] \
             or lower limits.max_count",
        ));
    }
    // A mapsize that is not an increase is covered by nostrfy's existing
    // `database.max_map_size` (the size the map is opened at); report it so
    // the operator knows the value was seen.
    if let Some(Value::Int(value)) = strfry.get("dbParams.mapsize")
        && *value > 0
        && (*value as u64) < nostrfy.database.max_map_size as u64
    {
        out.push((
            "dbParams.mapsize",
            "smaller than nostrfy's database.max_map_size (the map is opened at \
             max_map_size)",
        ));
    }
    out
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
    // The merge applies and validates one proposal at a time, so the
    // warnings `validate` emits would repeat once per proposal; the
    // returned error is unaffected.
    crate::logging::suppressed(|| {
        let cfg: Config = toml::from_str(text).map_err(|e| e.to_string())?;
        cfg.validate().map_err(|e| e.to_string())
    })
}

/// Finds the strfry config to read, in strfry's own order: an explicit path
/// (the flag or `$STRFRY_CONFIG`, returned even when it does not exist so
/// the caller can report it), then `/etc/strfry.conf`, then `./strfry.conf`.
/// The boolean is true for an explicitly requested path.
pub(crate) fn find_config(explicit: Option<&Path>) -> Option<(PathBuf, bool)> {
    if let Some(path) = explicit {
        return Some((path.to_path_buf(), true));
    }
    if let Some(path) = std::env::var_os("STRFRY_CONFIG") {
        return Some((PathBuf::from(path), true));
    }
    for candidate in ["/etc/strfry.conf", "strfry.conf"] {
        let path = PathBuf::from(candidate);
        if path.exists() {
            return Some((path, false));
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
        // strfry's 10 TB map exceeds nostrfy's ceiling: raised to
        // `database.max_map_size` (the map is opened at that size).
        assert!(paths.contains(&"database.max_map_size".into()));
    }

    #[test]
    fn skips_the_zero_count_cap_and_smaller_mapsize() {
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
        // A strfry map smaller than nostrfy's reservation is already
        // covered: no proposal.
        cfg.values
            .insert("dbParams.mapsize".into(), Value::Int(512 * 1024 * 1024));
        assert!(
            !proposals(&cfg, &nostrfy)
                .iter()
                .any(|p| p.path() == "database.max_map_size"),
            "a smaller map size must not be proposed"
        );
        // A larger one raises the ceiling so the migration cannot run into
        // a full map.
        cfg.values.insert(
            "dbParams.mapsize".into(),
            Value::Int(2 * 1024 * 1024 * 1024 * 1024),
        );
        assert!(
            proposals(&cfg, &nostrfy)
                .iter()
                .any(|p| p.path() == "database.max_map_size"),
            "a larger map size is proposed"
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
        let unmapped = unmapped(&cfg, &Config::default());
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
        // A mapsize below nostrfy's reservation is reported as not merged
        // (the sample's 10 TB is larger and is proposed instead).
        assert!(!keys.contains(&"dbParams.mapsize"));
    }

    #[test]
    fn parses_jaxn_comments_and_strings() {
        // strfry reads `//` and `/* ... */` comments and single-quoted
        // strings; missing them merged commented-out assignments or let a
        // commented-out brace derail the nesting.
        let cfg = StrfryConfig::parse(
            "db = \"/x\"\n\
             // relay.bind = \"9.9.9.9\"\n\
             /* relay.negentropy { maxSyncEvents = 1 } */\n\
             relay {\n\
               // {\n\
               info { name = 'single quoted' description = \"caf\\u00e9\\nnext\" }\n\
               port = 7777\n\
             }\n",
        );
        assert_eq!(cfg.get("relay.port"), Some(&Value::Int(7777)));
        assert_eq!(
            cfg.get("relay.info.name"),
            Some(&Value::Str("single quoted".into()))
        );
        assert_eq!(
            cfg.get("relay.info.description"),
            Some(&Value::Str("caf\u{e9}\nnext".into()))
        );
        // The commented-out assignments must not become values.
        assert_eq!(cfg.get("relay.bind"), None);
        assert_eq!(cfg.get("relay.negentropy.maxSyncEvents"), None);
    }

    #[test]
    fn array_comments_do_not_derail_the_scan() {
        let cfg = StrfryConfig::parse(
            "db = \"/x\"\n\
             foo = [ # [note\n 1 ]\n\
             relay { info { name = \"after\" } port = 7777 }\n",
        );
        assert_eq!(
            cfg.get("relay.info.name"),
            Some(&Value::Str("after".into()))
        );
        assert_eq!(cfg.get("relay.port"), Some(&Value::Int(7777)));
    }

    #[test]
    fn hex_pubkey_is_merged_and_npub_is_reported() {
        let mut cfg = parsed();
        cfg.values
            .insert("relay.info.pubkey".into(), Value::Str("aa".repeat(32)));
        let nostrfy = Config::default();
        assert!(
            proposals(&cfg, &nostrfy)
                .iter()
                .any(|p| p.path() == "relay.pubkey")
        );
        assert!(
            !unmapped(&cfg, &nostrfy)
                .iter()
                .any(|(key, _)| *key == "relay.info.pubkey")
        );

        // strfry also accepts an npub; nostrfy requires 64 hex, so it is
        // reported instead of proposed (and rejected by validation).
        cfg.values
            .insert("relay.info.pubkey".into(), Value::Str("npub1qqq".into()));
        assert!(
            !proposals(&cfg, &nostrfy)
                .iter()
                .any(|p| p.path() == "relay.pubkey")
        );
        assert!(
            unmapped(&cfg, &nostrfy)
                .iter()
                .any(|(key, _)| *key == "relay.info.pubkey")
        );
    }

    #[test]
    fn meaningful_zeros_are_merged() {
        let mut cfg = parsed();
        cfg.values
            .insert("events.rejectEventsNewerThanSeconds".into(), Value::Int(0));
        cfg.values
            .insert("relay.maxPendingOutboundBytes".into(), Value::Int(0));
        let nostrfy = Config::default();
        let paths: Vec<String> = proposals(&cfg, &nostrfy)
            .iter()
            .map(Proposal::path)
            .collect();
        assert!(paths.contains(&"limits.max_created_at_future_secs".into()));
        assert!(paths.contains(&"limits.max_out_queue_bytes".into()));
        // `maxFilterLimitCount = 0` stays excluded (COUNT is disabled).
        cfg.values
            .insert("relay.maxFilterLimitCount".into(), Value::Int(0));
        assert!(
            !proposals(&cfg, &nostrfy)
                .iter()
                .any(|p| p.path() == "limits.max_count")
        );
    }

    #[test]
    fn parses_triple_quoted_concat_hex_and_trailing_comments() {
        let cfg = StrfryConfig::parse(
            "db = \"/x\"\n\
             relay {\n\
               info { name = \"\"\"multi\nline\"\"\" description = 'a' + 'b' }\n\
               port = 0x1f91\n\
               bind = \"127.0.0.1\" maxReqFilterSize = 200//comment\n\
             }\n",
        );
        assert_eq!(
            cfg.get("relay.info.name"),
            Some(&Value::Str("multi\nline".into()))
        );
        assert_eq!(
            cfg.get("relay.info.description"),
            Some(&Value::Str("ab".into()))
        );
        assert_eq!(cfg.get("relay.port"), Some(&Value::Int(0x1f91)));
        assert_eq!(cfg.get("relay.maxReqFilterSize"), Some(&Value::Int(200)));
    }

    #[test]
    fn deeply_nested_blocks_do_not_overflow_the_stack() {
        let text = format!("a{}{}", "{".repeat(5000), "}".repeat(5000));
        let cfg = StrfryConfig::parse(&text);
        // The parser must survive an absurd nesting depth; the over-deep
        // levels are ignored rather than crashing the process.
        assert!(cfg.get("a").is_none());
    }

    #[test]
    fn strips_the_newline_after_a_triple_quote() {
        // jaxn's `mqstring` strips one newline right after the opening
        // delimiter; keeping it would merge a different value.
        let cfg =
            StrfryConfig::parse("db = \"/x\"\nrelay { info { name = \"\"\"\nMy Relay\"\"\" } }\n");
        assert_eq!(
            cfg.get("relay.info.name"),
            Some(&Value::Str("My Relay".into()))
        );
    }

    #[test]
    fn unspaced_plus_and_signed_hex_are_parsed() {
        let cfg = StrfryConfig::parse(
            "db = \"/x\"\n\
             relay { port = 7000+77 maxReqFilterSize = 0x10+0x10 maxWebsocketPayloadSize = -0x10 }\n",
        );
        assert_eq!(cfg.get("relay.port"), Some(&Value::Int(7077)));
        assert_eq!(cfg.get("relay.maxReqFilterSize"), Some(&Value::Int(32)));
        assert_eq!(
            cfg.get("relay.maxWebsocketPayloadSize"),
            Some(&Value::Int(-16))
        );
    }

    #[test]
    fn an_array_with_a_triple_quoted_string_does_not_derail() {
        // The array skipper must understand triple quotes: an odd quote or
        // a `]` inside the string otherwise ends the array early and the
        // rest is tokenized as real config.
        let cfg = StrfryConfig::parse(
            "db = \"/x\"\n\
             foo = [ \"\"\"a\"b] relay { port = 9999 } c\"\"\" ]\n\
             relay { port = 7777 }\n",
        );
        assert_eq!(cfg.get("relay.port"), Some(&Value::Int(7777)));
    }

    #[test]
    fn find_config_prefers_the_explicit_path() {
        let dir =
            std::env::temp_dir().join(format!("nostrfy-strfry-config-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("custom.conf");
        std::fs::write(&path, "db = \"/x\"\n").unwrap();
        assert_eq!(find_config(Some(&path)), Some((path.clone(), true)));
        // An explicit path is returned even when missing: the caller reports
        // it instead of silently falling back to another file.
        assert_eq!(
            find_config(Some(&dir.join("missing.conf"))),
            Some((dir.join("missing.conf"), true))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
