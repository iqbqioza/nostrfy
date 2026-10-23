//! NIP-98: HTTP Auth.
//!
//! Verifies NIP-98 HTTP auth events (`kind:27235` events sent in the
//! `Authorization: Nostr <base64 event>` header), shared by the NIP-86
//! management API and the NIP-29 LiveKit token endpoint.

use base64::Engine;

use crate::event::Event;
use crate::nips::nip01;
use crate::util::unix_now;

pub const AUTH_KIND: u64 = 27235;
pub const PAYLOAD_TAG: &str = "payload";
pub const URL_TAG: &str = "u";
pub const METHOD_TAG: &str = "method";

/// Extracts the base64 event from an `Authorization` header value carrying
/// the NIP-98 `Nostr` scheme. HTTP auth-schemes are case-insensitive
/// (RFC 9110), and clients send `Nostr`, `nostr` and `NOSTR`: a
/// case-sensitive prefix comparison rejected the non-canonical spellings.
/// Returns `None` for another scheme (`Bearer`, ...) or a scheme with no
/// token.
pub fn strip_nostr_scheme(value: &str) -> Option<&str> {
    // RFC 9110: the scheme and credentials are separated by one or more
    // whitespace characters. Split at the first one and trim the rest, so
    // `Nostr  tok` and `Nostr\ttok` work; an empty token is no token.
    let (scheme, token) = value.split_once(char::is_whitespace)?;
    let token = token.trim();
    scheme
        .eq_ignore_ascii_case("Nostr")
        .then_some(token)
        .filter(|token| !token.is_empty())
}

/// Verifies an encoded NIP-98 event. The token is accepted in both the
/// spec's standard Base64 and the Base64url-without-padding form some
/// client libraries emit (the Blossom endpoints already accept both, so
/// rejecting the url-safe form here would 401 legitimate clients on the
/// NIP-86 and LiveKit routes). Decoding is the only leniency: the JSON,
/// signature and tag checks below are strict.
/// When `expected_pubkey` is given the
/// event must be authored by it; when `require_payload` is set the event
/// must carry a `payload` tag (NIP-86 requires it); when
/// `expected_payload_hash` is given the tag value must additionally equal
/// the sha256 hex of the request body — presence alone would let a captured
/// authorization be replayed against a different body. The `u` tag value is
/// checked with `url_matches` and the `method` tag must equal the HTTP
/// method of the request (NIP-98 requirement 4).
pub fn verify(
    encoded: &str,
    expected_pubkey: Option<&str>,
    require_payload: bool,
    expected_payload_hash: Option<&str>,
    method: &str,
    url_matches: impl Fn(&str) -> bool,
) -> Option<Verified> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded))
        .ok()?;
    let event: Event = serde_json::from_slice(&raw).ok()?;
    if event.kind != AUTH_KIND {
        return None;
    }
    if let Some(expected) = expected_pubkey
        && !event.pubkey.eq_ignore_ascii_case(expected)
    {
        return None;
    }
    let now = unix_now();
    if event.created_at.abs_diff(now) > 60 {
        return None;
    }
    let url_ok = event
        .tags
        .iter()
        .any(|t| t.len() >= 2 && t[0] == URL_TAG && url_matches(&t[1]));
    if !url_ok {
        return None;
    }
    let method_ok = event
        .tags
        .iter()
        .any(|t| t.len() >= 2 && t[0] == METHOD_TAG && t[1] == method);
    if !method_ok {
        return None;
    }
    if require_payload {
        let payload_ok = event.tags.iter().any(|t| {
            t.len() >= 2
                && t[0] == PAYLOAD_TAG
                && expected_payload_hash.is_none_or(|want| t[1].eq_ignore_ascii_case(want))
        });
        if !payload_ok {
            return None;
        }
    }
    if nip01::verify(&event).is_err() {
        return None;
    }
    Some(Verified {
        pubkey: event.pubkey,
        id: event.id,
        created_at: event.created_at,
    })
}

/// sha256 hex of HTTP request bytes, for the NIP-98 `payload` tag
/// comparison (NIP-98: the tag is the sha256 of the request body).
pub fn payload_sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}

/// A verified NIP-98 authorization: the author pubkey, the auth event id
/// (the caller records the id in its replay guard), and the event's
/// `created_at` (the guard must remember the id for the whole interval
/// the event still verifies).
pub struct Verified {
    pub pubkey: String,
    pub id: String,
    pub created_at: u64,
}

/// NIP-98 replay guard: "the `u` tag MUST be exactly the same as the
/// absolute request URL" only authorizes one request, so a captured
/// `Authorization` header must not be reusable. Entries expire with the
/// 60-second auth window; a hard cap bounds memory even under an
/// authenticated event flood. Expired entries are pruned on every call.
/// At capacity the guard evicts a live entry of the most prolific author
/// instead of refusing the new authorization: a fail-closed cap let anyone
/// with a signing key flood 4096 authorizations and lock every other
/// identity — the admin's management NIP-98 included — out for the rest of
/// the window. The flood's own entries are the eviction pool (an attacker
/// can sign a fresh event at will, so replay protection for the flood
/// itself is worth nothing), which keeps a quiet identity's live
/// authorizations tracked and its captured ones unreplayable. Among tied
/// authors the one whose entries were presented most recently is chosen: a
/// fresh-key flood outranks (and so evicts) its own fresh entries, not a
/// quiet identity's older — possibly captured — authorization. This is
/// process-local replay protection; restarting clears the guard.
pub struct ReplayGuard {
    seen: std::sync::Mutex<std::collections::HashMap<String, Entry>>,
    /// Monotonic presentation sequence (see [`Entry::presented`]).
    next_presentation: std::sync::atomic::AtomicU64,
    /// Unix time of the last capacity warning: `accept` runs for every
    /// authenticated request, so a flood that fills the guard must not log
    /// one line per evicted authorization.
    last_capacity_warning: std::sync::atomic::AtomicU64,
}

/// One live authorization: when it stops verifying, who presented it, and a
/// monotonic presentation sequence. The author and sequence drive the fair
/// eviction at capacity (see [`ReplayGuard`]); the sequence is deliberately
/// not derived from the client-signed `created_at`.
struct Entry {
    expiry: u64,
    /// Monotonic acceptance order. A flood is presented after a captured
    /// authorization, so this (unlike `created_at`) cannot be backdated.
    presented: u64,
    /// The author, used to bound one management identity's protected
    /// entries instead of letting it fill the whole guard.
    pubkey: String,
    /// A management identity (admin or method grantee) authorization:
    /// never evicted by another author, so a flood cannot reset a captured
    /// header. Its own older entries are the only protected eviction pool.
    protected: bool,
}

impl Default for ReplayGuard {
    fn default() -> Self {
        ReplayGuard {
            seen: std::sync::Mutex::new(std::collections::HashMap::new()),
            next_presentation: std::sync::atomic::AtomicU64::new(0),
            last_capacity_warning: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

impl ReplayGuard {
    /// Maximum authorizations tracked within one window.
    const MAX_ENTRIES: usize = 4096;
    /// Maximum protected authorizations one management identity may hold
    /// concurrently. Without a per-author bound one grantee could fill the
    /// whole guard with its own protected entries and make every other
    /// management identity fail closed until they expire (AUD-16).
    const MAX_PROTECTED_PER_AUTHOR: usize = 64;
    /// Minimum seconds between capacity warnings.
    const WARNING_INTERVAL: u64 = 60;

    /// Records an **unprotected** authorization (an identity without a
    /// management grant); equivalent to [`Self::accept_as`] with
    /// `protected = false`. Kept as the simple entry point for callers that
    /// only need replay detection.
    pub fn accept(&self, id: &str, now: u64, created_at: u64, pubkey: &str) -> bool {
        self.accept_as(id, now, created_at, pubkey, false)
    }

    /// Records `id` (valid until the event stops verifying); returns
    /// `false` when it was already used (a replay) or when the guard is full
    /// of other authors' protected entries. Expired entries are pruned
    /// first.
    ///
    /// `protected` marks an authorization of a management identity (the
    /// configured admin pubkey or a pubkey with a method grant). Protected
    /// entries are **never** evicted for another author: a flood of unknown
    /// identities must not be able to remove a captured admin/grantee
    /// authorization and make it replayable. A protected author is bounded
    /// to [`Self::MAX_PROTECTED_PER_AUTHOR`] live entries; past that, the
    /// new request evicts that author's own oldest entry. At global capacity
    /// the guard evicts the oldest unprotected entry, or (when every entry
    /// is protected) the requesting author's own oldest protected entry;
    /// when the requester has none, it refuses the new authorization (fail
    /// closed). One grantee therefore cannot fill the guard and lock every
    /// other management identity out.
    ///
    /// `pubkey` identifies the author for that per-author bound.
    /// `valid_until` must cover the whole NIP-98 validity interval of the
    /// event: callers pass its `created_at` and the guard extends past the
    /// inclusive 60-second boundary, so a replay at the last valid second
    /// (or inside a future-dated event's extended window) is still refused.
    pub(crate) fn accept_as(
        &self,
        id: &str,
        now: u64,
        created_at: u64,
        pubkey: &str,
        protected: bool,
    ) -> bool {
        // NIP-98 events may spell the same key in upper/mixed case; the
        // per-author quota must use the canonical lowercase form or one
        // grantee gets 64 slots per spelling and can fill the guard.
        let pubkey = pubkey.to_ascii_lowercase();
        let pubkey = pubkey.as_str();
        let valid_until = created_at.saturating_add(61);
        let presented = self
            .next_presentation
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .saturating_add(1);
        let mut warn = false;
        let accepted = {
            let mut seen = self.seen.lock().unwrap_or_else(|p| p.into_inner());
            seen.retain(|_, entry| entry.expiry > now);
            if seen.contains_key(id) {
                false
            } else {
                let mut admit = true;
                if protected {
                    let own = seen
                        .values()
                        .filter(|entry| entry.protected && entry.pubkey == pubkey)
                        .count();
                    if own >= Self::MAX_PROTECTED_PER_AUTHOR {
                        // One management identity's own entries are the
                        // only protected entries it may evict.
                        admit = Self::evict_oldest_protected(&mut seen, pubkey);
                    } else if seen.len() >= Self::MAX_ENTRIES {
                        warn = true;
                        // Prefer an unprotected victim; with none left,
                        // evict this author's own oldest protected entry
                        // rather than another identity's capture.
                        admit = Self::evict_unprotected(&mut seen)
                            || Self::evict_oldest_protected(&mut seen, pubkey);
                    }
                } else if seen.len() >= Self::MAX_ENTRIES {
                    warn = true;
                    admit = Self::evict_unprotected(&mut seen);
                }
                if admit {
                    seen.insert(
                        id.to_string(),
                        Entry {
                            expiry: valid_until,
                            presented,
                            pubkey: pubkey.to_string(),
                            protected,
                        },
                    );
                }
                admit
            }
        };
        if warn {
            self.warn_capacity(now);
        }
        accepted
    }

    /// Removes the oldest protected authorization belonging to `pubkey`
    /// (by presentation order). Other authors' protected captures are never
    /// victims.
    fn evict_oldest_protected(
        seen: &mut std::collections::HashMap<String, Entry>,
        pubkey: &str,
    ) -> bool {
        let victim = seen
            .iter()
            .filter(|(_, entry)| entry.protected && entry.pubkey == pubkey)
            .min_by_key(|(_, entry)| entry.presented)
            .map(|(id, _)| id.clone());
        if let Some(id) = victim {
            seen.remove(&id);
            true
        } else {
            false
        }
    }

    /// Removes the oldest **unprotected** authorization (by the guard's own
    /// presentation order, not the client-signed `created_at`). Returns
    /// false when every live entry is protected; the protected path then
    /// consults the requester's own entries.
    fn evict_unprotected(seen: &mut std::collections::HashMap<String, Entry>) -> bool {
        let victim = seen
            .iter()
            .filter(|(_, entry)| !entry.protected)
            .min_by_key(|(_, entry)| entry.presented)
            .map(|(id, _)| id.clone());
        if let Some(id) = victim {
            seen.remove(&id);
            true
        } else {
            false
        }
    }

    /// Rate-limited capacity warning (a bool would log once ever; time
    /// based keeps the operator informed while a flood persists).
    fn warn_capacity(&self, now: u64) {
        use std::sync::atomic::Ordering;
        let last = self.last_capacity_warning.load(Ordering::Relaxed);
        if now.saturating_sub(last) < Self::WARNING_INTERVAL {
            return;
        }
        if self
            .last_capacity_warning
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            log::warn!(
                "NIP-98 replay guard is at capacity ({} live authorizations); \
                 protected management captures are never evicted",
                Self::MAX_ENTRIES
            );
        }
    }
}

/// NIP-98: "The `u` tag MUST be exactly the same as the absolute request
/// URL (including query parameters)." The expected URL is the relay's
/// canonical HTTP origin (`relay.public_url` mapped to `https`/`http`, or
/// the bound `http://host:port` when unset) plus the exact request path and
/// query; the comparison is byte-for-byte.
///
/// One interop allowance: for a root request the path is `/`, and clients
/// (e.g. `nak`) send the bare origin without the trailing slash. Per
/// RFC 3986 an empty path is equivalent to `/` for http(s), so both
/// spellings are accepted — a strict compare 401s a correct client.
pub fn matches_request_url(
    tag: &str,
    identity: &crate::nips::nip62::RelayIdentity<'_>,
    request_path: &str,
    request_query: Option<&str>,
) -> bool {
    let mut expected = identity.http_origin();
    expected.push_str(request_path);
    if let Some(query) = request_query {
        expected.push('?');
        expected.push_str(query);
    }
    if tag == expected {
        return true;
    }
    if request_path == "/" && request_query.is_none() {
        let origin = identity.http_origin();
        return tag == origin;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nips::nip01::compute_id;
    use crate::nips::nip62::RelayIdentity;
    use secp256k1::{Keypair, XOnlyPublicKey};

    fn signed_event(method: Option<&str>, url: &str, created: u64) -> Event {
        let keypair = Keypair::from_secret_bytes([5u8; 32]).unwrap();
        let pubkey = XOnlyPublicKey::from_keypair(&keypair).0.to_string();
        let mut tags = vec![vec![URL_TAG.into(), url.into()]];
        if let Some(m) = method {
            tags.push(vec![METHOD_TAG.into(), m.into()]);
        }
        let mut ev = Event {
            id: String::new(),
            pubkey,
            created_at: created,
            kind: AUTH_KIND,
            tags,
            content: String::new(),
            sig: String::new(),
        };
        ev.id = compute_id(&ev);
        let id = ev.id_bytes().unwrap();
        ev.sig = secp256k1::schnorr::sign_no_aux_rand(&id, &keypair).to_string();
        ev
    }

    fn encode(ev: &Event) -> String {
        base64::engine::general_purpose::STANDARD.encode(serde_json::to_string(ev).unwrap())
    }

    fn encode_url_safe_no_pad(ev: &Event) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_string(ev).unwrap())
    }

    #[test]
    fn verify_accepts_base64url_without_padding() {
        // Client libraries emit the auth event in either Base64 form; the
        // Blossom endpoints accept both, so NIP-98 verification must too
        // (otherwise NIP-86 and LiveKit 401 legitimate clients).
        let now = unix_now();
        let ev = signed_event(Some("POST"), "https://relay.example.com/", now);
        let check = |encoded: &str| {
            verify(encoded, None, false, None, "POST", |u| {
                u == "https://relay.example.com/"
            })
            .is_some()
        };
        assert!(check(&encode(&ev)), "standard Base64 must verify");
        assert!(
            check(&encode_url_safe_no_pad(&ev)),
            "Base64url without padding must verify"
        );
        assert!(!check("!!!not-base64!!!"), "garbage must not verify");
    }

    #[test]
    fn nostr_scheme_is_case_insensitive() {
        // RFC 9110: auth-schemes are case-insensitive, and clients send the
        // NIP-98 scheme as `Nostr`, `nostr` or `NOSTR`.
        assert_eq!(strip_nostr_scheme("Nostr abc"), Some("abc"));
        assert_eq!(strip_nostr_scheme("nostr abc"), Some("abc"));
        assert_eq!(strip_nostr_scheme("NOSTR abc"), Some("abc"));
        assert_eq!(strip_nostr_scheme("NoStR abc"), Some("abc"));
        // RFC 9110 allows one or more whitespace characters.
        assert_eq!(strip_nostr_scheme("Nostr  abc"), Some("abc"));
        assert_eq!(strip_nostr_scheme("Nostr\tabc"), Some("abc"));
        assert_eq!(strip_nostr_scheme("Nostr   "), None);
        // Only the first space separates the scheme from the token.
        assert_eq!(strip_nostr_scheme("Nostr a b"), Some("a b"));
        // Other schemes and malformed values are not a NIP-98 authorization.
        assert_eq!(strip_nostr_scheme("Bearer abc"), None);
        assert_eq!(strip_nostr_scheme("Nostr"), None);
        assert_eq!(strip_nostr_scheme(""), None);
    }

    #[test]
    fn method_tag_must_match() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let now = unix_now();
        rt.block_on(async {
            // Correct method and url: accepted.
            let ev = signed_event(Some("POST"), "https://relay.example.com/", now);
            assert!(
                verify(&encode(&ev), None, false, None, "POST", |u| u
                    == "https://relay.example.com/",)
                .is_some()
            );
            // Wrong method: rejected (NIP-98 requirement 4).
            assert!(
                verify(&encode(&ev), None, false, None, "GET", |u| u
                    == "https://relay.example.com/",)
                .is_none()
            );
            // Missing method tag: rejected.
            let bare = signed_event(None, "https://relay.example.com/", now);
            assert!(
                verify(&encode(&bare), None, false, None, "POST", |u| u
                    == "https://relay.example.com/",)
                .is_none()
            );
        });
    }

    #[test]
    fn payload_tag_must_match_body_hash() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let now = unix_now();
        let body = br#"{"method":"banpubkey","params":[]}"#;
        let want = payload_sha256_hex(body);
        let mut ev = signed_event(Some("POST"), "https://relay.example.com/", now);
        ev.tags.push(vec![PAYLOAD_TAG.into(), want.clone()]);
        // Re-sign after adding the tag (the id commits to the tags).
        ev.id = compute_id(&ev);
        let id = ev.id_bytes().unwrap();
        let keypair = Keypair::from_secret_bytes([5u8; 32]).unwrap();
        ev.sig = secp256k1::schnorr::sign_no_aux_rand(&id, &keypair).to_string();
        let encoded = encode(&ev);
        rt.block_on(async {
            // Matching hash: accepted.
            assert!(
                verify(&encoded, None, true, Some(&want), "POST", |u| u
                    == "https://relay.example.com/",)
                .is_some()
            );
            // A captured authorization replayed against another body: rejected.
            let other = payload_sha256_hex(br#"{"method":"allowpubkey","params":[]}"#);
            assert!(
                verify(&encoded, None, true, Some(&other), "POST", |u| u
                    == "https://relay.example.com/",)
                .is_none()
            );
            // Missing tag when required: rejected.
            let bare = signed_event(Some("POST"), "https://relay.example.com/", now);
            assert!(
                verify(&encode(&bare), None, true, Some(&want), "POST", |u| u
                    == "https://relay.example.com/",)
                .is_none()
            );
        });
    }

    #[test]
    fn request_url_matches_exactly() {
        let identity = RelayIdentity::new("relay.example.com", 8080, "");
        // Exact match against the plain-HTTP origin of a directly served
        // relay.
        assert!(matches_request_url(
            "http://relay.example.com:8080/ws",
            &identity,
            "/ws",
            None
        ));
        // NIP-98 requires the exact absolute URL: other schemes are not
        // interchangeable.
        for other in [
            "https://relay.example.com:8080/ws",
            "wss://relay.example.com:8080/ws",
            "nostr+https://relay.example.com:8080/ws",
            "ws://relay.example.com:8080/ws",
        ] {
            assert!(
                !matches_request_url(other, &identity, "/ws", None),
                "{other} must not match an http request"
            );
        }
        // The query must match exactly, including parameter order.
        assert!(matches_request_url(
            "http://relay.example.com:8080/ws?a=1&b=2",
            &identity,
            "/ws",
            Some("a=1&b=2")
        ));
        assert!(!matches_request_url(
            "http://relay.example.com:8080/ws?a=1&b=2",
            &identity,
            "/ws",
            Some("b=2&a=1")
        ));
        // A query on one side but not the other is a mismatch.
        assert!(!matches_request_url(
            "http://relay.example.com:8080/ws?a=1",
            &identity,
            "/ws",
            None
        ));
        assert!(!matches_request_url(
            "http://relay.example.com:8080/ws",
            &identity,
            "/ws",
            Some("a=1")
        ));
        // The path must match exactly (including the trailing slash).
        assert!(!matches_request_url(
            "http://relay.example.com:8080/ws/",
            &identity,
            "/ws",
            None
        ));
        assert!(!matches_request_url(
            "http://relay.example.com:8080/other",
            &identity,
            "/ws",
            None
        ));
        // A bare authority is accepted for the root URL: per RFC 3986 an
        // empty path is equivalent to "/" for http(s), and clients (nak)
        // send the bare origin. See the interop allowance in
        // `matches_request_url`.
        assert!(matches_request_url(
            "http://relay.example.com:8080",
            &identity,
            "/",
            None
        ));
        assert!(matches_request_url(
            "http://relay.example.com:8080/",
            &identity,
            "/",
            None
        ));
        // Host and port must match; a non-default port may not be omitted.
        assert!(!matches_request_url(
            "http://evil.example.com:8080/ws",
            &identity,
            "/ws",
            None
        ));
        assert!(!matches_request_url(
            "http://relay.example.com:9999/ws",
            &identity,
            "/ws",
            None
        ));
        assert!(!matches_request_url(
            "http://relay.example.com/ws",
            &identity,
            "/ws",
            None
        ));
        // Unsupported schemes are rejected.
        assert!(!matches_request_url(
            "ftp://relay.example.com:8080/ws",
            &identity,
            "/ws",
            None
        ));
    }

    #[test]
    fn request_url_public_url_and_ports() {
        // With no public_url the relay is plain HTTP and the bound port is
        // part of the expected URL.
        let identity = RelayIdentity::new("relay.example.com", 443, "");
        assert!(matches_request_url(
            "http://relay.example.com:443/ws",
            &identity,
            "/ws",
            None
        ));
        assert!(!matches_request_url(
            "https://relay.example.com/ws",
            &identity,
            "/ws",
            None
        ));
        // public_url overrides the authority; the WebSocket scheme maps to
        // the HTTP scheme (`wss` -> `https`, `ws` -> `http`).
        let identity = RelayIdentity::new("127.0.0.1", 8080, "wss://public.example.net");
        assert!(matches_request_url(
            "https://public.example.net/ws",
            &identity,
            "/ws",
            None
        ));
        assert!(!matches_request_url(
            "wss://public.example.net/ws",
            &identity,
            "/ws",
            None
        ));
        assert!(!matches_request_url(
            "https://public.example.net:8443/ws",
            &identity,
            "/ws",
            None
        ));
        // A plain `ws://` public URL maps to `http`.
        let identity = RelayIdentity::new("127.0.0.1", 8080, "ws://public.example.net");
        assert!(matches_request_url(
            "http://public.example.net/ws",
            &identity,
            "/ws",
            None
        ));
    }

    #[test]
    fn request_url_accepts_a_bare_root_origin() {
        // Interop: clients (e.g. `nak admin`) send the origin without the
        // trailing slash for a root request. Per RFC 3986 the empty path is
        // equivalent to `/` for http(s), so both spellings must verify.
        let identity = RelayIdentity::new("127.0.0.1", 8080, "ws://public.example.net");
        assert!(matches_request_url(
            "http://public.example.net/",
            &identity,
            "/",
            None
        ));
        assert!(matches_request_url(
            "http://public.example.net",
            &identity,
            "/",
            None
        ));
        // A non-root path still requires the exact path (no slash leniency).
        assert!(!matches_request_url(
            "http://public.example.net",
            &identity,
            "/ws",
            None
        ));
        // A query on a root request keeps the exact form.
        assert!(!matches_request_url(
            "http://public.example.net",
            &identity,
            "/",
            Some("a=1")
        ));
        assert!(matches_request_url(
            "http://public.example.net/?a=1",
            &identity,
            "/",
            Some("a=1")
        ));
    }

    #[test]
    fn replay_guard_rejects_reuse_within_the_window() {
        let guard = ReplayGuard::default();
        assert!(guard.accept("aa", 1_000, 1_000, "pk-a"));
        assert!(
            !guard.accept("aa", 1_000, 1_000, "pk-a"),
            "the same id is a replay"
        );
        assert!(
            !guard.accept("aa", 1_059, 1_059, "pk-a"),
            "still within the window"
        );
        // After the 60-second window the entry expires.
        assert!(guard.accept("aa", 1_061, 1_061, "pk-a"));
        // Distinct ids are independent.
        assert!(guard.accept("bb", 1_061, 1_061, "pk-b"));
    }

    #[test]
    fn replay_guard_covers_the_full_validity_window() {
        // The guard is keyed to the event's validity interval, not the
        // first-accept time: a replay at the last valid second — or inside
        // a future-dated event's extended window — is still refused.
        let guard = ReplayGuard::default();
        assert!(guard.accept("aa", 1_000, 1_000, "pk-a"));
        assert!(
            !guard.accept("aa", 1_060, 1_060, "pk-a"),
            "the inclusive boundary second is still guarded"
        );
        assert!(guard.accept("aa", 1_061, 1_061, "pk-a"));
        // Future-dated event (created_at ahead): valid until
        // created_at + 60, guarded that long.
        assert!(guard.accept("bb", 1_000, 1_060, "pk-b"));
        assert!(
            !guard.accept("bb", 1_061, 1_061, "pk-b"),
            "a future-dated auth stays guarded past first-accept + 60"
        );
        assert!(
            !guard.accept("bb", 1_120, 1_120, "pk-b"),
            "still within created_at + 60"
        );
        assert!(guard.accept("bb", 1_121, 1_121, "pk-b"));
    }

    #[test]
    fn replay_guard_evicts_the_oldest_unprotected_entry_at_capacity() {
        // A single-key flood must not lock other identities out: at
        // capacity the oldest unprotected entry is evicted, so the quiet
        // identity is admitted and stays tracked, and what is lost is the
        // flood's own replay protection — worth nothing, since the flood
        // can re-sign at will.
        let guard = ReplayGuard::default();
        // flood-0 is presented first, so it is the oldest unprotected
        // entry and the deterministic eviction victim.
        assert!(guard.accept("flood-0", 1_000, 1_000, "pk-flood"));
        for n in 1..ReplayGuard::MAX_ENTRIES {
            assert!(guard.accept(&format!("flood-{n}"), 1_000, 1_000 + n as u64, "pk-flood"));
        }
        // The guard is full of the flooder's live entries: the quiet
        // identity is still admitted (the flood's oldest entry is evicted).
        assert!(
            guard.accept("quiet", 1_001, 1_001, "pk-quiet"),
            "a flood must not lock another identity out"
        );
        // Its authorization is tracked: a replay is refused.
        assert!(
            !guard.accept("quiet", 1_001, 1_001, "pk-quiet"),
            "the quiet authorization must stay protected from replay"
        );
        // The evicted entry is the flood's own oldest: replaying it is
        // admitted again (the flood could just re-sign, so this costs
        // nothing).
        assert!(
            guard.accept("flood-0", 1_001, 1_001, "pk-flood"),
            "the flood's evicted entry is admitted again"
        );
        // The quiet identity's entry survived the flood's next eviction
        // (the most prolific author is the flood, not the quiet identity).
        assert!(
            !guard.accept("quiet", 1_001, 1_001, "pk-quiet"),
            "the quiet entry must survive flood evictions"
        );
        // Once every entry expires the guard drains back to empty.
        assert!(
            guard.accept("new", 5_157, 5_157, "pk-new"),
            "acceptance resumes after the live entries expire"
        );
    }

    #[test]
    fn replay_guard_at_capacity_keeps_a_quiet_identity_tracked() {
        // The guard full of one-entry authors (an attacker with 4096 keys):
        // a quiet identity's new authorization evicts another unprotected
        // author's entry; the quiet identity's own earlier entry is newer
        // than the flood entries, so it is not the oldest victim.
        let guard = ReplayGuard::default();
        for n in 0..ReplayGuard::MAX_ENTRIES {
            assert!(guard.accept(&format!("id-{n}"), 1_000, 1_000, &format!("pk-{n}")));
        }
        // The quiet identity already holds one authorization from before
        // the flood; it must survive its own new authorization's eviction.
        assert!(guard.accept("quiet-old", 1_001, 1_001, "pk-quiet"));
        assert!(
            guard.accept("quiet-new", 1_002, 1_002, "pk-quiet"),
            "the quiet identity must be admitted at capacity"
        );
        assert!(
            !guard.accept("quiet-old", 1_002, 1_002, "pk-quiet"),
            "the quiet identity's earlier authorization must stay tracked"
        );
    }

    #[test]
    fn replay_guard_does_not_evict_a_capture_for_a_backdated_flood() {
        // A client can backdate its auth events by the full ±60 s window.
        // The eviction tie-break must use the guard's own presentation
        // order, not `created_at`/`expiry`: with the old "latest expiry"
        // rule a flood at created_at = now-60 made the victim the unique
        // latest expiry and evicted it on the first overflow.
        let guard = ReplayGuard::default();
        assert!(guard.accept_as("victim", 1_000, 1_000, "pk-victim", true));
        for n in 0..ReplayGuard::MAX_ENTRIES - 1 {
            assert!(guard.accept(&format!("flood-{n}"), 1_000, 940, &format!("pk-flood-{n}")));
        }
        assert!(guard.accept("extra", 1_002, 1_002, "pk-extra"));
        assert!(
            !guard.accept_as("victim", 1_002, 1_002, "pk-victim", true),
            "a backdated flood must not evict the capture"
        );
    }

    #[test]
    fn replay_guard_evicts_the_flood_before_a_pre_flood_capture() {
        // A fresh-key flood that overflows the guard must evict one of its
        // own fresh entries, not the older authorization a quiet identity
        // presented before the flood began: an attacker holding a captured
        // header would otherwise flip it back into a usable replay simply
        // by filling the guard (the previous oldest-first tie-break made
        // exactly that entry the victim).
        let guard = ReplayGuard::default();
        // The captured authorization, presented before the flood.
        assert!(guard.accept_as("victim", 1_000, 1_000, "pk-victim", true));
        // A fresh-key flood whose entries are all newer fills the guard.
        for n in 0..ReplayGuard::MAX_ENTRIES - 1 {
            assert!(guard.accept(
                &format!("flood-{n}"),
                1_000,
                1_001,
                &format!("pk-flood-{n}")
            ));
        }
        // The overflow admits the new key by evicting a flood entry...
        assert!(guard.accept("extra", 1_002, 1_002, "pk-extra"));
        // ...never the pre-flood capture: replaying it is still refused.
        assert!(
            !guard.accept_as("victim", 1_002, 1_002, "pk-victim", true),
            "a pre-flood capture must not be evicted by a fresh-key flood"
        );
    }

    #[test]
    fn replay_guard_protects_a_capture_presented_during_a_flood() {
        // The older tie-break evicted the newest non-requester, i.e. an
        // authorization presented while the flood was already running.
        // Protected entries are now never victims.
        let guard = ReplayGuard::default();
        for n in 0..ReplayGuard::MAX_ENTRIES - 1 {
            assert!(guard.accept(&format!("flood-{n}"), 1_000, 1_000, &format!("pk-{n}")));
        }
        assert!(guard.accept_as("victim", 1_001, 1_001, "pk-victim", true));
        // One more unknown-key request would have evicted the newest
        // non-requester under the old rule.
        assert!(guard.accept("extra", 1_002, 1_002, "pk-extra"));
        assert!(
            !guard.accept_as("victim", 1_002, 1_002, "pk-victim", true),
            "a capture presented during the flood must stay tracked"
        );
    }

    #[test]
    fn replay_guard_protects_a_multi_entry_management_identity() {
        // Two admin authorizations make the author "most prolific"; the old
        // count-first eviction removed the older one (the likely capture).
        let guard = ReplayGuard::default();
        for n in 0..ReplayGuard::MAX_ENTRIES - 2 {
            assert!(guard.accept(&format!("flood-{n}"), 1_000, 1_000, &format!("pk-{n}")));
        }
        assert!(guard.accept_as("admin-1", 1_000, 1_000, "pk-admin", true));
        assert!(guard.accept_as("admin-2", 1_000, 1_000, "pk-admin", true));
        assert!(guard.accept("extra", 1_002, 1_002, "pk-extra"));
        assert!(
            !guard.accept_as("admin-1", 1_002, 1_002, "pk-admin", true),
            "the older protected entry must not be evicted"
        );
        assert!(
            !guard.accept_as("admin-2", 1_002, 1_002, "pk-admin", true),
            "the newer protected entry must not be evicted"
        );
    }

    #[test]
    fn replay_guard_bounds_protected_entries_per_author() {
        // AUD-16: one grantee used to be able to fill all 4096 protected
        // slots with its own authorizations, locking every other manager
        // out for the 60 s window. Its own entries are now the only
        // protected eviction pool and are capped per author.
        let guard = ReplayGuard::default();
        let grantee = "pk-grantee";
        for n in 0..ReplayGuard::MAX_PROTECTED_PER_AUTHOR {
            assert!(guard.accept_as(&format!("g-{n}"), 1_000, 1_000, grantee, true));
        }
        // A different management identity is still admitted: the grantee
        // never occupied more than its quota.
        assert!(guard.accept_as("admin", 1_001, 1_001, "pk-admin", true));
        assert!(
            guard.seen.lock().unwrap().len() <= ReplayGuard::MAX_PROTECTED_PER_AUTHOR + 1,
            "one author must not fill the protected pool"
        );
        // The grantee may keep working: its next authorization evicts its
        // own oldest entry, not another author's capture.
        assert!(guard.accept_as("g-new", 1_002, 1_002, grantee, true));
        assert!(
            !guard.accept_as("g-new", 1_002, 1_002, grantee, true),
            "the newest entry stays tracked"
        );
        // The admin's entry survived the grantee's eviction.
        assert!(
            !guard.accept_as("admin", 1_002, 1_002, "pk-admin", true),
            "another author's protected capture must not be evicted"
        );
    }

    #[test]
    fn protected_quota_is_case_insensitive() {
        // H07: the same management key in upper/mixed case must not get a
        // fresh 64-entry quota; otherwise case variants fill the 4096 guard
        // and lock other managers out.
        let guard = ReplayGuard::default();
        let upper = "AA".repeat(32);
        let lower = "aa".repeat(32);
        for n in 0..ReplayGuard::MAX_PROTECTED_PER_AUTHOR {
            assert!(guard.accept_as(&format!("g-{n}"), 1_000, 1_000, &upper, true));
        }
        assert_eq!(
            guard.seen.lock().unwrap().len(),
            ReplayGuard::MAX_PROTECTED_PER_AUTHOR,
            "case variants must share the same per-author quota"
        );
        assert!(guard.accept_as("lower", 1_000, 1_000, &lower, true));
        assert_eq!(
            guard.seen.lock().unwrap().len(),
            ReplayGuard::MAX_PROTECTED_PER_AUTHOR,
            "the lowercase entry evicts the author's own oldest entry"
        );
        assert!(
            !guard.accept_as("lower", 1_000, 1_000, &lower, true),
            "the new entry stays tracked"
        );
    }

    #[test]
    fn replay_guard_fails_closed_when_every_entry_is_protected() {
        // Evicting a protected entry could make a capture replayable. If
        // the guard is full of protected entries, refuse the new
        // authorization instead (the caller returns 401; entries expire).
        let guard = ReplayGuard::default();
        for n in 0..ReplayGuard::MAX_ENTRIES {
            assert!(guard.accept_as(&format!("p-{n}"), 1_000, 1_000, &format!("pk-{n}"), true));
        }
        assert!(
            !guard.accept_as("new", 1_001, 1_001, "pk-new", true),
            "a new protected authorization must not evict another capture"
        );
        assert!(
            !guard.accept("u", 1_001, 1_001, "pk-u"),
            "an unprotected authorization cannot evict a protected capture either"
        );
        assert!(
            !guard.accept_as("p-0", 1_001, 1_001, "pk-0", true),
            "the existing protected entries stay tracked"
        );
    }
}
