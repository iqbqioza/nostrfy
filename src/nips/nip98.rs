//! NIP-98: HTTP Auth.
//!
//! Verifies NIP-98 HTTP auth events (`kind:27235` events sent in the
//! `Authorization: Nostr <base64 event>` header), shared by the NIP-86
//! management API and the NIP-29 LiveKit token endpoint.

use base64::Engine;
use secp256k1::Secp256k1;

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
    let (scheme, token) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("Nostr").then_some(token)
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
    secp: &Secp256k1<secp256k1::All>,
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
    if nip01::verify(&event, secp).is_err() {
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
/// authenticated event flood. Expired entries are pruned on every call,
/// and at capacity a new authorization is rejected (fail closed) instead
/// of evicting a live entry — evicting one would let a captured
/// authorization be replayed once the entry was dropped. The guard drains
/// by itself within a minute of the flood ending. This is process-local
/// replay protection; restarting clears the guard.
pub struct ReplayGuard {
    seen: std::sync::Mutex<std::collections::HashMap<String, u64>>,
    /// Unix time of the last capacity warning: `accept` runs for every
    /// authenticated request, so a flood that fills the guard must not log
    /// one line per rejected authorization.
    last_capacity_warning: std::sync::atomic::AtomicU64,
}

impl Default for ReplayGuard {
    fn default() -> Self {
        ReplayGuard {
            seen: std::sync::Mutex::new(std::collections::HashMap::new()),
            last_capacity_warning: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

impl ReplayGuard {
    /// Maximum authorizations tracked within one window.
    const MAX_ENTRIES: usize = 4096;
    /// Minimum seconds between capacity warnings.
    const WARNING_INTERVAL: u64 = 60;

    /// Records `id` (valid until the event stops verifying); returns
    /// `false` when it was already used (a replay) or when the guard is
    /// full. Expired entries are pruned first; a full guard of still-live
    /// authorizations rejects the new one instead of evicting a live entry.
    /// `valid_until` must cover the whole NIP-98 validity interval of the
    /// event: callers pass its `created_at` and the guard extends past the
    /// inclusive 60-second boundary, so a replay at the last valid second
    /// (or inside a future-dated event's extended window) is still refused.
    pub fn accept(&self, id: &str, now: u64, created_at: u64) -> bool {
        let valid_until = created_at.saturating_add(61);
        let mut seen = self.seen.lock().unwrap_or_else(|p| p.into_inner());
        seen.retain(|_, expiry| *expiry > now);
        if seen.contains_key(id) {
            return false;
        }
        if seen.len() >= Self::MAX_ENTRIES {
            // Drop the lock before logging: the warning must not stall the
            // other requests waiting on the guard.
            drop(seen);
            self.warn_capacity(now);
            return false;
        }
        seen.insert(id.to_string(), valid_until);
        true
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
                "NIP-98 replay guard is full ({} live authorizations): refusing new \
                 authorizations until entries expire",
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
        let secp = Secp256k1::new();
        let keypair = Keypair::from_seckey_slice(&secp, &[5u8; 32]).unwrap();
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
        ev.sig = secp.sign_schnorr_no_aux_rand(&id, &keypair).to_string();
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
        let secp = Secp256k1::new();
        let now = unix_now();
        let ev = signed_event(Some("POST"), "https://relay.example.com/", now);
        let check = |encoded: &str| {
            verify(encoded, None, &secp, false, None, "POST", |u| {
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
        let secp = Secp256k1::new();
        let now = unix_now();
        rt.block_on(async {
            // Correct method and url: accepted.
            let ev = signed_event(Some("POST"), "https://relay.example.com/", now);
            assert!(
                verify(&encode(&ev), None, &secp, false, None, "POST", |u| u
                    == "https://relay.example.com/",)
                .is_some()
            );
            // Wrong method: rejected (NIP-98 requirement 4).
            assert!(
                verify(&encode(&ev), None, &secp, false, None, "GET", |u| u
                    == "https://relay.example.com/",)
                .is_none()
            );
            // Missing method tag: rejected.
            let bare = signed_event(None, "https://relay.example.com/", now);
            assert!(
                verify(&encode(&bare), None, &secp, false, None, "POST", |u| u
                    == "https://relay.example.com/",)
                .is_none()
            );
        });
    }

    #[test]
    fn payload_tag_must_match_body_hash() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let secp = Secp256k1::new();
        let now = unix_now();
        let body = br#"{"method":"banpubkey","params":[]}"#;
        let want = payload_sha256_hex(body);
        let mut ev = signed_event(Some("POST"), "https://relay.example.com/", now);
        ev.tags.push(vec![PAYLOAD_TAG.into(), want.clone()]);
        // Re-sign after adding the tag (the id commits to the tags).
        ev.id = compute_id(&ev);
        let id = ev.id_bytes().unwrap();
        let keypair = Keypair::from_seckey_slice(&secp, &[5u8; 32]).unwrap();
        ev.sig = secp.sign_schnorr_no_aux_rand(&id, &keypair).to_string();
        let encoded = encode(&ev);
        rt.block_on(async {
            // Matching hash: accepted.
            assert!(
                verify(&encoded, None, &secp, true, Some(&want), "POST", |u| u
                    == "https://relay.example.com/",)
                .is_some()
            );
            // A captured authorization replayed against another body: rejected.
            let other = payload_sha256_hex(br#"{"method":"allowpubkey","params":[]}"#);
            assert!(
                verify(&encoded, None, &secp, true, Some(&other), "POST", |u| u
                    == "https://relay.example.com/",)
                .is_none()
            );
            // Missing tag when required: rejected.
            let bare = signed_event(Some("POST"), "https://relay.example.com/", now);
            assert!(
                verify(
                    &encode(&bare),
                    None,
                    &secp,
                    true,
                    Some(&want),
                    "POST",
                    |u| u == "https://relay.example.com/",
                )
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
        assert!(guard.accept("aa", 1_000, 1_000));
        assert!(!guard.accept("aa", 1_000, 1_000), "the same id is a replay");
        assert!(!guard.accept("aa", 1_059, 1_059), "still within the window");
        // After the 60-second window the entry expires.
        assert!(guard.accept("aa", 1_061, 1_061));
        // Distinct ids are independent.
        assert!(guard.accept("bb", 1_061, 1_061));
    }

    #[test]
    fn replay_guard_covers_the_full_validity_window() {
        // The guard is keyed to the event's validity interval, not the
        // first-accept time: a replay at the last valid second — or inside
        // a future-dated event's extended window — is still refused.
        let guard = ReplayGuard::default();
        assert!(guard.accept("aa", 1_000, 1_000));
        assert!(
            !guard.accept("aa", 1_060, 1_060),
            "the inclusive boundary second is still guarded"
        );
        assert!(guard.accept("aa", 1_061, 1_061));
        // Future-dated event (created_at ahead): valid until
        // created_at + 60, guarded that long.
        assert!(guard.accept("bb", 1_000, 1_060));
        assert!(
            !guard.accept("bb", 1_061, 1_061),
            "a future-dated auth stays guarded past first-accept + 60"
        );
        assert!(
            !guard.accept("bb", 1_120, 1_120),
            "still within created_at + 60"
        );
        assert!(guard.accept("bb", 1_121, 1_121));
    }

    #[test]
    fn replay_guard_rejects_new_entries_when_full_instead_of_evicting() {
        let guard = ReplayGuard::default();
        for n in 0..ReplayGuard::MAX_ENTRIES {
            assert!(guard.accept(&format!("id-{n}"), 1_000, 1_000));
        }
        // The guard is full of live entries: the new authorization is
        // refused (fail closed) instead of evicting a live one...
        assert!(
            !guard.accept("new", 1_001, 1_001),
            "a full guard must reject the new authorization"
        );
        // ...and no live entry was dropped to make room: the oldest and the
        // newest authorizations are both still tracked as replays.
        assert!(
            !guard.accept("id-0", 1_001, 1_001),
            "the oldest live entry must not be evicted"
        );
        assert!(
            !guard.accept("id-4095", 1_001, 1_001),
            "the newest entry remains protected from replay"
        );
        // Once the 60-second window passes, all entries expire and the guard
        // drains by itself.
        assert!(
            guard.accept("new", 1_061, 1_061),
            "acceptance resumes after the live entries expire"
        );
    }
}
