//! NIP-19: bech32-encoded entities.
//!
//! Decodes `npub1`, `note1`, `nevent1`, and `naddr1` strings into their
//! binary representations.  The bech32m codec is implemented from scratch
//! to avoid adding an external dependency.

use anyhow::{Result, anyhow};

// ---------------------------------------------------------------------------
// bech32 / bech32m codec  (BIP-173 / BIP-350)
// ---------------------------------------------------------------------------

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Generator values shared by bech32 and bech32m.
const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

fn polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    for &v in values {
        let top = chk >> 25;
        chk = (chk & 0x1ffffff) << 5 ^ v as u32;
        for (i, &g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &[u8]) -> Vec<u8> {
    let mut exp = Vec::with_capacity(hrp.len() * 2 + 1);
    for &b in hrp {
        exp.push(b >> 5);
    }
    exp.push(0);
    for &b in hrp {
        exp.push(b & 31);
    }
    exp
}

/// Verify the bech32/bech32m checksum.
///
/// `data` must include the 6-element checksum at the end.
/// Returns `true` for bech32m, `false` for bech32.
fn verify_checksum(hrp: &[u8], data: &[u8]) -> Option<bool> {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    let poly = polymod(&values);
    if poly == 1 {
        Some(false) // bech32
    } else if poly == 0x2bc830a3 {
        Some(true) // bech32m
    } else {
        None
    }
}

/// Whether `s` is a complete `hrp`-prefixed bech32 string with a
/// valid checksum (BIP-173). Case-insensitive (BIP-173 permits all-lowercase
/// or all-uppercase) but a *mixed-case* string is invalid bech32 and
/// returns `false`, so the nsec-leak detector never mistakes a mixed-case
/// look-alike for a real secret key. Only legacy bech32 (constant `1`) is
/// accepted: a bech32m-valid look-alike is not a spendable `nsec` key and
/// must not mute the event.
pub(crate) fn bech32_checksum_valid(hrp: &str, s: &str) -> bool {
    let is_lower = !s.chars().any(|c| c.is_ascii_uppercase());
    let is_upper = !s.chars().any(|c| c.is_ascii_lowercase());
    if !is_lower && !is_upper {
        return false;
    }
    let s = s.to_lowercase();
    let Some(body) = s.strip_prefix(hrp).and_then(|r| r.strip_prefix('1')) else {
        return false;
    };
    if body.len() < 6 {
        return false;
    }
    let data: Option<Vec<u8>> = body
        .chars()
        .map(|ch| {
            if !ch.is_ascii() {
                return None;
            }
            CHARSET.iter().position(|&c| c == ch as u8).map(|p| p as u8)
        })
        .collect();
    let Some(data) = data else {
        return false;
    };
    verify_checksum(hrp.as_bytes(), &data) == Some(false)
}

/// Create a bech32 checksum for `data` (without checksum). NIP-19
/// mandates legacy bech32 (constant `1`) for its entities — the spec's
/// own example strings validate with `1`, not the bech32m constant — so
/// the encoder emits the canonical form mainstream decoders accept. The
/// decoder still accepts both constants.
fn create_checksum(hrp: &[u8], data: &[u8]) -> Vec<u8> {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0u8; 6]);
    let poly = polymod(&values) ^ 1; // bech32 (BIP-173)
    (0..6)
        .map(|i| ((poly >> (5 * (5 - i))) & 31) as u8)
        .collect()
}

/// Legacy bech32m checksum, used only for the Blossom storage paths that
/// predate the canonical encoder (existing blob directories keep the old
/// bech32m npub names).
fn create_checksum_m(hrp: &[u8], data: &[u8]) -> Vec<u8> {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0u8; 6]);
    let poly = polymod(&values) ^ 0x2bc830a3; // bech32m (BIP-350)
    (0..6)
        .map(|i| ((poly >> (5 * (5 - i))) & 31) as u8)
        .collect()
}

/// Decode a bech32/bech32m string into HRP and 5-bit data.
fn bech32_decode(input: &str) -> Result<(String, Vec<u8>, bool)> {
    // NIP-19: bech32-formatted strings SHOULD be limited to 5000 characters
    // — beyond that the string is a DoS vector, not a NIP-19 entity.
    if input.chars().count() > 5000 {
        return Err(anyhow!("bech32 string exceeds the 5000-character limit"));
    }
    // BIP-173: input must be ASCII and either all-lowercase or
    // all-uppercase, never mixed. Uppercase input is decoded as its
    // lowercase form (the charset, separator and checksum are
    // case-insensitive). The checks are byte-wise: bech32 is ASCII-only, so
    // Unicode case conversion (which allocates and can expand characters)
    // must not be used here.
    if !input.is_ascii() {
        return Err(anyhow!("invalid bech32 character '?'"));
    }
    let has_lower = input.bytes().any(|b| b.is_ascii_lowercase());
    let has_upper = input.bytes().any(|b| b.is_ascii_uppercase());
    if has_lower && has_upper {
        return Err(anyhow!("invalid bech32 character '?'"));
    }
    let lower;
    let normalized: &str = if has_upper {
        lower = input.to_ascii_lowercase();
        &lower
    } else {
        input
    };

    // Find the last '1' separator.
    let sep_pos = normalized
        .rfind('1')
        .ok_or_else(|| anyhow!("missing bech32 separator '1'"))?;

    let hrp = &normalized[..sep_pos];
    if hrp.is_empty() {
        return Err(anyhow!("empty human-readable part"));
    }

    let data_part = &normalized[sep_pos + 1..];
    if data_part.is_empty() {
        return Err(anyhow!("empty data part"));
    }

    // Validate characters. BIP-173 requires ASCII only: a non-ASCII char
    // must not be silently truncated to its low byte (which could pass the
    // charset check as a look-alike).
    for ch in data_part.chars() {
        if !ch.is_ascii() || !CHARSET.contains(&(ch as u8)) {
            return Err(anyhow!("invalid bech32 character '{ch}'"));
        }
    }

    let data_5bit: Vec<u8> = data_part
        .chars()
        .map(|c| CHARSET.iter().position(|&ch| ch == c as u8).unwrap() as u8)
        .collect();

    if data_5bit.len() < 6 {
        return Err(anyhow!("invalid bech32m checksum"));
    }

    // Verify checksum; prefer bech32m.
    let is_bech32m = match verify_checksum(hrp.as_bytes(), &data_5bit) {
        Some(v) => v,
        None => return Err(anyhow!("invalid bech32m checksum")),
    };

    let payload = &data_5bit[..data_5bit.len() - 6];
    Ok((hrp.to_string(), payload.to_vec(), is_bech32m))
}

/// Expand 5-bit groups into 8-bit bytes (BIP-173 convert_bits).
fn convert_bits(data: &[u8], from_bits: u32, to_bits: u32, pad: bool) -> Result<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();
    let maxv = (1u32 << to_bits) - 1;

    for &value in data {
        if (value as u32 >> from_bits) != 0 {
            return Err(anyhow!("invalid data in bech32 encoding"));
        }
        acc = (acc << from_bits) | value as u32;
        bits += from_bits;
        while bits >= to_bits {
            bits -= to_bits;
            out.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to_bits - bits)) & maxv) as u8);
        }
    } else if bits >= from_bits || ((acc << (to_bits - bits)) & maxv) != 0 {
        return Err(anyhow!("invalid data in bech32 encoding"));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// NIP-19 entity types
// ---------------------------------------------------------------------------

/// A decoded NIP-19 entity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Nip19Entity {
    /// `npub1...` — a 32-byte public key.
    Pubkey([u8; 32]),
    /// `note1...` — a 32-byte event ID (non-witness).
    Note([u8; 32]),
    /// `nevent1...` — an event ID with optional relays and author hint.
    Event {
        id: [u8; 32],
        relays: Vec<String>,
        author: Option<[u8; 32]>,
        kind: Option<u64>,
    },
    /// `naddr1...` — a parameterized replaceable event address.
    Addr {
        kind: u64,
        pubkey: [u8; 32],
        d_tag: String,
        relays: Vec<String>,
    },
}

// ---------------------------------------------------------------------------
// NIP-19 TLV parsing
// ---------------------------------------------------------------------------

/// NIP-19 TLV types (19.md): `0` = special (nprofile pubkey / nevent id /
/// naddr `d` tag), `1` = relay, `2` = author (pubkey), `3` = kind (32-bit
/// big-endian). Earlier revisions used non-standard numbers here, which made
/// every standard `nevent1`/`naddr1` undecodable.
const TLV_SPECIAL: u8 = 0;
const TLV_RELAY: u8 = 1;
const TLV_AUTHOR: u8 = 2;
const TLV_KIND: u8 = 3;

fn parse_tlv(data: &[u8]) -> Result<Vec<(u8, Vec<u8>)>> {
    let mut items = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        if pos + 2 > data.len() {
            return Err(anyhow!("invalid TLV structure"));
        }
        let tlv_type = data[pos];
        // NIP-19: `T` and `L` are one byte each. A two-byte length made
        // every standard `nevent1`/`naddr1` string undecodable.
        let len = data[pos + 1] as usize;
        pos += 2;
        if pos + len > data.len() {
            return Err(anyhow!("invalid TLV structure"));
        }
        items.push((tlv_type, data[pos..pos + len].to_vec()));
        pos += len;
    }
    Ok(items)
}

/// Parse a NIP-19 bech32m string into an entity.
pub fn parse_nip19(input: &str) -> Result<Nip19Entity> {
    let (hrp, data_5bit, _is_bech32m) = bech32_decode(input)?;
    let data = convert_bits(&data_5bit, 5, 8, false)?;

    match hrp.as_str() {
        "npub" => {
            if data.len() != 32 {
                return Err(anyhow!("invalid length: expected 32, got {}", data.len()));
            }
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&data);
            Ok(Nip19Entity::Pubkey(pk))
        }
        "note" => {
            if data.len() != 32 {
                return Err(anyhow!("invalid length: expected 32, got {}", data.len()));
            }
            let mut id = [0u8; 32];
            id.copy_from_slice(&data);
            Ok(Nip19Entity::Note(id))
        }
        "nevent" => {
            let tlv = parse_tlv(&data)?;
            let mut id = None;
            let mut relays = Vec::new();
            let mut author = None;
            let mut kind = None;
            for (tlv_type, value) in &tlv {
                match *tlv_type {
                    TLV_SPECIAL if value.len() == 32 => {
                        let mut buf = [0u8; 32];
                        buf.copy_from_slice(value);
                        id = Some(buf);
                    }
                    TLV_RELAY => {
                        if let Ok(s) = std::str::from_utf8(value) {
                            relays.push(s.to_string());
                        }
                    }
                    TLV_AUTHOR if value.len() == 32 => {
                        let mut buf = [0u8; 32];
                        buf.copy_from_slice(value);
                        author = Some(buf);
                    }
                    TLV_KIND if value.len() == 4 => {
                        let k = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                        kind = Some(k as u64);
                    }
                    _ => {}
                }
            }
            let id = id.ok_or_else(|| anyhow!("invalid TLV structure"))?;
            Ok(Nip19Entity::Event {
                id,
                relays,
                author,
                kind,
            })
        }
        "naddr" => {
            let tlv = parse_tlv(&data)?;
            let mut kind = None;
            let mut pubkey = None;
            let mut d_tag = None;
            let mut relays = Vec::new();
            for (tlv_type, value) in &tlv {
                match *tlv_type {
                    TLV_KIND if value.len() == 4 => {
                        let k = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                        kind = Some(k as u64);
                    }
                    TLV_AUTHOR if value.len() == 32 => {
                        let mut buf = [0u8; 32];
                        buf.copy_from_slice(value);
                        pubkey = Some(buf);
                    }
                    TLV_SPECIAL => {
                        // A present-but-invalid d tag must not silently
                        // resolve to the `d=""` address (a different event).
                        match std::str::from_utf8(value) {
                            Ok(s) => d_tag = Some(s.to_string()),
                            Err(_) => return Err(anyhow!("invalid TLV structure")),
                        }
                    }
                    TLV_RELAY => {
                        if let Ok(s) = std::str::from_utf8(value) {
                            relays.push(s.to_string());
                        }
                    }
                    _ => {}
                }
            }
            let kind = kind.ok_or_else(|| anyhow!("invalid TLV structure"))?;
            let pubkey = pubkey.ok_or_else(|| anyhow!("invalid TLV structure"))?;
            let d_tag = d_tag.unwrap_or_default();
            Ok(Nip19Entity::Addr {
                kind,
                pubkey,
                d_tag,
                relays,
            })
        }
        // NIP-19 `nprofile1...`: TLV with type 0 = 32-byte pubkey and
        // optional type 1 relays. Resolves to the author like `npub1...`
        // so REST identifiers and inbox/outbox filters accept it.
        "nprofile" => {
            let tlv = parse_tlv(&data)?;
            let mut pubkey = None;
            for (tlv_type, value) in &tlv {
                if *tlv_type == TLV_SPECIAL && value.len() == 32 {
                    let mut buf = [0u8; 32];
                    buf.copy_from_slice(value);
                    pubkey = Some(buf);
                }
            }
            let pubkey = pubkey.ok_or_else(|| anyhow!("invalid TLV structure"))?;
            Ok(Nip19Entity::Pubkey(pubkey))
        }
        other => Err(anyhow!("unknown NIP-19 prefix '{other}'")),
    }
}

/// Encode 8-bit bytes into bech32 with the given HRP (the NIP-19
/// canonical form: legacy bech32 constant).
pub(crate) fn bech32_encode(hrp: &str, data: &[u8]) -> Result<String> {
    let data_5bit = convert_bits(data, 8, 5, true)?;
    let checksum = create_checksum(hrp.as_bytes(), &data_5bit);
    let mut combined = data_5bit;
    combined.extend_from_slice(&checksum);
    let encoded: String = combined
        .iter()
        .map(|&b| CHARSET[b as usize] as char)
        .collect();
    Ok(format!("{hrp}1{encoded}"))
}

/// Encode into bech32m — kept only for the Blossom storage paths that
/// used it before the encoder became canonical (the legacy directory
/// names must still be reproducible for the migration fallback).
pub(crate) fn bech32m_encode(hrp: &str, data: &[u8]) -> Result<String> {
    let data_5bit = convert_bits(data, 8, 5, true)?;
    let checksum = create_checksum_m(hrp.as_bytes(), &data_5bit);
    let mut combined = data_5bit;
    combined.extend_from_slice(&checksum);
    let encoded: String = combined
        .iter()
        .map(|&b| CHARSET[b as usize] as char)
        .collect();
    Ok(format!("{hrp}1{encoded}"))
}

/// Convert a NIP-19 entity to its hex string representation.
#[allow(dead_code)]
pub fn nip19_to_hex(entity: &Nip19Entity) -> Nip19Hex {
    match entity {
        Nip19Entity::Pubkey(pk) => Nip19Hex::Pubkey(hex::encode(pk)),
        Nip19Entity::Note(id) => Nip19Hex::EventId(hex::encode(id)),
        Nip19Entity::Event { id, .. } => Nip19Hex::EventId(hex::encode(id)),
        Nip19Entity::Addr {
            kind,
            pubkey,
            d_tag,
            ..
        } => Nip19Hex::Addr {
            kind: *kind,
            pubkey: hex::encode(pubkey),
            d_tag: d_tag.clone(),
        },
    }
}

#[allow(dead_code)]
pub enum Nip19Hex {
    Pubkey(String),
    EventId(String),
    Addr {
        kind: u64,
        pubkey: String,
        d_tag: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::fuzz_tests::Rng;

    #[test]
    fn overlong_bech32_strings_are_rejected() {
        // NIP-19: "Bech32-formatted strings SHOULD be limited in size to
        // 5000 characters" — beyond that the string is not a NIP-19 entity.
        let mut long = "npub1".to_string();
        while long.chars().count() < 6000 {
            long.push('q');
        }
        let err = parse_nip19(&long).unwrap_err();
        assert_eq!(
            err.to_string(),
            "bech32 string exceeds the 5000-character limit"
        );
        // The boundary itself is accepted for parsing (and then fails the
        // checksum, which is the correct next error for a fabricated string).
        let mut edge = "npub1".to_string();
        while edge.chars().count() < 5000 {
            edge.push('q');
        }
        assert_ne!(
            parse_nip19(&edge).unwrap_err().to_string(),
            "bech32 string exceeds the 5000-character limit",
            "exactly 5000 characters is still within the limit"
        );
    }

    #[test]
    fn bech32m_roundtrip() {
        // npub1 for a known pubkey
        let hex_pk = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
        let pk_bytes = hex::decode(hex_pk).unwrap();
        let encoded = bech32_encode("npub", &pk_bytes).unwrap();

        let entity = parse_nip19(&encoded).unwrap();
        match entity {
            Nip19Entity::Pubkey(pk) => {
                assert_eq!(hex::encode(pk), hex_pk);
            }
            _ => panic!("expected Pubkey"),
        }
    }

    #[test]
    fn encoder_emits_the_spec_canonical_bech32_checksum() {
        // NIP-19 mandates bech32-(not-m) for the entities; the spec's own
        // example npub for this pubkey validates with the legacy constant.
        let hex_pk = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
        let pk_bytes = hex::decode(hex_pk).unwrap();
        let encoded = bech32_encode("npub", &pk_bytes).unwrap();
        // The spec example string (legacy bech32 checksum):
        // npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6
        assert_eq!(
            encoded,
            "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6"
        );
        // The old bech32m form differs and must NOT be emitted.
        assert_ne!(
            encoded,
            "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkws3w8ktc"
        );
        // The legacy bech32m encoder is still available for the storage
        // path fallback.
        let legacy = bech32m_encode("npub", &pk_bytes).unwrap();
        assert_eq!(
            legacy,
            "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkws3w8ktc"
        );
    }

    #[test]
    fn parse_known_npub() {
        // bech32m-encoded npub for pubkey 3bf0c63f...
        let result = parse_nip19("npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkws3w8ktc");
        assert!(result.is_ok(), "failed to parse npub: {:?}", result.err());
    }

    #[test]
    fn uppercase_bech32_is_accepted() {
        // BIP-173: all-uppercase input is valid; it decodes to the same
        // pubkey as its lowercase form.
        let hex_pk = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
        let npub = "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkws3w8ktc";
        match parse_nip19(&npub.to_uppercase()).unwrap() {
            Nip19Entity::Pubkey(pk) => assert_eq!(hex::encode(pk), hex_pk),
            _ => panic!("expected Pubkey"),
        }
    }

    #[test]
    fn invalid_checksum() {
        let result = parse_nip19("npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkws3w8kt");
        assert!(result.is_err());
    }

    #[test]
    fn rejects_non_ascii_lookalikes() {
        let base = "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkws3w8ktc";
        assert!(parse_nip19(base).is_ok());
        // U+0138 (ĸ) has low byte 0x38 = '8': a truncating cast used to let
        // it pass the charset check as a look-alike. BIP-173 requires ASCII.
        let lookalike = base.replace('8', "\u{0138}");
        assert!(parse_nip19(&lookalike).is_err());
    }

    #[test]
    fn unknown_prefix() {
        // nsec1 has a valid bech32m checksum but is not a known NIP-19 prefix.
        // Encode a valid nsec1 string to ensure it decodes.
        let data = [0x01u8; 32];
        let encoded = bech32_encode("nsec", &data).unwrap();
        assert!(encoded.starts_with("nsec1"));
        let result = parse_nip19(&encoded);
        assert_eq!(
            result.unwrap_err().to_string(),
            "unknown NIP-19 prefix 'nsec'"
        );
    }

    #[test]
    fn tlv_lengths_are_one_byte() {
        // The TLV payload of the `nprofile` vector in the NIP-19 spec
        // (pubkey 3bf0c63f..., relays wss://r.x.com and
        // wss://djbas.sadkb.com). `T` and `L` are one byte each.
        let data = hex::decode(
            "00203bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d\
             010d7773733a2f2f722e782e636f6d\
             01157773733a2f2f646a6261732e7361646b622e636f6d",
        )
        .unwrap();
        let items = parse_tlv(&data).unwrap();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].0, TLV_SPECIAL);
        assert_eq!(
            hex::encode(&items[0].1),
            "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d"
        );
        assert_eq!(items[1], (TLV_RELAY, b"wss://r.x.com".to_vec()));
        assert_eq!(items[2], (TLV_RELAY, b"wss://djbas.sadkb.com".to_vec()));
    }

    #[test]
    fn nevent_roundtrip() {
        let id = [0x42u8; 32];
        let entity = Nip19Entity::Event {
            id,
            relays: vec!["wss://relay.example.com".to_string()],
            author: None,
            kind: None,
        };
        // Encode with the standard TLV types: 0 = special (event id),
        // 1 = relay.
        let mut data = Vec::new();
        data.push(TLV_SPECIAL);
        data.push(32);
        data.extend_from_slice(&id);
        let relay = b"wss://relay.example.com";
        data.push(TLV_RELAY);
        data.push(relay.len() as u8);
        data.extend_from_slice(relay);

        let encoded = bech32_encode("nevent", &data).unwrap();
        let parsed = parse_nip19(&encoded).unwrap();
        assert_eq!(parsed, entity);
    }

    #[test]
    fn naddr_roundtrip_with_standard_types() {
        // A standard naddr: d-tag at 0, relay at 1, author pubkey at 2, kind
        // at 3.
        let mut data = Vec::new();
        let d = b"post-1";
        data.push(TLV_SPECIAL);
        data.push(d.len() as u8);
        data.extend_from_slice(d);
        let relay = b"wss://relay.example.com";
        data.push(TLV_RELAY);
        data.push(relay.len() as u8);
        data.extend_from_slice(relay);
        data.push(TLV_AUTHOR);
        data.push(32);
        data.extend_from_slice(&[0x11u8; 32]);
        data.push(TLV_KIND);
        data.push(4);
        data.extend_from_slice(&30023u32.to_be_bytes());

        let encoded = bech32_encode("naddr", &data).unwrap();
        let parsed = parse_nip19(&encoded).unwrap();
        assert_eq!(
            parsed,
            Nip19Entity::Addr {
                kind: 30023,
                pubkey: [0x11u8; 32],
                d_tag: "post-1".to_string(),
                relays: vec!["wss://relay.example.com".to_string()],
            }
        );
    }

    #[test]
    fn nevent_with_author_hint_parses_id_and_author_separately() {
        // A standard nevent carrying both the id (type 0) and the optional
        // author pubkey (type 2) must not confuse the author for the id.
        let id = [0x42u8; 32];
        let author = [0x77u8; 32];
        let mut data = Vec::new();
        data.push(TLV_SPECIAL);
        data.push(32);
        data.extend_from_slice(&id);
        data.push(TLV_AUTHOR);
        data.push(32);
        data.extend_from_slice(&author);
        data.push(TLV_KIND);
        data.push(4);
        data.extend_from_slice(&7u32.to_be_bytes());

        let encoded = bech32_encode("nevent", &data).unwrap();
        match parse_nip19(&encoded).unwrap() {
            Nip19Entity::Event {
                id: got_id,
                author: got_author,
                kind,
                ..
            } => {
                assert_eq!(got_id, id, "id must come from the type-0 TLV");
                assert_eq!(
                    got_author,
                    Some(author),
                    "author must come from the type-2 TLV"
                );
                assert_eq!(kind, Some(7));
            }
            _ => panic!("expected event"),
        }
    }

    #[test]
    fn decodes_standard_vectors() {
        // The npub from the NIP-19 spec.
        let npub =
            parse_nip19("npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6").unwrap();
        match npub {
            Nip19Entity::Pubkey(pk) => {
                assert_eq!(
                    hex::encode(pk),
                    "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d"
                );
            }
            _ => panic!("expected pubkey"),
        }
        // A standard nevent (id at TLV type 0) must decode, even though the
        // old code expected the id at type 2.
        let mut data = Vec::new();
        data.push(TLV_SPECIAL);
        data.push(32);
        data.extend_from_slice(&[0x42u8; 32]);
        data.push(TLV_KIND);
        data.push(4);
        data.extend_from_slice(&1u32.to_be_bytes());
        let encoded = bech32_encode("nevent", &data).unwrap();
        match parse_nip19(&encoded).unwrap() {
            Nip19Entity::Event { id, kind, .. } => {
                assert_eq!(id, [0x42u8; 32]);
                assert_eq!(kind, Some(1));
            }
            _ => panic!("expected event"),
        }
        // A standard naddr (d at type 0, author at type 2) must decode.
        let mut data = Vec::new();
        let d = b"";
        data.push(TLV_SPECIAL);
        data.push(d.len() as u8);
        data.extend_from_slice(d);
        data.push(TLV_AUTHOR);
        data.push(32);
        data.extend_from_slice(&[0x22u8; 32]);
        data.push(TLV_KIND);
        data.push(4);
        data.extend_from_slice(&0u32.to_be_bytes());
        let encoded = bech32_encode("naddr", &data).unwrap();
        match parse_nip19(&encoded).unwrap() {
            Nip19Entity::Addr {
                kind,
                pubkey,
                d_tag,
                ..
            } => {
                assert_eq!(kind, 0);
                assert_eq!(pubkey, [0x22u8; 32]);
                assert_eq!(d_tag, "");
            }
            _ => panic!("expected addr"),
        }
    }

    // ----- deterministic fuzzing (see crate::fuzz_tests) -----

    /// A TLV item: one type byte, one length byte, the value.
    fn push_tlv(data: &mut Vec<u8>, tlv_type: u8, value: &[u8]) {
        assert!(value.len() <= u8::MAX as usize);
        data.push(tlv_type);
        data.push(value.len() as u8);
        data.extend_from_slice(value);
    }

    #[test]
    fn fuzz_parse_nip19_never_panics_on_random_strings() {
        // A charset mixing valid bech32 characters with the shapes that
        // make the decoder branch: separators, mixed case, non-ASCII,
        // whitespace.
        const ALPHABET: &[char] = &[
            'q', 'p', 'z', '1', 'n', 's', 'e', 'c', '0', '2', 'b', 'u', 't', 'N', 'P', 'U', 'B',
            ':', '/', '.', '-', '_', 'é', '日', '𝄞', '\n', '\t', '"', '\\',
        ];
        let mut rng = Rng::new(0x5eed_19a0);
        for _ in 0..20_000 {
            let len = rng.below(64);
            let text: String = (0..len)
                .map(|_| ALPHABET[rng.below(ALPHABET.len())])
                .collect();
            let _ = parse_nip19(&text);
        }
        // Random bytes decoded as UTF-8 (lossy, so invalid sequences become
        // replacement characters) hit the same entry point.
        let mut bytes = [0u8; 48];
        for _ in 0..5_000 {
            let len = rng.below(bytes.len() + 1);
            rng.fill(&mut bytes[..len]);
            let _ = parse_nip19(&String::from_utf8_lossy(&bytes[..len]));
        }
    }

    #[test]
    fn fuzz_nip19_roundtrips_random_entities() {
        let mut rng = Rng::new(0x5eed_19b0);
        for _ in 0..400 {
            let mut raw = [0u8; 32];
            rng.fill(&mut raw);

            // npub and note: 32 random bytes each.
            let npub = bech32_encode("npub", &raw).unwrap();
            assert_eq!(parse_nip19(&npub).unwrap(), Nip19Entity::Pubkey(raw));
            let note = bech32_encode("note", &raw).unwrap();
            assert_eq!(parse_nip19(&note).unwrap(), Nip19Entity::Note(raw));

            // nprofile: special pubkey plus random relays (which decode to
            // the pubkey, like npub).
            let mut tlv = Vec::new();
            push_tlv(&mut tlv, TLV_SPECIAL, &raw);
            for _ in 0..rng.below(3) {
                let relay = format!("wss://{}.example", rng.hex(8));
                push_tlv(&mut tlv, TLV_RELAY, relay.as_bytes());
            }
            let nprofile = bech32_encode("nprofile", &tlv).unwrap();
            assert_eq!(parse_nip19(&nprofile).unwrap(), Nip19Entity::Pubkey(raw));

            // nevent: id plus optional relays, author hint and kind.
            let mut id = [0u8; 32];
            rng.fill(&mut id);
            let mut tlv = Vec::new();
            push_tlv(&mut tlv, TLV_SPECIAL, &id);
            let mut relays = Vec::new();
            for _ in 0..rng.below(3) {
                let relay = format!("wss://{}.example", rng.hex(8));
                push_tlv(&mut tlv, TLV_RELAY, relay.as_bytes());
                relays.push(relay);
            }
            let mut author = None;
            if rng.bool() {
                let mut pk = [0u8; 32];
                rng.fill(&mut pk);
                push_tlv(&mut tlv, TLV_AUTHOR, &pk);
                author = Some(pk);
            }
            let mut kind = None;
            if rng.bool() {
                let k = rng.next_u64() as u32;
                push_tlv(&mut tlv, TLV_KIND, &k.to_be_bytes());
                kind = Some(k as u64);
            }
            let nevent = bech32_encode("nevent", &tlv).unwrap();
            assert_eq!(
                parse_nip19(&nevent).unwrap(),
                Nip19Entity::Event {
                    id,
                    relays,
                    author,
                    kind,
                }
            );

            // naddr: required kind and pubkey, a random d tag and optional
            // relays.
            let mut pubkey = [0u8; 32];
            rng.fill(&mut pubkey);
            let d_tag = format!("post-{}", rng.hex(6));
            let k = rng.next_u64() as u32;
            let mut tlv = Vec::new();
            push_tlv(&mut tlv, TLV_SPECIAL, d_tag.as_bytes());
            push_tlv(&mut tlv, TLV_AUTHOR, &pubkey);
            push_tlv(&mut tlv, TLV_KIND, &k.to_be_bytes());
            let mut relays = Vec::new();
            for _ in 0..rng.below(3) {
                let relay = format!("wss://{}.example", rng.hex(8));
                push_tlv(&mut tlv, TLV_RELAY, relay.as_bytes());
                relays.push(relay);
            }
            let naddr = bech32_encode("naddr", &tlv).unwrap();
            assert_eq!(
                parse_nip19(&naddr).unwrap(),
                Nip19Entity::Addr {
                    kind: k as u64,
                    pubkey,
                    d_tag,
                    relays,
                }
            );
        }
    }

    #[test]
    fn fuzz_nip19_tlv_payloads_never_panic() {
        // Random TLV bytes (arbitrary types, lengths, truncations) wrapped
        // in a valid bech32 envelope for every structured prefix.
        let mut rng = Rng::new(0x5eed_19c0);
        let mut payload = [0u8; 64];
        for _ in 0..5_000 {
            let len = rng.below(payload.len() + 1);
            rng.fill(&mut payload[..len]);
            for hrp in ["nevent", "naddr", "nprofile"] {
                let encoded = bech32_encode(hrp, &payload[..len]).unwrap();
                let _ = parse_nip19(&encoded);
            }
        }
    }
}
