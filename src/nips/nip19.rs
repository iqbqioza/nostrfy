//! NIP-19: bech32-encoded entities.
//!
//! Decodes `npub1`, `note1`, `nevent1`, and `naddr1` strings into their
//! binary representations.  The bech32m codec is implemented from scratch
//! to avoid adding an external dependency.

use std::fmt;

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

/// Whether `s` is a complete `hrp`-prefixed bech32/bech32m string with a
/// valid checksum (BIP-173). Case-insensitive (BIP-173 permits all-lowercase
/// or all-uppercase) but a *mixed-case* string is invalid bech32 and
/// returns `false`, so the nsec-leak detector never mistakes a mixed-case
/// look-alike for a real secret key.
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
    verify_checksum(hrp.as_bytes(), &data).is_some()
}

/// Create a bech32m checksum for `data` (without checksum).
fn create_checksum(hrp: &[u8], data: &[u8]) -> Vec<u8> {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0u8; 6]);
    let poly = polymod(&values) ^ 0x2bc830a3; // bech32m
    (0..6)
        .map(|i| ((poly >> (5 * (5 - i))) & 31) as u8)
        .collect()
}

/// Decode a bech32/bech32m string into HRP and 5-bit data.
fn bech32_decode(input: &str) -> Result<(String, Vec<u8>, bool), Bech32Error> {
    // Must be lowercase or uppercase, not mixed.
    let input_lower = input.to_lowercase();
    let input_upper = input.to_uppercase();
    // BIP-173: all-uppercase input is valid — decode it as its lowercase
    // form (the charset, separator and checksum are case-insensitive).
    if input != input_lower && input != input_upper {
        return Err(Bech32Error::InvalidChar('?'));
    }
    let normalized: &str = &input_lower;

    // Find the last '1' separator.
    let sep_pos = normalized.rfind('1').ok_or(Bech32Error::MissingSeparator)?;

    let hrp = &normalized[..sep_pos];
    if hrp.is_empty() {
        return Err(Bech32Error::EmptyHrp);
    }

    let data_part = &normalized[sep_pos + 1..];
    if data_part.is_empty() {
        return Err(Bech32Error::EmptyData);
    }

    // Validate characters. BIP-173 requires ASCII only: a non-ASCII char
    // must not be silently truncated to its low byte (which could pass the
    // charset check as a look-alike).
    for ch in data_part.chars() {
        if !ch.is_ascii() || !CHARSET.contains(&(ch as u8)) {
            return Err(Bech32Error::InvalidChar(ch));
        }
    }

    let data_5bit: Vec<u8> = data_part
        .chars()
        .map(|c| CHARSET.iter().position(|&ch| ch == c as u8).unwrap() as u8)
        .collect();

    if data_5bit.len() < 6 {
        return Err(Bech32Error::InvalidChecksum);
    }

    // Verify checksum; prefer bech32m.
    let is_bech32m = match verify_checksum(hrp.as_bytes(), &data_5bit) {
        Some(v) => v,
        None => return Err(Bech32Error::InvalidChecksum),
    };

    let payload = &data_5bit[..data_5bit.len() - 6];
    Ok((hrp.to_string(), payload.to_vec(), is_bech32m))
}

/// Expand 5-bit groups into 8-bit bytes (BIP-173 convert_bits).
fn convert_bits(
    data: &[u8],
    from_bits: u32,
    to_bits: u32,
    pad: bool,
) -> Result<Vec<u8>, Bech32Error> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();
    let maxv = (1u32 << to_bits) - 1;

    for &value in data {
        if (value as u32 >> from_bits) != 0 {
            return Err(Bech32Error::InvalidData);
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
        return Err(Bech32Error::InvalidData);
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

#[derive(Debug, Clone)]
pub enum Bech32Error {
    MissingSeparator,
    EmptyHrp,
    EmptyData,
    InvalidChar(char),
    InvalidChecksum,
    InvalidData,
    InvalidLength { expected: usize, got: usize },
    UnknownPrefix(String),
    InvalidTlv,
}

impl fmt::Display for Bech32Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSeparator => write!(f, "missing bech32 separator '1'"),
            Self::EmptyHrp => write!(f, "empty human-readable part"),
            Self::EmptyData => write!(f, "empty data part"),
            Self::InvalidChar(c) => write!(f, "invalid bech32 character '{c}'"),
            Self::InvalidChecksum => write!(f, "invalid bech32m checksum"),
            Self::InvalidData => write!(f, "invalid data in bech32 encoding"),
            Self::InvalidLength { expected, got } => {
                write!(f, "invalid length: expected {expected}, got {got}")
            }
            Self::UnknownPrefix(p) => write!(f, "unknown NIP-19 prefix '{p}'"),
            Self::InvalidTlv => write!(f, "invalid TLV structure"),
        }
    }
}

impl std::error::Error for Bech32Error {}

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

fn parse_tlv(data: &[u8]) -> Result<Vec<(u8, Vec<u8>)>, Bech32Error> {
    let mut items = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        if pos + 3 > data.len() {
            return Err(Bech32Error::InvalidTlv);
        }
        let tlv_type = data[pos];
        let len = u16::from_be_bytes([data[pos + 1], data[pos + 2]]) as usize;
        pos += 3;
        if pos + len > data.len() {
            return Err(Bech32Error::InvalidTlv);
        }
        items.push((tlv_type, data[pos..pos + len].to_vec()));
        pos += len;
    }
    Ok(items)
}

/// Parse a NIP-19 bech32m string into an entity.
pub fn parse_nip19(input: &str) -> Result<Nip19Entity, Bech32Error> {
    let (hrp, data_5bit, _is_bech32m) = bech32_decode(input)?;
    let data = convert_bits(&data_5bit, 5, 8, false)?;

    match hrp.as_str() {
        "npub" => {
            if data.len() != 32 {
                return Err(Bech32Error::InvalidLength {
                    expected: 32,
                    got: data.len(),
                });
            }
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&data);
            Ok(Nip19Entity::Pubkey(pk))
        }
        "note" => {
            if data.len() != 32 {
                return Err(Bech32Error::InvalidLength {
                    expected: 32,
                    got: data.len(),
                });
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
            let id = id.ok_or(Bech32Error::InvalidTlv)?;
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
                            Err(_) => return Err(Bech32Error::InvalidTlv),
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
            let kind = kind.ok_or(Bech32Error::InvalidTlv)?;
            let pubkey = pubkey.ok_or(Bech32Error::InvalidTlv)?;
            let d_tag = d_tag.unwrap_or_default();
            Ok(Nip19Entity::Addr {
                kind,
                pubkey,
                d_tag,
                relays,
            })
        }
        other => Err(Bech32Error::UnknownPrefix(other.to_string())),
    }
}

/// Encode 8-bit bytes into bech32m with the given HRP.
#[allow(dead_code)]
pub(crate) fn bech32m_encode(hrp: &str, data: &[u8]) -> Result<String, Bech32Error> {
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

    #[test]
    fn bech32m_roundtrip() {
        // npub1 for a known pubkey
        let hex_pk = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
        let pk_bytes = hex::decode(hex_pk).unwrap();
        let encoded = bech32m_encode("npub", &pk_bytes).unwrap();

        let entity = parse_nip19(&encoded).unwrap();
        match entity {
            Nip19Entity::Pubkey(pk) => {
                assert_eq!(hex::encode(pk), hex_pk);
            }
            _ => panic!("expected Pubkey"),
        }
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
        let encoded = bech32m_encode("nsec", &data).unwrap();
        assert!(encoded.starts_with("nsec1"));
        let result = parse_nip19(&encoded);
        assert!(
            matches!(result, Err(Bech32Error::UnknownPrefix(ref p)) if p == "nsec"),
            "expected UnknownPrefix(\"nsec\"), got {:?}",
            result
        );
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
        data.extend_from_slice(&(32u16).to_be_bytes());
        data.extend_from_slice(&id);
        let relay = b"wss://relay.example.com";
        data.push(TLV_RELAY);
        data.extend_from_slice(&(relay.len() as u16).to_be_bytes());
        data.extend_from_slice(relay);

        let encoded = bech32m_encode("nevent", &data).unwrap();
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
        data.extend_from_slice(&(d.len() as u16).to_be_bytes());
        data.extend_from_slice(d);
        let relay = b"wss://relay.example.com";
        data.push(TLV_RELAY);
        data.extend_from_slice(&(relay.len() as u16).to_be_bytes());
        data.extend_from_slice(relay);
        data.push(TLV_AUTHOR);
        data.extend_from_slice(&(32u16).to_be_bytes());
        data.extend_from_slice(&[0x11u8; 32]);
        data.push(TLV_KIND);
        data.extend_from_slice(&(4u16).to_be_bytes());
        data.extend_from_slice(&30023u32.to_be_bytes());

        let encoded = bech32m_encode("naddr", &data).unwrap();
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
        data.extend_from_slice(&(32u16).to_be_bytes());
        data.extend_from_slice(&id);
        data.push(TLV_AUTHOR);
        data.extend_from_slice(&(32u16).to_be_bytes());
        data.extend_from_slice(&author);
        data.push(TLV_KIND);
        data.extend_from_slice(&(4u16).to_be_bytes());
        data.extend_from_slice(&7u32.to_be_bytes());

        let encoded = bech32m_encode("nevent", &data).unwrap();
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
        data.extend_from_slice(&(32u16).to_be_bytes());
        data.extend_from_slice(&[0x42u8; 32]);
        data.push(TLV_KIND);
        data.extend_from_slice(&(4u16).to_be_bytes());
        data.extend_from_slice(&1u32.to_be_bytes());
        let encoded = bech32m_encode("nevent", &data).unwrap();
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
        data.extend_from_slice(&(d.len() as u16).to_be_bytes());
        data.extend_from_slice(d);
        data.push(TLV_AUTHOR);
        data.extend_from_slice(&(32u16).to_be_bytes());
        data.extend_from_slice(&[0x22u8; 32]);
        data.push(TLV_KIND);
        data.extend_from_slice(&(4u16).to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        let encoded = bech32m_encode("naddr", &data).unwrap();
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
}
