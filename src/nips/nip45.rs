//! NIP-45: Counting Results.
//!
//! `["COUNT", <subscription_id>, <filters>]` is answered with
//! `["COUNT", <subscription_id>, {"count": <n>}]`. When the count was capped
//! by the relay's limits the response carries `"approximate": true`, and when
//! the filter is HyperLogLog-eligible an `"hll"` register set is included so
//! clients can merge counts across relays.

use serde_json::{Value, json};

use crate::event::Event;
use crate::filter::Filter;
use crate::nips::nip13;

/// Builds the COUNT response. `events` are the events matched by `filters`
/// (already deduplicated by the scan); `approximate` signals that the relay
/// stopped counting at its limit.
pub fn count_response(
    sub_id: &str,
    filters: &[Filter],
    events: &[Event],
    approximate: bool,
) -> Value {
    let mut body = json!({ "count": events.len() });
    if approximate {
        body["approximate"] = json!(true);
    } else if let Some(hll) = hll(filters, events) {
        body["hll"] = json!(hll);
    }
    json!(["COUNT", sub_id, body])
}

/// Computes the HyperLogLog register set (256 bytes, hex-encoded, 512 hex
/// chars) over the pubkeys of `events`. NIP-45 defines the offset per
/// filter, so a single HLL over an OR'd union is only well-defined when
/// every filter is HLL-eligible with the same offset (the canonical
/// single-target queries); otherwise `None` is returned and the response
/// omits `hll`.
pub fn hll(filters: &[Filter], events: &[Event]) -> Option<String> {
    let mut offset: Option<usize> = None;
    for filter in filters {
        // A filter without a tag attribute is not HLL-eligible (the spec
        // leaves that case undefined), so the union is not either.
        let candidate = hll_offset(filter)?;
        match offset {
            None => offset = Some(candidate),
            Some(existing) if existing == candidate => {}
            Some(_) => return None,
        }
    }
    let offset = offset?;
    let mut registers = [0u8; 256];
    for event in events {
        let Some(pubkey) = event.pubkey_bytes() else {
            continue;
        };
        let register = pubkey[offset] as usize;
        // NIP-45: count the leading zero bits starting at `offset + 1`.
        // The canonical implementation (fiatjaf/nostr) slices the 7 bytes
        // after the register byte (a 56-bit window): counting to the end
        // of the pubkey (up to 192 bits) would inflate the register when
        // the tail is all zeros and produce a different hll than every
        // reference relay.
        let zeros = nip13::leading_zero_bits(&pubkey[offset + 1..offset + 8]);
        let value = (zeros + 1) as u8;
        if value > registers[register] {
            registers[register] = value;
        }
    }
    Some(hex::encode(registers))
}

/// The deterministic HLL offset for a filter (NIP-45): derived from the
/// first tag attribute's first value — a 64-char hex id/pubkey, an address
/// (`<kind>:<pubkey>:<d>`, using the pubkey part) or a sha256 hash.
/// Per the spec the attribute must carry the `#` prefix: a non-`#` key is
/// an unknown filter field (ignored by the scan) and must not influence
/// the offset, or the registers would differ from other relays' for the
/// same query.
fn hll_offset(filter: &Filter) -> Option<usize> {
    // "Take the first tag attribute in the filter": `Filter::tags`
    // preserves the client's JSON attribute order (`preserve_order`), so
    // this is the document-order first `#` key.
    let (_, value) = filter.tags.iter().find(|(n, _)| n.starts_with('#'))?;
    let value = crate::filter::tag_values(value).next()?;
    let hex_string = if value.len() == 64 && hex::decode(value).is_ok() {
        value.to_string()
    } else if let Some(pubkey) = address_pubkey(value) {
        pubkey.to_string()
    } else {
        // Includes malformed addresses (non-numeric kind, non-hex pubkey):
        // the spec hashes anything that is not a valid id/pubkey/address.
        hex::encode(sha256(value.as_bytes()))
    };
    let nibble = hex_nibble(*hex_string.as_bytes().get(32)?)?;
    Some(nibble as usize + 8)
}

/// The `<pubkey>` of a well-formed `<kind>:<pubkey>:<d>` address (the kind
/// must be numeric and the pubkey 64 hex chars); `None` for anything else,
/// which the caller then hashes as a whole.
fn address_pubkey(value: &str) -> Option<&str> {
    let (kind, rest) = value.split_once(':')?;
    kind.parse::<u64>().ok()?;
    let (pubkey, _d) = rest.split_once(':')?;
    (pubkey.len() == 64 && hex::decode(pubkey).is_ok()).then_some(pubkey)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        // Uppercase hex carries the same value: the offset must agree with
        // the stored (lowercase) form instead of dropping HLL eligibility.
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_format() {
        assert_eq!(
            count_response("sub", &[], &[][..], false),
            serde_json::json!(["COUNT", "sub", { "count": 0 }])
        );
    }

    fn filter_with_tag(value: &str) -> Filter {
        serde_json::from_value(serde_json::json!({ "#e": [value] })).unwrap()
    }

    #[test]
    fn hll_offset_from_hex() {
        // The hex char at position 32 of a 64-char id determines the offset.
        let mut hex = "a".repeat(64);
        hex.replace_range(32..33, "c"); // c = 12 -> offset 20
        let f = filter_with_tag(&hex);
        assert_eq!(hll_offset(&f), Some(20));
        // Uppercase carries the same value as lowercase.
        let upper = hex.to_ascii_uppercase();
        let f = filter_with_tag(&upper);
        assert_eq!(hll_offset(&f), Some(20));
    }

    #[test]
    fn hll_offset_from_address_and_hash() {
        let mut pubkey = "b".repeat(64);
        pubkey.replace_range(32..33, "f"); // f = 15 -> offset 23
        let f = filter_with_tag(&format!("30023:{pubkey}:post-1"));
        assert_eq!(hll_offset(&f), Some(23));
        // Non-hex values are sha256-hashed.
        let f = filter_with_tag("hello world");
        assert!(hll_offset(&f).is_some_and(|o| (8..=23).contains(&o)));
        // A malformed address (non-numeric kind) is not an address: the
        // whole value is hashed like any other string.
        let f = filter_with_tag(&format!("notakind:{pubkey}:post-1"));
        assert!(hll_offset(&f).is_some_and(|o| (8..=23).contains(&o)));
        // Filters without a tag attribute are not eligible.
        let f: Filter = serde_json::from_value(serde_json::json!({"kinds": [7]})).unwrap();
        assert!(hll_offset(&f).is_none());
    }

    #[test]
    fn hll_offset_uses_the_first_tag_attribute_in_order() {
        // NIP-45: the offset comes from the *first* tag attribute in the
        // filter, in the client's JSON order.
        let mut a = "a".repeat(64);
        a.replace_range(32..33, "c"); // c = 12 -> offset 20
        let mut b = "b".repeat(64);
        b.replace_range(32..33, "f"); // f = 15 -> offset 23
        let f: Filter =
            serde_json::from_value(serde_json::json!({"#b": [b], "#a": [a]})).unwrap();
        assert_eq!(hll_offset(&f), Some(23), "the first # attribute must win");
    }

    #[test]
    fn hll_requires_one_common_offset() {
        // One HLL over an OR'd union is only defined when every filter is
        // eligible with the same offset; otherwise the response omits it.
        let mut a = "a".repeat(64);
        a.replace_range(32..33, "c"); // offset 20
        let mut b = "b".repeat(64);
        b.replace_range(32..33, "f"); // offset 23
        let same1 = filter_with_tag(&a);
        let same2 = filter_with_tag(&a);
        assert!(hll(&[same1.clone(), same2], &[]).is_some());
        let other = filter_with_tag(&b);
        assert!(
            hll(&[same1.clone(), other], &[]).is_none(),
            "different offsets cannot share one register set"
        );
        let untagged: Filter = serde_json::from_value(serde_json::json!({"kinds": [1]})).unwrap();
        assert!(
            hll(&[same1, untagged], &[]).is_none(),
            "an ineligible filter makes the union ineligible"
        );
    }

    #[test]
    fn hll_registers_are_deterministic_and_bounded() {
        let mut ev = Event {
            id: String::new(),
            pubkey: "c".repeat(64),
            created_at: 1,
            kind: 7,
            tags: vec![],
            content: String::new(),
            sig: String::new(),
        };
        ev.id = crate::nips::nip01::compute_id(&ev);
        let mut tag_value = "d".repeat(64);
        tag_value.replace_range(32..33, "0"); // offset 8
        let filter = filter_with_tag(&tag_value);
        let h1 = hll(std::slice::from_ref(&filter), std::slice::from_ref(&ev)).unwrap();
        assert_eq!(h1.len(), 512);
        // Identical input yields the same registers.
        assert_eq!(
            h1,
            hll(std::slice::from_ref(&filter), std::slice::from_ref(&ev)).unwrap()
        );
    }

    #[test]
    fn hll_reference_vector_pins_algorithm() {
        // Pinned reference vector against the canonical `fiatjaf/nostr`
        // interpretation: offset 8 (tag `00..00`), 56-bit window
        // (`offset+1..offset+8`), value = leading-zero-bits + 1.
        fn ev_with_pubkey(pubkey: &str) -> Event {
            let mut ev = Event {
                id: String::new(),
                pubkey: pubkey.to_string(),
                created_at: 1,
                kind: 7,
                tags: vec![],
                content: String::new(),
                sig: String::new(),
            };
            ev.id = crate::nips::nip01::compute_id(&ev);
            ev
        }
        let filter = filter_with_tag(&"0".repeat(64)); // nibble 0 -> offset 8
        assert_eq!(hll_offset(&filter), Some(8));
        // pubkey[8] selects the register; the next 7 bytes set the value.
        // All-zero tail => 56 zero bits => value 57 (0x39).
        let zero = ev_with_pubkey(&"00".repeat(32));
        let ff_reg = format!("{}{}{}", "00".repeat(8), "ff", "00".repeat(23));
        let ff = ev_with_pubkey(&ff_reg);
        let h = hll(&[filter], &[zero, ff]).unwrap();
        assert_eq!(h.len(), 512);
        assert_eq!(&h[0..2], "39", "register 0 must hold 57");
        assert_eq!(&h[510..512], "39", "register 255 must hold 57");
        assert!(
            h[2..510].chars().all(|c| c == '0'),
            "all other registers must be zero"
        );
    }

    #[test]
    fn hll_offset_ignores_non_tag_keys() {
        // NIP-45: the offset comes from the first `#`-prefixed tag
        // attribute; a non-`#` key (an unknown filter field) must not
        // influence it, or the registers would differ from other relays.
        let mut hex = "a".repeat(64);
        hex.replace_range(32..33, "c"); // c = 12 -> offset 20
        let f: Filter =
            serde_json::from_value(serde_json::json!({"foo": "bar", "#e": [hex]})).unwrap();
        assert_eq!(hll_offset(&f), Some(20));
        // Without any `#`-prefixed attribute the filter is not eligible.
        let f: Filter = serde_json::from_value(serde_json::json!({"foo": "bar"})).unwrap();
        assert!(hll_offset(&f).is_none());
    }

    #[test]
    fn approximate_flag_in_response() {
        let resp = count_response("s", &[], &[], true);
        assert_eq!(
            resp,
            serde_json::json!(["COUNT", "s", { "count": 0, "approximate": true }])
        );
    }
}
