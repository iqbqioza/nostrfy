//! NIP-77: Negentropy Syncing.
//!
//! The reconciliation protocol (items, fingerprints, range splitting) lives
//! here; the binary encoding is in [`codec`].

mod codec;

use anyhow::anyhow;
use codec::{parse_message, write_bound, write_varint};

/// A from-scratch implementation of the Negentropy protocol V1 (range-based
/// set reconciliation). This module only implements the server side: given
/// a client message and the relay's own item set it produces the response.
///
/// Binary format (see the NIP-77 appendix):
/// - items are sorted by (timestamp, id), ascending;
/// - a message is `0x61` (protocol version) followed by adjacent ranges;
/// - each range: upper bound, mode varint (0=skip, 1=fingerprint, 2=id list),
///   and a payload.
use std::cmp::Ordering;

use sha2::{Digest, Sha256};

pub const PROTOCOL_VERSION: u8 = 0x61;

/// The maximum number of ranges one NEG-MSG may carry: the per-range
/// fingerprint/bisection work grows with the item set, so the input side
/// is budgeted to keep a single frame's CPU cost bounded (the round
/// budget then caps the total).
pub(crate) const MAX_NEG_RANGES_PER_MSG: usize = 1024;
/// Ranges with at most this many items are answered with an id list instead
/// of being bisected.
pub const ID_LIST_THRESHOLD: usize = 100;

/// A (timestamp, id) record used for reconciliation.
pub type Item = (u64, [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bound {
    pub ts: u64,
    /// Disambiguating id prefix (0..=32 bytes); trailing bytes are zeros.
    pub prefix: Vec<u8>,
}

#[derive(Debug)]
enum Mode {
    Skip,
    Fingerprint([u8; 16]),
    /// The sender listed its ids for this range; the server responds with
    /// its own ids without inspecting the client's.
    IdList,
}

#[derive(Debug)]
struct Range {
    upper: Bound,
    mode: Mode,
}

// ----- item helpers -----

/// Sorts items by (timestamp, id) ascending, as required by the protocol.
pub fn sort_items(mut items: Vec<Item>) -> Vec<Item> {
    items.sort_by(compare);
    items
}

fn compare(a: &Item, b: &Item) -> Ordering {
    a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1))
}

/// Compares an item with an exclusive upper bound.
fn item_cmp(item: &Item, bound: &Bound) -> Ordering {
    match item.0.cmp(&bound.ts) {
        Ordering::Less => Ordering::Less,
        Ordering::Greater => Ordering::Greater,
        Ordering::Equal => {
            let mut padded = [0u8; 32];
            padded[..bound.prefix.len()].copy_from_slice(&bound.prefix);
            item.1.cmp(&padded)
        }
    }
}

/// Fingerprint of all ids in `items`: sum mod 2^256 (little-endian limbs),
/// followed by the count as a varint, hashed with SHA-256; the first 16
/// bytes are the fingerprint.
fn fingerprint(items: &[Item]) -> [u8; 16] {
    let mut sum = [0u8; 32];
    for (_, id) in items {
        let mut carry = 0u32;
        for i in 0..32 {
            let acc = sum[i] as u32 + id[i] as u32 + carry;
            sum[i] = (acc & 0xff) as u8;
            carry = acc >> 8;
        }
    }
    let mut hasher = Sha256::new();
    hasher.update(sum);
    let mut count_buf = [0u8; 10];
    let count_len = write_varint(&mut count_buf, items.len() as u64);
    hasher.update(&count_buf[..count_len]);
    let digest = hasher.finalize();
    digest[..16].try_into().unwrap()
}

// ----- server response -----

/// Computes the server's response to a client message.
///
/// `items` must already be sorted ascending by (timestamp, id) via
/// [`sort_items`]. Returns the raw response message (without hex encoding).
pub fn respond(items: &[Item], client_message: &[u8]) -> anyhow::Result<Vec<u8>> {
    if client_message.first() != Some(&PROTOCOL_VERSION) {
        // Protocol version negotiation: reply with the highest version we
        // support (a single byte).
        return Ok(vec![PROTOCOL_VERSION]);
    }
    let mut ranges = parse_message(client_message)?;
    // NIP-77: every message covers the complete timestamp/ID space. A
    // message whose final explicit range does not reach infinity implicitly
    // appends a Skip range to infinity.
    if ranges.last().is_none_or(|range| range.upper.ts != u64::MAX) {
        ranges.push(Range {
            upper: Bound {
                ts: u64::MAX,
                prefix: Vec::new(),
            },
            mode: Mode::Skip,
        });
    }
    // A single message must not scan unbounded fingerprint/bisection
    // work: thousands of ranges over a 100k-item set would burn seconds
    // of CPU per frame (the client controls the number of ranges it
    // sends, so this is the input-side budget of the protocol).
    if ranges.len() > MAX_NEG_RANGES_PER_MSG {
        return Err(anyhow!("too many ranges in one negentropy message"));
    }
    let mut out: Vec<u8> = Vec::new();
    out.push(PROTOCOL_VERSION);
    let mut prev_ts = 0u64;

    let mut lower = Bound {
        ts: 0,
        prefix: Vec::new(),
    };
    for range in &ranges {
        let upper = &range.upper;
        // Ranges must be adjacent and ascending.
        if lower.ts > upper.ts
            || (lower.ts == upper.ts && lower.prefix.as_slice() > upper.prefix.as_slice())
        {
            return Err(anyhow!("ranges out of order"));
        }
        match &range.mode {
            Mode::Skip => {
                write_bound(&mut out, upper, &mut prev_ts);
                let mut buf = [0u8; 10];
                let n = write_varint(&mut buf, 0);
                out.extend_from_slice(&buf[..n]);
                lower = upper.clone();
            }
            Mode::IdList => {
                let ids = ids_in(items, &lower, upper);
                write_bound(&mut out, upper, &mut prev_ts);
                let mut buf = [0u8; 10];
                let n = write_varint(&mut buf, 2);
                out.extend_from_slice(&buf[..n]);
                let n = write_varint(&mut buf, ids.len() as u64);
                out.extend_from_slice(&buf[..n]);
                for id in ids {
                    out.extend_from_slice(&id);
                }
                lower = upper.clone();
            }
            Mode::Fingerprint(client_fp) => {
                // Process [lower, upper) possibly splitting it repeatedly.
                loop {
                    let start = items.partition_point(|i| item_cmp(i, &lower) == Ordering::Less);
                    let end = items.partition_point(|i| item_cmp(i, upper) == Ordering::Less);
                    let slice = &items[start..end];
                    let fp = fingerprint(slice);
                    if fp == *client_fp {
                        // In sync for this range.
                        write_bound(&mut out, upper, &mut prev_ts);
                        let mut buf = [0u8; 10];
                        let n = write_varint(&mut buf, 0);
                        out.extend_from_slice(&buf[..n]);
                        lower = upper.clone();
                        break;
                    }
                    if slice.len() <= ID_LIST_THRESHOLD {
                        // Answer the whole range with an id list.
                        let ids: Vec<[u8; 32]> = slice.iter().map(|(_, id)| *id).collect();
                        write_bound(&mut out, upper, &mut prev_ts);
                        let mut buf = [0u8; 10];
                        let n = write_varint(&mut buf, 2);
                        out.extend_from_slice(&buf[..n]);
                        let n = write_varint(&mut buf, ids.len() as u64);
                        out.extend_from_slice(&buf[..n]);
                        for id in ids {
                            out.extend_from_slice(&id);
                        }
                        lower = upper.clone();
                        break;
                    }
                    // Split at the median item and emit the first half as a
                    // fingerprint range, then keep processing the second half.
                    let mid = slice.len() / 2;
                    let mid_item = &slice[mid];
                    let mid_bound = split_bound(&slice[mid - 1], mid_item);
                    let first = &slice[..mid];
                    write_bound(&mut out, &mid_bound, &mut prev_ts);
                    let mut buf = [0u8; 10];
                    let n = write_varint(&mut buf, 1);
                    out.extend_from_slice(&buf[..n]);
                    out.extend_from_slice(&fingerprint(first));
                    lower = mid_bound;
                }
            }
        }
    }
    Ok(out)
}

fn ids_in(items: &[Item], lower: &Bound, upper: &Bound) -> Vec<[u8; 32]> {
    let start = items.partition_point(|i| item_cmp(i, lower) == Ordering::Less);
    let end = items.partition_point(|i| item_cmp(i, upper) == Ordering::Less);
    items[start..end].iter().map(|(_, id)| *id).collect()
}

/// The bound between two adjacent items: excludes `a`, includes `b`.
fn split_bound(a: &Item, b: &Item) -> Bound {
    if a.0 != b.0 {
        return Bound {
            ts: b.0,
            prefix: Vec::new(),
        };
    }
    let common =
        a.1.iter()
            .zip(b.1.iter())
            .take_while(|(x, y)| x == y)
            .count();
    Bound {
        ts: b.0,
        // The prefix is the common bytes plus one (`common.min(31) + 1` ≤
        // 32). Production data is deduplicated by event id, but `respond`
        // is public: an identical adjacent pair would otherwise index
        // `b.1[..=32]` out of bounds and panic.
        prefix: b.1[..common.min(31) + 1].to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(ts: u64, id: u8) -> Item {
        let mut bytes = [0u8; 32];
        bytes[31] = id;
        (ts, bytes)
    }

    #[test]
    fn split_bound_tolerates_identical_items() {
        // Production data is deduplicated by event id, but `respond` is
        // public: an identical adjacent pair must not panic (the prefix is
        // capped at 32 bytes).
        let a = item(5, 7);
        let b = item(5, 7);
        let bound = split_bound(&a, &b);
        assert_eq!(bound.ts, 5);
        assert_eq!(bound.prefix.len(), 32, "the prefix is capped");
    }

    #[test]
    fn varint_roundtrip() {
        for value in [0u64, 1, 127, 128, 300, 16_384, u64::MAX] {
            let mut buf = [0u8; 10];
            let n = write_varint(&mut buf, value);
            let mut pos = 0;
            assert_eq!(codec::read_varint(&buf[..n], &mut pos).unwrap(), value);
            assert_eq!(pos, n);
        }
    }

    #[test]
    fn fingerprints_differ() {
        let a = vec![item(1, 1), item(2, 2)];
        let b = vec![item(1, 1), item(2, 3)];
        assert_ne!(fingerprint(&a), fingerprint(&b));
        let c = vec![item(1, 1), item(2, 2), item(5, 9)];
        assert_ne!(fingerprint(&a), fingerprint(&c));
    }

    #[test]
    fn full_sync_with_empty_client() {
        // Client sends a single Skip-to-infinity range: server answers Skip.
        let mut hello = vec![PROTOCOL_VERSION];
        // upper = infinity
        let mut buf = [0u8; 10];
        let n = write_varint(&mut buf, 0);
        hello.extend_from_slice(&buf[..n]);
        let n = write_varint(&mut buf, 0);
        hello.extend_from_slice(&buf[..n]);
        let n = write_varint(&mut buf, 0);
        hello.extend_from_slice(&buf[..n]);

        let items = sort_items(vec![item(1, 1), item(2, 2)]);
        let resp = respond(&items, &hello).unwrap();
        assert_eq!(resp, vec![PROTOCOL_VERSION, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn appends_implicit_skip_to_infinity() {
        let mut message = vec![PROTOCOL_VERSION];
        let mut buf = [0u8; 10];
        let n = write_varint(&mut buf, 1); // upper timestamp 0
        message.extend_from_slice(&buf[..n]);
        let n = write_varint(&mut buf, 0); // empty ID prefix
        message.extend_from_slice(&buf[..n]);
        let n = write_varint(&mut buf, 0); // Skip
        message.extend_from_slice(&buf[..n]);

        let response = respond(&[item(1, 1)], &message).unwrap();
        assert_eq!(
            response,
            vec![PROTOCOL_VERSION, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn client_with_empty_set_gets_all_ids() {
        // Client's message: one fingerprint range over [0, inf) with a
        // bogus fingerprint (client has nothing).
        let mut msg = vec![PROTOCOL_VERSION];
        let mut buf = [0u8; 10];
        let n = write_varint(&mut buf, 0); // infinity upper
        msg.extend_from_slice(&buf[..n]);
        let n = write_varint(&mut buf, 0); // empty id prefix
        msg.extend_from_slice(&buf[..n]);
        let n = write_varint(&mut buf, 1); // mode = fingerprint
        msg.extend_from_slice(&buf[..n]);
        msg.extend_from_slice(&[0u8; 16]); // client's fingerprint

        let items = sort_items(vec![item(1, 7), item(3, 9)]);
        let resp = respond(&items, &msg).unwrap();

        // Expect: version + range with infinity upper, mode 2, 2 ids.
        assert_eq!(resp[0], PROTOCOL_VERSION);
        assert_eq!(resp[1], 0x00); // infinity ts
        assert_eq!(resp[2], 0x00); // empty prefix
        assert_eq!(resp[3], 0x02); // mode id list
        assert_eq!(resp[4], 0x02); // two ids
        assert_eq!(&resp[5..37], &items[0].1);
        assert_eq!(&resp[37..69], &items[1].1);
    }

    #[test]
    fn synced_client_gets_skip() {
        let items = sort_items(vec![item(1, 1)]);
        let mut msg = vec![PROTOCOL_VERSION];
        let mut buf = [0u8; 10];
        let n = write_varint(&mut buf, 0);
        msg.extend_from_slice(&buf[..n]);
        let n = write_varint(&mut buf, 0);
        msg.extend_from_slice(&buf[..n]);
        let n = write_varint(&mut buf, 1);
        msg.extend_from_slice(&buf[..n]);
        msg.extend_from_slice(&fingerprint(&items));

        let resp = respond(&items, &msg).unwrap();
        // version + infinity bound (ts=0, len=0) + mode 0 (skip)
        assert_eq!(resp, vec![PROTOCOL_VERSION, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn version_negotiation() {
        let resp = respond(&[], &[0x62]).unwrap();
        assert_eq!(resp, vec![PROTOCOL_VERSION]);
    }

    #[test]
    fn large_ranges_are_bisected() {
        // 300 items and a bogus client fingerprint: the server must bisect
        // into fingerprint ranges (mode 1) instead of dumping one id list.
        let mut raw = Vec::new();
        for i in 0..300u64 {
            raw.push(item(i, (i % 256) as u8));
        }
        let items = sort_items(raw);

        let mut msg = vec![PROTOCOL_VERSION];
        let mut buf = [0u8; 10];
        let n = write_varint(&mut buf, 0);
        msg.extend_from_slice(&buf[..n]);
        let n = write_varint(&mut buf, 0);
        msg.extend_from_slice(&buf[..n]);
        let n = write_varint(&mut buf, 1);
        msg.extend_from_slice(&buf[..n]);
        msg.extend_from_slice(&[0u8; 16]);

        let resp = respond(&items, &msg).unwrap();
        assert!(
            resp.len() > 2000,
            "response too small: {} bytes {:?}",
            resp.len(),
            &resp[..30]
        );

        // Structurally verify the response: two bisected fingerprint ranges
        // followed by an id list with the remaining 75 items.
        let ranges = parse_message(&resp).unwrap();
        assert_eq!(ranges.len(), 3);
        assert!(matches!(ranges[0].mode, Mode::Fingerprint(_)));
        assert!(matches!(ranges[1].mode, Mode::Fingerprint(_)));
        assert!(matches!(ranges[2].mode, Mode::IdList));
        assert_eq!(ranges[0].upper.ts, 150);
        assert_eq!(ranges[1].upper.ts, 225);
        assert_eq!(ranges[2].upper.ts, u64::MAX);

        let mut pos = 1usize;
        let mut prev = 0u64;
        for _ in &ranges {
            codec::read_bound(&resp, &mut pos, &mut prev).unwrap();
            match codec::read_varint(&resp, &mut pos).unwrap() {
                1 => pos += 16,
                2 => {
                    let count = codec::read_varint(&resp, &mut pos).unwrap();
                    assert_eq!(count, 75);
                    pos += count as usize * 32;
                }
                other => panic!("unexpected mode {other}"),
            }
        }
        assert_eq!(pos, resp.len());
    }
}
