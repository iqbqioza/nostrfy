//! The Negentropy V1 binary codec: varints, bound encoding and message
//! parsing. The reconciliation logic lives in `super`.

use anyhow::anyhow;

use super::{Bound, Mode, PROTOCOL_VERSION, Range};

/// Base-128 varints, most significant digit first.
pub(crate) fn write_varint(out: &mut [u8], mut value: u64) -> usize {
    // Most significant base-128 digit first; high bit set on all but the last.
    let mut digits = [0u8; 10];
    let mut n = 0;
    loop {
        digits[n] = (value & 0x7f) as u8;
        value >>= 7;
        n += 1;
        if value == 0 {
            break;
        }
    }
    for (i, &d) in digits[..n].iter().rev().enumerate() {
        out[i] = if i + 1 == n { d } else { d | 0x80 };
    }
    n
}

pub(crate) fn read_varint(data: &[u8], pos: &mut usize) -> anyhow::Result<u64> {
    let mut value = 0u64;
    loop {
        let b = *data.get(*pos).ok_or_else(|| anyhow!("truncated varint"))?;
        *pos += 1;
        value = value
            .checked_mul(128)
            .and_then(|v| v.checked_add((b & 0x7f) as u64))
            .ok_or_else(|| anyhow!("varint overflow"))?;
        if b & 0x80 == 0 {
            return Ok(value);
        }
    }
}

// ----- bound encoding -----

/// Encodes a bound. `prev_ts` tracks the offset delta encoding.
pub(crate) fn write_bound(out: &mut Vec<u8>, bound: &Bound, prev_ts: &mut u64) {
    let encoded = if bound.ts == u64::MAX {
        0
    } else {
        1 + (bound.ts.saturating_sub(*prev_ts))
    };
    *prev_ts = bound.ts;
    let mut buf = [0u8; 10];
    let n = write_varint(&mut buf, encoded);
    out.extend_from_slice(&buf[..n]);
    let n = write_varint(&mut buf, bound.prefix.len() as u64);
    out.extend_from_slice(&buf[..n]);
    out.extend_from_slice(&bound.prefix);
}

pub(crate) fn read_bound(data: &[u8], pos: &mut usize, prev_ts: &mut u64) -> anyhow::Result<Bound> {
    let encoded = read_varint(data, pos)?;
    let ts = if encoded == 0 {
        u64::MAX
    } else {
        prev_ts.saturating_add(encoded - 1)
    };
    *prev_ts = ts;
    let len = read_varint(data, pos)?;
    // Compare before casting: on 32-bit targets `as usize` would truncate a
    // length ≥ 2^32 and could turn an over-long prefix into an accepted one.
    if len > 32 {
        return Err(anyhow!("bound prefix too long"));
    }
    let len = len as usize;
    let prefix = data
        .get(*pos..*pos + len)
        .ok_or_else(|| anyhow!("truncated bound prefix"))?
        .to_vec();
    *pos += len;
    Ok(Bound { ts, prefix })
}

// ----- message parsing -----

/// Parses a NEG-MSG body. `max_ranges` bounds the number of ranges the
/// message may carry, enforced *while parsing*: the caller's post-parse
/// check would otherwise let a small frame allocate the whole range vector
/// (and every bound prefix in it) before being rejected.
pub(crate) fn parse_message(data: &[u8], max_ranges: usize) -> anyhow::Result<Vec<Range>> {
    if data.is_empty() {
        return Err(anyhow!("empty message"));
    }
    if data[0] != PROTOCOL_VERSION {
        return Err(anyhow!("unsupported protocol version"));
    }
    let mut pos = 1usize;
    let mut prev_ts = 0u64;
    let mut ranges = Vec::new();
    while pos < data.len() {
        if ranges.len() >= max_ranges {
            return Err(anyhow!("too many ranges in one negentropy message"));
        }
        let upper = read_bound(data, &mut pos, &mut prev_ts)?;
        let mode = read_varint(data, &mut pos)?;
        let mode = match mode {
            0 => Mode::Skip,
            1 => {
                let mut fp = [0u8; 16];
                let end = pos + 16;
                let bytes = data
                    .get(pos..end)
                    .ok_or_else(|| anyhow!("truncated fingerprint"))?;
                fp.copy_from_slice(bytes);
                pos = end;
                Mode::Fingerprint(fp)
            }
            2 => {
                let len = read_varint(data, &mut pos)?;
                // The cap is checked on the u64: `as usize` would truncate a
                // length ≥ 2^32 on 32-bit targets and could accept an
                // over-long id list as a short one.
                if len > 10_000_000 {
                    return Err(anyhow!("id list too long"));
                }
                let len = len as usize;
                let end = pos
                    .checked_add(len * 32)
                    .ok_or_else(|| anyhow!("id list too long"))?;
                if end > data.len() {
                    return Err(anyhow!("truncated id list"));
                }
                pos = end;
                Mode::IdList
            }
            other => return Err(anyhow!("unknown mode {other}")),
        };
        ranges.push(Range { upper, mode });
    }
    Ok(ranges)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::fuzz_tests::Rng;

    fn varint(mut v: u64) -> Vec<u8> {
        // Big-endian groups (the codec's read_varint is `value * 128 + group`).
        let mut groups = vec![(v & 0x7f) as u8];
        v >>= 7;
        while v != 0 {
            groups.push((v & 0x7f) as u8);
            v >>= 7;
        }
        groups.reverse();
        let n = groups.len();
        groups
            .iter()
            .enumerate()
            .map(|(i, g)| if i < n - 1 { g | 0x80 } else { *g })
            .collect()
    }

    #[test]
    fn parse_message_error_paths() {
        // Empty and wrong-version messages are refused up front.
        assert_eq!(
            parse_message(&[], 1024).unwrap_err().to_string(),
            "empty message"
        );
        assert_eq!(
            parse_message(&[0x62], 1024).unwrap_err().to_string(),
            "unsupported protocol version"
        );
        // A bound prefix longer than 32 bytes is refused.
        let mut msg = vec![PROTOCOL_VERSION];
        msg.extend(varint(1)); // ts delta
        msg.extend(varint(33)); // prefix length > 32
        assert_eq!(
            parse_message(&msg, 1024).unwrap_err().to_string(),
            "bound prefix too long"
        );
        // An id list longer than the cap is refused.
        let mut msg = vec![PROTOCOL_VERSION];
        msg.extend(varint(0)); // ts delta = infinity
        msg.extend(varint(0)); // empty prefix
        msg.extend(varint(2)); // mode = id list
        msg.extend(varint(10_000_001));
        assert_eq!(
            parse_message(&msg, 1024).unwrap_err().to_string(),
            "id list too long"
        );
        // A truncated id list is refused.
        let mut msg = vec![PROTOCOL_VERSION];
        msg.extend(varint(0));
        msg.extend(varint(0));
        msg.extend(varint(2));
        msg.extend(varint(2)); // two ids claimed...
        msg.extend(vec![0u8; 10]); // ...but only 10 bytes present
        assert_eq!(
            parse_message(&msg, 1024).unwrap_err().to_string(),
            "truncated id list"
        );
        // A truncated fingerprint is refused.
        let mut msg = vec![PROTOCOL_VERSION];
        msg.extend(varint(0));
        msg.extend(varint(0));
        msg.extend(varint(1)); // mode = fingerprint
        msg.extend(vec![0u8; 4]); // only 4 of 16 bytes
        assert_eq!(
            parse_message(&msg, 1024).unwrap_err().to_string(),
            "truncated fingerprint"
        );
        // An unknown mode is refused.
        let mut msg = vec![PROTOCOL_VERSION];
        msg.extend(varint(0));
        msg.extend(varint(0));
        msg.extend(varint(5));
        assert_eq!(
            parse_message(&msg, 1024).unwrap_err().to_string(),
            "unknown mode 5"
        );
    }

    #[test]
    fn oversized_lengths_are_rejected_before_the_usize_cast() {
        // A length varint ≥ 2^32 must hit the cap as a u64: on a 32-bit
        // target the old `as usize` truncated it (2^32 -> 0) and an
        // over-long bound prefix / id list could slip through as an empty
        // one. The test also guards the 64-bit behaviour (over-cap lengths
        // are rejected regardless of the word size).
        let mut msg = vec![PROTOCOL_VERSION];
        msg.extend(varint(0)); // ts delta = infinity
        msg.extend(varint(u64::from(u32::MAX) + 1)); // prefix length 2^32
        assert_eq!(
            parse_message(&msg, 1024).unwrap_err().to_string(),
            "bound prefix too long"
        );
        let mut msg = vec![PROTOCOL_VERSION];
        msg.extend(varint(0)); // ts delta = infinity
        msg.extend(varint(0)); // empty prefix
        msg.extend(varint(2)); // mode = id list
        msg.extend(varint(u64::from(u32::MAX) + 1)); // 2^32 ids claimed
        assert_eq!(
            parse_message(&msg, 1024).unwrap_err().to_string(),
            "id list too long"
        );
    }

    #[test]
    fn parse_message_bails_out_at_the_range_cap() {
        // A tiny frame can claim an unbounded number of ranges (three bytes
        // each): the cap must stop the parse before the whole vector is
        // materialized, not after.
        let mut msg = vec![PROTOCOL_VERSION];
        for _ in 0..2000 {
            msg.extend(varint(1)); // ts delta
            msg.extend(varint(0)); // empty prefix
            msg.extend(varint(0)); // mode = skip
        }
        assert_eq!(
            parse_message(&msg, 10).unwrap_err().to_string(),
            "too many ranges in one negentropy message"
        );
        assert_eq!(
            parse_message(&msg, 3000).unwrap().len(),
            2000,
            "a message within the cap still parses"
        );
        assert_eq!(
            parse_message(&msg, 2000).unwrap().len(),
            2000,
            "exactly at the cap is allowed"
        );
    }

    // ----- deterministic fuzzing (see crate::fuzz_tests) -----

    /// The test-side counterpart of a parsed [`Range`]: the id-list payload
    /// is discarded by the parser, so it is generated instead of compared.
    enum TestMode {
        Skip,
        Fingerprint([u8; 16]),
        IdList(Vec<[u8; 32]>),
    }

    struct TestRange {
        ts: u64,
        prefix: Vec<u8>,
        mode: TestMode,
    }

    /// Encodes ranges exactly like the protocol: version byte, then each
    /// range's bound, mode and payload.
    fn encode_message(ranges: &[TestRange]) -> Vec<u8> {
        let mut out = vec![PROTOCOL_VERSION];
        let mut prev_ts = 0u64;
        let mut buf = [0u8; 10];
        for range in ranges {
            let bound = Bound {
                ts: range.ts,
                prefix: range.prefix.clone(),
            };
            write_bound(&mut out, &bound, &mut prev_ts);
            let n = match &range.mode {
                TestMode::Skip => write_varint(&mut buf, 0),
                TestMode::Fingerprint(_) => write_varint(&mut buf, 1),
                TestMode::IdList(_) => write_varint(&mut buf, 2),
            };
            out.extend_from_slice(&buf[..n]);
            match &range.mode {
                TestMode::Skip => {}
                TestMode::Fingerprint(fp) => out.extend_from_slice(fp),
                TestMode::IdList(ids) => {
                    let n = write_varint(&mut buf, ids.len() as u64);
                    out.extend_from_slice(&buf[..n]);
                    for id in ids {
                        out.extend_from_slice(id);
                    }
                }
            }
        }
        out
    }

    fn random_ranges(rng: &mut Rng, count: usize) -> Vec<TestRange> {
        let mut ts = 0u64;
        let mut ranges = Vec::with_capacity(count);
        for _ in 0..count {
            // Non-decreasing timestamps, including repeated timestamps and
            // the infinity encoding (u64::MAX once the bound is reached).
            match rng.below(4) {
                0 => {}
                1 => ts = u64::MAX,
                _ => ts = ts.saturating_add(rng.next_u64() % 1_000_000),
            }
            let prefix_len = rng.below(33);
            let prefix = (0..prefix_len).map(|_| rng.next_u64() as u8).collect();
            let mode = match rng.below(3) {
                0 => TestMode::Skip,
                1 => {
                    let mut fp = [0u8; 16];
                    rng.fill(&mut fp);
                    TestMode::Fingerprint(fp)
                }
                _ => {
                    let ids = (0..rng.below(6))
                        .map(|_| {
                            let mut id = [0u8; 32];
                            rng.fill(&mut id);
                            id
                        })
                        .collect();
                    TestMode::IdList(ids)
                }
            };
            ranges.push(TestRange { ts, prefix, mode });
        }
        ranges
    }

    fn assert_same_range(decoded: &Range, source: &TestRange) {
        assert_eq!(decoded.upper.ts, source.ts, "timestamp must round-trip");
        assert_eq!(
            decoded.upper.prefix, source.prefix,
            "bound prefix must round-trip"
        );
        match (&decoded.mode, &source.mode) {
            (Mode::Skip, TestMode::Skip) => {}
            (Mode::Fingerprint(a), TestMode::Fingerprint(b)) => {
                assert_eq!(a, b, "fingerprint must round-trip");
            }
            (Mode::IdList, TestMode::IdList(_)) => {}
            (decoded, _) => panic!("decoded mode {decoded:?} does not match the encoded one"),
        }
    }

    #[test]
    fn fuzz_parse_message_never_panics_on_random_bytes() {
        // Tens of thousands of random buffers of varied lengths through the
        // parse entry point. Half of them are forced to start with the
        // protocol version so the bound/varint/mode paths are reached
        // often, not just the three-byte version check.
        let mut rng = Rng::new(0x5eed_7701);
        let mut buf = [0u8; 256];
        let mut parsed_ok = 0usize;
        for i in 0..30_000 {
            let len = rng.below(buf.len() + 1);
            rng.fill(&mut buf[..len]);
            if i % 2 == 0 && len > 0 {
                buf[0] = PROTOCOL_VERSION;
            }
            // Alternate between a generous cap and tiny ones, so the range
            // cap is fuzzed too.
            let cap = if i % 4 == 0 { 1 + rng.below(16) } else { 1024 };
            if let Ok(ranges) = parse_message(&buf[..len], cap) {
                assert!(ranges.len() <= cap, "the range cap must be enforced");
                parsed_ok += 1;
            }
            // The bound/varint readers are independently reachable and must
            // also tolerate arbitrary slices and offsets.
            let mut pos = rng.below(len + 1);
            let _ = read_varint(&buf[..len], &mut pos);
            let mut pos = rng.below(len + 1);
            let mut prev_ts = rng.next_u64();
            let _ = read_bound(&buf[..len], &mut pos, &mut prev_ts);
        }
        assert!(parsed_ok > 0, "the corpus must reach the success path");
    }

    #[test]
    fn fuzz_message_roundtrips_through_the_codec() {
        // decode(encode(x)) == x for random bounds (timestamps, prefix
        // lengths), fingerprints and id lists; and the encoding is
        // canonical when no discarded id-list payload is involved.
        let mut rng = Rng::new(0x5eed_7702);
        for _ in 0..5_000 {
            let count = rng.below(6);
            let ranges = random_ranges(&mut rng, count);
            let bytes = encode_message(&ranges);
            let decoded = parse_message(&bytes, count.max(1)).expect("encoded message must parse");
            assert_eq!(decoded.len(), ranges.len());
            for (decoded, source) in decoded.iter().zip(&ranges) {
                assert_same_range(decoded, source);
            }
            if !ranges
                .iter()
                .any(|range| matches!(range.mode, TestMode::IdList(_)))
            {
                let reencoded = encode_message(
                    &decoded
                        .iter()
                        .map(|range| TestRange {
                            ts: range.upper.ts,
                            prefix: range.upper.prefix.clone(),
                            mode: match &range.mode {
                                Mode::Skip => TestMode::Skip,
                                Mode::Fingerprint(fp) => TestMode::Fingerprint(*fp),
                                Mode::IdList => unreachable!("filtered above"),
                            },
                        })
                        .collect::<Vec<_>>(),
                );
                assert_eq!(reencoded, bytes, "the encoding must be canonical");
            }
            // An over-tight cap must reject the whole message while
            // parsing, not truncate it.
            if count > 0 {
                assert!(parse_message(&bytes, count - 1).is_err());
            }
        }
    }

    #[test]
    fn fuzz_varints_roundtrip_and_overflows_are_errors() {
        let mut rng = Rng::new(0x5eed_7703);
        for _ in 0..20_000 {
            let value = rng.next_u64();
            let mut buf = [0u8; 16];
            let n = write_varint(&mut buf, value);
            assert!(n <= 10, "a u64 varint is at most 10 bytes");
            let mut pos = 0;
            assert_eq!(read_varint(&buf[..n], &mut pos).unwrap(), value);
            assert_eq!(pos, n);
        }
        // A never-terminating varint runs out of input, and one whose
        // value exceeds u64 is rejected by the checked arithmetic.
        let mut pos = 0;
        assert!(read_varint(&[0x80; 32], &mut pos).is_err());
        let mut pos = 0;
        assert!(read_varint(&[0xff; 11], &mut pos).is_err());
    }
}
