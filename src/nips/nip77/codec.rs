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
}
