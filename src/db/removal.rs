//! Event removal operations: NIP-09 deletions, NIP-86 bans, NIP-62
//! vanish and the NIP-40 expiration purge.

use super::store::{
    CREATED_LEN, ID_LEN, Store, created_key, delegated_by, dtag_key_safe, pubkey_key,
    replaceable_key, tag_key,
};
use crate::error::Result;
use crate::event::Event;
use crate::nips::nip09;

/// Bounds how many index entries a removal pass materializes at once: a
/// vanished pubkey's full history, every expired id or every version of
/// a deleted addressable event must never pin the writer thread's memory
/// in one `Vec`. The walks below resume just past the last collected key,
/// so entries the caller leaves in place cannot loop forever.
const REMOVAL_CHUNK: usize = 4096;

impl Store {
    /// Applies a deletion request.
    ///
    /// `request_pubkey` is the hex pubkey of the deletion event: only events
    /// authored by the same pubkey are removed (NIP-09). Deletion requests
    /// themselves are never removed. `request_created` limits how old the
    /// deleted events may be; `addresses` are NIP-09 `a` tags referencing
    /// addressable events, whose every version up to `request_created` is
    /// removed.
    /// Like [`Self::apply_deletion_group`] with no group scope (NIP-09).
    pub(crate) fn apply_deletion_group(
        &self,
        targets: &[String],
        addresses: &[nip09::Address],
        request_pubkey: Option<&str>,
        request_created: u64,
        group: Option<&str>,
    ) -> Result<usize> {
        // Disk-full guard: a removal still writes (the deleted marker),
        // so the same SIGBUS protection as the put path applies.
        self.disk_full_error()?;
        let mut wtxn = self.env.write_txn()?;
        let mut removed = 0usize;

        for target in targets {
            let Ok(id) = hex::decode(target) else {
                continue;
            };
            if id.len() != ID_LEN {
                continue;
            }
            let Some(raw) = self.events.get(&wtxn, &id)? else {
                continue;
            };
            let Ok(event) = serde_json::from_slice::<Event>(raw) else {
                continue;
            };
            // NIP-09: only events authored by the request's pubkey are
            // deleted, and deletion requests cannot be deleted. NIP-26:
            // the delegator may also delete events published by a
            // delegatee on their behalf.
            if event.kind == nip09::DELETION_KIND {
                continue;
            }
            if let Some(pubkey) = request_pubkey
                && event.pubkey != pubkey
                && !delegated_by(&event, pubkey)
            {
                continue;
            }
            // NIP-29 9005 moderation: restrict to events of the admin's own
            // group, so a group admin cannot delete another group's content
            // (or the relay's metadata) by referencing its id.
            if let Some(gid) = group
                && crate::nips::nip29::group_id_any(&event)
                    .map(str::to_string)
                    .as_deref()
                    != Some(gid)
            {
                continue;
            }
            self.deleted.put(&mut wtxn, &id, b"")?;
            self.remove_event(&mut wtxn, &id)?;
            removed += 1;
        }

        // NIP-09 `a` tags: remove every version of the referenced
        // addressable events published up to the deletion request.
        for address in addresses {
            // Only the author of the addressable event may delete it.
            if let Some(pubkey) = request_pubkey
                && address.pubkey != pubkey
            {
                continue;
            }
            let Ok(pubkey) = hex::decode(&address.pubkey) else {
                continue;
            };
            if pubkey.len() != ID_LEN {
                continue;
            }
            let start = replaceable_key(address.kind, &pubkey, "");
            let end = replaceable_key(address.kind.saturating_add(1), &pubkey, "");
            let mut last_key: Option<Vec<u8>> = None;
            loop {
                let lower = match &last_key {
                    Some(k) => std::ops::Bound::Excluded(k.as_slice()),
                    None => std::ops::Bound::Included(start.as_slice()),
                };
                let entries: Vec<(Vec<u8>, Vec<u8>)> = self
                    .replaceable
                    .range(&wtxn, &(lower, std::ops::Bound::Excluded(end.as_slice())))?
                    .filter_map(|item| item.ok().map(|(k, v)| (k.to_vec(), v.to_vec())))
                    .take(REMOVAL_CHUNK)
                    .collect();
                if entries.is_empty() {
                    break;
                }
                last_key = Some(entries.last().unwrap().0.clone());
                for (key, value) in entries {
                    // key = kind(8) + pubkey(32) + dlen(4) + d
                    if key.len() < CREATED_LEN + ID_LEN + 4 {
                        continue;
                    }
                    if key[CREATED_LEN..CREATED_LEN + ID_LEN] != pubkey {
                        continue;
                    }
                    let dlen = u32::from_be_bytes(
                        key[CREATED_LEN + ID_LEN..CREATED_LEN + ID_LEN + 4]
                            .try_into()
                            .unwrap(),
                    ) as usize;
                    if key.len() != CREATED_LEN + ID_LEN + 4 + dlen {
                        continue;
                    }
                    let d = &key[CREATED_LEN + ID_LEN + 4..];
                    // The stored slot key truncates over-long `d` tags (see
                    // `dtag_key_safe`), so compare against the truncated form.
                    if d != dtag_key_safe(&address.d).as_bytes() {
                        continue;
                    }
                    if value.len() < CREATED_LEN + ID_LEN {
                        continue;
                    }
                    let created = u64::from_be_bytes(value[..CREATED_LEN].try_into().unwrap());
                    if created > request_created {
                        continue;
                    }
                    let id = &value[CREATED_LEN..CREATED_LEN + ID_LEN];
                    self.deleted.put(&mut wtxn, id, b"")?;
                    self.remove_event(&mut wtxn, id)?;
                    removed += 1;
                }
            }
        }

        wtxn.commit()?;
        Ok(removed)
    }

    /// NIP-86 banevent: marks the event as banned, removes it from storage
    /// and rejects future re-publication.
    pub(crate) fn apply_ban(&self, id: &[u8], reason: &str) -> Result<bool> {
        self.disk_full_error()?;
        let mut wtxn = self.env.write_txn()?;
        self.banned.put(&mut wtxn, id, reason.as_bytes())?;
        let removed = if self.events.get(&wtxn, id)?.is_some() {
            self.remove_event(&mut wtxn, id)?;
            true
        } else {
            false
        };
        wtxn.commit()?;
        Ok(removed)
    }

    pub(crate) fn apply_unban(&self, id: &[u8]) -> Result<bool> {
        let mut wtxn = self.env.write_txn()?;
        let removed = self.banned.delete(&mut wtxn, id)?;
        wtxn.commit()?;
        Ok(removed)
    }

    pub(crate) fn list_banned(&self) -> Result<Vec<(String, String)>> {
        let rtxn = self.env.read_txn()?;
        let mut out = Vec::new();
        for item in self.banned.iter(&rtxn)? {
            let (id, reason) = item?;
            out.push((
                hex::encode(id),
                String::from_utf8_lossy(reason).into_owned(),
            ));
        }
        Ok(out)
    }
    /// Counts events per kind by walking the `by_kind` index in key order
    /// (kind-major: every event of kind 0 first, then kind 1, ...), examining
    /// at most `max_keys` entries. `more` is true when the walk was cut short
    /// (the counts then cover the lowest-numbered kinds only). Returns
    /// `(kind, count)` pairs in ascending kind order.
    pub(crate) fn kind_counts(&self, max_keys: usize) -> Result<(Vec<(u64, u64)>, bool)> {
        let rtxn = self.env.read_txn()?;
        let mut counts: Vec<(u64, u64)> = Vec::new();
        let mut examined = 0usize;
        let mut more = false;
        for item in self.by_kind.iter(&rtxn)? {
            let (key, _) = item?;
            if key.len() >= 8 {
                let kind = u64::from_be_bytes(key[..8].try_into().expect("8-byte kind prefix"));
                match counts.last_mut() {
                    Some((k, c)) if *k == kind => *c += 1,
                    _ => counts.push((kind, 1)),
                }
            }
            examined += 1;
            if examined >= max_keys {
                more = true;
                break;
            }
        }
        Ok((counts, more))
    }

    /// Counts events per author by walking the `by_pubkey` index in key
    /// order (pubkey-major), examining at most `max_keys` entries. `more`
    /// is true when the walk was cut short. Returns `(pubkey, count)` pairs
    /// in ascending pubkey order.
    pub(crate) fn author_counts(&self, max_keys: usize) -> Result<(crate::db::AuthorCounts, bool)> {
        let rtxn = self.env.read_txn()?;
        let mut counts: crate::db::AuthorCounts = Vec::new();
        let mut examined = 0usize;
        let mut more = false;
        for item in self.by_pubkey.iter(&rtxn)? {
            let (key, _) = item?;
            if key.len() >= ID_LEN {
                let pubkey = key[..ID_LEN].to_vec();
                match counts.last_mut() {
                    Some((p, c)) if *p == pubkey => *c += 1,
                    _ => counts.push((pubkey, 1)),
                }
            }
            examined += 1;
            if examined >= max_keys {
                more = true;
                break;
            }
        }
        Ok((counts, more))
    }

    /// NIP-62: deletes every event authored by `pubkey` (including NIP-09
    /// deletion requests and NIP-59 gift wraps that p-tag it) and records the
    /// pubkey so that no future event from it is accepted.
    pub(crate) fn apply_vanish(&self, pubkey: &[u8]) -> Result<usize> {
        self.disk_full_error()?;
        let mut wtxn = self.env.write_txn()?;
        self.vanish.put(&mut wtxn, pubkey, b"")?;

        let mut removed = 0usize;
        let start = pubkey_key(pubkey, 0, &[0u8; ID_LEN]);
        let end = pubkey_key(pubkey, u64::MAX, &[0xffu8; ID_LEN]);
        let mut last_key: Option<Vec<u8>> = None;
        loop {
            let lower = match &last_key {
                Some(k) => std::ops::Bound::Excluded(k.as_slice()),
                None => std::ops::Bound::Included(start.as_slice()),
            };
            let entries: Vec<(Vec<u8>, Vec<u8>)> = self
                .by_pubkey
                .range(&wtxn, &(lower, std::ops::Bound::Excluded(end.as_slice())))?
                .filter_map(|item| {
                    item.ok()
                        .map(|(k, _)| (k.to_vec(), k[k.len() - ID_LEN..].to_vec()))
                })
                .take(REMOVAL_CHUNK)
                .collect();
            if entries.is_empty() {
                break;
            }
            last_key = Some(entries.last().unwrap().0.clone());
            let pubkey_hex = hex::encode(pubkey);
            for (key, id) in entries {
                let Some(raw) = self.events.get(&wtxn, &id)? else {
                    continue;
                };
                let Ok(event) = serde_json::from_slice::<Event>(raw) else {
                    continue;
                };
                // NIP-62: only events *authored* by the vanished pubkey are
                // removed. NIP-26 delegatee events are indexed under the
                // delegator's pubkey too, but they belong to the delegatee and
                // must survive a delegator's request to vanish. Their
                // delegator-side index entry is dropped nevertheless, so the
                // vanished identity's feed is not revived by the delegation.
                if event.pubkey != pubkey_hex {
                    if crate::nips::nip26::delegation(&event).is_some() {
                        self.by_pubkey.delete(&mut wtxn, &key)?;
                    }
                    continue;
                }
                self.remove_event(&mut wtxn, &id)?;
                removed += 1;
            }
        }

        // NIP-59 gift wraps addressed to the vanished pubkey. The by_tag
        // index stores the tag value verbatim (the 64-char hex string), not
        // the decoded bytes.
        let pubkey_hex = hex::encode(pubkey).into_bytes();
        let start = tag_key(b'p', &pubkey_hex, 0, &[0u8; ID_LEN]);
        let end = tag_key(b'p', &pubkey_hex, u64::MAX, &[0xffu8; ID_LEN]);
        let mut last_key: Option<Vec<u8>> = None;
        loop {
            let lower = match &last_key {
                Some(k) => std::ops::Bound::Excluded(k.as_slice()),
                None => std::ops::Bound::Included(start.as_slice()),
            };
            let entries: Vec<(Vec<u8>, Vec<u8>)> = self
                .by_tag
                .range(&wtxn, &(lower, std::ops::Bound::Excluded(end.as_slice())))?
                .filter_map(|item| {
                    item.ok()
                        .map(|(k, _)| (k.to_vec(), k[k.len() - ID_LEN..].to_vec()))
                })
                .take(REMOVAL_CHUNK)
                .collect();
            if entries.is_empty() {
                break;
            }
            last_key = Some(entries.last().unwrap().0.clone());
            for (_, id) in entries {
                let Some(raw) = self.events.get(&wtxn, &id)? else {
                    continue;
                };
                let Ok(event) = serde_json::from_slice::<Event>(raw) else {
                    continue;
                };
                if event.kind == crate::nips::nip62::GIFT_WRAP_KIND {
                    self.remove_event(&mut wtxn, &id)?;
                    removed += 1;
                }
            }
        }

        wtxn.commit()?;
        Ok(removed)
    }

    /// NIP-59: relays SHOULD delete `kind:1059` gift wraps addressed to a
    /// pubkey when that pubkey signs a NIP-09 deletion request. Wraps are
    /// signed by random keys, so they cannot be deleted by their recipient
    /// through the normal deletion flow.
    pub(crate) fn delete_gift_wraps_to(&self, pubkey: &[u8]) -> Result<usize> {
        let mut wtxn = self.env.write_txn()?;
        // The by_tag index stores the tag value verbatim (the 64-char hex
        // string), not the decoded bytes.
        let pubkey_hex = hex::encode(pubkey).into_bytes();
        let start = tag_key(b'p', &pubkey_hex, 0, &[0u8; ID_LEN]);
        let end = tag_key(b'p', &pubkey_hex, u64::MAX, &[0xffu8; ID_LEN]);
        let mut last_key: Option<Vec<u8>> = None;
        let mut removed = 0usize;
        loop {
            let lower = match &last_key {
                Some(k) => std::ops::Bound::Excluded(k.as_slice()),
                None => std::ops::Bound::Included(start.as_slice()),
            };
            let entries: Vec<(Vec<u8>, Vec<u8>)> = self
                .by_tag
                .range(&wtxn, &(lower, std::ops::Bound::Excluded(end.as_slice())))?
                .filter_map(|item| {
                    item.ok()
                        .map(|(k, _)| (k.to_vec(), k[k.len() - ID_LEN..].to_vec()))
                })
                .take(REMOVAL_CHUNK)
                .collect();
            if entries.is_empty() {
                break;
            }
            last_key = Some(entries.last().unwrap().0.clone());
            for (_, id) in entries {
                let Some(raw) = self.events.get(&wtxn, &id)? else {
                    continue;
                };
                let Ok(event) = serde_json::from_slice::<Event>(raw) else {
                    continue;
                };
                if event.kind == crate::nips::nip62::GIFT_WRAP_KIND {
                    self.remove_event(&mut wtxn, &id)?;
                    removed += 1;
                }
            }
        }
        wtxn.commit()?;
        Ok(removed)
    }

    pub(crate) fn purge_expired(&self, now: u64) -> Result<usize> {
        // NIP-40 disabled: nothing is expired. Stale entries written while
        // it was enabled are removed by `remove_event` (which deletes the
        // entry regardless of the toggle), so re-enabling the feature can
        // never resurrect a purged event through a stale key.
        if !self
            .expiry_enabled
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return Ok(0);
        }
        let mut wtxn = self.env.write_txn()?;
        let since_key = created_key(0, &[0u8; ID_LEN]);
        let until_key = created_key(now, &[0xffu8; ID_LEN]);
        let mut last_key: Option<Vec<u8>> = None;
        let mut removed = 0usize;
        loop {
            let lower = match &last_key {
                Some(k) => std::ops::Bound::Excluded(k.as_slice()),
                None => std::ops::Bound::Included(since_key.as_slice()),
            };
            let entries: Vec<(Vec<u8>, Vec<u8>)> = self
                .expiry
                .range(
                    &wtxn,
                    &(lower, std::ops::Bound::Excluded(until_key.as_slice())),
                )?
                .filter_map(|item| {
                    item.ok()
                        .map(|(k, _)| (k.to_vec(), k[k.len() - ID_LEN..].to_vec()))
                })
                .take(REMOVAL_CHUNK)
                .collect();
            if entries.is_empty() {
                break;
            }
            last_key = Some(entries.last().unwrap().0.clone());
            for (_, id) in entries {
                if self.events.get(&wtxn, &id)?.is_some() {
                    self.remove_event(&mut wtxn, &id)?;
                    removed += 1;
                }
            }
        }
        wtxn.commit()?;
        Ok(removed)
    }
}
