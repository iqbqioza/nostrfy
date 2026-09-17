//! Event removal operations: NIP-09 deletions, NIP-86 bans, NIP-62
//! vanish and the NIP-40 expiration purge.

use super::store::{
    CREATED_LEN, GIFT_WRAP_INDEX, ID_LEN, Store, created_key, decode_purged_group_marker,
    delegated_by, deleted_address_key, dtag_key_safe, encode_purged_group_marker, pubkey_key,
    purged_group_key, replaceable_key, tag_key,
};
use crate::error::Result;
use crate::event::Event;
use crate::nips::{nip09, nip29, nip43};

/// Bounds how many index entries a removal pass materializes at once: a
/// vanished pubkey's full history, every expired id or every version of
/// a deleted addressable event must never pin the writer thread's memory
/// in one `Vec`. The walks below resume just past the last collected key,
/// so entries the caller leaves in place cannot loop forever.
const REMOVAL_CHUNK: usize = 4096;

/// Compares two hex pubkeys/ids on decoded bytes (case-insensitive like
/// the scan's hex decode), falling back to exact match when either side
/// is not valid hex.
fn pubkeys_equal(a: &str, b: &str) -> bool {
    match (hex::decode(a), hex::decode(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// Whether removing a `kind` event can change the derived NIP-29 group
/// state or NIP-43 role state, so a removal containing one must make the
/// caller rebuild from the surviving events. Ordinary posts do not.
fn is_group_state_kind(kind: u64) -> bool {
    (nip29::MOD_MIN..=nip29::MOD_MAX).contains(&kind)
        || kind == nip29::JOIN
        || kind == nip29::LEAVE
        || matches!(
            kind,
            nip43::ROLE_DEFINITION
                | nip43::MEMBERSHIP_LIST
                | nip43::ADD_USER
                | nip43::REMOVE_USER
                | nip43::JOIN
                | nip43::LEAVE
        )
}

/// One [`REMOVAL_CHUNK`]-sized page of `(index key, event id)` pairs from
/// `db`, resuming inside `bounds`. Iteration errors propagate: a swallowed
/// cursor error used to end the walk early while the caller reported
/// success (and wrote its vanish/purge marker) with the rest of the
/// history still stored. A corrupt short key (bitrot/hand edit) is skipped
/// instead of sliced — `key.len() - ID_LEN` would underflow and panic the
/// writer, silently aborting the removal.
fn removal_chunk(
    db: heed::Database<heed::types::Bytes, heed::types::Bytes>,
    wtxn: &heed::RwTxn,
    bounds: (std::ops::Bound<&[u8]>, std::ops::Bound<&[u8]>),
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut entries = Vec::new();
    for item in db.range(wtxn, &bounds)? {
        let (key, _) = item?;
        if key.len() < ID_LEN {
            log::warn!(
                "skipping corrupt {}-byte index key during removal",
                key.len()
            );
            continue;
        }
        entries.push((key.to_vec(), key[key.len() - ID_LEN..].to_vec()));
        if entries.len() == REMOVAL_CHUNK {
            break;
        }
    }
    Ok(entries)
}

impl Store {
    /// NIP-59: deletes every stored `kind:1059` event addressed to `pubkey`.
    ///
    /// Walks the reserved [`GIFT_WRAP_INDEX`] namespace — one narrow range
    /// keyed by the decoded pubkey — instead of the whole `p` tag namespace.
    /// The visible tag index stores values verbatim, so the previous
    /// implementation had to scan every `p` entry (the store's most expensive
    /// deletion path, reachable from any NIP-09 deletion request) just to
    /// catch hex case variants.
    fn remove_gift_wraps_for(&self, pubkey: &[u8], removed: &mut usize) -> Result<()> {
        let start = tag_key(GIFT_WRAP_INDEX, pubkey, 0, &[0u8; ID_LEN]);
        let end = crate::db::store::range_end(
            tag_key(GIFT_WRAP_INDEX, pubkey, u64::MAX, &[0xffu8; ID_LEN]),
            u64::MAX,
        );
        let mut last_key: Option<Vec<u8>> = None;
        loop {
            // A fresh write transaction per chunk: one pubkey's wrap index
            // can hold an unbounded number of entries, and a single
            // transaction across the whole walk pinned the writer (a
            // MapFull also aborted the entire purge instead of one chunk).
            let mut wtxn = self.env.write_txn()?;
            let lower = match &last_key {
                Some(key) => std::ops::Bound::Excluded(key.as_slice()),
                None => std::ops::Bound::Included(start.as_slice()),
            };
            let entries = removal_chunk(
                self.by_tag,
                &wtxn,
                (lower, std::ops::Bound::Excluded(end.as_slice())),
            )?;
            if entries.is_empty() {
                break;
            }
            last_key = Some(entries.last().expect("non-empty chunk").0.clone());
            for (key, id) in entries {
                if self.events.get(&wtxn, &id)?.is_none() {
                    // A dangling index entry (the event is already gone):
                    // drop it so later deletions do not keep revisiting it.
                    self.by_tag.delete(&mut wtxn, &key)?;
                    continue;
                }
                // The index is only written for kind:1059 events, so the
                // entry cannot point at any other kind.
                self.remove_event(&mut wtxn, &id)?;
                *removed += 1;
            }
            wtxn.commit()?;
        }
        Ok(())
    }

    /// Applies a deletion request.
    ///
    /// `request_pubkey` is the hex pubkey of the deletion event: only events
    /// authored by the same pubkey are removed (NIP-09). Deletion requests
    /// themselves are never removed. `request_created` bounds only the
    /// `addresses` (NIP-09's created_at cut applies to `a`/addressable
    /// targets); `e` targets are removed regardless of their timestamp.
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
        // Fail closed: a deletion must be scoped to a requester (author /
        // delegator) or to a group. The old signature allowed both to be
        // `None`, which skipped every authorization check and would delete
        // arbitrary events if a future caller passed neither.
        if request_pubkey.is_none() && group.is_none() {
            return Ok(0);
        }
        let mut removed = 0usize;

        // The `e`-tag targets are bounded by the deletion request's own tag
        // list, but the batch is still split into REMOVAL_CHUNK-sized write
        // transactions so a huge request never pins one commit.
        for chunk in targets.chunks(REMOVAL_CHUNK) {
            let mut wtxn = self.env.write_txn()?;
            for target in chunk {
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
                // the delegator may also delete events published on their
                // behalf; delegated_by revalidates the target's delegation
                // signature and conditions before allowing that exception.
                if event.kind == nip09::DELETION_KIND {
                    continue;
                }
                // NIP-09's created_at cut applies to `a` (addressable)
                // targets only: an `e` target is deleted regardless of its
                // timestamp. The relay accepts events up to 3600 s in the
                // future, so applying the cut here made a clock-skewed post
                // undeletable while its deletion was acknowledged.
                if let Some(pubkey) = request_pubkey
                    && !pubkeys_equal(&event.pubkey, pubkey)
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
                // NIP-29's relay-signed metadata (39000-39005) is managed by
                // the relay: a group admin's 9005 must not delete it even
                // within their own group (the group check above would pass for
                // its own gid).
                if group.is_some()
                    && (crate::nips::nip29::GROUP_META..=crate::nips::nip29::GROUP_PINS)
                        .contains(&event.kind)
                {
                    continue;
                }
                self.deleted.put(&mut wtxn, &id, b"")?;
                self.remove_event(&mut wtxn, &id)?;
                removed += 1;
            }
            wtxn.commit()?;
        }

        // NIP-09 `a` tags: remove every version of the referenced
        // addressable events published up to the deletion request.
        for address in addresses {
            // The author may delete their own address; a NIP-26 delegator
            // may delete versions published on their behalf (checked per
            // version below, mirroring the `e`-tag path). Compare decoded
            // bytes (case-insensitive like the scan's hex decode) so an
            // uppercase `a` value still matches the author.
            let author_owns = request_pubkey.is_none_or(|pubkey| {
                hex::decode(&address.pubkey)
                    .ok()
                    .zip(hex::decode(pubkey).ok())
                    .is_some_and(|(a, b)| a == b)
            });
            let mut delegated_any = false;
            let Ok(pubkey) = hex::decode(&address.pubkey) else {
                continue;
            };
            if pubkey.len() != ID_LEN {
                continue;
            }
            // NIP-09: tombstone the address up to the request's created_at
            // *before* removing the versions, so a later re-publication of
            // an older version cannot resurrect the address even if a crash
            // or a MapFull interrupts the walk (mirrors `purge_group`'s
            // marker-first ordering). The per-id tombstones below only cover
            // the versions that exist right now. Merged with an existing
            // tombstone by keeping the furthest cut.
            let akey = deleted_address_key(address.kind, &pubkey, &address.d);
            if author_owns {
                self.merge_address_tombstone(&akey, request_created)?;
            }
            let start = replaceable_key(address.kind, &pubkey, "");
            let end = replaceable_key(address.kind.saturating_add(1), &pubkey, "");
            let mut last_key: Option<Vec<u8>> = None;
            loop {
                // A fresh write transaction per chunk: one address's version
                // history is unbounded, and a single transaction across it
                // pinned the writer while a MapFull aborted the whole
                // deletion. A replay after a crash re-walks the remaining
                // versions (the removed ones are already gone).
                let mut wtxn = self.env.write_txn()?;
                let lower = match &last_key {
                    Some(k) => std::ops::Bound::Excluded(k.as_slice()),
                    None => std::ops::Bound::Included(start.as_slice()),
                };
                // The slot values (not the keys) carry the removed id, so
                // this walk cannot use `removal_chunk`; iteration errors
                // still propagate so a cursor failure cannot report a
                // partial removal as a clean one.
                let mut entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
                for item in self
                    .replaceable
                    .range(&wtxn, &(lower, std::ops::Bound::Excluded(end.as_slice())))?
                {
                    let (k, v) = item?;
                    entries.push((k.to_vec(), v.to_vec()));
                    if entries.len() == REMOVAL_CHUNK {
                        break;
                    }
                }
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
                    if !author_owns {
                        let requester = request_pubkey.expect("not author_owns implies Some");
                        let delegated = self
                            .events
                            .get(&wtxn, id)?
                            .and_then(|raw| serde_json::from_slice::<Event>(raw).ok())
                            .is_some_and(|event| delegated_by(&event, requester));
                        if !delegated {
                            continue;
                        }
                        delegated_any = true;
                    }
                    self.deleted.put(&mut wtxn, id, b"")?;
                    self.remove_event(&mut wtxn, id)?;
                    removed += 1;
                }
                wtxn.commit()?;
            }
            // A delegated requester may only tombstone when a version
            // actually matched (the walk above authorizes each version): an
            // unmatched delegation must not leave a tombstone that blocks
            // the author's future publications up to the cut. Author-owned
            // addresses were already tombstoned before the walk.
            if !author_owns && delegated_any {
                self.merge_address_tombstone(&akey, request_created)?;
            }
        }

        Ok(removed)
    }

    /// Merges the NIP-09 `a`-tag tombstone at `akey` with the request's
    /// `cut`, keeping the furthest cut, and commits it. A tombstone written
    /// before the versions are removed keeps a crash or MapFull mid-walk
    /// from leaving the removals without their re-publication guard.
    fn merge_address_tombstone(&self, akey: &[u8], cut: u64) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;
        let merged = match self.deleted.get(&wtxn, akey)? {
            Some(old) if old.len() >= CREATED_LEN => {
                cut.max(u64::from_be_bytes(old[..CREATED_LEN].try_into().unwrap()))
            }
            _ => cut,
        };
        self.deleted.put(&mut wtxn, akey, &merged.to_be_bytes())?;
        wtxn.commit()?;
        Ok(())
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
        self.disk_full_error()?;
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
    /// NIP-29: deletes every stored event tagged with the deleted group
    /// `gid` (the `h` tag). A fresh create on the same id installs a public
    /// group, so without the purge the old (possibly private) history would
    /// suddenly be served under the new settings.
    ///
    /// `now` is the purge time recorded in [`PURGED_GROUPS`]: `h`-tagged
    /// re-publications with `created_at <= cut` are rejected at the put
    /// path, so the purged history cannot re-enter the database after a
    /// re-create, and a `kind:9007` re-create is rejected only while its
    /// `created_at` is before `now`. One marker covers the whole group (a
    /// create/purge cycle no longer writes a tombstone per purged event,
    /// which grew the database by the group's whole history). The marker is
    /// written and committed *first*: a put queued behind the purge sees it,
    /// and a crash mid-purge leaves the (fail-closed) cut rather than a
    /// window where re-published events are accepted. A second commit
    /// after the walk folds the newest removed timestamp into the cut, so
    /// same-second or future-dated purged events are rejected too.
    pub(crate) fn purge_group(&self, gid: &str, now: u64) -> Result<usize> {
        self.disk_full_error()?;
        let key = purged_group_key(gid);
        // Merge with an earlier purge of the same id: the furthest purge
        // time (for the re-create exception) and the furthest cut cover
        // every already-rejected generation.
        let (mut purge_now, mut cut) = {
            let mut wtxn = self.env.write_txn()?;
            let (old_now, old_cut) = self
                .purged_groups
                .get(&wtxn, &key)?
                .map(decode_purged_group_marker)
                .unwrap_or((0, 0));
            let purge_now = old_now.max(now);
            // The initial cut covers `now`; the final commit below raises
            // it to the newest removed event.
            let cut = old_cut.max(now);
            self.purged_groups
                .put(&mut wtxn, &key, &encode_purged_group_marker(purge_now, cut))?;
            wtxn.commit()?;
            (purge_now, cut)
        };
        let start = tag_key(b'h', gid.as_bytes(), 0, &[0u8; ID_LEN]);
        let end = tag_key(b'h', gid.as_bytes(), u64::MAX, &[0xffu8; ID_LEN]);
        let mut last_key: Option<Vec<u8>> = None;
        let mut removed = 0usize;
        let mut max_created = 0u64;
        loop {
            // A fresh write transaction per chunk: a group's history is
            // unbounded, and one transaction across the whole purge pinned
            // the writer while a MapFull aborted everything.
            let mut wtxn = self.env.write_txn()?;
            let lower = match &last_key {
                Some(k) => std::ops::Bound::Excluded(k.as_slice()),
                None => std::ops::Bound::Included(start.as_slice()),
            };
            let entries = removal_chunk(
                self.by_tag,
                &wtxn,
                (lower, std::ops::Bound::Excluded(end.as_slice())),
            )?;
            if entries.is_empty() {
                break;
            }
            last_key = Some(entries.last().unwrap().0.clone());
            for (_, id) in entries {
                let Some(raw) = self.events.get(&wtxn, &id)? else {
                    continue;
                };
                // The removed event's timestamp raises the cut: without it
                // a same-second or future-dated event would be removed by
                // this purge and then accepted again on replay.
                if let Ok(event) = serde_json::from_slice::<Event>(raw) {
                    max_created = max_created.max(event.created_at);
                }
                self.remove_event(&mut wtxn, &id)?;
                removed += 1;
            }
            wtxn.commit()?;
        }
        if max_created > cut {
            // Re-merge rather than overwrite: another purge cannot run
            // concurrently (single writer), but a legacy 8-byte marker may
            // have been upgraded by the initial commit above, and the
            // furthest-cut rule must hold either way.
            let mut wtxn = self.env.write_txn()?;
            let (old_now, old_cut) = self
                .purged_groups
                .get(&wtxn, &key)?
                .map(decode_purged_group_marker)
                .unwrap_or((0, 0));
            purge_now = purge_now.max(old_now);
            cut = old_cut.max(max_created);
            self.purged_groups
                .put(&mut wtxn, &key, &encode_purged_group_marker(purge_now, cut))?;
            wtxn.commit()?;
        }
        Ok(removed)
    }

    /// NIP-62: deletes every event authored by `pubkey` (including NIP-09
    /// deletion requests and NIP-59 gift wraps that p-tag it) and records the
    /// pubkey so that no future event from it is accepted.
    ///
    /// Replays are cheap: the stored marker keeps the furthest `until_created`
    /// already honored, and a request covered by it removes nothing (NIP-62
    /// requests are signed, re-broadcastable events, so an unchecked replay
    /// would re-walk the author's whole history and rewrite the NIP-29/43
    /// snapshots on every delivery).
    pub(crate) fn apply_vanish(&self, pubkey: &[u8], until_created: u64) -> Result<(usize, bool)> {
        self.disk_full_error()?;
        // Replay check: a marker covering this request means every event up
        // to its cut was already removed (the marker is written last, see
        // below), so there is nothing to do.
        {
            let rtxn = self.env.read_txn()?;
            // Legacy entries (written before the marker carried the timestamp)
            // have an empty value and count as `until_created = 0`, so they are
            // upgraded by the next request.
            if let Some(raw) = self.vanish.get(&rtxn, pubkey)? {
                let covered = raw
                    .get(..8)
                    .map(|bytes| u64::from_be_bytes(bytes.try_into().expect("checked length")))
                    .unwrap_or(0);
                if covered >= until_created {
                    return Ok((0, false));
                }
            }
        }

        let mut removed = 0usize;
        // Whether a NIP-29/NIP-43 state event (moderation/join/leave/role
        // mutation) was removed: only then does the derived state need a
        // rebuild. Deleting a member's ordinary posts must not trigger a
        // full-history scan.
        let mut group_state_removed = false;
        let start = pubkey_key(pubkey, 0, &[0u8; ID_LEN]);
        // NIP-62: the request deletes the pubkey's history *until its
        // `.created_at`* — events published (timestamped) after the request
        // are not covered by it.
        // Exclusive `(until + 1, 0..)`: covers every event with
        // `created_at <= until`, including the maximal id at exactly `until`.
        let end = crate::db::store::range_end(
            pubkey_key(pubkey, until_created.saturating_add(1), &[0u8; ID_LEN]),
            until_created,
        );
        let mut last_key: Option<Vec<u8>> = None;
        loop {
            // A fresh write transaction per chunk: the author's history is
            // unbounded, and one transaction across it pinned the writer
            // while a MapFull aborted the whole vanish. The marker is
            // written after the walk, so a partial pass is retried by a
            // re-delivered request.
            let mut wtxn = self.env.write_txn()?;
            let lower = match &last_key {
                Some(k) => std::ops::Bound::Excluded(k.as_slice()),
                None => std::ops::Bound::Included(start.as_slice()),
            };
            let entries = removal_chunk(
                self.by_pubkey,
                &wtxn,
                (lower, std::ops::Bound::Excluded(end.as_slice())),
            )?;
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
                // Compared case-insensitively: history stored with an
                // uppercase author hex must vanish like lowercase history.
                if !pubkeys_equal(&event.pubkey, &pubkey_hex) {
                    if crate::nips::nip26::delegation(&event).is_some() {
                        self.by_pubkey.delete(&mut wtxn, &key)?;
                    }
                    continue;
                }
                group_state_removed |= is_group_state_kind(event.kind);
                self.remove_event(&mut wtxn, &id)?;
                removed += 1;
            }
            wtxn.commit()?;
        }

        // NIP-59 gift wraps addressed to the vanished pubkey: the reserved
        // recipient index (keyed by the decoded pubkey) finds every hex case
        // variant with one narrow range. A failure here must not write the
        // marker below: the re-delivered request has to finish the wraps.
        self.remove_gift_wraps_for(pubkey, &mut removed)?;

        // The marker is written last, in its own transaction: a crash or a
        // failure mid-walk leaves no marker, so a re-delivered request
        // finishes the removal (already-removed chunks are gone) — the walk
        // is idempotent and eventual consistency holds. The writer thread
        // handles one message at a time, so no put can interleave between
        // the walk and the marker: every put queued behind this vanish
        // still sees the marker.
        let mut wtxn = self.env.write_txn()?;
        self.vanish
            .put(&mut wtxn, pubkey, &until_created.to_be_bytes())?;
        wtxn.commit()?;

        Ok((removed, group_state_removed))
    }

    /// NIP-59: relays SHOULD delete `kind:1059` gift wraps addressed to a
    /// pubkey when that pubkey signs a NIP-09 deletion request. Wraps are
    /// signed by random keys, so they cannot be deleted by their recipient
    /// through the normal deletion flow.
    pub(crate) fn delete_gift_wraps_to(&self, pubkey: &[u8]) -> Result<usize> {
        self.disk_full_error()?;
        let mut removed = 0usize;
        self.remove_gift_wraps_for(pubkey, &mut removed)?;
        Ok(removed)
    }

    /// Removes every stored event whose NIP-40 expiration has arrived.
    /// The returned bool reports whether a NIP-29/NIP-43 state event was
    /// among them, so the caller rebuilds the derived state (mirrors
    /// [`Self::apply_vanish`]'s second field).
    pub(crate) fn purge_expired(&self, now: u64) -> Result<(usize, bool)> {
        self.disk_full_error()?;
        // NIP-40 disabled: nothing is expired. Stale entries written while
        // it was enabled are removed by `remove_event` (which deletes the
        // entry regardless of the toggle), so re-enabling the feature can
        // never resurrect a purged event through a stale key.
        if !self
            .expiry_enabled
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return Ok((0, false));
        }
        let since_key = created_key(0, &[0u8; ID_LEN]);
        // NIP-40 semantics are `expiration <= now`: include every key at the
        // current second by using the largest possible event id as the
        // inclusive upper bound.
        let until_key = created_key(now, &[0xff; ID_LEN]);
        let mut last_key: Option<Vec<u8>> = None;
        let mut removed = 0usize;
        let mut group_state_removed = false;
        loop {
            // A fresh write transaction per chunk: the expired backlog is
            // unbounded, and one transaction across it pinned the writer
            // while a MapFull aborted the whole purge. Purges run
            // periodically, so a partial pass simply resumes next time.
            let mut wtxn = self.env.write_txn()?;
            let lower = match &last_key {
                Some(k) => std::ops::Bound::Excluded(k.as_slice()),
                None => std::ops::Bound::Included(since_key.as_slice()),
            };
            let entries = removal_chunk(
                self.expiry,
                &wtxn,
                (lower, std::ops::Bound::Included(until_key.as_slice())),
            )?;
            if entries.is_empty() {
                break;
            }
            last_key = Some(entries.last().unwrap().0.clone());
            for (key, id) in entries {
                if let Some(raw) = self.events.get(&wtxn, &id)? {
                    if let Ok(event) = serde_json::from_slice::<Event>(raw) {
                        group_state_removed |= is_group_state_kind(event.kind);
                    }
                    self.remove_event(&mut wtxn, &id)?;
                    removed += 1;
                } else {
                    // The event is already gone (removed outside the normal
                    // path or corrupt data): drop the orphaned expiry key
                    // too, or every purge would re-examine it forever.
                    self.expiry.delete(&mut wtxn, &key)?;
                }
            }
            wtxn.commit()?;
        }
        Ok((removed, group_state_removed))
    }
}
